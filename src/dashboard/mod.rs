//! The web dashboard: an HTTPS server that shows the tunnels on this server.
//!
//! `eztunnel dashboard setup` creates the state directory (random port, a random password shown
//! once, a self-signed certificate); `eztunnel dashboard serve` runs the server; `eztunnel
//! dashboard demo` serves the same interface with sample data on the loopback address only.
mod acme;
mod activation;
mod agent;
mod alerts;
mod assets;
mod audit;
mod auth;
mod data;
mod edit;
mod fleet;
mod history;
mod host;
mod http;
mod link;
mod ops;
mod conntest;
mod maintain;
mod prefs;
mod relay;
mod service;
mod spoofcheck;
mod sshadd;
mod tls;
pub mod terminal;
mod tools;
mod wizard;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

/// Where the dashboard keeps its settings, certificate and audit log.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/eztunnel-dashboard";
const SETTINGS_FILE: &str = "settings.json";
const PASSWORD_LENGTH: usize = 20;
/// Letters and digits that cannot be mistaken for each other when read from a screen.
const PASSWORD_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// The random port is chosen from this range.
const PORT_RANGE: std::ops::RangeInclusive<u16> = 20_000..=60_999;

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    version: u32,
    port: u16,
    password_hash: String,
    created: u64,
    /// A Let's Encrypt certificate for this address instead of the self-signed one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme: Option<acme::AcmeSettings>,
    /// The issued chain, key and address are committed in one atomic settings write.
    /// Old installations with no bundle still read their legacy ACME files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme_certificate: Option<acme::SavedCertificate>,
}

fn settings_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SETTINGS_FILE)
}

fn load_settings(state_dir: &Path) -> Result<Settings> {
    let path = settings_path(state_dir);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "read {}; run `eztunnel dashboard setup` first",
            path.display()
        )
    })?;
    let settings: Settings = serde_json::from_str(&text).context("unreadable dashboard settings")?;
    ensure!(settings.version == 1, "unknown dashboard settings version");
    Ok(settings)
}

/// Changes the settings file: under an exclusive lock (between processes too: the dashboard and
/// the terminal commands), on the settings as they are now. A change prepared earlier (before a
/// minute-long certificate order) cannot put back a password changed meanwhile.
fn update_settings<T>(state_dir: &Path, change: impl FnOnce(&mut Settings) -> Result<T>) -> Result<T> {
    let path = state_dir.join("settings.lock");
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let lock = options.open(&path).with_context(|| format!("open {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // SAFETY: flock on a descriptor owned here; released when `lock` is dropped.
        ensure!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0, "lock the dashboard settings");
    }
    let mut settings = load_settings(state_dir)?;
    let result = change(&mut settings)?;
    save_settings(state_dir, &settings)?;
    drop(lock);
    Ok(result)
}

/// Saves a new password hash (changed from the Settings screen).
pub(crate) fn save_password_hash(state_dir: &Path, hash: &str) -> Result<()> {
    update_settings(state_dir, |settings| {
        settings.password_hash = hash.to_string();
        Ok(())
    })
}

fn save_settings(state_dir: &Path, settings: &Settings) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(settings)?;
    write_private(&settings_path(state_dir), &bytes)
}

/// Fills `bytes` from the operating system's random source.
pub(crate) fn random_bytes(bytes: &mut [u8]) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(bytes)
        .map_err(|_| anyhow::anyhow!("no random source"))
}

fn random_password() -> Result<String> {
    // Rejection sampling keeps every letter equally likely.
    let limit = 256 - 256 % PASSWORD_ALPHABET.len();
    let mut password = String::with_capacity(PASSWORD_LENGTH);
    let mut buffer = [0u8; 64];
    while password.len() < PASSWORD_LENGTH {
        random_bytes(&mut buffer)?;
        for byte in buffer {
            if (byte as usize) < limit && password.len() < PASSWORD_LENGTH {
                password.push(PASSWORD_ALPHABET[byte as usize % PASSWORD_ALPHABET.len()] as char);
            }
        }
    }
    Ok(password)
}

fn random_free_port() -> Result<u16> {
    let span = (*PORT_RANGE.end() - *PORT_RANGE.start()) as u32 + 1;
    for _ in 0..200 {
        let mut bytes = [0u8; 4];
        random_bytes(&mut bytes)?;
        let port = *PORT_RANGE.start() + (u32::from_le_bytes(bytes) % span) as u16;
        if std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok() {
            return Ok(port);
        }
    }
    bail!("no free port found")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect {}", dir.display()))?;
    }
    Ok(())
}

/// Writes a file readable only by its owner, through a temporary file so a crash never leaves
/// half a file behind.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let temporary = path.with_extension("tmp");
    let _ = std::fs::remove_file(&temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn require_root() -> Result<()> {
    ensure!(
        crate::manager::store::is_root(),
        "the dashboard manages system services; run it as root"
    );
    Ok(())
}

/// The address to print for this server: its outgoing IPv4 address, or a placeholder.
fn shown_address() -> String {
    crate::manager::local_ip().unwrap_or_else(|| "SERVER-IP".to_string())
}

/// Creates the dashboard's settings: a random port, a random password (printed once) and a
/// self-signed certificate; with `service`, installs and starts its system service. A dashboard
/// that was removed but kept its settings only gets its service back.
pub fn setup(state_dir: &Path, port: Option<u16>, service: bool) -> Result<()> {
    require_root()?;
    if settings_path(state_dir).exists() {
        ensure!(
            service && !service::installed(),
            "the dashboard is already set up; use `eztunnel dashboard reset-password` for a new password"
        );
        load_settings(state_dir)?;
        service::install(state_dir)?;
        println!("The dashboard runs again with its earlier settings and password ({}).", service::UNIT);
        return Ok(());
    }
    create_private_dir(state_dir)?;
    let port = match port {
        Some(port) => port,
        None => random_free_port()?,
    };
    let password = random_password()?;
    let settings = Settings {
        version: 1,
        port,
        password_hash: auth::hash_password(&password)?,
        created: now(),
        acme: None,
        acme_certificate: None,
    };
    let address = shown_address();
    tls::load_or_create(state_dir, &address)?;
    save_settings(state_dir, &settings)?;
    println!("Dashboard is set up.");
    println!();
    println!("  Address:   https://{address}:{port}");
    println!("  Password:  {password}");
    println!();
    println!("The password is shown only this once. Keep it somewhere safe.");
    println!("The certificate is self-signed, so the browser warns once before it opens the page.");
    if service {
        service::install(state_dir)?;
        println!("The dashboard runs now and starts with the server ({}).", service::UNIT);
    } else {
        println!("Start it with: eztunnel dashboard serve");
    }
    Ok(())
}

/// Moves the dashboard to another port.
pub fn set_port(state_dir: &Path, port: u16) -> Result<()> {
    require_root()?;
    ensure!(port >= 1024, "use a port from 1024 to 65535");
    if load_settings(state_dir)?.port == port {
        println!("The dashboard already uses port {port}.");
        return Ok(());
    }
    std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))
        .with_context(|| format!("port {port} is in use by another program"))?;
    update_settings(state_dir, |settings| {
        settings.port = port;
        Ok(())
    })?;
    println!("The dashboard's port is {port} now. Open it in the firewall if one is in use.");
    service::apply("the new port")
}

/// Stops the dashboard and removes its service. Its settings, history and backups stay unless
/// `delete_data` is set. Joined servers keep their tunnels; they lose the dashboard.
pub fn remove(state_dir: &Path, delete_data: bool) -> Result<()> {
    require_root()?;
    service::remove();
    if delete_data {
        if state_dir.exists() {
            std::fs::remove_dir_all(state_dir).with_context(|| format!("delete {}", state_dir.display()))?;
        }
        println!("The dashboard is removed with its settings, history and backups.");
    } else {
        println!("The dashboard is stopped and its service removed.");
        println!("Its settings, history and backups stay in {}; set it up again to run it with them.", state_dir.display());
    }
    println!("Tunnels on this server and on joined servers keep running.");
    Ok(())
}

/// The dashboard's system service.
pub const DASHBOARD_UNIT: &str = service::UNIT;

/// Accept a DNS name (including punycode) or an IP for the existing ACME HTTP-01 flow.
/// Reject URL schemes, ports and paths: the dashboard port stays unchanged.
pub(crate) fn certificate_address(text: &str) -> Result<String> {
    let value = text.trim().trim_end_matches('.');
    ensure!(!value.is_empty(), "enter a domain name or IP address");
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    ensure!(value.len() <= 253 && value.is_ascii(), "use a DNS hostname (international names must use their punycode form)");
    let names: Vec<&str> = value.split('.').collect();
    ensure!(names.len() >= 2 && names.iter().all(|part| {
        !part.is_empty() && part.len() <= 63 &&
        !part.starts_with('-') && !part.ends_with('-') &&
        part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }), "enter a valid domain name without a scheme, port or path");
    ensure!(names.last().is_some_and(|last| last.bytes().any(|b| b.is_ascii_alphabetic())), "the domain must have a DNS suffix");
    Ok(value.to_ascii_lowercase())
}

pub fn service_start() -> Result<()> {
    require_root()?;
    service::start()
}

pub fn service_stop() -> Result<()> {
    require_root()?;
    service::stop()
}

pub fn service_restart() -> Result<()> {
    require_root()?;
    service::restart()
}

/// Restarts the agent service, for example after an update so it runs the new program.
pub fn agent_restart() -> Result<()> {
    require_root()?;
    let status = std::process::Command::new("systemctl").args(["restart", agent::UNIT]).status()?;
    ensure!(status.success(), "systemctl restart {} failed", agent::UNIT);
    Ok(())
}

/// What `eztunnel dashboard status` and the manager's Web dashboard screen show.
pub struct Summary {
    pub set_up: bool,
    pub service_installed: bool,
    pub running: bool,
    pub url: String,
    pub certificate: String,
    /// The dashboard this server is joined to as an agent.
    pub joined_to: Option<String>,
    pub agent_running: bool,
}

pub fn summary(state_dir: &Path) -> Summary {
    let settings = load_settings(state_dir).ok();
    let certificate = match settings.as_ref().and_then(|s| s.acme.as_ref()) {
        None => "self-signed".to_string(),
        Some(wanted) => {
            let staging = if wanted.staging { ", staging" } else { "" };
            match acme::load_for(state_dir, wanted).and_then(|issued| issued.validity().ok()) {
                Some((_, until)) => format!("Let's Encrypt for {}{staging}, valid until {}", wanted.address, acme::utc_text(until)),
                None => format!("Let's Encrypt for {}{staging}, not issued yet", wanted.address),
            }
        }
    };
    let url = settings.as_ref().map_or_else(String::new, |s| {
        let host = s.acme.as_ref().map_or_else(shown_address, |a| a.address.clone());
        let host = if host.contains(':') { format!("[{host}]") } else { host };
        format!("https://{host}:{}", s.port)
    });
    Summary {
        set_up: settings.is_some(),
        service_installed: service::installed(),
        running: service::active(service::UNIT),
        url,
        certificate,
        joined_to: agent::joined(Path::new(agent::CONFIG_DIR)),
        agent_running: service::active(agent::UNIT),
    }
}

/// `eztunnel dashboard status`.
pub fn status(state_dir: &Path) -> Result<()> {
    let s = summary(state_dir);
    if s.set_up {
        let state = match (s.service_installed, s.running) {
            (_, true) => "running",
            (true, false) => "stopped",
            (false, false) => "no service (run `eztunnel dashboard setup` to add it)",
        };
        println!("Dashboard:    {state}");
        println!("Address:      {}", s.url);
        println!("Certificate:  {}", s.certificate);
        if let Some((worker_running, detail, phase)) = activation::status(state_dir) {
            println!("Activation:   {}{}", phase.as_deref().unwrap_or("unknown"), if worker_running { " (in progress)" } else { "" });
            if let Some(detail) = detail { println!("Activation detail: {detail}"); }
        }
    } else {
        println!("Dashboard:    not set up on this server");
    }
    match &s.joined_to {
        Some(hub) => println!("Agent:        joined to the dashboard at {hub} ({})", if s.agent_running { "running" } else { "stopped" }),
        None => println!("Agent:        not joined to a dashboard"),
    }
    Ok(())
}

/// Replaces the password with a new random one, printed once. Signed-in browsers are signed out
/// when the dashboard restarts.
pub fn reset_password(state_dir: &Path) -> Result<()> {
    require_root()?;
    let password = random_password()?;
    let hash = auth::hash_password(&password)?;
    update_settings(state_dir, |settings| {
        settings.password_hash = hash;
        Ok(())
    })?;
    println!("New password (shown only this once): {password}");
    service::apply("the new password; every browser signed in with the old one is signed out")
}

/// Runs the dashboard over HTTPS with the settings made by `setup`.
pub async fn serve(state_dir: &Path, listen: Option<IpAddr>) -> Result<()> {
    require_root()?;
    let settings = load_settings(state_dir)?;
    let swap = Arc::new(tls::Swap::self_signed(state_dir, &shown_address())?);
    // Load the committed matching chain before accepting a TLS connection. Renewal is
    // asynchronous but initial certificate selection must never race with the first client.
    if settings.acme.is_some() && acme::install_stored(state_dir, &swap).is_none() {
        eprintln!("Dashboard has no valid stored certificate for its configured address; using self-signed until renewal succeeds");
    }
    let tls = tls::server_config(swap.clone())?;
    let audit = audit::Audit::open(&state_dir.join("audit.log"))?;
    let history = Arc::new(history::History::new(Box::new(history::FileStore::open(
        &state_dir.join("history"),
    )?)));
    let live = data::Live::start(Box::new(data::LocalSource::new()?), Some(history.clone()));
    let state = Arc::new(http::AppState {
        history,
        auth: auth::Auth::new(settings.password_hash),
        audit,
        live,
        ops: Arc::new(ops::LocalOps),
        busy: Default::default(),
        followers: Arc::new(tokio::sync::Semaphore::new(http::MAX_FOLLOWERS)),
        fleet: Some(fleet::Fleet::open(state_dir)?),
        public: (
            settings.acme.as_ref().map_or_else(shown_address, |a| a.address.clone()),
            settings.port,
        ),
        agent_slots: Arc::new(tokio::sync::Semaphore::new(256)),
        certificate_task: Default::default(),
        cert: Some(swap.clone()),
        demo: false,
        secure: true,
        state_dir: state_dir.to_path_buf(),
        alerts: Default::default(),
    });
    tokio::spawn(http::backup_loop(state.clone()));
    tokio::spawn(http::alert_loop(state.clone()));
    let address = SocketAddr::new(listen.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)), settings.port);
    audit_start(&state, address);
    if let Some(acme_settings) = settings.acme.clone() {
        let reporter = state.clone();
        tokio::spawn(acme::keep_renewed(
            state_dir.to_path_buf(),
            acme_settings,
            swap,
            move |result| match result {
                Ok(next) => reporter.audit.record(
                    None,
                    "certificate",
                    &format!("Let's Encrypt certificate in use; next renewal {}", acme::utc_text(next)),
                ),
                Err(error) => {
                    eprintln!("Let's Encrypt certificate: {error}");
                    reporter.audit.record(None, "certificate_failed", &error);
                }
            },
        ));
    }
    http::serve(state, address, Some(tls)).await
}

/// Replaces the certificate/address together. A rejected or interrupted write keeps
/// the previous pair and domain usable across the next service restart.
fn change_certificate_settings(state_dir: &Path, next: Option<(acme::AcmeSettings, &acme::Issued)>) -> Result<(Option<acme::AcmeSettings>, Option<acme::SavedCertificate>)> {
    let replacement = next.map(|(wanted, issued)| {
        acme::SavedCertificate::from_issued(&wanted, issued).map(|saved| (wanted, saved))
    }).transpose()?;
    update_settings(state_dir, |settings| {
        let previous = (settings.acme.clone(), settings.acme_certificate.clone());
        settings.acme = replacement.as_ref().map(|(wanted, _)| wanted.clone());
        settings.acme_certificate = replacement.map(|(_, saved)| saved);
        Ok(previous)
    })
}

/// Issue and validate a new certificate before modifying any live Dashboard settings.
/// A systemd-managed Dashboard uses a separately supervised activation worker so
/// restarting it can never kill the only code able to restore its old certificate.
pub async fn certificate(state_dir: &Path, lets_encrypt: bool, staging: bool, address: Option<String>) -> Result<()> {
    require_root()?;
    load_settings(state_dir)?;
    let selected = if lets_encrypt {
        let address = certificate_address(&address.unwrap_or_else(shown_address))?;
        ensure!(address != "SERVER-IP", "this server's address was not found; give it with --address");
        let wanted = acme::AcmeSettings { address: address.clone(), staging };
        println!("Asking Let's Encrypt for a certificate for {address}.");
        println!("It checks this server over port 80, which must be free and open for about a minute.");
        let issued = acme::issue(state_dir, &wanted, 80).await?;
        let (_, until) = issued.validity()?;
        let kind = if staging { " (staging, not trusted by browsers)" } else { "" };
        println!("Certificate ready{kind}, valid until {}.", acme::utc_text(until));
        activation::Selection {
            certificate: Some(acme::SavedCertificate::from_issued(&wanted, &issued)?),
            acme: Some(wanted),
        }
    } else {
        activation::Selection { acme: None, certificate: None }
    };
    activation::schedule(state_dir, selected)?;
    println!("Certificate change requested. An active systemd Dashboard is restarted and HTTPS-verified by a separate recovery worker; check Dashboard Settings or journalctl for the final result.");
    Ok(())
}

/// If the activation worker itself is unexpectedly terminated, restore the
/// previous verified selection without overwriting any unrelated newer settings.
pub async fn recover_certificate(state_dir: &Path) -> Result<()> {
    activation::recover(state_dir).await
}

/// Internal transient-systemd-unit entry point; never run inside the Dashboard service.
pub async fn activate_certificate_worker(state_dir: &Path) -> Result<()> {
    activation::run(state_dir).await
}

/// Serves the interface with sample data on the loopback address, over plain HTTP. Nothing on
/// the machine is read or changed; the password is printed at start.
pub async fn demo(port: u16, empty: bool) -> Result<()> {
    let password = random_password()?;
    let now_minute = now() / 60;
    let demo_tunnels = if empty {
        Vec::new()
    } else {
        vec![("game-fec", 3.2e6, true), ("web-wss", 11.0e6, true), ("cdn-xhttps", 0.9e6, true), ("backup-tcp", 1.5e6, false)]
    };
    let names: Vec<&str> = demo_tunnels.iter().map(|t| t.0).collect();
    let demo_ops = ops::DemoOps::new(&names);
    let state = Arc::new(http::AppState {
        history: Arc::new(history::History::new(Box::new(history::DemoStore {
            tunnels: demo_tunnels,
            started_minute: now_minute,
        }))),
        auth: auth::Auth::new(auth::hash_password(&password)?),
        audit: audit::Audit::disabled().with_samples(),
        live: data::Live::start(Box::new(data::DemoSource::with_ops(!empty, demo_ops.clone())), None),
        ops: Arc::new(demo_ops),
        busy: Default::default(),
        followers: Arc::new(tokio::sync::Semaphore::new(http::MAX_FOLLOWERS)),
        fleet: None,
        public: ("203.0.113.10".into(), port),
        agent_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        certificate_task: Default::default(),
        cert: None,
        demo: true,
        secure: false,
        state_dir: std::env::temp_dir().join(format!("eztunnel-demo-{}", std::process::id())),
        alerts: Default::default(),
    });
    tokio::spawn(http::alert_loop(state.clone()));
    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    println!("Dashboard demo with sample data: http://{address}");
    println!("Password: {password}");
    http::serve(state, address, None).await
}

/// `eztunnel agent join CODE`: admits this server to a dashboard and installs the agent service.
pub async fn agent_join(code: &str) -> Result<()> {
    agent::join(code, Path::new(agent::CONFIG_DIR), true).await
}

/// `eztunnel agent run`: the agent service.
pub async fn agent_run(config_dir: &Path) -> Result<()> {
    agent::run(config_dir).await
}

/// `eztunnel agent leave`: stops the agent and forgets the dashboard.
pub fn agent_leave() -> Result<()> {
    agent::leave(Path::new(agent::CONFIG_DIR))
}

fn audit_start(state: &http::AppState, address: SocketAddr) {
    state
        .audit
        .record(None, "start", &format!("listening on {address}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_issued(domain: &str) -> acme::Issued {
        let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(vec![domain.to_owned()]).unwrap();
        acme::Issued {
            chain: vec![rustls::pki_types::CertificateDer::from(cert.der().as_ref().to_vec())],
            key: rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        }
    }

    fn test_settings(state_dir: &Path) {
        save_settings(state_dir, &Settings {
            version: 1, port: 31337, password_hash: "unchanged".into(), created: 1,
            acme: None, acme_certificate: None,
        }).unwrap();
    }

    #[test]
    fn certificate_change_is_atomic_across_domain_key_and_chain_and_survives_restarts() {
        let dir = tempfile::tempdir().unwrap();
        test_settings(dir.path());
        let a = acme::AcmeSettings { address: "a.example.org".into(), staging: false };
        let b = acme::AcmeSettings { address: "b.example.org".into(), staging: false };
        let issued_a = test_issued(&a.address);
        let issued_b = test_issued(&b.address);
        change_certificate_settings(dir.path(), Some((a.clone(), &issued_a))).unwrap();
        let saved_a = load_settings(dir.path()).unwrap();
        assert_eq!(saved_a.acme, Some(a.clone()));
        assert_eq!(saved_a.password_hash, "unchanged");
        let swap = tls::Swap::self_signed(dir.path(), "127.0.0.1").unwrap();
        assert_eq!(http::certificate_is_active(dir.path(), Some(&swap)), Some(false), "a manual --no-service dashboard still serves its previous certificate");
        assert!(acme::install_stored(dir.path(), &swap).is_some());
        assert_eq!(http::certificate_is_active(dir.path(), Some(&swap)), Some(true));
        let original_der = swap.current().cert[0].as_ref().to_vec();

        // Inject a settings persistence failure AFTER a successful simulated ACME issue.
        // A temp-directory collision blocks the single-file atomic rename before any
        // of the active address, key, or chain can be changed.
        std::fs::create_dir(dir.path().join("settings.tmp")).unwrap();
        assert!(change_certificate_settings(dir.path(), Some((b.clone(), &issued_b))).is_err());
        assert_eq!(load_settings(dir.path()).unwrap().acme, Some(a.clone()));
        let after_failed_restart = tls::Swap::self_signed(dir.path(), "127.0.0.1").unwrap();
        assert!(acme::install_stored(dir.path(), &after_failed_restart).is_some());
        assert_eq!(after_failed_restart.current().cert[0].as_ref(), original_der);
        assert_eq!(http::certificate_is_active(dir.path(), Some(&after_failed_restart)), Some(true));
        assert!(!dir.path().join("acme-chain.pem").exists(), "no separately writable active chain");
        assert!(!dir.path().join("acme-key.der").exists(), "no separately writable active key");
        std::fs::remove_dir(dir.path().join("settings.tmp")).unwrap();

        // A bogus certificate/key combination is rejected before touching settings.
        let mismatched = acme::Issued { chain: issued_b.chain.clone(), key: issued_a.key.clone_key() };
        assert!(change_certificate_settings(dir.path(), Some((b.clone(), &mismatched))).is_err());
        assert_eq!(load_settings(dir.path()).unwrap().acme, Some(a));
        change_certificate_settings(dir.path(), Some((b.clone(), &issued_b))).unwrap();
        assert_eq!(http::certificate_is_active(dir.path(), Some(&swap)), Some(false), "saving a domain change is not the same as applying TLS in a manually started dashboard");
        let restarted = tls::Swap::self_signed(dir.path(), "127.0.0.1").unwrap();
        assert!(acme::install_stored(dir.path(), &restarted).is_some());
        assert_eq!(http::certificate_is_active(dir.path(), Some(&restarted)), Some(true));
        assert_eq!(load_settings(dir.path()).unwrap().acme, Some(b));
        change_certificate_settings(dir.path(), None).unwrap();
        assert_eq!(http::certificate_is_active(dir.path(), Some(&restarted)), Some(false));
        let fallback = tls::Swap::self_signed(dir.path(), "127.0.0.1").unwrap();
        assert_eq!(http::certificate_is_active(dir.path(), Some(&fallback)), Some(true));
    }

    #[test]
    fn ip_certificates_keep_the_original_ipv4_and_ipv6_capability() {
        for address in ["203.0.113.10", "2001:db8::1"] {
            let ip = address.parse().unwrap();
            let mut params = rcgen::CertificateParams::default();
            params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = params.self_signed(&key).unwrap();
            let issued = acme::Issued {
                chain: vec![rustls::pki_types::CertificateDer::from(cert.der().as_ref().to_vec())],
                key: rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
            };
            let wanted = acme::AcmeSettings { address: address.into(), staging: false };
            let saved = acme::SavedCertificate::from_issued(&wanted, &issued).unwrap();
            assert_eq!(saved.issued_for(&wanted).unwrap().chain[0].as_ref(), cert.der().as_ref());
        }
    }

    #[test]
    fn legacy_certificate_must_match_the_saved_address_before_serving() {
        let dir = tempfile::tempdir().unwrap();
        test_settings(dir.path());
        let a = acme::AcmeSettings { address: "a.example.org".into(), staging: false };
        let issued = test_issued(&a.address);
        // Previous-version pair can be loaded only when it matches the configured SAN.
        std::fs::write(dir.path().join("acme-key.der"), issued.key.secret_pkcs8_der()).unwrap();
        let mut pem_text = String::new();
        for cert in &issued.chain {
            use base64::Engine;
            pem_text.push_str("-----BEGIN CERTIFICATE-----\n");
            pem_text.push_str(&base64::engine::general_purpose::STANDARD.encode(cert.as_ref()));
            pem_text.push_str("\n-----END CERTIFICATE-----\n");
        }
        std::fs::write(dir.path().join("acme-chain.pem"), pem_text).unwrap();
        update_settings(dir.path(), |s| { s.acme = Some(a.clone()); Ok(()) }).unwrap();
        assert!(acme::load_for(dir.path(), &a).is_some());
        let b = acme::AcmeSettings { address: "b.example.org".into(), staging: false };
        update_settings(dir.path(), |s| { s.acme = Some(b.clone()); Ok(()) }).unwrap();
        assert!(acme::load_for(dir.path(), &b).is_none());
    }

    #[test]
    fn certificate_address_accepts_dns_and_ip_but_not_urls_or_invalid_labels() {
        assert_eq!(certificate_address(" Dashboard.Example.COM. ").unwrap(), "dashboard.example.com");
        assert_eq!(certificate_address("203.0.113.10").unwrap(), "203.0.113.10");
        assert_eq!(certificate_address("2001:db8::1").unwrap(), "2001:db8::1");
        for invalid in ["", "https://example.com", "example.com:443", "a..example.com", "-a.example.com", "a-.example.com", "localhost", "*.example.com", "some/path.example"] {
            assert!(certificate_address(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn passwords_are_long_and_use_only_unambiguous_letters() {
        let password = random_password().unwrap();
        assert_eq!(password.len(), PASSWORD_LENGTH);
        assert!(password.bytes().all(|b| PASSWORD_ALPHABET.contains(&b)));
        assert_ne!(password, random_password().unwrap());
    }

    #[test]
    fn settings_are_written_privately_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            version: 1,
            port: 31_000,
            password_hash: "x".into(),
            created: 1,
            acme: Some(acme::AcmeSettings { address: "203.0.113.10".into(), staging: true }),
            acme_certificate: None,
        };
        save_settings(dir.path(), &settings).unwrap();
        let back = load_settings(dir.path()).unwrap();
        assert_eq!(back.port, 31_000);
        assert_eq!(back.acme, settings.acme);
        // Settings written before certificates existed still load.
        write_private(&settings_path(dir.path()), br#"{"version":1,"port":1,"password_hash":"x","created":1}"#).unwrap();
        assert_eq!(load_settings(dir.path()).unwrap().acme, None);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(settings_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
