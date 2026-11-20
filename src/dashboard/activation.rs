//! Applies a prepared certificate in a separate transient systemd unit.  The process that
//! requests a certificate may be killed when the Dashboard service restarts, so it must
//! never be responsible for its own rollback or readiness check.
use super::{acme, load_settings, service, update_settings, write_private};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Command, time::{Duration, Instant}};

const FILE: &str = "certificate-activation.json";
const UNIT: &str = "eztunnel-dashboard-certificate-activation.service";
const READY_DEADLINE: Duration = Duration::from_secs(45);
const RETRY_INTERVAL: Duration = Duration::from_millis(350);

/// A selection is indivisible. No separate key/chain/domain writes are allowed.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct Selection {
    pub acme: Option<acme::AcmeSettings>,
    pub certificate: Option<acme::SavedCertificate>,
}

impl Selection {
    fn current(state_dir: &Path) -> Result<Self> {
        let settings = load_settings(state_dir)?;
        Ok(Self { acme: settings.acme, certificate: settings.acme_certificate })
    }

    fn validate(&self, state_dir: &Path) -> Result<Vec<u8>> {
        match (&self.acme, &self.certificate) {
            (Some(wanted), Some(saved)) => {
                let issued = saved.issued_for(wanted)?;
                let (_, until) = issued.validity()?;
                ensure!(until > super::now(), "certificate expired before activation");
                Ok(issued.chain.first().context("no leaf certificate")?.as_ref().to_vec())
            }
            (None, None) => super::tls::self_signed_der(state_dir)
                .context("self-signed fallback certificate is missing"),
            // Previously installed versions stored ACME files separately; keep their
            // exact chain/key untouched and validate them before choosing a rollback.
            (Some(wanted), None) => {
                let issued = acme::load(state_dir).context("legacy certificate files are unavailable")?;
                acme::validate_for(&issued, wanted)?;
                let (_, until) = issued.validity()?;
                ensure!(until > super::now(), "previous certificate has expired");
                Ok(issued.chain.first().context("no legacy leaf")?.as_ref().to_vec())
            }
            (None, Some(_)) => bail!("certificate without a configured address"),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Queued, Applying, Restoring, Active, Recovered, RecoveryFailed, Failed, Manual,
}

impl Phase {
    fn unfinished(self) -> bool { matches!(self, Self::Queued | Self::Applying | Self::Restoring) }
}

#[derive(Serialize, Deserialize)]
struct Transaction {
    phase: Phase,
    /// Retained until positive verification or verified rollback. The file is private.
    previous: Option<Selection>,
    requested: Option<Selection>,
    detail: Option<String>,
}

impl Transaction {
    fn save(&self, state_dir: &Path) -> Result<()> {
        write_private(&state_dir.join(FILE), &serde_json::to_vec_pretty(self)?)
    }

    fn load(state_dir: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(
            &std::fs::read(state_dir.join(FILE)).context("read certificate activation record")?,
        )?)
    }

    fn finish(&mut self, state_dir: &Path, phase: Phase, detail: impl Into<String>) -> Result<()> {
        self.phase = phase;
        self.detail = Some(detail.into());
        // Retain recovery material only when it may still be necessary.
        if matches!(phase, Phase::Active | Phase::Recovered | Phase::Manual | Phase::Failed) {
            self.previous = None;
            self.requested = None;
        }
        self.save(state_dir)
    }
}

/// Expose only progress/diagnostics to authenticated HTTP clients, never the
/// private-key-bearing transaction record.
pub(super) fn status(state_dir: &Path) -> Option<(bool, Option<String>, Option<String>)> {
    let tx = Transaction::load(state_dir).ok()?;
    let running = tx.phase.unfinished() && service::active(UNIT);
    let detail = match tx.phase {
        Phase::Recovered | Phase::RecoveryFailed | Phase::Failed => tx.detail,
        Phase::Queued | Phase::Applying | Phase::Restoring if !running =>
            Some(format!("certificate activation interrupted; run 'eztunnel dashboard recover-certificate --state-dir {}' to restore the previous configuration", state_dir.display())),
        Phase::Manual => tx.detail,
        _ => None,
    };
    let state = match tx.phase {
        Phase::Manual => "restart_required",
        Phase::Active => "active",
        Phase::Recovered => "recovered",
        Phase::RecoveryFailed => "recovery_failed",
        Phase::Failed => "failed",
        Phase::Queued => "queued",
        Phase::Applying => "applying",
        Phase::Restoring => "restoring",
    };
    Some((running, detail, Some(state.into())))
}

/// Called from a CLI, or from the Dashboard after ACME has issued a certificate.
/// The transient unit is outside the Dashboard service's cgroup.
pub(super) fn schedule(state_dir: &Path, requested: Selection) -> Result<()> {
    super::require_root()?;
    let _ = requested.validate(state_dir)?;
    if state_dir.join(FILE).exists() {
        let previous = Transaction::load(state_dir).context("unreadable previous certificate activation record; recover it before replacing it")?;
        ensure!(!previous.phase.unfinished(),
            "a previous certificate activation is pending or interrupted; if its worker stopped, use 'eztunnel dashboard recover-certificate' before starting another");
        ensure!(!matches!(previous.phase, Phase::RecoveryFailed),
            "a previous certificate activation needs recovery; run 'eztunnel dashboard recover-certificate'");
    }
    let previous = Selection::current(state_dir)?;
    // Evaluate service state once for this scheduling attempt.
    let running = service::active(service::UNIT);
    // A scheduling error must not strand a private transaction unnecessarily.
    let executable = if running { Some(service::program()?) } else { None };
    let mut transaction = Transaction {
        phase: Phase::Queued,
        previous: Some(previous.clone()),
        requested: Some(requested.clone()),
        detail: None,
    };
    transaction.save(state_dir)?;

    // Manual/no-service mode never restarts the process that invoked this command.
    // It is explicitly *pending restart*, not reported as active.
    if !running {
        let changed = update_settings(state_dir, |settings| {
            let current = Selection { acme: settings.acme.clone(), certificate: settings.acme_certificate.clone() };
            ensure!(current == previous, "dashboard certificate choice changed while preparing activation");
            settings.acme = requested.acme;
            settings.acme_certificate = requested.certificate;
            Ok(())
        });
        if let Err(error) = changed {
            transaction.finish(state_dir, Phase::Failed, format!("save certificate choice: {error:#}"))?;
            return Err(error);
        }
        transaction.finish(state_dir, Phase::Manual,
            if service::installed() {
                format!("Dashboard service is inactive. Certificate saved but NOT activated; start it with 'systemctl start {}' and verify HTTPS.", service::UNIT)
            } else {
                "Certificate saved for the next manual Dashboard process start; restart 'eztunnel dashboard serve' to activate it.".into()
            })?;
        return Ok(());
    }

    let result = Command::new("systemd-run")
        .arg("--unit").arg(UNIT)
        .arg("--collect")
        .arg("--service-type=exec")
        .arg("--")
        .arg(executable.context("dashboard executable was not found")?)
        .args(["dashboard", "certificate-activation-worker", "--state-dir"])
        .arg(state_dir)
        .status();
    match result {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => {
            let detail = format!("systemd-run failed ({status}); the previous Dashboard certificate remains selected");
            transaction.finish(state_dir, Phase::Failed, detail.clone())?;
            bail!("{detail}");
        }
        Err(error) => {
            transaction.finish(state_dir, Phase::Failed, format!("could not launch independent activation worker: {error}; previous Dashboard settings unchanged"))?;
            Err(error).context("start independent systemd certificate activation worker")
        }
    }
}

fn commit(state_dir: &Path, from: &Selection, to: &Selection) -> Result<()> {
    update_settings(state_dir, |settings| {
        let actual = Selection { acme: settings.acme.clone(), certificate: settings.acme_certificate.clone() };
        ensure!(&actual == from, "certificate settings changed concurrently; refusing to overwrite unrelated configuration");
        settings.acme = to.acme.clone();
        settings.acme_certificate = to.certificate.clone();
        Ok(())
    })
}

async fn ready(state_dir: &Path, cert: &[u8], deadline: Duration) -> Result<()> {
    let port = load_settings(state_dir)?.port;
    let end = Instant::now() + deadline;
    let mut last = "service not ready".to_string();
    loop {
        if service::active(service::UNIT) {
            match super::terminal::probe_https(port, cert).await {
                Ok(()) => return Ok(()),
                Err(error) => last = format!("{error:#}"),
            }
        } else {
            last = "Dashboard service is not active".into();
        }
        if Instant::now() >= end {
            bail!("Dashboard failed live HTTPS readiness on local port {port} with the expected certificate: {last}");
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

/// An expired or unusable previous ACME certificate cannot be a safe recovery
/// endpoint. Fall back to the dashboard's existing self-signed certificate rather
/// than blocking an otherwise valid renewal or leaving a non-starting service.
fn recovery_selection(state_dir: &Path, previous: &Selection) -> Result<(Selection, Vec<u8>)> {
    match previous.validate(state_dir) {
        Ok(leaf) => Ok((previous.clone(), leaf)),
        Err(problem) => {
            eprintln!("Previous Dashboard certificate is unusable ({problem:#}); choosing its existing self-signed fallback for recovery");
            let fallback = Selection { acme: None, certificate: None };
            let leaf = fallback.validate(state_dir)?;
            Ok((fallback, leaf))
        }
    }
}

async fn restore(state_dir: &Path, tx: &mut Transaction, cause: &anyhow::Error) -> Result<()> {
    tx.phase = Phase::Restoring;
    tx.detail = Some(format!("activation failed: {cause:#}; restoring the previous certificate"));
    tx.save(state_dir)?;
    let previous = tx.previous.as_ref().context("no previous certificate saved for rollback")?.clone();
    let (recovery, expected) = recovery_selection(state_dir, &previous)?;
    let requested = tx.requested.as_ref().context("missing attempted certificate")?.clone();
    commit(state_dir, &requested, &recovery)?;
    // A failed start or a start-limit hit may leave the unit stopped. Restart even if
    // inactive; unlike service::apply, never treat inactivity as success.
    service::reset_failed()?;
    let restart = service::restart();
    let recovered = if let Err(error) = restart { Err(error) } else { ready(state_dir, &expected, READY_DEADLINE).await };
    match recovered {
        Ok(()) => {
            let outcome = if recovery == previous { "previous configuration" } else { "self-signed fallback" };
            tx.finish(state_dir, Phase::Recovered, format!("new certificate activation failed ({cause:#}); {outcome} was automatically restored and its HTTPS endpoint verified"))?;
            Ok(())
        }
        Err(error) => {
            tx.phase = Phase::RecoveryFailed;
            tx.detail = Some(format!(
                "replacement failed ({cause:#}); previous configuration was saved but Dashboard recovery was not verified ({error:#}). Run 'eztunnel dashboard recover-certificate --state-dir {}' and inspect 'journalctl -u {}'",
                state_dir.display(), service::UNIT
            ));
            tx.save(state_dir)?;
            Err(error.context("previous Dashboard configuration restored but service recovery failed"))
        }
    }
}

/// Executed ONLY in the independently supervised systemd transient unit.
pub async fn run(state_dir: &Path) -> Result<()> {
    super::require_root()?;
    let mut tx = Transaction::load(state_dir)?;
    ensure!(tx.phase == Phase::Queued, "certificate activation is not queued");
    let previous = tx.previous.as_ref().context("missing rollback settings")?.clone();
    let requested = tx.requested.as_ref().context("missing proposed settings")?.clone();
    let expected = requested.validate(state_dir)?;
    // An expired previous certificate can still be replaced; recovery will
    // use the self-signed fallback if that old identity cannot be served.
    ensure!(service::active(service::UNIT), "Dashboard service became inactive before activation; nothing was changed");
    tx.phase = Phase::Applying;
    tx.save(state_dir)?;
    commit(state_dir, &previous, &requested)?;
    let activation = match service::restart() {
        Ok(()) => ready(state_dir, &expected, READY_DEADLINE).await,
        Err(error) => Err(error),
    };
    match activation {
        Ok(()) => tx.finish(state_dir, Phase::Active, "Dashboard restarted and live HTTPS serves the configured certificate"),
        Err(error) => {
            eprintln!("Dashboard certificate activation failed: {error:#}; restoring previous configuration");
            restore(state_dir, &mut tx, &error).await?;
            Err(error.context("certificate activation failed; previous Dashboard service recovered"))
        }
    }
}

/// Manual recovery path if an independent worker itself was unexpectedly killed or
/// recovery could not be verified. Never overwrite an unrelated newer selection.
pub async fn recover(state_dir: &Path) -> Result<()> {
    super::require_root()?;
    ensure!(!service::active(UNIT), "certificate activation worker is still running; cannot recover concurrently");
    let mut tx = Transaction::load(state_dir)?;
    let previous = tx.previous.as_ref().context("no pending certificate rollback exists")?.clone();
    let (recovery, previous_cert) = recovery_selection(state_dir, &previous)?;
    let requested = tx.requested.as_ref().context("missing last attempted certificate")?.clone();
    let actual = Selection::current(state_dir)?;
    if actual == requested {
        commit(state_dir, &requested, &recovery)?;
    } else if actual == previous && recovery != previous {
        commit(state_dir, &previous, &recovery)?;
    } else {
        ensure!(actual == recovery, "Dashboard settings changed independently; refusing to overwrite them");
    }
    service::reset_failed()?;
    service::restart()?;
    ready(state_dir, &previous_cert, READY_DEADLINE).await?;
    let outcome = if recovery == previous { "previous Dashboard configuration" } else { "self-signed fallback" };
    tx.finish(state_dir, Phase::Recovered, format!("{outcome} restored and live HTTPS verified"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unusable_previous_acme_certificate_does_not_block_recovery_to_self_signed() {
        let dir = tempfile::tempdir().unwrap();
        super::super::tls::Swap::self_signed(dir.path(), "127.0.0.1").unwrap();
        let previous = Selection {
            acme: Some(acme::AcmeSettings { address: "expired.example.test".into(), staging: false }),
            certificate: None,
        };
        let (recovered, leaf) = recovery_selection(dir.path(), &previous).unwrap();
        assert!(recovered.acme.is_none());
        assert_eq!(leaf, super::super::tls::self_signed_der(dir.path()).unwrap());
    }

    #[test]
    fn transaction_progress_never_serializes_private_material_into_status_response() {
        let dir = tempfile::tempdir().unwrap();
        let cert = Selection { acme: None, certificate: None };
        let mut tx = Transaction { phase: Phase::Applying, previous: Some(cert.clone()), requested: Some(cert), detail: None };
        tx.save(dir.path()).unwrap();
        let response = status(dir.path()).unwrap();
        assert!(!response.0);
        assert!(response.1.unwrap().contains("recover-certificate"));
        tx.finish(dir.path(), Phase::Active, "verified").unwrap();
        let saved = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(saved.contains("active"));
        assert!(Transaction::load(dir.path()).unwrap().previous.is_none());
    }
}
