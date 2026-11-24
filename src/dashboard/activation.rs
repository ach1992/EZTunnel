//! Applies a prepared certificate in a separate transient systemd unit.  The process that
//! requests a certificate may be killed when the Dashboard service restarts, so it must
//! never be responsible for its own rollback or readiness check.
use super::{acme, load_settings, service, update_settings, write_private};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

const FILE: &str = "certificate-activation.json";
const LOCK_FILE: &str = "certificate-activation.lock";
const RECOVERY_LOCK_FILE: &str = "certificate-recovery.lock";

/// One state-directory lock serializes admission, journal mutations and renewal
/// publication across CLI, Dashboard and the independent systemd worker. Never
/// hold it over network ACME issuance, service restarts or HTTPS readiness waits.
struct Guard(File);

impl Guard {
    fn acquire(state_dir: &Path) -> Result<Self> {
        Self::lock(state_dir, LOCK_FILE, false)
    }

    /// A separate nonblocking advisory lock covers an entire *manual* recovery.
    /// The short transaction lock must still be released for service restart
    /// and HTTPS verification, but another recover-certificate process cannot
    /// own the old journal or finish it after a new activation is admitted.
    /// The kernel releases this lock if the recovery process terminates.
    fn try_recovery(state_dir: &Path) -> Result<Self> {
        Self::lock(state_dir, RECOVERY_LOCK_FILE, true)
    }

    fn lock(state_dir: &Path, file_name: &str, nonblocking: bool) -> Result<Self> {
        let path = state_dir.join(file_name);
        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
            if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
                let error = std::io::Error::last_os_error();
                if nonblocking && error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    bail!(
                        "another recover-certificate process is already recovering the Dashboard; retry after it finishes"
                    );
                }
                return Err(error).with_context(|| format!("lock {}", path.display()));
            }
        }
        Ok(Self(file))
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: unlock the descriptor owned by this guard.
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn admission_available(state_dir: &Path) -> Result<bool> {
    let path = state_dir.join(FILE);
    if !path.exists() {
        return Ok(true);
    }
    let phase = Transaction::load(state_dir)?.phase;
    Ok(!phase.unfinished() && phase != Phase::RecoveryFailed)
}

/// Renewal checks the transaction both before costly issuance and under the
/// same admission lock immediately before its final settings write.
pub(super) fn renewal_available(state_dir: &Path, wanted: &acme::AcmeSettings) -> Result<bool> {
    let _guard = Guard::acquire(state_dir)?;
    if !admission_available(state_dir)? {
        return Ok(false);
    }
    Ok(super::load_settings(state_dir)?.acme.as_ref() == Some(wanted))
}

pub(super) fn publish_renewal(
    state_dir: &Path,
    wanted: &acme::AcmeSettings,
    issued: &acme::Issued,
) -> Result<bool> {
    let saved = acme::SavedCertificate::from_issued(wanted, issued)?;
    let _guard = Guard::acquire(state_dir)?;
    if !admission_available(state_dir)? {
        return Ok(false);
    }
    update_settings(state_dir, |current| {
        ensure!(
            current.acme.as_ref() == Some(wanted),
            "Dashboard certificate target changed while renewing"
        );
        current.acme_certificate = Some(saved);
        Ok(())
    })?;
    Ok(true)
}

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
        Ok(Self {
            acme: settings.acme,
            certificate: settings.acme_certificate,
        })
    }

    fn validate(&self, state_dir: &Path) -> Result<Vec<u8>> {
        match (&self.acme, &self.certificate) {
            (Some(wanted), Some(saved)) => {
                let issued = saved.issued_for(wanted)?;
                let (_, until) = issued.validity()?;
                ensure!(
                    until > super::now(),
                    "certificate expired before activation"
                );
                Ok(issued
                    .chain
                    .first()
                    .context("no leaf certificate")?
                    .as_ref()
                    .to_vec())
            }
            (None, None) => super::tls::self_signed_der(state_dir)
                .context("self-signed fallback certificate is missing"),
            // Previously installed versions stored ACME files separately; keep their
            // exact chain/key untouched and validate them before choosing a rollback.
            (Some(wanted), None) => {
                let issued =
                    acme::load(state_dir).context("legacy certificate files are unavailable")?;
                acme::validate_for(&issued, wanted)?;
                let (_, until) = issued.validity()?;
                ensure!(until > super::now(), "previous certificate has expired");
                Ok(issued
                    .chain
                    .first()
                    .context("no legacy leaf")?
                    .as_ref()
                    .to_vec())
            }
            (None, Some(_)) => bail!("certificate without a configured address"),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Queued,
    Applying,
    Restoring,
    Active,
    Recovered,
    RecoveryFailed,
    Failed,
    Manual,
}

impl Phase {
    fn unfinished(self) -> bool {
        matches!(self, Self::Queued | Self::Applying | Self::Restoring)
    }
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
    fn save(&self, state_dir: &Path, _guard: &Guard) -> Result<()> {
        // Every journal write must have this guard; write_private's fixed .tmp
        // name cannot collide with another owner while the guard is held.
        write_private(&state_dir.join(FILE), &serde_json::to_vec_pretty(self)?)
    }

    fn load(state_dir: &Path) -> Result<Self> {
        Ok(serde_json::from_slice(
            &std::fs::read(state_dir.join(FILE)).context("read certificate activation record")?,
        )?)
    }

    fn finish(
        &mut self,
        state_dir: &Path,
        guard: &Guard,
        phase: Phase,
        detail: impl Into<String>,
    ) -> Result<()> {
        self.phase = phase;
        self.detail = Some(detail.into());
        // Retain recovery material only when it may still be necessary.
        if matches!(
            phase,
            Phase::Active | Phase::Recovered | Phase::Manual | Phase::Failed
        ) {
            self.previous = None;
            self.requested = None;
        }
        self.save(state_dir, guard)
    }
}

/// Expose only progress/diagnostics to authenticated HTTP clients, never the
/// private-key-bearing transaction record.
pub(super) fn status(state_dir: &Path) -> Option<(bool, Option<String>, Option<String>)> {
    let tx = Transaction::load(state_dir).ok()?;
    let running = tx.phase.unfinished() && service::active(UNIT);
    let detail = match tx.phase {
        Phase::Recovered | Phase::RecoveryFailed | Phase::Failed => tx.detail,
        Phase::Queued | Phase::Applying | Phase::Restoring if !running => Some(format!(
            "certificate activation interrupted; run 'eztunnel dashboard recover-certificate --state-dir {}' to restore the previous configuration",
            state_dir.display()
        )),
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
    let guard = Guard::acquire(state_dir)?;
    // Evaluate service state while holding the same admission lock as journal
    // creation. The worker will acquire it after systemd-run has dispatched.
    let running = service::active(service::UNIT);
    let executable = if running {
        Some(service::program()?)
    } else {
        None
    };
    let (mut transaction, previous) = admit_locked(state_dir, &guard, requested.clone())?;

    // Manual/no-service mode never restarts the process that invoked this command.
    // It is explicitly *pending restart*, not reported as active.
    if !running {
        let changed = update_settings(state_dir, |settings| {
            let current = Selection {
                acme: settings.acme.clone(),
                certificate: settings.acme_certificate.clone(),
            };
            ensure!(
                current == previous,
                "dashboard certificate choice changed while preparing activation"
            );
            settings.acme = requested.acme;
            settings.acme_certificate = requested.certificate;
            Ok(())
        });
        if let Err(error) = changed {
            transaction.finish(
                state_dir,
                &guard,
                Phase::Failed,
                format!("save certificate choice: {error:#}"),
            )?;
            return Err(error);
        }
        transaction.finish(state_dir, &guard, Phase::Manual,
            if service::installed() {
                format!("Dashboard service is inactive. Certificate saved but NOT activated; start it with 'systemctl start {}' and verify HTTPS.", service::UNIT)
            } else {
                "Certificate saved for the next manual Dashboard process start; restart 'eztunnel dashboard serve' to activate it.".into()
            })?;
        return Ok(());
    }

    let result = Command::new("systemd-run")
        .arg("--unit")
        .arg(UNIT)
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
            let detail = format!(
                "systemd-run failed ({status}); the previous Dashboard certificate remains selected"
            );
            transaction.finish(state_dir, &guard, Phase::Failed, detail.clone())?;
            bail!("{detail}");
        }
        Err(error) => {
            transaction.finish(state_dir, &guard, Phase::Failed, format!("could not launch independent activation worker: {error}; previous Dashboard settings unchanged"))?;
            Err(error).context("start independent systemd certificate activation worker")
        }
    }
}

/// Admission is one indivisible check-and-journal write, covered by the same
/// interprocess guard used by all later journal updates and renewal publication.
fn admit_locked(
    state_dir: &Path,
    guard: &Guard,
    requested: Selection,
) -> Result<(Transaction, Selection)> {
    if state_dir.join(FILE).exists() {
        let previous = Transaction::load(state_dir).context(
            "unreadable previous activation transaction; resolve it before replacing it",
        )?;
        ensure!(
            !previous.phase.unfinished(),
            "another certificate activation owns the transaction; retry after it finishes or run recover-certificate if its worker stopped"
        );
        ensure!(
            previous.phase != Phase::RecoveryFailed,
            "previous certificate activation needs recovery; run recover-certificate"
        );
    }
    let previous = Selection::current(state_dir)?;
    let transaction = Transaction {
        phase: Phase::Queued,
        previous: Some(previous.clone()),
        requested: Some(requested),
        detail: None,
    };
    transaction.save(state_dir, guard)?;
    Ok((transaction, previous))
}

fn commit(state_dir: &Path, from: &Selection, to: &Selection) -> Result<()> {
    update_settings(state_dir, |settings| {
        let actual = Selection {
            acme: settings.acme.clone(),
            certificate: settings.acme_certificate.clone(),
        };
        ensure!(
            &actual == from,
            "certificate settings changed concurrently; refusing to overwrite unrelated configuration"
        );
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
            bail!(
                "Dashboard failed live HTTPS readiness on local port {port} with the expected certificate: {last}"
            );
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
            eprintln!(
                "Previous Dashboard certificate is unusable ({problem:#}); choosing its existing self-signed fallback for recovery"
            );
            let fallback = Selection {
                acme: None,
                certificate: None,
            };
            let leaf = fallback.validate(state_dir)?;
            Ok((fallback, leaf))
        }
    }
}

/// A concurrent older renewal may have finished before this transaction was
/// queued (which is legitimate). A worker must refuse changed settings without
/// ever leaving an orphaned Applying journal or erasing the renewed certificate.
fn begin_commit(state_dir: &Path) -> Result<(Transaction, Vec<u8>)> {
    let guard = Guard::acquire(state_dir)?;
    let mut tx = Transaction::load(state_dir)?;
    ensure!(
        tx.phase == Phase::Queued,
        "certificate activation is not queued"
    );
    if !service::active(service::UNIT) {
        tx.finish(
            state_dir,
            &guard,
            Phase::Failed,
            "Dashboard stopped before activation; selected certificate was not modified",
        )?;
        bail!("Dashboard service became inactive before activation; nothing was changed");
    }
    let expected = commit_queued(state_dir, &guard, &mut tx)?;
    Ok((tx, expected))
}

/// The worker's complete in-lock state transition, also exercised with synthetic
/// renewals in unit tests without invoking the real system manager.
fn commit_queued(state_dir: &Path, guard: &Guard, tx: &mut Transaction) -> Result<Vec<u8>> {
    ensure!(
        tx.phase == Phase::Queued,
        "certificate activation is not queued"
    );
    let previous = tx
        .previous
        .as_ref()
        .context("missing rollback settings")?
        .clone();
    let requested = tx
        .requested
        .as_ref()
        .context("missing proposed settings")?
        .clone();
    let expected = match requested.validate(state_dir) {
        Ok(leaf) => leaf,
        Err(error) => {
            tx.finish(state_dir, guard, Phase::Failed, format!("proposed certificate is no longer valid: {error:#}; previous selection unchanged"))?;
            return Err(error);
        }
    };
    tx.phase = Phase::Applying;
    tx.save(state_dir, guard)?;
    if let Err(error) = commit(state_dir, &previous, &requested) {
        // Distinguish a rejected write from a rare ambiguous error after a
        // write: never discard rollback material if requested settings landed.
        let actual = Selection::current(state_dir)?;
        if actual != requested {
            if actual.validate(state_dir).is_ok() {
                tx.finish(state_dir, guard, Phase::Failed,
                    format!("activation declined because a valid certificate changed before commit ({error:#}); the independent renewal was preserved"))?;
            } else {
                tx.phase = Phase::RecoveryFailed;
                tx.detail = Some(format!(
                    "activation declined because the current certificate changed to an unusable selection ({error:#}); prior recovery material retained for recover-certificate"
                ));
                tx.save(state_dir, guard)?;
            }
        } else {
            tx.detail = Some(format!(
                "commit result unclear ({error:#}); run recover-certificate if the worker stopped"
            ));
            tx.save(state_dir, guard)?;
        }
        return Err(
            error.context("certificate activation did not acquire its expected configuration")
        );
    }
    Ok(expected)
}

/// An unsynchronized older writer may have installed a different *valid*
/// certificate. Preserve its selection, but never treat its persistence as
/// proof that the Dashboard actually started and serves that identity.
fn superseded_leaf(
    state_dir: &Path,
    tx: &Transaction,
    actual: &Selection,
) -> Result<Option<Vec<u8>>> {
    if actual
        == tx
            .requested
            .as_ref()
            .context("missing requested selection")?
        || actual == tx.previous.as_ref().context("missing previous selection")?
    {
        return Ok(None);
    }
    Ok(actual.validate(state_dir).ok())
}

/// Refuse stale terminal writes even if another actor replaced the journal
/// while this operation was outside the short transaction lock. A new Queued
/// transaction always remains authoritative over an older recovery snapshot.
fn ensure_restoring_owner(state_dir: &Path, tx: &Transaction, _guard: &Guard) -> Result<()> {
    let current = Transaction::load(state_dir)?;
    ensure!(
        current.phase == Phase::Restoring
            && current.previous == tx.previous
            && current.requested == tx.requested,
        "certificate activation transaction changed while recovery was verifying HTTPS; refusing stale recovery journal write"
    );
    Ok(())
}

/// Finish only after actual HTTPS readiness. Keep rollback material when the
/// certificate is valid on disk but not verified live, or settings change during
/// verification. This part is separately testable without invoking systemd.
fn finish_superseded(
    state_dir: &Path,
    tx: &mut Transaction,
    selection: &Selection,
    verification: Result<()>,
) -> Result<()> {
    let guard = Guard::acquire(state_dir)?;
    ensure_restoring_owner(state_dir, tx, &guard)?;
    let result = verification.and_then(|()| {
        ensure!(
            Selection::current(state_dir)? == *selection,
            "certificate selection changed while verifying live HTTPS readiness"
        );
        Ok(())
    });
    match result {
        Ok(()) => tx.finish(state_dir, &guard, Phase::Recovered,
            "a valid independent certificate superseded the activation; the existing selection was preserved and its live HTTPS endpoint verified"),
        Err(error) => {
            tx.phase = Phase::RecoveryFailed;
            tx.detail = Some(format!(
                "an independent certificate superseded activation but live HTTPS readiness was not verified ({error:#}); valid settings were preserved. Retry 'eztunnel dashboard recover-certificate --state-dir {}' after fixing the service",
                state_dir.display()
            ));
            tx.save(state_dir, &guard)?;
            Err(error.context("independent certificate is persisted but Dashboard recovery is unverified"))
        }
    }
}

/// The external certificate can be kept only if its actual TLS leaf and
/// Dashboard API are reachable. Avoid unnecessary restarts of a healthy service;
/// if not healthy, restart and verify while outside the transaction lock.
async fn verify_superseded(
    state_dir: &Path,
    tx: &mut Transaction,
    selection: &Selection,
    leaf: &[u8],
) -> Result<()> {
    let live = if service::active(service::UNIT) {
        match load_settings(state_dir) {
            Ok(settings) => super::terminal::probe_https(settings.port, leaf)
                .await
                .is_ok(),
            Err(_) => false,
        }
    } else {
        false
    };
    let result = if live {
        Ok(())
    } else {
        match service::reset_failed().and_then(|()| service::restart()) {
            Ok(()) => ready(state_dir, leaf, READY_DEADLINE).await,
            Err(error) => Err(error),
        }
    };
    finish_superseded(state_dir, tx, selection, result)
}

async fn restore(state_dir: &Path, tx: &mut Transaction, cause: &anyhow::Error) -> Result<()> {
    let previous = tx
        .previous
        .as_ref()
        .context("no previous certificate saved for rollback")?
        .clone();
    let (recovery, expected) = recovery_selection(state_dir, &previous)?;
    let requested = tx
        .requested
        .as_ref()
        .context("missing attempted certificate")?
        .clone();
    let superseded = {
        let guard = Guard::acquire(state_dir)?;
        tx.phase = Phase::Restoring;
        tx.detail = Some(format!(
            "activation failed: {cause:#}; restoring the previous certificate"
        ));
        tx.save(state_dir, &guard)?;
        let actual = Selection::current(state_dir)?;
        if actual == requested {
            commit(state_dir, &requested, &recovery)?;
            None
        } else if actual == previous && recovery != previous {
            commit(state_dir, &previous, &recovery)?;
            None
        } else if actual != recovery {
            if let Some(leaf) = superseded_leaf(state_dir, tx, &actual)? {
                // The journal remains Restoring, with previous/requested material.
                // A valid file is not enough: verify outside this lock first.
                Some((actual, leaf))
            } else {
                tx.phase = Phase::RecoveryFailed;
                tx.detail = Some("unexpected invalid certificate selection while restoring; previous recovery material preserved; run recover-certificate".into());
                tx.save(state_dir, &guard)?;
                bail!("cannot safely replace an unrelated unusable certificate during rollback");
            }
        } else {
            None
        }
    };
    if let Some((selection, leaf)) = superseded {
        return verify_superseded(state_dir, tx, &selection, &leaf).await;
    }
    // Restart even when the unit stopped or systemd's start limit was reached.
    let restart = service::reset_failed().and_then(|()| service::restart());
    let recovered = if let Err(error) = restart {
        Err(error)
    } else {
        ready(state_dir, &expected, READY_DEADLINE).await
    };
    let guard = Guard::acquire(state_dir)?;
    match recovered {
        Ok(()) => {
            let outcome = if recovery == previous {
                "previous configuration"
            } else {
                "self-signed fallback"
            };
            tx.finish(state_dir, &guard, Phase::Recovered, format!("new certificate activation failed ({cause:#}); {outcome} was automatically restored and its HTTPS endpoint verified"))?;
            Ok(())
        }
        Err(error) => {
            tx.phase = Phase::RecoveryFailed;
            tx.detail = Some(format!(
                "replacement failed ({cause:#}); previous configuration was saved but Dashboard recovery was not verified ({error:#}). Run 'eztunnel dashboard recover-certificate --state-dir {}' and inspect 'journalctl -u {}'",
                state_dir.display(),
                service::UNIT
            ));
            tx.save(state_dir, &guard)?;
            Err(error
                .context("previous Dashboard configuration restored but service recovery failed"))
        }
    }
}

/// Executed ONLY in the independently supervised systemd transient unit.
pub async fn run(state_dir: &Path) -> Result<()> {
    super::require_root()?;
    let (mut tx, expected) = begin_commit(state_dir)?;
    let activation = match service::restart() {
        Ok(()) => ready(state_dir, &expected, READY_DEADLINE).await,
        Err(error) => Err(error),
    };
    match activation {
        Ok(()) => {
            let guard = Guard::acquire(state_dir)?;
            tx.finish(
                state_dir,
                &guard,
                Phase::Active,
                "Dashboard restarted and live HTTPS serves the configured certificate",
            )
        }
        Err(error) => {
            eprintln!(
                "Dashboard certificate activation failed: {error:#}; restoring previous configuration"
            );
            restore(state_dir, &mut tx, &error).await?;
            Err(error
                .context("certificate activation failed; previous Dashboard service recovered"))
        }
    }
}

/// If the worker was interrupted, recover the previously owned selection. A
/// valid independently renewed certificate is retained and the aborted journal
/// released instead of requiring the operator to edit private JSON files.
pub async fn recover(state_dir: &Path) -> Result<()> {
    super::require_root()?;
    // Keep the recovery-specific lock until the final journal update (or
    // failure). It never blocks normal activation/renewal or holds the short
    // certificate transaction lock across systemd/network operations.
    let _recovery_owner = Guard::try_recovery(state_dir)?;
    let (mut tx, recovery, expected, superseded) = {
        let guard = Guard::acquire(state_dir)?;
        ensure!(
            !service::active(UNIT),
            "certificate activation worker is still running; cannot recover concurrently"
        );
        let mut tx = Transaction::load(state_dir)?;
        ensure!(
            tx.phase.unfinished() || matches!(tx.phase, Phase::RecoveryFailed),
            "no pending certificate rollback exists"
        );
        let previous = tx
            .previous
            .as_ref()
            .context("no pending certificate rollback exists")?
            .clone();
        let (recovery, expected) = recovery_selection(state_dir, &previous)?;
        let requested = tx
            .requested
            .as_ref()
            .context("missing last attempted certificate")?
            .clone();
        let actual = Selection::current(state_dir)?;
        let superseded =
            superseded_leaf(state_dir, &tx, &actual)?.map(|leaf| (actual.clone(), leaf));
        if superseded.is_some() {
            // Reserve recovery ownership, but retain private rollback material
            // until the live certificate and Dashboard API are verified.
            tx.phase = Phase::Restoring;
            tx.save(state_dir, &guard)?;
        }
        if superseded.is_none() {
            // An independently changed *valid* certificate is released above.
            // An invalid outsider is not ours to overwrite automatically. An
            // explicit recovery command may restore the previous identity only if
            // that invalid selection still targets the affected ACME address.
            let known = actual == requested || actual == previous || actual == recovery;
            let correct_domain = actual.acme == previous.acme || actual.acme == requested.acme;
            if !known && !(correct_domain && actual.validate(state_dir).is_err()) {
                tx.phase = Phase::RecoveryFailed;
                tx.detail = Some("Dashboard settings changed independently to an unrelated selection; no certificate was overwritten; inspect the configured identity before retrying recovery".into());
                tx.save(state_dir, &guard)?;
                bail!("refusing to overwrite a changed unrelated certificate selection");
            }
            tx.phase = Phase::Restoring;
            tx.save(state_dir, &guard)?;
            if actual != recovery {
                commit(state_dir, &actual, &recovery)?;
            }
        }
        (tx, recovery, expected, superseded)
    };
    if let Some((selection, leaf)) = superseded {
        return verify_superseded(state_dir, &mut tx, &selection, &leaf).await;
    }
    let outcome = service::reset_failed().and_then(|()| service::restart());
    let verified = if let Err(error) = outcome {
        Err(error)
    } else {
        ready(state_dir, &expected, READY_DEADLINE).await
    };
    let guard = Guard::acquire(state_dir)?;
    ensure_restoring_owner(state_dir, &tx, &guard)?;
    if let Err(error) = verified {
        tx.phase = Phase::RecoveryFailed;
        tx.detail = Some(format!(
            "previous selection was restored but HTTPS is still unavailable ({error:#}); recovery can be retried"
        ));
        tx.save(state_dir, &guard)?;
        return Err(error.context(
            "previous certificate restored but Dashboard readiness could not be verified",
        ));
    }
    let outcome = if &recovery == tx.previous.as_ref().context("missing previous")? {
        "previous Dashboard configuration"
    } else {
        "self-signed fallback"
    };
    tx.finish(
        state_dir,
        &guard,
        Phase::Recovered,
        format!("{outcome} restored and live HTTPS verified"),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn issued(address: &str) -> acme::Issued {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(address.try_into().unwrap()));
        let cert = params.self_signed(&key).unwrap();
        acme::Issued {
            chain: vec![rustls::pki_types::CertificateDer::from(
                cert.der().as_ref().to_vec(),
            )],
            key: rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
        }
    }

    fn fixture(path: &Path) -> (acme::AcmeSettings, acme::Issued) {
        let wanted = acme::AcmeSettings {
            address: "first.example.test".into(),
            staging: false, cloudflare_token: None,
        };
        let initial = issued(&wanted.address);
        super::super::save_settings(
            path,
            &super::super::Settings {
                version: 1,
                port: 34001,
                password_hash: "irrelevant".into(),
                created: 1,
                acme: Some(wanted.clone()),
                acme_certificate: Some(
                    acme::SavedCertificate::from_issued(&wanted, &initial).unwrap(),
                ),
            },
        )
        .unwrap();
        super::super::tls::Swap::self_signed(path, "127.0.0.1").unwrap();
        (wanted, initial)
    }

    fn requested_for(address: &str) -> Selection {
        let wanted = acme::AcmeSettings {
            address: address.into(),
            staging: false, cloudflare_token: None,
        };
        let issued = issued(&wanted.address);
        Selection {
            certificate: Some(acme::SavedCertificate::from_issued(&wanted, &issued).unwrap()),
            acme: Some(wanted),
        }
    }

    fn requested_second() -> Selection {
        requested_for("second.example.test")
    }

    #[test]
    fn renewal_published_before_admission_is_preserved_as_previous_selection() {
        let dir = tempfile::tempdir().unwrap();
        let (wanted, _) = fixture(dir.path());
        let renewed = issued(&wanted.address);
        assert!(publish_renewal(dir.path(), &wanted, &renewed).unwrap());
        let renewed_selection = Selection::current(dir.path()).unwrap();
        assert_eq!(
            renewed_selection
                .certificate
                .as_ref()
                .unwrap()
                .issued_for(&wanted)
                .unwrap()
                .chain[0],
            renewed.chain[0]
        );
        let guard = Guard::acquire(dir.path()).unwrap();
        let (mut tx, previous) = admit_locked(dir.path(), &guard, requested_second()).unwrap();
        assert!(
            previous == renewed_selection,
            "the latest valid renewal is the rollback reference"
        );
        commit_queued(dir.path(), &guard, &mut tx).unwrap();
        assert!(Selection::current(dir.path()).unwrap() == tx.requested.clone().unwrap());
        commit(dir.path(), tx.requested.as_ref().unwrap(), &previous).unwrap();
        tx.finish(
            dir.path(),
            &guard,
            Phase::Recovered,
            "previous renewed cert verified",
        )
        .unwrap();
        assert!(
            Selection::current(dir.path()).unwrap() == renewed_selection,
            "valid renewed certificate must survive rollback"
        );
    }

    #[test]
    fn renewal_is_deferred_before_commit_and_during_readiness_then_allowed_when_finished() {
        let dir = tempfile::tempdir().unwrap();
        let (wanted, _) = fixture(dir.path());
        let old_selection = Selection::current(dir.path()).unwrap();
        let newest = issued(&wanted.address);
        let guard = Guard::acquire(dir.path()).unwrap();
        let (mut tx, _) = admit_locked(dir.path(), &guard, requested_second()).unwrap();
        drop(guard);
        assert!(!renewal_available(dir.path(), &wanted).unwrap());
        assert!(!publish_renewal(dir.path(), &wanted, &newest).unwrap());
        assert!(Selection::current(dir.path()).unwrap() == old_selection);
        let guard = Guard::acquire(dir.path()).unwrap();
        commit_queued(dir.path(), &guard, &mut tx).unwrap();
        drop(guard);
        assert!(
            !publish_renewal(dir.path(), &wanted, &newest).unwrap(),
            "a renewal must not overwrite a committed replacement during HTTPS readiness"
        );
        let new_selection = tx.requested.clone().unwrap();
        assert!(Selection::current(dir.path()).unwrap() == new_selection);
        let guard = Guard::acquire(dir.path()).unwrap();
        tx.finish(dir.path(), &guard, Phase::Active, "HTTPS verified")
            .unwrap();
        drop(guard);
        let new_wanted = new_selection.acme.as_ref().unwrap();
        let next = issued(&new_wanted.address);
        assert!(publish_renewal(dir.path(), new_wanted, &next).unwrap());
        assert_eq!(
            Selection::current(dir.path())
                .unwrap()
                .certificate
                .as_ref()
                .unwrap()
                .issued_for(new_wanted)
                .unwrap()
                .chain[0],
            next.chain[0]
        );
    }

    #[test]
    fn precommit_external_renewal_refusal_is_terminal_and_can_be_retried() {
        let dir = tempfile::tempdir().unwrap();
        let (wanted, _) = fixture(dir.path());
        let replacement = requested_second();
        let guard = Guard::acquire(dir.path()).unwrap();
        let (mut tx, _) = admit_locked(dir.path(), &guard, replacement.clone()).unwrap();
        drop(guard);
        // Simulate a legacy renewal writer that did not use the new lock.
        let renewed = issued(&wanted.address);
        let saved = acme::SavedCertificate::from_issued(&wanted, &renewed).unwrap();
        super::super::update_settings(dir.path(), |settings| {
            settings.acme_certificate = Some(saved);
            Ok(())
        })
        .unwrap();
        let valid_renewed = Selection::current(dir.path()).unwrap();
        let guard = Guard::acquire(dir.path()).unwrap();
        assert!(commit_queued(dir.path(), &guard, &mut tx).is_err());
        assert_eq!(Transaction::load(dir.path()).unwrap().phase, Phase::Failed);
        assert!(Selection::current(dir.path()).unwrap() == valid_renewed);
        let (_, latest_previous) = admit_locked(dir.path(), &guard, replacement).unwrap();
        assert!(latest_previous == valid_renewed);
        assert_eq!(Transaction::load(dir.path()).unwrap().phase, Phase::Queued);
    }

    #[test]
    fn invalid_precommit_external_change_keeps_recovery_material_instead_of_losing_it() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path());
        let guard = Guard::acquire(dir.path()).unwrap();
        let (mut tx, _) = admit_locked(dir.path(), &guard, requested_second()).unwrap();
        drop(guard);
        // Simulates a broken old writer: the selection changes but its valid
        // certificate is no longer present. Never call that valid renewal.
        super::super::update_settings(dir.path(), |settings| {
            settings.acme_certificate = None;
            Ok(())
        })
        .unwrap();
        let guard = Guard::acquire(dir.path()).unwrap();
        assert!(commit_queued(dir.path(), &guard, &mut tx).is_err());
        let retained = Transaction::load(dir.path()).unwrap();
        assert_eq!(retained.phase, Phase::RecoveryFailed);
        assert!(retained.previous.is_some() && retained.requested.is_some());
        assert!(
            admit_locked(dir.path(), &guard, requested_second()).is_err(),
            "operator recovery is still required for an invalid unrelated state"
        );
    }

    /// A legacy, lock-unaware writer can publish B2 after our worker committed
    /// B. Tests below exercise the real terminal decision without invoking
    /// host systemctl. The isolated systemd QA covers the actual TLS probe.
    fn superseded_fixture() -> (tempfile::TempDir, Transaction, Selection) {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path());
        let guard = Guard::acquire(dir.path()).unwrap();
        let (mut tx, _) = admit_locked(dir.path(), &guard, requested_second()).unwrap();
        commit_queued(dir.path(), &guard, &mut tx).unwrap();
        drop(guard);
        let target = tx
            .requested
            .as_ref()
            .unwrap()
            .acme
            .as_ref()
            .unwrap()
            .clone();
        let newer = issued(&target.address);
        let saved = acme::SavedCertificate::from_issued(&target, &newer).unwrap();
        super::super::update_settings(dir.path(), |settings| {
            settings.acme_certificate = Some(saved);
            Ok(())
        })
        .unwrap();
        let selected = Selection::current(dir.path()).unwrap();
        assert!(
            superseded_leaf(dir.path(), &tx, &selected)
                .unwrap()
                .is_some()
        );
        // The real restore()/recover() path records ownership as Restoring
        // before dropping its short journal lock for live HTTPS readiness.
        let guard = Guard::acquire(dir.path()).unwrap();
        tx.phase = Phase::Restoring;
        tx.save(dir.path(), &guard).unwrap();
        drop(guard);
        (dir, tx, selected)
    }

    #[test]
    fn superseding_valid_certificate_can_finish_only_after_positive_https_evidence() {
        let (dir, mut tx, selected) = superseded_fixture();
        assert_eq!(
            Transaction::load(dir.path()).unwrap().phase,
            Phase::Restoring
        );
        // The verification is supplied by the live TLS+API probe in production.
        finish_superseded(dir.path(), &mut tx, &selected, Ok(())).unwrap();
        let final_tx = Transaction::load(dir.path()).unwrap();
        assert_eq!(final_tx.phase, Phase::Recovered);
        assert!(final_tx.previous.is_none() && final_tx.requested.is_none());
        assert!(Selection::current(dir.path()).unwrap() == selected);
        let guard = Guard::acquire(dir.path()).unwrap();
        assert!(admit_locked(dir.path(), &guard, requested_second()).is_ok());
    }

    #[test]
    fn superseding_valid_certificate_with_unverified_https_retains_recovery_and_retries() {
        let (dir, mut tx, selected) = superseded_fixture();
        let failure = anyhow::anyhow!("live TLS leaf mismatch or Dashboard API unavailable");
        assert!(finish_superseded(dir.path(), &mut tx, &selected, Err(failure)).is_err());
        let saved = Transaction::load(dir.path()).unwrap();
        assert_eq!(saved.phase, Phase::RecoveryFailed);
        assert!(saved.previous.is_some() && saved.requested.is_some());
        assert!(
            saved
                .detail
                .unwrap()
                .contains("live HTTPS readiness was not verified")
        );
        assert!(Selection::current(dir.path()).unwrap() == selected);
        let guard = Guard::acquire(dir.path()).unwrap();
        assert!(admit_locked(dir.path(), &guard, requested_second()).is_err());
        drop(guard);
        // The next manual recovery reasserts ownership as Restoring before
        // releasing the journal lock for the new HTTPS probe.
        let guard = Guard::acquire(dir.path()).unwrap();
        tx.phase = Phase::Restoring;
        tx.save(dir.path(), &guard).unwrap();
        drop(guard);
        finish_superseded(dir.path(), &mut tx, &selected, Ok(())).unwrap();
        assert_eq!(
            Transaction::load(dir.path()).unwrap().phase,
            Phase::Recovered
        );
        assert!(Selection::current(dir.path()).unwrap() == selected);
    }

    #[test]
    fn changed_identity_during_readiness_cannot_clear_rollback_journal() {
        let (dir, mut tx, selected) = superseded_fixture();
        let target = selected.acme.as_ref().unwrap().clone();
        let another =
            acme::SavedCertificate::from_issued(&target, &issued(&target.address)).unwrap();
        super::super::update_settings(dir.path(), |settings| {
            settings.acme_certificate = Some(another);
            Ok(())
        })
        .unwrap();
        let current = Selection::current(dir.path()).unwrap();
        assert!(current != selected);
        assert!(finish_superseded(dir.path(), &mut tx, &selected, Ok(())).is_err());
        let saved = Transaction::load(dir.path()).unwrap();
        assert_eq!(saved.phase, Phase::RecoveryFailed);
        assert!(saved.previous.is_some() && saved.requested.is_some());
        assert!(Selection::current(dir.path()).unwrap() == current);
    }

    #[test]
    fn concurrent_manual_recoveries_have_one_exclusive_owner_and_release_on_exit() {
        let dir = tempfile::tempdir().unwrap();
        let other_dir = tempfile::tempdir().unwrap();
        let first = Guard::try_recovery(dir.path()).unwrap();
        let error = Guard::try_recovery(dir.path()).err().unwrap();
        assert!(format!("{error:#}").contains("another recover-certificate process"));
        // A recovery in another installation is independent of this one.
        let _other = Guard::try_recovery(other_dir.path()).unwrap();
        drop(first);
        let _next = Guard::try_recovery(dir.path()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let lock = std::fs::metadata(dir.path().join(RECOVERY_LOCK_FILE)).unwrap();
            assert_eq!(lock.permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn stale_manual_finalizer_cannot_overwrite_new_queued_transaction() {
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path());
        let guard = Guard::acquire(dir.path()).unwrap();
        let (mut first, _) = admit_locked(dir.path(), &guard, requested_second()).unwrap();
        let old_snapshot: Transaction =
            serde_json::from_slice(&serde_json::to_vec(&first).unwrap()).unwrap();
        first.phase = Phase::Restoring;
        first.save(dir.path(), &guard).unwrap();
        let external = Selection::current(dir.path()).unwrap();
        first
            .finish(dir.path(), &guard, Phase::Recovered, "live HTTPS verified")
            .unwrap();
        let replacement = requested_for("third.example.test");
        let (second, _) = admit_locked(dir.path(), &guard, replacement).unwrap();
        assert_eq!(Transaction::load(dir.path()).unwrap().phase, Phase::Queued);
        drop(guard);

        // The original recovery's in-memory snapshot is now stale. TLS is
        // still serving the same valid certificate, so certificate identity
        // checking *alone* would incorrectly allow it to erase T2.
        let mut stale = old_snapshot;
        assert!(finish_superseded(dir.path(), &mut stale, &external, Ok(())).is_err());
        assert!(
            finish_superseded(
                dir.path(),
                &mut stale,
                &external,
                Err(anyhow::anyhow!("old HTTPS check failed"))
            )
            .is_err()
        );
        let current = Transaction::load(dir.path()).unwrap();
        assert_eq!(current.phase, Phase::Queued);
        assert!(current.previous == second.previous);
        assert!(current.requested == second.requested);
        assert!(current.detail.is_none());
        assert!(Selection::current(dir.path()).unwrap() == external);
    }

    #[test]
    fn concurrent_admissions_have_one_owner_and_private_valid_journal() {
        use std::sync::{Arc, Barrier};
        let dir = tempfile::tempdir().unwrap();
        fixture(dir.path());
        let path = Arc::new(dir.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(9));
        let mut threads = Vec::new();
        for index in 0..8 {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            let selection = requested_for(if index % 2 == 0 {
                "second.example.test"
            } else {
                "third.example.test"
            });
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let guard = Guard::acquire(&path).unwrap();
                admit_locked(&path, &guard, selection).is_ok()
            }));
        }
        barrier.wait();
        let accepted: usize = threads
            .into_iter()
            .map(|task| usize::from(task.join().unwrap()))
            .sum();
        assert_eq!(
            accepted, 1,
            "only one process-local contender may own the transaction"
        );
        let saved = Transaction::load(&path).unwrap();
        assert_eq!(saved.phase, Phase::Queued);
        let requested = saved.requested.unwrap();
        assert!(matches!(
            requested.acme.as_ref().unwrap().address.as_str(),
            "second.example.test" | "third.example.test"
        ));
        assert!(
            requested.validate(&path).is_ok(),
            "the winning request keeps its own consistent domain, certificate and key"
        );
        assert!(path.join(FILE).exists());
        assert!(!path.join("certificate-activation.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path.join(FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.join(LOCK_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn unusable_previous_acme_certificate_does_not_block_recovery_to_self_signed() {
        let dir = tempfile::tempdir().unwrap();
        super::super::tls::Swap::self_signed(dir.path(), "127.0.0.1").unwrap();
        let previous = Selection {
            acme: Some(acme::AcmeSettings {
                address: "expired.example.test".into(),
                staging: false, cloudflare_token: None,
            }),
            certificate: None,
        };
        let (recovered, leaf) = recovery_selection(dir.path(), &previous).unwrap();
        assert!(recovered.acme.is_none());
        assert_eq!(
            leaf,
            super::super::tls::self_signed_der(dir.path()).unwrap()
        );
    }

    #[test]
    fn transaction_progress_never_serializes_private_material_into_status_response() {
        let dir = tempfile::tempdir().unwrap();
        let cert = Selection {
            acme: None,
            certificate: None,
        };
        let mut tx = Transaction {
            phase: Phase::Applying,
            previous: Some(cert.clone()),
            requested: Some(cert),
            detail: None,
        };
        let guard = Guard::acquire(dir.path()).unwrap();
        tx.save(dir.path(), &guard).unwrap();
        let response = status(dir.path()).unwrap();
        assert!(!response.0);
        assert!(response.1.unwrap().contains("recover-certificate"));
        tx.finish(dir.path(), &guard, Phase::Active, "verified")
            .unwrap();
        let saved = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(saved.contains("active"));
        assert!(Transaction::load(dir.path()).unwrap().previous.is_none());
    }
}
