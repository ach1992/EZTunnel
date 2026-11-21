# Maintaining the ach1992/EZTunnel fork

This repository remains a GitHub fork of [B3hnamR/EZTunnel](https://github.com/B3hnamR/EZTunnel) (AGPL-3.0-only). The separate fork main is the only branch used for our installers, official binaries and updates. The contributor PR at [upstream #2](https://github.com/B3hnamR/EZTunnel/pull/2) stays open and its contributor branch must not be reset or repurposed while the maintainer is reviewing it.

This is a **temporary independent installation channel** while the upstream maintainer
considers our changes. The intended outcome is a working, single-command fork
installer and Release, not an ongoing custom signing or distribution system.
Once a released upstream version contains the needed features and is verified
on our servers, decide separately when to migrate or retire this fork. Do not
silently switch the installer to upstream binaries before then.


## Synchronizing upstream

The scheduled/manual **Propose upstream sync** workflow fetches upstream `main`, merges it into an isolated `sync/upstream-<sha>` branch and opens a PR **into our own fork main**. It does not push upstream, force-update main, integrate, publish, or deploy. A merge conflict fails visibly; a human resolves it in a task branch and re-tests rather than discarding either side. It leaves an already-open sync PR alone. Since PRs created with `GITHUB_TOKEN` do not trigger ordinary PR workflows, the sync workflow explicitly dispatches Fork CI for its branch.

Before accepting a sync PR, verify the changes preserve the fork's Fleet CLI and Dashboard domain controls, fork-owned Release/download identity, the distinct package version, and committed generated UI assets. Run the required CI and obtain exact-diff independent review before integrating. For a manual sync use `git remote add upstream https://github.com/B3hnamR/EZTunnel.git`, `git fetch upstream main`, and `git merge --no-ff upstream/main` from a new branch based on fork main. Never `reset --hard` fork main to upstream.

## Official Releases and installation

The fork publishes only to `ach1992/EZTunnel`. The manual **Publish fork release**
workflow runs from reviewed `main`, builds Linux x86_64 and ARM64 executables,
packages `eztunnel-linux-<arch>.tar.gz` archives plus `SHA256SUMS`, and
publishes a versioned GitHub Release. Existing Releases/tags are never overwritten.
No separate signing key, Actions secret or manual bootstrap is needed.
A manual workflow dispatch on a **non-main branch** builds test artifacts for
both CPUs but skips publication. Only an authorized dispatch from reviewed
`main` may publish a public Release. The native GNU/Linux build contract
and its GLIBC/runtime checks are documented in [architectures.md](architectures.md).


Install on each Linux server with the same one-line experience as upstream:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/ach1992/EZTunnel/main/scripts/install-latest.sh)
```

The installer and built-in `eztunnel upgrade` command download only from the **fork's** GitHub Releases. It validates
HTTPS, SHA256SUMS, ELF architecture and the executable version, preserves
the replaced binary and never restarts running tunnels. For a specific tag,
use `--version v0.12.0-ach.1`. Dashboard official downloads use the same
HTTPS/checksum model; Agent transfers use authenticated management channels
and matching SHA256 checks. Manually uploaded programs are an explicitly
administrator-trusted input, **not** independently authenticated releases.

**Trust boundary:** SHA256SUMS detects corrupt or mismatched archives; it does not
independently authenticate a publisher if the GitHub account serving both
archives and checksums is compromised. This simplified fork does not claim a
separate Ed25519 release-signing identity. Tunnel Noise authentication,
stored keys and paired peer identities remain unchanged.

Updates use private staging, persistent configuration validation and automatic
rollback when a tunnel fails to recover. Manual rollback requires the exact
previous executable whose SHA256 was recorded by the updater. The one-line installer restarts active Dashboard and Agent services when replacing the program,
but never restarts running tunnel services. It keeps a separate
`eztunnel.backup-<sha256>` for the replaced binary.

**Fork maintenance scope:** maintainers use the one-line installer or the local CLI/manager
upgrade path. Dashboard-initiated binary upgrades are not a fork acceptance requirement;
do not add compatibility work or dedicated validation for that workflow.

## Dashboard domain

Dashboard **Settings > Dashboard access** accepts a DNS hostname or IP without scheme/port and requests a Let's Encrypt certificate using the existing HTTP-01 issuing/renewal implementation. An issued certificate, its key and the configured address are stored as **one atomic, owner-private settings update**; a failed change leaves the previous working pair intact. Previously stored legacy certificate files can still be loaded when their actual SAN and key match the configured address. DNS must resolve to this host and **port 80** must be publicly reachable for issuing and renewing; the Dashboard's HTTPS port remains unchanged. With a running systemd Dashboard service, a successful certificate change requests a restart; with `dashboard setup --no-service` plus a manually executed `dashboard serve` process, the Settings API reports **restart_required** until the process is restarted with the saved certificate. The new certificate is called **active** only after the live TLS resolver presents the committed chain; the browser may need to sign in at the new hostname. Existing paired agents keep their stored Noise identity and configured connection addresses; do not silently rewrite their enrollment. The self-signed fallback remains available.

### Systemd certificate activation recovery

A Dashboard process cannot safely be responsible for its own restart rollback:
`systemctl restart eztunnel-dashboard.service` terminates the calling service cgroup.
The certificate API/CLI therefore issues and validates the certificate first, persists a
private activation transaction retaining the previous selection, and dispatches an independent
transient `systemd-run` worker. A short-lived per-state-directory
`certificate-activation.lock` serializes CLI/API admission, journal updates,
worker commit/recovery and ACME renewal publication across processes. The lock
is **not** held during external certificate issuance, service restart or HTTPS
readiness. Renewal due during an unfinished activation waits and retries; an
already-published valid renewal remains the rollback baseline. Conflicts with
legacy/independent writers cannot strand `Applying`/`Restoring`: a rejected
pre-commit attempt finishes as failed without changing the renewed certificate.
A valid superseding certificate is preserved, but a transaction becomes terminal
only after the real Dashboard HTTPS leaf and session API have been verified.
When the independently valid certificate cannot be served, recovery material
remains in `RecoveryFailed` for a later `recover-certificate` retry; the worker
tries a real restart and readiness check before deciding. Competing CLI/API
requests get a clear already-active-transaction error; no global locking or
operator-configurable concurrency ceiling is imposed.
Manual `recover-certificate` also holds a **separate, per-state-directory,
nonblocking `certificate-recovery.lock` for its entire operation**. Only one
operator process may complete that same recovery; a concurrent attempt receives
an explicit retryable error. Unlike the short transaction guard, this separate
OS-owned lock can span systemd restart and HTTPS readiness and is automatically
released when its process exits, including after an interruption. Under the
short journal guard, recovery completion checks that its persisted Restoring
transaction still owns the previous/requested selections before finalizing; a
stale process cannot overwrite a new activation journal. Recovery resets a
systemd unit only if it is actually failed; an inactive or unloaded unit is
simply restarted, avoiding an unnecessary `reset-failed: Unit not loaded` error.
Unrelated Dashboard instances and ordinary new activation/ACME operations are
not globally blocked.
The worker commits a complete key/chain/domain tuple,
restarts the Dashboard and checks **both** the exact TLS certificate and the live
`/api/session` response. If startup fails, it restores the previous tuple, resets a failed
systemd service if necessary, restarts it again and verifies HTTPS before recording recovery.
An unexpected worker interruption leaves the private transaction and the operator command
`eztunnel dashboard recover-certificate --state-dir PATH`; `eztunnel dashboard status`
reports the recoverable state. Inactive/no-service installations are explicitly
`restart_required`, not falsely successful.

The end-to-end regression is `scripts/test-systemd-certificate.py`. It requires an **explicitly
marked disposable systemd container** and never runs against a host accidentally; the runner
sets `/run/eztunnel-r1r-test-container`, uses a private test-only Dashboard service and
simulates a replacement process that exits before accepting HTTPS. It validates successful
activation from the authenticated Dashboard API, real previous-process termination, the
presented TLS leaf, automatic rollback after startup failure, inactive-service handling,
manual recovery from an interrupted worker, **two concurrent independent CLI
processes** competing for the same activation journal, and superseding valid
certificates during both healthy Dashboard service and failed replacement startup.
The failed-startup case must retain the private recovery material, preserve the
superseding certificate and demonstrate a later manual HTTPS-verified recovery.
The test additionally launches two competing manual recovery CLI processes,
checks that only one owns recovery, verifies that a later T2 activation journal
remains intact, and kills a manual recovery mid-operation before retrying.
Deterministic Rust tests cover renewal before admission, during queued/committed
activation, external legacy renewal conflicts, retry after a rejected commit,
HTTPS verification outcomes, stale-finalizer rejection, recovery lock lifecycle,
and journal privacy. It neither orders real ACME certificates nor
changes Production or Agent/tunnel units.

## Local Fleet CLI endpoint selection

Fleet CLI first authenticates the locally saved TLS certificate, then uses the same
Dashboard API and authenticated session. It probes loopback first and then addresses
assigned to local network interfaces so `dashboard serve --listen 10.0.0.2` remains
manageable without changing source. Use `eztunnel fleet --dashboard-address 10.0.0.2 servers`
when the bound local address cannot be auto-discovered; the certificate
fingerprint check is not bypassed by this override. It does not create an alternate
Agent management stack.

## Version bookkeeping

Fork releases use distinct SemVer tags, starting from `v0.12.0-ach.1`; keep `Cargo.toml`, `Cargo.lock`, release notes, built binary `--version` and GitHub Release tag consistent. A future upstream sync may conflict with these fork-owned files; resolve explicitly. Keep change history in Git commits, PRs and Releases rather than a parallel chat log.
