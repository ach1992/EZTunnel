# Maintaining the ach1992/EZTunnel fork

This repository remains a GitHub fork of [B3hnamR/EZTunnel](https://github.com/B3hnamR/EZTunnel) (AGPL-3.0-only). The separate fork main is the only branch used for our installers, official binaries and updates. The contributor PR at [upstream #2](https://github.com/B3hnamR/EZTunnel/pull/2) stays open and its contributor branch must not be reset or repurposed while the maintainer is reviewing it.

## Synchronizing upstream

The scheduled/manual **Propose upstream sync** workflow fetches upstream `main`, merges it into an isolated `sync/upstream-<sha>` branch and opens a PR **into our own fork main**. It does not push upstream, force-update main, integrate, publish, or deploy. A merge conflict fails visibly; a human resolves it in a task branch and re-tests rather than discarding either side. It leaves an already-open sync PR alone. Since PRs created with `GITHUB_TOKEN` do not trigger ordinary PR workflows, the sync workflow explicitly dispatches Fork CI for its branch.

Before accepting a sync PR, verify the changes preserve the fork's Fleet CLI and Dashboard domain controls, fork-owned release/download/signing identity, the distinct package version, and committed generated UI assets. Run the required CI and obtain exact-diff independent review before integrating. For a manual sync use `git remote add upstream https://github.com/B3hnamR/EZTunnel.git`, `git fetch upstream main`, and `git merge --no-ff upstream/main` from a new branch based on fork main. Never `reset --hard` fork main to upstream.

## Release authority and installation

This fork intentionally downloads only GitHub Releases from **ach1992/EZTunnel**, via `scripts/install-latest.sh`, Dashboard Maintenance and the auto-join bootstrap. The installed fork's program updater verifies an embedded **fork** Ed25519 release key (ID 1), not the upstream release key. An ordinary developer build with no `EZTUNNEL_RELEASE_PUBLIC_KEY_HEX` cannot authenticate files for updater installation; it can still run locally for development.

**A first fork release is blocked until the reviewed, non-secret public key pin is filled in.**
The checked-in `.github/release-public-key.hex` initially contains `UNPROVISIONED`. After
creating the seed, derive the matching 32-byte Ed25519 public key locally, submit that **public**
hex (64 lowercase characters) as a reviewed change to the pin file, and only then release. The
workflow refuses to publish if the Actions signing seed does not match that reviewed identity.
Changing only the Actions secret can never silently replace the trusted key of installed clients.
An intentional rotation requires a separately reviewed signed-bridge migration.

**The release signing secret has not been provisioned automatically.** The Owner must securely generate an Ed25519 private seed locally/offline, keep a recoverable private backup, and set GitHub Actions repository secret `EZTUNNEL_RELEASE_KEY_HEX` (hex-encoded, 32 bytes). Never commit, publish, print into logs or chat, or include this secret in executable assets. One possible local setup using OpenSSL and GitHub CLI:

```bash
umask 077
openssl genpkey -algorithm Ed25519 -out ./eztunnel-fork-release-key.pem
openssl pkey -in ./eztunnel-fork-release-key.pem -outform DER |
  tail -c 32 | od -An -tx1 -v | tr -d ' \n' |
  gh secret set EZTUNNEL_RELEASE_KEY_HEX --repo ach1992/EZTunnel
```

Derive the public hex locally and put **only that public value** in
`.github/release-public-key.hex` via a separately reviewed commit:

```bash
openssl pkey -in ./eztunnel-fork-release-key.pem -pubout -outform DER | \
  tail -c 32 | od -An -tx1 -v | tr -d ' \n'
```
Run `bash scripts/test-release-public-key.sh` to verify a changed secret cannot pass the pin gate.

Keep the private key file outside the repository. The manual **Publish signed fork release** workflow derives only the public key, embeds it when building x86_64/ARM64, signs the binaries in a final publisher job, verifies the signature before publication, creates matching release archives and `SHA256SUMS`, and publishes a versioned release. It must be run on `main` **after** independent review, successful tests and explicit release authorization. If the secret is absent, the workflow fails before release; do not silently substitute upstream binaries or unsigned builds. Do not rotate the trusted public key without a deliberate migration plan for the installed fork versions.

For installation after a release exists:

```bash
curl -fsSLo install-eztunnel-fork.sh https://raw.githubusercontent.com/ach1992/EZTunnel/main/scripts/install-latest.sh
sudo bash install-eztunnel-fork.sh --no-menu
sudo eztunnel menu
```

The installer keeps a backup of an existing executable and does not restart tunnels. Dashboard/agent programs and running tunnel services must be validated on test machines before any production rollout.

## Dashboard domain

Dashboard **Settings > Dashboard access** accepts a DNS hostname or IP without scheme/port and requests a Let's Encrypt certificate using the existing HTTP-01 issuing/renewal implementation. An issued certificate, its key and the configured address are stored as **one atomic, owner-private settings update**; a failed change leaves the previous working pair intact. Previously stored legacy certificate files can still be loaded when their actual SAN and key match the configured address. DNS must resolve to this host and **port 80** must be publicly reachable for issuing and renewing; the Dashboard's HTTPS port remains unchanged. With a running systemd Dashboard service, a successful certificate change requests a restart; with `dashboard setup --no-service` plus a manually executed `dashboard serve` process, the Settings API reports **restart_required** until the process is restarted with the saved certificate. The new certificate is called **active** only after the live TLS resolver presents the committed chain; the browser may need to sign in at the new hostname. Existing paired agents keep their stored Noise identity and configured connection addresses; do not silently rewrite their enrollment. The self-signed fallback remains available.

### Systemd certificate activation recovery

A Dashboard process cannot safely be responsible for its own restart rollback:
`systemctl restart eztunnel-dashboard.service` terminates the calling service cgroup.
The certificate API/CLI therefore issues and validates the certificate first, persists a
private activation transaction retaining the previous selection, and dispatches an independent
transient `systemd-run` worker. This worker commits a complete key/chain/domain tuple,
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
presented TLS leaf, automatic rollback after startup failure, inactive-service handling and
manual recovery from an interrupted worker. It neither orders real ACME certificates nor
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
