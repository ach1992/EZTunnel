# Maintaining the ach1992/EZTunnel fork

This repository remains a GitHub fork of [B3hnamR/EZTunnel](https://github.com/B3hnamR/EZTunnel) (AGPL-3.0-only). The separate fork main is the only branch used for our installers, official binaries and updates. The contributor PR at [upstream #2](https://github.com/B3hnamR/EZTunnel/pull/2) stays open and its contributor branch must not be reset or repurposed while the maintainer is reviewing it.

## Synchronizing upstream

The scheduled/manual **Propose upstream sync** workflow fetches upstream `main`, merges it into an isolated `sync/upstream-<sha>` branch and opens a PR **into our own fork main**. It does not push upstream, force-update main, integrate, publish, or deploy. A merge conflict fails visibly; a human resolves it in a task branch and re-tests rather than discarding either side. It leaves an already-open sync PR alone. Since PRs created with `GITHUB_TOKEN` do not trigger ordinary PR workflows, the sync workflow explicitly dispatches Fork CI for its branch.

Before accepting a sync PR, verify the changes preserve the fork's Fleet CLI and Dashboard domain controls, fork-owned release/download/signing identity, the distinct package version, and committed generated UI assets. Run the required CI and obtain exact-diff independent review before integrating. For a manual sync use `git remote add upstream https://github.com/B3hnamR/EZTunnel.git`, `git fetch upstream main`, and `git merge --no-ff upstream/main` from a new branch based on fork main. Never `reset --hard` fork main to upstream.

## Release authority and installation

This fork intentionally downloads only GitHub Releases from **ach1992/EZTunnel**, via `scripts/install-latest.sh`, Dashboard Maintenance and the auto-join bootstrap. The installed fork's program updater verifies an embedded **fork** Ed25519 release key (ID 1), not the upstream release key. An ordinary developer build with no `EZTUNNEL_RELEASE_PUBLIC_KEY_HEX` cannot authenticate files for updater installation; it can still run locally for development.

**The release signing secret has not been provisioned automatically.** The Owner must securely generate an Ed25519 private seed locally/offline, keep a recoverable private backup, and set GitHub Actions repository secret `EZTUNNEL_RELEASE_KEY_HEX` (hex-encoded, 32 bytes). Never commit, publish, print into logs or chat, or include this secret in executable assets. One possible local setup using OpenSSL and GitHub CLI:

```bash
umask 077
openssl genpkey -algorithm Ed25519 -out ./eztunnel-fork-release-key.pem
openssl pkey -in ./eztunnel-fork-release-key.pem -outform DER |
  tail -c 32 | od -An -tx1 -v | tr -d ' \n' |
  gh secret set EZTUNNEL_RELEASE_KEY_HEX --repo ach1992/EZTunnel
```

Keep the private key file outside the repository. The manual **Publish signed fork release** workflow derives only the public key, embeds it when building x86_64/ARM64, signs the binaries in a final publisher job, verifies the signature before publication, creates matching release archives and `SHA256SUMS`, and publishes a versioned release. It must be run on `main` **after** independent review, successful tests and explicit release authorization. If the secret is absent, the workflow fails before release; do not silently substitute upstream binaries or unsigned builds. Do not rotate the trusted public key without a deliberate migration plan for the installed fork versions.

For installation after a release exists:

```bash
curl -fsSLo install-eztunnel-fork.sh https://raw.githubusercontent.com/ach1992/EZTunnel/main/scripts/install-latest.sh
sudo bash install-eztunnel-fork.sh --no-menu
sudo eztunnel menu
```

The installer keeps a backup of an existing executable and does not restart tunnels. Dashboard/agent programs and running tunnel services must be validated on test machines before any production rollout.

## Dashboard domain

Dashboard **Settings > Dashboard access** accepts a DNS hostname or IP without scheme/port and requests a Let's Encrypt certificate using the existing HTTP-01 issuing/renewal implementation. DNS must resolve to this host and **port 80** must be publicly reachable for issuing and renewing; the Dashboard's HTTPS port remains unchanged. A successful certificate change restarts the dashboard and the browser may need to sign in at the new hostname. Existing paired agents keep their stored Noise identity and configured connection addresses; do not silently rewrite their enrollment. The self-signed fallback remains available.

## Version bookkeeping

Fork releases use distinct SemVer tags, starting from `v0.12.0-ach.1`; keep `Cargo.toml`, `Cargo.lock`, release notes, built binary `--version` and GitHub Release tag consistent. A future upstream sync may conflict with these fork-owned files; resolve explicitly. Keep change history in Git commits, PRs and Releases rather than a parallel chat log.
