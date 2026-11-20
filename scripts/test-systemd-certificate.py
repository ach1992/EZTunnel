#!/usr/bin/env python3
"""Isolated Debian/systemd acceptance: activate, fail, rollback and inspect live TLS.

This script deliberately installs a temporary systemd unit with the normal Dashboard
service name and MUST run only inside a disposable marked container. It does not
request ACME/production DNS or touch agents, tunnels or host networking.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import http.client
import re
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time

MARKER = Path("/run/eztunnel-r1r-test-container")
STATE = Path(os.environ.get("EZTUNNEL_R1R_QA_STATE", "/var/lib/eztunnel-r1r-systemd-qa"))
UNIT = Path("/etc/systemd/system/eztunnel-dashboard.service")
WRAPPER = Path("/usr/local/libexec/eztunnel-r1r-test-dashboard")
WORKER = "eztunnel-dashboard-certificate-activation.service"


def cmd(*args: str, check: bool = True, **kw):
    return subprocess.run([str(a) for a in args], check=check, text=True, **kw)


def system(*args: str, check: bool = True):
    return cmd("systemctl", *args, check=check, capture_output=True)


def tls_probe(port: int):
    ctx = ssl._create_unverified_context()
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname="localhost") as conn:
            actual = conn.getpeercert(binary_form=True)
            conn.sendall(b"GET /api/session HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            reply = conn.recv(4096)
            if not reply.startswith(b"HTTP/1.1 200") or b"signed_in" not in reply:
                raise AssertionError(f"dashboard endpoint did not return expected HTTP API: {reply[:160]!r}")
            return actual


def until(message: str, fn, seconds=75):
    start = time.monotonic()
    last = ""
    while time.monotonic() < start + seconds:
        try:
            value = fn()
            if value:
                return value
        except (OSError, ValueError, AssertionError) as exc:
            last = str(exc)
        time.sleep(0.4)
    raise AssertionError(f"timeout {message}; last={last}")


def settings():
    return json.loads((STATE / "settings.json").read_text())


def cert_for(domain: str):
    with tempfile.TemporaryDirectory(prefix="eztunnel-cert-qa-") as root:
        root = Path(root)
        key = root / "key.pem"
        pem = root / "cert.pem"
        der = root / "cert.der"
        pkcs8 = root / "key.der"
        cmd("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", pem, "-days", "3", "-subj", f"/CN={domain}",
            "-addext", f"subjectAltName=DNS:{domain}",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cmd("openssl", "x509", "-in", pem, "-outform", "DER", "-out", der)
        cmd("openssl", "pkcs8", "-topk8", "-nocrypt", "-in", key,
            "-outform", "DER", "-out", pkcs8)
        expected = der.read_bytes()
        wanted = {"address": domain, "staging": False}
        return {
            "acme": wanted,
            "certificate": {"wanted": wanted, "chain": [expected.hex()], "key": pkcs8.read_bytes().hex()},
        }, expected


def state_of_cert(selection, expected):
    result = settings()
    assert result["acme"] == selection["acme"], "unexpected saved domain"
    assert result.get("acme_certificate") == selection["certificate"], "unexpected saved key/chain"
    return tls_probe(result["port"]) == expected


def phase(name: str):
    data = json.loads((STATE / "certificate-activation.json").read_text())
    if data.get("phase") != name:
        return False
    return data


def save_selected(selection):
    data = settings()
    data["acme"] = selection["acme"]
    data["acme_certificate"] = selection["certificate"]
    path = STATE / "settings.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)


def transaction(previous, requested):
    obj = {"phase": "queued", "previous": previous, "requested": requested, "detail": None}
    path = STATE / "certificate-activation.json"
    path.write_text(json.dumps(obj))
    path.chmod(0o600)


def activate(binary: Path):
    run = cmd("systemd-run", "--unit", WORKER, "--collect", "--service-type=exec",
              "--", binary, "dashboard", "certificate-activation-worker",
              "--state-dir", STATE, check=False, capture_output=True)
    if run.returncode:
        raise AssertionError(f"activation scheduling failed: {run.stdout} {run.stderr}")


def supersession_scenarios(binary: Path):
    """R1-N3: a valid persisted identity is not evidence of live HTTPS."""
    # Healthy supersession during a simulated interrupted worker: manual
    # recovery must preserve B2, verify live HTTPS and avoid needless restart.
    original = {"acme": None, "certificate": None}
    requested, _ = cert_for("fail.example.test")
    healthy, healthy_der = cert_for("healthy-external.example.test")
    transaction(original, requested)
    path = STATE / "certificate-activation.json"
    tx = json.loads(path.read_text())
    tx["phase"] = "restoring"
    path.write_text(json.dumps(tx))
    path.chmod(0o600)
    save_selected(healthy)
    system("reset-failed", "eztunnel-dashboard.service")
    system("restart", "eztunnel-dashboard.service")
    until("healthy independent certificate is serving HTTPS",
          lambda: check_service_live(healthy_der), seconds=40)
    old_pid = pid()
    cmd(binary, "dashboard", "recover-certificate", "--state-dir", STATE,
        check=True, capture_output=True)
    assert phase("recovered")
    assert check_service_live(healthy_der)
    assert pid() == old_pid, "already-healthy superseding certificate should not force another restart"
    assert state_of_cert(healthy, healthy_der)
    assert json.loads(path.read_text())["previous"] is None
    print("HEALTHY_EXTERNAL_SUPERSESSION_VERIFIED_OK", flush=True)

    # A real failed startup. When the broken replacement B is starting,
    # a test-only legacy writer switches settings to valid B2 and the wrapper
    # holds the service down. The worker must preserve B2 AND rollback journal.
    replacement, _ = cert_for("fail.example.test")
    superseded, superseded_der = cert_for("external-after-failed-start.example.test")
    transaction(healthy, replacement)
    persisted = settings()
    persisted["acme"] = superseded["acme"]
    persisted["acme_certificate"] = superseded["certificate"]
    staged = STATE / "supersede-next.json"
    staged.write_text(json.dumps(persisted))
    staged.chmod(0o600)
    blocked = STATE / "block-superseded"
    blocked.touch()
    try:
        activate(binary)
        until("failed startup with valid external supersession remains recoverable",
              lambda: phase("recovery_failed"), seconds=130)
        assert settings()["acme"] == superseded["acme"]
        assert settings()["acme_certificate"] == superseded["certificate"]
        journal = json.loads(path.read_text())
        assert journal["previous"] is not None and journal["requested"] is not None
        assert "live HTTPS readiness was not verified" in journal["detail"]
        assert not check_service_live(superseded_der)
        print("FAILED_SUPERSESSION_RETAINS_RECOVERY_OK", flush=True)
    finally:
        blocked.unlink(missing_ok=True)
        staged.unlink(missing_ok=True)

    until("failed supersession worker to terminate before manual retry",
          lambda: system("is-active", "--quiet", WORKER, check=False).returncode != 0,
          seconds=25)
    cmd(binary, "dashboard", "recover-certificate", "--state-dir", STATE,
        check=True, capture_output=True)
    until("recovery of valid independent certificate with actual HTTPS verification",
          lambda: check_service_live(superseded_der) and phase("recovered"), seconds=40)
    assert state_of_cert(superseded, superseded_der)
    journal = json.loads(path.read_text())
    assert journal["previous"] is None and journal["requested"] is None
    print("FAILED_SUPERSESSION_MANUAL_RECOVERY_VERIFIED_OK", flush=True)
    return superseded, superseded_der


def recovery_lock_is_held():
    """Probe the recovery lock from this *other* process, without modifying it."""
    with open(STATE / "certificate-recovery.lock", "a+b") as probe:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        else:
            fcntl.flock(probe, fcntl.LOCK_UN)
            return False


def mark_manual_recovery(previous, requested):
    transaction(previous, requested)
    journal = STATE / "certificate-activation.json"
    tx = json.loads(journal.read_text())
    tx["phase"] = "recovery_failed"
    tx["detail"] = "test-only manually recoverable interrupted activation"
    journal.write_text(json.dumps(tx))
    journal.chmod(0o600)


def concurrent_manual_recovery_scenarios(binary: Path, selected, selected_der, self_signed_der):
    """R1-N4: two distinct recovery CLI processes, new T2 and killed-owner retry."""
    until("prior activation worker is inactive",
          lambda: system("is-active", "--quiet", WORKER, check=False).returncode != 0,
          seconds=25)
    unexpected, _ = cert_for("manual-recovery-race.example.test")
    argv = [str(binary), "dashboard", "recover-certificate", "--state-dir", str(STATE)]
    # Prior deliberately failed startups repeatedly restart the same fixture.
    # Run manual ownership acceptance outside systemd's normal start-rate burst.
    time.sleep(10)
    system("reset-failed", "eztunnel-dashboard.service")

    # Both recovery commands see one valid superseding B2 while the service is
    # stopped. The wrapper deliberately delays the newly started service, so
    # the first process owns the recovery lock throughout a real HTTPS wait.
    mark_manual_recovery({"acme": None, "certificate": None}, unexpected)
    system("stop", "eztunnel-dashboard.service")
    slow = STATE / "slow-start"
    slow.touch()
    try:
        first = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        def owner_started():
            if first.poll() is not None:
                out, err = first.communicate(timeout=3)
                raise AssertionError(f"first recovery exited before owning journal (exit={first.returncode}): {out} {err}")
            return recovery_lock_is_held() and phase("restoring")
        until("first manual recovery owns the OS lock and Restoring journal",
              owner_started, seconds=15)
        second = subprocess.run(argv, text=True, capture_output=True, timeout=15)
        assert second.returncode != 0 and "another recover-certificate process" in second.stderr, (
            f"a second recovery must not own or finalize the first transaction: {second}"
        )
        assert phase("restoring"), "the refused second process must not change the journal"
        first_stdout, first_stderr = first.communicate(timeout=60)
        assert first.returncode == 0, f"first recovery failed: {first_stdout} {first_stderr}"
        assert phase("recovered") and check_service_live(selected_der)
        assert state_of_cert(selected, selected_der)
        completed = json.loads((STATE / "certificate-activation.json").read_text())
        assert completed["previous"] is None and completed["requested"] is None
        print("CONCURRENT_MANUAL_RECOVERY_OK accepted=1 refused=1", flush=True)

        # A new T2 is now admitted *after* T1 finished. With a slow replacement
        # startup, the expected T2 journal must remain owned by its new worker:
        # no stale T1 manual recovery is allowed to overwrite it.
        third = cmd(binary, "dashboard", "certificate", "--self-signed",
                    "--state-dir", STATE, capture_output=True, check=True)
        until("new activation owns a different queued/applying journal",
              lambda: phase("queued") or phase("applying"), seconds=15)
        t2 = json.loads((STATE / "certificate-activation.json").read_text())
        assert t2["previous"] is not None and t2["requested"] is not None
        assert t2["requested"]["acme"] is None
        until("new activation T2 completes without stale recovery overwrite",
              lambda: check_service_live(self_signed_der) and phase("active"), seconds=70)
        assert settings().get("acme") is None
        print("NEW_ACTIVATION_JOURNAL_SURVIVES_PRIOR_RECOVERY_OK", flush=True)
    finally:
        slow.unlink(missing_ok=True)
        if 'first' in locals() and first.poll() is None:
            first.kill()
            first.communicate(timeout=10)

    # Killing a recovery process must release the OS lock. The partially
    # restored journal remains usable by a fresh operator after the failure.
    time.sleep(10)  # let normal systemd start-limit window elapse in this busy fixture
    mark_manual_recovery({"acme": None, "certificate": None}, unexpected)
    system("stop", "eztunnel-dashboard.service")
    slow.touch()
    first = None
    try:
        first = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        until("interrupted recovery owns OS lock and durable Restoring state",
              lambda: recovery_lock_is_held() and phase("restoring"), seconds=15)
        first.kill()
        first.communicate(timeout=10)
        assert first.returncode != 0
        until("kernel releases recovery lock after process termination",
              lambda: not recovery_lock_is_held(), seconds=10)
        tx = json.loads((STATE / "certificate-activation.json").read_text())
        assert tx["phase"] == "restoring" and tx["previous"] is not None
    finally:
        slow.unlink(missing_ok=True)
        if first is not None and first.poll() is None:
            first.kill()
            first.communicate(timeout=10)
    # A child systemctl subprocess may have continued to start the service;
    # either way, the new recovery can safely retry without clearing T1 first.
    cmd(binary, "dashboard", "recover-certificate", "--state-dir", STATE,
        check=True, capture_output=True, timeout=65)
    until("recovery after killed operator serves the previous HTTPS identity",
          lambda: phase("recovered") and check_service_live(self_signed_der), seconds=40)
    tx = json.loads((STATE / "certificate-activation.json").read_text())
    assert tx["previous"] is None and tx["requested"] is None
    print("INTERRUPTED_MANUAL_RECOVERY_RETRY_OK", flush=True)


def request_self_signed_in_browser_api(port: int, password: str):
    """Real authenticated HTTP flow: the request process dies on its own restart."""
    def post(path, payload, cookie=None):
        conn = http.client.HTTPSConnection("127.0.0.1", port,
                                         context=ssl._create_unverified_context(), timeout=8)
        headers = {"content-type": "application/json", "x-eztunnel": "1"}
        if cookie:
            headers["Cookie"] = cookie
        try:
            conn.request("POST", path, json.dumps(payload), headers)
            response = conn.getresponse()
            result = response.status, response.getheader("Set-Cookie"), response.read()
            return result
        finally:
            conn.close()
    login_status, cookie, _ = post("/api/login", {"password": password})
    assert login_status == 200 and cookie and cookie.startswith("__Host-ezd="), "Dashboard login failed"
    changed_status, _, body = post("/api/dashboard/certificate", {"mode": "self_signed"}, cookie.split(";", 1)[0])
    assert changed_status == 202, f"certificate HTTP API rejected request: {changed_status} {body[:100]!r}"


def concurrent_certificate_cli_requests(binary: Path, port: int, self_signed_der: bytes):
    """Two *different OS processes* must never own one activation journal."""
    until("previous transient worker collection",
          lambda: system("is-active", "--quiet", WORKER, check=False).returncode != 0,
          seconds=20)
    # Hold admission until both independent CLI processes have started.
    lock_path = STATE / "certificate-activation.lock"
    with open(lock_path, "a+b") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        argv = [str(binary), "dashboard", "certificate", "--self-signed", "--state-dir", str(STATE)]
        first = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        second = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(0.5)
        fcntl.flock(held, fcntl.LOCK_UN)
        first_out, first_err = first.communicate(timeout=25)
        second_out, second_err = second.communicate(timeout=25)
    values = sorted([first.returncode, second.returncode])
    assert values == [0, 1], (
        f"expect exactly one accepted admission, got {values}: "
        f"first={first_out} {first_err}; second={second_out} {second_err}"
    )
    refused = first_err if first.returncode else second_err
    assert "another certificate activation owns the transaction" in refused, refused
    until("single accepted activation reaches live HTTPS and terminal journal",
          lambda: check_service_live(self_signed_der) and phase("active"), seconds=65)
    tx = json.loads((STATE / "certificate-activation.json").read_text())
    assert tx["previous"] is None and tx["requested"] is None, "successful journal must be terminal"
    journal = STATE / "certificate-activation.json"
    assert journal.stat().st_mode & 0o777 == 0o600
    assert not (STATE / "certificate-activation.tmp").exists()
    print("CONCURRENT_INTERPROCESS_ADMISSION_OK accepted=1 refused=1 private_journal=600", flush=True)


def pid():
    return int(system("show", "eztunnel-dashboard.service", "--property=MainPID",
                      "--value").stdout.strip())


def check_service_live(expected: bytes):
    try:
        return system("is-active", "--quiet", "eztunnel-dashboard.service", check=False).returncode == 0 and tls_probe(settings()["port"]) == expected
    except Exception:
        return False


def main(binary: Path):
    if not MARKER.exists() or not os.path.samefile("/proc/1/exe", "/usr/lib/systemd/systemd"):
        raise SystemExit("refusing to execute outside the specifically marked isolated systemd container")
    if os.geteuid() != 0 or not binary.is_file():
        raise SystemExit("run as root with a verified candidate binary")
    existing = system("cat", "eztunnel-dashboard.service", check=False)
    if existing.returncode == 0 or UNIT.exists() or WRAPPER.exists() or STATE.exists():
        raise SystemExit("refusing to overwrite an existing test or service state")

    STATE.mkdir(mode=0o700)
    WRAPPER.parent.mkdir(parents=True, exist_ok=True)
    try:
        created = cmd(binary, "dashboard", "setup", "--no-service", "--state-dir", STATE,
                      capture_output=True)
        assert created.returncode == 0
        password_match = re.search(r"Password:\s*([A-Za-z0-9]+)", created.stdout)
        assert password_match, "setup did not provide its one-time QA password"
        password = password_match.group(1)
        initial = settings()
        old_cert = (STATE / "cert.der").read_bytes()
        port = initial["port"]
        # Controlled failure injection in an isolated fixture, not product code.
        WRAPPER.write_text(
            "#!/bin/sh\n"
            f"if grep -q 'fail.example.test' '{STATE}/settings.json'; then\n"
            f"  if [ -f '{STATE}/supersede-next.json' ]; then mv '{STATE}/supersede-next.json' '{STATE}/settings.json'; chmod 600 '{STATE}/settings.json'; fi\n"
            "  echo 'intentional test-only replacement startup failure' >&2\n"
            "  exit 66\n"
            "fi\n"
            f"if [ -f '{STATE}/block-superseded' ]; then echo 'intentional blocked superseded replacement' >&2; exit 67; fi\n"
            f"if [ -f '{STATE}/slow-start' ]; then sleep 3; fi\n"
            f"exec '{binary}' dashboard serve --state-dir '{STATE}'\n"
        )
        WRAPPER.chmod(0o755)
        UNIT.write_text(
            "[Unit]\nDescription=Isolated EZTunnel R1-R certificate QA dashboard\nAfter=network-online.target\n"
            "[Service]\nType=simple\n"
            f"ExecStart={WRAPPER}\n"
            "Restart=always\nRestartSec=1\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )
        system("daemon-reload")
        system("start", "eztunnel-dashboard.service")
        until("initial HTTPS readiness", lambda: check_service_live(old_cert), seconds=30)
        pid_before = pid()
        print(f"INITIAL_OK pid={pid_before} port={port} self_signed_sha256={hashlib.sha256(old_cert).hexdigest()[:16]}", flush=True)

        first, first_der = cert_for("ok.example.test")
        assert first_der != old_cert
        transaction({"acme": None, "certificate": None}, first)
        activate(binary)
        until("first activation outcome", lambda: phase("active"), seconds=75)
        until("new HTTPS identity after real systemd restart",
              lambda: check_service_live(first_der), seconds=15)
        pid_active = pid()
        assert pid_active != pid_before, "previous Dashboard process was not terminated by systemd"
        assert state_of_cert(first, first_der)
        print(f"ACTIVATED_OK pid={pid_active} cert_sha256={hashlib.sha256(first_der).hexdigest()[:16]}", flush=True)

        # Unlike direct worker invocation, this uses the exact authenticated API
        # path reported by the reviewer. It restarts the *requesting* service.
        request_self_signed_in_browser_api(port, password)
        until("self-signed certificate and durable activation result from Dashboard HTTP API",
              lambda: check_service_live(old_cert) and settings().get("acme") is None and phase("active"),
              seconds=65)
        pid_after_api = pid()
        assert pid_after_api != pid_active, "the API's initiating Dashboard PID was not terminated"
        print(f"AUTHENTICATED_API_ACTIVATION_OK old_pid={pid_active} new_pid={pid_after_api}", flush=True)

        # Return to the first valid certificate before injecting a broken startup.
        transaction({"acme": None, "certificate": None}, first)
        activate(binary)
        until("first valid certificate reactivated", lambda: check_service_live(first_der) and phase("active"), seconds=60)

        bad, bad_der = cert_for("fail.example.test")
        transaction(first, bad)
        activate(binary)
        recovered = until("failed replacement startup auto-recovery",
                          lambda: phase("recovered"), seconds=120)
        assert "previous configuration was automatically restored" in recovered["detail"]
        until("old working certificate restored by independent worker",
              lambda: check_service_live(first_der), seconds=20)
        assert not check_service_live(bad_der)
        assert state_of_cert(first, first_der)
        print(f"ROLLED_BACK_OK pid={pid()} previous_sha256={hashlib.sha256(first_der).hexdigest()[:16]}", flush=True)

        # Inactive is not success. The CLI must persist pending-restart, not start
        # a stopped systemd unit or assert that the replacement is active.
        system("stop", "eztunnel-dashboard.service")
        changed = cmd(binary, "dashboard", "certificate", "--self-signed", "--state-dir", STATE,
                      check=True, capture_output=True)
        assert phase("manual"), "inactive service was incorrectly marked active"
        assert system("is-active", "--quiet", "eztunnel-dashboard.service", check=False).returncode != 0
        system("start", "eztunnel-dashboard.service")
        until("manual pending-restart selection applies after an actual start",
              lambda: check_service_live(old_cert), seconds=30)
        print("INACTIVE_PENDING_RESTART_OK", flush=True)

        # Simulate a killed transient worker *after* it changed the persisted
        # settings but before completing activation/rollback, then recover by CLI.
        altered, _ = cert_for("interrupted.example.test")
        transaction({"acme": None, "certificate": None}, altered)
        s = settings()
        s["acme"] = altered["acme"]
        s["acme_certificate"] = altered["certificate"]
        (STATE / "settings.json").write_text(json.dumps(s))
        (STATE / "settings.json").chmod(0o600)
        txpath = STATE / "certificate-activation.json"
        tx = json.loads(txpath.read_text())
        tx["phase"] = "applying"
        txpath.write_text(json.dumps(tx))
        txpath.chmod(0o600)
        cmd(binary, "dashboard", "recover-certificate", "--state-dir", STATE,
            capture_output=True)
        assert phase("recovered")
        until("operator recovery restores previous HTTPS identity",
              lambda: check_service_live(old_cert), seconds=30)
        print("INTERRUPTED_WORKER_MANUAL_RECOVERY_OK", flush=True)

        # Independently exercise the two-process admission race at the end of
        # acceptance: the earlier failed-startup scenario has aged out of
        # systemd's default restart rate window. No product limits are changed.
        transaction({"acme": None, "certificate": None}, first)
        activate(binary)
        until("certificate ready before independent CLI race",
              lambda: check_service_live(first_der) and phase("active"), seconds=65)
        (STATE / "slow-start").touch()
        try:
            concurrent_certificate_cli_requests(binary, port, old_cert)
        finally:
            (STATE / "slow-start").unlink(missing_ok=True)
        # These tests change only the marked QA unit and its disposable state.
        # Allow the prior tightly packed restarts to leave systemd's default
        # start-rate interval before deliberate supersession failure injection.
        time.sleep(10)
        latest, latest_der = supersession_scenarios(binary)
        concurrent_manual_recovery_scenarios(binary, latest, latest_der, old_cert)
        print("SYSTEMD_CERTIFICATE_ACCEPTANCE_PASS", flush=True)
    finally:
        # Never tear down the test Dashboard service while an independent worker
        # still owns its systemd restart/recovery transaction.
        until("transient activation unit to finish before fixture cleanup",
              lambda: system("is-active", "--quiet", WORKER, check=False).returncode != 0,
              seconds=120)
        system("stop", "eztunnel-dashboard.service", check=False)
        if UNIT.exists():
            UNIT.unlink()
            system("daemon-reload", check=False)
        if WRAPPER.exists():
            WRAPPER.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("/usr/local/bin/eztunnel"))
    args = parser.parse_args()
    main(args.binary)
