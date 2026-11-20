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
            "  echo 'intentional test-only replacement startup failure' >&2\n"
            "  exit 66\n"
            "fi\n"
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
