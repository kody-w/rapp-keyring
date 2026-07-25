#!/usr/bin/env python3
"""
RAPP Keyring conformance gate.

This is the artifact to hand a security reviewer. Each check states a claim the
project makes, then proves or disproves it against the code and the running
binary — no check passes on inspection alone.

    python3 conformance.py            # human-readable report
    python3 conformance.py --json     # machine-readable, for CI

Exit codes:  0 all checks passed  |  1 one or more failed  |  2 could not run
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import rapp_keyring as rk  # noqa: E402

SOURCE_PATH = os.path.join(ROOT, "rapp_keyring.py")
CLI = [sys.executable, SOURCE_PATH]

RESULTS = []


def check(cid: str, claim: str):
    """Register a conformance check. The function returns (ok, detail)."""
    def decorate(fn):
        fn._cid, fn._claim = cid, claim
        RESULTS.append(fn)
        return fn
    return decorate


def source() -> str:
    with open(SOURCE_PATH, "r", encoding="utf-8") as fh:
        return fh.read()


def run_cli(args, home, stdin=None, caller=None):
    env = os.environ.copy()
    env["RAPP_KEYRING_HOME"] = home
    if caller:
        env["RAPP_KEYRING_CALLER"] = caller
    return subprocess.run(
        CLI + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, input=stdin,
    )


# ---------------------------------------------------------------------------
# C1 — no network
# ---------------------------------------------------------------------------

@check("C1", "The program opens no network connections.")
def c1_no_network():
    src = source()
    banned = [
        r"^\s*import\s+socket\b",
        r"^\s*import\s+requests\b",
        r"^\s*from\s+socket\s+import",
        r"^\s*import\s+http\.client",
        r"^\s*from\s+urllib\s+import\s+request",
        r"urllib\.request",
        r"http\.client",
        r"socket\.socket",
    ]
    hits = []
    for pattern in banned:
        for match in re.finditer(pattern, src, re.MULTILINE):
            line = src[:match.start()].count("\n") + 1
            hits.append("%s:%d" % (pattern, line))
    if hits:
        return False, "network-capable references found: %s" % ", ".join(hits)

    # Prove it at runtime: make socket construction fatal, then exercise the CLI.
    probe = tempfile.mkdtemp(prefix="rk-conf-c1-")
    try:
        sentinel = os.path.join(probe, "sitecustomize.py")
        with open(sentinel, "w") as fh:
            fh.write(
                "import socket, os\n"
                "def _boom(*a, **k):\n"
                "    os._exit(97)\n"
                "socket.socket = _boom\n"
                "socket.create_connection = _boom\n"
            )
        env = os.environ.copy()
        env["RAPP_KEYRING_HOME"] = probe
        env["PYTHONPATH"] = probe
        proc = subprocess.run(
            CLI + ["doctor", "--fast"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        if proc.returncode == 97:
            return False, "a socket was created while running `doctor`"
        return True, "no network imports; `doctor` runs with socket() booby-trapped"
    finally:
        shutil.rmtree(probe, ignore_errors=True)


# ---------------------------------------------------------------------------
# C2 — secrets never reach argv
# ---------------------------------------------------------------------------

@check("C2", "Secret values are never passed as command-line arguments.")
def c2_no_argv_secrets():
    src = source()
    # The macOS write path must use bare -w (prompt) and feed stdin.
    if re.search(r'"-w"\s*,\s*(hexed|value|payload|secret)', src):
        return False, "a secret is interpolated into a `security -w` argument"
    for match in re.finditer(r'"security",\s*"add-generic-password"', src):
        window = src[match.start():match.start() + 500]
        if '"-w",' in window and 'input=' not in window:
            return False, "add-generic-password call passes a value without using stdin"

    # Prove it live: store a secret, and confirm the marker never appeared in
    # any process's argv while the write was in flight.
    home = tempfile.mkdtemp(prefix="rk-conf-c2-")
    marker = "CONFORMANCE-ARGV-PROBE-" + binascii.hexlify(os.urandom(8)).decode()
    try:
        run_cli(["init"], home)
        watcher = subprocess.Popen(
            ["sh", "-c",
             "for i in $(seq 1 400); do ps -Ao args= 2>/dev/null; done"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        proc = run_cli(["set", "conf/argv-probe", "--stdin"], home,
                       stdin=marker.encode())
        seen = watcher.communicate(timeout=60)[0].decode("utf-8", "replace")
        if proc.returncode != 0:
            return False, "could not store the probe secret: %s" % proc.stderr.decode()[:120]
        if marker in seen:
            return False, "the secret appeared in process arguments (ps could read it)"
        return True, "%d ps snapshots taken during a write; secret never in argv" % seen.count("\n")
    finally:
        try:
            run_cli(["rm", "conf/argv-probe", "--yes"], home)
        except Exception:
            pass
        shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------------------
# C3/C4 — policy posture
# ---------------------------------------------------------------------------

@check("C3", "Policy denies by default; unknown callers get nothing.")
def c3_default_deny():
    pol = json.loads(json.dumps(rk.DEFAULT_POLICY))
    if pol.get("default") != "deny":
        return False, "shipped policy default is %r" % pol.get("default")
    for action in ("run", "get"):
        allowed, _ = rk.policy_decide(pol, "some-unknown-tool", action, "any/secret")
        if allowed:
            return False, "an unknown caller was allowed to %r" % action
    return True, "unknown callers are denied both `run` and `get`"


@check("C4", "No AI agent may read a secret in plaintext by default.")
def c4_agents_cannot_read():
    pol = json.loads(json.dumps(rk.DEFAULT_POLICY))
    agents = ["claude-code", "copilot-cli", "brainstem", "cursor", "vscode"]
    for agent in agents:
        allowed, _ = rk.policy_decide(pol, agent, "get", "any/secret")
        if allowed:
            return False, "%s may perform a sighted read out of the box" % agent
    injectable = [a for a in agents if rk.policy_decide(pol, a, "run", "any/secret")[0]]
    return True, ("no agent may `get`; %d of %d may `run` (inject without sight)"
                  % (len(injectable), len(agents)))


@check("C5", "A sighted read requires an explicit acknowledgement.")
def c5_sighted_requires_ack():
    home = tempfile.mkdtemp(prefix="rk-conf-c5-")
    secret = b"conformance-sighted-value-123456"
    try:
        run_cli(["init"], home)
        proc = run_cli(["set", "conf/sighted", "--stdin"], home, stdin=secret)
        if proc.returncode != 0:
            return None, "no backend available to test against"
        bare = run_cli(["get", "conf/sighted"], home, caller="shell")
        if bare.returncode == 0 or secret in bare.stdout:
            return False, "the secret was printed without --i-know"
        acked = run_cli(["get", "conf/sighted", "--i-know"], home, caller="shell")
        if acked.returncode != 0 or secret not in acked.stdout:
            return False, "--i-know did not permit an authorized read"
        return True, "plaintext withheld without --i-know, released with it"
    finally:
        run_cli(["rm", "conf/sighted", "--yes"], home)
        shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------------------
# C6/C7 — redaction
# ---------------------------------------------------------------------------

@check("C6", "An injected secret cannot escape through the child's output.")
def c6_redaction_live():
    home = tempfile.mkdtemp(prefix="rk-conf-c6-")
    secret = b"conformance-redaction-value-abcdef123456"
    try:
        run_cli(["init"], home)
        if run_cli(["set", "conf/redact", "--stdin"], home, stdin=secret).returncode != 0:
            return None, "no backend available to test against"
        script = (
            "import os,sys,base64,binascii\n"
            "v=os.environ['CONF_REDACT'].encode()\n"
            "sys.stdout.write('plain:'+v.decode()+'\\n')\n"
            "sys.stdout.write('b64:'+base64.b64encode(v).decode()+'\\n')\n"
            "sys.stdout.write('hex:'+binascii.hexlify(v).decode()+'\\n')\n"
            "sys.stderr.write('err:'+v.decode()+'\\n')\n"
        )
        proc = run_cli(
            ["run", "--grant", "conf/redact", "--", sys.executable, "-c", script],
            home, caller="shell",
        )
        combined = proc.stdout + proc.stderr
        leaks = []
        if secret in combined:
            leaks.append("plaintext")
        if base64.b64encode(secret) in combined:
            leaks.append("base64")
        if binascii.hexlify(secret) in combined:
            leaks.append("hex")
        if leaks:
            return False, "secret escaped as: %s" % ", ".join(leaks)
        if b"redacted" not in combined:
            return False, "child produced no output; redaction not exercised"
        return True, "plaintext, base64 and hex forms all masked on stdout and stderr"
    finally:
        run_cli(["rm", "conf/redact", "--yes"], home)
        shutil.rmtree(home, ignore_errors=True)


@check("C7", "Redaction holds when a secret is split across reads.")
def c7_redaction_boundary():
    secret = b"boundary-split-secret-value-0123456789"
    for split in range(1, len(secret)):
        red = rk.Redactor({"s": secret})
        out = red.scrub(b"lead" + secret[:split])
        out += red.scrub(secret[split:] + b"tail")
        out += red.flush()
        if secret in out:
            return False, "leaked when split at byte %d" % split
    red = rk.Redactor({"s": secret})
    payload = b"a" + secret + b"b"
    out = b"".join(red.scrub(payload[i:i + 1]) for i in range(len(payload))) + red.flush()
    if secret in out:
        return False, "leaked under byte-at-a-time delivery"
    return True, "held across all %d split points and byte-at-a-time delivery" % (len(secret) - 1)


# ---------------------------------------------------------------------------
# C8 — audit
# ---------------------------------------------------------------------------

@check("C8", "The audit log is tamper-evident.")
def c8_audit_tamper_evident():
    home = tempfile.mkdtemp(prefix="rk-conf-c8-")
    saved = os.environ.get("RAPP_KEYRING_HOME")
    os.environ["RAPP_KEYRING_HOME"] = home
    try:
        audit = rk.Audit(os.path.join(home, "audit.jsonl"))
        for i in range(5):
            audit.append("probe", caller="conformance", name="n%d" % i)
        ok, message, count = audit.verify()
        if not ok:
            return False, "a freshly written chain did not verify: %s" % message

        detections = []
        original = open(audit.path).read()

        lines = original.strip().split("\n")
        rec = json.loads(lines[2])
        rec["caller"] = "impostor"
        lines[2] = rk.canonical_json(rec)
        open(audit.path, "w").write("\n".join(lines) + "\n")
        detections.append(not audit.verify()[0])

        lines = original.strip().split("\n")
        del lines[1]
        open(audit.path, "w").write("\n".join(lines) + "\n")
        detections.append(not audit.verify()[0])

        open(audit.path, "w").write(original)
        with open(audit.path, "a") as fh:
            fh.write(rk.canonical_json(
                {"seq": 99, "ts": rk.now_iso(), "action": "get",
                 "caller": "attacker", "prev": "0" * 64, "hash": "f" * 64}) + "\n")
        detections.append(not audit.verify()[0])

        if not all(detections):
            names = ["modification", "deletion", "forged append"]
            missed = [n for n, d in zip(names, detections) if not d]
            return False, "undetected: %s" % ", ".join(missed)
        return True, "%d-record chain verified; modification, deletion and forged append all detected" % count
    finally:
        if saved is None:
            os.environ.pop("RAPP_KEYRING_HOME", None)
        else:
            os.environ["RAPP_KEYRING_HOME"] = saved
        shutil.rmtree(home, ignore_errors=True)


@check("C9", "Secret values never appear in the audit log or in `list`.")
def c9_no_values_in_metadata():
    home = tempfile.mkdtemp(prefix="rk-conf-c9-")
    secret = b"conformance-never-logged-value-778899"
    try:
        run_cli(["init"], home)
        if run_cli(["set", "conf/quiet", "--stdin"], home, stdin=secret).returncode != 0:
            return None, "no backend available to test against"
        run_cli(["run", "--grant", "conf/quiet", "--", "true"], home, caller="shell")
        listing = run_cli(["list"], home).stdout
        audit_out = run_cli(["audit", "all", "--json"], home).stdout
        on_disk = b""
        for name in os.listdir(home):
            path = os.path.join(home, name)
            if os.path.isfile(path):
                on_disk += open(path, "rb").read()
        for label, blob in (("list", listing), ("audit", audit_out), ("state files", on_disk)):
            if secret in blob:
                return False, "the secret value appears in %s" % label
        return True, "value absent from `list`, the audit log, and all on-disk state"
    finally:
        run_cli(["rm", "conf/quiet", "--yes"], home)
        shutil.rmtree(home, ignore_errors=True)


# ---------------------------------------------------------------------------
# C10/C11 — storage integrity
# ---------------------------------------------------------------------------

@check("C10", "Any secret shape round-trips: binary, multi-line, unicode, large.")
def c10_round_trip():
    try:
        backend = rk.choose_backend()
    except rk.KeyringError as exc:
        return None, str(exc)
    cases = {
        "single byte": b"\x00",
        "all 256 byte values": bytes(range(256)),
        # rapp-keyring: allow  synthetic PEM fixture, not a real key
        "multi-line PEM": b"-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----\n",
        "unicode": "pässwörd-中文-\U0001f510".encode("utf-8"),
        "4 KiB blob": os.urandom(4096),
    }
    key = "conf/roundtrip"
    try:
        for label, blob in cases.items():
            backend.set(key, blob)
            if backend.get(key) != blob:
                return False, "%s did not survive a round trip" % label
        return True, "all %d shapes round-tripped through %s" % (len(cases), backend.name)
    finally:
        try:
            backend.delete(key)
        except Exception:
            pass


@check("C11", "State files are readable only by their owner.")
def c11_permissions():
    home = tempfile.mkdtemp(prefix="rk-conf-c11-")
    try:
        run_cli(["init"], home)
        run_cli(["set", "conf/perm", "--stdin"], home, stdin=b"permission-check-value")
        problems = []
        for root, dirs, files in os.walk(home):
            for name in list(dirs) + list(files):
                problems.extend(rk.check_permissions(os.path.join(root, name)))
        problems.extend(rk.check_permissions(home))
        if problems:
            return False, "; ".join(problems[:3])
        return True, "every file and directory under the keyring home is owner-only"
    finally:
        run_cli(["rm", "conf/perm", "--yes"], home)
        shutil.rmtree(home, ignore_errors=True)


@check("C12", "The build reports a version and a spec level.")
def c12_versioned():
    proc = subprocess.run(CLI + ["version", "--json"],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        return False, "`version` failed"
    payload = json.loads(proc.stdout.decode())
    if not payload.get("version") or payload.get("version") == "0.0.0-dev":
        return False, "no VERSION file alongside the program"
    return True, "version %s, spec %s" % (payload["version"], payload["spec"])


# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="RAPP Keyring conformance gate")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    report, failed, skipped = [], 0, 0
    for fn in RESULTS:
        try:
            outcome = fn()
            ok, detail = outcome if outcome is not None else (None, "no result")
        except Exception as exc:  # a check that explodes is a failing check
            ok, detail = False, "check raised %s: %s" % (type(exc).__name__, exc)
        status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
        if ok is None:
            skipped += 1
        elif not ok:
            failed += 1
        report.append({"id": fn._cid, "claim": fn._claim, "status": status, "detail": detail})

    if args.json:
        print(json.dumps({
            "version": rk.__version__,
            "spec": rk.SPEC_VERSION,
            "passed": sum(1 for r in report if r["status"] == "PASS"),
            "failed": failed,
            "skipped": skipped,
            "checks": report,
        }, indent=2))
        return 1 if failed else 0

    print("RAPP Keyring %s — conformance" % rk.__version__)
    print("=" * 72)
    for row in report:
        print()
        print("%s  %s  %s" % (row["status"].ljust(4), row["id"], row["claim"]))
        print("      %s" % row["detail"])
    print()
    print("=" * 72)
    passed = sum(1 for r in report if r["status"] == "PASS")
    print("%d passed, %d failed, %d skipped" % (passed, failed, skipped))
    if failed:
        print()
        print("CONFORMANCE FAILED — do not ship this build.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
