#!/usr/bin/env python3
"""
RAPP Keyring test suite. Standard library only; no network.

Pure-logic tests run everywhere. Tests that need a real credential store are
skipped when no backend is available, so the suite is meaningful on a headless
CI runner and thorough on a developer machine.

    python3 tests/test_keyring.py -v
"""

import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import rapp_keyring as rk  # noqa: E402

CLI = [sys.executable, os.path.join(ROOT, "rapp_keyring.py")]


def backend_available() -> bool:
    try:
        rk.choose_backend()
        return True
    except rk.KeyringError:
        return False


class TempHome(unittest.TestCase):
    """Every test gets an isolated RAPP_KEYRING_HOME."""

    def setUp(self):
        self.home = tempfile.mkdtemp(prefix="rk-test-")
        self._saved = os.environ.get("RAPP_KEYRING_HOME")
        os.environ["RAPP_KEYRING_HOME"] = self.home

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("RAPP_KEYRING_HOME", None)
        else:
            os.environ["RAPP_KEYRING_HOME"] = self._saved
        shutil.rmtree(self.home, ignore_errors=True)

    def cli(self, *args, **kwargs):
        env = os.environ.copy()
        env["RAPP_KEYRING_HOME"] = self.home
        env.update(kwargs.pop("env", {}))
        return subprocess.run(
            CLI + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            input=kwargs.pop("input", None),
        )


# ---------------------------------------------------------------- name rules

class TestNames(unittest.TestCase):
    def test_env_name_derivation(self):
        cases = {
            "azure/storage-key": "AZURE_STORAGE_KEY",
            "github/pat": "GITHUB_PAT",
            "a.b.c": "A_B_C",
            "simple": "SIMPLE",
            "with-dash": "WITH_DASH",
        }
        for name, expected in cases.items():
            self.assertEqual(rk.env_name_for(name), expected, name)

    def test_env_name_never_starts_with_digit(self):
        self.assertTrue(rk.env_name_for("9lives")[0].isalpha())

    def test_valid_names_accepted(self):
        for name in ("azure/storage-key", "a", "x_1.2-3/y"):
            self.assertEqual(rk.validate_name(name), name)

    def test_invalid_names_rejected(self):
        for name in ("", "../etc/passwd", "has space", "a" * 200, "/leading"):
            with self.assertRaises(rk.KeyringError, msg=name):
                rk.validate_name(name)

    def test_traversal_rejected_even_when_charset_is_legal(self):
        with self.assertRaises(rk.KeyringError):
            rk.validate_name("a/../../b")


# ----------------------------------------------------------------- redaction

class TestRedactor(unittest.TestCase):
    SECRET = b"SuperSecret-Value-12345"

    def redact(self, data: bytes, secrets=None) -> bytes:
        red = rk.Redactor(secrets or {"test/key": self.SECRET})
        return red.scrub(data) + red.flush()

    def test_plain_occurrence_masked(self):
        out = self.redact(b"before " + self.SECRET + b" after")
        self.assertNotIn(self.SECRET, out)
        self.assertIn(b"redacted:test/key", out)
        self.assertIn(b"before ", out)
        self.assertIn(b" after", out)

    def test_base64_variant_masked(self):
        out = self.redact(b"tok " + base64.b64encode(self.SECRET))
        self.assertNotIn(base64.b64encode(self.SECRET), out)

    def test_hex_variant_masked(self):
        import binascii
        out = self.redact(b"hex " + binascii.hexlify(self.SECRET))
        self.assertNotIn(binascii.hexlify(self.SECRET), out)

    def test_url_encoded_variant_masked(self):
        from urllib.parse import quote
        encoded = quote(self.SECRET.decode(), safe="").encode()
        if encoded != self.SECRET:  # only meaningful if encoding changes it
            out = self.redact(b"url " + encoded)
            self.assertNotIn(encoded, out)

    def test_split_across_chunk_boundary(self):
        """The whole reason scrub() holds back a tail buffer."""
        red = rk.Redactor({"test/key": self.SECRET})
        first, second = self.SECRET[:10], self.SECRET[10:]
        out = red.scrub(b"lead" + first)
        out += red.scrub(second + b"tail")
        out += red.flush()
        self.assertNotIn(self.SECRET, out)
        self.assertIn(b"redacted:test/key", out)

    def test_byte_by_byte_delivery(self):
        """Worst case: one byte per read."""
        red = rk.Redactor({"test/key": self.SECRET})
        payload = b"xx" + self.SECRET + b"yy"
        out = b"".join(red.scrub(payload[i:i + 1]) for i in range(len(payload)))
        out += red.flush()
        self.assertNotIn(self.SECRET, out)

    def test_nothing_lost_when_no_secret_present(self):
        payload = b"a" * 1000 + b"needle" + b"b" * 1000
        self.assertEqual(self.redact(payload), payload)

    def test_very_short_secrets_are_not_masked(self):
        """Masking a 2-char value would destroy unrelated output."""
        red = rk.Redactor({"tiny": b"ab"})
        self.assertEqual(red.scrub(b"abcabc") + red.flush(), b"abcabc")

    def test_multiple_secrets_all_masked(self):
        a, b = b"AAAA-secret-one", b"BBBB-secret-two"
        red = rk.Redactor({"one": a, "two": b})
        out = red.scrub(a + b" and " + b) + red.flush()
        self.assertNotIn(a, out)
        self.assertNotIn(b, out)

    def test_overlapping_secrets_longest_wins(self):
        long_secret = b"abcdef123456789"
        short_secret = b"abcdef12"
        red = rk.Redactor({"long": long_secret, "short": short_secret})
        out = red.scrub(long_secret) + red.flush()
        self.assertNotIn(long_secret, out)
        self.assertIn(b"redacted:long", out)

    def test_large_stream_throughput(self):
        red = rk.Redactor({"test/key": self.SECRET})
        out = b""
        for _ in range(50):
            out += red.scrub(b"z" * 10000)
        out += red.scrub(b"z" * 100 + self.SECRET)
        out += red.flush()
        self.assertNotIn(self.SECRET, out)
        self.assertEqual(out.count(b"z"), 50 * 10000 + 100)


# --------------------------------------------------------------------- audit

class TestAudit(TempHome):
    def test_chain_verifies(self):
        audit = rk.Audit()
        for i in range(5):
            audit.append("test", caller="unit", name="n%d" % i)
        ok, message, count = audit.verify()
        self.assertTrue(ok, message)
        self.assertEqual(count, 5)

    def test_sequence_is_monotonic(self):
        audit = rk.Audit()
        for _ in range(4):
            audit.append("test", caller="unit")
        seqs = [r["seq"] for r in audit.records()]
        self.assertEqual(seqs, [1, 2, 3, 4])

    def test_modified_record_detected(self):
        audit = rk.Audit()
        for i in range(3):
            audit.append("test", caller="unit", name="n%d" % i)
        lines = open(audit.path).read().strip().split("\n")
        rec = json.loads(lines[1])
        rec["caller"] = "impostor"
        lines[1] = rk.canonical_json(rec)
        open(audit.path, "w").write("\n".join(lines) + "\n")
        ok, message, _ = audit.verify()
        self.assertFalse(ok)
        self.assertIn("2", message)

    def test_deleted_record_detected(self):
        audit = rk.Audit()
        for i in range(4):
            audit.append("test", caller="unit", name="n%d" % i)
        lines = open(audit.path).read().strip().split("\n")
        del lines[1]
        open(audit.path, "w").write("\n".join(lines) + "\n")
        ok, _, _ = audit.verify()
        self.assertFalse(ok)

    def test_appended_forgery_detected(self):
        """A forged record cannot be appended without the real previous hash."""
        audit = rk.Audit()
        audit.append("test", caller="unit")
        forged = {"seq": 2, "ts": rk.now_iso(), "action": "get", "caller": "attacker",
                  "prev": "0" * 64, "hash": "f" * 64}
        with open(audit.path, "a") as fh:
            fh.write(rk.canonical_json(forged) + "\n")
        ok, _, _ = audit.verify()
        self.assertFalse(ok)

    def test_no_secret_value_in_audit(self):
        audit = rk.Audit()
        audit.append("set", caller="unit", name="a/b", size=42)
        blob = open(audit.path).read()
        self.assertIn("a/b", blob)
        self.assertNotIn("42424242", blob)


# -------------------------------------------------------------------- policy

class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.pol = json.loads(json.dumps(rk.DEFAULT_POLICY))

    def test_default_denies_unknown_caller(self):
        allowed, _ = rk.policy_decide(self.pol, "random-tool", "run", "azure/key")
        self.assertFalse(allowed)

    def test_agent_may_run_but_not_get(self):
        run_ok, _ = rk.policy_decide(self.pol, "claude-code", "run", "azure/key")
        get_ok, _ = rk.policy_decide(self.pol, "claude-code", "get", "azure/key")
        self.assertTrue(run_ok, "agents should be able to inject")
        self.assertFalse(get_ok, "agents must not read plaintext by default")

    def test_glob_grant(self):
        self.pol["callers"]["ci"] = {"run": ["azure/*"], "get": []}
        self.assertTrue(rk.policy_decide(self.pol, "ci", "run", "azure/one")[0])
        self.assertFalse(rk.policy_decide(self.pol, "ci", "run", "github/pat")[0])

    def test_deny_beats_allow(self):
        self.pol["callers"]["ci"] = {"run": ["*"], "get": [], "deny": ["prod/*"]}
        self.assertTrue(rk.policy_decide(self.pol, "ci", "run", "dev/key")[0])
        self.assertFalse(rk.policy_decide(self.pol, "ci", "run", "prod/key")[0])

    def test_explicit_entry_does_not_fall_through_to_wildcard(self):
        self.pol["callers"]["*"] = {"run": ["*"], "get": ["*"]}
        self.pol["callers"]["locked"] = {"run": [], "get": []}
        self.assertFalse(rk.policy_decide(self.pol, "locked", "run", "anything")[0])


# ------------------------------------------------------------- CLI behaviour

class TestCLI(TempHome):
    def test_version(self):
        proc = self.cli("version", "--json")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("version", json.loads(proc.stdout.decode()))

    def test_help_without_args_is_not_a_crash(self):
        proc = self.cli()
        self.assertEqual(proc.returncode, 1)
        self.assertIn(b"rapp-keyring", proc.stdout + proc.stderr)

    def test_run_without_command_is_a_clear_error(self):
        proc = self.cli("run", "--grant", "x")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"--", proc.stderr)

    def test_unknown_secret_lists_known_ones(self):
        self.cli("init")
        proc = self.cli("run", "--grant", "does/not-exist", "--", "true")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"no stored secret matches", proc.stderr)

    def test_scan_reports_kind_not_value(self):
        probe = os.path.join(self.home, "leaky.json")
        with open(probe, "w") as fh:
            fh.write('{"conn":"AccountKey=' + "A" * 60 + '=="}\n')
        proc = self.cli("scan", probe, "--json")
        payload = json.loads(proc.stdout.decode())
        self.assertEqual(len(payload["findings"]), 1)
        self.assertNotIn("A" * 60, proc.stdout.decode())
        self.assertIn("Azure", payload["findings"][0]["kind"])

    def test_scan_pragma_suppresses_and_records_reason(self):
        probe = os.path.join(self.home, "fixture.py")
        with open(probe, "w") as fh:
            fh.write("# rapp-keyring: allow test fixture, not a real key\n")
            fh.write('KEY = "AccountKey=' + "A" * 60 + '=="\n')
        proc = self.cli("scan", probe, "--json")
        payload = json.loads(proc.stdout.decode())
        self.assertEqual(payload["findings"], [])
        self.assertEqual(len(payload["suppressed"]), 1)
        self.assertIn("test fixture", payload["suppressed"][0]["reason"])
        self.assertEqual(proc.returncode, 0)

    def test_scan_no_pragma_flag_overrides_suppression(self):
        probe = os.path.join(self.home, "fixture.py")
        with open(probe, "w") as fh:
            fh.write('KEY = "AccountKey=' + "A" * 60 + '==" # rapp-keyring: allow fixture\n')
        self.assertEqual(self.cli("scan", probe).returncode, 0)
        self.assertNotEqual(self.cli("scan", probe, "--no-pragma").returncode, 0)

    def test_scan_clean_file_exits_zero(self):
        probe = os.path.join(self.home, "clean.json")
        with open(probe, "w") as fh:
            fh.write('{"hello":"world"}\n')
        self.assertEqual(self.cli("scan", probe).returncode, 0)


@unittest.skipUnless(backend_available(), "no credential backend on this machine")
class TestRoundTrip(TempHome):
    SECRET = b"integration-secret-value-9876543210"
    NAME = "test/rapp-keyring-integration"

    def setUp(self):
        super().setUp()
        self.cli("init")

    def tearDown(self):
        try:
            rk.choose_backend().delete(self.NAME)
        except Exception:
            pass
        super().tearDown()

    def test_set_then_inject(self):
        proc = self.cli("set", self.NAME, "--stdin", input=self.SECRET)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())

        proc = self.cli(
            "run", "--grant", self.NAME, "--",
            sys.executable, "-c",
            "import os;print(len(os.environ['%s']))" % rk.env_name_for(self.NAME),
            env={"RAPP_KEYRING_CALLER": "shell"},
        )
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(proc.stdout.decode().strip(), str(len(self.SECRET)))

    def test_child_cannot_leak_to_stdout(self):
        self.cli("set", self.NAME, "--stdin", input=self.SECRET)
        proc = self.cli(
            "run", "--grant", self.NAME, "--",
            sys.executable, "-c",
            "import os;print(os.environ['%s'])" % rk.env_name_for(self.NAME),
            env={"RAPP_KEYRING_CALLER": "shell"},
        )
        self.assertNotIn(self.SECRET, proc.stdout)
        self.assertIn(b"redacted", proc.stdout)

    def test_exit_code_propagates(self):
        self.cli("set", self.NAME, "--stdin", input=self.SECRET)
        proc = self.cli(
            "run", "--grant", self.NAME, "--",
            sys.executable, "-c", "import sys;sys.exit(42)",
            env={"RAPP_KEYRING_CALLER": "shell"},
        )
        self.assertEqual(proc.returncode, 42)

    def test_agent_get_is_denied(self):
        self.cli("set", self.NAME, "--stdin", input=self.SECRET)
        proc = self.cli("get", self.NAME, "--i-know",
                        env={"RAPP_KEYRING_CALLER": "claude-code"})
        self.assertEqual(proc.returncode, 3)
        self.assertNotIn(self.SECRET, proc.stdout)

    def test_get_requires_acknowledgement(self):
        self.cli("set", self.NAME, "--stdin", input=self.SECRET)
        proc = self.cli("get", self.NAME, env={"RAPP_KEYRING_CALLER": "shell"})
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(self.SECRET, proc.stdout)

    def test_binary_secret_round_trips(self):
        blob = bytes(range(256))
        backend = rk.choose_backend()
        backend.set(self.NAME, blob)
        self.assertEqual(backend.get(self.NAME), blob)

    def test_multiline_secret_round_trips(self):
        blob = b"-----BEGIN KEY-----\nline1\nline2\n-----END KEY-----\n"
        backend = rk.choose_backend()
        backend.set(self.NAME, blob)
        self.assertEqual(backend.get(self.NAME), blob)

    def test_list_never_prints_value(self):
        self.cli("set", self.NAME, "--stdin", input=self.SECRET)
        proc = self.cli("list")
        self.assertIn(self.NAME.encode(), proc.stdout)
        self.assertNotIn(self.SECRET, proc.stdout)

    def test_audit_records_the_run(self):
        self.cli("set", self.NAME, "--stdin", input=self.SECRET)
        self.cli("run", "--grant", self.NAME, "--", "true",
                 env={"RAPP_KEYRING_CALLER": "shell"})
        proc = self.cli("audit", "all", "--json")
        records = json.loads(proc.stdout.decode())
        actions = [r["action"] for r in records]
        self.assertIn("set", actions)
        self.assertIn("run", actions)
        self.assertNotIn(self.SECRET.decode(), proc.stdout.decode())

    def test_file_permissions_are_owner_only(self):
        self.cli("set", self.NAME, "--stdin", input=self.SECRET)
        for path in (rk.p_policy(), rk.p_index(), rk.p_audit()):
            if os.path.exists(path):
                self.assertEqual(os.stat(path).st_mode & 0o077, 0,
                                 "%s is group/other accessible" % path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
