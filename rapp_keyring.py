#!/usr/bin/env python3
"""
RAPP Keyring — an on-device credential broker for AI agents.

The problem it solves: AI agents run on your machine with broad shell access and
need real credentials. The usual answers are all bad. Plaintext in a config file
leaks through settings sync, screenshots, and repos. Exported environment
variables leak into every child process and every `env` dump. And the moment an
agent *reads* a secret, that secret is in the model's context — which means it
travels to a cloud API, lands in a transcript, and may be echoed back into a
file or a pull request.

RAPP Keyring's central idea is USE WITHOUT SIGHT: the primary interface is not
"give me the secret," it is "run this command with the secret injected." The
value is placed in a child process's environment and never returned to the
caller. Anything the child prints is scanned on the way out and the secret is
masked before it can reach a terminal, a log, or an agent's context window.

Reading a secret in the clear is still possible — sometimes you genuinely need
it — but it is a separate, policy-gated action that must be asked for
explicitly and is recorded distinctly in a tamper-evident audit log.

Design constraints:
  * Python 3.8+, standard library only. No pip install, no supply chain.
  * Zero network. This program opens no sockets, ever. Enforced by conformance.
  * Secret values are never passed as command-line arguments (argv is world
    readable via `ps`), never written to disk in plaintext, never logged.
  * Secrets at rest live in the OS credential store (macOS Keychain, libsecret,
    Windows DPAPI). The portable fallback is an age-encrypted file.

Homepage: https://github.com/kody-w/rapp-keyring
License: MIT
"""

from __future__ import annotations

import argparse
import base64
import binascii
import errno
import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Version
# --------------------------------------------------------------------------

def _read_version() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        with open(os.path.join(here, "VERSION"), "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "0.0.0-dev"


__version__ = _read_version()

SPEC_VERSION = 1

# --------------------------------------------------------------------------
# Paths and layout
# --------------------------------------------------------------------------

def keyring_home() -> str:
    return os.environ.get(
        "RAPP_KEYRING_HOME", os.path.join(os.path.expanduser("~"), ".rapp-keyring")
    )


def p_config() -> str:
    return os.path.join(keyring_home(), "config.json")


def p_policy() -> str:
    return os.path.join(keyring_home(), "policy.json")


def p_audit() -> str:
    return os.path.join(keyring_home(), "audit.jsonl")


def p_store() -> str:
    return os.path.join(keyring_home(), "store")


def p_index() -> str:
    return os.path.join(keyring_home(), "index.json")


# --------------------------------------------------------------------------
# Small utilities
# --------------------------------------------------------------------------

class KeyringError(Exception):
    """User-facing error. Message is printed without a traceback."""


class PolicyDenied(KeyringError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonical_json(obj) -> str:
    """Deterministic JSON so hashes over the same content always agree."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def ensure_dir(path: str, mode: int = 0o700) -> None:
    if not os.path.isdir(path):
        os.makedirs(path, mode=mode, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def atomic_write(path: str, data: str, mode: int = 0o600) -> None:
    """Write via a temp file in the same directory, then rename.

    A partial write must never be observable, and the file must never exist
    with permissive modes even briefly.
    """
    directory = os.path.dirname(os.path.abspath(path))
    ensure_dir(directory)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".swap")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_json(path: str, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as exc:
        raise KeyringError("%s is corrupt: %s" % (path, exc))


def check_permissions(path: str) -> list:
    """Return a list of complaints about group/other-accessible paths."""
    problems = []
    try:
        st = os.stat(path)
    except OSError:
        return problems
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        problems.append(
            "%s is accessible to group/other (mode %s)" % (path, oct(st.st_mode & 0o777))
        )
    return problems


VALID_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$")


def validate_name(name: str) -> str:
    """Secret names are path-like: `azure/storage-key`, `github/pat`."""
    if not VALID_NAME.match(name or ""):
        raise KeyringError(
            "invalid secret name %r — use letters, digits, and . _ - / "
            "(e.g. azure/storage-key)" % name
        )
    if ".." in name:
        raise KeyringError("invalid secret name %r — '..' is not allowed" % name)
    return name


def env_name_for(name: str) -> str:
    """azure/storage-key -> AZURE_STORAGE_KEY"""
    out = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    if not out or out[0].isdigit():
        out = "S_" + out
    return out


def is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except (ValueError, AttributeError):
        return False


# --------------------------------------------------------------------------
# Backends
#
# Every backend stores an opaque byte string under a name. Values are
# hex-encoded before they reach the OS tool, which keeps binary and multi-line
# secrets safe and, on macOS specifically, keeps the value on a single line so
# it can be delivered over stdin instead of argv.
# --------------------------------------------------------------------------

class Backend:
    name = "abstract"
    available = False

    def set(self, key: str, value: bytes) -> None:
        raise NotImplementedError

    def get(self, key: str) -> bytes:
        raise NotImplementedError

    def delete(self, key: str) -> None:
        raise NotImplementedError

    def describe(self) -> str:
        return self.name


def _run(cmd, input_bytes=None, check=True, env=None):
    proc = subprocess.run(
        cmd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if check and proc.returncode != 0:
        raise KeyringError(
            "%s failed (exit %d): %s"
            % (cmd[0], proc.returncode, proc.stderr.decode("utf-8", "replace").strip())
        )
    return proc


class KeychainBackend(Backend):
    """macOS Keychain.

    `security add-generic-password -U -w`, given no inline value, prompts for
    the password and then for a confirmation, reading both from stdin. Feeding
    the value twice over a pipe stores it without the value ever appearing in
    argv — which `ps` would otherwise expose to every process on the machine.

    That prompt has a hard 128-character buffer, measured on macOS 26.5: a
    129th character is silently truncated, not rejected. Since values are
    hex-encoded, one item holds at most 64 raw bytes — far too small for a
    private key or a connection string.

    Rather than fall back to passing the value in argv, secrets are split into
    64-byte chunks stored as separate items, with a small header item written
    LAST. The header is the commit point: it records the chunk count, the total
    length, and a truncated digest, so a write interrupted halfway leaves no
    readable secret rather than a silently truncated one.
    """

    name = "keychain"
    CHUNK = 64            # raw bytes -> 128 hex chars, the proven maximum
    FORMAT = 1

    def __init__(self, service_prefix: str = "rapp-keyring"):
        self.prefix = service_prefix
        self.account = os.environ.get("USER") or os.environ.get("LOGNAME") or "rapp"
        self.available = sys.platform == "darwin" and shutil.which("security") is not None

    def _service(self, key: str, chunk: int = None) -> str:
        if chunk is None:
            return "%s:%s" % (self.prefix, key)
        return "%s:%s#%d" % (self.prefix, key, chunk)

    def _write_item(self, service: str, payload: bytes) -> None:
        hexed = binascii.hexlify(payload).decode("ascii")
        if len(hexed) > 128:
            raise KeyringError("internal error: chunk exceeds keychain prompt buffer")
        proc = subprocess.run(
            [
                "security", "add-generic-password",
                "-a", self.account, "-s", service,
                "-D", "RAPP Keyring secret", "-U", "-w",
            ],
            input=("%s\n%s\n" % (hexed, hexed)).encode("ascii"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode != 0:
            raise KeyringError(
                "keychain write failed: %s"
                % proc.stderr.decode("utf-8", "replace").strip()
            )

    def _read_item(self, service: str) -> bytes:
        proc = subprocess.run(
            ["security", "find-generic-password", "-a", self.account, "-s", service, "-w"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode != 0:
            raise KeyringError("keychain item %r not found" % service)
        hexed = proc.stdout.decode("ascii", "replace").strip()
        try:
            return binascii.unhexlify(hexed)
        except (binascii.Error, ValueError):
            raise KeyringError(
                "keychain item %r is not RAPP Keyring encoded "
                "(was it added by hand with `security`?)" % service
            )

    def _delete_item(self, service: str) -> None:
        subprocess.run(
            ["security", "delete-generic-password", "-a", self.account, "-s", service],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def set(self, key: str, value: bytes) -> None:
        chunks = [value[i:i + self.CHUNK] for i in range(0, len(value), self.CHUNK)] or [b""]
        # Clear any longer previous version so stale chunks cannot be read back.
        self.delete(key)
        for index, chunk in enumerate(chunks):
            self._write_item(self._service(key, index), chunk)
        header = canonical_json({
            "v": self.FORMAT,
            "n": len(chunks),
            "l": len(value),
            "h": sha256_hex(value)[:32],
        }).encode("ascii")
        self._write_item(self._service(key), header)  # commit point, written last
        if self.get(key) != value:
            raise KeyringError("keychain write verification failed for %r" % key)

    def get(self, key: str) -> bytes:
        try:
            header = json.loads(self._read_item(self._service(key)).decode("ascii"))
        except KeyringError:
            raise KeyringError("secret %r not found in keychain" % key)
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise KeyringError(
                "secret %r has an unrecognized keychain header — it may predate "
                "this version of rapp-keyring; re-store it with `rapp-keyring set`" % key
            )
        if header.get("v") != self.FORMAT:
            raise KeyringError(
                "secret %r uses keychain format %s, this build speaks %d"
                % (key, header.get("v"), self.FORMAT)
            )
        parts = [self._read_item(self._service(key, i)) for i in range(header["n"])]
        value = b"".join(parts)
        if len(value) != header["l"] or sha256_hex(value)[:32] != header["h"]:
            raise KeyringError(
                "secret %r failed its integrity check — the keychain items are "
                "incomplete or were modified outside rapp-keyring" % key
            )
        return value

    def delete(self, key: str) -> None:
        try:
            header = json.loads(self._read_item(self._service(key)).decode("ascii"))
            count = int(header.get("n", 0))
        except Exception:
            count = 0
        self._delete_item(self._service(key))
        # Walk past the recorded count so orphans from an interrupted write go too.
        for index in range(max(count, 0) + 16):
            self._delete_item(self._service(key, index))

    def describe(self) -> str:
        return "macOS Keychain (service prefix %r, account %r, %d-byte chunks)" % (
            self.prefix, self.account, self.CHUNK)


class SecretToolBackend(Backend):
    """Linux: libsecret / GNOME Keyring via `secret-tool`."""

    name = "secret-tool"

    def __init__(self, service_prefix: str = "rapp-keyring"):
        self.prefix = service_prefix
        self.available = shutil.which("secret-tool") is not None

    def set(self, key: str, value: bytes) -> None:
        hexed = binascii.hexlify(value).decode("ascii")
        _run(
            ["secret-tool", "store", "--label=RAPP Keyring: %s" % key,
             "service", self.prefix, "name", key],
            input_bytes=(hexed + "\n").encode("ascii"),
        )
        if self.get(key) != value:
            raise KeyringError("secret-tool write verification failed for %r" % key)

    def get(self, key: str) -> bytes:
        proc = subprocess.run(
            ["secret-tool", "lookup", "service", self.prefix, "name", key],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            raise KeyringError("secret %r not found in secret-tool store" % key)
        try:
            return binascii.unhexlify(proc.stdout.decode("ascii", "replace").strip())
        except (binascii.Error, ValueError):
            raise KeyringError("secret %r is not RAPP Keyring encoded" % key)

    def delete(self, key: str) -> None:
        subprocess.run(
            ["secret-tool", "clear", "service", self.prefix, "name", key],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def describe(self) -> str:
        return "libsecret via secret-tool (service %r)" % self.prefix


class DPAPIBackend(Backend):
    """Windows: DPAPI via PowerShell, scoped to the current user."""

    name = "dpapi"

    def __init__(self):
        self.available = os.name == "nt" and shutil.which("powershell") is not None
        self.dir = os.path.join(keyring_home(), "dpapi")

    def _path(self, key: str) -> str:
        return os.path.join(self.dir, sha256_hex(key) + ".dpapi")

    def _ps(self, script: str, input_bytes=None):
        return _run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            input_bytes=input_bytes,
        )

    def set(self, key: str, value: bytes) -> None:
        ensure_dir(self.dir)
        hexed = binascii.hexlify(value).decode("ascii")
        target = self._path(key).replace("'", "''")
        script = (
            "Add-Type -AssemblyName System.Security;"
            "$h=[Console]::In.ReadToEnd().Trim();"
            "$b=[Text.Encoding]::UTF8.GetBytes($h);"
            "$p=[Security.Cryptography.ProtectedData]::Protect("
            "$b,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);"
            "[IO.File]::WriteAllBytes('%s',$p)" % target
        )
        self._ps(script, input_bytes=(hexed + "\n").encode("ascii"))
        if self.get(key) != value:
            raise KeyringError("DPAPI write verification failed for %r" % key)

    def get(self, key: str) -> bytes:
        path = self._path(key)
        if not os.path.exists(path):
            raise KeyringError("secret %r not found in DPAPI store" % key)
        target = path.replace("'", "''")
        script = (
            "Add-Type -AssemblyName System.Security;"
            "$p=[IO.File]::ReadAllBytes('%s');"
            "$b=[Security.Cryptography.ProtectedData]::Unprotect("
            "$p,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser);"
            "[Console]::Out.Write([Text.Encoding]::UTF8.GetString($b))" % target
        )
        proc = self._ps(script)
        try:
            return binascii.unhexlify(proc.stdout.decode("ascii", "replace").strip())
        except (binascii.Error, ValueError):
            raise KeyringError("secret %r is not RAPP Keyring encoded" % key)

    def delete(self, key: str) -> None:
        try:
            os.unlink(self._path(key))
        except OSError:
            pass

    def describe(self) -> str:
        return "Windows DPAPI (CurrentUser scope)"


class AgeBackend(Backend):
    """Portable fallback: one age-encrypted file per secret.

    The age identity is itself held in the OS credential store when one is
    available, so the encrypted files on disk are inert without an OS-level
    unlock. When no OS store exists (headless CI, containers), the identity
    falls back to a 0600 file and that reduction in protection is reported by
    `doctor` rather than hidden.
    """

    name = "age"
    IDENTITY_KEY = "__rapp_keyring_age_identity__"

    def __init__(self, os_backend: "Backend" = None):
        self.available = shutil.which("age") is not None and shutil.which("age-keygen") is not None
        self.os_backend = os_backend if (os_backend and os_backend.available) else None
        self.dir = p_store()
        self.identity_file = os.path.join(keyring_home(), "identity.age-key")

    def _load_identity(self) -> str:
        if self.os_backend is not None:
            try:
                return self.os_backend.get(self.IDENTITY_KEY).decode("utf-8")
            except KeyringError:
                pass
        if os.path.exists(self.identity_file):
            with open(self.identity_file, "r", encoding="utf-8") as fh:
                return fh.read()
        raise KeyringError("no age identity — run `rapp-keyring init` first")

    def _ensure_identity(self) -> str:
        try:
            return self._load_identity()
        except KeyringError:
            pass
        proc = _run(["age-keygen"])
        identity = proc.stdout.decode("utf-8")
        if self.os_backend is not None:
            self.os_backend.set(self.IDENTITY_KEY, identity.encode("utf-8"))
        else:
            atomic_write(self.identity_file, identity, mode=0o600)
        return identity

    def _recipient(self, identity: str) -> str:
        for line in identity.splitlines():
            if line.startswith("# public key: "):
                return line.split("# public key: ", 1)[1].strip()
        proc = _run(["age-keygen", "-y"], input_bytes=identity.encode("utf-8"))
        return proc.stdout.decode("ascii").strip()

    def _path(self, key: str) -> str:
        return os.path.join(self.dir, sha256_hex(key) + ".age")

    def set(self, key: str, value: bytes) -> None:
        ensure_dir(self.dir)
        identity = self._ensure_identity()
        recipient = self._recipient(identity)
        proc = _run(["age", "-r", recipient, "-o", "-"], input_bytes=value)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-", suffix=".age")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(proc.stdout)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path(key))
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        if self.get(key) != value:
            raise KeyringError("age write verification failed for %r" % key)

    def get(self, key: str) -> bytes:
        path = self._path(key)
        if not os.path.exists(path):
            raise KeyringError("secret %r not found in age store" % key)
        identity = self._load_identity()
        fd, tmp = tempfile.mkstemp(prefix=".rk-id-", suffix=".key")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(identity)
            with open(path, "rb") as fh:
                blob = fh.read()
            proc = _run(["age", "-d", "-i", tmp], input_bytes=blob)
            return proc.stdout
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def delete(self, key: str) -> None:
        try:
            os.unlink(self._path(key))
        except OSError:
            pass

    def describe(self) -> str:
        where = "OS credential store" if self.os_backend else "0600 file (no OS store available)"
        return "age-encrypted files in %s; identity held in %s" % (self.dir, where)


def os_backend_for_platform() -> Backend:
    if sys.platform == "darwin":
        return KeychainBackend()
    if os.name == "nt":
        return DPAPIBackend()
    return SecretToolBackend()


def choose_backend(preferred: str = None) -> Backend:
    """Pick a backend: explicit request, then OS store, then age."""
    osb = os_backend_for_platform()
    preferred = preferred or os.environ.get("RAPP_KEYRING_BACKEND") or \
        load_json(p_config(), {}).get("backend")

    if preferred and preferred != "auto":
        candidates = {
            "keychain": KeychainBackend,
            "secret-tool": SecretToolBackend,
            "dpapi": DPAPIBackend,
            "age": lambda: AgeBackend(osb),
        }
        if preferred not in candidates:
            raise KeyringError(
                "unknown backend %r — choose from: %s"
                % (preferred, ", ".join(sorted(candidates)))
            )
        backend = candidates[preferred]()
        if not backend.available:
            raise KeyringError(
                "backend %r is not available on this machine (run "
                "`rapp-keyring doctor`)" % preferred
            )
        return backend

    if osb.available:
        return osb
    age = AgeBackend(osb)
    if age.available:
        return age
    raise KeyringError(
        "no usable backend. Install `age` (brew install age / apt install age), "
        "or run on a machine with an OS credential store. See `rapp-keyring doctor`."
    )


# --------------------------------------------------------------------------
# Index — the list of known secret names. Names only. Never values.
# --------------------------------------------------------------------------

def index_load() -> dict:
    data = load_json(p_index(), {"version": SPEC_VERSION, "secrets": {}})
    data.setdefault("secrets", {})
    return data


def index_add(name: str, backend: str, meta: dict = None) -> None:
    idx = index_load()
    entry = idx["secrets"].get(name, {})
    entry.update(
        {
            "backend": backend,
            "updated": now_iso(),
            "env": env_name_for(name),
        }
    )
    entry.setdefault("created", entry.get("updated"))
    if meta:
        entry.update(meta)
    idx["secrets"][name] = entry
    atomic_write(p_index(), json.dumps(idx, indent=2) + "\n")


def index_remove(name: str) -> None:
    idx = index_load()
    idx["secrets"].pop(name, None)
    atomic_write(p_index(), json.dumps(idx, indent=2) + "\n")


def index_names() -> list:
    return sorted(index_load()["secrets"].keys())


# --------------------------------------------------------------------------
# Audit log — append-only JSONL, hash-chained so edits are detectable.
#
# Each record carries the hash of the record before it. Changing or deleting
# any historical line breaks the chain from that point forward, which
# `audit verify` reports with the exact sequence number.
# --------------------------------------------------------------------------

GENESIS = "0" * 64


class Audit:
    def __init__(self, path: str = None):
        self.path = path or p_audit()

    def _last(self):
        last_hash, seq = GENESIS, 0
        if not os.path.exists(self.path):
            return last_hash, seq
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                last_hash = rec.get("hash", last_hash)
                seq = rec.get("seq", seq)
        return last_hash, seq

    def append(self, action: str, **fields) -> str:
        prev, seq = self._last()
        record = {
            "seq": seq + 1,
            "ts": now_iso(),
            "action": action,
            "caller": fields.pop("caller", "unknown"),
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "?",
            "host": platform.node(),
            "prev": prev,
        }
        record.update(fields)
        record["hash"] = sha256_hex(prev + canonical_json(record))
        ensure_dir(os.path.dirname(os.path.abspath(self.path)))
        # Append with O_APPEND so concurrent writers cannot interleave records.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (canonical_json(record) + "\n").encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        return record["hash"]

    def records(self) -> list:
        out = []
        if not os.path.exists(self.path):
            return out
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify(self):
        """Return (ok, message, checked_count)."""
        prev = GENESIS
        count = 0
        for rec in self.records():
            count += 1
            claimed = rec.get("hash")
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("prev") != prev:
                return (
                    False,
                    "chain break at seq %s: prev=%s expected=%s"
                    % (rec.get("seq"), rec.get("prev"), prev),
                    count,
                )
            expect = sha256_hex(prev + canonical_json(body))
            if claimed != expect:
                return (
                    False,
                    "record %s was modified (hash mismatch)" % rec.get("seq"),
                    count,
                )
            prev = claimed
        return True, "chain intact", count


# --------------------------------------------------------------------------
# Caller identity
#
# Derived from the process ancestry. This is deliberately advisory: anything
# running as your user could set RAPP_KEYRING_CALLER or read the OS store
# directly. Its purpose is to make accidental over-reach visible and auditable,
# not to defend against a hostile local process. SECURITY.md says so plainly.
# --------------------------------------------------------------------------

AGENT_SIGNATURES = [
    ("claude-code", ("claude",)),
    ("copilot-cli", ("copilot",)),
    ("vscode", ("code helper", "electron", "code")),
    ("cursor", ("cursor",)),
    ("brainstem", ("brainstem", "rapp_agent", "agent.py")),
    ("python", ("python",)),
    ("node", ("node",)),
]


def _process_ancestry(max_depth: int = 8) -> list:
    """Walk up the parent chain from our caller, returning (pid, command) pairs.

    We start at the parent, not at ourselves: this process is always a Python
    interpreter, so including it would label every caller "python".
    """
    chain = []
    pid = os.getppid()
    for _ in range(max_depth):
        try:
            proc = subprocess.run(
                ["ps", "-o", "ppid=,comm=", "-p", str(pid)],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            out = proc.stdout.decode("utf-8", "replace").strip()
            if not out:
                break
            parts = out.split(None, 1)
            ppid = int(parts[0])
            comm = parts[1] if len(parts) > 1 else "?"
            chain.append((pid, comm))
            if ppid <= 1 or ppid == pid:
                break
            pid = ppid
        except (OSError, ValueError, IndexError):
            break
    return chain


def caller_identity() -> str:
    explicit = os.environ.get("RAPP_KEYRING_CALLER")
    if explicit:
        return explicit.strip()
    for _pid, comm in _process_ancestry():
        low = comm.lower()
        for label, needles in AGENT_SIGNATURES:
            if any(n in low for n in needles):
                return label
    return "shell"


# --------------------------------------------------------------------------
# Policy
# --------------------------------------------------------------------------

DEFAULT_POLICY = {
    "version": SPEC_VERSION,
    "default": "deny",
    "_comment": [
        "Two verbs, and the difference between them is the entire point.",
        "  run — inject the secret into a child process. The caller never sees it.",
        "  get — return the secret in plaintext to the caller. For an AI agent",
        "        this means the secret enters the model's context and travels to",
        "        a cloud API. Grant it rarely, and prefer an empty list.",
        "Patterns are globs matched against the secret name: azure/* , github/pat , *",
    ],
    "callers": {
        "shell": {"run": ["*"], "get": ["*"]},
        "claude-code": {"run": ["*"], "get": []},
        "copilot-cli": {"run": ["*"], "get": []},
        "brainstem": {"run": ["*"], "get": []},
        "*": {"run": [], "get": []},
    },
}


def policy_load() -> dict:
    pol = load_json(p_policy(), None)
    if pol is None:
        return json.loads(json.dumps(DEFAULT_POLICY))
    pol.setdefault("default", "deny")
    pol.setdefault("callers", {})
    return pol


def policy_save(pol: dict) -> None:
    atomic_write(p_policy(), json.dumps(pol, indent=2) + "\n")


def policy_decide(pol: dict, caller: str, action: str, name: str):
    """Return (allowed: bool, reason: str). Deny wins; no wildcard fallthrough
    once an explicit caller entry exists."""
    callers = pol.get("callers", {})
    entry = callers.get(caller)
    matched_as = caller
    if entry is None:
        entry = callers.get("*")
        matched_as = "*"
    if entry is None:
        return False, "no policy entry for caller %r and no '*' default" % caller

    denies = entry.get("deny", [])
    for pattern in denies:
        if fnmatch.fnmatch(name, pattern):
            return False, "caller %r denied by rule %r" % (matched_as, pattern)

    allows = entry.get(action, [])
    for pattern in allows:
        if fnmatch.fnmatch(name, pattern):
            return True, "caller %r allowed '%s' by rule %r" % (matched_as, action, pattern)

    return False, (
        "caller %r has no '%s' grant matching %r "
        "(grant it with: rapp-keyring policy allow %s %s %s)"
        % (matched_as, action, name, caller, action, name)
    )


# --------------------------------------------------------------------------
# Redaction
#
# Secrets are masked in the child's output before that output reaches a
# terminal, a pipe, or an agent's context. Matching runs over a sliding buffer
# so a secret split across two reads is still caught.
# --------------------------------------------------------------------------

class Redactor:
    def __init__(self, secrets: dict):
        """secrets maps name -> raw bytes value."""
        self.patterns = []
        for name, value in secrets.items():
            if not value or len(value) < 4:
                # Very short values would mask innocent text everywhere.
                continue
            mask = ("«redacted:%s»" % name).encode("utf-8")
            self.patterns.append((value, mask))
            # A secret often reaches output re-encoded rather than verbatim.
            for variant in self._variants(value):
                if variant and variant != value and len(variant) >= 4:
                    self.patterns.append((variant, mask))
        # Longest first, so an overlapping short match cannot pre-empt a long one.
        self.patterns.sort(key=lambda pair: len(pair[0]), reverse=True)
        self.max_len = max([len(p) for p, _ in self.patterns], default=0)
        self._tail = b""

    @staticmethod
    def _variants(value: bytes) -> list:
        out = []
        try:
            out.append(base64.b64encode(value))
        except Exception:
            pass
        try:
            out.append(binascii.hexlify(value))
        except Exception:
            pass
        try:
            text = value.decode("utf-8")
            out.append(json.dumps(text)[1:-1].encode("utf-8"))  # JSON-escaped
            from urllib.parse import quote  # stdlib; no network involved
            out.append(quote(text, safe="").encode("utf-8"))
        except Exception:
            pass
        return out

    def scrub(self, chunk: bytes) -> bytes:
        if not self.patterns:
            return chunk
        data = self._tail + chunk
        for needle, mask in self.patterns:
            data = data.replace(needle, mask)
        # Hold back enough bytes that a secret straddling the boundary is
        # still matchable on the next read.
        hold = max(self.max_len - 1, 0)
        if hold and len(data) > hold:
            emit, self._tail = data[:-hold], data[-hold:]
        else:
            emit, self._tail = b"", data
        return emit

    def flush(self) -> bytes:
        data = self._tail
        self._tail = b""
        if not self.patterns:
            return data
        for needle, mask in self.patterns:
            data = data.replace(needle, mask)
        return data


# --------------------------------------------------------------------------
# Secret input — never from argv
# --------------------------------------------------------------------------

def read_secret_value(from_stdin: bool, generate: int = 0) -> bytes:
    if generate:
        raw = os.urandom(max(16, generate))
        return base64.urlsafe_b64encode(raw).rstrip(b"=")[:generate].ljust(generate, b"x")
    if from_stdin or not is_tty():
        data = sys.stdin.buffer.read()
        # A trailing newline is almost always the shell's, not the secret's.
        if data.endswith(b"\r\n"):
            data = data[:-2]
        elif data.endswith(b"\n"):
            data = data[:-1]
        if not data:
            raise KeyringError("no secret received on stdin")
        return data
    import getpass
    first = getpass.getpass("secret value (input hidden): ")
    second = getpass.getpass("confirm: ")
    if first != second:
        raise KeyringError("values did not match")
    if not first:
        raise KeyringError("empty secret refused")
    return first.encode("utf-8")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_init(args) -> int:
    home = keyring_home()
    ensure_dir(home)
    ensure_dir(p_store())
    if not os.path.exists(p_policy()):
        policy_save(DEFAULT_POLICY)
        created_policy = True
    else:
        created_policy = False

    backend = choose_backend(args.backend)
    config = load_json(p_config(), {})
    config.update({"version": SPEC_VERSION, "backend": args.backend or "auto"})
    atomic_write(p_config(), json.dumps(config, indent=2) + "\n")

    if isinstance(backend, AgeBackend):
        backend._ensure_identity()

    if not os.path.exists(p_index()):
        atomic_write(p_index(), json.dumps({"version": SPEC_VERSION, "secrets": {}}, indent=2) + "\n")

    audit = Audit()
    audit.append("init", caller=caller_identity(), backend=backend.name)

    print("RAPP Keyring initialized")
    print("  home:    %s" % home)
    print("  backend: %s" % backend.describe())
    print("  policy:  %s%s" % (p_policy(), " (created with safe defaults)" if created_policy else ""))
    print("  audit:   %s" % p_audit())
    print()
    print("Next: store a secret without it ever touching argv or disk:")
    print("  printf '%s' \"$SECRET\" | rapp-keyring set azure/storage-key --stdin")
    return 0


def cmd_set(args) -> int:
    name = validate_name(args.name)
    caller = caller_identity()
    backend = choose_backend()
    value = read_secret_value(args.stdin, args.generate or 0)
    backend.set(name, value)
    index_add(name, backend.name, {"bytes": len(value)})
    Audit().append(
        "set", caller=caller, name=name, backend=backend.name,
        size=len(value), decision="allow",
    )
    if args.generate:
        print("stored %s (%d bytes, generated)" % (name, len(value)))
    else:
        print("stored %s (%d bytes) in %s" % (name, len(value), backend.name))
    print("  inject with: rapp-keyring run --grant %s -- <command>   # env %s"
          % (name, env_name_for(name)))
    return 0


def cmd_get(args) -> int:
    """A sighted read. Deliberately awkward, loudly audited."""
    name = validate_name(args.name)
    caller = caller_identity()
    pol = policy_load()
    allowed, reason = policy_decide(pol, caller, "get", name)

    if not allowed:
        Audit().append("get", caller=caller, name=name, decision="deny", reason=reason)
        raise PolicyDenied(
            "denied: %s\n\n"
            "This is the sighted-read path — it returns the secret in plaintext,\n"
            "which for an AI agent means the value enters the model context and\n"
            "leaves the machine. Prefer:\n"
            "    rapp-keyring run --grant %s -- <command>\n"
            "which injects the secret without revealing it." % (reason, name)
        )

    if not args.i_know and not os.environ.get("RAPP_KEYRING_SIGHTED"):
        Audit().append("get", caller=caller, name=name, decision="deny",
                       reason="missing --i-know acknowledgement")
        raise KeyringError(
            "refusing to print a secret without an explicit acknowledgement.\n"
            "If you truly need the plaintext value, re-run with --i-know.\n"
            "If a program needs it, use `rapp-keyring run` instead — it injects\n"
            "the secret without exposing it to you or to an agent's context."
        )

    backend = choose_backend()
    value = backend.get(name)
    Audit().append(
        "get", caller=caller, name=name, decision="allow",
        sighted=True, reason=reason, size=len(value),
    )
    sys.stdout.buffer.write(value)
    if sys.stdout.isatty():
        sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()
    return 0


def _resolve_grants(patterns: list) -> list:
    """Expand glob patterns against known secret names."""
    known = index_names()
    resolved, missing = [], []
    for pattern in patterns:
        if any(ch in pattern for ch in "*?["):
            hits = [n for n in known if fnmatch.fnmatch(n, pattern)]
            if not hits:
                missing.append(pattern)
            resolved.extend(hits)
        else:
            validate_name(pattern)
            if pattern in known:
                resolved.append(pattern)
            else:
                missing.append(pattern)
    if missing:
        raise KeyringError(
            "no stored secret matches: %s\nknown secrets: %s"
            % (", ".join(missing), ", ".join(known) or "(none — run `rapp-keyring set`)")
        )
    # Preserve order, drop duplicates.
    seen, out = set(), []
    for name in resolved:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def cmd_run(args) -> int:
    """The primary interface: inject, execute, redact. Caller never sees values."""
    if not args.command:
        raise KeyringError("nothing to run — put the command after `--`\n"
                           "  rapp-keyring run --grant azure/* -- ./deploy.sh")

    caller = caller_identity()
    pol = policy_load()
    names = _resolve_grants(args.grant or [])
    if not names:
        raise KeyringError("no secrets granted — pass --grant NAME (globs allowed)")

    audit = Audit()
    for name in names:
        allowed, reason = policy_decide(pol, caller, "run", name)
        if not allowed:
            audit.append("run", caller=caller, name=name, decision="deny", reason=reason,
                         cmd=args.command[0])
            raise PolicyDenied("denied: %s" % reason)

    backend = choose_backend()
    secrets = {}
    for name in names:
        secrets[name] = backend.get(name)

    env = os.environ.copy()
    mapping = {}
    for name, value in secrets.items():
        var = env_name_for(name)
        mapping[name] = var
        try:
            env[var] = value.decode("utf-8")
        except UnicodeDecodeError:
            env[var] = base64.b64encode(value).decode("ascii")
            env[var + "_B64"] = "1"
    for spec in args.env or []:
        if "=" not in spec:
            raise KeyringError("--env expects VAR=secret/name, got %r" % spec)
        var, sname = spec.split("=", 1)
        if sname not in secrets:
            raise KeyringError("--env %r references %r which was not granted" % (spec, sname))
        env[var] = secrets[sname].decode("utf-8", "replace")
        mapping[sname] = var

    env["RAPP_KEYRING_INJECTED"] = ",".join(sorted(mapping.values()))

    audit.append(
        "run", caller=caller, names=sorted(names), decision="allow",
        cmd=args.command[0], argc=len(args.command),
        redacted=not args.no_redact, env_vars=sorted(mapping.values()),
    )

    if args.no_redact:
        # Interactive children (TTY-dependent) need the real terminal. The
        # trade-off is explicit, opt-in, and recorded above.
        proc = subprocess.Popen(args.command, env=env)
        try:
            return proc.wait()
        except KeyboardInterrupt:
            proc.send_signal(signal.SIGINT)
            return proc.wait()

    redactor_out = Redactor(secrets)
    redactor_err = Redactor(secrets)
    proc = subprocess.Popen(
        args.command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    import selectors

    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, (redactor_out, sys.stdout.buffer))
    selector.register(proc.stderr, selectors.EVENT_READ, (redactor_err, sys.stderr.buffer))
    open_streams = 2
    try:
        while open_streams:
            for key, _mask in selector.select(timeout=0.25):
                redactor, sink = key.data
                chunk = key.fileobj.read1(65536) if hasattr(key.fileobj, "read1") \
                    else key.fileobj.read(65536)
                if not chunk:
                    sink.write(redactor.flush())
                    sink.flush()
                    selector.unregister(key.fileobj)
                    open_streams -= 1
                    continue
                sink.write(redactor.scrub(chunk))
                sink.flush()
    except KeyboardInterrupt:
        proc.send_signal(signal.SIGINT)
    finally:
        selector.close()
        sys.stdout.buffer.write(redactor_out.flush())
        sys.stderr.buffer.write(redactor_err.flush())
        sys.stdout.buffer.flush()
        sys.stderr.buffer.flush()
    return proc.wait()


def cmd_list(args) -> int:
    idx = index_load()["secrets"]
    if args.json:
        print(json.dumps(idx, indent=2))
        return 0
    if not idx:
        print("no secrets stored. Add one:")
        print("  printf '%s' \"$VALUE\" | rapp-keyring set some/name --stdin")
        return 0
    width = max(max(len(n) for n in idx), len("NAME"))
    ewidth = max(max(len(m.get("env", "")) for m in idx.values()), len("ENV"))
    print("%-*s  %-*s  %-10s  %s" % (width, "NAME", ewidth, "ENV", "BACKEND", "UPDATED"))
    for name in sorted(idx):
        meta = idx[name]
        print("%-*s  %-*s  %-10s  %s" % (
            width, name, ewidth, meta.get("env", env_name_for(name)),
            meta.get("backend", "?"), meta.get("updated", "?")))
    print()
    print("%d secret(s). Values are never displayed by `list`." % len(idx))
    return 0


def cmd_rm(args) -> int:
    name = validate_name(args.name)
    caller = caller_identity()
    if name not in index_names() and not args.force:
        raise KeyringError("%r is not a known secret (use --force to delete anyway)" % name)
    if not args.yes:
        if not is_tty():
            raise KeyringError("refusing to delete non-interactively without --yes")
        answer = input("delete secret %r permanently? [y/N] " % name)
        if answer.strip().lower() not in ("y", "yes"):
            print("aborted")
            return 1
    choose_backend().delete(name)
    index_remove(name)
    Audit().append("rm", caller=caller, name=name, decision="allow")
    print("deleted %s" % name)
    return 0


def cmd_policy(args) -> int:
    pol = policy_load()
    if args.policy_action == "show":
        print(json.dumps(pol, indent=2))
        return 0
    if args.policy_action == "path":
        print(p_policy())
        return 0
    if args.policy_action in ("allow", "deny"):
        caller, verb, pattern = args.caller, args.verb, args.pattern
        if verb not in ("run", "get"):
            raise KeyringError("verb must be 'run' or 'get', got %r" % verb)
        entry = pol.setdefault("callers", {}).setdefault(caller, {"run": [], "get": []})
        if args.policy_action == "allow":
            entry.setdefault(verb, [])
            if pattern not in entry[verb]:
                entry[verb].append(pattern)
            note = "allow %s %s %s" % (caller, verb, pattern)
        else:
            entry.setdefault("deny", [])
            if pattern not in entry["deny"]:
                entry["deny"].append(pattern)
            note = "deny %s %s" % (caller, pattern)
        policy_save(pol)
        Audit().append("policy", caller=caller_identity(), change=note, decision="allow")
        print("policy updated: %s" % note)
        if verb == "get" and args.policy_action == "allow":
            print()
            print("NOTE: 'get' returns plaintext to the caller. If that caller is an")
            print("      AI agent, the secret will enter the model's context and leave")
            print("      this machine. Prefer granting 'run' instead.")
        return 0
    if args.policy_action == "test":
        caller = args.caller or caller_identity()
        allowed, reason = policy_decide(pol, caller, args.verb, args.pattern)
        print("%s: %s" % ("ALLOW" if allowed else "DENY", reason))
        return 0 if allowed else 1
    raise KeyringError("unknown policy action %r" % args.policy_action)


def cmd_audit(args) -> int:
    audit = Audit()
    if args.audit_action == "verify":
        ok, message, count = audit.verify()
        if args.json:
            print(json.dumps({"ok": ok, "message": message, "records": count}, indent=2))
        else:
            print("%s — %s (%d record(s))" % ("OK" if ok else "TAMPERED", message, count))
        return 0 if ok else 2
    if args.audit_action == "path":
        print(p_audit())
        return 0
    records = audit.records()
    if args.audit_action == "tail":
        records = records[-args.count:]
    if args.json:
        print(json.dumps(records, indent=2))
        return 0
    if not records:
        print("no audit records yet")
        return 0
    for rec in records:
        target = rec.get("name") or ",".join(rec.get("names", [])) or rec.get("change", "")
        flag = " SIGHTED" if rec.get("sighted") else ""
        print("%s  seq=%-4s %-8s %-14s %-28s %s%s" % (
            rec.get("ts", "?"), rec.get("seq", "?"), rec.get("decision", "?"),
            rec.get("action", "?"), (rec.get("caller") or "?"), target, flag))
    return 0


def cmd_rotate(args) -> int:
    """Replace a secret's value and record the rotation as a first-class event."""
    name = validate_name(args.name)
    caller = caller_identity()
    if name not in index_names():
        raise KeyringError("%r is not a known secret" % name)
    backend = choose_backend()
    try:
        old = backend.get(name)
        old_fp = sha256_hex(old)[:16]
    except KeyringError:
        old_fp = None
    value = read_secret_value(args.stdin, args.generate or 0)
    backend.set(name, value)
    index_add(name, backend.name, {"bytes": len(value), "rotated": now_iso()})
    Audit().append(
        "rotate", caller=caller, name=name, decision="allow",
        old_fingerprint=old_fp, new_fingerprint=sha256_hex(value)[:16],
    )
    print("rotated %s (%d bytes)" % (name, len(value)))
    print("  fingerprints are truncated SHA-256 — they identify a value without revealing it")
    return 0


PLAINTEXT_HOTSPOTS = [
    "~/Library/Application Support/Code/User/settings.json",
    "~/.aws/credentials",
    "~/.netrc",
    "~/.npmrc",
    "~/.pypirc",
    "~/.docker/config.json",
    "~/.kube/config",
]

SECRET_PATTERNS = [
    (re.compile(r"AccountKey=[A-Za-z0-9+/=]{40,}"), "Azure storage account key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"), "GitHub token"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"), "OpenAI-style API key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "Slack token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"), "private key"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."), "JWT"),
]


# A scanner that cannot be silenced gets switched off entirely, so it needs a
# way to say "this one is deliberate". The pragma must name a reason, which
# keeps the suppression reviewable in a diff instead of invisible.
ALLOW_PRAGMA = re.compile(r"rapp-keyring:\s*allow(?:\s+(?P<reason>\S.*?))?\s*$")


def cmd_scan(args) -> int:
    """Find plaintext credentials sitting in well-known config files.

    Reports file, line, and what kind of secret it looks like — never the value.
    """
    targets = list(args.paths) if args.paths else [os.path.expanduser(p) for p in PLAINTEXT_HOTSPOTS]
    findings, suppressed = [], []
    for path in targets:
        path = os.path.expanduser(path)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                previous = ""
                for lineno, line in enumerate(fh, 1):
                    for pattern, label in SECRET_PATTERNS:
                        if pattern.search(line):
                            # Accept the pragma on the offending line or the one
                            # above it — a long credential line is exactly where
                            # a trailing comment is least readable.
                            pragma = ALLOW_PRAGMA.search(line) or ALLOW_PRAGMA.search(previous)
                            if pragma and not args.no_pragma:
                                suppressed.append({
                                    "file": path, "line": lineno, "kind": label,
                                    "reason": (pragma.group("reason") or "").strip()
                                             or "(no reason given)",
                                })
                            else:
                                findings.append({"file": path, "line": lineno, "kind": label})
                            break
                    previous = line
        except (OSError, UnicodeDecodeError) as exc:
            if isinstance(exc, OSError) and exc.errno not in (errno.EACCES, errno.EPERM):
                raise
    if args.json:
        print(json.dumps({
            "findings": findings,
            "suppressed": suppressed,
            "scanned": len(targets),
        }, indent=2))
        return 1 if findings else 0
    if not findings:
        print("scanned %d location(s) — no plaintext credentials found" % len(targets))
        if suppressed:
            print("(%d suppressed by an explicit `rapp-keyring: allow` pragma; "
                  "re-run with --no-pragma to see them)" % len(suppressed))
        return 0
    print("Plaintext credentials found (values are not shown):")
    print()
    for finding in findings:
        print("  %s:%s  — %s" % (finding["file"], finding["line"], finding["kind"]))
    print()
    if suppressed:
        print("(%d further match(es) suppressed by an explicit pragma)" % len(suppressed))
        print()
    print("%d finding(s). Migrate each one:" % len(findings))
    print("  1. rapp-keyring set <name> --stdin      # paste the value, hidden")
    print("  2. remove it from the file")
    print("  3. rapp-keyring run --grant <name> -- <the program that needed it>")
    print("  4. rotate the credential at its source — assume it already leaked")
    return 1


def cmd_doctor(args) -> int:
    """Health and posture check. Exit non-zero if anything needs attention."""
    problems, notes = [], []
    home = keyring_home()

    print("RAPP Keyring %s — doctor" % __version__)
    print("  platform: %s %s / python %s" % (platform.system(), platform.machine(),
                                             platform.python_version()))
    print()

    print("paths")
    if not os.path.isdir(home):
        problems.append("not initialized — run `rapp-keyring init`")
        print("  home:   %s  MISSING" % home)
    else:
        print("  home:   %s" % home)
        for path in (home, p_policy(), p_index(), p_audit(), p_store()):
            problems.extend(check_permissions(path))
    print()

    print("backends")
    any_backend = False
    for backend in (KeychainBackend(), SecretToolBackend(), DPAPIBackend(),
                    AgeBackend(os_backend_for_platform())):
        mark = "available" if backend.available else "not available"
        if backend.available:
            any_backend = True
        print("  %-12s %s" % (backend.name, mark))
    if not any_backend:
        problems.append("no usable backend — install `age`, or use a machine with an OS credential store")
    try:
        active = choose_backend()
        print("  active:      %s" % active.describe())
        if isinstance(active, AgeBackend) and active.os_backend is None:
            notes.append("age identity is a 0600 file — no OS credential store on this machine")
    except KeyringError as exc:
        problems.append(str(exc))
    print()

    print("policy")
    pol = policy_load()
    print("  default: %s" % pol.get("default"))
    sighted = [c for c, e in pol.get("callers", {}).items() if e.get("get")]
    for caller in sorted(sighted):
        grants = pol["callers"][caller]["get"]
        if caller == "shell":
            print("  %s may read plaintext: %s  (you, at a terminal)" % (caller, grants))
        else:
            notes.append(
                "caller %r may read plaintext (%s) — if that is an AI agent, secrets "
                "will enter model context" % (caller, ", ".join(grants))
            )
    if not sighted:
        print("  no caller may read plaintext — strongest posture")
    print()

    print("audit")
    ok, message, count = Audit().verify()
    print("  chain: %s (%d record(s))" % (message, count))
    if not ok:
        problems.append("audit chain is broken: %s" % message)
    print()

    print("secrets")
    names = index_names()
    print("  %d stored" % len(names))
    missing = []
    if names and not args.fast:
        try:
            backend = choose_backend()
            for name in names:
                try:
                    backend.get(name)
                except KeyringError:
                    missing.append(name)
        except KeyringError:
            pass
    if missing:
        problems.append("indexed but unreadable from the backend: %s" % ", ".join(missing))
    print()

    print("caller identity")
    print("  this process resolves to: %s" % caller_identity())
    print("  (advisory only — see SECURITY.md)")
    print()

    for note in notes:
        print("NOTE: %s" % note)
    if notes:
        print()
    if problems:
        print("PROBLEMS (%d):" % len(problems))
        for problem in problems:
            print("  - %s" % problem)
        return 1
    print("All checks passed.")
    return 0


def cmd_version(args) -> int:
    if args.json:
        print(json.dumps({
            "version": __version__,
            "spec": SPEC_VERSION,
            "python": platform.python_version(),
            "platform": platform.system(),
        }, indent=2))
    else:
        print("rapp-keyring %s (spec %d)" % (__version__, SPEC_VERSION))
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

EPILOG = """\
the shape of it:

  rapp-keyring init
  printf '%s' "$KEY" | rapp-keyring set azure/storage-key --stdin
  rapp-keyring run --grant azure/* -- ./deploy.sh

`run` is the point. The secret is injected into the child's environment as
AZURE_STORAGE_KEY, and anything the child prints is scanned on the way out so
the value cannot reach your terminal, your logs, or an agent's context.

`get` prints a secret in plaintext. It is policy-gated, needs --i-know, and is
recorded as a sighted read. Reach for it only when nothing else will do.

full docs: https://github.com/kody-w/rapp-keyring
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rapp-keyring",
        description="On-device credential broker for AI agents — use without sight.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")
    sub = parser.add_subparsers(dest="cmd")

    p = sub.add_parser("init", help="create the store, policy, and audit log")
    p.add_argument("--backend", help="keychain | secret-tool | dpapi | age (default: auto)")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("set", help="store a secret (value never touches argv)")
    p.add_argument("name")
    p.add_argument("--stdin", action="store_true", help="read the value from stdin")
    p.add_argument("--generate", type=int, metavar="N",
                   help="generate a random N-character secret instead")
    p.set_defaults(func=cmd_set)

    p = sub.add_parser("run", help="run a command with secrets injected and output redacted")
    p.add_argument("--grant", action="append", metavar="NAME",
                   help="secret to inject; globs allowed; repeatable")
    p.add_argument("--env", action="append", metavar="VAR=name",
                   help="map a secret to a specific env var name")
    p.add_argument("--no-redact", action="store_true",
                   help="do not filter child output (needed for interactive TTY programs)")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("get", help="print a secret in plaintext (policy-gated, audited)")
    p.add_argument("name")
    p.add_argument("--i-know", action="store_true",
                   help="acknowledge that this exposes the secret to the caller")
    p.set_defaults(func=cmd_get)

    p = sub.add_parser("list", help="list secret names (never values)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("rm", help="delete a secret")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("rotate", help="replace a secret's value, recording the rotation")
    p.add_argument("name")
    p.add_argument("--stdin", action="store_true")
    p.add_argument("--generate", type=int, metavar="N")
    p.set_defaults(func=cmd_rotate)

    p = sub.add_parser("policy", help="inspect and edit access policy")
    psub = p.add_subparsers(dest="policy_action", required=True)
    psub.add_parser("show")
    psub.add_parser("path")
    for verb in ("allow", "deny"):
        q = psub.add_parser(verb)
        q.add_argument("caller")
        q.add_argument("verb", choices=["run", "get"])
        q.add_argument("pattern")
    q = psub.add_parser("test")
    q.add_argument("verb", choices=["run", "get"])
    q.add_argument("pattern")
    q.add_argument("--caller")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("audit", help="read and verify the tamper-evident log")
    asub = p.add_subparsers(dest="audit_action", required=True)
    q = asub.add_parser("tail")
    q.add_argument("-n", "--count", type=int, default=20)
    q.add_argument("--json", action="store_true")
    q = asub.add_parser("all")
    q.add_argument("--json", action="store_true")
    q = asub.add_parser("verify")
    q.add_argument("--json", action="store_true")
    asub.add_parser("path")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("scan", help="find plaintext credentials in well-known config files")
    p.add_argument("paths", nargs="*")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-pragma", action="store_true",
                   help="ignore `rapp-keyring: allow` suppressions and report everything")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("doctor", help="health and posture check")
    p.add_argument("--fast", action="store_true", help="skip per-secret readback")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("version", help="print version")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_version)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if getattr(args, "version", False) and not getattr(args, "cmd", None):
        print("rapp-keyring %s (spec %d)" % (__version__, SPEC_VERSION))
        return 0
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 1

    # argparse.REMAINDER keeps a leading "--"; drop it.
    if getattr(args, "command", None) and args.command and args.command[0] == "--":
        args.command = args.command[1:]

    for attr in ("json", "i_know", "fast", "stdin", "generate", "yes", "force",
                 "no_pragma"):
        if not hasattr(args, attr):
            setattr(args, attr, False)

    try:
        return args.func(args)
    except PolicyDenied as exc:
        sys.stderr.write("rapp-keyring: %s\n" % exc)
        return 3
    except KeyringError as exc:
        sys.stderr.write("rapp-keyring: %s\n" % exc)
        return 1
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        sys.stderr.write("\ninterrupted\n")
        return 130


if __name__ == "__main__":
    sys.exit(main())
