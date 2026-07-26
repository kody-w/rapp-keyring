# RAPP Keyring

> An on-device credential broker for AI agents. The agent gets to **use** a
> secret without ever getting to **see** it.

[![conformance](https://github.com/kody-w/rapp-keyring/actions/workflows/ci.yml/badge.svg)](https://github.com/kody-w/rapp-keyring/actions/workflows/ci.yml)

---

## The problem

An AI agent running on your machine needs real credentials — to deploy, to call
an API, to read a database. Every ordinary way of giving it one is a leak:

| What people do | How it leaks |
|---|---|
| Put the key in `settings.json` / `.env` | Settings sync uploads it. Screenshots catch it. It gets committed. |
| `export API_KEY=...` | Inherited by every child process, and dumped by any `env` call. |
| Let the agent read the secret | **The value enters the model's context** — it leaves your machine, lands in a transcript, and may be echoed into a file or a PR. |

That third row is the one that has no traditional answer, and it is the one that
matters most now. A secret an agent has *read* is a secret you have disclosed to
a third party, whatever your intentions were.

## The idea: use without sight

The primary interface is not "give me the secret." It is **"run this command
with the secret injected."**

```bash
rapp-keyring run --grant azure/storage-key -- ./deploy.sh
```

The value is placed in the child's environment as `AZURE_STORAGE_KEY`. It is
never returned to the caller. And everything the child prints is scanned on the
way out, so the secret cannot escape into your terminal, your logs, or an
agent's context:

```console
$ rapp-keyring run --grant azure/storage-key -- sh -c 'echo "key is $AZURE_STORAGE_KEY"'
key is «redacted:azure/storage-key»
```

That masking covers re-encoded forms too — base64, hex, URL-encoded, and
JSON-escaped — because a leak rarely arrives verbatim.

Reading a secret in the clear is still possible when you genuinely need it, but
it is a **separate, policy-gated action** that must be asked for explicitly and
is recorded distinctly in a tamper-evident log.

---

## Install

```bash
curl -fsSL https://kody-w.github.io/rapp-keyring/install.sh | bash
```

Or just take the file — it is one script with no dependencies:

```bash
curl -fsSLO https://raw.githubusercontent.com/kody-w/rapp-keyring/main/rapp_keyring.py
python3 rapp_keyring.py --help
```

Requires Python 3.8+. No `pip install`, no third-party packages, no network
access at runtime.

---

## Use

```bash
rapp-keyring init

# store a secret — the value goes over stdin, never through argv
printf '%s' "$MY_KEY" | rapp-keyring set azure/storage-key --stdin

# or be prompted, with the input hidden
rapp-keyring set github/pat

# use it
rapp-keyring run --grant azure/storage-key -- ./deploy.sh

# globs work; several secrets at once
rapp-keyring run --grant 'azure/*' --grant github/pat -- ./release.sh

# map to a specific variable name
rapp-keyring run --grant github/pat --env GH_TOKEN=github/pat -- gh pr create
```

Find what is already lying around in plaintext:

```console
$ rapp-keyring scan
Plaintext credentials found (values are not shown):

  ~/Library/Application Support/Code/User/settings.json:6  — Azure storage account key

1 finding(s). Migrate each one:
  1. rapp-keyring set <name> --stdin
  2. remove it from the file
  3. rapp-keyring run --grant <name> -- <the program that needed it>
  4. rotate the credential at its source — assume it already leaked
```

---

## Policy

Two verbs, and the difference between them is the whole design:

| Verb | Meaning | Safe for an agent? |
|---|---|---|
| `run` | inject into a child process; caller never sees the value | **yes** |
| `get` | return the plaintext to the caller | **no** — it enters model context |

Out of the box, agents may `run` and may not `get`:

```json
{
  "default": "deny",
  "callers": {
    "shell":       { "run": ["*"], "get": ["*"] },
    "claude-code": { "run": ["*"], "get": [] },
    "copilot-cli": { "run": ["*"], "get": [] },
    "brainstem":   { "run": ["*"], "get": [] },
    "*":           { "run": [],    "get": [] }
  }
}
```

Tighten or widen it per caller, with globs and explicit denies:

```bash
rapp-keyring policy allow ci run 'azure/*'
rapp-keyring policy deny  ci run 'prod/*'      # deny always wins
rapp-keyring policy test  run azure/key --caller ci
```

---

## Audit

Every action appends to a hash-chained JSONL log. Each record carries the digest
of the record before it, so modifying, deleting, or forging an entry breaks the
chain at a detectable point.

```console
$ rapp-keyring audit tail -n 3
2026-07-25T19:51:02Z  seq=15  allow  run   claude-code  azure/storage-key
2026-07-25T19:52:41Z  seq=16  deny   get   claude-code  azure/storage-key
2026-07-25T19:53:10Z  seq=17  allow  get   shell        azure/storage-key SIGHTED

$ rapp-keyring audit verify
OK — chain intact (17 record(s))
```

Secret *values* never appear in the log — only names, sizes, and truncated
fingerprints that identify a value without revealing it.

---

## Where secrets actually live

| Platform | Store |
|---|---|
| macOS | Keychain, via the stdin prompt path so no value ever reaches `argv` |
| Linux | libsecret / GNOME Keyring (`secret-tool`) |
| Windows | DPAPI, CurrentUser scope |
| Anywhere | age-encrypted files, with the identity held in the OS store |

A note on the macOS path, because it is the sort of detail that decides whether
a tool is trustworthy: `security add-generic-password`'s prompt has a hard
128-character buffer, and a longer value is **silently truncated rather than
rejected**. Passing the value in `argv` instead would have been the easy fix and
would have exposed every secret to `ps`. Instead, values are split into 64-byte
chunks with a header written last as the commit point, so an interrupted write
leaves nothing readable rather than something subtly wrong.

---

## Verify the claims yourself

```bash
python3 conformance.py       # 12 checks, each one proved against the running code
python3 tests/test_keyring.py -v
```

The conformance gate does not accept inspection as evidence. C1 runs the CLI
with `socket()` booby-trapped to prove nothing reaches the network. C2 takes
hundreds of thousands of `ps` snapshots *during* a write and fails if the secret
ever appears in any process's arguments. C7 splits a secret at every possible
byte boundary to prove redaction cannot be defeated by chunking.

```
PASS  C1  The program opens no network connections.
PASS  C2  Secret values are never passed as command-line arguments.
PASS  C3  Policy denies by default; unknown callers get nothing.
PASS  C4  No AI agent may read a secret in plaintext by default.
PASS  C5  A sighted read requires an explicit acknowledgement.
PASS  C6  An injected secret cannot escape through the child's output.
PASS  C7  Redaction holds when a secret is split across reads.
PASS  C8  The audit log is tamper-evident.
PASS  C9  Secret values never appear in the audit log or in `list`.
PASS  C10 Any secret shape round-trips: binary, multi-line, unicode, large.
PASS  C11 State files are readable only by their owner.
PASS  C12 The build reports a version and a spec level.
```

---

## What this does not protect against

Read [SECURITY.md](SECURITY.md) before deploying it. The short version, stated
plainly because a control trusted beyond its boundary is worse than no control:

- **Caller identity is advisory.** It is derived from process ancestry. Anything
  running as your user can set `RAPP_KEYRING_CALLER` and claim to be you. Policy
  makes over-reach *visible and auditable*; it is not a security boundary
  against a hostile local process.
- **A granted secret is a used secret.** `run` hands the value to the child. A
  malicious child can exfiltrate it by means other than stdout.
- **Root, or you, can read the OS credential store directly.** This tool raises
  the floor on accidents and disclosure-by-context. It does not defeat an
  attacker who already has your user account.

---

## Use with RAPP

RAPP Keyring is the credential layer for the [RAPP](https://github.com/kody-w)
ecosystem. It pairs with [RAPP Light](https://github.com/kody-w/rapp-light),
which governs *what an agent may do*, while Keyring governs *what an agent may
hold*. See [`examples/`](examples/) for wiring it into Claude Code, the RAPP
brainstem, and CI.

---

## License

MIT — see [LICENSE](LICENSE).

---

<sub>RAPP Keyring is a trademark of Wildhaven Homes LLC. Code is MIT licensed; the license does not grant rights to the name. [Trademark notice](TRADEMARK.md)</sub>
