# Security model

This document is written to be argued with, not to reassure. A control trusted
beyond its actual boundary is more dangerous than no control at all, so the
limits are stated as plainly as the guarantees.

## What this defends

RAPP Keyring exists to close one specific, newly common failure: **an AI agent
reads a credential, and the credential thereby leaves the machine.**

When an agent reads a secret, that value enters the model's context window. It
is transmitted to a model provider, it lands in a session transcript, it may be
retained, and it may be reproduced later into a file, a log, or a pull request.
None of that is malicious. It is the ordinary operation of the system. But the
result is indistinguishable from disclosure.

Traditional secret managers do not address this, because they are built around
the assumption that *retrieving* a secret is the safe operation and *storing* it
is the risky one. For agents, that is inverted.

## Trust boundaries

```
   ┌─────────────────────────────────────────────────────────┐
   │  the model provider (a third party)                     │  ← secrets must
   │  receives everything in the agent's context             │     never reach here
   └────────────────────────▲────────────────────────────────┘
                            │ context
   ┌────────────────────────┴────────────────────────────────┐
   │  the AI agent process                                   │  ← untrusted with
   │  runs as your user, has a shell                         │     plaintext
   └────────────────────────┬────────────────────────────────┘
                            │ exec
   ┌────────────────────────▼────────────────────────────────┐
   │  rapp-keyring                                           │  ← the broker
   │  policy · audit · redaction                             │
   └────────────────────────┬────────────────────────────────┘
                            │ env
   ┌────────────────────────▼────────────────────────────────┐
   │  the child process that actually needs the credential   │  ← trusted with
   │  (deploy.sh, gh, az, curl)                              │     plaintext
   └─────────────────────────────────────────────────────────┘
```

The design goal is to move the credential from the OS credential store into the
**child process** without it ever transiting the **agent process's context**.

## Threats and dispositions

| # | Threat | Disposition |
|---|---|---|
| T1 | Secret sits in a plaintext config file and syncs to a cloud | **Mitigated.** Secrets live in the OS credential store. `scan` finds existing plaintext so it can be migrated. |
| T2 | Secret is visible in `ps` while being stored | **Mitigated.** Values are never passed in `argv`; they travel over stdin. Proved by conformance C2, which samples `ps` continuously during a write. |
| T3 | Agent reads a secret and it enters model context | **Mitigated by default.** `get` is denied to every agent caller in the shipped policy, and additionally requires `--i-know`. The intended path, `run`, never returns the value. |
| T4 | A command echoes the secret, and the agent reads it from the output | **Mitigated.** Child stdout and stderr are filtered, including base64, hex, URL-encoded and JSON-escaped forms, and across read boundaries. Proved by C6 and C7. |
| T5 | Secret leaks into the audit log or into `list` output | **Mitigated.** Only names, sizes, and truncated digests are recorded. Proved by C9. |
| T6 | Audit log is edited to hide an access | **Detected, not prevented.** The log is hash-chained; modification, deletion, and forged appends are all detectable via `audit verify`. A local user *can* delete the whole file — see below. |
| T7 | A partial write leaves a silently truncated secret | **Mitigated.** On macOS the chunk header is written last as a commit point and carries a length and digest; an incomplete value fails its integrity check on read rather than being returned wrong. |
| T8 | The tool phones home | **Mitigated.** No network code exists. C1 proves it by running the CLI with `socket()` booby-trapped. |
| T9 | A hostile local process impersonates a trusted caller | **NOT mitigated.** See below. |
| T10 | A granted child process exfiltrates the secret | **NOT mitigated.** See below. |
| T11 | An attacker with your user account reads the OS credential store | **NOT mitigated.** See below. |

## What this explicitly does not stop

**Caller identity is advisory.** Caller identity is derived from walking the
process ancestry. Anything running as your user can set `RAPP_KEYRING_CALLER`
and claim to be anything. During development of this tool the author's own agent
demonstrated exactly that, deliberately, and it is recorded here rather than
quietly fixed, because it cannot be fixed at this layer. Local process identity
is not attestable without OS support this tool does not require.

What policy therefore *is*: a mechanism that makes over-reach **visible,
auditable, and inconvenient**, and that prevents the overwhelmingly common case
— an agent following the path of least resistance straight into a plaintext
read. What it is **not**: a boundary against a local adversary.

**A granted secret is a used secret.** `run` places the plaintext in the child's
environment. That is the entire point. A malicious or compromised child can send
it anywhere. Grant narrowly, and treat `--grant` as an authorization decision.

**Redaction covers the channel it owns.** Child stdout and stderr are filtered.
A child that writes the secret to a file, opens its own socket, or renders it to
a terminal it controls directly is not covered. Redaction is a safety net for
accidental echo, not a containment boundary.

**Local root, and you, win.** Anyone who can run as your user can query the OS
credential store directly, with or without this tool. RAPP Keyring raises the
floor on accidents and on disclosure-by-context. It does not defeat an attacker
who already holds your account. This is the same boundary every endpoint DLP
product has, and pretending otherwise is how a control gets trusted where it
should not be.

**The audit log can be deleted.** Tampering is *detectable*; destruction is not
*preventable* by a user-space tool writing to the user's own home directory. For
an environment where that matters, ship the log to a collector — the format is
append-only JSONL and is designed to be tailed.

## Reporting a vulnerability

Open a security advisory on the repository:
<https://github.com/kody-w/rapp-keyring/security/advisories/new>

Please include the version (`rapp-keyring version --json`), the platform, and a
reproduction. If the finding is that one of the "not mitigated" items above is
worse than described, that is a valid and welcome report.
