# RAPP Keyring in CI

RAPP Keyring is for *developer machines*, where an interactive agent is the
risk. In CI, your platform's own secret store is the right tool — it already
scopes secrets to a job and masks them in logs.

Use RAPP Keyring in CI for one thing: **proving no credential was committed.**

```yaml
- name: The repo must not contain credentials
  run: python3 rapp_keyring.py scan $(git ls-files)
```

`scan` exits non-zero on a finding and reports file, line, and the kind of
secret — never the value, so a failing build log does not become the leak.
