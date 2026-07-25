# Using RAPP Keyring with Claude Code

## The rule to give your agent

Put this in `CLAUDE.md` so the agent knows the shape of the thing:

```markdown
## Credentials

Never read, print, or inline a credential. All credentials live in RAPP Keyring.
To use one, inject it into the command that needs it:

    rapp-keyring run --grant <name> -- <command>

`rapp-keyring list` shows what is available (names only). If you believe you
need the plaintext value, stop and ask me — do not run `rapp-keyring get`.
```

## Why this works without any trust

The default policy denies `get` to `claude-code`, so the agent cannot read a
secret even if it decides to try:

```console
$ rapp-keyring get azure/storage-key --i-know
rapp-keyring: denied: caller 'claude-code' has no 'get' grant matching 'azure/storage-key'

This is the sighted-read path — it returns the secret in plaintext, which for
an AI agent means the value enters the model context and leaves the machine.
Prefer:
    rapp-keyring run --grant azure/storage-key -- <command>
```

Meanwhile `run` works, and output is masked, so a careless command cannot leak
the value back into the transcript:

```console
$ rapp-keyring run --grant azure/storage-key -- sh -c 'echo $AZURE_STORAGE_KEY'
«redacted:azure/storage-key»
```

## Typical grants

```bash
rapp-keyring policy allow claude-code run 'azure/*'
rapp-keyring policy allow claude-code run 'github/*'
rapp-keyring policy deny  claude-code run 'prod/*'     # deny always wins
rapp-keyring policy test  run prod/db --caller claude-code
```

## Reviewing what the agent did

```bash
rapp-keyring audit tail -n 50
rapp-keyring audit verify
```
