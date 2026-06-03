# GateKeeper CLI

The CLI authenticates through OAuth device authorization and stores tokens in
the OS keyring when available, falling back to a `0600` local credentials file.

```bash
gatekeeper login --url https://gatekeeper.b3n.in
gatekeeper whoami
gatekeeper token list
```

