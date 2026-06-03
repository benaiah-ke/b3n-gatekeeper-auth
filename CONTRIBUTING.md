# Contributing

GateKeeper is security-sensitive infrastructure. Keep changes small, tested,
and explicit.

## Development Rules

- Do not log secrets, one-time codes, refresh tokens, API tokens, or private
  keys.
- Add or update tests for auth behavior, token lifecycle, role checks, and
  security boundaries.
- Prefer explicit schemas and migrations over implicit table creation.
- Keep public API changes documented in `docs/architecture.md` or the relevant
  integration guide.
- Do not add a SaaS/vendor dependency for core auth behavior.

## Checks

```bash
make test-api
make lint-api
make build-ui
make compose-check
```

