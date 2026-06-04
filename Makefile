.PHONY: test-api lint-api build-ui compose-check api-dev ui-dev

test-api:
	cd api && uv run pytest

lint-api:
	cd api && uv run ruff check app tests

build-ui:
	pnpm --filter @b3n/gatekeeper-ui build

compose-check:
	GATEKEEPER_ENV_FILE=.env.example.selfhost docker compose -f deploy/docker-compose.selfhost.yml config -q

api-dev:
	cd api && uv run uvicorn app.main:app --reload

ui-dev:
	pnpm --filter @b3n/gatekeeper-ui dev
