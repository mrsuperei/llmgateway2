# LLM Proxy Gateway (starter)

Go starter project for a multi-tenant LLM proxy gateway.

## What’s included
- OpenAI-compatible endpoints:
  - `POST /v1/chat/completions`
  - `GET /v1/models`
- Multi-user (tenant) auth via gateway API keys (hashed in Postgres).
- Provider abstraction layer + routing by model prefix (`gemini-`, `gpt-`, `claude-`) with DB overrides.
- Credential storage per user/provider (multiple credentials supported).
- Postgres-backed per-credential window rate limits (minute/day/month).
- Gemini CLI adapter **(starter)**:
  - `GET /ui/gemini` page to start Google OAuth login
  - stores OAuth token JSON in Postgres
  - executes `gemini` CLI subprocess for chat requests (non-streaming; streaming emits one chunk).

> NOTE: The Gemini CLI credential injection varies across CLI versions.
> This starter stores tokens and wires the plumbing; you’ll likely adjust
> `internal/providers/gemini_cli.go` to match your CLI’s expected auth format.

## Quickstart

### 1) Start Postgres
```bash
docker compose up -d
```

### 2) Create a user + gateway API key
Run the seed script (requires `psql`):
```bash
scripts/seed.sh
```
It prints a `GATEWAY_API_KEY`. Keep it.

### 3) Run the gateway
```bash
cp .env.example .env
# Fill GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET if you want OAuth UI
go run ./cmd/gateway
```

### 4) Login (Gemini OAuth)
Open:
- http://localhost:8080/ui/gemini

Paste your gateway key, click Login.

### 5) Chat via OpenAI-compatible endpoint
```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $GATEWAY_API_KEY" \
  -d '{
    "model":"gemini-2.5-pro",
    "messages":[{"role":"user","content":"Hello from the gateway!"}]
  }'
```

## Project layout

- `cmd/gateway`: main
- `internal/api`: HTTP routes + handlers + OAuth UI
- `internal/providers`: provider adapters
- `internal/routing`: model -> provider routing
- `internal/store`: Postgres repositories
- `internal/ratelimit`: per-credential limiting
- `internal/openai`: minimal OpenAI schema types
- `internal/db`: migration runner + SQL migrations

## Next steps (recommended)
- Encrypt stored credentials (api keys + OAuth tokens) with envelope encryption.
- Implement real OpenAI/Anthropic adapters using official endpoints.
- Improve key selection rules: token-bucket + health checks + exponential backoff.
- Streaming support: parse CLI streaming output or switch to official HTTP APIs for streaming.
- Add admin API/UI to manage users/providers/credentials/limits/routes.
