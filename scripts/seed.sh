#!/usr/bin/env bash
set -euo pipefail

DATABASE_URL="${DATABASE_URL:-postgres://postgres:postgres@localhost:5432/llmproxy?sslmode=disable}"

# Create a user + gateway api key
USER_EMAIL="${USER_EMAIL:-demo@example.com}"
USER_NAME="${USER_NAME:-Demo User}"

# generate random key
GATEWAY_API_KEY="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

KEY_HASH="$(python3 - <<PY
import hashlib
print(hashlib.sha256("${GATEWAY_API_KEY}".encode()).hexdigest())
PY
)"

psql "${DATABASE_URL}" <<SQL
INSERT INTO users(email, display_name) VALUES ('${USER_EMAIL}', '${USER_NAME}') RETURNING id;
SQL

USER_ID="$(psql "${DATABASE_URL}" -tA -c "SELECT id FROM users WHERE email='${USER_EMAIL}' ORDER BY created_at DESC LIMIT 1;")"

psql "${DATABASE_URL}" <<SQL
INSERT INTO user_api_keys(user_id, key_hash, label) VALUES ('${USER_ID}', '${KEY_HASH}', 'seed');
-- Default routing for gemini models
INSERT INTO model_routes(user_id, model_prefix, provider_key) VALUES ('${USER_ID}','gemini-','gemini_cli')
ON CONFLICT DO NOTHING;
SQL

echo "USER_ID=${USER_ID}"
echo "GATEWAY_API_KEY=${GATEWAY_API_KEY}"
echo ""
echo "Use: Authorization: Bearer ${GATEWAY_API_KEY}"
