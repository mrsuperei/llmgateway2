-- Multi-tenant core tables + credentials + rate limits + simple routing

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT,
  display_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Gateway API keys to authenticate callers against this proxy
CREATE TABLE IF NOT EXISTS user_api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  key_hash TEXT NOT NULL UNIQUE,
  label TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at TIMESTAMPTZ
);

-- Providers configured per user/tenant
CREATE TABLE IF NOT EXISTS providers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_key TEXT NOT NULL, -- "openai", "anthropic", "gemini_cli", ...
  base_url TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, provider_key)
);

-- Credentials per provider: supports API keys and OAuth tokens, multiple per provider.
CREATE TABLE IF NOT EXISTS provider_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider_id UUID NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
  credential_type TEXT NOT NULL, -- "api_key" | "oauth2"
  label TEXT,
  -- api_key
  api_key_ciphertext BYTEA,
  -- oauth2 tokens (encrypted at rest if you wire KMS later; for starter we store plaintext JSON)
  oauth_token_json JSONB,
  -- metadata (e.g., project id, email)
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  is_disabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Rate limit config per credential (add more knobs as you need)
CREATE TABLE IF NOT EXISTS credential_limits (
  credential_id UUID PRIMARY KEY REFERENCES provider_credentials(id) ON DELETE CASCADE,
  rpm INTEGER,  -- requests per minute
  rpd INTEGER,  -- requests per day
  rpmth INTEGER -- requests per month
);

-- Counters for rate limiting (windowed)
CREATE TABLE IF NOT EXISTS credential_counters (
  credential_id UUID NOT NULL REFERENCES provider_credentials(id) ON DELETE CASCADE,
  window_type TEXT NOT NULL, -- 'minute' | 'day' | 'month'
  window_start TIMESTAMPTZ NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (credential_id, window_type, window_start)
);

-- Optional: explicit model routing per user.
CREATE TABLE IF NOT EXISTS model_routes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  model_prefix TEXT NOT NULL,     -- e.g. "gpt-", "claude-", "gemini-"
  provider_key TEXT NOT NULL,     -- e.g. "openai", "anthropic", "gemini_cli"
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(user_id, model_prefix)
);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_provider_credentials_user_provider ON provider_credentials(user_id, provider_id);
CREATE INDEX IF NOT EXISTS idx_credential_counters_window
ON credential_counters(credential_id, window_type, window_start);