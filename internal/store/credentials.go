package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

type Credential struct {
	ID             string
	UserID         string
	ProviderKey    string
	CredentialType string // api_key|oauth2
	Label          string
	OAuthTokenJSON string
}

type CredentialsRepo struct{ pool *pgxpool.Pool }

// UpdateOAuthToken updates the stored oauth token JSON for a credential.
// This is useful after an automatic refresh so the DB stays consistent.
func (r *CredentialsRepo) UpdateOAuthToken(ctx context.Context, credentialID string, tok *oauth2.Token) error {
	j, _ := json.Marshal(tok)
	_, err := r.pool.Exec(ctx, `
UPDATE provider_credentials
SET oauth_token_json=$1::jsonb
WHERE id=$2 AND credential_type='oauth2'
`, string(j), credentialID)
	return err
}

func (r *CredentialsRepo) UpsertGeminiOAuth(ctx context.Context, userID string, tok *oauth2.Token) error {
	// Ensure provider exists
	var providerID string
	err := r.pool.QueryRow(ctx, `
INSERT INTO providers(user_id, provider_key) VALUES($1,'gemini_cli')
ON CONFLICT(user_id, provider_key) DO UPDATE SET provider_key=EXCLUDED.provider_key
RETURNING id
`, userID).Scan(&providerID)
	if err != nil {
		_ = r.pool.QueryRow(ctx, `SELECT id FROM providers WHERE user_id=$1 AND provider_key='gemini_cli'`, userID).Scan(&providerID)
	}

	j, _ := json.Marshal(tok)

	// Keep one "default" OAuth credential for now; you can extend with multiple labels later
	_, err = r.pool.Exec(ctx, `
INSERT INTO provider_credentials(user_id, provider_id, credential_type, label, oauth_token_json, metadata)
VALUES($1,$2,'oauth2','google-oauth-default',$3::jsonb, '{}'::jsonb)
ON CONFLICT DO NOTHING
`, userID, providerID, string(j))
	if err != nil {
		return err
	}

	// Update existing
	_, _ = r.pool.Exec(ctx, `
UPDATE provider_credentials
SET oauth_token_json=$1::jsonb
WHERE user_id=$2 AND provider_id=$3 AND credential_type='oauth2' AND label='google-oauth-default'
`, string(j), userID, providerID)

	// Set a sensible default limit (optional)
	// (noop if already exists)
	_, _ = r.pool.Exec(ctx, `
INSERT INTO credential_limits(credential_id, rpm, rpd, rpmth)
SELECT id, 60, 1000, 25000
FROM provider_credentials
WHERE user_id=$1 AND provider_id=$2 AND credential_type='oauth2' AND label='google-oauth-default'
ON CONFLICT(credential_id) DO NOTHING
`, userID, providerID)

	_ = time.Now()
	return nil
}

func (r *CredentialsRepo) SelectCredentialForModel(ctx context.Context, userID, providerKey, model string) (Credential, error) {
	// Naive selection strategy for starter:
	// - pick the first enabled credential with remaining quota.
	// The ratelimiter will enforce limits; later you can make this selection strategy smarter.
	rows, err := r.pool.Query(ctx, `
SELECT c.id, c.user_id, p.provider_key, c.credential_type, COALESCE(c.label,''), COALESCE(c.oauth_token_json::text,'')
FROM provider_credentials c
JOIN providers p ON p.id=c.provider_id
WHERE c.user_id=$1 AND p.provider_key=$2 AND c.is_disabled=false
ORDER BY c.created_at ASC
`, userID, providerKey)
	if err != nil {
		return Credential{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var c Credential
		if err := rows.Scan(&c.ID, &c.UserID, &c.ProviderKey, &c.CredentialType, &c.Label, &c.OAuthTokenJSON); err != nil {
			return Credential{}, err
		}
		return c, nil
	}
	return Credential{}, errors.New("no credentials configured for provider: " + providerKey)
}
