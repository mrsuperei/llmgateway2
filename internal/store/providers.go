package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ProvidersRepo struct{ pool *pgxpool.Pool }

func (r *ProvidersRepo) EnsureProvider(ctx context.Context, userID, providerKey string) (string, error) {
	var id string
	err := r.pool.QueryRow(ctx, `
INSERT INTO providers(user_id, provider_key)
VALUES($1,$2)
ON CONFLICT(user_id, provider_key) DO UPDATE SET provider_key=EXCLUDED.provider_key
RETURNING id
`, userID, providerKey).Scan(&id)
	if err != nil {
		// If RETURNING on conflict doesn't return, fallback select:
		_ = r.pool.QueryRow(ctx, `SELECT id FROM providers WHERE user_id=$1 AND provider_key=$2`, userID, providerKey).Scan(&id)
	}
	return id, nil
}

func (r *ProvidersRepo) ListProviderKeysForUser(ctx context.Context, userID string) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
SELECT DISTINCT p.provider_key
FROM providers p
JOIN provider_credentials c ON c.provider_id=p.id
WHERE p.user_id=$1 AND c.is_disabled=false
`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}
