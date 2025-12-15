package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type OAuthStateRepo struct{ pool *pgxpool.Pool }

// Small table-less state store using Postgres temp table pattern:
// For simplicity in starter, we keep a dedicated table.
func (r *OAuthStateRepo) Put(ctx context.Context, state, userID string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS oauth_states(
  state TEXT PRIMARY KEY,
  user_id UUID NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);`)
	if err != nil {
		return err
	}
	_, err = r.pool.Exec(ctx, `
INSERT INTO oauth_states(state, user_id, expires_at)
VALUES($1,$2,$3)
ON CONFLICT(state) DO UPDATE SET user_id=EXCLUDED.user_id, expires_at=EXCLUDED.expires_at
`, state, userID, expiresAt)
	return err
}

func (r *OAuthStateRepo) Consume(ctx context.Context, state string) (string, error) {
	var userID string
	var expires time.Time
	err := r.pool.QueryRow(ctx, `SELECT user_id, expires_at FROM oauth_states WHERE state=$1`, state).Scan(&userID, &expires)
	if err != nil || time.Now().After(expires) {
		return "", ErrNotFound
	}
	_, _ = r.pool.Exec(ctx, `DELETE FROM oauth_states WHERE state=$1`, state)
	return userID, nil
}
