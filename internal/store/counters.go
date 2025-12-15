package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type CountersRepo struct{ pool *pgxpool.Pool }

func (r *CountersRepo) IncAndCheck(ctx context.Context, credentialID, window string, windowStart time.Time, limit int) (bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var count int
	err = tx.QueryRow(ctx, `
INSERT INTO credential_counters(credential_id, window_type, window_start, count)
VALUES($1,$2,$3,1)
ON CONFLICT (credential_id, window_type, window_start)
DO UPDATE SET count = credential_counters.count + 1
RETURNING count
`, credentialID, window, windowStart).Scan(&count)
	if err != nil {
		return false, err
	}

	if err := tx.Commit(ctx); err != nil {
		return false, err
	}
	return count <= limit, nil
}
