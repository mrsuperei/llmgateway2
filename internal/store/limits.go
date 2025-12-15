package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Limits struct {
	RPM   *int
	RPD   *int
	RPMth *int
}

type LimitsRepo struct{ pool *pgxpool.Pool }

func (r *LimitsRepo) Get(ctx context.Context, credentialID string) (Limits, error) {
	var rpm, rpd, rpmth *int
	_ = r.pool.QueryRow(ctx, `
SELECT rpm, rpd, rpmth
FROM credential_limits
WHERE credential_id=$1
`, credentialID).Scan(&rpm, &rpd, &rpmth)
	return Limits{RPM: rpm, RPD: rpd, RPMth: rpmth}, nil
}
