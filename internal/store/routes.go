package store

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RoutesRepo struct{ pool *pgxpool.Pool }

func (r *RoutesRepo) RouteForModel(ctx context.Context, userID, model string) (providerKey string, ok bool, err error) {
	prefix := modelPrefix(model)
	err = r.pool.QueryRow(ctx, `
SELECT provider_key
FROM model_routes
WHERE user_id=$1 AND model_prefix=$2
`, userID, prefix).Scan(&providerKey)
	if err != nil {
		return "", false, nil
	}
	return providerKey, true, nil
}

func modelPrefix(m string) string {
	m = strings.ToLower(m)
	if i := strings.Index(m, "-"); i > 0 {
		return m[:i+1]
	}
	return m
}
