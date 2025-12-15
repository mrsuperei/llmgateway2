package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

type UsersRepo struct{ pool *pgxpool.Pool }

func hashKey(k string) string {
	h := sha256.Sum256([]byte(k))
	return hex.EncodeToString(h[:])
}

var ErrNotFound = errors.New("not found")

func (r *UsersRepo) ResolveUserIDFromGatewayKey(ctx context.Context, rawKey string) (string, error) {
	kh := hashKey(rawKey)
	var id string
	err := r.pool.QueryRow(ctx, `
SELECT user_id
FROM user_api_keys
WHERE key_hash=$1 AND revoked_at IS NULL
`, kh).Scan(&id)
	if err != nil {
		return "", ErrNotFound
	}
	return id, nil
}
