package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/yourorg/llm-proxy-gateway/internal/store"
)

type ctxKey string

const (
	ctxKeyRequestID ctxKey = "rid"
	ctxKeyUserID    ctxKey = "uid"
)

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" {
			var b [8]byte
			_, _ = rand.Read(b[:])
			rid = hex.EncodeToString(b[:])
		}
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, rid)
		w.Header().Set("X-Request-Id", rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func Recover(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error().
						Str("rid", RequestIDFrom(r.Context())).
						Interface("panic", rec).
						Bytes("stack", debug.Stack()).
						Msg("panic")
					http.Error(w, "internal error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

func AccessLog(logger zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			logger.Info().
				Str("rid", RequestIDFrom(r.Context())).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Dur("dur_ms", time.Since(start)).
				Msg("req")
		})
	}
}

func AuthenticateUser(st *store.Store) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			key := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			uid, err := st.Users().ResolveUserIDFromGatewayKey(r.Context(), key)
			if err != nil {
				http.Error(w, "invalid api key", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), ctxKeyUserID, uid)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

func UserIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyUserID).(string); ok {
		return v
	}
	return ""
}
