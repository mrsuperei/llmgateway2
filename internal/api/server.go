package api

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/yourorg/llm-proxy-gateway/internal/config"
	"github.com/yourorg/llm-proxy-gateway/internal/middleware"
	"github.com/yourorg/llm-proxy-gateway/internal/providers"
	"github.com/yourorg/llm-proxy-gateway/internal/store"
)

type Server struct {
	Router http.Handler
}

func NewServer(cfg config.Config, pool *pgxpool.Pool, logger zerolog.Logger) (*Server, error) {
	st := store.New(pool)

	reg := providers.NewRegistry(logger, st, cfg)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recover(logger))
	r.Use(middleware.AccessLog(logger))

	// Public UI endpoints for OAuth login (Gemini CLI)
	r.Get("/ui/gemini", GeminiLoginPage(cfg))
	r.Get("/oauth2/start", OAuthStart(cfg, st, logger))
	r.Get("/oauth2/callback", OAuthCallback(cfg, st, logger))

	// Health
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); _, _ = w.Write([]byte("ok")) })

	// OpenAI-compatible API (requires gateway user api key)
	r.Route("/v1", func(r chi.Router) {
		r.Use(middleware.AuthenticateUser(st))

		r.Get("/models", ListModels(reg))
		r.Post("/chat/completions", ChatCompletions(reg))
		r.Post("/completions", Completions(reg))
	})

	if r == nil {
		return nil, errors.New("router nil")
	}
	return &Server{Router: r}, nil
}
