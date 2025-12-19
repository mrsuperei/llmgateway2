package providers

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/yourorg/llm-proxy-gateway/internal/config"
	"github.com/yourorg/llm-proxy-gateway/internal/openai"
	"github.com/yourorg/llm-proxy-gateway/internal/routing"
	"github.com/yourorg/llm-proxy-gateway/internal/store"
)

type Registry struct {
	log    zerolog.Logger
	store  *store.Store
	cfg    any
	router *routing.Router
	adpts  map[string]Provider
}

func NewRegistry(log zerolog.Logger, st *store.Store, cfg any) *Registry {
	r := &Registry{
		log:   log,
		store: st,
		cfg:   cfg,
		adpts: make(map[string]Provider),
	}
	r.router = routing.NewRouter(st)

	// Register adapters here
	if c, ok := cfg.(config.Config); ok {
		// Use CLI adapter (unofficial CLI endpoints)
		r.adpts["gemini_cli"] = NewGeminiCLIAdapter(log, st, c)
	} else {
		// fallback: zero config
		r.adpts["gemini_cli"] = NewGeminiCLIAdapter(log, st, config.Config{})
	}
	r.adpts["openai"] = NewOpenAIStubAdapter(log, st)       // placeholder
	r.adpts["anthropic"] = NewAnthropicStubAdapter(log, st) // placeholder
	return r
}

func (r *Registry) resolveProvider(ctx context.Context, userID, model string) (Provider, string, error) {
	provKey, err := r.router.RouteModel(ctx, userID, model)
	if err != nil {
		return nil, "", err
	}
	adpt, ok := r.adpts[provKey]
	if !ok {
		return nil, "", errors.New("provider not configured: " + provKey)
	}
	return adpt, provKey, nil
}

func (r *Registry) ListModels(ctx context.Context, userID string) ([]openai.ModelEntry, error) {
	// Simple union of all providers that have at least one credential.
	keys, err := r.store.Providers().ListProviderKeysForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	var out []openai.ModelEntry
	for _, k := range keys {
		adpt, ok := r.adpts[k]
		if !ok {
			continue
		}
		ms, err := adpt.ListModels(ctx, userID)
		if err != nil {
			r.log.Warn().Err(err).Str("provider", k).Msg("list models failed")
			continue
		}
		out = append(out, ms...)
	}
	return out, nil
}

func (r *Registry) ChatCompletions(ctx context.Context, userID string, req openai.ChatCompletionsRequest) (openai.ChatCompletionsResponse, error) {
	adpt, provKey, err := r.resolveProvider(ctx, userID, req.Model)
	if err != nil {
		return openai.ChatCompletionsResponse{}, err
	}
	start := time.Now()
	resp, err := adpt.ChatCompletions(ctx, userID, req)
	r.log.Info().
		Str("provider", provKey).
		Str("model", req.Model).
		Dur("dur", time.Since(start)).
		Err(err).
		Msg("chat")
	return resp, err
}

func (r *Registry) ChatCompletionsStream(ctx context.Context, userID string, req openai.ChatCompletionsRequest, emit func(any) error) error {
	adpt, _, err := r.resolveProvider(ctx, userID, req.Model)
	if err != nil {
		return err
	}
	return adpt.ChatCompletionsStream(ctx, userID, req, emit)
}

func ModelPrefix(model string) string {
	if i := strings.Index(model, "-"); i > 0 {
		return model[:i+1]
	}
	return model
}
