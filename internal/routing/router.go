package routing

import (
	"context"
	"errors"
	"strings"

	"github.com/yourorg/llm-proxy-gateway/internal/store"
)

// Router picks a provider based on model prefix and user routes.
// Defaults:
// - model starts with "gemini-" => gemini_cli
// - model starts with "gpt-" => openai
// - model starts with "claude-" => anthropic
type Router struct {
	st *store.Store
}

func NewRouter(st *store.Store) *Router { return &Router{st: st} }

func (r *Router) RouteModel(ctx context.Context, userID, model string) (string, error) {
	// DB override first
	if p, ok, err := r.st.Routes().RouteForModel(ctx, userID, model); err != nil {
		return "", err
	} else if ok {
		return p, nil
	}

	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "gemini-"):
		return "gemini_cli", nil
	case strings.HasPrefix(m, "gpt-"):
		return "openai", nil
	case strings.HasPrefix(m, "claude-"):
		return "anthropic", nil
	default:
		return "", errors.New("unknown model prefix; add a route in model_routes")
	}
}
