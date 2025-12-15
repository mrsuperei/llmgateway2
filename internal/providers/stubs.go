package providers

import (
	"context"
	"errors"
	"time"

	"github.com/rs/zerolog"

	"github.com/yourorg/llm-proxy-gateway/internal/openai"
	"github.com/yourorg/llm-proxy-gateway/internal/store"
)

type stubAdapter struct {
	key string
	log zerolog.Logger
	_   *store.Store
}

func NewOpenAIStubAdapter(log zerolog.Logger, _ *store.Store) Provider {
	return &stubAdapter{key: "openai", log: log}
}
func NewAnthropicStubAdapter(log zerolog.Logger, _ *store.Store) Provider {
	return &stubAdapter{key: "anthropic", log: log}
}
func (s *stubAdapter) Key() string { return s.key }

func (s *stubAdapter) ListModels(ctx context.Context, userID string) ([]openai.ModelEntry, error) {
	// placeholder
	return []openai.ModelEntry{
		{ID: s.key + "-stub-model", Object: "model", OwnedBy: s.key},
	}, nil
}
func (s *stubAdapter) ChatCompletions(ctx context.Context, userID string, req openai.ChatCompletionsRequest) (openai.ChatCompletionsResponse, error) {
	return openai.ChatCompletionsResponse{}, errors.New("stub provider: implement real adapter")
}
func (s *stubAdapter) ChatCompletionsStream(ctx context.Context, userID string, req openai.ChatCompletionsRequest, emit func(any) error) error {
	_ = emit(map[string]any{
		"id":      "stub",
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   req.Model,
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": "stub provider: implement real adapter"}}},
	})
	return nil
}
