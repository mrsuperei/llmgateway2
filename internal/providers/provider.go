package providers

import (
	"context"

	"github.com/yourorg/llm-proxy-gateway/internal/openai"
)

type Provider interface {
	Key() string
	ListModels(ctx context.Context, userID string) ([]openai.ModelEntry, error)
	ChatCompletions(ctx context.Context, userID string, req openai.ChatCompletionsRequest) (openai.ChatCompletionsResponse, error)
	ChatCompletionsStream(ctx context.Context, userID string, req openai.ChatCompletionsRequest, emit func(any) error) error
}
