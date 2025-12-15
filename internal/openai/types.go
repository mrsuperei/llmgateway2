package openai

// Minimal subset of the OpenAI-compatible schema used by this starter.
// Expand as needed (tools, multimodal, response_format, etc).

type ChatCompletionsRequest struct {
	Model       string            `json:"model"`
	Messages    []ChatMessage     `json:"messages"`
	Stream      bool              `json:"stream,omitempty"`
	Temperature *float64          `json:"temperature,omitempty"`
	MaxTokens   *int              `json:"max_tokens,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type ChatMessage struct {
	Role    string `json:"role"` // system|user|assistant|tool
	Content any    `json:"content"`
}

type ChatCompletionsResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason,omitempty"`
	} `json:"choices"`
}

type ModelsResponse struct {
	Object string       `json:"object"`
	Data   []ModelEntry `json:"data"`
}
type ModelEntry struct {
	ID     string `json:"id"`
	Object string `json:"object"`
	OwnedBy string `json:"owned_by,omitempty"`
}
