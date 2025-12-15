package api

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/yourorg/llm-proxy-gateway/internal/middleware"
	"github.com/yourorg/llm-proxy-gateway/internal/openai"
	"github.com/yourorg/llm-proxy-gateway/internal/providers"
)

func ListModels(reg *providers.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := middleware.UserIDFrom(r.Context())
		models, err := reg.ListModels(r.Context(), uid)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(openai.ModelsResponse{
			Object: "list",
			Data:   models,
		})
	}
}

func ChatCompletions(reg *providers.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req openai.ChatCompletionsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		uid := middleware.UserIDFrom(r.Context())

		if req.Stream {
			// Minimal SSE streaming: provider returns chunks.
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			fl, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "streaming not supported", http.StatusBadRequest)
				return
			}
			err := reg.ChatCompletionsStream(r.Context(), uid, req, func(data any) error {
				b, _ := json.Marshal(data)
				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(b)
				_, _ = w.Write([]byte("\n\n"))
				fl.Flush()
				return nil
			})
			if err != nil {
				// best-effort stream error
				msg := "data: {\"error\":\"" + escape(err.Error()) + "\"}\n\n"
				_, _ = w.Write([]byte(msg))
				fl.Flush()
			}
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			fl.Flush()
			return
		}

		resp, err := reg.ChatCompletions(r.Context(), uid, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func Completions(reg *providers.Registry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// left as an exercise; for now we map to chat with a single user message
		http.Error(w, "not implemented: use /v1/chat/completions", http.StatusNotImplemented)
	}
}

func escape(s string) string {
	// minimal JSON string escape for streaming error messages
	out := ""
	for _, ch := range s {
		switch ch {
		case '\\':
			out += "\\\\"
		case '"':
			out += "\\\""
		case '\n':
			out += "\\n"
		case '\r':
			out += "\\r"
		case '\t':
			out += "\\t"
		default:
			out += string(ch)
		}
	}
	return out
}

var _ zerolog.Logger
