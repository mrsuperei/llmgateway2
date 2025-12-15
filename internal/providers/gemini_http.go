package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/yourorg/llm-proxy-gateway/internal/auth"
	"github.com/yourorg/llm-proxy-gateway/internal/config"
	"github.com/yourorg/llm-proxy-gateway/internal/openai"
	"github.com/yourorg/llm-proxy-gateway/internal/ratelimit"
	"github.com/yourorg/llm-proxy-gateway/internal/store"
)

// Gemini HTTP adapter
//
// This adapter uses OAuth tokens stored in Postgres and calls the Gemini
// Generative Language API over HTTP (no subprocess/CLI).
//
// Provider key is kept as "gemini_cli" to remain compatible with the starter DB schema
// and OAuth UI flow, but the implementation is pure HTTP.

type GeminiHTTPAdapter struct {
	log zerolog.Logger
	st  *store.Store
	rl  *ratelimit.Service
	cfg config.Config

	httpClient *http.Client
}

func NewGeminiHTTPAdapter(log zerolog.Logger, st *store.Store, cfg config.Config) Provider {
	return &GeminiHTTPAdapter{
		log:        log,
		st:         st,
		rl:         ratelimit.New(st),
		cfg:        cfg,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (g *GeminiHTTPAdapter) Key() string { return "gemini_cli" }

func (g *GeminiHTTPAdapter) ListModels(ctx context.Context, userID string) ([]openai.ModelEntry, error) {
	// Best effort: call the models list endpoint; fall back to a small curated list.
	token, _, err := g.loadAccessToken(ctx, userID, "gemini-2.5-pro")
	if err != nil {
		return []openai.ModelEntry{
			{ID: "gemini-2.5-pro", Object: "model", OwnedBy: "google"},
			{ID: "gemini-2.5-flash", Object: "model", OwnedBy: "google"},
		}, nil
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://generativelanguage.googleapis.com/v1beta/models", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return []openai.ModelEntry{{ID: "gemini-2.5-pro", Object: "model", OwnedBy: "google"}}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return []openai.ModelEntry{{ID: "gemini-2.5-pro", Object: "model", OwnedBy: "google"}}, nil
	}
	var payload struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return []openai.ModelEntry{{ID: "gemini-2.5-pro", Object: "model", OwnedBy: "google"}}, nil
	}

	out := make([]openai.ModelEntry, 0, len(payload.Models))
	for _, m := range payload.Models {
		id := strings.TrimPrefix(m.Name, "models/")
		if id == "" {
			continue
		}
		out = append(out, openai.ModelEntry{ID: id, Object: "model", OwnedBy: "google"})
	}
	if len(out) == 0 {
		out = []openai.ModelEntry{{ID: "gemini-2.5-pro", Object: "model", OwnedBy: "google"}}
	}
	return out, nil
}

func (g *GeminiHTTPAdapter) ChatCompletions(ctx context.Context, userID string, req openai.ChatCompletionsRequest) (openai.ChatCompletionsResponse, error) {
	token, credID, err := g.loadAccessToken(ctx, userID, req.Model)
	if err != nil {
		return openai.ChatCompletionsResponse{}, err
	}

	// rate limit per credential
	if err := g.rl.Allow(ctx, credID); err != nil {
		return openai.ChatCompletionsResponse{}, err
	}

	gemReq := openAIToGemini(req)
	raw, err := g.callGenerateContent(ctx, token, req.Model, gemReq)
	if err != nil {
		return openai.ChatCompletionsResponse{}, err
	}
	assistant, err := geminiExtractText(raw)
	if err != nil {
		return openai.ChatCompletionsResponse{}, err
	}

	now := time.Now().Unix()
	resp := openai.ChatCompletionsResponse{
		ID:      "chatcmpl_gemini_" + randID(),
		Object:  "chat.completion",
		Created: now,
		Model:   req.Model,
	}
	resp.Choices = []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason,omitempty"`
	}{{
		Index: 0,
		Message: struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{Role: "assistant", Content: assistant},
		FinishReason: "stop",
	}}
	return resp, nil
}

func (g *GeminiHTTPAdapter) ChatCompletionsStream(ctx context.Context, userID string, req openai.ChatCompletionsRequest, emit func(any) error) error {
	token, credID, err := g.loadAccessToken(ctx, userID, req.Model)
	if err != nil {
		return err
	}
	if err := g.rl.Allow(ctx, credID); err != nil {
		return err
	}

	gemReq := openAIToGemini(req)

	// Use Gemini streaming endpoint and translate each chunk to OpenAI SSE chunks.
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:streamGenerateContent", req.Model)
	body, _ := json.Marshal(gemReq)
	httpReq, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("gemini http error: %s body=%s", httpResp.Status, string(b))
	}

	created := time.Now().Unix()
	id := "chatcmpl_gemini_" + randID()
	// Gemini stream is typically JSON per line/event. We parse line-by-line and emit deltas.
	// We keep a best-effort implementation to match the starter's streaming contract.
	scanner := bufio.NewScanner(httpResp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		ln := strings.TrimSpace(scanner.Text())
		if ln == "" {
			continue
		}
		// Some deployments prefix with "data:" when using SSE.
		ln = strings.TrimPrefix(ln, "data:")
		ln = strings.TrimSpace(ln)
		if ln == "[DONE]" {
			break
		}

		// Each event can be a partial GenerateContentResponse-like structure.
		txt, _ := geminiExtractText([]byte(ln))
		if txt == "" {
			continue
		}
		if err := emit(map[string]any{
			"id":      id,
			"object":  "chat.completion.chunk",
			"created": created,
			"model":   req.Model,
			"choices": []any{map[string]any{
				"index": 0,
				"delta": map[string]any{"content": txt},
			}},
		}); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emit(map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   req.Model,
		"choices": []any{map[string]any{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": "stop",
		}},
	})
}

// --- HTTP + OAuth helpers ---

func (g *GeminiHTTPAdapter) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.cfg.GoogleClientID,
		ClientSecret: g.cfg.GoogleClientSecret,
		Endpoint:     google.Endpoint,
		// scopes are not strictly required for refresh, but kept aligned with the login flow.
		Scopes: []string{
			"openid",
			"email",
			"profile",
			"https://www.googleapis.com/auth/generative-language",
		},
		RedirectURL: g.cfg.GoogleRedirectURL,
	}
}

// loadAccessToken selects a credential and returns a valid access token.
// If the stored token is expired and refreshable, it will be refreshed and persisted.
func (g *GeminiHTTPAdapter) loadAccessToken(ctx context.Context, userID, model string) (accessToken string, credentialID string, err error) {
	cred, err := g.st.Credentials().SelectCredentialForModel(ctx, userID, g.Key(), model)
	if err != nil {
		return "", "", err
	}
	if cred.CredentialType != "oauth2" {
		return "", "", errors.New("gemini requires oauth2 credential; got: " + cred.CredentialType)
	}
	tok, err := auth.TokenFromJSON([]byte(cred.OAuthTokenJSON))
	if err != nil {
		return "", "", errors.New("invalid stored oauth token json")
	}

	// Refresh if needed and persist.
	ts := g.oauthConfig().TokenSource(ctx, tok)
	newTok, err := ts.Token()
	if err != nil {
		return "", "", err
	}
	// Persist only if changed.
	if newTok.AccessToken != tok.AccessToken || !newTok.Expiry.Equal(tok.Expiry) {
		_ = g.st.Credentials().UpdateOAuthToken(ctx, cred.ID, newTok)
	}
	return newTok.AccessToken, cred.ID, nil
}

func (g *GeminiHTTPAdapter) callGenerateContent(ctx context.Context, accessToken, model string, payload any) ([]byte, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", model)
	body, _ := json.Marshal(payload)

	r, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+accessToken)
	r.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gemini http error: %s body=%s", resp.Status, string(b))
	}
	return b, nil
}

// --- request/response mapping ---

type geminiGenerateContentRequest struct {
	Contents []struct {
		Role  string `json:"role,omitempty"`
		Parts []struct {
			Text string `json:"text,omitempty"`
		} `json:"parts"`
	} `json:"contents"`
}

func openAIToGemini(req openai.ChatCompletionsRequest) geminiGenerateContentRequest {
	// Gemini expects a list of "contents". We'll map OpenAI messages:
	// system -> user (prefixed)
	// user -> user
	// assistant -> model
	var contents []struct {
		Role  string `json:"role,omitempty"`
		Parts []struct {
			Text string `json:"text,omitempty"`
		} `json:"parts"`
	}

	for _, m := range req.Messages {
		role := strings.ToLower(m.Role)
		gRole := "user"
		switch role {
		case "assistant":
			gRole = "model"
		case "system":
			gRole = "user"
		default:
			gRole = "user"
		}

		text := ""
		switch v := m.Content.(type) {
		case string:
			text = v
		default:
			// best effort
			j, _ := json.Marshal(v)
			text = string(j)
		}
		if role == "system" {
			text = "[system] " + text
		}
		if strings.TrimSpace(text) == "" {
			continue
		}

		contents = append(contents, struct {
			Role  string `json:"role,omitempty"`
			Parts []struct {
				Text string `json:"text,omitempty"`
			} `json:"parts"`
		}{
			Role: gRole,
			Parts: []struct {
				Text string `json:"text,omitempty"`
			}{{Text: text}},
		})
	}

	return geminiGenerateContentRequest{Contents: contents}
}

func geminiExtractText(raw []byte) (string, error) {
	// Gemini response shape (v1beta):
	// {"candidates":[{"content":{"parts":[{"text":"..."}]}}]}
	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Candidates) == 0 || len(parsed.Candidates[0].Content.Parts) == 0 {
		return "", nil
	}
	return strings.TrimSpace(parsed.Candidates[0].Content.Parts[0].Text), nil
}

func randID() string {
	return strings.ReplaceAll(time.Now().Format("20060102150405.000000000"), ".", "")
}
