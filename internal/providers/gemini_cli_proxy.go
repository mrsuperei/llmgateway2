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
	"os"
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

// Gemini Direct OAuth Adapter
//
// This adapter calls the Google Generative Language API directly using OAuth tokens
// (the same way the Gemini CLI does internally), without needing to run the CLI.
//
// API endpoint: https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent
// Auth: OAuth 2.0 bearer token in Authorization header

type GeminiDirectAdapter struct {
	log zerolog.Logger
	st  *store.Store
	rl  *ratelimit.Service
	cfg config.Config

	httpClient *http.Client
	// Base URL for Gemini API (generativelanguage.googleapis.com)
	apiBaseURL string
}

func NewGeminiDirectAdapter(log zerolog.Logger, st *store.Store, cfg config.Config) Provider {
	// Use the official Generative Language API endpoint
	apiBase := getEnvOrDefault("GEMINI_API_BASE_URL", "https://cloudcode-pa.googleapis.com")

	return &GeminiDirectAdapter{
		log:        log,
		st:         st,
		rl:         ratelimit.New(st),
		cfg:        cfg,
		apiBaseURL: apiBase,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (g *GeminiDirectAdapter) Key() string { return "gemini_cli" }

func (g *GeminiDirectAdapter) ListModels(ctx context.Context, userID string) ([]openai.ModelEntry, error) {
	token, _, err := g.loadAccessToken(ctx, userID, "gemini-2.5-pro")
	if err != nil {
		return []openai.ModelEntry{
			{ID: "gemini-2.5-pro", Object: "model", OwnedBy: "google"},
			{ID: "gemini-2.5-flash", Object: "model", OwnedBy: "google"},
			{ID: "gemini-2.0-flash", Object: "model", OwnedBy: "google"},
		}, nil
	}

	// List models via API
	url := fmt.Sprintf("%s/v1beta/models", g.apiBaseURL)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		g.log.Warn().Err(err).Msg("failed to list models")
		return g.fallbackModels(), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		g.log.Warn().Int("status", resp.StatusCode).Msg("list models returned error")
		return g.fallbackModels(), nil
	}

	var payload struct {
		Models []struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName,omitempty"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return g.fallbackModels(), nil
	}

	out := make([]openai.ModelEntry, 0, len(payload.Models))
	for _, m := range payload.Models {
		// Model name format: "models/gemini-2.5-pro"
		id := strings.TrimPrefix(m.Name, "models/")
		if id == "" || !strings.HasPrefix(id, "gemini-") {
			continue
		}
		out = append(out, openai.ModelEntry{
			ID:      id,
			Object:  "model",
			OwnedBy: "google",
		})
	}

	if len(out) == 0 {
		return g.fallbackModels(), nil
	}
	return out, nil
}

func (g *GeminiDirectAdapter) ChatCompletions(ctx context.Context, userID string, req openai.ChatCompletionsRequest) (openai.ChatCompletionsResponse, error) {
	token, credID, err := g.loadAccessToken(ctx, userID, req.Model)
	if err != nil {
		return openai.ChatCompletionsResponse{}, err
	}

	// Rate limit check
	if err := g.rl.Allow(ctx, credID); err != nil {
		return openai.ChatCompletionsResponse{}, err
	}

	// Convert OpenAI format to Gemini format
	gemReq := g.buildGenerateContentRequest(req)

	// Call Gemini API
	raw, err := g.callGenerateContent(ctx, token, req.Model, gemReq)
	if err != nil {
		return openai.ChatCompletionsResponse{}, err
	}

	// Extract response
	assistant, err := g.extractTextFromResponse(raw)
	if err != nil {
		return openai.ChatCompletionsResponse{}, err
	}

	// Build OpenAI-compatible response
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

func (g *GeminiDirectAdapter) ChatCompletionsStream(ctx context.Context, userID string, req openai.ChatCompletionsRequest, emit func(any) error) error {
	token, credID, err := g.loadAccessToken(ctx, userID, req.Model)
	if err != nil {
		return err
	}

	if err := g.rl.Allow(ctx, credID); err != nil {
		return err
	}

	gemReq := g.buildGenerateContentRequest(req)

	// Use streaming endpoint
	url := fmt.Sprintf("%s/v1beta/models/%s:streamGenerateContent?alt=sse", g.apiBaseURL, req.Model)
	body, _ := json.Marshal(gemReq)

	httpReq, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("stream request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("gemini api error: %s body=%s", httpResp.Status, string(b))
	}

	created := time.Now().Unix()
	id := "chatcmpl_gemini_" + randID()

	// Parse SSE stream
	scanner := bufio.NewScanner(httpResp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		ln := strings.TrimSpace(scanner.Text())
		if ln == "" {
			continue
		}

		// SSE format: "data: {...}"
		if !strings.HasPrefix(ln, "data:") {
			continue
		}
		ln = strings.TrimPrefix(ln, "data:")
		ln = strings.TrimSpace(ln)

		if ln == "[DONE]" {
			break
		}

		// Extract text from chunk
		txt, _ := g.extractTextFromResponse([]byte(ln))
		if txt == "" {
			continue
		}

		// Emit OpenAI-format chunk
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

	// Send final chunk
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

// --- OAuth and Token Management ---

func (g *GeminiDirectAdapter) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.cfg.GoogleClientID,
		ClientSecret: g.cfg.GoogleClientSecret,
		Endpoint:     google.Endpoint,
		Scopes: []string{
			"openid",
			"email",
			"profile",
			"https://www.googleapis.com/auth/generative-language.tuning",
			"https://www.googleapis.com/auth/generative-language.retriever",
		},
		RedirectURL: g.cfg.GoogleRedirectURL,
	}
}

func (g *GeminiDirectAdapter) loadAccessToken(ctx context.Context, userID, model string) (accessToken string, credentialID string, err error) {
	cred, err := g.st.Credentials().SelectCredentialForModel(ctx, userID, g.Key(), model)
	if err != nil {
		return "", "", fmt.Errorf("no credentials found: %w", err)
	}
	if cred.CredentialType != "oauth2" {
		return "", "", errors.New("gemini requires oauth2 credential; got: " + cred.CredentialType)
	}

	tok, err := auth.TokenFromJSON([]byte(cred.OAuthTokenJSON))
	if err != nil {
		return "", "", errors.New("invalid stored oauth token json")
	}

	// Auto-refresh if needed
	ts := g.oauthConfig().TokenSource(ctx, tok)
	newTok, err := ts.Token()
	if err != nil {
		return "", "", fmt.Errorf("token refresh failed: %w", err)
	}

	// Persist if changed
	if newTok.AccessToken != tok.AccessToken || !newTok.Expiry.Equal(tok.Expiry) {
		if err := g.st.Credentials().UpdateOAuthToken(ctx, cred.ID, newTok); err != nil {
			g.log.Warn().Err(err).Msg("failed to update token")
		}
	}

	return newTok.AccessToken, cred.ID, nil
}

// --- API Calls ---

func (g *GeminiDirectAdapter) callGenerateContent(ctx context.Context, accessToken, model string, payload any) ([]byte, error) {
	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent", g.apiBaseURL, model)
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gemini api error: %s body=%s", resp.Status, string(b))
	}
	return b, nil
}

// --- Request/Response Mapping ---

type geminiContent struct {
	Role  string `json:"role,omitempty"`
	Parts []struct {
		Text string `json:"text,omitempty"`
	} `json:"parts"`
}

type geminiGenerateContentRequest struct {
	Contents []geminiContent `json:"contents"`
}

func (g *GeminiDirectAdapter) buildGenerateContentRequest(req openai.ChatCompletionsRequest) geminiGenerateContentRequest {
	var contents []geminiContent

	for _, m := range req.Messages {
		role := strings.ToLower(m.Role)
		gRole := "user"
		switch role {
		case "assistant":
			gRole = "model"
		case "system":
			gRole = "user" // System messages treated as user messages
		default:
			gRole = "user"
		}

		text := ""
		switch v := m.Content.(type) {
		case string:
			text = v
		default:
			j, _ := json.Marshal(v)
			text = string(j)
		}

		if role == "system" {
			text = "[system] " + text
		}
		if strings.TrimSpace(text) == "" {
			continue
		}

		contents = append(contents, geminiContent{
			Role: gRole,
			Parts: []struct {
				Text string `json:"text,omitempty"`
			}{{Text: text}},
		})
	}

	return geminiGenerateContentRequest{Contents: contents}
}

func (g *GeminiDirectAdapter) extractTextFromResponse(raw []byte) (string, error) {
	// Gemini response format:
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

// --- Helpers ---

func (g *GeminiDirectAdapter) fallbackModels() []openai.ModelEntry {
	return []openai.ModelEntry{
		{ID: "gemini-2.5-pro", Object: "model", OwnedBy: "google"},
		{ID: "gemini-2.5-flash", Object: "model", OwnedBy: "google"},
		{ID: "gemini-2.0-flash", Object: "model", OwnedBy: "google"},
	}
}

func randID() string {
	return strings.ReplaceAll(time.Now().Format("20060102150405.000000000"), ".", "")
}

func getEnvOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
