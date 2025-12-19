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

// Gemini CLI Adapter - Uses unofficial CLI endpoints
//
// This adapter uses the internal Gemini CLI API endpoints that Google uses
// for their gemini-cli tool. These endpoints are different from the public
// Generative Language API and only require standard Google OAuth scopes.
//
// Base URL: https://generativelanguage.googleapis.com
// Auth: Standard Google OAuth token

type GeminiCLIAdapter struct {
	log zerolog.Logger
	st  *store.Store
	rl  *ratelimit.Service
	cfg config.Config

	httpClient *http.Client
	// CLI API base URL (different from public API)
	apiBaseURL string
}

func NewGeminiCLIAdapter(log zerolog.Logger, st *store.Store, cfg config.Config) Provider {
	// Use the CLI endpoint (same as CLIProxyAPI-Extended)
	apiBase := getEnvOrDefault("GEMINI_CLI_API_BASE", "https://cloudcode-pa.googleapis.com/")

	return &GeminiCLIAdapter{
		log:        log,
		st:         st,
		rl:         ratelimit.New(st),
		cfg:        cfg,
		apiBaseURL: apiBase,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (g *GeminiCLIAdapter) Key() string { return "gemini_cli" }

func (g *GeminiCLIAdapter) ListModels(ctx context.Context, userID string) ([]openai.ModelEntry, error) {
	// Return fallback models since CLI endpoints don't have a models list
	return g.fallbackModels(), nil
}

func (g *GeminiCLIAdapter) ChatCompletions(ctx context.Context, userID string, req openai.ChatCompletionsRequest) (openai.ChatCompletionsResponse, error) {
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

	// Call Gemini CLI API
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

func (g *GeminiCLIAdapter) ChatCompletionsStream(ctx context.Context, userID string, req openai.ChatCompletionsRequest, emit func(any) error) error {
	token, credID, err := g.loadAccessToken(ctx, userID, req.Model)
	if err != nil {
		return err
	}

	if err := g.rl.Allow(ctx, credID); err != nil {
		return err
	}

	gemReq := g.buildGenerateContentRequest(req)

	// Use streaming endpoint with alt=sse
	url := fmt.Sprintf("%s/v1/models/%s:streamGenerateContent?alt=sse", g.apiBaseURL, req.Model)
	body, _ := json.Marshal(gemReq)

	httpReq, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-client", "")

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("stream request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 300 {
		b, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("gemini cli api error: %s body=%s", httpResp.Status, string(b))
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

func (g *GeminiCLIAdapter) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.cfg.GoogleClientID,
		ClientSecret: g.cfg.GoogleClientSecret,
		Endpoint:     google.Endpoint,
		// Standard Google scopes - no special Gemini scopes needed for CLI endpoints
		Scopes: []string{
			"openid",
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		RedirectURL: g.cfg.GoogleRedirectURL,
	}
}

func (g *GeminiCLIAdapter) loadAccessToken(ctx context.Context, userID, model string) (accessToken string, credentialID string, err error) {
	cred, err := g.st.Credentials().SelectCredentialForModel(ctx, userID, g.Key(), model)
	if err != nil {
		return "", "", fmt.Errorf("no credentials found: %w", err)
	}
	if cred.CredentialType != "oauth2" {
		return "", "", errors.New("gemini cli requires oauth2 credential; got: " + cred.CredentialType)
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

func (g *GeminiCLIAdapter) callGenerateContent(ctx context.Context, accessToken, model string, payload any) ([]byte, error) {
	// CLI endpoint format: /v1/models/{model}:generateContent (not /v1beta)
	url := fmt.Sprintf("%s/v1/models/%s:generateContent", g.apiBaseURL, model)
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	// Mimic the CLI user agent
	req.Header.Set("x-goog-api-client", "genai-go/0.18.0")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api request failed: %w", err)
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		g.log.Error().
			Str("url", url).
			Int("status", resp.StatusCode).
			Str("body", string(b)).
			Msg("gemini cli api error")
		return nil, fmt.Errorf("gemini cli api error: %s body=%s", resp.Status, string(b))
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
	Contents          []geminiContent `json:"contents"`
	SystemInstruction *geminiContent  `json:"systemInstruction,omitempty"`
}

func (g *GeminiCLIAdapter) buildGenerateContentRequest(req openai.ChatCompletionsRequest) geminiGenerateContentRequest {
	var contents []geminiContent

	// System instruction support (Gemini 1.5+)
	var systemInstruction string

	for _, m := range req.Messages {
		role := strings.ToLower(m.Role)

		// Extract system messages as system instruction
		if role == "system" {
			text := ""
			switch v := m.Content.(type) {
			case string:
				text = v
			default:
				j, _ := json.Marshal(v)
				text = string(j)
			}
			if systemInstruction == "" {
				systemInstruction = text
			} else {
				systemInstruction += "\n\n" + text
			}
			continue // Don't add system messages to contents
		}

		gRole := "user"
		switch role {
		case "assistant":
			gRole = "model"
		case "user":
			gRole = "user"
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

	// Build request with optional system instruction
	result := geminiGenerateContentRequest{
		Contents: contents,
	}

	if systemInstruction != "" {
		result.SystemInstruction = &geminiContent{
			Parts: []struct {
				Text string `json:"text,omitempty"`
			}{{Text: systemInstruction}},
		}
	}

	return result
}

func (g *GeminiCLIAdapter) extractTextFromResponse(raw []byte) (string, error) {
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

func (g *GeminiCLIAdapter) fallbackModels() []openai.ModelEntry {
	return []openai.ModelEntry{
		{ID: "gemini-2.0-flash-exp", Object: "model", OwnedBy: "google"},
		{ID: "gemini-exp-1206", Object: "model", OwnedBy: "google"},
		{ID: "gemini-2.0-flash-thinking-exp-1219", Object: "model", OwnedBy: "google"},
		{ID: "gemini-2.0-flash-thinking-exp", Object: "model", OwnedBy: "google"},
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
