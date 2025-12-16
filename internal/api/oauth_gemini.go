package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/yourorg/llm-proxy-gateway/internal/config"
	"github.com/yourorg/llm-proxy-gateway/internal/store"
)

// OAuth2 config for Gemini Generative Language API
// Uses the same scopes as the Gemini CLI
func googleOAuthConfig(cfg config.Config) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.GoogleClientID,
		ClientSecret: cfg.GoogleClientSecret,
		RedirectURL:  cfg.GoogleRedirectURL,
		Scopes: []string{
			"openid",
			"email",
			"profile",
			// Gemini-specific scopes (required for CLI API access)
			"https://www.googleapis.com/auth/generative-language.tuning",
			"https://www.googleapis.com/auth/generative-language.retriever",
		},
		Endpoint: google.Endpoint,
	}
}

func OAuthStart(cfg config.Config, st *store.Store, logger zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cfg.GoogleClientID == "" || cfg.GoogleClientSecret == "" {
			http.Error(w, "GOOGLE_CLIENT_ID/SECRET not configured", http.StatusPreconditionFailed)
			return
		}
		gatewayKey := r.URL.Query().Get("gateway_key")
		userID, err := st.Users().ResolveUserIDFromGatewayKey(r.Context(), gatewayKey)
		if err != nil {
			http.Error(w, "invalid gateway_key", http.StatusUnauthorized)
			return
		}

		state, err := randomState(32)
		if err != nil {
			http.Error(w, "state error", http.StatusInternalServerError)
			return
		}

		// Persist state with short TTL
		if err := st.OAuthStates().Put(r.Context(), state, userID, time.Now().Add(10*time.Minute)); err != nil {
			logger.Error().Err(err).Msg("failed storing oauth state")
			http.Error(w, "state store error", http.StatusInternalServerError)
			return
		}

		url := googleOAuthConfig(cfg).AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.ApprovalForce)
		http.Redirect(w, r, url, http.StatusFound)
	}
}

func OAuthCallback(cfg config.Config, st *store.Store, logger zerolog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		state := r.URL.Query().Get("state")
		code := r.URL.Query().Get("code")
		if state == "" || code == "" {
			http.Error(w, "missing state/code", http.StatusBadRequest)
			return
		}

		userID, err := st.OAuthStates().Consume(ctx, state)
		if err != nil {
			http.Error(w, "invalid/expired state", http.StatusBadRequest)
			return
		}

		tok, err := googleOAuthConfig(cfg).Exchange(ctx, code)
		if err != nil {
			logger.Error().Err(err).Msg("oauth exchange failed")
			http.Error(w, "oauth exchange failed", http.StatusBadRequest)
			return
		}

		// Store credential under provider "gemini_cli"
		if err := st.Credentials().UpsertGeminiOAuth(ctx, userID, tok); err != nil {
			logger.Error().Err(err).Msg("failed saving token")
			http.Error(w, "failed saving token", http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(
			"✅ Login OK!\n\n" +
				"Je OAuth tokens zijn opgeslagen.\n" +
				"Je kunt nu /v1/chat/completions gebruiken met model prefix 'gemini-'\n\n" +
				"Je kunt dit tabblad sluiten.\n",
		))
	}
}

func randomState(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Helper functions for token serialization
func tokenToJSON(tok *oauth2.Token) ([]byte, error) {
	return json.Marshal(tok)
}

func tokenFromJSON(b []byte) (*oauth2.Token, error) {
	var tok oauth2.Token
	if err := json.Unmarshal(b, &tok); err != nil {
		return nil, err
	}
	tok.Expiry = tok.Expiry.UTC()
	return &tok, nil
}

// Exported for provider usage
func TokenFromJSON(b []byte) (*oauth2.Token, error) { return tokenFromJSON(b) }
func TokenToJSON(tok *oauth2.Token) ([]byte, error) { return tokenToJSON(tok) }
func BackgroundContext() context.Context            { return context.Background() }
