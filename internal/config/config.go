package config

import (
	"fmt"
	"log"
	"os"
)

type Config struct {
	HTTPAddr    string
	DatabaseURL string
	LogLevel    string

	// Gateway auth: clients call this gateway with "Authorization: Bearer <gateway_api_key>".
	// Keys are stored hashed in Postgres (see migrations).
	// Admin bootstrap can be done via the seed script in /scripts.

	// Google OAuth (Gemini CLI proxy UI)
	GoogleClientID     string
	GoogleClientSecret string
	GoogleRedirectURL  string // e.g. http://localhost:8080/oauth2/callback
}

func MustLoad() Config {
	fmt.Println("DEBUG ENV GOOGLE_CLIENT_ID =", os.Getenv("GOOGLE_CLIENT_ID"))
	fmt.Println("DEBUG ENV GOOGLE_CLIENT_SECRET =", os.Getenv("GOOGLE_CLIENT_SECRET"))

	cfg := Config{
		HTTPAddr:    getenv("HTTP_ADDR", ":8080"),
		DatabaseURL: getenv("DATABASE_URL", "postgresql://helixrun:test@localhost:5432/helixrun"),
		LogLevel:    getenv("LOG_LEVEL", "info"),

		GoogleClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirectURL:  getenv("GOOGLE_REDIRECT_URL", "http://localhost:8080/oauth2/callback"),
	}
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	return cfg
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}
