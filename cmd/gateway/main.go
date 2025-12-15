package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/yourorg/llm-proxy-gateway/internal/api"
	"github.com/yourorg/llm-proxy-gateway/internal/config"
	"github.com/yourorg/llm-proxy-gateway/internal/db"
	"github.com/yourorg/llm-proxy-gateway/internal/logging"
)

func main() {

	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  No .env file found, relying on environment")
	}

	cfg := config.MustLoad()

	logger := logging.New(cfg.LogLevel)
	logger.Info().Str("addr", cfg.HTTPAddr).Msg("starting gateway")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool := db.MustConnect(ctx, cfg.DatabaseURL)
	defer pool.Close()

	if err := db.Migrate(ctx, pool); err != nil {
		logger.Fatal().Err(err).Msg("db migration failed")
	}

	app, err := api.NewServer(cfg, pool, logger)
	if err != nil {
		logger.Fatal().Err(err).Msg("server init failed")
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           app.Router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info().Msg("listening")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("http server error")
		}
	}()

	// graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Info().Msg("shutting down")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	_ = srv.Shutdown(shutdownCtx)
}
