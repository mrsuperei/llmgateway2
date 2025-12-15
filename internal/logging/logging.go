package logging

import (
	"os"
	"strings"

	"github.com/rs/zerolog"
)

func New(level string) zerolog.Logger {
	lvl, err := zerolog.ParseLevel(strings.ToLower(level))
	if err != nil {
		lvl = zerolog.InfoLevel
	}
	zerolog.TimeFieldFormat = "2006-01-02T15:04:05.000Z07:00"
	logger := zerolog.New(os.Stdout).With().Timestamp().Logger().Level(lvl)
	return logger
}
