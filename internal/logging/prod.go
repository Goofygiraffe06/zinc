//go:build !dev
// +build !dev

package logging

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func InitLogger(logFilePath string) (*os.File, error) {
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	// JSON logs only, no console output
	zerolog.TimeFieldFormat = time.RFC3339
	log.Logger = zerolog.New(file).With().Timestamp().Logger()

	return file, nil
}
