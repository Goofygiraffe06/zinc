package logging

import "github.com/rs/zerolog/log"

func DebugLog(msg string, args ...interface{}) {
	log.Debug().Msgf(msg, args...)
}

func InfoLog(msg string, args ...interface{}) {
	log.Info().Msgf(msg, args...)
}

func ErrorLog(msg string, args ...interface{}) {
	log.Error().Msgf(msg, args...)
}

func FatalLog(msg string, args ...interface{}) {
	log.Fatal().Msgf(msg, args...)
}
