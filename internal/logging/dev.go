//go:build dev
// +build dev

package logging

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger sets up console (colored) + file (JSON, UNIX timestamp) logging
func InitLogger(logFilePath string) (*os.File, error) {
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	// Color styles for console
	dim := color.New(color.FgHiBlack).SprintFunc()
	inf := color.New(color.FgGreen, color.Bold).SprintFunc()
	dbg := color.New(color.FgCyan, color.Bold).SprintFunc()
	wrn := color.New(color.FgYellow, color.Bold).SprintFunc()
	errC := color.New(color.FgRed, color.Bold).SprintFunc()
	fat := color.New(color.FgHiRed, color.Bold, color.BgBlack).SprintFunc()
	msgC := color.New(color.FgWhite, color.Bold).SprintFunc()
	keyC := color.New(color.FgCyan).SprintFunc()
	valC := color.New(color.FgWhite).SprintFunc()

	// Console writer (pretty colors)
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: "3:04PM",
	}

	consoleWriter.FormatTimestamp = func(i interface{}) string {
		return dim(fmt.Sprintf("%s", i))
	}
	consoleWriter.FormatLevel = func(i interface{}) string {
		lvl := strings.ToLower(fmt.Sprintf("%s", i))
		switch lvl {
		case "info":
			return inf("INF")
		case "debug":
			return dbg("DBG")
		case "warn":
			return wrn("WRN")
		case "error":
			return errC("ERR")
		case "fatal":
			return fat("FTL")
		default:
			return lvl
		}
	}
	consoleWriter.FormatMessage = func(i interface{}) string {
		return msgC(fmt.Sprintf("%s", i))
	}
	consoleWriter.FormatFieldName = func(i interface{}) string {
		return keyC(fmt.Sprintf("%s=", i))
	}
	consoleWriter.FormatFieldValue = func(i interface{}) string {
		return valC(fmt.Sprintf("%s", i))
	}

	// Multi-writer: console (colors) + file (JSON)
	zerolog.TimeFieldFormat = time.RFC3339 // console timestamp format
	multi := zerolog.MultiLevelWriter(consoleWriter, file)
	log.Logger = zerolog.New(multi).With().Timestamp().Logger()

	// Force UNIX time format in file output
	fileLogger := zerolog.New(file).With().Timestamp().Logger()
	fileLogger = fileLogger.With().Timestamp().Logger()
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	return file, nil
}
