//go:build dev
// +build dev

package logging

import (
	"os"
	"time"

	"github.com/fatih/color"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// coloredLevelEncoder adds color to log levels in development mode
func coloredLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	var levelStr string
	switch level {
	case zapcore.DebugLevel:
		levelStr = color.New(color.FgCyan, color.Bold).Sprint("DBG")
	case zapcore.InfoLevel:
		levelStr = color.New(color.FgGreen, color.Bold).Sprint("INF")
	case zapcore.WarnLevel:
		levelStr = color.New(color.FgMagenta, color.Bold).Sprint("WRN")
	case zapcore.ErrorLevel:
		levelStr = color.New(color.FgRed, color.Bold).Sprint("ERR")
	case zapcore.DPanicLevel, zapcore.PanicLevel:
		levelStr = color.New(color.FgHiRed, color.Bold).Sprint("PNC")
	case zapcore.FatalLevel:
		levelStr = color.New(color.FgHiRed, color.Bold, color.BgBlack).Sprint("FTL")
	default:
		levelStr = level.CapitalString()
	}
	enc.AppendString(levelStr)
}

// coloredTimeEncoder adds dim color to timestamps
func coloredTimeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	dim := color.New(color.FgHiBlack).SprintFunc()
	enc.AppendString(dim(t.Format("15:04:05")))
}

// InitLogger initializes a development logger with colorized console output and JSON file logging
func InitLogger(logFilePath string) (*os.File, error) {
	file, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	// Console encoder config with colors
	consoleEncoderConfig := zapcore.EncoderConfig{
		TimeKey:        "T",
		LevelKey:       "L",
		NameKey:        "N",
		CallerKey:      zapcore.OmitKey,
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "M",
		StacktraceKey:  "S",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    coloredLevelEncoder,
		EncodeTime:     coloredTimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// File encoder config (JSON)
	fileEncoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create console encoder (with colors)
	consoleEncoder := zapcore.NewConsoleEncoder(consoleEncoderConfig)

	// Create file encoder (JSON)
	fileEncoder := zapcore.NewJSONEncoder(fileEncoderConfig)

	// Create a multi-core that writes to both console and file
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, zapcore.AddSync(os.Stdout), zapcore.DebugLevel),
		zapcore.NewCore(fileEncoder, zapcore.AddSync(file), zapcore.DebugLevel),
	)

	// Create logger without caller info
	l := zap.New(core, zap.AddStacktrace(zapcore.ErrorLevel))

	// Set the global logger
	SetLogger(l)

	return file, nil
}
