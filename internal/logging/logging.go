package logging

import (
	"go.uber.org/zap"
)

var logger *zap.Logger

// GetLogger returns the global logger instance
func GetLogger() *zap.Logger {
	if logger == nil {
		// Fallback to a development logger if not initialized
		logger, _ = zap.NewDevelopment()
	}
	return logger
}

// SetLogger sets the global logger instance
func SetLogger(l *zap.Logger) {
	logger = l
}

// DebugLog logs a debug message with printf-style formatting
func DebugLog(msg string, args ...interface{}) {
	GetLogger().Sugar().Debugf(msg, args...)
}

// InfoLog logs an info message with printf-style formatting
func InfoLog(msg string, args ...interface{}) {
	GetLogger().Sugar().Infof(msg, args...)
}

// WarnLog logs a warning message with printf-style formatting
func WarnLog(msg string, args ...interface{}) {
	GetLogger().Sugar().Warnf(msg, args...)
}

// ErrorLog logs an error message with printf-style formatting
func ErrorLog(msg string, args ...interface{}) {
	GetLogger().Sugar().Errorf(msg, args...)
}

// FatalLog logs a fatal message with printf-style formatting and exits
func FatalLog(msg string, args ...interface{}) {
	GetLogger().Sugar().Fatalf(msg, args...)
}

// Debug logs a structured debug message
func Debug(msg string, fields ...zap.Field) {
	GetLogger().Debug(msg, fields...)
}

// Info logs a structured info message
func Info(msg string, fields ...zap.Field) {
	GetLogger().Info(msg, fields...)
}

// Warn logs a structured warning message
func Warn(msg string, fields ...zap.Field) {
	GetLogger().Warn(msg, fields...)
}

// Error logs a structured error message
func Error(msg string, fields ...zap.Field) {
	GetLogger().Error(msg, fields...)
}

// Fatal logs a structured fatal message and exits
func Fatal(msg string, fields ...zap.Field) {
	GetLogger().Fatal(msg, fields...)
}
