package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// ServerReadTimeout returns the maximum duration for reading the entire request, including the body.
func ServerReadTimeout() time.Duration {
	return MustParseDuration("SERVER_READ_TIMEOUT", "10s")
}

// ServerReadHeaderTimeout returns the amount of time allowed to read request headers.
func ServerReadHeaderTimeout() time.Duration {
	return MustParseDuration("SERVER_READ_HEADER_TIMEOUT", "5s")
}

// ServerWriteTimeout returns the maximum duration before timing out writes of the response.
func ServerWriteTimeout() time.Duration {
	return MustParseDuration("SERVER_WRITE_TIMEOUT", "15s")
}

// ServerIdleTimeout returns the maximum amount of time to wait for the next request when keep-alives are enabled.
func ServerIdleTimeout() time.Duration {
	return MustParseDuration("SERVER_IDLE_TIMEOUT", "60s")
}

// MaxRequestBodyBytes returns the maximum allowed size of incoming request bodies.
// Supports raw integers (bytes) or human-friendly values like "2MB", "512KB".
func MaxRequestBodyBytes() int64 {
	val := GetEnv("MAX_REQUEST_BODY_BYTES", "1MB")
	n, err := parseBytes(val)
	if err != nil || n <= 0 {
		return 1 << 20 // 1MB default
	}
	return n
}

// DBWorkerCount controls the number of DB workers.
func DBWorkerCount() int {
	return parseIntEnv("DB_WORKER_COUNT", 4)
}

// CryptoWorkerCount controls the number of crypto workers.
func CryptoWorkerCount() int {
	return parseIntEnv("CRYPTO_WORKER_COUNT", 4)
}

// SMTPWorkerCount controls the number of SMTP workers.
func SMTPWorkerCount() int {
	return parseIntEnv("SMTP_WORKER_COUNT", 2)
}

// WorkerQueueSize controls the queue size for each worker pool.
func WorkerQueueSize() int {
	return parseIntEnv("WORKER_QUEUE_SIZE", 1024)
}

func parseIntEnv(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil || i <= 0 {
		return def
	}
	return i
}

func parseBytes(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	// If plain number, treat as bytes
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	mult := int64(1)
	switch {
	case strings.HasSuffix(s, "KB"):
		mult = 1 << 10
		s = strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		mult = 1 << 20
		s = strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "GB"):
		mult = 1 << 30
		s = strings.TrimSuffix(s, "GB")
	default:
		// bytes by default
		mult = 1
	}
	base := strings.TrimSpace(s)
	n, err := strconv.ParseFloat(base, 64)
	if err != nil {
		return 0, err
	}
	return int64(n * float64(mult)), nil
}
