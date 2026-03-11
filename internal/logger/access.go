package logger

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/8w6s/noxis/config"
	"github.com/8w6s/noxis/internal/utils"
	"github.com/valyala/fasthttp"
)

// AccessLogEntry represents a single JSON log line
type AccessLogEntry struct {
	Timestamp  string `json:"timestamp"`
	ClientIP   string `json:"client_ip"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Status     int    `json:"status"`
	BytesSent  int    `json:"bytes_sent"`
	DurationMs int64  `json:"duration_ms"`
	Action     string `json:"action"`
}

// AccessLogger is a middleware that logs HTTP requests to a file in JSON format.
type AccessLogger struct {
	file    *os.File
	handler fasthttp.RequestHandler
}

// NewAccessLogger creates a wrapper that logs requests to the specified path.
func NewAccessLogger(path string, next fasthttp.RequestHandler, cfg *config.AppConfig) *AccessLogger {
	if path == "" {
		return &AccessLogger{handler: next}
	}

	// Ensure directory exists
	if dir := filepath.Dir(path); dir != "" {
		os.MkdirAll(dir, 0755)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[Logger] Failed to open access log file %s: %v. Access logging disabled.", path, err)
		return &AccessLogger{handler: next}
	}

	logger := &AccessLogger{
		file:    f,
		handler: next,
	}

	return logger
}

// ServeHTTP implements fasthttp.RequestHandler
func (l *AccessLogger) ServeHTTP(ctx *fasthttp.RequestCtx) {
	start := time.Now()

	// Execute next handler (the pipeline)
	l.handler(ctx)

	duration := time.Since(start).Milliseconds()
	status := ctx.Response.StatusCode()
	
	action := "passed"
	switch status {
	case fasthttp.StatusForbidden, fasthttp.StatusTooManyRequests:
		action = "blocked"
	case fasthttp.StatusServiceUnavailable:
		action = "challenged"
	}

	entry := AccessLogEntry{
		Timestamp:  time.Now().Format(time.RFC3339),
		ClientIP:   utils.GetClientIP(ctx),
		Method:     string(ctx.Method()),
		Path:       string(ctx.Path()),
		Status:     status,
		BytesSent:  len(ctx.Response.Body()),
		DurationMs: duration,
		Action:     action,
	}

	b, err := json.Marshal(entry)
	if err == nil {
		// Log line is appended with newline
		fmt.Fprintln(l.file, string(b))
	}
}

// Close gracefully closes the underlying access log file
func (l *AccessLogger) Close() error {
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}
