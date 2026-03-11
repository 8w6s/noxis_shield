package logger

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
)

func TestAccessLogger(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "access_test.log")

	// Dummy handler that simulates a request passing through
	dummyHandler := func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString("Hello, World!")
	}

	loggerMiddleware := NewAccessLogger(logPath, dummyHandler, nil)

	ctx := &fasthttp.RequestCtx{}
	// Init first before setting values
	ctx.Init(&ctx.Request, nil, nil)
	
	ctx.Request.Header.SetMethod("GET")
	ctx.Request.SetRequestURI("/api/test")
	ctx.Request.Header.SetUserAgent("NoxisTest/1.0")

	// Process request
	loggerMiddleware.ServeHTTP(ctx)
	
	// Wait briefly for file flush just in case
	time.Sleep(10 * time.Millisecond)
	
	// Close file to allow Windows to clean up TempDir
	loggerMiddleware.Close()

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("Failed to open log file: %v", err)
	}
	defer f.Close()

	content, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 1 {
		t.Fatalf("Expected 1 log line, got %d", len(lines))
	}

	var entry AccessLogEntry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("Failed to parse JSON formatted log: %v\nRaw line: %s", err, lines[0])
	}

	if entry.Method != "GET" {
		t.Errorf("Expected method GET, got %s", entry.Method)
	}
	if entry.Path != "/api/test" {
		t.Errorf("Expected path /api/test, got %s", entry.Path)
	}
	if entry.Status != fasthttp.StatusOK {
		t.Errorf("Expected status 200, got %d", entry.Status)
	}
	if entry.Action != "passed" {
		t.Errorf("Expected action passed, got %s", entry.Action)
	}
}
