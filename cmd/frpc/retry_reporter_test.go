package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func captureRetry(t *testing.T, level slog.Level, err error, wait time.Duration) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	retryReporter(context.Background())(err, wait)

	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		records = append(records, record)
	}
	return records
}

// A Connector that cannot be admitted used to retry forever with no log line,
// no admin API and no exit, which from the outside is indistinguishable from a
// hang. Reporting the attempt is what tells those two apart.
func TestRetryReporterAnnouncesTheRetryAtDefaultLevel(t *testing.T) {
	records := captureRetry(t, slog.LevelInfo, errors.New("knock refused"), 4*time.Second)
	if len(records) != 1 {
		t.Fatalf("got %d records at info level, want exactly 1", len(records))
	}
	if got := records[0]["retry_in"]; got != "4s" {
		t.Fatalf("retry_in = %v, want 4s", got)
	}
}

// OnRetry's contract warns the error "is not guaranteed to be safe for
// persistent logs", so the text must not appear at the default level.
func TestRetryReporterWithholdsTheErrorTextUntilDebug(t *testing.T) {
	const secret = "knock refused for tenant-secret-detail"
	info := captureRetry(t, slog.LevelInfo, errors.New(secret), time.Second)
	for _, record := range info {
		if _, present := record["err"]; present {
			t.Fatalf("default level leaked the error text: %v", record)
		}
	}

	debug := captureRetry(t, slog.LevelDebug, errors.New(secret), time.Second)
	var sawErr bool
	for _, record := range debug {
		if text, present := record["err"]; present {
			sawErr = true
			if text != secret {
				t.Fatalf("debug err = %v, want the original message", text)
			}
		}
	}
	if !sawErr {
		t.Fatal("debug level did not include the error text an operator asked for")
	}
}

// The runner calls OnRetry only with a non-nil error today, but a callback that
// logs a retry with no cause would be actively misleading.
func TestRetryReporterIgnoresANilError(t *testing.T) {
	if records := captureRetry(t, slog.LevelDebug, nil, time.Second); len(records) != 0 {
		t.Fatalf("got %d records for a nil error, want none", len(records))
	}
}
