package share

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
)

type rotatingAdmitter struct {
	mu       sync.Mutex
	next     uint64
	retired  []uint64
	openTime time.Duration
}

type retryReport struct {
	err  error
	wait time.Duration
}

func (a *rotatingAdmitter) Admit(_ context.Context, knockResourceID, resourceID string) (Admission, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.next++
	return Admission{
		KnockResourceID: knockResourceID,
		ResourceID:      resourceID,
		RunID:           "run",
		RunAttempt:      1,
		Token:           "token",
		ResourceHost:    "127.0.0.1:7000",
		SessionID:       a.next,
		SessionReceipt:  testSessionReceipt(a.next, "run", 1),
		OpenTime:        a.openTime,
	}, nil
}

func (a *rotatingAdmitter) Retire(_ context.Context, admission Admission) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.retired = append(a.retired, admission.SessionID)
	return nil
}

func testSessionReceipt(sessionID uint64, runID string, runAttempt uint64) qurl.NativeSessionReceipt {
	return qurl.NativeSessionReceipt{
		CellID: "cell0", SessionID: sessionID, SessionIssuedAtMillis: 1,
		RunID: runID, RunAttempt: runAttempt,
	}
}

func TestAdmissionFormattingRedactsBearerToken(t *testing.T) {
	admission := Admission{
		KnockResourceID: "q_catalog", ResourceID: "resource-public", RunID: "run-one", RunAttempt: 3,
		Token: "bearer-must-never-appear", ResourceHost: "frp.example:7000", SessionID: 42,
		SessionReceipt: qurl.NativeSessionReceipt{
			CellID: "cell0", SessionID: 42, SessionIssuedAtMillis: 1234, RunID: "run-one", RunAttempt: 3,
		},
		OpenTime: time.Minute,
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		formatted := fmt.Sprintf(format, admission)
		if strings.Contains(formatted, admission.Token) || !strings.Contains(formatted, "Token:[REDACTED]") {
			t.Fatalf("format %q leaked or omitted redaction: %s", format, formatted)
		}
		for _, useful := range []string{admission.ResourceID, admission.RunID, admission.ResourceHost, "cell0"} {
			if !strings.Contains(formatted, useful) {
				t.Fatalf("format %q omitted non-secret identity %q: %s", format, useful, formatted)
			}
		}
	}
}

func TestRetryAfterCountsCallbackTimeTowardDelay(t *testing.T) {
	const (
		wait          = time.Second
		callbackDelay = 1500 * time.Millisecond
	)
	started := time.Now()
	err := retryAfter(context.Background(), func(error, time.Duration) {
		time.Sleep(callbackDelay)
	}, errors.New("retry attempt failed"), wait)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed >= 2*time.Second {
		t.Fatalf("retryAfter() took %s; callback time did not consume the retry delay", elapsed)
	}
}
