package agentstate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// markerPathFor resolves the marker file inside dir without going through the
// env/default fallback, so tests assert against the concrete path.
func markerPathFor(dir string) string { return filepath.Join(dir, RefreshMarkerFile) }

func refreshMarkerTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(realSDKTempDir(t), "state")
	if err := os.Mkdir(dir, dirMode); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRegistrationRefreshMarker_AbsentIsNotPresent(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	m, present, err := LoadRegistrationRefreshMarker(dir)
	if err != nil {
		t.Fatalf("LoadRegistrationRefreshMarker on empty dir: %v", err)
	}
	if present {
		t.Fatalf("present = true on empty dir, want false (marker = %#v)", m)
	}
}

func TestRegistrationRefreshMarker_RequestSetsFreshSchedule(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := RequestRegistrationRefresh(dir, "sustained knock failures"); err != nil {
		t.Fatalf("RequestRegistrationRefresh: %v", err)
	}
	m, present, err := LoadRegistrationRefreshMarker(dir)
	if err != nil {
		t.Fatalf("LoadRegistrationRefreshMarker: %v", err)
	}
	if !present {
		t.Fatal("present = false after RequestRegistrationRefresh, want true")
	}
	if m.AttemptCount != 0 || m.LastAttemptUnixMilli != 0 || m.NextAttemptUnixMilli != 0 {
		t.Fatalf("fresh retry schedule = %#v, want zero attempts", m)
	}
	if m.Reason != "sustained knock failures" {
		t.Fatalf("Reason = %q, want %q", m.Reason, "sustained knock failures")
	}
	if m.StartedAtUnix == 0 {
		t.Fatal("StartedAtUnix = 0, want a stamped time")
	}
	// Mode is the non-secret pub mode.
	info, err := os.Stat(markerPathFor(dir))
	if err != nil {
		t.Fatalf("stat marker: %v", err)
	}
	if got := info.Mode().Perm(); got != pubMode {
		t.Fatalf("marker mode = %v, want %v", got, pubMode)
	}
}

func TestRegistrationRefreshMarker_RequestIsEpisodeIdempotent(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := RequestRegistrationRefresh(dir, "first"); err != nil {
		t.Fatalf("first RequestRegistrationRefresh: %v", err)
	}
	if err := MarkRegistrationRefreshAttempted(dir); err != nil {
		t.Fatalf("MarkRegistrationRefreshAttempted: %v", err)
	}
	// A subsequent budget exit requests again — must be a no-op on the
	// existing (attempted) marker.
	if err := RequestRegistrationRefresh(dir, "second-should-be-ignored"); err != nil {
		t.Fatalf("second RequestRegistrationRefresh: %v", err)
	}
	m, present, err := LoadRegistrationRefreshMarker(dir)
	if err != nil {
		t.Fatalf("LoadRegistrationRefreshMarker: %v", err)
	}
	if !present {
		t.Fatal("present = false, want true")
	}
	if m.AttemptCount != 1 || m.NextAttemptUnixMilli <= m.LastAttemptUnixMilli {
		t.Fatalf("retry schedule reset by second request: %#v", m)
	}
	if m.Reason != "first" {
		t.Fatalf("Reason = %q, want the original %q (second request must not overwrite)", m.Reason, "first")
	}
}

func TestRegistrationRefreshMarker_MarkAttemptAdvancesAndPersistsFields(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := RequestRegistrationRefresh(dir, "reason-x"); err != nil {
		t.Fatalf("RequestRegistrationRefresh: %v", err)
	}
	before, _, _ := LoadRegistrationRefreshMarker(dir)
	if err := MarkRegistrationRefreshAttempted(dir); err != nil {
		t.Fatalf("MarkRegistrationRefreshAttempted: %v", err)
	}
	m, present, err := LoadRegistrationRefreshMarker(dir)
	if err != nil {
		t.Fatalf("LoadRegistrationRefreshMarker: %v", err)
	}
	if !present || m.AttemptCount != 1 || m.LastAttemptUnixMilli <= 0 || m.NextAttemptUnixMilli <= m.LastAttemptUnixMilli {
		t.Fatalf("marker present=%v schedule=%#v, want one scheduled retry", present, m)
	}
	if m.Reason != "reason-x" || m.StartedAtUnix != before.StartedAtUnix {
		t.Fatalf("MarkRegistrationRefreshAttempted did not preserve episode fields: got %#v, want reason=%q started_at=%d", m, "reason-x", before.StartedAtUnix)
	}
}

func TestRegistrationRefreshMarker_AttemptsBackOffAndCap(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := RequestRegistrationRefresh(dir, "outage"); err != nil {
		t.Fatal(err)
	}
	var previous time.Duration
	for attempt := uint32(1); attempt <= 9; attempt++ {
		if err := MarkRegistrationRefreshAttempted(dir); err != nil {
			t.Fatal(err)
		}
		m, present, err := LoadRegistrationRefreshMarker(dir)
		if err != nil || !present {
			t.Fatalf("load attempt %d: present=%v err=%v", attempt, present, err)
		}
		delay := time.Duration(m.NextAttemptUnixMilli-m.LastAttemptUnixMilli) * time.Millisecond
		if m.AttemptCount != attempt || delay <= 0 || delay > refreshRetryMaximum+time.Millisecond {
			t.Fatalf("attempt %d schedule = %#v delay=%v", attempt, m, delay)
		}
		if attempt > 1 && previous < refreshRetryMaximum/2 && delay < previous/2 {
			t.Fatalf("attempt %d delay %v did not grow from %v", attempt, delay, previous)
		}
		previous = delay
	}
}

func TestRegistrationRefreshMarker_MarkAttemptedAbsentIsNoop(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := MarkRegistrationRefreshAttempted(dir); err != nil {
		t.Fatalf("MarkRegistrationRefreshAttempted on absent marker should be a no-op, got %v", err)
	}
	if _, present, _ := LoadRegistrationRefreshMarker(dir); present {
		t.Fatal("MarkRegistrationRefreshAttempted created a marker where none existed")
	}
}

func TestRegistrationRefreshMarker_ClearRemoves(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := RequestRegistrationRefresh(dir, "r"); err != nil {
		t.Fatalf("RequestRegistrationRefresh: %v", err)
	}
	if err := ClearRegistrationRefreshMarker(dir); err != nil {
		t.Fatalf("ClearRegistrationRefreshMarker: %v", err)
	}
	if _, present, err := LoadRegistrationRefreshMarker(dir); err != nil || present {
		t.Fatalf("after clear: present=%v err=%v, want absent+nil", present, err)
	}
}

func TestRegistrationRefreshMarker_ClearAbsentIsSuccess(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := ClearRegistrationRefreshMarker(dir); err != nil {
		t.Fatalf("ClearRegistrationRefreshMarker on absent marker should succeed, got %v", err)
	}
}

func TestRegistrationRefreshMarker_ClearThenRequestStartsNewEpisode(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := RequestRegistrationRefresh(dir, "episode-1"); err != nil {
		t.Fatalf("request 1: %v", err)
	}
	if err := MarkRegistrationRefreshAttempted(dir); err != nil {
		t.Fatalf("mark attempted: %v", err)
	}
	if err := ClearRegistrationRefreshMarker(dir); err != nil { // healthy knock
		t.Fatalf("clear: %v", err)
	}
	if err := RequestRegistrationRefresh(dir, "episode-2"); err != nil { // new episode
		t.Fatalf("request 2: %v", err)
	}
	m, present, err := LoadRegistrationRefreshMarker(dir)
	if err != nil || !present {
		t.Fatalf("after re-arm: present=%v err=%v, want present", present, err)
	}
	if m.AttemptCount != 0 {
		t.Fatalf("new episode attempt count = %d, want zero", m.AttemptCount)
	}
	if m.Reason != "episode-2" {
		t.Fatalf("Reason = %q, want %q", m.Reason, "episode-2")
	}
}

func TestRegistrationRefreshMarker_CorruptJSONIsError(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := os.WriteFile(markerPathFor(dir), []byte("{not json"), pubMode); err != nil {
		t.Fatalf("seed corrupt marker: %v", err)
	}
	_, present, err := LoadRegistrationRefreshMarker(dir)
	if !errors.Is(err, ErrInvalidRefreshMarker) {
		t.Fatal("LoadRegistrationRefreshMarker on corrupt JSON returned nil error; want a decode error so the caller can log it")
	}
	if present {
		t.Fatal("present = true for a corrupt marker")
	}
}

func TestRegistrationRefreshMarker_StrictSchemaRejectsAmbiguity(t *testing.T) {
	valid := `"attempt_count":0,"started_at_unix":1,"last_attempt_unix_milli":0,"next_attempt_unix_milli":0`
	tests := map[string]string{
		"missing version":       `{` + valid + `}`,
		"wrong version":         `{"version":1,` + valid + `}`,
		"missing attempt count": `{"version":2,"started_at_unix":1,"last_attempt_unix_milli":0,"next_attempt_unix_milli":0}`,
		"zero timestamp":        `{"version":2,"attempt_count":0,"started_at_unix":0,"last_attempt_unix_milli":0,"next_attempt_unix_milli":0}`,
		"invalid attempted":     `{"version":2,"attempt_count":1,"started_at_unix":1,"last_attempt_unix_milli":0,"next_attempt_unix_milli":0}`,
		"unknown field":         `{"version":2,` + valid + `,"extra":true}`,
		"duplicate field":       `{"version":2,` + valid + `,"attempt_count":1}`,
		"trailing value":        `{"version":2,` + valid + `}{}`,
		"unclean reason":        `{"version":2,"reason":" spaced ",` + valid + `}`,
		"control reason":        "{\"version\":2,\"reason\":\"line\\nfeed\"," + valid + "}",
		"oversize reason":       `{"version":2,"reason":"` + strings.Repeat("a", refreshMarkerReasonMaxBytes+1) + `",` + valid + `}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			dir := refreshMarkerTestDir(t)
			if err := os.WriteFile(markerPathFor(dir), []byte(raw), pubMode); err != nil {
				t.Fatal(err)
			}
			if marker, present, err := LoadRegistrationRefreshMarker(dir); !errors.Is(err, ErrInvalidRefreshMarker) || present || marker != (RefreshMarker{}) {
				t.Fatalf("LoadRegistrationRefreshMarker = (%#v, %v, %v), want zero, absent, invalid", marker, present, err)
			}
		})
	}
}

func TestRegistrationRefreshMarker_RequestRejectsUnboundedReason(t *testing.T) {
	for name, reason := range map[string]string{
		"control":  "line\nfeed",
		"oversize": strings.Repeat("a", refreshMarkerReasonMaxBytes+1),
		"invalid":  string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			dir := refreshMarkerTestDir(t)
			if err := RequestRegistrationRefresh(dir, reason); err == nil {
				t.Fatal("RequestRegistrationRefresh accepted an unbounded/noncanonical reason")
			}
			if _, err := os.Lstat(markerPathFor(dir)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid reason created marker: %v", err)
			}
		})
	}
}

func TestRegistrationRefreshMarker_EmptyFileIsError(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := os.WriteFile(markerPathFor(dir), []byte("   \n"), pubMode); err != nil {
		t.Fatalf("seed empty marker: %v", err)
	}
	if _, present, err := LoadRegistrationRefreshMarker(dir); !errors.Is(err, ErrInvalidRefreshMarker) || present {
		t.Fatalf("empty marker: present=%v err=%v, want present=false and a non-nil error", present, err)
	}
}

func TestRegistrationRefreshMarker_OversizeIsError(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	big := append([]byte(`{"reason":"`), []byte(strings.Repeat("a", refreshMarkerFileMaxBytes+1))...)
	big = append(big, []byte(`"}`)...)
	if err := os.WriteFile(markerPathFor(dir), big, pubMode); err != nil {
		t.Fatalf("seed oversize marker: %v", err)
	}
	if _, present, err := LoadRegistrationRefreshMarker(dir); !errors.Is(err, ErrInvalidRefreshMarker) || present {
		t.Fatalf("oversize marker: present=%v err=%v, want present=false and a non-nil error", present, err)
	}
}

// RequestRegistrationRefresh is presence-gated, not decode-gated: it leaves
// an existing marker untouched so transient faults cannot reset its cadence.
func TestRegistrationRefreshMarker_RequestLeavesExistingCorruptUntouched(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	const corrupt = "{bad"
	if err := os.WriteFile(markerPathFor(dir), []byte(corrupt), pubMode); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if err := RequestRegistrationRefresh(dir, "should-not-overwrite"); err != nil {
		t.Fatalf("RequestRegistrationRefresh over corrupt marker: %v", err)
	}
	raw, err := os.ReadFile(markerPathFor(dir))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(raw) != corrupt {
		t.Fatalf("RequestRegistrationRefresh overwrote an existing marker (got %q, want the untouched %q); presence gate broken", raw, corrupt)
	}
}

func TestRegistrationRefreshMarkerRejectsAndNeverOverwritesSymlink(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	target := filepath.Join(realSDKTempDir(t), "outside-marker.json")
	if err := os.WriteFile(target, []byte(`{"outside":true}`), pubMode); err != nil {
		t.Fatal(err)
	}
	path := markerPathFor(dir)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, present, err := LoadRegistrationRefreshMarker(dir); !errors.Is(err, ErrInvalidRefreshMarker) || present {
		t.Fatalf("symlink marker load = present %v, err %v; want invalid and absent", present, err)
	}
	if err := RequestRegistrationRefresh(dir, "must-not-follow"); err != nil {
		t.Fatalf("presence-gated request over symlink: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("RequestRegistrationRefresh replaced the existing marker symlink")
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"outside":true}` {
		t.Fatalf("outside marker target was changed: %s", raw)
	}
}

// refreshMarkerSDKStoreForTest opens an owning SDKStore on dir so marker
// contention runs through the same RLock+continuity path the connector uses.
func refreshMarkerSDKStoreForTest(t *testing.T, dir string) *SDKStore {
	t.Helper()
	t.Setenv(EnvKeyProvider, KeyProviderFile)
	store, err := NewSDKStore(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestRegistrationRefreshMarker_ConcurrentRequestsNeverResetRetrySchedule(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := RequestRegistrationRefresh(dir, "episode-under-test"); err != nil {
		t.Fatal(err)
	}
	if err := MarkRegistrationRefreshAttempted(dir); err != nil {
		t.Fatal(err)
	}
	storeA := refreshMarkerSDKStoreForTest(t, dir)
	storeB := refreshMarkerSDKStoreForTest(t, dir)

	const writers = 8
	const attempts = 25
	start := make(chan struct{})
	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			<-start
			for i := 0; i < attempts; i++ {
				var err error
				switch writer % 3 {
				case 0:
					err = RequestRegistrationRefresh(dir, "storm-package")
				case 1:
					err = storeA.RequestRegistrationRefresh("storm-store-a")
				default:
					err = storeB.RequestRegistrationRefresh("storm-store-b")
				}
				if err != nil {
					t.Errorf("presence-gated request over a live episode must be a silent no-op, got %v", err)
				}
			}
		}(writer)
	}
	close(start)
	wg.Wait()

	m, present, err := LoadRegistrationRefreshMarker(dir)
	if err != nil || !present {
		t.Fatalf("post-storm marker: present=%v err=%v, want the original episode", present, err)
	}
	if m.AttemptCount != 1 || m.NextAttemptUnixMilli <= m.LastAttemptUnixMilli {
		t.Fatalf("concurrent requests reset retry schedule: %#v", m)
	}
	if m.Reason != "episode-under-test" {
		t.Fatalf("Reason = %q, want the original %q untouched by the storm", m.Reason, "episode-under-test")
	}
}

// Multi-writer churn plus a concurrent reader: request/attempt/clear sequences
// race across two SDKStore instances and the package-level entry points while
// a 9th goroutine loops Loads. Every Load must observe absent or a fully-valid
// marker; a decode failure would mean a torn marker escaped the tmp+rename
// write path. Detection errors from the pinned read/write validators racing a
// concurrent rename/remove are legitimate and tolerated.
func TestRegistrationRefreshMarker_ConcurrentChurnNeverExposesTornMarker(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	storeA := refreshMarkerSDKStoreForTest(t, dir)
	storeB := refreshMarkerSDKStoreForTest(t, dir)

	tornMarker := func(err error) bool {
		return err != nil && strings.Contains(err.Error(), "decode")
	}
	validateLoaded := func(m RefreshMarker) {
		if m.Version != refreshMarkerVersion || m.StartedAtUnix <= 0 || m.Reason != "churn" {
			t.Errorf("concurrent Load returned a partially-valid marker %#v", m)
		}
	}

	const writers = 8
	const cycles = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	for writer := 0; writer < writers; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			<-start
			requestOp := func() error { return RequestRegistrationRefresh(dir, "churn") }
			attemptOp := func() error { return MarkRegistrationRefreshAttempted(dir) }
			clearOp := func() error { return ClearRegistrationRefreshMarker(dir) }
			switch writer % 3 {
			case 1:
				requestOp = func() error { return storeA.RequestRegistrationRefresh("churn") }
				attemptOp = storeA.MarkRegistrationRefreshAttempted
				clearOp = storeA.ClearRegistrationRefreshMarker
			case 2:
				requestOp = func() error { return storeB.RequestRegistrationRefresh("churn") }
				attemptOp = storeB.MarkRegistrationRefreshAttempted
				clearOp = storeB.ClearRegistrationRefreshMarker
			}
			for i := 0; i < cycles; i++ {
				for _, op := range []func() error{requestOp, attemptOp, clearOp} {
					if err := op(); tornMarker(err) {
						t.Errorf("marker mutation decoded a torn marker: %v", err)
					}
				}
			}
		}(writer)
	}

	stop := make(chan struct{})
	loaderDone := make(chan int)
	go func() {
		loads := 0
		for {
			select {
			case <-stop:
				loaderDone <- loads
				return
			default:
			}
			var m RefreshMarker
			var present bool
			var err error
			if loads%2 == 0 {
				m, present, err = LoadRegistrationRefreshMarker(dir)
			} else {
				m, present, err = storeA.LoadRegistrationRefreshMarker()
			}
			loads++
			if tornMarker(err) {
				t.Errorf("concurrent Load decoded a torn marker: %v", err)
				continue
			}
			if err == nil && present {
				validateLoaded(m)
			}
		}
	}()

	close(start)
	wg.Wait()
	close(stop)
	if loads := <-loaderDone; loads == 0 {
		t.Fatal("concurrent loader never ran; the churn observed nothing")
	}

	m, present, err := LoadRegistrationRefreshMarker(dir)
	if err != nil {
		t.Fatalf("quiescent Load after churn: %v", err)
	}
	if present {
		validateLoaded(m)
	}
}

// The on-disk shape is the documented wire contract; pin it so a field rename
// is a conscious change.
func TestRegistrationRefreshMarker_OnDiskShape(t *testing.T) {
	dir := refreshMarkerTestDir(t)
	if err := RequestRegistrationRefresh(dir, "shape"); err != nil {
		t.Fatalf("RequestRegistrationRefresh: %v", err)
	}
	raw, err := os.ReadFile(markerPathFor(dir))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("marker is not valid JSON: %v", err)
	}
	for _, field := range []string{"attempt_count", "started_at_unix", "last_attempt_unix_milli", "next_attempt_unix_milli"} {
		if _, ok := generic[field]; !ok {
			t.Fatalf("marker JSON missing %q key: %s", field, raw)
		}
	}
	if generic["version"] != float64(refreshMarkerVersion) {
		t.Fatalf("marker JSON version = %#v, want %d: %s", generic["version"], refreshMarkerVersion, raw)
	}
}
