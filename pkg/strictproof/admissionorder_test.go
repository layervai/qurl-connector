package strictproof

import (
	"strings"
	"testing"
)

func TestVerifyAdmissionOrderAcceptsAdmittedCycles(t *testing.T) {
	for name, events := range map[string][]string{
		"minimal cold cycle": {
			EventBootstrapOK, EventKnockSuccess, EventLoginSuccess, EventProxyAllow,
		},
		"warm cycle without enrollment": {
			EventKnockSuccess, EventLoginSuccess, EventProxyAllow,
		},
		"retried knock then admission": {
			"qurl.connector.knock.error", "qurl.connector.knock.error",
			EventKnockSuccess, EventLoginSuccess, EventProxyAllow,
		},
		"reconnect re-registers proxies": {
			EventKnockSuccess, EventLoginSuccess, EventProxyAllow,
			"qurl.connector.login.error", EventLoginSuccess, EventProxyAllow,
		},
		"multiple routes allowed after one login": {
			EventKnockSuccess, EventLoginSuccess, EventProxyAllow, EventProxyAllow, EventProxyAllow,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyAdmissionOrder(events); err != nil {
				t.Fatalf("admitted cycle rejected: %v", err)
			}
		})
	}
}

func TestVerifyAdmissionOrderRejectsUnorderedOrIncompleteCycles(t *testing.T) {
	for name, events := range map[string][]string{
		"nothing observed":        {},
		"proxy before login":      {EventKnockSuccess, EventProxyAllow, EventLoginSuccess},
		"login before knock":      {EventLoginSuccess, EventKnockSuccess, EventProxyAllow},
		"proxy with no login":     {EventKnockSuccess, EventProxyAllow},
		"login with no knock":     {EventLoginSuccess, EventProxyAllow},
		"never reached proxy":     {EventKnockSuccess, EventLoginSuccess},
		"knock denied throughout": {"qurl.connector.knock.deny", EventLoginSuccess, EventProxyAllow},
		"only enrollment":         {EventBootstrapOK},
		"proxy first":             {EventProxyAllow, EventKnockSuccess, EventLoginSuccess},
		"simultaneous impossible": {EventKnockSuccess, EventLoginSuccess, EventLoginSuccess},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyAdmissionOrder(events); err == nil {
				t.Fatalf("unordered or incomplete cycle accepted: %v", events)
			}
		})
	}
}

func TestVerifyAdmissionOrderFailureNamesTheOffendingStage(t *testing.T) {
	err := VerifyAdmissionOrder([]string{EventKnockSuccess, EventProxyAllow, EventLoginSuccess})
	if err == nil {
		t.Fatal("out-of-order cycle accepted")
	}
	if !strings.Contains(err.Error(), EventProxyAllow) || !strings.Contains(err.Error(), EventLoginSuccess) {
		t.Fatalf("failure does not name both stages: %v", err)
	}
}

func TestScanAuditEventsPreservesLogOrder(t *testing.T) {
	log := strings.Join([]string{
		`{"ts":"2026-07-27T00:00:00Z","event":"qurl.connector.bootstrap.success"}`,
		`some unrelated startup line`,
		`{"ts":"2026-07-27T00:00:01Z","event":"qurl.connector.knock.error"}`,
		`{"ts":"2026-07-27T00:00:02Z","event":"qurl.connector.knock.success"}`,
		`{"ts":"2026-07-27T00:00:03Z","event":"qurl.connector.login.success"}`,
		`{"ts":"2026-07-27T00:00:04Z","event":"qurl.connector.proxy.allow"}`,
	}, "\n")
	got := ScanAuditEvents(log)
	want := []string{EventBootstrapOK, EventKnockSuccess, EventLoginSuccess, EventProxyAllow}
	if len(got) != len(want) {
		t.Fatalf("scanned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scanned %v, want %v", got, want)
		}
	}
	if err := VerifyAdmissionOrder(got); err != nil {
		t.Fatalf("scanned stream rejected: %v", err)
	}
}

func TestScanAuditEventsIgnoresUnknownAndEmptyInput(t *testing.T) {
	if got := ScanAuditEvents(""); len(got) != 0 {
		t.Fatalf("empty log scanned %v", got)
	}
	if got := ScanAuditEvents("qurl.connector.teardown\nqurl.connector.proxy.deny\n"); len(got) != 0 {
		t.Fatalf("non-admission events scanned %v", got)
	}
	// A single line carrying two events reports the earlier one, so the derived
	// order follows the log text rather than the internal lookup order.
	got := ScanAuditEvents("prefix " + EventLoginSuccess + " then " + EventProxyAllow)
	if len(got) != 1 || got[0] != EventLoginSuccess {
		t.Fatalf("multi-event line scanned %v, want [%s]", got, EventLoginSuccess)
	}
}

func TestVerifyBoundAdmissionOrderRequiresOneCanonicalRunID(t *testing.T) {
	const runID = "0123456789abcdef"
	valid := []AdmissionObservation{
		{Event: EventKnockSuccess, TraceID: runID},
		{Event: EventLoginSuccess, TraceID: runID},
		{Event: EventProxyAllow, TraceID: runID},
	}
	if err := VerifyBoundAdmissionOrder(valid); err != nil {
		t.Fatalf("bound admission rejected: %v", err)
	}
	for name, mutate := range map[string]func([]AdmissionObservation){
		"missing run id": func(observations []AdmissionObservation) {
			observations[0].TraceID = ""
		},
		"mismatched run id": func(observations []AdmissionObservation) {
			observations[2].TraceID = "fedcba9876543210"
		},
	} {
		t.Run(name, func(t *testing.T) {
			observations := append([]AdmissionObservation(nil), valid...)
			mutate(observations)
			if err := VerifyBoundAdmissionOrder(observations); err == nil {
				t.Fatal("unbound admission accepted")
			}
		})
	}
}
