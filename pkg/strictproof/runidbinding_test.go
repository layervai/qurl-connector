package strictproof

import (
	"strings"
	"testing"
)

func boundCycle(label, runID string) CycleRunIDObservation {
	observed := make(map[RunIDCarrier]string, len(requiredCarriers))
	for _, carrier := range requiredCarriers {
		observed[carrier] = runID
	}
	return CycleRunIDObservation{Label: label, Observed: observed}
}

func TestVerifyRunIDCycleBindingAcceptsBoundRotatingCycles(t *testing.T) {
	cycles := []CycleRunIDObservation{
		boundCycle("cold", "0123456789abcdef"),
		boundCycle("warm", "fedcba9876543210"),
		boundCycle("reassigned", "00112233445566ff"),
	}
	if err := VerifyRunIDCycleBinding(cycles); err != nil {
		t.Fatalf("bound rotating cycles rejected: %v", err)
	}
}

func TestVerifyRunIDCycleBindingRequiresRotation(t *testing.T) {
	reused := "0123456789abcdef"
	err := VerifyRunIDCycleBinding([]CycleRunIDObservation{
		boundCycle("first", reused),
		boundCycle("second", reused),
	})
	if err == nil {
		t.Fatal("a reused RunID across outer cycles was accepted")
	}
	if !strings.Contains(err.Error(), "second") || !strings.Contains(err.Error(), "first") {
		t.Fatalf("failure does not name both cycles: %v", err)
	}
}

func TestVerifyRunIDCycleBindingRequiresAtLeastTwoCycles(t *testing.T) {
	for name, cycles := range map[string][]CycleRunIDObservation{
		"none": nil,
		"one":  {boundCycle("only", "0123456789abcdef")},
	} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyRunIDCycleBinding(cycles); err == nil {
				t.Fatal("rotation claimed without a second cycle")
			}
		})
	}
}

func TestVerifyRunIDCycleBindingRequiresEveryCarrier(t *testing.T) {
	for _, missing := range requiredCarriers {
		t.Run(string(missing), func(t *testing.T) {
			incomplete := boundCycle("incomplete", "0123456789abcdef")
			delete(incomplete.Observed, missing)
			err := VerifyRunIDCycleBinding([]CycleRunIDObservation{
				incomplete,
				boundCycle("other", "fedcba9876543210"),
			})
			if err == nil {
				t.Fatalf("cycle missing %s was accepted", missing)
			}
			if !strings.Contains(err.Error(), string(missing)) {
				t.Fatalf("failure does not name the missing carrier %s: %v", missing, err)
			}
		})
	}
}

func TestVerifyRunIDCycleBindingRejectsDivergenceWithinACycle(t *testing.T) {
	for _, diverging := range requiredCarriers {
		t.Run(string(diverging), func(t *testing.T) {
			cycle := boundCycle("diverging", "0123456789abcdef")
			cycle.Observed[diverging] = "aaaaaaaaaaaaaaaa"
			err := VerifyRunIDCycleBinding([]CycleRunIDObservation{
				cycle,
				boundCycle("other", "fedcba9876543210"),
			})
			if err == nil {
				t.Fatalf("a cycle that changed its RunID at %s was accepted", diverging)
			}
			if !strings.Contains(err.Error(), string(diverging)) {
				t.Fatalf("failure does not name the diverging carrier %s: %v", diverging, err)
			}
		})
	}
}

func TestVerifyRunIDCycleBindingRejectsNoncanonicalRunIDs(t *testing.T) {
	// Exactly qurl-go's ValidateCycleRunID contract: 16 lowercase hex bytes,
	// never trimmed or case-folded by the consumer.
	for name, runID := range map[string]string{
		"empty":            "",
		"too short":        "0123456789abcde",
		"too long":         "0123456789abcdef0",
		"uppercase hex":    "0123456789ABCDEF",
		"non hex":          "0123456789abcdeg",
		"leading space":    " 123456789abcdef",
		"trailing newline": "0123456789abcde\n",
	} {
		t.Run(name, func(t *testing.T) {
			err := VerifyRunIDCycleBinding([]CycleRunIDObservation{
				boundCycle("noncanonical", runID),
				boundCycle("other", "fedcba9876543210"),
			})
			if err == nil {
				t.Fatalf("noncanonical RunID %q was accepted", runID)
			}
		})
	}
}

func TestVerifyRunIDCycleBindingRejectsUnknownCarriers(t *testing.T) {
	cycle := boundCycle("extra", "0123456789abcdef")
	cycle.Observed["some other hop"] = "0123456789abcdef"
	err := VerifyRunIDCycleBinding([]CycleRunIDObservation{
		cycle,
		boundCycle("other", "fedcba9876543210"),
	})
	if err == nil {
		t.Fatal("an unenumerated RunID carrier was silently accepted")
	}
	if !strings.Contains(err.Error(), "some other hop") {
		t.Fatalf("failure does not name the unknown carrier: %v", err)
	}
}

func TestVerifyRunIDCycleBindingRejectsEmptyObservationMap(t *testing.T) {
	err := VerifyRunIDCycleBinding([]CycleRunIDObservation{
		{Label: "unobserved"},
		boundCycle("other", "fedcba9876543210"),
	})
	if err == nil {
		t.Fatal("a cycle with no observations at all was accepted")
	}
}

// admissionLog renders one phase's audit stream the way the hardened rig
// captures it: JSONL entries, some wrapped in a slog-mirror prefix, with
// unrelated lines interleaved.
func admissionLog(runID string) string {
	return strings.Join([]string{
		`{"ts":"2026-08-02T00:00:00Z","event":"qurl.connector.bootstrap.success","outcome":"success"}`,
		"time=2026-08-02T00:00:01Z level=INFO msg=qurl.connector.knock.success " +
			`{"ts":"2026-08-02T00:00:01Z","event":"qurl.connector.knock.success","outcome":"success","trace_id":"` + runID + `","run_id":"` + runID + `"}`,
		"a prose line that mentions qurl.connector.login.success without JSON",
		`{"ts":"2026-08-02T00:00:02Z","event":"qurl.connector.login.success","outcome":"success","trace_id":"` + runID + `","run_id":"` + runID + `"}`,
		`{"ts":"2026-08-02T00:00:03Z","event":"qurl.connector.proxy.allow","outcome":"allow","trace_id":"` + runID + `","run_id":"` + runID + `"}`,
		`{"ts":"2026-08-02T00:00:04Z","event":"qurl.connector.teardown","outcome":"success","run_id":"` + runID + `"}`,
		"",
	}, "\n")
}

func TestScanCycleRunIDObservationBindsOneCycleAndVerifiesRotation(t *testing.T) {
	cold, err := ScanCycleRunIDObservation("cold", admissionLog("0123456789abcdef"))
	if err != nil {
		t.Fatalf("scan cold: %v", err)
	}
	warm, err := ScanCycleRunIDObservation("warm", admissionLog("fedcba9876543210"))
	if err != nil {
		t.Fatalf("scan warm: %v", err)
	}
	for _, carrier := range requiredCarriers {
		if got := cold.Observed[carrier]; got != "0123456789abcdef" {
			t.Fatalf("cold %s = %q, want the cycle RunID", carrier, got)
		}
	}
	if len(cold.Observed) != len(requiredCarriers) {
		t.Fatalf("cold observed %d carriers, want exactly %d", len(cold.Observed), len(requiredCarriers))
	}
	if err := VerifyRunIDCycleBinding([]CycleRunIDObservation{cold, warm}); err != nil {
		t.Fatalf("scanned rotating cycles rejected: %v", err)
	}
}

func TestScanCycleRunIDObservationRejectsTwoCyclesInOneLog(t *testing.T) {
	log := admissionLog("0123456789abcdef") + admissionLog("fedcba9876543210")
	_, err := ScanCycleRunIDObservation("cold", log)
	if err == nil {
		t.Fatal("a log holding two admission cycles was scanned as one")
	}
	if !strings.Contains(err.Error(), "cold") || !strings.Contains(err.Error(), string(CarrierKnockKNK)) {
		t.Fatalf("failure does not name the label and diverging carrier: %v", err)
	}
}

func TestScanCycleRunIDObservationLeavesUnseenCarriersAbsent(t *testing.T) {
	log := `{"event":"qurl.connector.knock.success","run_id":"0123456789abcdef"}` + "\n"
	observation, err := ScanCycleRunIDObservation("cold", log)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(observation.Observed) != 1 {
		t.Fatalf("observed %d carriers, want only %s", len(observation.Observed), CarrierKnockKNK)
	}
	err = VerifyRunIDCycleBinding([]CycleRunIDObservation{
		observation,
		boundCycle("warm", "fedcba9876543210"),
	})
	if err == nil || !strings.Contains(err.Error(), string(CarrierFirstFRPLogin)) {
		t.Fatalf("missing Login carrier not reported by name: %v", err)
	}
}

func TestScanCycleRunIDObservationRecordsBlankRunIDAsObserved(t *testing.T) {
	// An old binary emits the events without run_id; that must fail as a
	// noncanonical observation at the carrier, not as an unobserved carrier.
	log := strings.Join([]string{
		`{"event":"qurl.connector.knock.success"}`,
		`{"event":"qurl.connector.login.success"}`,
		`{"event":"qurl.connector.proxy.allow"}`,
		"",
	}, "\n")
	observation, err := ScanCycleRunIDObservation("cold", log)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	err = VerifyRunIDCycleBinding([]CycleRunIDObservation{
		observation,
		boundCycle("warm", "fedcba9876543210"),
	})
	if err == nil || !strings.Contains(err.Error(), "noncanonical") {
		t.Fatalf("blank run_id not rejected as noncanonical: %v", err)
	}
}

func TestScanCycleRunIDObservationIgnoresDenyErrorAndUnknownEvents(t *testing.T) {
	log := strings.Join([]string{
		`{"event":"qurl.connector.knock.deny","run_id":"aaaaaaaaaaaaaaaa"}`,
		`{"event":"qurl.connector.login.error","run_id":"bbbbbbbbbbbbbbbb"}`,
		`{"event":"qurl.connector.knock.success","run_id":"0123456789abcdef"}`,
		"",
	}, "\n")
	observation, err := ScanCycleRunIDObservation("cold", log)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(observation.Observed) != 1 || observation.Observed[CarrierKnockKNK] != "0123456789abcdef" {
		t.Fatalf("deny/error entries leaked into the observation: %#v", observation.Observed)
	}
}
