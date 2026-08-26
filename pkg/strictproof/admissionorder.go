package strictproof

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// The Connector's stable audit event strings for the three admission stages a
// cycle must pass through, in the only order the design permits: the NHP knock
// opens the data-plane fence, the authenticated FRP Login is admitted, and only
// then may a proxy be registered and allowed.
const (
	EventKnockSuccess = "qurl.connector.knock.success"
	EventLoginSuccess = "qurl.connector.login.success"
	EventProxyAllow   = "qurl.connector.proxy.allow"
	EventBootstrapOK  = "qurl.connector.bootstrap.success"
)

// admissionStages is the required order. Index in this slice is the required
// relative position of each stage's FIRST occurrence.
var admissionStages = []string{EventKnockSuccess, EventLoginSuccess, EventProxyAllow}

// VerifyAdmissionOrder checks that one Connector cycle reached proxy startup
// only after an authenticated FRP Login, which itself came only after a
// successful knock.
//
// events is the ordered sequence of Connector audit event names observed in a
// single cycle, oldest first. Callers pass every event they saw, including
// retries and denials; this verifier reasons about first occurrences, because
// the property under test is "no proxy was ever allowed before Login was
// admitted", not "nothing was ever retried".
//
// Inventory row: frp-authenticated-login-before-proxy-startup.
//
// The login.success stage is not an inferred client-side success. The pinned
// LayerV FRP fork invokes OnFirstLoginSuccess synchronously only after frps
// accepted and authenticated Login and before it creates the control or starts
// proxy registration. The Connector emits login.success in that callback and
// gates proxy.allow on the same admitted latch. VerifyBoundAdmissionOrder below
// additionally requires one exact RunID across the successful knock, accepted
// Login, and proxy allow events.
func VerifyAdmissionOrder(events []string) error {
	if len(events) == 0 {
		return fmt.Errorf("no Connector audit events observed; admission order is unproven")
	}

	first := make(map[string]int, len(admissionStages))
	for index, event := range events {
		if _, seen := first[event]; seen {
			continue
		}
		for _, stage := range admissionStages {
			if event == stage {
				first[event] = index
			}
		}
	}

	for _, stage := range admissionStages {
		if _, ok := first[stage]; !ok {
			return fmt.Errorf("cycle never reached %s; observed %s", stage, summarizeEvents(events))
		}
	}
	for i := 1; i < len(admissionStages); i++ {
		earlier, later := admissionStages[i-1], admissionStages[i]
		if first[later] <= first[earlier] {
			return fmt.Errorf(
				"%s (position %d) was not preceded by %s (position %d); observed %s",
				later, first[later], earlier, first[earlier], summarizeEvents(events),
			)
		}
	}
	return nil
}

// AdmissionObservation is the bounded audit subset needed to prove one
// authenticated admission cycle.
type AdmissionObservation struct {
	Event   string
	TraceID string
}

var cycleRunIDPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// VerifyBoundAdmissionOrder proves the three ordered stages belong to the same
// caller-owned native cycle accepted by frps.
func VerifyBoundAdmissionOrder(observations []AdmissionObservation) error {
	events := make([]string, 0, len(observations))
	runID := ""
	for _, observation := range observations {
		events = append(events, observation.Event)
		if observation.Event != EventKnockSuccess &&
			observation.Event != EventLoginSuccess &&
			observation.Event != EventProxyAllow {
			continue
		}
		if !cycleRunIDPattern.MatchString(observation.TraceID) {
			return fmt.Errorf("%s has no canonical cycle RunID", observation.Event)
		}
		if runID == "" {
			runID = observation.TraceID
		} else if observation.TraceID != runID {
			return fmt.Errorf("admission stages carry different cycle RunIDs")
		}
	}
	if err := VerifyAdmissionOrder(events); err != nil {
		return err
	}
	if runID == "" {
		return fmt.Errorf("admission cycle has no RunID")
	}
	return nil
}

// summarizeEvents renders an observed stream compactly for a failure message.
// It is bounded so a long-running cycle cannot turn one assertion failure into
// thousands of log lines.
func summarizeEvents(events []string) string {
	const maximum = 24
	shown := events
	suffix := ""
	if len(shown) > maximum {
		shown = shown[:maximum]
		suffix = fmt.Sprintf(" …(+%d more)", len(events)-maximum)
	}
	return "[" + strings.Join(shown, " ") + "]" + suffix
}

// ScanAuditEvents extracts the ordered Connector audit event names from a raw
// captured log. The Connector mirrors every audit entry through slog, so a
// container or subprocess log carries the same events in the same order as the
// JSONL audit sink; scanning the log keeps this usable in rigs that have no
// audit file mounted.
//
// Only the known qurl.connector.* event strings are returned, so an unrelated
// line that merely mentions one of them in prose cannot inject a stage.
func ScanAuditEvents(log string) []string {
	known := []string{
		EventBootstrapOK,
		EventKnockSuccess,
		EventLoginSuccess,
		EventProxyAllow,
	}
	var events []string
	for _, line := range strings.Split(log, "\n") {
		// One line may legitimately carry only one event; take the earliest
		// known match so ordering follows the log, not the slice above.
		best, bestAt := "", -1
		for _, event := range known {
			at := strings.Index(line, event)
			if at < 0 {
				continue
			}
			if bestAt < 0 || at < bestAt {
				best, bestAt = event, at
			}
		}
		if best != "" {
			events = append(events, best)
		}
	}
	return events
}

// ScanAdmissionObservations extracts only reviewed event/trace_id fields from
// JSON audit lines. Prefixes from the mirrored slog sink are tolerated by
// locating the first JSON object on each line.
func ScanAdmissionObservations(log string) []AdmissionObservation {
	known := map[string]bool{
		EventKnockSuccess: true,
		EventLoginSuccess: true,
		EventProxyAllow:   true,
	}
	var observations []AdmissionObservation
	for _, line := range strings.Split(log, "\n") {
		start := strings.IndexByte(line, '{')
		if start < 0 {
			continue
		}
		var entry struct {
			Event   string `json:"event"`
			TraceID string `json:"trace_id"`
		}
		if json.Unmarshal([]byte(line[start:]), &entry) == nil && known[entry.Event] {
			observations = append(observations, AdmissionObservation{
				Event: entry.Event, TraceID: entry.TraceID,
			})
		}
	}
	return observations
}
