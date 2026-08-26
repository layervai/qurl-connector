package strictproof

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	qurl "github.com/layervai/qurl-go/qurl"
)

// RunIDCarrier names one place a cycle RunID is observable. The names are the
// admission surfaces the inventory row enumerates — each backed by a distinct
// audit event the Connector emits from distinct evidence — so a failure
// message points at the exact hop that diverged.
type RunIDCarrier string

const (
	// CarrierKnockKNK is the RunID the cycle presented inside the native
	// NHP_KNK body, observed on the qurl.connector.knock.success entry. The
	// entry is emitted only after qurl-go authenticated the assigned cell's
	// admission reply for that session identity.
	CarrierKnockKNK RunIDCarrier = "knock KNK"
	// CarrierFirstFRPLogin is the RunID frps returned on the accepted first
	// FRP Login, observed on qurl.connector.login.success. The fork's
	// OnFirstLoginSuccess hook validates the server-returned value equals the
	// presented cycle RunID byte for byte before the entry is emitted, so
	// this carrier is a server-side acceptance read back by the client.
	CarrierFirstFRPLogin RunIDCarrier = "first FRP Login"
	// CarrierProxyRegistration is the RunID of the admitted session under
	// which the cycle's proxies were registered, observed on
	// qurl.connector.proxy.allow (gated on the same admission latch the
	// login.success hook set).
	CarrierProxyRegistration RunIDCarrier = "FRP proxy registration"
)

// requiredCarriers is the exact set the row demands within one cycle. Every one
// must be observed; an unobserved carrier is a failure, not a pass.
var requiredCarriers = []RunIDCarrier{
	CarrierKnockKNK,
	CarrierFirstFRPLogin,
	CarrierProxyRegistration,
}

// CycleRunIDObservation is what one complete outer Connector cycle presented at
// each carrier. A carrier that was never observed must be absent from the map
// rather than present with an empty string, so "we did not look" and "it was
// blank" cannot be confused.
type CycleRunIDObservation struct {
	// Label identifies the cycle in failure messages (a process name, a
	// container name, an ordinal — whatever the rig used).
	Label string
	// Observed maps each carrier to the exact RunID bytes seen there.
	Observed map[RunIDCarrier]string
}

// VerifyRunIDCycleBinding checks that each outer cycle used exactly one
// canonical RunID at every enumerated carrier, and that a fresh outer cycle
// rotated to a new RunID instead of reusing the previous one.
//
// Inventory row: connector.run_id_cycle_binding
// (TestSandboxConnectorUDP/run_id_cycle_binding scans the hardened cold and
// warm audit logs with ScanCycleRunIDObservation and hands the result here).
//
// PROVEN here, given complete observations: the RunID is canonical per
// qurl-go's own ValidateCycleRunID; it is byte-identical across the knock KNK,
// the authenticated first FRP Login, and the proxy registration within a
// cycle; every enumerated carrier was actually observed; and no two cycles
// share a RunID. This is exactly the recovery chain the knock-invalid rollout
// ledger requires — a fresh cycle means a new RunID, a new UDP knock
// admission, a new Login, and proxy registration under that one value.
//
// NOT proven here: producer-side reads. The assigned cell's ACK metadata and
// the qRTS SessionStore record are never read back by any client lane
// (qurl-go's NativeKnockResult exposes no RunID), and FRP reconnect Logins
// inside one cycle have no per-reconnect audit surface — the fork's
// OnFirstLoginSuccess fires once per service run. The login.success carrier is
// the closest client-observable statement of the server side: it is emitted
// only after the accepted Login's server-returned RunID was validated equal to
// the presented one.
func VerifyRunIDCycleBinding(cycles []CycleRunIDObservation) error {
	// Rotation is half the requirement, and one cycle cannot demonstrate it.
	if len(cycles) < 2 {
		return fmt.Errorf("observed %d outer cycle(s); rotation needs at least 2", len(cycles))
	}

	canonical := make([]string, 0, len(cycles))
	for index, cycle := range cycles {
		label := cycle.Label
		if label == "" {
			label = fmt.Sprintf("cycle %d", index)
		}
		runID, err := singleCycleRunID(label, cycle.Observed)
		if err != nil {
			return err
		}
		canonical = append(canonical, runID)
	}

	seen := make(map[string]string, len(canonical))
	for index, runID := range canonical {
		label := cycles[index].Label
		if label == "" {
			label = fmt.Sprintf("cycle %d", index)
		}
		if previous, reused := seen[runID]; reused {
			return fmt.Errorf("%s reused the RunID from %s instead of rotating it", label, previous)
		}
		seen[runID] = label
	}
	return nil
}

// singleCycleRunID returns the one RunID a cycle must have used everywhere, or
// an error naming the missing or divergent carrier.
func singleCycleRunID(label string, observed map[RunIDCarrier]string) (string, error) {
	if len(observed) == 0 {
		return "", fmt.Errorf("%s carries no RunID observations", label)
	}
	for _, carrier := range requiredCarriers {
		if _, ok := observed[carrier]; !ok {
			return "", fmt.Errorf("%s has no RunID observation at %s", label, carrier)
		}
	}
	// An observation the row does not enumerate is a contract change, not a
	// bonus: fail rather than quietly ignore it.
	for carrier := range observed {
		if !isRequiredCarrier(carrier) {
			return "", fmt.Errorf("%s carries an unrecognized RunID carrier %q", label, carrier)
		}
	}

	distinct := make(map[string][]RunIDCarrier, 1)
	for _, carrier := range requiredCarriers {
		runID := observed[carrier]
		if err := qurl.ValidateCycleRunID(runID); err != nil {
			return "", fmt.Errorf("%s presented a noncanonical RunID at %s: %w", label, carrier, err)
		}
		distinct[runID] = append(distinct[runID], carrier)
	}
	if len(distinct) != 1 {
		return "", fmt.Errorf("%s used %d different RunIDs within one cycle: %s", label, len(distinct), describeDivergence(distinct))
	}
	for runID := range distinct {
		return runID, nil
	}
	return "", fmt.Errorf("%s produced no RunID", label) // unreachable: distinct has exactly one key
}

func isRequiredCarrier(carrier RunIDCarrier) bool {
	for _, required := range requiredCarriers {
		if carrier == required {
			return true
		}
	}
	return false
}

// runIDCarrierByEvent maps each admission audit event to the carrier its
// run_id field observes. Only success/allow events participate: a deny or
// error entry describes a cycle that never reached the carrier it would have
// bound.
var runIDCarrierByEvent = map[string]RunIDCarrier{
	EventKnockSuccess: CarrierKnockKNK,
	EventLoginSuccess: CarrierFirstFRPLogin,
	EventProxyAllow:   CarrierProxyRegistration,
}

// ScanCycleRunIDObservation extracts one cycle's RunID observations from a raw
// captured Connector audit log (JSONL; slog-mirror prefixes are tolerated by
// locating the first JSON object on each line, like ScanAdmissionObservations).
//
// The caller's contract is one admission cycle per log — the hardened rig
// snapshots the cold and warm phases separately, and VerifyBoundAdmissionOrder
// already rejects a phase log whose admission stages span two RunIDs. Within
// that contract every knock.success / login.success / proxy.allow entry's
// run_id feeds the corresponding carrier; two entries of one event class that
// disagree mean the log holds more than one cycle, and the scan fails rather
// than guessing which cycle to bind. An event class that never appears stays
// absent from the observation map, so VerifyRunIDCycleBinding reports the
// missing carrier by name; a present-but-empty run_id is recorded as observed
// and fails canonicality there, keeping "we did not look" and "it was blank"
// distinct.
func ScanCycleRunIDObservation(label, log string) (CycleRunIDObservation, error) {
	observation := CycleRunIDObservation{
		Label:    label,
		Observed: make(map[RunIDCarrier]string, len(requiredCarriers)),
	}
	for _, line := range strings.Split(log, "\n") {
		start := strings.IndexByte(line, '{')
		if start < 0 {
			continue
		}
		var entry struct {
			Event string `json:"event"`
			RunID string `json:"run_id"`
		}
		if json.Unmarshal([]byte(line[start:]), &entry) != nil {
			continue
		}
		carrier, ok := runIDCarrierByEvent[entry.Event]
		if !ok {
			continue
		}
		if previous, seen := observation.Observed[carrier]; seen && previous != entry.RunID {
			return CycleRunIDObservation{}, fmt.Errorf(
				"%s carries two different RunIDs at %s; the log holds more than one admission cycle",
				label, carrier)
		}
		observation.Observed[carrier] = entry.RunID
	}
	return observation, nil
}

// describeDivergence renders the RunID-to-carrier grouping deterministically so
// a failure message is stable across runs.
func describeDivergence(distinct map[string][]RunIDCarrier) string {
	runIDs := make([]string, 0, len(distinct))
	for runID := range distinct {
		runIDs = append(runIDs, runID)
	}
	sort.Strings(runIDs)
	out := ""
	for i, runID := range runIDs {
		if i > 0 {
			out += "; "
		}
		out += runID + " at "
		for j, carrier := range distinct[runID] {
			if j > 0 {
				out += ", "
			}
			out += string(carrier)
		}
	}
	return out
}
