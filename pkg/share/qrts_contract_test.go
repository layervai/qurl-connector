package share

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/layervai/qurl-connector/contracts"
	"github.com/layervai/qurl-connector/pkg/config"
)

// qrtsKnockContractEnv optionally points at the tunnel server's matching
// snapshot. When present, producer and consumer snapshots must agree before
// this test reaches the matcher assertions.
const qrtsKnockContractEnv = "QRTS_KNOCK_TOKEN_LOGIN_CONTRACT"

const qrtsRecoverableNewProxyContractEnv = "QRTS_RECOVERABLE_NEWPROXY_CONTRACT"

type qrtsKnockTokenLoginContract struct {
	SchemaVersion        int      `json:"schema_version"`
	LoginMetasKey        string   `json:"login_metas_key"`
	RejectTag            string   `json:"reject_tag"`
	ClientNeedles        []string `json:"client_needles"`
	LoginRejectWireTexts []string `json:"login_reject_wire_texts"`
}

type qrtsRecoverableNewProxyContract struct {
	SchemaVersion   int                      `json:"schema_version"`
	NewProxyRejects []qrtsNewProxyWireReject `json:"new_proxy_rejects"`
}

type qrtsNewProxyWireReject struct {
	Tag      string `json:"tag"`
	WireText string `json:"wire_text"`
}

// TestQRTSKnockTokenLoginContract binds the checked-in consumer snapshot of
// the knock-token Login contract to the production surfaces that implement
// it: the exact StatusExporter tag classifier and the Login.Metas key constant.
func TestQRTSKnockTokenLoginContract(t *testing.T) {
	contract := decodeKnockTokenLoginContract(t, "Connector snapshot", contracts.QRTSKnockTokenLogin)

	if producerPath := os.Getenv(qrtsKnockContractEnv); producerPath != "" {
		producerFixture, err := os.ReadFile(producerPath)
		if err != nil {
			t.Fatalf("read qRTS producer fixture %q: %v", producerPath, err)
		}
		producer := decodeKnockTokenLoginContract(t, "qRTS producer fixture", producerFixture)
		if producer.LoginMetasKey != contract.LoginMetasKey ||
			producer.RejectTag != contract.RejectTag ||
			!slices.Equal(producer.ClientNeedles, contract.ClientNeedles) ||
			!slices.Equal(producer.LoginRejectWireTexts, contract.LoginRejectWireTexts) {
			t.Errorf("qRTS knock-token Login contract drifted:\n  producer  %+v\n  Connector %+v\nreconcile qRTS's vendored copy and %q together (contracts/README.md, Changing a contract)",
				producer, contract, "contracts/qrts_knock_token_login_wire_contract.json")
		}
	}

	// The Login.Metas key the managed session stamps the AC token under must be
	// the contract key — qRTS reads exactly this map entry.
	if config.MetaQURLKnockToken != contract.LoginMetasKey {
		t.Errorf("config.MetaQURLKnockToken = %q, contract login_metas_key = %q; the stamped key and the key qRTS reads must be identical",
			config.MetaQURLKnockToken, contract.LoginMetasKey)
	}

	if !slices.Equal(contract.ClientNeedles, []string{contract.RejectTag}) {
		t.Fatalf("client needles = %q, want the one exact reject tag %q", contract.ClientNeedles, contract.RejectTag)
	}

	// Every needle must be provably matched by at least one producer wire
	// text. A needle no wire text contains is dead — the classifier would
	// never fire on a real reject, which is the historical bug this contract
	// exists to prevent.
	for _, needle := range contract.ClientNeedles {
		matched := false
		for _, wireText := range contract.LoginRejectWireTexts {
			if strings.Contains(strings.ToLower(wireText), needle) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("client needle %q is contained in no login_reject_wire_texts entry — dead needle", needle)
		}
	}

	for _, wireText := range contract.LoginRejectWireTexts {
		t.Run(wireText, func(t *testing.T) {
			if got := proxyStartErrorTag(wireText); got != contract.RejectTag {
				t.Errorf("proxyStartErrorTag(%q) = %q, want %q", wireText, got, contract.RejectTag)
			}
		})
	}

	// StatusExporter.Err contains NewProxyResp.Error verbatim. Prefixes,
	// whitespace, alternate delimiters, and near-miss tags must not classify.
	negatives := []string{
		"start error: knock_invalid: knock token expired",
		" knock_invalid: knock token expired",
		"knock_invalid:knock token expired",
		"knock-invalid: knock token expired",
		"token expired",
	}
	for _, msg := range negatives {
		if proxyStartErrorTag(msg) == contract.RejectTag {
			t.Errorf("proxyStartErrorTag(%q) classified the contract tag", msg)
		}
	}
}

// TestQRTSRecoverableNewProxyContract binds qRTS's exact NewProxy terminal
// wire values to the production StatusExporter classifier. This replaces the
// retired log-sniffer contract: the managed FRP session reads the direct
// NewProxyResp.Error value at byte zero and rotates only on an exact tag.
func TestQRTSRecoverableNewProxyContract(t *testing.T) {
	expectedTags := map[string]struct{}{
		"owner_missing": {},
		"knock_invalid": {},
		"session_stale": {},
	}
	contract := decodeRecoverableNewProxyContract(t, "Connector snapshot", contracts.QRTSRecoverableNewProxy, expectedTags)

	var producerByTag map[string]string
	if producerPath := os.Getenv(qrtsRecoverableNewProxyContractEnv); producerPath != "" {
		producerFixture, err := os.ReadFile(producerPath)
		if err != nil {
			t.Fatalf("read qRTS producer fixture %q: %v", producerPath, err)
		}
		producer := decodeRecoverableNewProxyContract(t, "qRTS producer fixture", producerFixture, expectedTags)
		producerByTag = make(map[string]string, len(producer.NewProxyRejects))
		for _, reject := range producer.NewProxyRejects {
			producerByTag[reject.Tag] = reject.WireText
		}
	}

	for _, reject := range contract.NewProxyRejects {
		if producerByTag != nil && producerByTag[reject.Tag] != reject.WireText {
			t.Errorf("qRTS %s wire text drifted: producer=%q Connector=%q", reject.Tag, producerByTag[reject.Tag], reject.WireText)
		}
		if got := proxyStartErrorTag(reject.WireText); got != reject.Tag {
			t.Errorf("proxyStartErrorTag(%q) = %q, want %q", reject.WireText, got, reject.Tag)
		}
		for _, mutated := range []string{
			"start error: " + reject.WireText,
			" " + reject.WireText,
			strings.Replace(reject.WireText, ": ", ":", 1),
			strings.ToUpper(reject.Tag) + strings.TrimPrefix(reject.WireText, reject.Tag),
		} {
			if proxyStartErrorTag(mutated) == reject.Tag {
				t.Errorf("proxyStartErrorTag(%q) accepted off-contract framing for %q", mutated, reject.Tag)
			}
		}
	}
}

func decodeRecoverableNewProxyContract(t *testing.T, source string, fixture []byte, expectedTags map[string]struct{}) qrtsRecoverableNewProxyContract {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(fixture))
	decoder.DisallowUnknownFields()
	var contract qrtsRecoverableNewProxyContract
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("decode %s: %v", source, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("decode %s: expected one JSON value, got trailing content: %v", source, err)
	}
	if contract.SchemaVersion != 1 {
		t.Fatalf("%s schema_version = %d, want 1", source, contract.SchemaVersion)
	}
	if len(contract.NewProxyRejects) != len(expectedTags) {
		t.Fatalf("%s has %d NewProxy rejects, want exactly %d", source, len(contract.NewProxyRejects), len(expectedTags))
	}
	seen := make(map[string]struct{}, len(contract.NewProxyRejects))
	for index, reject := range contract.NewProxyRejects {
		if _, ok := expectedTags[reject.Tag]; !ok {
			t.Fatalf("%s new_proxy_rejects[%d].tag = %q, want a supported admission-rotation tag", source, index, reject.Tag)
		}
		if _, duplicate := seen[reject.Tag]; duplicate {
			t.Fatalf("%s repeats NewProxy reject tag %q", source, reject.Tag)
		}
		seen[reject.Tag] = struct{}{}
		if reject.WireText == "" || reject.WireText != strings.TrimSpace(reject.WireText) || !strings.HasPrefix(reject.WireText, reject.Tag+": ") {
			t.Fatalf("%s NewProxy reject %q has noncanonical wire_text %q", source, reject.Tag, reject.WireText)
		}
	}
	return contract
}

func decodeKnockTokenLoginContract(t *testing.T, source string, fixture []byte) qrtsKnockTokenLoginContract {
	t.Helper()

	// Strict by design: unknown fields, schema bumps, and trailing content
	// all require a coordinated Connector/qRTS update instead of slipping
	// through as nominally backward-compatible metadata.
	decoder := json.NewDecoder(bytes.NewReader(fixture))
	decoder.DisallowUnknownFields()
	var contract qrtsKnockTokenLoginContract
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("decode %s: %v", source, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("decode %s: expected one JSON value, got trailing content: %v", source, err)
	}
	if contract.SchemaVersion != 1 {
		t.Fatalf("%s schema_version = %d, want 1", source, contract.SchemaVersion)
	}
	for name, value := range map[string]string{
		"login_metas_key": contract.LoginMetasKey,
		"reject_tag":      contract.RejectTag,
	} {
		if value == "" || value != strings.TrimSpace(value) || value != strings.ToLower(value) {
			t.Fatalf("%s %s = %q, want non-empty lowercase with no padding", source, name, value)
		}
		if strings.ContainsAny(value, " \t") {
			t.Fatalf("%s %s = %q, want no internal whitespace", source, name, value)
		}
	}
	if len(contract.ClientNeedles) == 0 {
		t.Fatalf("%s has no client_needles", source)
	}
	seenNeedles := make(map[string]struct{}, len(contract.ClientNeedles))
	for i, needle := range contract.ClientNeedles {
		// IsTokenLoginError lowercases the message before scanning, so a
		// needle with an uppercase byte can never match anything.
		if needle == "" || needle != strings.TrimSpace(needle) || needle != strings.ToLower(needle) {
			t.Fatalf("%s client_needles[%d] = %q, want non-empty lowercase with no padding", source, i, needle)
		}
		if _, duplicate := seenNeedles[needle]; duplicate {
			t.Fatalf("%s repeats client needle %q", source, needle)
		}
		seenNeedles[needle] = struct{}{}
	}
	if len(contract.LoginRejectWireTexts) == 0 {
		t.Fatalf("%s has no login_reject_wire_texts", source)
	}
	seenWireTexts := make(map[string]struct{}, len(contract.LoginRejectWireTexts))
	for i, wireText := range contract.LoginRejectWireTexts {
		if wireText == "" || wireText != strings.TrimSpace(wireText) {
			t.Fatalf("%s login_reject_wire_texts[%d] = %q, want non-empty with no padding", source, i, wireText)
		}
		if !strings.HasPrefix(wireText, contract.RejectTag+": ") {
			t.Fatalf("%s login_reject_wire_texts[%d] = %q, want exact reject_tag %q followed by colon-space",
				source, i, wireText, contract.RejectTag)
		}
		if strings.TrimSpace(strings.TrimPrefix(wireText, contract.RejectTag+": ")) == "" {
			t.Fatalf("%s login_reject_wire_texts[%d] = %q, want a non-empty detail after the tag", source, i, wireText)
		}
		if _, duplicate := seenWireTexts[wireText]; duplicate {
			t.Fatalf("%s repeats wire text %q", source, wireText)
		}
		seenWireTexts[wireText] = struct{}{}
	}
	return contract
}
