package proofprovenance

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/version"
)

type operationalTestFixture struct {
	hub         qurl.HubBootstrap
	cellKeys    map[string]string
	manifest    operationalDeploymentManifest
	manifestRaw []byte
	outputPath  string
}

func newOperationalTestFixture(t *testing.T) operationalTestFixture {
	t.Helper()
	hubKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	cell0Key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	cell1Key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, 32))
	hub := qurl.HubBootstrap{
		Host: "hub.nhp.example.com", Port: 443, ServerPublicKeyB64: hubKey,
	}
	hubEndpoint, err := operationalEndpointFromHub(hub)
	if err != nil {
		t.Fatal(err)
	}
	cell0SHA, err := publicKeySHA256(cell0Key)
	if err != nil {
		t.Fatal(err)
	}
	cell1SHA, err := publicKeySHA256(cell1Key)
	if err != nil {
		t.Fatal(err)
	}
	manifest := operationalDeploymentManifest{
		Hub: hubEndpoint,
		Cells: []operationalCell{
			{
				CellID: "cell0",
				operationalEndpoint: operationalEndpoint{
					Host: "cell0.nhp.example.com", Port: 443,
					ServerPublicKeySHA256: cell0SHA,
				},
			},
			{
				CellID: "cell1",
				operationalEndpoint: operationalEndpoint{
					Host: "cell1.nhp.example.com", Port: 443,
					ServerPublicKeySHA256: cell1SHA,
				},
			},
		},
	}
	manifest.Repositories.QURLConnector = strings.Repeat("a", 40)
	manifestRaw, err := json.Marshal(struct {
		SchemaVersion int                 `json:"schema_version"`
		Repositories  any                 `json:"repositories"`
		Hub           operationalEndpoint `json:"hub"`
		Cells         []operationalCell   `json:"cells"`
		Phase         string              `json:"phase"`
		Images        map[string]string   `json:"images"`
	}{
		SchemaVersion: 1,
		Repositories:  manifest.Repositories,
		Hub:           manifest.Hub,
		Cells:         manifest.Cells,
		Phase:         "pre_removal",
		Images:        map[string]string{"qurl_connector": "sha256:" + strings.Repeat("f", 64)},
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "deployment.json")
	if err := os.WriteFile(manifestPath, manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "operational.json")
	t.Setenv(envStrictProof, "true")
	t.Setenv(envStrictOperationalProvenancePath, outputPath)
	t.Setenv(envProofExpectedSHA, manifest.Repositories.QURLConnector)
	t.Setenv(envDeploymentManifestPath, manifestPath)
	t.Setenv(envDeploymentManifestSHA256, sha256Hex(manifestRaw))
	t.Setenv(envTypedEvidenceContractSHA256, strings.Repeat("b", 64))
	previousCommit := version.GitCommit
	version.GitCommit = manifest.Repositories.QURLConnector
	t.Cleanup(func() { version.GitCommit = previousCommit })
	return operationalTestFixture{
		hub:         hub,
		cellKeys:    map[string]string{"cell0": cell0Key, "cell1": cell1Key},
		manifest:    manifest,
		manifestRaw: manifestRaw,
		outputPath:  outputPath,
	}
}

func (fixture operationalTestFixture) binding(cellID string, generation, revision int64, lease time.Time) *qurl.AgentRuntimeBinding {
	cell := fixture.manifest.Cells[0]
	if cellID == "cell1" {
		cell = fixture.manifest.Cells[1]
	}
	return &qurl.AgentRuntimeBinding{
		AgentID:              "agent-proof-01",
		CellID:               cellID,
		AssignmentGeneration: generation,
		EndpointRevision:     revision,
		LeaseExpiresAt:       lease,
		NHPUDPEndpoint: qurl.NHPUDPEndpoint{
			Host:               cell.Host,
			Port:               cell.Port,
			ServerPublicKeyB64: fixture.cellKeys[cellID],
		},
	}
}

func readOperationalTestProvenance(t *testing.T, path string) operationalProvenance {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var provenance operationalProvenance
	if err := decodeJSONWithUniqueKeys(raw, &provenance, true); err != nil {
		t.Fatal(err)
	}
	return provenance
}

func TestStrictOperationalProvenancePublishesOnlyRealOrderedBindings(t *testing.T) {
	fixture := newOperationalTestFixture(t)
	lease := time.Date(2026, 7, 24, 1, 2, 3, 456000000, time.UTC)
	parentInfo, err := os.Lstat(filepath.Dir(fixture.outputPath))
	if err != nil {
		t.Fatal(err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode().Perm() != 0o700 {
		t.Fatalf("operational provenance parent mode = %v, want real directory 0700", parentInfo.Mode())
	}

	if err := Record(
		fixture.hub,
		fixture.binding("cell0", 1, 1, lease),
		BoundaryRegistration,
	); err != nil {
		t.Fatalf("record registration: %v", err)
	}
	if err := Record(
		fixture.hub,
		fixture.binding("cell0", 1, 1, lease),
		BoundaryWarmOpen,
	); err != nil {
		t.Fatalf("record warm open: %v", err)
	}
	if err := Record(
		fixture.hub,
		fixture.binding("cell1", 2, 2, lease.Add(time.Hour)),
		BoundaryAssignmentRefresh,
	); err != nil {
		t.Fatalf("record reassignment: %v", err)
	}
	if err := Record(
		fixture.hub,
		fixture.binding("cell1", 2, 3, lease.Add(2*time.Hour)),
		BoundaryAssignmentRefresh,
	); err != nil {
		t.Fatalf("record refresh: %v", err)
	}

	provenance := readOperationalTestProvenance(t, fixture.outputPath)
	if provenance.SchemaVersion != 2 ||
		provenance.AgentID != "agent-proof-01" ||
		provenance.ConnectorSHA != strings.Repeat("a", 40) ||
		provenance.DeploymentManifestSHA256 != sha256Hex(fixture.manifestRaw) ||
		provenance.TypedEvidenceContractSHA256 != strings.Repeat("b", 64) {
		t.Fatalf("identity binding = %#v", provenance)
	}
	gotPhases := make([]string, 0, len(provenance.Observations))
	for _, observation := range provenance.Observations {
		gotPhases = append(gotPhases, observation.Phase)
	}
	if strings.Join(gotPhases, ",") != "registration,warm_open,reassignment,refresh" {
		t.Fatalf("phases = %v", gotPhases)
	}
	raw, err := os.ReadFile(fixture.outputPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"private_key", "device_credential", "api_key", "otp", "lv_live_",
		fixture.cellKeys["cell0"], fixture.hub.ServerPublicKeyB64,
	} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("operational provenance contains forbidden material %q", forbidden)
		}
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(fixture.outputPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("operational provenance mode = %#o, want 0600", got)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(fixture.outputPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("atomic publication left temporary file %q", entry.Name())
		}
	}
}

func TestStrictOperationalProvenanceFailsClosedOnSyntheticOrOutOfOrderBindings(t *testing.T) {
	fixture := newOperationalTestFixture(t)
	lease := time.Date(2026, 7, 24, 1, 2, 3, 0, time.UTC)

	if err := Record(
		fixture.hub,
		fixture.binding("cell0", 1, 1, lease),
		BoundaryWarmOpen,
	); err == nil || !strings.Contains(err.Error(), "does not follow registration") {
		t.Fatalf("out-of-order warm open error = %v", err)
	}
	if _, err := os.Stat(fixture.outputPath); !os.IsNotExist(err) {
		t.Fatalf("out-of-order boundary created output: %v", err)
	}

	if err := Record(
		fixture.hub,
		fixture.binding("cell0", 1, 1, lease),
		BoundaryRegistration,
	); err != nil {
		t.Fatal(err)
	}
	if err := Record(
		fixture.hub,
		fixture.binding("cell0", 1, 2, lease),
		BoundaryWarmOpen,
	); err == nil || !strings.Contains(err.Error(), "does not exactly match") {
		t.Fatalf("drifted warm-open error = %v", err)
	}
	if got := len(readOperationalTestProvenance(t, fixture.outputPath).Observations); got != 1 {
		t.Fatalf("failed warm open changed observation count to %d", got)
	}

	if err := Record(
		fixture.hub,
		fixture.binding("cell0", 1, 1, lease),
		BoundaryWarmOpen,
	); err != nil {
		t.Fatal(err)
	}
	if err := Record(
		fixture.hub,
		fixture.binding("cell0", 2, 2, lease.Add(time.Hour)),
		BoundaryAssignmentRefresh,
	); err == nil || !strings.Contains(err.Error(), "different-cell reassignment") {
		t.Fatalf("same-cell reassignment error = %v", err)
	}
	if got := len(readOperationalTestProvenance(t, fixture.outputPath).Observations); got != 2 {
		t.Fatalf("failed reassignment changed observation count to %d", got)
	}
	if err := Record(
		fixture.hub,
		fixture.binding("cell1", 2, 2, lease.Add(time.Hour)),
		BoundaryAssignmentRefresh,
	); err != nil {
		t.Fatal(err)
	}
	if err := Record(
		fixture.hub,
		fixture.binding("cell1", 2, 3, lease.Add(30*time.Minute)),
		BoundaryAssignmentRefresh,
	); err == nil || !strings.Contains(err.Error(), "did not remain") {
		t.Fatalf("regressed refresh lease error = %v", err)
	}
	if got := len(readOperationalTestProvenance(t, fixture.outputPath).Observations); got != 3 {
		t.Fatalf("failed refresh changed observation count to %d", got)
	}
}

func TestStrictOperationalProvenanceRejectsTamperedInputs(t *testing.T) {
	fixture := newOperationalTestFixture(t)
	lease := time.Date(2026, 7, 24, 1, 2, 3, 0, time.UTC)
	binding := fixture.binding("cell0", 1, 1, lease)

	t.Run("manifest digest", func(t *testing.T) {
		t.Setenv(envDeploymentManifestSHA256, strings.Repeat("c", 64))
		err := Record(fixture.hub, binding, BoundaryRegistration)
		if err == nil || !strings.Contains(err.Error(), "deployment manifest digest") {
			t.Fatalf("error = %v", err)
		}
	})

	if err := Record(
		fixture.hub, binding, BoundaryRegistration,
	); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(fixture.outputPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(raw, []byte(`"agent_id"`), []byte(`"agent_id":"duplicate","agent_id"`), 1)
	if err := os.WriteFile(fixture.outputPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	err = Record(fixture.hub, binding, BoundaryWarmOpen)
	if err == nil || !strings.Contains(err.Error(), "duplicate JSON key") {
		t.Fatalf("duplicate-key error = %v", err)
	}
}

func TestStrictOperationalProvenanceIsDisabledOutsideExactStrictMode(t *testing.T) {
	t.Setenv(envStrictProof, "false")
	if err := Record(
		qurl.HubBootstrap{},
		nil,
		BoundaryRegistration,
	); err != nil {
		t.Fatalf("non-strict recorder = %v", err)
	}
	t.Setenv(envStrictProof, "true")
	if err := Record(
		qurl.HubBootstrap{},
		nil,
		BoundaryRegistration,
	); err != nil {
		t.Fatalf("strict recorder without explicit output path = %v", err)
	}
	t.Setenv(envStrictOperationalProvenancePath, filepath.Join(t.TempDir(), "operational.json"))
	t.Setenv(envStrictProof, "TRUE")
	if err := Record(
		qurl.HubBootstrap{},
		nil,
		BoundaryRegistration,
	); err == nil || !strings.Contains(err.Error(), "exactly true or false") {
		t.Fatalf("invalid strict mode error = %v", err)
	}
}

func TestStrictOperationalProvenanceRejectsPathCollisionAndInvalidAgentID(t *testing.T) {
	t.Run("deployment manifest path collision", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		manifestPath := os.Getenv(envDeploymentManifestPath)
		t.Setenv(
			envStrictOperationalProvenancePath,
			filepath.Join(filepath.Dir(manifestPath), ".", filepath.Base(manifestPath)),
		)
		before, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		err = Record(
			fixture.hub,
			fixture.binding("cell0", 1, 1, time.Now().UTC().Add(time.Hour)),
			BoundaryRegistration,
		)
		if err == nil || !strings.Contains(err.Error(), "must differ") {
			t.Fatalf("path collision error = %v", err)
		}
		after, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, before) {
			t.Fatal("path collision modified the deployment manifest")
		}
	})

	t.Run("agent identity", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		binding := fixture.binding("cell0", 1, 1, time.Now().UTC().Add(time.Hour))
		binding.AgentID = "Agent_not-canonical"
		err := Record(fixture.hub, binding, BoundaryRegistration)
		if err == nil || !strings.Contains(err.Error(), "non-canonical agent identity") {
			t.Fatalf("invalid agent id error = %v", err)
		}
		if _, err := os.Stat(fixture.outputPath); !os.IsNotExist(err) {
			t.Fatalf("invalid agent id created provenance: %v", err)
		}
	})

	t.Run("non-exact JSON counter", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		binding := fixture.binding("cell0", maxExactJSONInteger+1, 1, time.Now().UTC().Add(time.Hour))
		err := Record(fixture.hub, binding, BoundaryRegistration)
		if err == nil || !strings.Contains(err.Error(), "exact JSON integers") {
			t.Fatalf("oversized generation error = %v", err)
		}
		if _, err := os.Stat(fixture.outputPath); !os.IsNotExist(err) {
			t.Fatalf("oversized generation created provenance: %v", err)
		}
	})
}

func TestStrictOperationalProvenanceRejectsInvalidHubIdentity(t *testing.T) {
	fixture := newOperationalTestFixture(t)
	lease := time.Date(2026, 7, 24, 1, 2, 3, 0, time.UTC)
	binding := fixture.binding("cell0", 1, 1, lease)

	cases := []struct {
		name    string
		mutate  func(hub *qurl.HubBootstrap)
		wantErr string
	}{
		{
			name:    "malformed key",
			mutate:  func(hub *qurl.HubBootstrap) { hub.ServerPublicKeyB64 = "!!not-base64!!" },
			wantErr: "server public key must be canonical base64 for exactly 32 bytes",
		},
		{
			name: "short key",
			mutate: func(hub *qurl.HubBootstrap) {
				hub.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 16))
			},
			wantErr: "server public key must be canonical base64 for exactly 32 bytes",
		},
		{
			name:    "empty host",
			mutate:  func(hub *qurl.HubBootstrap) { hub.Host = "" },
			wantErr: "Hub endpoint is invalid",
		},
		{
			name:    "port zero",
			mutate:  func(hub *qurl.HubBootstrap) { hub.Port = 0 },
			wantErr: "Hub endpoint is invalid",
		},
		{
			name:    "port too high",
			mutate:  func(hub *qurl.HubBootstrap) { hub.Port = 70000 },
			wantErr: "Hub endpoint is invalid",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			hub := fixture.hub
			testCase.mutate(&hub)
			err := Record(hub, binding, BoundaryRegistration)
			if err == nil || !strings.Contains(err.Error(), "validate Hub identity") ||
				!strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("invalid Hub error = %v, want %q", err, testCase.wantErr)
			}
			if _, statErr := os.Stat(fixture.outputPath); !os.IsNotExist(statErr) {
				t.Fatalf("invalid Hub created provenance: %v", statErr)
			}
		})
	}
}

func TestStrictOperationalProvenanceRequiresExactlyOneManifestCellMatch(t *testing.T) {
	lease := time.Date(2026, 7, 24, 1, 2, 3, 0, time.UTC)

	t.Run("tuple mismatch", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		binding := fixture.binding("cell0", 1, 1, lease)
		binding.NHPUDPEndpoint.Host = "cell1.nhp.example.com"
		err := Record(fixture.hub, binding, BoundaryRegistration)
		if err == nil || !strings.Contains(err.Error(), "validate runtime assignment") ||
			!strings.Contains(err.Error(), "assigned-cell tuple does not match the deployment manifest") {
			t.Fatalf("mismatched tuple error = %v", err)
		}
		if _, statErr := os.Stat(fixture.outputPath); !os.IsNotExist(statErr) {
			t.Fatalf("mismatched tuple created provenance: %v", statErr)
		}
	})

	t.Run("absent cell", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		binding := fixture.binding("cell0", 1, 1, lease)
		binding.CellID = "cell9"
		err := Record(fixture.hub, binding, BoundaryRegistration)
		if err == nil || !strings.Contains(err.Error(), "assigned cell is absent or duplicated in the deployment manifest") {
			t.Fatalf("absent cell error = %v", err)
		}
		if _, statErr := os.Stat(fixture.outputPath); !os.IsNotExist(statErr) {
			t.Fatalf("absent cell created provenance: %v", statErr)
		}
	})

	t.Run("binding key not canonical", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		binding := fixture.binding("cell0", 1, 1, lease)
		binding.NHPUDPEndpoint.ServerPublicKeyB64 = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 16))
		err := Record(fixture.hub, binding, BoundaryRegistration)
		if err == nil || !strings.Contains(err.Error(), "validate assigned-cell identity") ||
			!strings.Contains(err.Error(), "server public key must be canonical base64 for exactly 32 bytes") {
			t.Fatalf("invalid binding key error = %v", err)
		}
		if _, statErr := os.Stat(fixture.outputPath); !os.IsNotExist(statErr) {
			t.Fatalf("invalid binding key created provenance: %v", statErr)
		}
	})

	t.Run("duplicated cell", func(t *testing.T) {
		fixture := newOperationalTestFixture(t)
		duplicated := fixture.manifest
		duplicated.Cells = []operationalCell{fixture.manifest.Cells[0], fixture.manifest.Cells[0]}
		raw, err := json.Marshal(duplicated)
		if err != nil {
			t.Fatal(err)
		}
		duplicatedPath := filepath.Join(filepath.Dir(fixture.outputPath), "deployment-duplicated.json")
		if err := os.WriteFile(duplicatedPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv(envDeploymentManifestPath, duplicatedPath)
		t.Setenv(envDeploymentManifestSHA256, sha256Hex(raw))

		err = Record(fixture.hub, fixture.binding("cell0", 1, 1, lease), BoundaryRegistration)
		if err == nil || !strings.Contains(err.Error(), "assigned cell is absent or duplicated in the deployment manifest") {
			t.Fatalf("duplicated cell error = %v", err)
		}
		if _, statErr := os.Stat(fixture.outputPath); !os.IsNotExist(statErr) {
			t.Fatalf("duplicated cell created provenance: %v", statErr)
		}
	})
}

// recordOperationalTestBoundaries drives the first count entries of the
// canonical four-boundary sequence through the production Record path so
// mutation tests start from a genuinely published sidecar.
func recordOperationalTestBoundaries(t *testing.T, fixture operationalTestFixture, lease time.Time, count int) {
	t.Helper()
	steps := []struct {
		binding  *qurl.AgentRuntimeBinding
		boundary Boundary
	}{
		{fixture.binding("cell0", 1, 1, lease), BoundaryRegistration},
		{fixture.binding("cell0", 1, 1, lease), BoundaryWarmOpen},
		{fixture.binding("cell1", 2, 2, lease.Add(time.Hour)), BoundaryAssignmentRefresh},
		{fixture.binding("cell1", 2, 3, lease.Add(2*time.Hour)), BoundaryAssignmentRefresh},
	}
	for index := 0; index < count; index++ {
		if err := Record(fixture.hub, steps[index].binding, steps[index].boundary); err != nil {
			t.Fatalf("record boundary %d: %v", index, err)
		}
	}
}

func rewriteOperationalTestProvenance(t *testing.T, path string, mutate func(provenance *operationalProvenance)) {
	t.Helper()
	provenance := readOperationalTestProvenance(t, path)
	mutate(&provenance)
	encoded, err := json.Marshal(provenance)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStrictOperationalProvenanceRejectsMutatedExistingSidecar(t *testing.T) {
	lease := time.Date(2026, 7, 24, 1, 2, 3, 0, time.UTC)
	cases := []struct {
		name       string
		boundaries int
		mutate     func(provenance *operationalProvenance)
		wantErr    string
	}{
		{
			name:       "schema version",
			boundaries: 1,
			mutate:     func(provenance *operationalProvenance) { provenance.SchemaVersion = 1 },
			wantErr:    "identity binding changed",
		},
		{
			name:       "connector sha",
			boundaries: 1,
			mutate:     func(provenance *operationalProvenance) { provenance.ConnectorSHA = strings.Repeat("d", 40) },
			wantErr:    "identity binding changed",
		},
		{
			name:       "agent id",
			boundaries: 1,
			mutate:     func(provenance *operationalProvenance) { provenance.AgentID = "agent-proof-99" },
			wantErr:    "identity binding changed",
		},
		{
			name:       "deployment manifest sha",
			boundaries: 1,
			mutate: func(provenance *operationalProvenance) {
				provenance.DeploymentManifestSHA256 = strings.Repeat("d", 64)
			},
			wantErr: "identity binding changed",
		},
		{
			name:       "typed evidence contract sha",
			boundaries: 1,
			mutate: func(provenance *operationalProvenance) {
				provenance.TypedEvidenceContractSHA256 = strings.Repeat("d", 64)
			},
			wantErr: "identity binding changed",
		},
		{
			name:       "hub port",
			boundaries: 1,
			mutate:     func(provenance *operationalProvenance) { provenance.Hub.Port = 8443 },
			wantErr:    "identity binding changed",
		},
		{
			name:       "empty observations",
			boundaries: 1,
			mutate:     func(provenance *operationalProvenance) { provenance.Observations = nil },
			wantErr:    "invalid observation count",
		},
		{
			name:       "five observations",
			boundaries: 4,
			mutate: func(provenance *operationalProvenance) {
				provenance.Observations = append(provenance.Observations, provenance.Observations[3])
			},
			wantErr: "invalid observation count",
		},
		{
			name:       "duplicated registration phase",
			boundaries: 1,
			mutate: func(provenance *operationalProvenance) {
				provenance.Observations = append(provenance.Observations, provenance.Observations[0])
			},
			wantErr: `observation 1 phase is "registration", want "warm_open"`,
		},
		{
			name:       "observation cell host",
			boundaries: 1,
			mutate:     func(provenance *operationalProvenance) { provenance.Observations[0].Host = "cell9.nhp.example.com" },
			wantErr:    "assigned-cell tuple does not match the deployment manifest",
		},
		{
			name:       "observation port",
			boundaries: 1,
			mutate:     func(provenance *operationalProvenance) { provenance.Observations[0].Port = 8443 },
			wantErr:    "assigned-cell tuple does not match the deployment manifest",
		},
		{
			name:       "observation key sha",
			boundaries: 1,
			mutate: func(provenance *operationalProvenance) {
				provenance.Observations[0].ServerPublicKeySHA256 = strings.Repeat("d", 64)
			},
			wantErr: "assigned-cell tuple does not match the deployment manifest",
		},
		{
			name:       "observation port out of range",
			boundaries: 1,
			mutate:     func(provenance *operationalProvenance) { provenance.Observations[0].Port = 0 },
			wantErr:    "assigned-cell tuple is invalid",
		},
		{
			name:       "observation lease not canonical UTC",
			boundaries: 1,
			mutate: func(provenance *operationalProvenance) {
				provenance.Observations[0].LeaseExpiresAt = "2026-07-24T01:02:03+02:00"
			},
			wantErr: "assignment lease expiry is not canonical UTC RFC3339",
		},
		{
			name:       "warm open revision drift",
			boundaries: 2,
			mutate:     func(provenance *operationalProvenance) { provenance.Observations[1].EndpointRevision = 9 },
			wantErr:    "warm-open assignment does not exactly match registration",
		},
		{
			name:       "reassignment generation not newer",
			boundaries: 3,
			mutate:     func(provenance *operationalProvenance) { provenance.Observations[2].AssignmentGeneration = 1 },
			wantErr:    "reassignment is not a newer different-cell assignment",
		},
		{
			name:       "refresh revision regressed",
			boundaries: 4,
			mutate:     func(provenance *operationalProvenance) { provenance.Observations[3].EndpointRevision = 1 },
			wantErr:    "refresh did not remain on the reassigned tuple",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newOperationalTestFixture(t)
			recordOperationalTestBoundaries(t, fixture, lease, testCase.boundaries)
			rewriteOperationalTestProvenance(t, fixture.outputPath, testCase.mutate)
			before, err := os.ReadFile(fixture.outputPath)
			if err != nil {
				t.Fatal(err)
			}

			// The boundary argument is irrelevant here: validation of the
			// existing sidecar precedes every append decision, so a valid
			// follow-up binding is enough to reach the branch under test.
			err = Record(
				fixture.hub,
				fixture.binding("cell1", 2, 3, lease.Add(2*time.Hour)),
				BoundaryAssignmentRefresh,
			)
			if err == nil || !strings.Contains(err.Error(), "validate existing operational provenance") ||
				!strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("mutated sidecar error = %v, want %q", err, testCase.wantErr)
			}
			after, err := os.ReadFile(fixture.outputPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, before) {
				t.Fatal("rejected Record modified the operational provenance file")
			}
		})
	}
}
