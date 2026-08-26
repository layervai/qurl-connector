package proofprovenance

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/internal/atomicfile"
	"github.com/layervai/qurl-connector/pkg/version"
)

const (
	envStrictProof                           = "QURL_CONNECTOR_STRICT_PROOF"
	envStrictOperationalProvenancePath       = "QURL_CONNECTOR_STRICT_OPERATIONAL_PROVENANCE_PATH"
	envProofExpectedSHA                      = "QURL_CONNECTOR_PROOF_EXPECTED_SHA"
	envDeploymentManifestPath                = "QURL_CONNECTOR_DEPLOYMENT_MANIFEST_PATH"
	envDeploymentManifestSHA256              = "QURL_CONNECTOR_DEPLOYMENT_MANIFEST_SHA256"
	envTypedEvidenceContractSHA256           = "QURL_CONNECTOR_TYPED_EVIDENCE_CONTRACT_SHA256"
	maxDeploymentManifestBytes         int64 = 1 << 20
	maxOperationalProvenanceBytes      int64 = 64 << 10
	maxExactJSONInteger                int64 = 9_007_199_254_740_991
)

var lowercaseSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var lowercaseGitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Boundary identifies the real qurl-go lifecycle result being observed.
type Boundary uint8

const (
	BoundaryRegistration Boundary = iota + 1
	BoundaryWarmOpen
	BoundaryAssignmentRefresh
)

type operationalEndpoint struct {
	Host                  string `json:"host"`
	Port                  int    `json:"port"`
	ServerPublicKeySHA256 string `json:"server_public_key_sha256"`
}

type operationalCell struct {
	CellID string `json:"cell_id"`
	operationalEndpoint
}

type operationalObservation struct {
	AssignmentGeneration  int64  `json:"assignment_generation"`
	CellID                string `json:"cell_id"`
	EndpointRevision      int64  `json:"endpoint_revision"`
	Host                  string `json:"host"`
	LeaseExpiresAt        string `json:"lease_expires_at"`
	Phase                 string `json:"phase"`
	Port                  int    `json:"port"`
	ServerPublicKeySHA256 string `json:"server_public_key_sha256"`
}

type operationalProvenance struct {
	SchemaVersion               int                      `json:"schema_version"`
	AgentID                     string                   `json:"agent_id"`
	ConnectorSHA                string                   `json:"connector_sha"`
	DeploymentManifestSHA256    string                   `json:"deployment_manifest_sha256"`
	TypedEvidenceContractSHA256 string                   `json:"typed_evidence_contract_sha256"`
	Hub                         operationalEndpoint      `json:"hub"`
	Observations                []operationalObservation `json:"observations"`
}

type operationalDeploymentManifest struct {
	Repositories struct {
		QURLConnector string `json:"qurl_connector"`
	} `json:"repositories"`
	Hub   operationalEndpoint `json:"hub"`
	Cells []operationalCell   `json:"cells"`
}

// Record is an attended-proof-only producer. It never
// invents assignment state: every observation comes from a validated qurl-go
// runtime binding returned by registration, warm open, or authenticated refresh.
// Ordinary customer runs do not create the sidecar.
func Record(hub qurl.HubBootstrap, binding *qurl.AgentRuntimeBinding, boundary Boundary) error {
	outputPath := os.Getenv(envStrictOperationalProvenancePath)
	if outputPath == "" {
		return nil
	}
	switch os.Getenv(envStrictProof) {
	case "", "false":
		return nil
	case "true":
	default:
		return fmt.Errorf("%s must be exactly true or false", envStrictProof)
	}
	if binding == nil {
		return errors.New("qurl-go returned no runtime binding")
	}
	if err := validatePrivateOutputParent(outputPath); err != nil {
		return fmt.Errorf("validate operational provenance parent: %w", err)
	}

	manifestPath := os.Getenv(envDeploymentManifestPath)
	samePath, err := sameCleanPath(outputPath, manifestPath)
	if err != nil {
		return fmt.Errorf("resolve proof paths: %w", err)
	}
	if samePath {
		return errors.New("operational provenance path must differ from deployment manifest path")
	}
	connectorSHA := os.Getenv(envProofExpectedSHA)
	if !lowercaseGitSHAPattern.MatchString(connectorSHA) {
		return fmt.Errorf("%s must be an exact lowercase Git SHA", envProofExpectedSHA)
	}
	if version.GitCommit != connectorSHA {
		return fmt.Errorf("running Connector commit %q does not match %s", version.GitCommit, envProofExpectedSHA)
	}
	deploymentSHA := os.Getenv(envDeploymentManifestSHA256)
	if !lowercaseSHA256Pattern.MatchString(deploymentSHA) {
		return fmt.Errorf("%s must be an exact lowercase SHA-256", envDeploymentManifestSHA256)
	}
	typedEvidenceSHA := os.Getenv(envTypedEvidenceContractSHA256)
	if !lowercaseSHA256Pattern.MatchString(typedEvidenceSHA) {
		return fmt.Errorf("%s must be an exact lowercase SHA-256", envTypedEvidenceContractSHA256)
	}
	if !validAgentID(binding.AgentID) {
		return errors.New("runtime binding has a non-canonical agent identity")
	}

	manifestBytes, err := readRegularFileBounded(
		manifestPath,
		maxDeploymentManifestBytes,
	)
	if err != nil {
		return fmt.Errorf("read deployment manifest: %w", err)
	}
	actualDeploymentSHA := sha256Hex(manifestBytes)
	if actualDeploymentSHA != deploymentSHA {
		return fmt.Errorf("deployment manifest digest is %s, want %s", actualDeploymentSHA, deploymentSHA)
	}
	var manifest operationalDeploymentManifest
	if err := decodeJSONWithUniqueKeys(manifestBytes, &manifest, false); err != nil {
		return fmt.Errorf("decode deployment manifest: %w", err)
	}
	if manifest.Repositories.QURLConnector != connectorSHA {
		return fmt.Errorf("deployment manifest Connector commit is %q, want %s", manifest.Repositories.QURLConnector, connectorSHA)
	}

	hubEndpoint, err := operationalEndpointFromHub(hub)
	if err != nil {
		return fmt.Errorf("validate Hub identity: %w", err)
	}
	if hubEndpoint != manifest.Hub {
		return errors.New("runtime Hub does not match the deployment manifest")
	}
	observation, err := operationalObservationFromBinding(binding, manifest.Cells)
	if err != nil {
		return err
	}

	provenance := operationalProvenance{
		SchemaVersion:               2,
		AgentID:                     binding.AgentID,
		ConnectorSHA:                connectorSHA,
		DeploymentManifestSHA256:    deploymentSHA,
		TypedEvidenceContractSHA256: typedEvidenceSHA,
		Hub:                         hubEndpoint,
		Observations:                make([]operationalObservation, 0, 4),
	}
	if _, err := os.Lstat(outputPath); err == nil { //nolint:gosec // G703: the explicit attended-proof output path is the contract; reads are regular-file, identity, size, and JSON checked.
		raw, readErr := readRegularFileBounded(outputPath, maxOperationalProvenanceBytes)
		if readErr != nil {
			return fmt.Errorf("read existing operational provenance: %w", readErr)
		}
		if decodeErr := decodeJSONWithUniqueKeys(raw, &provenance, true); decodeErr != nil {
			return fmt.Errorf("decode existing operational provenance: %w", decodeErr)
		}
		if err := validateExistingOperationalProvenance(
			provenance,
			connectorSHA,
			binding.AgentID,
			deploymentSHA,
			typedEvidenceSHA,
			hubEndpoint,
			manifest.Cells,
		); err != nil {
			return fmt.Errorf("validate existing operational provenance: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("lstat operational provenance: %w", err)
	}

	if err := appendOperationalBoundary(&provenance, observation, boundary); err != nil {
		return err
	}
	encoded, err := json.Marshal(provenance)
	if err != nil {
		return fmt.Errorf("encode operational provenance: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := atomicfile.Write(outputPath, encoded, 0o600); err != nil {
		return fmt.Errorf("publish operational provenance: %w", err)
	}
	return nil
}

func operationalEndpointFromHub(hub qurl.HubBootstrap) (operationalEndpoint, error) {
	keySHA, err := publicKeySHA256(hub.ServerPublicKeyB64)
	if err != nil {
		return operationalEndpoint{}, err
	}
	if hub.Host == "" || hub.Port < 1 || hub.Port > 65535 {
		return operationalEndpoint{}, errors.New("Hub endpoint is invalid")
	}
	return operationalEndpoint{
		Host: hub.Host, Port: hub.Port, ServerPublicKeySHA256: keySHA,
	}, nil
}

func operationalObservationFromBinding(binding *qurl.AgentRuntimeBinding, cells []operationalCell) (operationalObservation, error) {
	keySHA, err := publicKeySHA256(binding.NHPUDPEndpoint.ServerPublicKeyB64)
	if err != nil {
		return operationalObservation{}, fmt.Errorf("validate assigned-cell identity: %w", err)
	}
	observation := operationalObservation{
		AssignmentGeneration:  binding.AssignmentGeneration,
		CellID:                binding.CellID,
		EndpointRevision:      binding.EndpointRevision,
		Host:                  binding.NHPUDPEndpoint.Host,
		LeaseExpiresAt:        binding.LeaseExpiresAt.UTC().Format(time.RFC3339Nano),
		Port:                  binding.NHPUDPEndpoint.Port,
		ServerPublicKeySHA256: keySHA,
	}
	if err := validateOperationalObservation(observation, cells); err != nil {
		return operationalObservation{}, fmt.Errorf("validate runtime assignment: %w", err)
	}
	return observation, nil
}

func validateExistingOperationalProvenance(
	provenance operationalProvenance,
	connectorSHA string,
	agentID string,
	deploymentSHA string,
	typedEvidenceSHA string,
	hub operationalEndpoint,
	cells []operationalCell,
) error {
	if provenance.SchemaVersion != 2 ||
		provenance.ConnectorSHA != connectorSHA ||
		provenance.AgentID != agentID ||
		provenance.DeploymentManifestSHA256 != deploymentSHA ||
		provenance.TypedEvidenceContractSHA256 != typedEvidenceSHA ||
		provenance.Hub != hub {
		return errors.New("operational provenance identity binding changed")
	}
	if len(provenance.Observations) == 0 || len(provenance.Observations) > 4 {
		return errors.New("operational provenance has an invalid observation count")
	}
	phases := []string{"registration", "warm_open", "reassignment", "refresh"}
	for index, observation := range provenance.Observations {
		if observation.Phase != phases[index] {
			return fmt.Errorf("observation %d phase is %q, want %q", index, observation.Phase, phases[index])
		}
		if err := validateOperationalObservation(observation, cells); err != nil {
			return fmt.Errorf("observation %s: %w", observation.Phase, err)
		}
	}
	if len(provenance.Observations) >= 2 &&
		!sameOperationalAssignment(provenance.Observations[0], provenance.Observations[1], true) {
		return errors.New("warm-open assignment does not exactly match registration")
	}
	if len(provenance.Observations) >= 3 {
		warm := provenance.Observations[1]
		reassigned := provenance.Observations[2]
		if reassigned.CellID == warm.CellID ||
			reassigned.AssignmentGeneration <= warm.AssignmentGeneration {
			return errors.New("reassignment is not a newer different-cell assignment")
		}
	}
	if len(provenance.Observations) == 4 {
		reassigned := provenance.Observations[2]
		refreshed := provenance.Observations[3]
		if !sameOperationalAssignment(reassigned, refreshed, false) ||
			refreshed.EndpointRevision < reassigned.EndpointRevision ||
			operationalLeaseBefore(refreshed, reassigned) {
			return errors.New("refresh did not remain on the reassigned tuple")
		}
	}
	return nil
}

func validateOperationalObservation(observation operationalObservation, cells []operationalCell) error {
	if observation.AssignmentGeneration < 1 ||
		observation.AssignmentGeneration > maxExactJSONInteger ||
		observation.EndpointRevision < 1 ||
		observation.EndpointRevision > maxExactJSONInteger {
		return errors.New("assignment generation and endpoint revision must be positive exact JSON integers")
	}
	if observation.CellID == "" || observation.Host == "" ||
		observation.Port < 1 || observation.Port > 65535 ||
		!lowercaseSHA256Pattern.MatchString(observation.ServerPublicKeySHA256) {
		return errors.New("assigned-cell tuple is invalid")
	}
	lease, err := time.Parse(time.RFC3339Nano, observation.LeaseExpiresAt)
	if err != nil || lease.Location() != time.UTC {
		return errors.New("assignment lease expiry is not canonical UTC RFC3339")
	}
	matches := 0
	for _, cell := range cells {
		if cell.CellID != observation.CellID {
			continue
		}
		matches++
		if cell.Host != observation.Host ||
			cell.Port != observation.Port ||
			cell.ServerPublicKeySHA256 != observation.ServerPublicKeySHA256 {
			return errors.New("assigned-cell tuple does not match the deployment manifest")
		}
	}
	if matches != 1 {
		return errors.New("assigned cell is absent or duplicated in the deployment manifest")
	}
	return nil
}

func appendOperationalBoundary(provenance *operationalProvenance, observation operationalObservation, boundary Boundary) error {
	switch boundary {
	case BoundaryRegistration:
		if len(provenance.Observations) != 0 {
			return errors.New("registration observation is not the first boundary")
		}
		observation.Phase = "registration"
	case BoundaryWarmOpen:
		if len(provenance.Observations) != 1 {
			return errors.New("warm-open observation does not follow registration")
		}
		observation.Phase = "warm_open"
		if !sameOperationalAssignment(provenance.Observations[0], observation, true) {
			return errors.New("warm-open assignment does not exactly match registration")
		}
	case BoundaryAssignmentRefresh:
		switch len(provenance.Observations) {
		case 2:
			observation.Phase = "reassignment"
			warm := provenance.Observations[1]
			if observation.CellID == warm.CellID ||
				observation.AssignmentGeneration <= warm.AssignmentGeneration {
				return errors.New("first authenticated refresh is not a newer different-cell reassignment")
			}
		case 3:
			observation.Phase = "refresh"
			reassigned := provenance.Observations[2]
			if !sameOperationalAssignment(reassigned, observation, false) ||
				observation.EndpointRevision < reassigned.EndpointRevision ||
				operationalLeaseBefore(observation, reassigned) {
				return errors.New("second authenticated refresh did not remain on the reassigned tuple")
			}
		default:
			return errors.New("authenticated refresh observation is out of order")
		}
	default:
		return errors.New("unknown operational boundary")
	}
	provenance.Observations = append(provenance.Observations, observation)
	return nil
}

func sameOperationalAssignment(left, right operationalObservation, exact bool) bool {
	if left.AssignmentGeneration != right.AssignmentGeneration ||
		left.CellID != right.CellID ||
		left.Host != right.Host ||
		left.Port != right.Port ||
		left.ServerPublicKeySHA256 != right.ServerPublicKeySHA256 {
		return false
	}
	return !exact ||
		(left.EndpointRevision == right.EndpointRevision &&
			left.LeaseExpiresAt == right.LeaseExpiresAt)
}

func operationalLeaseBefore(left, right operationalObservation) bool {
	leftLease, leftErr := time.Parse(time.RFC3339Nano, left.LeaseExpiresAt)
	rightLease, rightErr := time.Parse(time.RFC3339Nano, right.LeaseExpiresAt)
	return leftErr != nil || rightErr != nil || leftLease.Before(rightLease)
}

func publicKeySHA256(value string) (string, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != 32 {
		return "", errors.New("server public key must be canonical base64 for exactly 32 bytes")
	}
	return sha256Hex(key), nil
}

func validAgentID(value string) bool {
	if len(value) < 2 || len(value) > 64 {
		return false
	}
	for index, character := range []byte(value) {
		lowerAlphaNumeric := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9'
		if index == 0 || index == len(value)-1 {
			if !lowerAlphaNumeric {
				return false
			}
			continue
		}
		if !lowerAlphaNumeric && character != '-' {
			return false
		}
	}
	return true
}

func sameCleanPath(left, right string) (bool, error) {
	if right == "" {
		return false, fmt.Errorf("%s is required", envDeploymentManifestPath)
	}
	leftAbsolute, err := filepath.Abs(filepath.Clean(left))
	if err != nil {
		return false, err
	}
	rightAbsolute, err := filepath.Abs(filepath.Clean(right))
	if err != nil {
		return false, err
	}
	return leftAbsolute == rightAbsolute, nil
}

func validatePrivateOutputParent(path string) error {
	parent := filepath.Dir(filepath.Clean(path))
	pathInfo, err := os.Lstat(parent) //nolint:gosec // G703: the explicit proof output parent is validated as a real private directory before use.
	if err != nil {
		return err
	}
	if !pathInfo.IsDir() {
		return errors.New("parent is not a real directory")
	}
	if permissions := pathInfo.Mode().Perm(); permissions != 0o700 {
		return fmt.Errorf("parent mode is %#o, want 0700", permissions)
	}
	directory, err := os.Open(parent) //nolint:gosec // G703: lstat/open identity is compared below before the parent is trusted.
	if err != nil {
		return err
	}
	defer directory.Close()
	openedInfo, err := directory.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.IsDir() || !os.SameFile(pathInfo, openedInfo) {
		return errors.New("parent changed while it was opened")
	}
	return nil
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func readRegularFileBounded(path string, maximum int64) ([]byte, error) {
	if path == "" {
		return nil, errors.New("path is required")
	}
	pathInfo, err := os.Lstat(path) //nolint:gosec // G703: callers pass explicit attended-proof paths; this function rejects symlinks, swaps, non-regular files, and oversized input.
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("path is not a regular file")
	}
	file, err := os.Open(path) //nolint:gosec // G703: the lstat/open identity check below prevents symlink and replacement races.
	if err != nil {
		return nil, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, errors.New("path changed while it was opened")
	}
	if openedInfo.Size() < 1 || openedInfo.Size() > maximum {
		return nil, fmt.Errorf("file size %d is outside 1..%d bytes", openedInfo.Size(), maximum)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != openedInfo.Size() {
		return nil, errors.New("file changed while it was read")
	}
	return raw, nil
}

func decodeJSONWithUniqueKeys(raw []byte, destination any, disallowUnknown bool) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if disallowUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanUniqueJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanUniqueJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("JSON object did not close")
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("JSON array did not close")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("trailing JSON input")
}
