package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/agentstate"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

const (
	testConnectorCacheAgentID = "agent-remove"
	testConnectorRequestNonce = "ERERERERERERERERERERERERERERERERERERERERERE"
)

func testConnectorResourceBinding(id, resourceID string) *qurl.ConnectorResource {
	routingID := testConnectorRoutingID
	if resourceID == testPublicResourceID2 {
		routingID = testConnectorRoutingID2
	}
	return &qurl.ConnectorResource{
		ResourceID: resourceID, ConnectorRoutingID: routingID,
		KnockResourceID: "cell-resource", Slug: id,
	}
}

func recordTestConnectorBindingLocked(cache *connectorIdentityCache, txn *connectorIdentityCacheTxn, id, resourceID string) error {
	return cache.recordResolutionLocked(txn, id, testConnectorResourceBinding(id, resourceID))
}

func markTestConnectorRequestLocked(cache *connectorIdentityCache, txn *connectorIdentityCacheTxn, id string) error {
	expected, _ := cache.resourceID(id)
	_, err := cache.ensurePendingRequestLocked(txn, id, expected)
	return err
}

type failContinuityOnCall struct {
	calls  atomic.Int32
	failAt int32
	err    error
}

type exposedConnectorAgentStateStore struct {
	state *qurl.AgentState
}

func (s *exposedConnectorAgentStateStore) LoadAgentState(context.Context) (*qurl.AgentState, error) {
	return s.state, nil
}

func (*exposedConnectorAgentStateStore) SaveAgentState(context.Context, *qurl.AgentState) error {
	return errors.New("unexpected save")
}

func (*exposedConnectorAgentStateStore) Close() error { return nil }

func (g *failContinuityOnCall) ValidateContinuity() error {
	if g.calls.Add(1) == g.failAt {
		return g.err
	}
	return nil
}

func newIdentityCacheTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(realPrivateConnectorTestDir(t), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func isolateConnectorStateForTest(t *testing.T, root string) {
	t.Helper()
	t.Setenv(agentstate.EnvStateDirPrimary, filepath.Join(root, "isolated-agent-state"))
}

func TestValidateConnectorCacheAgentStateScrubsCompleteLoadedSnapshot(t *testing.T) {
	state := &qurl.AgentState{
		AgentID:       testConnectorCacheAgentID,
		PrivateKeyB64: "private",
		PublicKeyB64:  "public",
		DeviceAPIKey:  "device-secret",
		PendingCredentialRecovery: &qurl.PendingAgentCredentialRecovery{
			RecoveryGrant: "recovery-grant",
			DeviceAPIKey:  "replacement-secret",
		},
		PendingCredentialRecoveryIssue: &qurl.PendingAgentCredentialRecoveryIssue{
			RequestNonce: "nonce",
		},
	}
	store := &exposedConnectorAgentStateStore{state: state}
	if err := validateConnectorCacheAgentState(context.Background(), store, testConnectorCacheAgentID); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*state, qurl.AgentState{}) {
		t.Fatalf("loaded AgentState retained fields after cache binding validation: %#v", state)
	}
}

func writeIdentityCacheRaw(t *testing.T, dir, raw string) {
	t.Helper()
	writeIdentityCacheBytes(t, dir, []byte(raw))
}

func writeIdentityCacheBytes(t *testing.T, dir string, raw []byte) {
	t.Helper()
	writeIdentityCacheLockForTest(t, dir)
	if err := os.WriteFile(filepath.Join(dir, connectorIdentityCacheFile), raw, connectorIdentityCacheMode); err != nil {
		t.Fatal(err)
	}
}

func writeIdentityCacheLockForTest(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, connectorIdentityCacheLockFile), nil, connectorIdentityCacheMode); err != nil {
		t.Fatal(err)
	}
}

func seedConnectorIdentityCacheForTest(t *testing.T, dir, id, resourceID string) {
	t.Helper()
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	store := qurl.FileAgentState(filepath.Join(dir, agentstate.AgentStateFile))
	if err := store.SaveAgentState(context.Background(), &qurl.AgentState{AgentID: testConnectorCacheAgentID}); err != nil {
		t.Fatal(err)
	}
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		if err := cache.bindAgentIDLocked(txn, testConnectorCacheAgentID); err != nil {
			return err
		}
		return recordTestConnectorBindingLocked(cache, txn, id, resourceID)
	}); err != nil {
		t.Fatal(err)
	}
}

func bindConnectorIdentityCacheForTest(t *testing.T, dir string) {
	t.Helper()
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return cache.bindAgentIDLocked(txn, testConnectorCacheAgentID)
	}); err != nil {
		t.Fatal(err)
	}
}

// resolveConnectorIdentitiesWithManagementFixture adapts the historical HTTP
// response fixtures in this file to the native resolver seam. It is test-only:
// production passes qurl.ResolveRegisteredAgentConnectorResource directly and
// the dedicated native tests below assert that no HTTP request is possible.
func resolveConnectorIdentitiesWithManagementFixture(ctx context.Context, cfg *nhpconfig.Config, client *qurl.Client, dir, agentID string, continuity connectorStateContinuity) error {
	resolve := func(ctx context.Context, _ *qurl.AgentRuntimeBinding, request *qurl.NativeConnectorResourceRequest, _ ...qurl.AgentRuntimeUDPOption) (*qurl.ConnectorResourceResolution, error) {
		var resource *qurl.ConnectorResource
		var err error
		if request.ExpectedResourceID != "" {
			resource, err = client.GetConnectorResource(ctx, request.ExpectedResourceID)
		} else {
			resource, err = client.GetConnectorResourceBySlug(ctx, request.ConnectorID)
			if errors.Is(err, qurl.ErrConnectorResourceNotFound) {
				var result *qurl.EnsureConnectorResourceResult
				result, err = client.EnsureConnectorResource(ctx, request.ConnectorID)
				if result != nil {
					resource = result.Resource
				}
			}
		}
		if err != nil {
			return nil, err
		}
		return &qurl.ConnectorResourceResolution{Resource: resource, FoundExisting: true}, nil
	}
	return resolveConnectorIdentities(ctx, cfg, &qurl.AgentRuntimeBinding{}, nil, dir, agentID, continuity, resolve)
}

func TestConnectorIdentityCacheRejectsMissingAfterNativeState(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := os.WriteFile(filepath.Join(dir, agentstate.AgentStateFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureConnectorIdentityCacheInitialized(dir); err == nil || !strings.Contains(err.Error(), "continuity state is missing") {
		t.Fatalf("ensure cache error = %v, want missing-continuity failure", err)
	}
	if _, err := os.Stat(filepath.Join(dir, connectorIdentityCacheFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cache unexpectedly recreated: %v", err)
	}
}

func TestConnectorIdentityCacheRejectsChangedAuthenticatedBinding(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*qurl.ConnectorResource)
	}{
		{name: "Connector id", mutate: func(resource *qurl.ConnectorResource) { resource.Slug = "other" }},
		{name: "routing id", mutate: func(resource *qurl.ConnectorResource) { resource.ConnectorRoutingID = testConnectorRoutingID2 }},
		{name: "knock id", mutate: func(resource *qurl.ConnectorResource) { resource.KnockResourceID = "other-cell-resource" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := newIdentityCacheTestDir(t)
			seedConnectorIdentityCacheForTest(t, dir, "web", testPublicResourceID)
			resource := testConnectorResourceBinding("web", testPublicResourceID)
			tt.mutate(resource)
			err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
				cache, err := loadConnectorIdentityCacheUnlocked(txn)
				if err != nil {
					return err
				}
				return cache.recordResolutionLocked(txn, "web", resource)
			})
			if err == nil {
				t.Fatal("changed authenticated binding was accepted")
			}
			cache, err := loadConnectorIdentityCache(dir)
			if err != nil {
				t.Fatal(err)
			}
			binding, ok := cache.binding("web")
			if !ok || binding != (connectorIdentityCacheEntry{
				ID: "web", ResourceID: testPublicResourceID,
				ConnectorRoutingID: testConnectorRoutingID, KnockResourceID: "cell-resource",
			}) {
				t.Fatalf("durable binding changed after rejection: %#v", binding)
			}
		})
	}
}

func TestPrepareConnectorRunRejectsBoundEmptyCacheBeforeRuntimeOpen(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	t.Setenv(agentstate.EnvStateDirPrimary, dir)
	writeIdentityCacheRaw(t, dir, `{"version":2,"agent_id":"`+testConnectorCacheAgentID+`","identities":[],"pending_requests":[]}`)

	configPath := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
	}}
	if err := nhpconfig.Save(cfg, configPath); err != nil {
		t.Fatal(err)
	}
	// If cache continuity were checked only after runtime open, this malformed
	// trust root would become the observed error (or a valid endpoint could see
	// fresh enrollment traffic). The bound-empty cache must win before either.
	t.Setenv(envHubHost, "not-a-layerv-host.example")
	t.Setenv(envHubPort, "443")
	t.Setenv(envHubServerPublicKey, validTestHubPublicKeyB64)
	t.Setenv("QURL_API_KEY", "lv_live_enrollment_must_not_be_used")

	_, _, _, err := prepareConnectorRun(context.Background(), configPath)
	if err == nil || !strings.Contains(err.Error(), "cache is bound or non-empty but native agent state is missing") {
		t.Fatalf("prepare error = %v, want pre-runtime bound-cache continuity failure", err)
	}
}

func TestConnectorIdentityCacheRejectsLegacySplitStateBeforeWritingCache(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := os.WriteFile(filepath.Join(dir, agentstate.PrivateKeyFile), []byte("legacy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureConnectorIdentityCacheInitialized(dir); err == nil || !strings.Contains(err.Error(), "legacy pre-native agent state") {
		t.Fatalf("ensure cache error = %v, want legacy-state reset failure", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, connectorIdentityCacheFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canonical cache was written beside legacy split state: %v", err)
	}
}

func TestHydrateConnectorResourceIDsRejectsMissingCacheBesideNativeState(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	t.Setenv(agentstate.EnvStateDirPrimary, dir)
	if err := os.WriteFile(filepath.Join(dir, agentstate.AgentStateFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	if err := hydrateConnectorResourceIDsReadOnlyContext(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "continuity state is missing") {
		t.Fatalf("hydrate error = %v, want missing-continuity failure", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, connectorIdentityCacheFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only hydration created missing cache: %v", err)
	}
}

func TestHydrateConnectorResourceIDsReadOnlyToleratesOrphanCacheEntries(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	t.Setenv(agentstate.EnvStateDirPrimary, dir)
	seedConnectorIdentityCacheForTest(t, dir, "web", testPublicResourceID)
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return recordTestConnectorBindingLocked(cache, txn, "removed-route", testPublicResourceID2)
	}); err != nil {
		t.Fatal(err)
	}

	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
	}}
	if err := hydrateConnectorResourceIDsReadOnlyContext(context.Background(), cfg); err != nil {
		t.Fatalf("read-only hydration rejected stale orphan: %v", err)
	}
	if got := cfg.Routes[0].ResourceID; got != testPublicResourceID {
		t.Fatalf("hydrated resource_id = %q, want %q", got, testPublicResourceID)
	}
	cache, err := loadConnectorIdentityCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.resourceID("removed-route"); !ok || got != testPublicResourceID2 {
		t.Fatalf("read-only hydration mutated orphan = %q, %v", got, ok)
	}
}

func TestConnectorIdentityCacheStrictSchema(t *testing.T) {
	tests := map[string]struct {
		raw  string
		want string
	}{
		"unknown envelope field":      {`{"version":2,"agent_id":"agent-remove","identities":[],"pending_requests":[],"extra":true}`, `unknown field "extra"`},
		"noncanonical envelope case":  {`{"version":2,"Agent_ID":"agent-remove","identities":[],"pending_requests":[]}`, `unknown field "Agent_ID"`},
		"missing agent id":            {`{"version":2,"identities":[],"pending_requests":[]}`, "missing agent_id"},
		"null agent id":               {`{"version":2,"agent_id":null,"identities":[],"pending_requests":[]}`, "missing agent_id"},
		"oversized agent id":          {`{"version":2,"agent_id":"` + strings.Repeat("a", 257) + `","identities":[],"pending_requests":[]}`, "exceeds 256 bytes"},
		"unknown entry field":         {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","resource_id":"` + testPublicResourceID + `","extra":true}],"pending_requests":[]}`, `unknown field "extra"`},
		"noncanonical entry case":     {`{"version":2,"agent_id":"agent-remove","identities":[{"ID":"web","resource_id":"` + testPublicResourceID + `"}],"pending_requests":[]}`, `unknown field "ID"`},
		"duplicate envelope field":    {`{"version":2,"agent_id":"agent-remove","identities":[],"identities":[{"id":"web","resource_id":"` + testPublicResourceID + `"}],"pending_requests":[]}`, `duplicate field "identities"`},
		"duplicate entry field":       {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","id":"api","resource_id":"` + testPublicResourceID + `"}],"pending_requests":[]}`, `duplicate field "id"`},
		"wrong version":               {`{"version":3,"agent_id":"agent-remove","identities":[],"pending_requests":[]}`, "version is 3, want 2"},
		"missing identities":          {`{"version":2,"agent_id":"agent-remove","pending_requests":[]}`, "missing identities"},
		"null identities":             {`{"version":2,"agent_id":"agent-remove","identities":null,"pending_requests":[]}`, "missing identities"},
		"missing pending":             {`{"version":2,"agent_id":"agent-remove","identities":[]}`, "missing pending_requests"},
		"null pending":                {`{"version":2,"agent_id":"agent-remove","identities":[],"pending_requests":null}`, "missing pending_requests"},
		"trailing JSON":               {`{"version":2,"agent_id":"agent-remove","identities":[],"pending_requests":[]} {}`, "multiple JSON values"},
		"duplicate id":                {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","resource_id":"` + testPublicResourceID + `","connector_routing_id":"` + testConnectorRoutingID + `","knock_resource_id":"cell-resource"},{"id":"web","resource_id":"` + testPublicResourceID2 + `","connector_routing_id":"` + testConnectorRoutingID2 + `","knock_resource_id":"cell-resource"}],"pending_requests":[]}`, `duplicate id "web"`},
		"duplicate resource":          {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"api","resource_id":"` + testPublicResourceID + `","connector_routing_id":"` + testConnectorRoutingID + `","knock_resource_id":"cell-resource"},{"id":"web","resource_id":"` + testPublicResourceID + `","connector_routing_id":"` + testConnectorRoutingID2 + `","knock_resource_id":"cell-resource"}],"pending_requests":[]}`, "maps resource_id"},
		"bad slug":                    {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"Bad Slug","resource_id":"` + testPublicResourceID + `"}],"pending_requests":[]}`, "does not match required format"},
		"bad public key":              {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","resource_id":"not-a-public-key"}],"pending_requests":[]}`, "P-256 DER SPKI"},
		"missing routing id":          {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","resource_id":"` + testPublicResourceID + `","knock_resource_id":"cell-resource"}],"pending_requests":[]}`, "connector_routing_id"},
		"oversized knock id":          {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","resource_id":"` + testPublicResourceID + `","connector_routing_id":"` + testConnectorRoutingID + `","knock_resource_id":"` + strings.Repeat("k", 65) + `"}],"pending_requests":[]}`, "exceeds 64 bytes"},
		"null crid":                   {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","resource_id":"` + testPublicResourceID + `","connector_routing_id":"` + testConnectorRoutingID + `","knock_resource_id":"cell-resource","crid":null}],"pending_requests":[]}`, "crid must be absent rather than null"},
		"pending continuity mismatch": {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","resource_id":"` + testPublicResourceID + `","connector_routing_id":"` + testConnectorRoutingID + `","knock_resource_id":"cell-resource"}],"pending_requests":[{"id":"web","request_nonce":"` + testConnectorRequestNonce + `","expected_resource_id":"` + testPublicResourceID2 + `"}]}`, "does not assert its exact cached resource_id"},
		"null pending expected id":    {`{"version":2,"agent_id":"agent-remove","identities":[],"pending_requests":[{"id":"web","request_nonce":"` + testConnectorRequestNonce + `","expected_resource_id":null}]}`, "expected_resource_id must be absent rather than null"},
		"unsorted identities":         {`{"version":2,"agent_id":"agent-remove","identities":[{"id":"web","resource_id":"` + testPublicResourceID + `","connector_routing_id":"` + testConnectorRoutingID + `","knock_resource_id":"cell-resource"},{"id":"api","resource_id":"` + testPublicResourceID2 + `","connector_routing_id":"` + testConnectorRoutingID2 + `","knock_resource_id":"cell-resource"}],"pending_requests":[]}`, "strictly sorted by id"},
		"unsorted pending":            {`{"version":2,"agent_id":"agent-remove","identities":[],"pending_requests":[{"id":"web","request_nonce":"` + testConnectorRequestNonce + `"},{"id":"api","request_nonce":"` + testConnectorRequestNonce + `"}]}`, "strictly sorted"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := newIdentityCacheTestDir(t)
			writeIdentityCacheRaw(t, dir, tt.raw)
			if _, err := loadConnectorIdentityCache(dir); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("load error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestConnectorIdentityCacheRejectsLossyUnicodeInputs(t *testing.T) {
	validPrefix := []byte(`{"version":2,"agent_id":"agent-`)
	validSuffix := []byte(`","identities":[],"pending_requests":[]}`)
	tests := map[string]struct {
		raw  []byte
		want string
	}{
		"malformed UTF-8": {
			raw:  append(append(append([]byte(nil), validPrefix...), 0xff), validSuffix...),
			want: "not valid UTF-8",
		},
		"unpaired surrogate escape": {
			raw:  []byte(`{"version":2,"agent_id":"agent-\ud800","identities":[],"pending_requests":[]}`),
			want: "UTF-16 surrogate escape",
		},
		"paired surrogate escapes": {
			raw:  []byte(`{"version":2,"agent_id":"agent-\ud83d\ude00","identities":[],"pending_requests":[]}`),
			want: "UTF-16 surrogate escape",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := newIdentityCacheTestDir(t)
			writeIdentityCacheBytes(t, dir, tt.raw)
			if _, err := loadConnectorIdentityCache(dir); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("load error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRejectConnectorIdentityCacheSurrogateEscapesAllowsEscapedLiteral(t *testing.T) {
	if err := rejectConnectorIdentityCacheSurrogateEscapes([]byte(`{"value":"literal-\\ud800"}`)); err != nil {
		t.Fatalf("escaped literal was rejected: %v", err)
	}
}

func TestConnectorIdentityCacheAgentIDBoundaryAndBinding(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	maxAgentID := strings.Repeat("a", connectorIdentityAgentIDMaxLen)
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		if err := cache.bindAgentIDLocked(txn, maxAgentID); err != nil {
			return err
		}
		return cache.bindAgentIDLocked(txn, maxAgentID)
	}); err != nil {
		t.Fatalf("maximum canonical agent id did not bind idempotently: %v", err)
	}
	otherAgentID := strings.Repeat("b", connectorIdentityAgentIDMaxLen)
	err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return cache.bindAgentIDLocked(txn, otherAgentID)
	})
	if err == nil || strings.Contains(err.Error(), maxAgentID) || strings.Contains(err.Error(), otherAgentID) {
		t.Fatalf("cross-agent binding error was absent or leaked raw ids: %v", err)
	}
}

func TestResolveConnectorIdentitiesRejectsCrossAgentCacheBeforeResourceCall(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return cache.bindAgentIDLocked(txn, "agent-original")
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "resource call forbidden", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	err = resolveConnectorIdentitiesWithManagementFixture(context.Background(), cfg, client, dir, "agent-restored", nil)
	if err == nil || !strings.Contains(err.Error(), "cross-device") {
		t.Fatalf("resolve error = %v, want cross-device cache rejection", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("resource API calls = %d, want zero before agent binding", calls.Load())
	}
}

func TestConnectorIdentityCacheRejectsInsecureFileAndDirectory(t *testing.T) {
	t.Run("directory mode", func(t *testing.T) {
		dir := newIdentityCacheTestDir(t)
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		// A loose-mode state directory the connector owns is tightened to
		// owner-only 0700 before the pinned mode check rather than failing the
		// first run on it (F2 onboarding ergonomics). The 0700 posture is still
		// what ends up on disk — reached by tightening, not rejection.
		if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
			t.Fatalf("initialize owned 0755 state dir = %v, want tightened success", err)
		}
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Fatalf("state dir mode = %04o, want 0700 after tightening", got)
		}
	})
	t.Run("cache mode", func(t *testing.T) {
		dir := newIdentityCacheTestDir(t)
		writeIdentityCacheRaw(t, dir, `{"version":2,"identities":[],"pending_requests":[]}`)
		if err := os.Chmod(filepath.Join(dir, connectorIdentityCacheFile), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConnectorIdentityCache(dir); err == nil || !strings.Contains(err.Error(), "want 0600") {
			t.Fatalf("error = %v, want exact cache-mode rejection", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := newIdentityCacheTestDir(t)
		target := filepath.Join(t.TempDir(), "target")
		if err := os.WriteFile(target, []byte(`{"version":2,"identities":[],"pending_requests":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, connectorIdentityCacheFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadConnectorIdentityCache(dir); err == nil {
			t.Fatal("load cache followed symlink")
		}
	})
}

func TestConnectorIdentityCacheRejectsOversizedSaveBeforeReplacingFile(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	bindConnectorIdentityCacheForTest(t, dir)
	path := filepath.Join(dir, connectorIdentityCacheFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	err = withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		for i := 0; i < 20000; i++ {
			id := fmt.Sprintf("pending-%05d-%s", i, strings.Repeat("a", 45))
			request, requestErr := qurl.NewNativeConnectorResourceRequest(id, "")
			if requestErr != nil {
				return requestErr
			}
			cache.pending[id] = connectorIdentityPendingRequest{ID: id, RequestNonce: request.RequestNonce}
		}
		return saveConnectorIdentityCacheUnlocked(txn, cache)
	})
	if err == nil || !strings.Contains(err.Error(), "exceeds 1048576-byte cap") {
		t.Fatalf("oversized save error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("oversized save replaced the last valid cache")
	}
	matches, err := filepath.Glob(filepath.Join(dir, "."+connectorIdentityCacheFile+".tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("oversized save created temporary files: %v", matches)
	}
}

func TestResolveConnectorIdentitiesColdThenWarmUsesDurableExactID(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	var posts, gets atomic.Int32
	var pendingObserved atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/resources":
			posts.Add(1)
			pendingRaw, readErr := os.ReadFile(filepath.Join(dir, connectorIdentityCacheFile))
			pendingObserved.Store(readErr == nil && strings.Contains(string(pendingRaw), `"pending_requests":[{"id":"web","request_nonce":`))
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"web"},"meta":{"found_existing":false}}`, testPublicResourceID, testConnectorRoutingID)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/resources" && r.URL.Query().Get("slug") == "web":
			gets.Add(1)
			_, _ = fmt.Fprint(w, `{"data":[]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			gets.Add(1)
			_, _ = fmt.Fprintf(w, `{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"web"}}}`, testPublicResourceID, testConnectorRoutingID)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	cold := nhpconfig.NewDefaulted()
	cold.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	if err := nhpconfig.Save(cold, configPath); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o444); err != nil {
		t.Fatal(err)
	}
	loadedCold, err := nhpconfig.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := resolveConnectorIdentitiesWithManagementFixture(context.Background(), loadedCold, client, dir, testConnectorCacheAgentID, nil); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("cold identity hydration modified read-only qurl-proxy.yaml")
	}

	warm := nhpconfig.NewDefaulted()
	warm.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	if err := resolveConnectorIdentitiesWithManagementFixture(context.Background(), warm, client, dir, testConnectorCacheAgentID, nil); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 1 || gets.Load() != 2 {
		t.Fatalf("resource calls: POST=%d GET=%d, want cold slug read + Ensure and one warm exact GET", posts.Load(), gets.Load())
	}
	if !pendingObserved.Load() {
		t.Fatal("Ensure was dispatched before its durable pending journal entry")
	}
	if warm.Routes[0].ResourceID != testPublicResourceID || warm.Routes[0].ConnectorRoutingID != testConnectorRoutingID {
		t.Fatalf("warm route = %#v", warm.Routes[0])
	}
	raw, err := os.ReadFile(filepath.Join(dir, connectorIdentityCacheFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"connector_routing_id", "knock_resource_id"} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("identity cache is missing required field %q: %s", required, raw)
		}
	}
	for _, forbidden := range []string{"device", "credential", "private_key", "api_key"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("identity cache contains forbidden field %q: %s", forbidden, raw)
		}
	}
}

func TestResolveConnectorIdentitiesRetainsPendingWhenContinuityFailsAfterAuthenticatedResolution(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/resources":
			_, _ = fmt.Fprint(w, `{"data":[]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/resources":
			posts.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"web"},"meta":{"found_existing":false}}`, testPublicResourceID, testConnectorRoutingID)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	continuityErr := fmt.Errorf("%w: injected post-resolution continuity loss", qurl.ErrAgentStateContinuity)
	// The transaction continuity gate checks the SDK on both sides of the
	// cache-namespace check, before and after each operation. Binding (4),
	// pending journal (4), and native resolution (4) complete;
	// continuity then fails immediately before the binding is committed.
	gate := &failContinuityOnCall{failAt: 13, err: continuityErr}
	err = resolveConnectorIdentitiesWithManagementFixture(context.Background(), cfg, client, dir, testConnectorCacheAgentID, gate)
	if !errors.Is(err, continuityErr) {
		t.Fatalf("resolve error = %v, want post-resolution continuity failure", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("Ensure calls = %d, want exactly one", posts.Load())
	}
	cache, err := loadConnectorIdentityCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, resolved := cache.resourceID("web"); resolved || !cache.isPending("web") {
		t.Fatalf("cache after continuity loss = %#v, want unresolved pending web", cache)
	}
	if cfg.Routes[0].ResourceID != "" || cfg.Routes[0].ConnectorRoutingID != "" {
		t.Fatalf("in-memory route committed after continuity loss: %#v", cfg.Routes[0])
	}
}

func TestResolveConnectorIdentitiesColdPreexistingSlugNeverEnsures(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	var posts, gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			posts.Add(1)
			http.Error(w, "Ensure forbidden", http.StatusInternalServerError)
			return
		}
		gets.Add(1)
		_, _ = fmt.Fprintf(w, `{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"web"}]}`, testPublicResourceID, testConnectorRoutingID)
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	if err := resolveConnectorIdentitiesWithManagementFixture(context.Background(), cfg, client, dir, testConnectorCacheAgentID, nil); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 0 || gets.Load() != 1 {
		t.Fatalf("POST=%d GET=%d, want read-only cold adoption", posts.Load(), gets.Load())
	}
	cache, err := loadConnectorIdentityCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.resourceID("web"); !ok || got != testPublicResourceID || cache.isPending("web") {
		t.Fatalf("adopted mapping = %q present=%v pending=%v", got, ok, cache.isPending("web"))
	}
}

func TestResolveConnectorIdentitiesPendingRestartRedrivesEnsureAndRetainsUnresolved(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	bindConnectorIdentityCacheForTest(t, dir)
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return markTestConnectorRequestLocked(cache, txn, "web")
	}); err != nil {
		t.Fatal(err)
	}
	var posts, gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			posts.Add(1)
			http.Error(w, "forbidden", http.StatusInternalServerError)
			return
		}
		gets.Add(1)
		_, _ = fmt.Fprint(w, `{"data":[]}`)
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	err = resolveConnectorIdentitiesWithManagementFixture(context.Background(), cfg, client, dir, testConnectorCacheAgentID, nil)
	if err == nil || !strings.Contains(err.Error(), "exact request is preserved for exact replay") {
		t.Fatalf("error = %v, want explicit exact-replay recovery", err)
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("POST=%d GET=%d, want one idempotent re-drive and one reconciliation lookup", posts.Load(), gets.Load())
	}
	cache, err := loadConnectorIdentityCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cache.isPending("web") {
		t.Fatal("unresolved pending identity was cleared")
	}
}

func TestResolveConnectorIdentitiesRejectsChangedContinuityBeforeNativeIO(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	bindConnectorIdentityCacheForTest(t, dir)
	if err := withConnectorIdentityCacheLock(dir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		return markTestConnectorRequestLocked(cache, txn, "web")
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	resolve := func(context.Context, *qurl.AgentRuntimeBinding, *qurl.NativeConnectorResourceRequest, ...qurl.AgentRuntimeUDPOption) (*qurl.ConnectorResourceResolution, error) {
		calls.Add(1)
		return nil, errors.New("native resolver must not be called")
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080, ResourceID: testPublicResourceID}}
	err := resolveConnectorIdentities(context.Background(), cfg, &qurl.AgentRuntimeBinding{}, nil, dir, testConnectorCacheAgentID, nil, resolve)
	if err == nil || !strings.Contains(err.Error(), `durable NHP request asserts resource_id ""`) {
		t.Fatalf("resolve error = %v, want durable continuity conflict", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("native resolver calls = %d, want zero", calls.Load())
	}
	cache, err := loadConnectorIdentityCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cache.isPending("web") {
		t.Fatal("continuity conflict cleared the durable request")
	}
}

func TestResolveConnectorIdentitiesPreservesUnknownOutcomeWithoutHTTPReconciliation(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	var posts, gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			posts.Add(1)
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Error("response writer cannot hijack")
				return
			}
			conn, _, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		case http.MethodGet:
			gets.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if posts.Load() == 0 {
				_, _ = fmt.Fprint(w, `{"data":[]}`)
			} else {
				_, _ = fmt.Fprintf(w, `{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"web"}]}`, testPublicResourceID, testConnectorRoutingID)
			}
		}
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	err = resolveConnectorIdentitiesWithManagementFixture(context.Background(), cfg, client, dir, testConnectorCacheAgentID, nil)
	if err == nil || !strings.Contains(err.Error(), "exact request is preserved for exact replay") {
		t.Fatalf("resolve error = %v, want preserved exact replay", err)
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("POST=%d GET=%d, want initial fixture lookup and one uncertain mutation only", posts.Load(), gets.Load())
	}
	cache, err := loadConnectorIdentityCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.resourceID("web"); ok || !cache.isPending("web") {
		t.Fatalf("cache id=%q present=%v pending=%v, want unresolved exact replay", got, ok, cache.isPending("web"))
	}
}

func TestResolveConnectorIdentitiesPreservesMalformedSuccessWithoutHTTPReconciliation(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
		t.Fatal(err)
	}
	var posts, gets atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			posts.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"web"},"meta":{}}`, testPublicResourceID, testConnectorRoutingID)
			return
		}
		gets.Add(1)
		if posts.Load() == 0 {
			_, _ = fmt.Fprint(w, `{"data":[]}`)
		} else {
			_, _ = fmt.Fprintf(w, `{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"web"}]}`, testPublicResourceID, testConnectorRoutingID)
		}
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	err = resolveConnectorIdentitiesWithManagementFixture(context.Background(), cfg, client, dir, testConnectorCacheAgentID, nil)
	if err == nil || !strings.Contains(err.Error(), "exact request is preserved for exact replay") {
		t.Fatalf("resolve error = %v, want preserved exact replay", err)
	}
	if posts.Load() != 1 || gets.Load() != 1 {
		t.Fatalf("POST=%d GET=%d, want no post-response HTTP reconciliation", posts.Load(), gets.Load())
	}
	cache, err := loadConnectorIdentityCache(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !cache.isPending("web") {
		t.Fatal("malformed authenticated result cleared exact replay state")
	}
}

func TestResolveConnectorIdentitiesClearsOnlyAuthenticatedTerminalNHPRejections(t *testing.T) {
	tests := []struct {
		name        string
		resolveErr  error
		wantPending bool
	}{
		{name: "identity rejected", resolveErr: qurl.ErrConnectorResourceIdentityRejected},
		{name: "entitlement denied", resolveErr: qurl.ErrConnectorResourceEntitlementDenied},
		{name: "identity conflict", resolveErr: qurl.ErrConnectorResourceIdentityConflict},
		{name: "quota exceeded", resolveErr: qurl.ErrConnectorResourceQuotaExceeded},
		{name: "invalid request", resolveErr: qurl.ErrConnectorResourceRequestRejected},
		{name: "unavailable", resolveErr: qurl.ErrConnectorResourceUnavailable, wantPending: true},
		{name: "rate limited", resolveErr: qurl.ErrConnectorResourceRateLimited, wantPending: true},
		{name: "malformed authenticated result", resolveErr: qurl.ErrInvalidNativeConnectorResourceResponse, wantPending: true},
		{name: "transport", resolveErr: context.DeadlineExceeded, wantPending: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := newIdentityCacheTestDir(t)
			if err := ensureConnectorIdentityCacheInitialized(dir); err != nil {
				t.Fatal(err)
			}
			resolve := func(context.Context, *qurl.AgentRuntimeBinding, *qurl.NativeConnectorResourceRequest, ...qurl.AgentRuntimeUDPOption) (*qurl.ConnectorResourceResolution, error) {
				return nil, tt.resolveErr
			}
			cfg := nhpconfig.NewDefaulted()
			cfg.Routes = []nhpconfig.Route{{ID: "web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
			err := resolveConnectorIdentities(context.Background(), cfg, &qurl.AgentRuntimeBinding{}, nil, dir, testConnectorCacheAgentID, nil, resolve)
			if !errors.Is(err, tt.resolveErr) {
				t.Fatalf("resolve error = %v, want %v", err, tt.resolveErr)
			}
			cache, err := loadConnectorIdentityCache(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := cache.isPending("web"); got != tt.wantPending {
				t.Fatalf("pending = %v, want %v", got, tt.wantPending)
			}
		})
	}
}

func TestResolveConnectorIdentitiesRejectsOrphanBeforeResourceNetwork(t *testing.T) {
	dir := newIdentityCacheTestDir(t)
	writeIdentityCacheRaw(t, dir, `{"version":2,"agent_id":"`+testConnectorCacheAgentID+`","identities":[{"id":"old-web","resource_id":"`+testPublicResourceID+`","connector_routing_id":"`+testConnectorRoutingID+`","knock_resource_id":"cell-resource"}],"pending_requests":[]}`)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "should not be reached", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "new-web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	err = resolveConnectorIdentitiesWithManagementFixture(context.Background(), cfg, client, dir, testConnectorCacheAgentID, nil)
	if err == nil || !strings.Contains(err.Error(), "orphan id") {
		t.Fatalf("error = %v, want orphan recovery instruction", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("resource API calls = %d, want zero", calls.Load())
	}
}

func TestConnectorIdentityCacheContinuityGuardsRejectNilReceiver(t *testing.T) {
	var cache *connectorIdentityCache
	tests := map[string]func(){
		"continuity state": func() {
			cache.hasContinuityState()
		},
		"orphan identities": func() {
			_ = cache.rejectOrphanIdentities(nil)
		},
	}
	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("nil cache did not fail fast")
				}
			}()
			run()
		})
	}
}
