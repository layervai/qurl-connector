package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
	"github.com/layervai/qurl-connector/pkg/agentstate"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func seedCompletedRemoveAgentState(t *testing.T, dir, agentID string) {
	t.Helper()
	state := completedRemoveAgentState(t, agentID, canonicalRemoveDeviceAPIKey(0))
	store, err := qurl.OpenFileAgentState(filepath.Join(dir, agentstate.AgentStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAgentState(context.Background(), state); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func canonicalRemoveDeviceAPIKey(fill byte) string {
	return "lv_live_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func completedRemoveAgentState(t *testing.T, agentID, deviceAPIKey string) *qurl.AgentState {
	t.Helper()
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registeredAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	return &qurl.AgentState{
		AgentID:        agentID,
		PrivateKeyB64:  base64.StdEncoding.EncodeToString(privateKey.Bytes()),
		PublicKeyB64:   base64.StdEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
		RegisteredAt:   &registeredAt,
		DeviceAPIKey:   deviceAPIKey,
		DeviceAPIKeyID: "key_DvK9mN2pQr7S",
	}
}

type removeTestStateKeyWrapper struct{}

func (removeTestStateKeyWrapper) WrapKey(_ context.Context, plaintextKey []byte, _ qurl.AgentStateKeyBinding) (qurl.WrappedAgentStateKey, error) {
	return qurl.WrappedAgentStateKey{Version: 1, Ciphertext: append([]byte(nil), plaintextKey...)}, nil
}

func (removeTestStateKeyWrapper) UnwrapKey(_ context.Context, wrapped qurl.WrappedAgentStateKey, _ qurl.AgentStateKeyBinding) ([]byte, error) {
	return append([]byte(nil), wrapped.Ciphertext...), nil
}

type replaceAgentStateAfterLoadStore struct {
	qurl.AgentStateStore
	replacement *qurl.AgentState
	loads       atomic.Int32
}

func (s *replaceAgentStateAfterLoadStore) LoadAgentState(ctx context.Context) (*qurl.AgentState, error) {
	state, err := s.AgentStateStore.LoadAgentState(ctx)
	if err != nil {
		return nil, err
	}
	s.loads.Add(1)
	if err := s.AgentStateStore.SaveAgentState(ctx, s.replacement); err != nil {
		*state = qurl.AgentState{}
		return nil, err
	}
	return state, nil
}

func (s *replaceAgentStateAfterLoadStore) ValidateContinuity() error {
	continuity, ok := s.AgentStateStore.(qurl.AgentStateContinuity)
	if !ok {
		return errors.New("test agent state store has no continuity capability")
	}
	return continuity.ValidateContinuity()
}

func activeConnectorResourceResponse(resourceID, slug string) string {
	return connectorResourceDetailResponse(resourceID, slug, "active")
}

func connectorResourceDetailResponse(resourceID, slug, status string) string {
	return fmt.Sprintf(`{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":%q,"slug":%q}}}`, resourceID, testConnectorRoutingID, status, slug)
}

func ensureConnectorResourceResponse(resourceID, slug string) string {
	return fmt.Sprintf(`{"data":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":%q},"meta":{"found_existing":true}}`, resourceID, testConnectorRoutingID, slug)
}

func seedRemoveSagaCache(t *testing.T, stateDir, id string, pending bool) {
	t.Helper()
	if err := ensureConnectorIdentityCacheInitialized(stateDir); err != nil {
		t.Fatal(err)
	}
	seedCompletedRemoveAgentState(t, stateDir, testConnectorCacheAgentID)
	if err := withConnectorIdentityCacheLock(stateDir, func(txn *connectorIdentityCacheTxn) error {
		cache, err := loadConnectorIdentityCacheUnlocked(txn)
		if err != nil {
			return err
		}
		if err := cache.bindAgentIDLocked(txn, testConnectorCacheAgentID); err != nil {
			return err
		}
		if pending {
			return markTestConnectorRequestLocked(cache, txn, id)
		}
		return recordTestConnectorBindingLocked(cache, txn, id, testPublicResourceID)
	}); err != nil {
		t.Fatal(err)
	}
}

func configureRemoveCommandTest(t *testing.T, cfgPath, stateDir, apiURL string) {
	t.Helper()
	t.Setenv(agentstate.EnvStateDirPrimary, stateDir)
	t.Setenv(agentstate.EnvKeyProvider, agentstate.KeyProviderFile)
	t.Setenv("QURL_API_URL", apiURL+"/v1")
	oldConfig, oldResourceID := cfgFile, removeResourceID
	cfgFile, removeResourceID = cfgPath, ""
	t.Cleanup(func() {
		cfgFile, removeResourceID = oldConfig, oldResourceID
	})
}

func TestRunRemovePendingRouteNeedsNoCredential(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(agentstate.EnvStateDirPrimary, filepath.Join(dir, "state"))
	oldConfig, oldResourceID := cfgFile, removeResourceID
	t.Cleanup(func() { cfgFile, removeResourceID = oldConfig, oldResourceID })
	cfgFile = filepath.Join(dir, "qurl-proxy.yaml")
	removeResourceID = ""
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{ID: "customer-web", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}}
	if err := nhpconfig.Save(cfg, cfgFile); err != nil {
		t.Fatal(err)
	}
	if err := runRemove(nil, []string{"customer-web"}); err != nil {
		t.Fatal(err)
	}
	got, err := nhpconfig.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Routes) != 0 {
		t.Fatalf("routes = %#v", got.Routes)
	}
}

func TestRunRemoveManagedRoutePreservesConfigWithoutDeviceState(t *testing.T) {
	dir := t.TempDir()
	oldConfig, oldResourceID := cfgFile, removeResourceID
	t.Cleanup(func() { cfgFile, removeResourceID = oldConfig, oldResourceID })
	cfgFile = filepath.Join(dir, "qurl-proxy.yaml")
	removeResourceID = ""
	t.Setenv(agentstate.EnvStateDirPrimary, filepath.Join(dir, "missing-state"))
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceID, ConnectorRoutingID: testConnectorRoutingID,
	}}
	if err := nhpconfig.Save(cfg, cfgFile); err != nil {
		t.Fatal(err)
	}

	err := runRemove(nil, []string{"customer-web"})
	if err == nil || !strings.Contains(err.Error(), "local route") {
		t.Fatalf("runRemove error = %v, want fail-closed device-state error", err)
	}
	got, loadErr := nhpconfig.Load(cfgFile)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if len(got.Routes) != 1 || got.Routes[0].ResourceID != testPublicResourceID {
		t.Fatalf("managed route was removed after failed remote revoke: %#v", got.Routes)
	}
}

func TestRunRemoveBindsTrulyEmptyCacheBeforeExactRemoteDelete(t *testing.T) {
	root := realPrivateConnectorTestDir(t)
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(agentstate.EnvStateDirPrimary, stateDir)
	t.Setenv(agentstate.EnvKeyProvider, agentstate.KeyProviderFile)
	if err := ensureConnectorIdentityCacheInitialized(stateDir); err != nil {
		t.Fatal(err)
	}
	seedCompletedRemoveAgentState(t, stateDir, testConnectorCacheAgentID)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, activeConnectorResourceResponse(testPublicResourceID, "customer-web"))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("QURL_API_URL", server.URL+"/v1")

	cfgPath := filepath.Join(root, "qurl-proxy.yaml")
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{
		{
			ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
			LocalIP: "127.0.0.1", LocalPort: 8080,
			ResourceID: testPublicResourceID, ConnectorRoutingID: testConnectorRoutingID,
		},
		{
			ID: "customer-api", Type: nhpconfig.RouteTypeHTTP,
			LocalIP: "127.0.0.1", LocalPort: 8081,
		},
	}
	if err := nhpconfig.Save(cfg, cfgPath); err != nil {
		t.Fatal(err)
	}
	oldConfig, oldResourceID := cfgFile, removeResourceID
	cfgFile, removeResourceID = cfgPath, ""
	t.Cleanup(func() { cfgFile, removeResourceID = oldConfig, oldResourceID })

	if err := runRemove(nil, []string{"customer-web"}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("resource API calls = %d, want exact GET then DELETE", calls.Load())
	}
	got, err := nhpconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Routes) != 1 || got.Routes[0].ID != "customer-api" {
		t.Fatalf("multi-route removal changed the wrong routes: %#v", got.Routes)
	}
	cache, err := loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if cache.agentID != testConnectorCacheAgentID || len(cache.byID) != 0 || len(cache.pending) != 0 {
		t.Fatalf("post-delete cache = %#v, want durable device binding with pruned identity", cache)
	}
}

func TestRegisteredConnectorResourceStateEliminatesABCIdentityTOCTOU(t *testing.T) {
	tests := []struct {
		name   string
		sealed bool
	}{
		{name: "plaintext"},
		{name: "sealed", sealed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stateDir := newIdentityCacheTestDir(t)
			if err := ensureConnectorIdentityCacheInitialized(stateDir); err != nil {
				t.Fatal(err)
			}
			if err := withConnectorIdentityCacheLock(stateDir, func(txn *connectorIdentityCacheTxn) error {
				cache, err := loadConnectorIdentityCacheUnlocked(txn)
				if err != nil {
					return err
				}
				return cache.bindAgentIDLocked(txn, "agent-a")
			}); err != nil {
				t.Fatal(err)
			}

			var stateStore qurl.AgentStateStore
			var closeStore func() error
			if tt.sealed {
				store, err := qurl.NewSealedFileAgentState(
					filepath.Join(stateDir, agentstate.SealedAgentStateFile),
					"test-wrapper",
					removeTestStateKeyWrapper{},
				)
				if err != nil {
					t.Fatal(err)
				}
				stateStore = store
				closeStore = store.Close
			} else {
				store, err := qurl.OpenFileAgentState(filepath.Join(stateDir, agentstate.AgentStateFile))
				if err != nil {
					t.Fatal(err)
				}
				stateStore = store
				closeStore = store.Close
			}
			t.Cleanup(func() {
				if err := closeStore(); err != nil {
					t.Errorf("close test state store: %v", err)
				}
			})

			stateB := completedRemoveAgentState(t, "agent-b", canonicalRemoveDeviceAPIKey(0x42))
			stateC := completedRemoveAgentState(t, "agent-c", canonicalRemoveDeviceAPIKey(0x43))
			if err := stateStore.SaveAgentState(context.Background(), stateB); err != nil {
				t.Fatal(err)
			}
			sequence := &replaceAgentStateAfterLoadStore{
				AgentStateStore: stateStore,
				replacement:     stateC,
			}
			var resourceCalls atomic.Int32
			err := withConnectorIdentityCacheLock(stateDir, func(txn *connectorIdentityCacheTxn) error {
				cache, err := loadConnectorIdentityCacheUnlocked(txn)
				if err != nil {
					return err
				}
				return withRegisteredConnectorResourceState(
					context.Background(),
					txn,
					cache,
					sequence,
					sequence,
					"https://resources.example.test",
					func(*qurl.Client, connectorStateContinuity) error {
						resourceCalls.Add(1)
						return nil
					},
				)
			})
			if err == nil || !strings.Contains(err.Error(), "refusing cross-device resource use") {
				t.Fatalf("A/B/C identity sequence error = %v, want cache/open mismatch", err)
			}
			if sequence.loads.Load() != 1 {
				t.Fatalf("state loads before rejection = %d, want exactly one B snapshot", sequence.loads.Load())
			}
			if resourceCalls.Load() != 0 {
				t.Fatalf("resource callbacks = %d, want zero before A/B identity validation", resourceCalls.Load())
			}
			persisted, err := stateStore.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			persistedAgentID := persisted.AgentID
			*persisted = qurl.AgentState{}
			if persistedAgentID != "agent-c" {
				t.Fatalf("post-open state identity = %q, want adversarial C replacement", persistedAgentID)
			}
		})
	}
}

func TestRunRemovePendingSagaRetainsOrCommitsExactFence(t *testing.T) {
	tests := []struct {
		name         string
		handler      func(http.ResponseWriter, *http.Request)
		wantErr      string
		wantPending  bool
		wantResolved bool
		wantRoute    bool
		wantDelete   int32
	}{
		{
			name: "management lookup commits identity before delete",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/v1/resources" && r.URL.Query().Get("slug") == "customer-web":
					_, _ = fmt.Fprintf(w, `{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"customer-web"}]}`, testPublicResourceID, testConnectorRoutingID)
				case r.Method == http.MethodDelete && r.URL.Path == "/v1/resources/"+testPublicResourceID:
					w.WriteHeader(http.StatusNoContent)
				default:
					http.Error(w, "unexpected request", http.StatusBadRequest)
				}
			},
			wantRoute: false, wantDelete: 1,
		},
		{
			name: "transient management lookup retains pending",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && r.URL.Path == "/v1/resources" && r.URL.Query().Get("slug") == "customer-web" {
					http.Error(w, `{"error":{"code":"internal_error"}}`, http.StatusInternalServerError)
					return
				}
				http.Error(w, "unexpected request", http.StatusBadRequest)
			},
			wantErr: "exact NHP retry state preserved", wantPending: true, wantRoute: true,
		},
		{
			name: "cross-slug management result retains pending",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet && r.URL.Path == "/v1/resources" && r.URL.Query().Get("slug") == "customer-web" {
					_, _ = fmt.Fprintf(w, `{"data":[{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"other-web"}]}`, testPublicResourceID, testConnectorRoutingID)
					return
				}
				http.Error(w, "unexpected request", http.StatusBadRequest)
			},
			wantErr: "slug", wantPending: true, wantRoute: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := realPrivateConnectorTestDir(t)
			stateDir := filepath.Join(root, "state")
			if err := os.Mkdir(stateDir, 0o700); err != nil {
				t.Fatal(err)
			}
			seedRemoveSagaCache(t, stateDir, "customer-web", true)
			cfgPath := filepath.Join(root, "qurl-proxy.yaml")
			cfg := nhpconfig.NewDefaulted()
			cfg.Routes = []nhpconfig.Route{{
				ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
				LocalIP: "127.0.0.1", LocalPort: 8080,
			}}
			if err := nhpconfig.Save(cfg, cfgPath); err != nil {
				t.Fatal(err)
			}
			var deletes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deletes.Add(1)
				}
				tt.handler(w, r)
			}))
			t.Cleanup(server.Close)
			configureRemoveCommandTest(t, cfgPath, stateDir, server.URL)

			err := runRemove(nil, []string{"customer-web"})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("runRemove error = %v, want containing %q", err, tt.wantErr)
			}
			if deletes.Load() != tt.wantDelete {
				t.Fatalf("DELETE calls = %d, want %d", deletes.Load(), tt.wantDelete)
			}
			got, loadErr := nhpconfig.Load(cfgPath)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if routePresent := len(got.Routes) != 0; routePresent != tt.wantRoute {
				t.Fatalf("route present = %v, want %v", routePresent, tt.wantRoute)
			}
			cache, loadErr := loadConnectorIdentityCache(stateDir)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			_, resolved := cache.resourceID("customer-web")
			if cache.isPending("customer-web") != tt.wantPending || resolved != tt.wantResolved {
				t.Fatalf("cache after pending remove: pending=%v resolved=%v, want pending=%v resolved=%v", cache.isPending("customer-web"), resolved, tt.wantPending, tt.wantResolved)
			}
		})
	}
}

func TestRunRemoveExactPredeleteMismatchSendsNoDelete(t *testing.T) {
	root := realPrivateConnectorTestDir(t)
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedRemoveSagaCache(t, stateDir, "customer-web", false)
	cfgPath := filepath.Join(root, "qurl-proxy.yaml")
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceID, ConnectorRoutingID: testConnectorRoutingID,
	}}
	if err := nhpconfig.Save(cfg, cfgPath); err != nil {
		t.Fatal(err)
	}
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprint(w, activeConnectorResourceResponse(testPublicResourceID, "other-web"))
			return
		}
		deletes.Add(1)
		http.Error(w, "unexpected delete", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	configureRemoveCommandTest(t, cfgPath, stateDir, server.URL)
	if err := runRemove(nil, []string{"customer-web"}); err == nil || !strings.Contains(err.Error(), "belongs to Connector id") {
		t.Fatalf("pre-delete mismatch error = %v, want exact slug fence", err)
	}
	if deletes.Load() != 0 {
		t.Fatalf("DELETE calls = %d, want zero", deletes.Load())
	}
	if got, err := nhpconfig.Load(cfgPath); err != nil || len(got.Routes) != 1 {
		t.Fatalf("route was not preserved: cfg=%#v err=%v", got, err)
	}
	cache, err := loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.resourceID("customer-web"); !ok || got != testPublicResourceID {
		t.Fatalf("exact cache fence was lost: %q present=%v", got, ok)
	}
}

func TestRunRemoveDeleteThenYAMLSaveFailureRetainsExactRetryFence(t *testing.T) {
	root := realPrivateConnectorTestDir(t)
	stateDir := filepath.Join(root, "state")
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedRemoveSagaCache(t, stateDir, "customer-web", false)
	cfgPath := filepath.Join(configDir, "qurl-proxy.yaml")
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceID, ConnectorRoutingID: testConnectorRoutingID,
	}}
	if err := nhpconfig.Save(cfg, cfgPath); err != nil {
		t.Fatal(err)
	}

	var revoked atomic.Bool
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			status := "active"
			if revoked.Load() {
				status = "revoked"
			}
			_, _ = fmt.Fprint(w, connectorResourceDetailResponse(testPublicResourceID, "customer-web", status))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			deletes.Add(1)
			revoked.Store(true)
			if err := os.Chmod(configDir, 0o500); err != nil {
				t.Errorf("make config namespace read-only after DELETE: %v", err)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	t.Cleanup(func() { _ = os.Chmod(configDir, 0o700) })
	configureRemoveCommandTest(t, cfgPath, stateDir, server.URL)

	err := runRemove(nil, []string{"customer-web"})
	if err == nil || !strings.Contains(err.Error(), "saving config after remote deletion") {
		t.Fatalf("remove after YAML save failure = %v, want ordered post-delete save failure", err)
	}
	if err := os.Chmod(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	remaining, err := nhpconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Routes) != 1 {
		t.Fatalf("YAML route was not retained after failed save: %#v", remaining.Routes)
	}
	cache, err := loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.resourceID("customer-web"); !ok || got != testPublicResourceID {
		t.Fatalf("exact retry fence after YAML failure = %q present=%v", got, ok)
	}

	if err := runRemove(nil, []string{"customer-web"}); err != nil {
		t.Fatalf("idempotent retry against revoked exact ID: %v", err)
	}
	if deletes.Load() != 1 {
		t.Fatalf("DELETE calls across retry = %d, want exactly one", deletes.Load())
	}
}

func TestRunRemoveYAMLCommitThenCachePruneSyncFailureConvergesCachedOnly(t *testing.T) {
	root := realPrivateConnectorTestDir(t)
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedRemoveSagaCache(t, stateDir, "customer-web", false)
	cfgPath := filepath.Join(root, "qurl-proxy.yaml")
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceID, ConnectorRoutingID: testConnectorRoutingID,
	}}
	if err := nhpconfig.Save(cfg, cfgPath); err != nil {
		t.Fatal(err)
	}

	var revoked atomic.Bool
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			status := "active"
			if revoked.Load() {
				status = "revoked"
			}
			_, _ = fmt.Fprint(w, connectorResourceDetailResponse(testPublicResourceID, "customer-web", status))
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			deletes.Add(1)
			revoked.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	configureRemoveCommandTest(t, cfgPath, stateDir, server.URL)

	originalSync := syncConnectorIdentityCacheDir
	t.Cleanup(func() { syncConnectorIdentityCacheDir = originalSync })
	wantErr := errors.New("injected cache prune sync failure")
	var syncCalls atomic.Int32
	syncConnectorIdentityCacheDir = func(namespace *pinnedfs.Directory) error {
		if syncCalls.Add(1) == 1 {
			return wantErr
		}
		return originalSync(namespace)
	}
	err := runRemove(nil, []string{"customer-web"})
	syncConnectorIdentityCacheDir = originalSync
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "prune deleted Connector identity") {
		t.Fatalf("remove after cache-prune sync failure = %v, want ordered prune error", err)
	}
	remaining, err := nhpconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Routes) != 0 {
		t.Fatalf("YAML did not commit before cache prune failure: %#v", remaining.Routes)
	}
	cache, err := loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cache.resourceID("customer-web"); !ok || got != testPublicResourceID {
		t.Fatalf("cache-only retry fence after prune failure = %q present=%v", got, ok)
	}

	if err := runRemove(nil, []string{"customer-web"}); err != nil {
		t.Fatalf("cached-only retry did not converge: %v", err)
	}
	if deletes.Load() != 1 {
		t.Fatalf("DELETE calls across cached-only retry = %d, want exactly one", deletes.Load())
	}
	cache, err = loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.resourceID("customer-web"); ok {
		t.Fatal("cached-only retry did not prune exact identity")
	}
}

func TestRemoveReadOnlyConfiguredRouteStopsBeforeNetwork(t *testing.T) {
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceID, ConnectorRoutingID: testConnectorRoutingID,
	}}
	readOnlyErr := errors.New("read-only source mount")
	err := removeConnectorSelection(context.Background(), cfg, nil, nil, "customer-web", "", readOnlyErr)
	if !errors.Is(err, readOnlyErr) || !strings.Contains(err.Error(), "no qURL resource was changed") {
		t.Fatalf("read-only configured remove = %v, want host-edit-first zero-network guard", err)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("read-only guard mutated config in memory: %#v", cfg.Routes)
	}
}

func TestRunRemoveReadOnlyConfiguredRouteRequiresHostEditBeforeNetwork(t *testing.T) {
	root := realPrivateConnectorTestDir(t)
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(configDir, "qurl-proxy.yaml")
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceID, ConnectorRoutingID: testConnectorRoutingID,
	}}
	if err := nhpconfig.Save(cfg, cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfgPath + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfgPath, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(configDir, 0o700) })
	originalAcquire := acquireConnectorConfigTransaction
	acquireConnectorConfigTransaction = func(context.Context, string) (*nhpconfig.FileTransaction, error) {
		return nil, os.ErrPermission
	}
	t.Cleanup(func() { acquireConnectorConfigTransaction = originalAcquire })

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "unexpected network call", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	configureRemoveCommandTest(t, cfgPath, filepath.Join(root, "absent-state"), server.URL)

	err := runRemove(nil, []string{"customer-web"})
	if err == nil || !strings.Contains(err.Error(), "edit the host-side YAML") || !strings.Contains(err.Error(), "no qURL resource was changed") {
		t.Fatalf("read-only configured remove = %v, want host-edit-first guidance", err)
	}
	if requests.Load() != 0 {
		t.Fatalf("read-only configured remove made %d network calls, want zero", requests.Load())
	}
	if _, err := os.Lstat(cfgPath + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only configured remove created sibling config lock: %v", err)
	}
	remaining, err := nhpconfig.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining.Routes) != 1 {
		t.Fatalf("read-only configured remove mutated YAML: %#v", remaining.Routes)
	}
}

func TestRunRemoveReadOnlyCachedOnlyRecoveryCreatesNoConfigLock(t *testing.T) {
	root := realPrivateConnectorTestDir(t)
	stateDir := filepath.Join(root, "state")
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedRemoveSagaCache(t, stateDir, "customer-web", false)
	cfgPath := filepath.Join(configDir, "qurl-proxy.yaml")
	if err := os.WriteFile(cfgPath, []byte("routes: []\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(configDir, 0o700) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/resources/"+testPublicResourceID {
			http.Error(w, "unexpected mutation", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, connectorResourceDetailResponse(testPublicResourceID, "customer-web", "revoked"))
	}))
	t.Cleanup(server.Close)
	configureRemoveCommandTest(t, cfgPath, stateDir, server.URL)

	if err := runRemove(nil, []string{"customer-web"}); err != nil {
		t.Fatalf("read-only cached-only remove: %v", err)
	}
	if _, err := os.Lstat(cfgPath + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cached-only recovery created a sibling config lock: %v", err)
	}
	cache, err := loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.resourceID("customer-web"); ok {
		t.Fatal("read-only cached-only recovery did not prune retained identity")
	}
}

func TestRunRemoveStateNamespaceReplacementAfterExactReadStopsBeforeDelete(t *testing.T) {
	root := realPrivateConnectorTestDir(t)
	stateDir := filepath.Join(root, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedRemoveSagaCache(t, stateDir, "customer-web", false)
	cfgPath := filepath.Join(root, "qurl-proxy.yaml")
	cfg := nhpconfig.NewDefaulted()
	cfg.Routes = []nhpconfig.Route{{
		ID: "customer-web", Type: nhpconfig.RouteTypeHTTP,
		LocalIP: "127.0.0.1", LocalPort: 8080,
		ResourceID: testPublicResourceID, ConnectorRoutingID: testConnectorRoutingID,
	}}
	if err := nhpconfig.Save(cfg, cfgPath); err != nil {
		t.Fatal(err)
	}
	displaced := stateDir + "-displaced"
	var deletes atomic.Int32
	var replaced atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			if replaced.CompareAndSwap(false, true) {
				if err := os.Rename(stateDir, displaced); err != nil {
					t.Errorf("replace state namespace after exact read: %v", err)
				} else if err := os.Mkdir(stateDir, 0o700); err != nil {
					t.Errorf("create replacement state namespace: %v", err)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, activeConnectorResourceResponse(testPublicResourceID, "customer-web"))
			return
		}
		deletes.Add(1)
		http.Error(w, "unexpected delete", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	configureRemoveCommandTest(t, cfgPath, stateDir, server.URL)

	err := runRemove(nil, []string{"customer-web"})
	if err == nil || !strings.Contains(err.Error(), "replaced") {
		t.Fatalf("remove after state namespace replacement = %v, want continuity failure", err)
	}
	if deletes.Load() != 0 {
		t.Fatalf("DELETE calls = %d, want zero after continuity loss", deletes.Load())
	}
	if _, err := os.Lstat(filepath.Join(stateDir, connectorIdentityCacheFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement state namespace was mutated: %v", err)
	}
	got, loadErr := nhpconfig.Load(cfgPath)
	if loadErr != nil || len(got.Routes) != 1 {
		t.Fatalf("config route was not preserved: cfg=%#v err=%v", got, loadErr)
	}
	raw, readErr := os.ReadFile(filepath.Join(displaced, connectorIdentityCacheFile))
	if readErr != nil || !strings.Contains(string(raw), testPublicResourceID) {
		t.Fatalf("displaced exact cache fence was lost: %s err=%v", raw, readErr)
	}
}

func TestValidateConnectorDeletionTargetRejectsCrossIDResource(t *testing.T) {
	resource := &qurl.ConnectorResource{
		ResourceID: testPublicResourceID,
		Slug:       "other-web",
	}
	err := validateConnectorDeletionTarget(resource, "customer-web", testPublicResourceID)
	if err == nil || !strings.Contains(err.Error(), "other-web") || !strings.Contains(err.Error(), "refusing deletion") {
		t.Fatalf("validation error = %v, want cross-id deletion refusal", err)
	}
}

func TestReconcileConnectorDeletionProvesOutcomeUnknownCommit(t *testing.T) {
	var gets, deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			if gets.Add(1) == 1 {
				_, _ = fmt.Fprintf(w, `{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"active","slug":"customer-web"}}}`, testPublicResourceID, testConnectorRoutingID)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"resource":{"resource_id":%q,"connector_routing_id":%q,"knock_resource_id":"cell-resource","type":"tunnel","status":"revoked","slug":"customer-web"}}}`, testPublicResourceID, testConnectorRoutingID)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/resources/"+testPublicResourceID:
			deletes.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `{"error":{"code":"internal_error","detail":"reply lost after revoke"}}`)
		default:
			http.Error(w, "unexpected request", http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}

	deleted, err := reconcileConnectorResourceDeletion(context.Background(), client, "customer-web", testPublicResourceID, false)
	if err != nil || !deleted {
		t.Fatalf("reconcile outcome-unknown delete = deleted %v, err %v", deleted, err)
	}
	if gets.Load() != 2 || deletes.Load() != 1 {
		t.Fatalf("GETs=%d DELETEs=%d, want active read, one delete, revoked reconciliation", gets.Load(), deletes.Load())
	}
}

func TestReconcileConnectorDeletionNotFoundPreservesExactRetryIdentity(t *testing.T) {
	var deletes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/resources/"+testPublicResourceID {
			http.Error(w, `{"error":{"code":"not_found"}}`, http.StatusNotFound)
			return
		}
		deletes.Add(1)
		http.Error(w, "unexpected mutation", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	client, err := qurl.NewClient(qurl.BearerToken("device-token"), qurl.WithBaseURL(server.URL))
	if err != nil {
		t.Fatal(err)
	}

	deleted, err := reconcileConnectorResourceDeletion(context.Background(), client, "customer-web", testPublicResourceID, false)
	if err == nil || deleted || !errors.Is(err, qurl.ErrConnectorResourceNotFound) {
		t.Fatalf("not-found reconciliation = deleted %v, err %v; want fail-closed exact retry", deleted, err)
	}
	if deletes.Load() != 0 {
		t.Fatalf("DELETE calls = %d, want zero after unproven exact read", deletes.Load())
	}
}
