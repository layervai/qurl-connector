package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	qurl "github.com/layervai/qurl-go/qurl"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func managedNativeTestConfig(ids ...string) *nhpconfig.Config {
	cfg := nhpconfig.NewDefaulted()
	for i, id := range ids {
		cfg.Routes = append(cfg.Routes, nhpconfig.Route{
			ID: id, Type: nhpconfig.RouteTypeHTTP,
			LocalIP: "127.0.0.1", LocalPort: 8080 + i,
		})
	}
	return cfg
}

func copyNativeConnectorRequest(request *qurl.NativeConnectorResourceRequest) qurl.NativeConnectorResourceRequest {
	if request == nil {
		return qurl.NativeConnectorResourceRequest{}
	}
	return *request
}

func assertNativeRequestWasDurableBeforeDispatch(t *testing.T, stateDir string, request *qurl.NativeConnectorResourceRequest) {
	t.Helper()
	if request == nil {
		t.Fatal("native resolver received a nil request")
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, connectorIdentityCacheFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"id":"` + request.ConnectorID + `"`,
		`"request_nonce":"` + request.RequestNonce + `"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("native request was dispatched before %s was durable: %s", want, raw)
		}
	}
	if request.ExpectedResourceID != "" && !strings.Contains(string(raw), `"expected_resource_id":"`+request.ExpectedResourceID+`"`) {
		t.Fatalf("native continuity assertion was not durable before dispatch: %s", raw)
	}
}

func TestNativeConnectorResolutionReplaysExactRequestAfterLostResponse(t *testing.T) {
	stateDir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(stateDir); err != nil {
		t.Fatal(err)
	}
	var requests []qurl.NativeConnectorResourceRequest
	resolve := func(_ context.Context, _ *qurl.AgentRuntimeBinding, request *qurl.NativeConnectorResourceRequest, _ ...qurl.AgentRuntimeUDPOption) (*qurl.ConnectorResourceResolution, error) {
		assertNativeRequestWasDurableBeforeDispatch(t, stateDir, request)
		requests = append(requests, copyNativeConnectorRequest(request))
		if len(requests) == 1 {
			// Model a committed cell response that was lost in transit. The client
			// cannot distinguish it from an unavailable result and must preserve
			// the exact nonce across a process restart.
			return nil, qurl.ErrConnectorResourceUnavailable
		}
		return &qurl.ConnectorResourceResolution{
			Resource: testConnectorResourceBinding("web", testPublicResourceID),
		}, nil
	}

	first := managedNativeTestConfig("web")
	err := resolveConnectorIdentities(context.Background(), first, &qurl.AgentRuntimeBinding{}, nil, stateDir, testConnectorCacheAgentID, nil, resolve)
	if !errors.Is(err, qurl.ErrConnectorResourceUnavailable) {
		t.Fatalf("first resolution error = %v, want unavailable", err)
	}
	cache, err := loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if !cache.isPending("web") {
		t.Fatal("lost response cleared the exact replay request")
	}

	// A new config object models a fresh process. Only the durable cache carries
	// the original request nonce into the retry.
	restarted := managedNativeTestConfig("web")
	if err := resolveConnectorIdentities(context.Background(), restarted, &qurl.AgentRuntimeBinding{}, nil, stateDir, testConnectorCacheAgentID, nil, resolve); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || requests[0] != requests[1] {
		t.Fatalf("restart request changed: first=%#v second=%#v", requests[0], requests[1])
	}
	cache, err = loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	binding, present := cache.binding("web")
	if !present || cache.isPending("web") {
		t.Fatalf("completed replay cache binding=%#v present=%v pending=%v", binding, present, cache.isPending("web"))
	}
	if restarted.Routes[0].ResourceID != testPublicResourceID || restarted.Routes[0].ConnectorRoutingID != testConnectorRoutingID {
		t.Fatalf("restarted route binding = %#v", restarted.Routes[0])
	}
}

func TestNativeConnectorWarmContinuityUsesFreshNonceAndExactResource(t *testing.T) {
	stateDir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(stateDir); err != nil {
		t.Fatal(err)
	}
	var requests []qurl.NativeConnectorResourceRequest
	resolve := func(_ context.Context, _ *qurl.AgentRuntimeBinding, request *qurl.NativeConnectorResourceRequest, _ ...qurl.AgentRuntimeUDPOption) (*qurl.ConnectorResourceResolution, error) {
		assertNativeRequestWasDurableBeforeDispatch(t, stateDir, request)
		requests = append(requests, copyNativeConnectorRequest(request))
		return &qurl.ConnectorResourceResolution{
			Resource:      testConnectorResourceBinding("web", testPublicResourceID),
			FoundExisting: len(requests) > 1,
		}, nil
	}

	if err := resolveConnectorIdentities(context.Background(), managedNativeTestConfig("web"), &qurl.AgentRuntimeBinding{}, nil, stateDir, testConnectorCacheAgentID, nil, resolve); err != nil {
		t.Fatal(err)
	}
	warm := managedNativeTestConfig("web")
	if err := resolveConnectorIdentities(context.Background(), warm, &qurl.AgentRuntimeBinding{}, nil, stateDir, testConnectorCacheAgentID, nil, resolve); err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 {
		t.Fatalf("native requests = %d, want 2", len(requests))
	}
	if requests[0].ExpectedResourceID != "" {
		t.Fatalf("cold request expected_resource_id = %q, want absent", requests[0].ExpectedResourceID)
	}
	if requests[1].ExpectedResourceID != testPublicResourceID {
		t.Fatalf("warm request expected_resource_id = %q", requests[1].ExpectedResourceID)
	}
	if requests[0].RequestNonce == requests[1].RequestNonce {
		t.Fatal("a completed operation reused its nonce for a fresh continuity read")
	}
	if warm.Routes[0].ResourceID != testPublicResourceID || warm.Routes[0].ConnectorRoutingID != testConnectorRoutingID {
		t.Fatalf("warm route = %#v", warm.Routes[0])
	}
	if got := warm.KnockResourceID(testPublicResourceID); got != "cell-resource" {
		t.Fatalf("warm knock_resource_id = %q", got)
	}
}

func TestNativeConnectorMultiRoutePersistsCompleteSharedKnockBindings(t *testing.T) {
	stateDir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(stateDir); err != nil {
		t.Fatal(err)
	}
	var order []string
	resolve := func(_ context.Context, _ *qurl.AgentRuntimeBinding, request *qurl.NativeConnectorResourceRequest, _ ...qurl.AgentRuntimeUDPOption) (*qurl.ConnectorResourceResolution, error) {
		assertNativeRequestWasDurableBeforeDispatch(t, stateDir, request)
		order = append(order, request.ConnectorID)
		resourceID := testPublicResourceID
		if request.ConnectorID == "api" {
			resourceID = testPublicResourceID2
		}
		return &qurl.ConnectorResourceResolution{Resource: testConnectorResourceBinding(request.ConnectorID, resourceID)}, nil
	}
	cfg := managedNativeTestConfig("web", "api")
	if err := resolveConnectorIdentities(context.Background(), cfg, &qurl.AgentRuntimeBinding{}, nil, stateDir, testConnectorCacheAgentID, nil, resolve); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "web,api" {
		t.Fatalf("native request order = %v", order)
	}
	cache, err := loadConnectorIdentityCache(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range order {
		binding, ok := cache.binding(id)
		if !ok || binding.ConnectorRoutingID == "" || binding.KnockResourceID != "cell-resource" || cache.isPending(id) {
			t.Fatalf("binding %q = %#v present=%v pending=%v", id, binding, ok, cache.isPending(id))
		}
	}
}

func TestNativeConnectorRoutingPinConflictRetainsAuthenticatedBinding(t *testing.T) {
	stateDir := newIdentityCacheTestDir(t)
	if err := ensureConnectorIdentityCacheInitialized(stateDir); err != nil {
		t.Fatal(err)
	}
	cfg := managedNativeTestConfig("web")
	cfg.Routes[0].ConnectorRoutingID = testConnectorRoutingID2
	resolve := func(_ context.Context, _ *qurl.AgentRuntimeBinding, request *qurl.NativeConnectorResourceRequest, _ ...qurl.AgentRuntimeUDPOption) (*qurl.ConnectorResourceResolution, error) {
		assertNativeRequestWasDurableBeforeDispatch(t, stateDir, request)
		return &qurl.ConnectorResourceResolution{Resource: testConnectorResourceBinding("web", testPublicResourceID)}, nil
	}
	err := resolveConnectorIdentities(context.Background(), cfg, &qurl.AgentRuntimeBinding{}, nil, stateDir, testConnectorCacheAgentID, nil, resolve)
	if err == nil || !strings.Contains(err.Error(), "configured connector_routing_id") || !strings.Contains(err.Error(), "retained for explicit cleanup") {
		t.Fatalf("resolution error = %v, want retained routing-pin conflict", err)
	}
	cache, loadErr := loadConnectorIdentityCache(stateDir)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	binding, ok := cache.binding("web")
	if !ok || binding.ConnectorRoutingID != testConnectorRoutingID || cache.isPending("web") {
		t.Fatalf("retained binding = %#v present=%v pending=%v", binding, ok, cache.isPending("web"))
	}
	if cfg.Routes[0].ConnectorRoutingID != testConnectorRoutingID2 {
		t.Fatalf("conflicting operator pin was silently overwritten: %#v", cfg.Routes[0])
	}
}
