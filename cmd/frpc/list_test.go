package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/layervai/qurl-connector/pkg/agentstate"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func TestRunListEmptyPromptSaysConfigure(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "missing-qurl-proxy.yaml")
	previousCfgFile, previousJSON := cfgFile, listJSON
	cfgFile, listJSON = cfgPath, false
	t.Cleanup(func() { cfgFile, listJSON = previousCfgFile, previousJSON })
	out, err := withCapturedStdout(t, func() error { return runList(nil, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "configure a service") || strings.Contains(out, "register a service") {
		t.Fatalf("empty list guidance = %q", out)
	}
}

func TestRunListHumanHydratesCachedResourceIDReadOnly(t *testing.T) {
	dir := realPrivateConnectorTestDir(t)
	stateDir := filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(agentstate.EnvStateDirPrimary, stateDir)
	seedConnectorIdentityCacheForTest(t, stateDir, "web", testPublicResourceID)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	raw := []byte("routes:\n  - id: web\n    type: http\n    local_ip: 127.0.0.1\n    local_port: 8080\n")
	if err := os.WriteFile(cfgPath, raw, 0o400); err != nil {
		t.Fatal(err)
	}

	previousCfgFile, previousJSON := cfgFile, listJSON
	cfgFile, listJSON = cfgPath, false
	t.Cleanup(func() { cfgFile, listJSON = previousCfgFile, previousJSON })
	out, err := withCapturedStdout(t, func() error { return runList(nil, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, testPublicResourceID) {
		t.Fatalf("human list omitted cached resource_id:\n%s", out)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(raw) {
		t.Fatalf("list mutated YAML: got %q want %q", after, raw)
	}
}

func TestRunListJSONEmitsSnakeCaseRouteFields(t *testing.T) {
	dir := t.TempDir()
	isolateConnectorStateForTest(t, dir)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  addr: boundary.example.com
  port: 7000
  protocol: tcp
routes:
  - id: web
    type: http
    local_ip: 127.0.0.1
    local_port: 8080
    resource_id: `+testPublicResourceID+`
    connector_routing_id: c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    target_url: http://127.0.0.1:8080
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevCfgFile := cfgFile
	prevListJSON := listJSON
	cfgFile = cfgPath
	listJSON = true
	t.Cleanup(func() {
		cfgFile = prevCfgFile
		listJSON = prevListJSON
	})

	out, err := withCapturedStdout(t, func() error {
		return runList(nil, nil)
	})
	if err != nil {
		t.Fatalf("runList returned error: %v", err)
	}

	var routes []map[string]any
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		t.Fatalf("list JSON did not parse: %v\noutput:\n%s", err, out)
	}
	if len(routes) != 1 {
		t.Fatalf("routes length = %d, want 1", len(routes))
	}
	got := routes[0]
	for _, key := range []string{"id", "type", "local_ip", "local_port", "resource_id", "connector_routing_id", "target_url"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("list --json missing lower-snake key %q in %#v", key, got)
		}
	}
	if _, ok := got["subdomain"]; ok {
		t.Fatalf("canonical managed route must not synthesize a legacy subdomain in list --json: %#v", got)
	}
	for _, key := range []string{"Name", "ID", "Type", "LocalIP", "LocalPort", "Subdomain", "ResourceID", "TargetURL"} {
		if _, ok := got[key]; ok {
			t.Fatalf("list --json emitted legacy/PascalCase key %q in %#v", key, got)
		}
	}
	if got["id"] != "web" {
		t.Fatalf("id = %v, want web", got["id"])
	}
}

func TestRoutePublicLabelKeepsManagedAndCustomIdentitiesSeparate(t *testing.T) {
	tests := []struct {
		name  string
		route nhpconfig.Route
		want  string
	}{
		{
			name: "managed route does not expose internal routing label",
			route: nhpconfig.Route{
				ResourceID:         testPublicResourceID,
				ConnectorRoutingID: testConnectorRoutingID,
			},
			want: "",
		},
		{
			name: "managed route missing producer routing identity fails closed",
			route: nhpconfig.Route{
				ResourceID: testPublicResourceID,
				Subdomain:  "stale-client-label",
			},
			want: "",
		},
		{
			name:  "custom FRP route retains explicit subdomain",
			route: nhpconfig.Route{Subdomain: "custom-label"},
			want:  "custom-label",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := routePublicLabel(tc.route); got != tc.want {
				t.Fatalf("routePublicLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRunListDoesNotExposeManagedRoutingIdentityAsPublicURL(t *testing.T) {
	dir := t.TempDir()
	isolateConnectorStateForTest(t, dir)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  public_domain: connector.example
routes:
  - id: managed
    type: http
    local_ip: 127.0.0.1
    local_port: 8080
    resource_id: `+testPublicResourceID+`
    connector_routing_id: `+testConnectorRoutingID+`
  - id: stale-managed
    type: http
    local_ip: 127.0.0.1
    local_port: 8081
    subdomain: stale-client-label
    resource_id: `+testPublicResourceID2+`
  - id: custom
    type: http
    local_ip: 127.0.0.1
    local_port: 8082
    subdomain: custom-label
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevCfgFile := cfgFile
	prevListJSON := listJSON
	cfgFile = cfgPath
	listJSON = false
	t.Cleanup(func() {
		cfgFile = prevCfgFile
		listJSON = prevListJSON
	})

	out, err := withCapturedStdout(t, func() error { return runList(nil, nil) })
	if err != nil {
		t.Fatalf("runList returned error: %v", err)
	}
	if strings.Contains(out, "https://"+testConnectorRoutingID+".connector.example") {
		t.Fatalf("managed route exposed internal routing identity as a public URL:\n%s", out)
	}
	if strings.Contains(out, "https://stale-client-label.connector.example") {
		t.Fatalf("managed route fell back to stale subdomain:\n%s", out)
	}
	if !strings.Contains(out, "https://custom-label.connector.example") {
		t.Fatalf("custom route lost explicit subdomain:\n%s", out)
	}
}

func TestRunListJSONUsesIDFromSingleEnvFallbackRoute(t *testing.T) {
	dir := t.TempDir()
	isolateConnectorStateForTest(t, dir)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  addr: boundary.example.com
  port: 7000
  protocol: tcp
routes:
  - type: http
    local_ip: 127.0.0.1
    local_port: 8080
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(envConnectorID, "env-supplied")

	prevCfgFile := cfgFile
	prevListJSON := listJSON
	cfgFile = cfgPath
	listJSON = true
	t.Cleanup(func() {
		cfgFile = prevCfgFile
		listJSON = prevListJSON
	})

	out, err := withCapturedStdout(t, func() error {
		return runList(nil, nil)
	})
	if err != nil {
		t.Fatalf("runList returned error: %v", err)
	}

	var routes []map[string]any
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		t.Fatalf("list JSON did not parse: %v\noutput:\n%s", err, out)
	}
	if len(routes) != 1 {
		t.Fatalf("routes length = %d, want 1", len(routes))
	}
	id, ok := routes[0]["id"]
	if !ok {
		t.Fatalf("list --json omitted id key for single-route QURL_CONNECTOR_ID fallback config: %#v", routes[0])
	}
	if id != "env-supplied" {
		t.Fatalf("id = %v, want env-supplied", id)
	}
}

func TestRunListJSONMissingConfigEmitsEmptyArray(t *testing.T) {
	prevCfgFile := cfgFile
	prevListJSON := listJSON
	cfgFile = filepath.Join(t.TempDir(), "missing.yaml")
	listJSON = true
	t.Cleanup(func() {
		cfgFile = prevCfgFile
		listJSON = prevListJSON
	})

	out, err := withCapturedStdout(t, func() error {
		return runList(nil, nil)
	})
	if err != nil {
		t.Fatalf("runList returned error: %v", err)
	}
	var routes []map[string]any
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		t.Fatalf("list JSON did not parse: %v\noutput:\n%s", err, out)
	}
	if len(routes) != 0 {
		t.Fatalf("routes length = %d, want 0", len(routes))
	}
}

func TestRunListJSONNoRoutesEmitsEmptyArray(t *testing.T) {
	dir := t.TempDir()
	isolateConnectorStateForTest(t, dir)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  addr: boundary.example.com
  port: 7000
  protocol: tcp
routes: []
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	prevCfgFile := cfgFile
	prevListJSON := listJSON
	cfgFile = cfgPath
	listJSON = true
	t.Cleanup(func() {
		cfgFile = prevCfgFile
		listJSON = prevListJSON
	})

	out, err := withCapturedStdout(t, func() error {
		return runList(nil, nil)
	})
	if err != nil {
		t.Fatalf("runList returned error: %v", err)
	}
	var routes []map[string]any
	if err := json.Unmarshal([]byte(out), &routes); err != nil {
		t.Fatalf("list JSON did not parse: %v\noutput:\n%s", err, out)
	}
	if len(routes) != 0 {
		t.Fatalf("routes length = %d, want 0", len(routes))
	}
}
