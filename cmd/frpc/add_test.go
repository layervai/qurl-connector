package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func TestRunAddIsLocalAndDefersResourceProvisioning(t *testing.T) {
	dir := t.TempDir()
	oldTarget, oldID, oldNoVerify, oldConfig := addTarget, addID, addNoVerify, cfgFile
	t.Cleanup(func() {
		addTarget, addID, addNoVerify, cfgFile = oldTarget, oldID, oldNoVerify, oldConfig
	})
	addTarget = "http://127.0.0.1:18080"
	addID = "customer-web"
	addNoVerify = true
	cfgFile = filepath.Join(dir, "qurl-proxy.yaml")
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvAPIKeyFile, "")

	if err := runAdd(nil, nil); err != nil {
		t.Fatalf("runAdd without enrollment credential: %v", err)
	}
	cfg, err := nhpconfig.Load(cfgFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].ID != addID {
		t.Fatalf("routes = %#v", cfg.Routes)
	}
	if cfg.Routes[0].ResourceID != "" || cfg.Routes[0].ConnectorRoutingID != "" {
		t.Fatalf("add provisioned remote identity before native registration: %#v", cfg.Routes[0])
	}
	if _, err := os.Stat(filepath.Join(dir, "agent_state.json")); !os.IsNotExist(err) {
		t.Fatalf("add mutated SDK agent state: %v", err)
	}
}

func TestConcurrentAddTransactionsPreserveBothRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl-proxy.yaml")
	routes := []nhpconfig.Route{
		{ID: "first-route", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 18081},
		{ID: "second-route", Type: nhpconfig.RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 18082},
	}

	start := make(chan struct{})
	errs := make(chan error, len(routes))
	var ready sync.WaitGroup
	ready.Add(len(routes))
	for _, route := range routes {
		route := route
		go func() {
			ready.Done()
			<-start
			_, err := addRouteToConfig(context.Background(), path, route, "")
			errs <- err
		}()
	}
	ready.Wait()
	close(start)
	for range routes {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent add: %v", err)
		}
	}

	cfg, err := nhpconfig.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != len(routes) {
		t.Fatalf("routes = %#v, want both concurrent additions", cfg.Routes)
	}
	got := map[string]bool{}
	for _, route := range cfg.Routes {
		got[route.ID] = true
	}
	for _, route := range routes {
		if !got[route.ID] {
			t.Fatalf("routes = %#v, missing %q", cfg.Routes, route.ID)
		}
	}
}
