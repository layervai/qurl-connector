package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

const validTestHubPublicKeyB64 = "CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func realPrivateConnectorTestDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestConnectorHubBootstrapUsesCompletePinnedOverride(t *testing.T) {
	_, publicKey := runtimeTestKeypair(t)
	t.Setenv(envHubHost, "hub.example.com")
	t.Setenv(envHubPort, "443")
	t.Setenv(envHubServerPublicKey, base64.StdEncoding.EncodeToString(publicKey))
	hub, err := connectorHubBootstrap()
	if err != nil {
		t.Fatal(err)
	}
	if hub.Host != "hub.example.com" || hub.Port != 443 || hub.ServerPublicKeyB64 == "" {
		t.Fatalf("hub override = %+v", hub)
	}
}

func TestConnectorHubBootstrapRejectsPartialOrMalformedOverride(t *testing.T) {
	for _, test := range []struct {
		name string
		host string
		port string
		key  string
	}{
		{name: "partial", host: "hub.example.com"},
		{name: "IP host", host: "127.0.0.1", port: "443", key: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{name: "noncanonical port", host: "hub.example.com", port: "0443", key: base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{name: "short key", host: "hub.example.com", port: "443", key: base64.StdEncoding.EncodeToString(make([]byte, 31))},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(envHubHost, test.host)
			t.Setenv(envHubPort, test.port)
			t.Setenv(envHubServerPublicKey, test.key)
			if _, err := connectorHubBootstrap(); err == nil {
				t.Fatal("malformed Hub override was accepted")
			}
		})
	}
}

func TestDefaultHubPinRemainsUnprovisionedInSource(t *testing.T) {
	if defaultHubServerPublicKeyB64 != "" {
		t.Fatal("source embeds a production Hub key instead of release-time injection")
	}
}

func TestConnectorNativeSessionAuthorityUsesAuthenticatedOwner(t *testing.T) {
	t.Setenv(envNativeOwnerID, "owner-one")
	authority, err := connectorNativeSessionAuthority()
	if err != nil {
		t.Fatal(err)
	}
	if authority.OwnerID != "owner-one" {
		t.Fatalf("native session authority = %#v", authority)
	}
}

func TestConnectorNativeRuntimeConfigWiresSessionAuthority(t *testing.T) {
	t.Setenv(envHubHost, "hub.example.test")
	t.Setenv(envHubPort, "443")
	t.Setenv(envHubServerPublicKey, validTestHubPublicKeyB64)
	t.Setenv(envNativeOwnerID, "owner-one")
	config, err := connectorNativeRuntimeConfig(&nhpconfig.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if config.SessionOperations.OwnerID != "owner-one" {
		t.Fatalf("native runtime session authority = %#v", config.SessionOperations)
	}
}

func TestConnectorNativeSessionAuthorityRejectsMissingOwner(t *testing.T) {
	if _, err := connectorNativeSessionAuthority(); err == nil || !strings.Contains(err.Error(), "owner ID") {
		t.Fatalf("ownerless native session authority = %v", err)
	}
}

func TestRegistrationRefreshModeIsAutomaticByDefault(t *testing.T) {
	t.Setenv(envRefreshMode, "")
	mode, err := registrationRefreshMode()
	if err != nil || mode != "auto" {
		t.Fatalf("default refresh mode = %q, %v", mode, err)
	}
	t.Setenv(envRefreshMode, "disabled")
	mode, err = registrationRefreshMode()
	if err != nil || mode != "disabled" {
		t.Fatalf("diagnostic disabled mode = %q, %v", mode, err)
	}
	t.Setenv(envRefreshMode, "manual")
	if _, err := registrationRefreshMode(); err == nil {
		t.Fatal("retired manual refresh mode was accepted")
	}
}

func TestNormalizeRuntimeHostnamePreservesUTF8Boundaries(t *testing.T) {
	host := strings.Repeat("a", 254) + "é"
	got := normalizeRuntimeHostname(host)
	if len(got) > 255 || !utf8.ValidString(got) {
		t.Fatalf("normalized hostname is invalid: length=%d", len(got))
	}
	if got := normalizeRuntimeHostname(string([]byte{0xff})); got != "qurl-connector" {
		t.Fatalf("invalid UTF-8 fallback = %q", got)
	}
}

func TestClientVersionMetadataDropsBuildTimestamp(t *testing.T) {
	if got := clientVersionMeta("v0.5.1.260617"); got != "v0.5.1" {
		t.Fatalf("client version = %q", got)
	}
	if got := clientVersionMeta(" "); got != "dev" {
		t.Fatalf("empty client version = %q", got)
	}
}

func runtimeTestKeypair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	privateKey := make([]byte, 32)
	privateKey[0] = 7
	private, err := ecdh.X25519().NewPrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, private.PublicKey().Bytes()
}

func provisionedDefaultHubPinForTest(t *testing.T) string {
	t.Helper()
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
	previous := defaultHubServerPublicKeyB64
	defaultHubServerPublicKeyB64 = encoded
	t.Cleanup(func() { defaultHubServerPublicKeyB64 = previous })
	return encoded
}

func TestMainSourceDoesNotReintroduceManualRefreshApproval(t *testing.T) {
	data, err := os.ReadFile("run.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"explicit approval", "already attempted", "refresh-mode manual"} {
		if strings.Contains(strings.ToLower(string(data)), forbidden) {
			t.Fatalf("runtime source contains retired customer refresh contract %q", forbidden)
		}
	}
}
