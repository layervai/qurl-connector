package share

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// Exercise the actual TLS connection, NewProxy registration and HTTP request
// path. Fake session tests alone cannot establish that the origin gets the token.
func TestHermeticRuntimeHeadersReachOnlyTheirOrigin(t *testing.T) {
	testHermeticRuntimeHeadersReachOnlyTheirOrigin(t, false)
}

func TestHermeticUnixOriginHeadersAndMissingOrigin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file origin is not supported on Windows")
	}
	testHermeticRuntimeHeadersReachOnlyTheirOrigin(t, true)
}

func testHermeticRuntimeHeadersReachOnlyTheirOrigin(t *testing.T, unixOrigin bool) {
	certificate := httptest.NewTLSServer(http.NotFoundHandler())
	pair := certificate.TLS.Certificates[0]
	certificate.Close()
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	for path, block := range map[string]*pem.Block{
		certPath: {Type: "CERTIFICATE", Bytes: pair.Certificate[0]},
		keyPath:  {Type: "PRIVATE KEY", Bytes: key},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var expected atomic.Value
	expected.Store("first-token")
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(testProxyTokenHeader) != expected.Load().(string) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, "protected-file")
	}))
	var socketPath string
	if unixOrigin {
		socketDir, err := os.MkdirTemp("/tmp", "qo-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
		socketPath = filepath.Join(socketDir, "f.sock")
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatal(err)
		}
		_ = origin.Listener.Close()
		origin.Listener = listener
	}
	origin.Start()
	defer origin.Close()
	sibling := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(testProxyTokenHeader) != "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_, _ = io.WriteString(w, "sibling")
	}))
	defer sibling.Close()
	originClient := &http.Client{Timeout: time.Second}
	originURL := origin.URL
	if unixOrigin {
		originURL = "http://localhost/"
		originClient.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}}
	}
	response, err := originClient.Get(originURL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatal("origin accepted a request without its token")
	}
	port := reserveHermeticPort(t)
	plugin := newHermeticQRTSPlugin(t)
	serverConfig := hermeticFRPSConfig(port, port, "example.test", plugin.server.URL)
	serverConfig.Transport.TLS.CertFile = certPath
	serverConfig.Transport.TLS.KeyFile = keyPath
	server := startHermeticFRPSFromConfig(t, serverConfig)
	defer func() { _ = server.Close() }()
	common := &v1.ClientCommonConfig{}
	enabled := true
	common.Transport.TLS.Enable = &enabled
	common.Transport.TLS.TrustedCaFile = certPath
	common.Transport.TLS.ServerName = "example.com" // httptest's certificate name
	common.Log.Level = "error"
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	factory, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{Common: common, ReadyPoll: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	admission := groupTestAdmission(101)
	admission.ResourceHost = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	admission.OpenTime = 5 * time.Minute
	admitter := &hermeticAdmitter{admissions: []Admission{admission}}
	routes := groupTestRoutes("alpha", "beta")
	if unixOrigin {
		routes[0].LocalSocketPath = socketPath
		routes[0].LocalIP, routes[0].LocalPort = "", 0
	} else {
		routes[0].LocalPort = origin.Listener.Addr().(*net.TCPAddr).Port
	}
	routes[0].RequestHeaders = map[string]string{testProxyTokenHeader: "first-token"}
	routes[1].LocalPort = sibling.Listener.Addr().(*net.TCPAddr).Port
	// Unknown issuers and wrong names must fail before any route can serve.
	for _, unknownIssuer := range []bool{true, false} {
		wrongName := cloneCommon(common)
		if unknownIssuer {
			wrongName.Transport.TLS.TrustedCaFile = ""
		} else {
			wrongName.Transport.TLS.ServerName = "untrusted.example.test"
		}
		untrusted, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{Common: wrongName})
		if err != nil {
			t.Fatal(err)
		}
		session, err := untrusted.Start(context.Background(), admission, groupRoutesOf(routes))
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-session.Done():
			if session.Err() == nil {
				t.Fatal("untrusted TLS session ended without an error")
			}
			for _, state := range session.RouteStates() {
				if state.Phase == RouteServing {
					t.Fatal("untrusted TLS session registered a route")
				}
			}
		case <-session.Ready():
			t.Fatal("untrusted TLS session served a route")
		case <-time.After(5 * time.Second):
			t.Fatal("untrusted TLS session did not fail")
		}
	}
	runner, err := NewSessionGroupRunner(SessionGroupConfig{
		KnockResourceID: admission.KnockResourceID, ResourcePublicKey: admission.ResourcePublicKey,
		Routes: routes, Admitter: admitter, Sessions: factory,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- runner.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-result:
		case <-time.After(10 * time.Second):
			t.Error("header session did not stop")
		}
	}()
	assertProtectedRequest := func() {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "routing-alpha.example.test"
		request.Header.Set(testProxyTokenHeader, "forged-client-token")
		client := &http.Client{Timeout: time.Second}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || string(body) != "protected-file" {
			t.Fatalf("protected request did not use the configured token: status=%d read=%v", response.StatusCode, readErr)
		}
	}
	pollHermeticRoute(t, port, "routing-alpha.example.test", "protected-file", result)
	assertProtectedRequest()
	pollHermeticRoute(t, port, "routing-beta.example.test", "sibling", result)
	expected.Store("replacement-token")
	routes[0].RequestHeaders = map[string]string{testProxyTokenHeader: "replacement-token"}
	if err := runner.SetRoutes(ctx, routes); err != nil {
		t.Fatal(err)
	}
	pollHermeticRoute(t, port, "routing-alpha.example.test", "protected-file", result)
	pollHermeticRoute(t, port, "routing-beta.example.test", "sibling", result)
	// After registration converges, every request must use the replacement.
	// Do not retry through a stale proxy's unauthorized response here.
	for range 10 {
		assertProtectedRequest()
	}
	if unixOrigin {
		origin.Close()
		request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "routing-alpha.example.test"
		response, err := (&http.Client{Timeout: time.Second}).Do(request)
		if err == nil {
			body, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK || string(body) == "protected-file" {
				t.Fatal("missing Unix origin still serves")
			}
		}
		pollHermeticRoute(t, port, "routing-beta.example.test", "sibling", result)
	}
	if got := admitter.admissionCount(); got != 1 {
		t.Fatalf("token replacement used %d admissions, want one", got)
	}
}
