package share

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"golang.org/x/net/websocket"
)

func TestHermeticGroupRotationPreservesOriginalStream(t *testing.T) {
	testHermeticGroupRotationOriginalStream(t, false, false)
}

func TestHermeticGroupRotationRevokesOriginalStream(t *testing.T) {
	testHermeticGroupRotationOriginalStream(t, true, false)
}

func TestHermeticGroupDrainDeadlineKeepsReplacementServing(t *testing.T) {
	testHermeticGroupRotationOriginalStream(t, false, true)
}

func testHermeticGroupRotationOriginalStream(t *testing.T, revoke, expire bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/socket" {
			websocket.Handler(func(ws *websocket.Conn) {
				defer ws.Close()
				ticker := time.NewTicker(50 * time.Millisecond)
				defer ticker.Stop()
				for range ticker.C {
					if err := websocket.Message.Send(ws, "tick"); err != nil {
						return
					}
				}
			}).ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/events" {
			_, _ = io.WriteString(w, "ok")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
				if _, err := fmt.Fprintln(w, "data: tick"); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	}))
	t.Cleanup(backend.Close)
	port := reserveHermeticPort(t)
	plugin := newHermeticQRTSPlugin(t)
	frps := startHermeticFRPS(t, port, port, "example.test", plugin.server.URL)
	t.Cleanup(func() { _ = frps.Close() })
	common := &v1.ClientCommonConfig{}
	common.Log.Level = "error"
	falseValue := false
	common.Transport.TLS.Enable = &falseValue
	if err := common.Complete(); err != nil {
		t.Fatal(err)
	}
	factory, err := NewFRPSessionGroupFactory(FRPGroupFactoryConfig{Common: common, ReadyPoll: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	route := LocalHTTPRoute{RouteID: "stream", LocalIP: "127.0.0.1", LocalPort: backend.Listener.Addr().(*net.TCPAddr).Port,
		ResourcePublicKey: "resource-stream", ConnectorRoutingID: "routing-stream"}
	start := func(id uint64) GroupServingSession {
		t.Helper()
		admission := groupTestAdmission(id)
		admission.RunID = fmt.Sprintf("%016x", id)
		admission.Token = fmt.Sprintf("test-token-%d", id)
		admission.SessionReceipt = testSessionReceipt(id, admission.RunID, 1)
		admission.ResourceHost = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		session, startErr := factory.Start(ctx, admission, groupRoutesOf([]LocalHTTPRoute{route}))
		if startErr != nil {
			t.Fatal(startErr)
		}
		t.Cleanup(func() {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
			defer stopCancel()
			_ = session.Stop(stopCtx)
		})
		select {
		case <-session.Ready():
		case <-session.Done():
			t.Fatalf("session ended before serving: %v", session.Err())
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		return session
	}
	original := start(101)
	client, transport := newProofClient()
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "routing-stream.example.test"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("original stream response = %d %q", response.StatusCode, response.Header.Get("Content-Type"))
	}
	reader := bufio.NewReader(response.Body)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	wsConfig, err := websocket.NewConfig("ws://"+request.Host+"/socket", "http://"+request.Host)
	if err != nil {
		t.Fatal(err)
	}
	wsTransport, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer wsTransport.Close()
	_ = wsTransport.SetDeadline(time.Now().Add(15 * time.Second))
	ws, err := websocket.NewClient(wsConfig, wsTransport)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	var tick string
	if err := websocket.Message.Receive(ws, &tick); err != nil {
		t.Fatal(err)
	}
	_ = start(102)
	if _, err := reader.ReadString('\n'); err != nil {
		t.Fatalf("original stream ended before drain: %v", err)
	}
	if expire {
		drains := cycleDrainSet{changed: make(chan struct{}, 1)}
		retired := make(chan struct{})
		if err := drains.start(original, time.Now().Add(200*time.Millisecond), time.Second, func() error { close(retired); return nil }); err != nil {
			t.Fatal(err)
		}
		defer drains.cancel()
		select {
		case <-drains.changed:
		case <-ctx.Done():
			t.Fatal("deadline did not close original work")
		}
		if err := drains.stopAndWait(time.Second); err != nil {
			t.Fatalf("real FRP deadline was not a benign drain result: %v", err)
		}
		select {
		case <-retired:
		default:
			t.Fatal("original admission was not retired")
		}
		for {
			if _, err := reader.ReadString('\n'); err != nil {
				break
			}
			if ctx.Err() != nil {
				t.Fatal("original SSE outlived drain deadline")
			}
		}
		for {
			if err := websocket.Message.Receive(ws, &tick); err != nil {
				break
			}
			if ctx.Err() != nil {
				t.Fatal("original WebSocket outlived drain deadline")
			}
		}
		if status, body, err := proofGet(client, port, request.Host); err != nil || status != http.StatusOK || body != "ok" {
			t.Fatalf("original deadline interrupted replacement: %d %q %v", status, body, err)
		}
		return
	}
	drained := make(chan error, 1)
	go func() { drained <- original.(drainingSession).Drain(ctx) }()
	if status, body, err := proofGet(client, port, request.Host); err != nil || status != http.StatusOK || body != "ok" {
		t.Fatalf("replacement did not serve new requests: %d %q %v", status, body, err)
	}
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := reader.ReadString('\n'); err != nil {
			t.Fatalf("original stream ended after replacement began draining: %v", err)
		}
		if err := websocket.Message.Receive(ws, &tick); err != nil {
			t.Fatalf("original WebSocket ended during drain: %v", err)
		}
	}
	if revoke {
		original.(*frpGroupSession).retainDrainedRoutes(nil)
		for {
			if _, err := reader.ReadString('\n'); err != nil {
				break
			}
			if ctx.Err() != nil {
				t.Fatal("revoked original stream remained open")
			}
		}
		if status, body, err := proofGet(client, port, request.Host); err != nil || status != http.StatusOK || body != "ok" {
			t.Fatalf("original revocation interrupted replacement: %d %q %v", status, body, err)
		}
	}
	if revoke {
		for {
			if err := websocket.Message.Receive(ws, &tick); err != nil {
				break
			}
			if ctx.Err() != nil {
				t.Fatal("revoked original WebSocket remained open")
			}
		}
	}
	_ = ws.Close()
	_ = response.Body.Close()
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("drain failed after original stream closed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle old control did not finish draining")
	}
}
