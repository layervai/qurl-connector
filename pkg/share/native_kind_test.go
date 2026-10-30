package share

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
	"github.com/layervai/qurl-go/relayknock"
	"github.com/layervai/qurl-go/relayknock/relayknocktest"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

func TestNativeRegistrationKindInvalidBeforeState(t *testing.T) {
	for _, kind := range []qurl.RegistrationKeyKind{qurl.RegistrationKeyKindAccount, qurl.RegistrationKeyKindAgent, "unknown", " bootstrap"} {
		t.Run(string(kind), func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "must-not-exist")
			_, err := OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
				StateDir: dir, RequiredRegistrationKeyKind: kind,
				EnrollmentCredentialProvider: func(context.Context, qurl.AgentEnrollmentCredentialRequest) (string, error) {
					t.Error("invalid policy read credential")
					return "", errors.New("unexpected credential read")
				},
			})
			if !errors.Is(err, qurl.ErrInvalidRegisterConfig) {
				t.Fatalf("invalid policy: %v", err)
			}
			if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid policy touched state: %v", err)
			}
		})
	}
}

func TestNativeRegistrationExactKindBeforeREGAndRetry(t *testing.T) {
	for _, required := range []qurl.RegistrationKeyKind{qurl.RegistrationKeyKindBootstrap, qurl.RegistrationKeyKindConnectorBootstrap} {
		t.Run(string(required), func(t *testing.T) {
			fixture := newNativeKindFixture(t)
			other := qurl.RegistrationKeyKindBootstrap
			if required == other {
				other = qurl.RegistrationKeyKindConnectorBootstrap
			}
			fixture.kind.Store(string(other))
			cfg := fixture.config
			cfg.RequiredRegistrationKeyKind = required
			_, err := OpenNativeRuntime(context.Background(), cfg)
			if !errors.Is(err, qurl.ErrRegistrationKeyKindDisallowed) {
				t.Fatalf("mismatched kind: %v", err)
			}
			if strings.Contains(err.Error(), cfg.EnrollmentCredential) {
				t.Fatal("error leaked credential")
			}
			before := fixture.load(t)
			if before.RegisteredAt != nil || before.Assignment != nil || before.PendingActivation != nil || before.PendingCompletion != nil || before.DeviceAPIKey != "" {
				t.Fatal("mismatch persisted registration progress")
			}
			if fixture.hub.Load() != 1 || fixture.reg.Load() != 0 || fixture.completion.Load() != 0 {
				t.Fatalf("mismatch requests: hub=%d reg=%d completion=%d", fixture.hub.Load(), fixture.reg.Load(), fixture.completion.Load())
			}
			fixture.kind.Store(string(required))
			runtime, err := OpenNativeRuntime(context.Background(), cfg)
			if err != nil {
				t.Fatalf("retry: %v", err)
			}
			runtime.Binding.Destroy()
			if err := runtime.store.Close(); err != nil {
				t.Fatal(err)
			}
			after := fixture.load(t)
			if after.AgentID != before.AgentID || after.PublicKeyB64 != before.PublicKeyB64 || after.RegisteredAt == nil || after.EnrollmentCredentialKind != string(required) {
				t.Fatal("retry did not complete the same identity with required kind")
			}
			if fixture.hub.Load() != 2 || fixture.reg.Load() != 1 || fixture.completion.Load() != 1 {
				t.Fatalf("retry requests: hub=%d reg=%d completion=%d", fixture.hub.Load(), fixture.reg.Load(), fixture.completion.Load())
			}
		})
	}
}

func TestNativeRegistrationZeroKindAcceptsBothHeadlessKinds(t *testing.T) {
	for _, kind := range []qurl.RegistrationKeyKind{qurl.RegistrationKeyKindBootstrap, qurl.RegistrationKeyKindConnectorBootstrap} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := newNativeKindFixture(t)
			fixture.kind.Store(string(kind))
			runtime, err := OpenNativeRuntime(context.Background(), fixture.config)
			if err != nil {
				t.Fatal(err)
			}
			runtime.Binding.Destroy()
			if err := runtime.store.Close(); err != nil {
				t.Fatal(err)
			}
			if fixture.load(t).EnrollmentCredentialKind != string(kind) {
				t.Fatal("wrong enrolled kind")
			}
		})
	}
}

func TestNativeRegistrationPendingActivationHonorsExactKind(t *testing.T) {
	for _, kind := range []qurl.RegistrationKeyKind{qurl.RegistrationKeyKindBootstrap, qurl.RegistrationKeyKindConnectorBootstrap} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := newNativeKindFixture(t)
			fixture.kind.Store(string(kind))
			fixture.pauseREG.Store(true)
			cfg := fixture.config
			cfg.RequiredRegistrationKeyKind = kind
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			go func() {
				select {
				case <-fixture.regReceived:
					cancel()
				case <-ctx.Done():
				}
			}()
			if _, err := OpenNativeRuntime(ctx, cfg); err == nil {
				t.Fatal("interrupted REG succeeded")
			}
			before := fixture.load(t)
			if before.PendingActivation == nil || before.RegisteredAt != nil {
				t.Fatal("missing pending activation")
			}
			other := qurl.RegistrationKeyKindBootstrap
			if kind == other {
				other = qurl.RegistrationKeyKindConnectorBootstrap
			}
			cfg.RequiredRegistrationKeyKind = other
			if _, err := OpenNativeRuntime(context.Background(), cfg); !errors.Is(err, qurl.ErrRegistrationKeyKindDisallowed) {
				t.Fatalf("pending mismatch: %v", err)
			}
			if fixture.hub.Load() != 1 || fixture.reg.Load() != 1 || fixture.completion.Load() != 0 {
				t.Fatal("pending mismatch contacted network")
			}
			after := fixture.load(t)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("pending mismatch changed durable state")
			}
			fixture.pauseREG.Store(false)
			cfg.RequiredRegistrationKeyKind = kind
			runtime, err := OpenNativeRuntime(context.Background(), cfg)
			if err != nil {
				t.Fatalf("pending resume: %v", err)
			}
			runtime.Binding.Destroy()
			if err := runtime.store.Close(); err != nil {
				t.Fatal(err)
			}
			if fixture.hub.Load() != 1 || fixture.reg.Load() != 2 || fixture.completion.Load() != 1 {
				t.Fatal("pending resume did not reuse assignment")
			}
		})
	}
}

type nativeKindFixture struct {
	config      NativeRuntimeConfig
	kind        atomic.Value
	hub         atomic.Int32
	reg         atomic.Int32
	completion  atomic.Int32
	pauseREG    atomic.Bool
	regReceived chan struct{}
}

func (f *nativeKindFixture) load(t *testing.T) *qurl.AgentState {
	t.Helper()
	store, err := qurl.OpenFileAgentStateReadOnly(filepath.Join(f.config.StateDir, agentstate.AgentStateFile))
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.LoadAgentState(context.Background())
	if err := errors.Join(err, store.Close()); err != nil {
		t.Fatal(err)
	}
	return state
}

type nativeKindResolver struct{}

func (nativeKindResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
}

type nativeKindDialer struct{ address string }

func (d nativeKindDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func newNativeKindFixture(t *testing.T) *nativeKindFixture {
	t.Helper()
	t.Setenv(agentstate.EnvKeyProvider, agentstate.KeyProviderFile)
	dir := secureNativeStateDirForTest(t)
	agent, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store, err := qurl.OpenFileAgentState(filepath.Join(dir, agentstate.AgentStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(store.SaveAgentState(context.Background(), &qurl.AgentState{
		AgentID: "agent-exact-kind", SchemaVersion: 8, PrivateKeyB64: base64.StdEncoding.EncodeToString(agent.Bytes()), PublicKeyB64: base64.StdEncoding.EncodeToString(agent.PublicKey().Bytes()),
	}), store.Close()); err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	public := base64.StdEncoding.EncodeToString(server.PublicKey().Bytes())
	f := &nativeKindFixture{regReceived: make(chan struct{}, 1), config: NativeRuntimeConfig{
		StateDir: dir, Hostname: "kind-test", Version: "test", EnrollmentCredential: "lv_live_" + strings.Repeat("k", 43),
		Hub: qurl.HubBootstrap{Host: "hub.nhp.layerv.ai", Port: 443, ServerPublicKeyB64: public},
		UDPOptions: []qurl.AgentRuntimeUDPOption{
			qurl.WithAgentRuntimeUDPResolver(nativeKindResolver{}), qurl.WithAgentRuntimeUDPDialer(nativeKindDialer{conn.LocalAddr().String()}), qurl.WithAgentRuntimeUDPBounds(2*time.Second, 1),
		},
	}}
	f.kind.Store(string(qurl.RegistrationKeyKindBootstrap))
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		cookie := bytes.Repeat([]byte{0x5a}, 32)
		proof := false
		for {
			n, remote, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			var request *relayknock.Reply
			if proof {
				request, err = relayknocktest.OpenHubLSTCookieProofMessage(server.Bytes(), agent.PublicKey().Bytes(), cookie, buffer[:n])
			} else {
				request, err = relayknocktest.OpenInitiatorMessage(server.Bytes(), agent.PublicKey().Bytes(), buffer[:n])
			}
			if err != nil {
				t.Errorf("open request: %v", err)
				return
			}
			replyType := relayknock.TypeListResult
			var body []byte
			switch {
			case request.Type == relayknock.TypeRegister:
				f.reg.Add(1)
				select {
				case f.regReceived <- struct{}{}:
				default:
				}
				if f.pauseREG.Load() {
					continue
				}
				replyType = relayknock.TypeRegisterAck
				body = []byte(`{"errCode":"0","aspId":"agent"}`)
			case bytes.Contains(request.Body, []byte(`"cell_assignment"`)):
				if !proof {
					f.hub.Add(1)
					proof = true
					replyType = relayknock.TypeCookieChallenge
					body = []byte(fmt.Sprintf(`{"trxId":%d,"cookie":%q}`, request.Counter, base64.StdEncoding.EncodeToString(cookie)))
				} else {
					proof = false
					body, err = json.Marshal(map[string]any{"errCode": "0", "list": map[string]any{
						"query": "cell_assignment", "version": 1, "mode": "enroll", "agent_id": "agent-exact-kind",
						"registration":      map[string]string{"key_id": "key_KindTest0001", "key_kind": f.kind.Load().(string)},
						"assignment":        qurl.AgentAssignment{CellID: "cell-test", AssignmentGeneration: 1, EndpointRevision: 1, LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second), Endpoint: qurl.NHPUDPEndpoint{Host: "hub.nhp.layerv.ai", Port: 443, ServerPublicKeyB64: public}},
						"assignment_ticket": "synthetic-kind-ticket", "assignment_ticket_expires_at": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
					}})
				}
			default:
				f.completion.Add(1)
				body = []byte(`{"errCode":"0","list":{"query":"agent_registration_completion","version":1,"device_api_key_id":"key_DeviceTest01"}}`)
			}
			if err != nil {
				t.Errorf("encode reply: %v", err)
				return
			}
			ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Errorf("reply key: %v", err)
				return
			}
			packet, err := relayknocktest.BuildReply(replyType, &relayknock.KnockInputs{DeviceStaticPriv: server.Bytes(), ServerStaticPub: agent.PublicKey().Bytes(), EphemeralPriv: ephemeral.Bytes(), TimestampNanos: uint64(time.Now().UnixNano()), Counter: request.Counter, Preamble: 42, Body: body})
			if err != nil {
				t.Errorf("build reply: %v", err)
				return
			}
			if _, err := conn.WriteToUDP(packet, remote); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return f
}
