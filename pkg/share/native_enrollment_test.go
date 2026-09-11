package share

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

func TestOpenNativeRuntimeRetriesInterruptedEnrollment(t *testing.T) {
	for _, test := range []struct {
		name              string
		invalidCredential bool
	}{
		{name: "provider failure"},
		{name: "invalid credential", invalidCredential: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(agentstate.EnvKeyProvider, agentstate.KeyProviderFile)
			dir := secureNativeStateDirForTest(t)
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			interrupted := errors.New("enrollment provider interrupted")
			var requests []qurl.AgentEnrollmentCredentialRequest
			cfg := NativeRuntimeConfig{
				StateDir: dir, Hostname: "enrollment-test", Version: "test",
				Hub: qurl.HubBootstrap{
					Host: "hub.nhp.layerv.ai", Port: 443,
					ServerPublicKeyB64: base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
				},
				EnrollmentCredentialProvider: func(_ context.Context, request qurl.AgentEnrollmentCredentialRequest) (string, error) {
					requests = append(requests, request)
					if test.invalidCredential && len(requests) == 1 {
						return "short", nil
					}
					return "", interrupted
				},
				UDPOptions: []qurl.AgentRuntimeUDPOption{qurl.WithAgentRuntimeUDPResolver(&net.Resolver{
					PreferGo: true,
					Dial: func(context.Context, string, string) (net.Conn, error) {
						t.Error("local enrollment failure attempted DNS")
						return nil, interrupted
					},
				})},
			}
			_, err = OpenNativeRuntime(context.Background(), cfg)
			wantErr := interrupted
			if test.invalidCredential {
				wantErr = qurl.ErrInvalidRegisterConfig
			}
			if !errors.Is(err, wantErr) || len(requests) != 1 {
				t.Fatalf("first enrollment: error=%v provider calls=%d", err, len(requests))
			}
			loadState := func() *qurl.AgentState {
				reader, err := qurl.OpenFileAgentStateReadOnly(filepath.Join(dir, agentstate.AgentStateFile))
				if err != nil {
					t.Fatal(err)
				}
				state, loadErr := reader.LoadAgentState(context.Background())
				if err := errors.Join(loadErr, reader.Close()); err != nil {
					t.Fatal(err)
				}
				return state
			}
			before := loadState()
			credentialFree := cfg
			credentialFree.EnrollmentCredentialProvider = nil
			_, err = OpenNativeRuntime(context.Background(), credentialFree)
			if !errors.Is(err, qurl.ErrInvalidRegisterConfig) || !strings.Contains(err.Error(), "missing registration time") || len(requests) != 1 {
				t.Fatalf("credential-free open: error=%v provider calls=%d; want original offline error", err, len(requests))
			}
			// OpenNativeRuntime creates a new store on each call, as a new CLI
			// process does. No SDK runtime or in-memory credential survives.
			_, err = OpenNativeRuntime(context.Background(), cfg)
			if !errors.Is(err, interrupted) || errors.Is(err, qurl.ErrInvalidRegisterConfig) || len(requests) != 2 {
				t.Fatalf("retry: error=%v provider calls=%d; want provider retry", err, len(requests))
			}
			after := loadState()
			if requests[0].AgentID == "" || requests[0] != requests[1] || !reflect.DeepEqual(before, after) {
				t.Fatal("retry replaced the saved identity or enrollment state")
			}
		})
	}
}

func TestOpenNativeRuntimeConfigErrorDoesNotReenrollCompletedIdentity(t *testing.T) {
	t.Setenv(agentstate.EnvKeyProvider, agentstate.KeyProviderFile)
	dir := secureNativeStateDirForTest(t)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	now := time.Now()
	store, err := qurl.OpenFileAgentState(filepath.Join(dir, agentstate.AgentStateFile))
	if err != nil {
		t.Fatal(err)
	}
	completed := &qurl.AgentState{
		AgentID: "agent-test", SchemaVersion: 8, RegisteredAt: &now,
		PrivateKeyB64: base64.StdEncoding.EncodeToString(key.Bytes()), PublicKeyB64: publicKey,
		DeviceAPIKey: "lv_live_" + strings.Repeat("a", 43), DeviceAPIKeyID: "key_DeviceKey123",
		Assignment: &qurl.AgentAssignment{
			CellID: "cell-test", AssignmentGeneration: 1, EndpointRevision: 1, LeaseExpiresAt: now.Add(time.Hour),
			Endpoint: qurl.NHPUDPEndpoint{Host: "hub.nhp.layerv.ai", Port: 443, ServerPublicKeyB64: publicKey},
		},
	}
	if err := errors.Join(store.SaveAgentState(context.Background(), completed), store.Close()); err != nil {
		t.Fatal(err)
	}
	previous := connectNativeRuntime
	t.Cleanup(func() { connectNativeRuntime = previous })
	calls := 0
	var offlineErr error
	connectNativeRuntime = func(ctx context.Context, state qurl.AgentStateStore, opts ...qurl.AgentRuntimeRegistrationOption) (*qurl.Client, *qurl.AgentRuntimeBinding, error) {
		calls++
		client, binding, err := qurl.ConnectAgentRuntime(ctx, state, opts...)
		if calls == 1 {
			offlineErr = err
		}
		return client, binding, err
	}
	_, err = OpenNativeRuntime(context.Background(), NativeRuntimeConfig{
		StateDir: dir, ClientBaseURL: ":invalid",
		EnrollmentCredentialProvider: func(context.Context, qurl.AgentEnrollmentCredentialRequest) (string, error) {
			t.Error("completed identity invoked enrollment provider")
			return "", errors.New("unexpected enrollment")
		},
	})
	if !errors.Is(err, qurl.ErrInvalidRegisterConfig) || !errors.Is(err, offlineErr) || calls != 1 {
		t.Fatalf("completed config failure: error=%v runtime calls=%d; want original error and one offline call", err, calls)
	}
}
