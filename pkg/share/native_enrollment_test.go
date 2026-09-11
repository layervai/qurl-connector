package share

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

func TestOpenNativeRuntimeRetriesInterruptedEnrollment(t *testing.T) {
	for _, invalidCredential := range []bool{false, true} {
		t.Run(map[bool]string{false: "provider failure", true: "invalid credential"}[invalidCredential], func(t *testing.T) {
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
					if invalidCredential && len(requests) == 1 {
						return "short", nil
					}
					return "", interrupted
				},
			}
			_, err = OpenNativeRuntime(context.Background(), cfg)
			wantErr := interrupted
			if invalidCredential {
				wantErr = qurl.ErrInvalidRegisterConfig
			}
			if !errors.Is(err, wantErr) || len(requests) != 1 {
				t.Fatalf("first enrollment: error=%v provider calls=%d", err, len(requests))
			}
			reader, err := qurl.OpenFileAgentStateReadOnly(filepath.Join(dir, agentstate.AgentStateFile))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reader.Close() })
			before, err := reader.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// OpenNativeRuntime creates a new store on each call, as a new CLI
			// process does. No SDK runtime or in-memory credential survives.
			_, err = OpenNativeRuntime(context.Background(), cfg)
			if !errors.Is(err, interrupted) || len(requests) != 2 {
				t.Fatalf("retry: error=%v provider calls=%d; want provider retry", err, len(requests))
			}
			after, err := reader.LoadAgentState(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if requests[0].AgentID == "" || requests[0] != requests[1] || !reflect.DeepEqual(before, after) {
				t.Fatal("retry replaced the saved identity or enrollment state")
			}
		})
	}
}
