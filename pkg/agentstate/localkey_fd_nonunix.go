//go:build !unix

package agentstate

import "fmt"

func readLocalWrappingKey(string) ([]byte, error) {
	return nil, fmt.Errorf("%s=%s inherited-descriptor transport is unsupported on this platform", EnvKeyProvider, KeyProviderLocalKey)
}
