//go:build unix && !linux

package agentstate

func isAnonymousLocalKeySocketAddress(_ int, _ bool, name string) bool {
	return name == ""
}
