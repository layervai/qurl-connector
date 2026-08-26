//go:build darwin

package agentstate

// DefaultStateDir uses Darwin's real path rather than the /var symlink because
// private state traversal rejects every symlink component.
const DefaultStateDir = "/private/var/lib/layerv/agent"
