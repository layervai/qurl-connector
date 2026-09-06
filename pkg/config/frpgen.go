package config

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

const (
	maxProxyDiscriminatorLen = 16
	proxyHashSuffixLen       = 8
)

// These FRP metadata keys are cross-repository wire contracts with the qURL
// tunnel server.
const (
	MetaQURLKnockToken = "qurl_knock_token" //nolint:gosec // metadata key, not a credential
	MetaClientVersion  = "client_version"
	MetaResourceID     = "resource_id" //nolint:gosec // metadata key, not a credential
)

// FRPProxyName returns the bounded name used for one admitted route.
func FRPProxyName(routeID, discriminator string) string {
	discriminator = normalizeProxyDiscriminator(discriminator)
	if discriminator == "" {
		return routeID
	}
	return routeID + "-" + discriminator
}

func normalizeProxyDiscriminator(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	var b strings.Builder
	lastHyphen := false
	for _, r := range lower {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'z' {
			b.WriteRune(r)
			lastHyphen = false
		} else if r == '-' && b.Len() > 0 && !lastHyphen {
			b.WriteByte('-')
			lastHyphen = true
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if len(out) <= maxProxyDiscriminatorLen {
		return out
	}
	prefix := strings.TrimRight(out[:maxProxyDiscriminatorLen-proxyHashSuffixLen-1], "-")
	sum := sha256.Sum256([]byte(raw))
	return prefix + "-" + hex.EncodeToString(sum[:])[:proxyHashSuffixLen]
}
