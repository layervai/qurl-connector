package config

import (
	"strconv"
	"strings"
	"testing"
)

func TestFRPProxyNameNormalizesAndKeepsLongNamesDistinct(t *testing.T) {
	for input, want := range map[string]string{
		" Replica__ONE!! ": "replicaone",
		"-foo--bar-":       "foo-bar",
		"replica-٥":        "replica",
		"":                 "",
	} {
		got := normalizeProxyDiscriminator(input)
		if got != want {
			t.Errorf("normalizeProxyDiscriminator(%q) = %q, want %q", input, got, want)
		}
		if twice := normalizeProxyDiscriminator(got); twice != got {
			t.Errorf("normalization is not idempotent for %q: %q then %q", input, got, twice)
		}
	}
	a := FRPProxyName("web", "fileviewer-v2-66b6c48dd5-abcde")
	b := FRPProxyName("web", "fileviewer-v2-66b6c48dd5-fghij")
	if a == b || len(a) > len("web-")+maxProxyDiscriminatorLen || len(b) > len("web-")+maxProxyDiscriminatorLen {
		t.Fatalf("long proxy names = %q, %q", a, b)
	}
	if got := normalizeProxyDiscriminator("abcdef-ghijklmnop"); strings.Contains(got, "--") {
		t.Fatalf("truncated discriminator contains a double hyphen: %q", got)
	}
	seen := make(map[string]struct{}, 300)
	for i := range 300 {
		got := normalizeProxyDiscriminator("fileviewer-v2-66b6c48dd5-replica-" + strconv.Itoa(i))
		if _, exists := seen[got]; exists {
			t.Fatalf("same-prefix discriminator collision at %d: %q", i, got)
		}
		seen[got] = struct{}{}
	}
}
