package version

import (
	"strings"
	"testing"
)

func TestVersionStrings(t *testing.T) {
	if got := Full(); !strings.Contains(got, "qurl-connector") || strings.Contains(strings.ToLower(got), "opennhp") {
		t.Fatalf("Full() = %q", got)
	}
	if got := Short(); !strings.Contains(got, "qurl-connector") {
		t.Fatalf("Short() = %q", got)
	}
}
