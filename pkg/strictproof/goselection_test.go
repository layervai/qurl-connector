package strictproof

import (
	"context"
	"testing"
	"time"
)

// TestSelectedQurlGoIsTheReviewedArtifact is the toolchain half of the
// exact-signed-qurl-go-selection row. Unlike the go.mod/go.sum text
// assertions it does not trust the files: it asks the Go toolchain what this
// module graph actually resolves, then binds the resolved zip back to a VCS
// commit through the download origin. The Go cache can omit the optional
// origin URL, but it still supplies the exact VCS/hash and checksums.
//
// It runs in the ordinary `make test` lane and needs no network — the module
// is already in the build cache by the time the test binary exists.
func TestSelectedQurlGoIsTheReviewedArtifact(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	selection, err := SelectedModule(ctx, "../..", QurlGoModulePath)
	if err != nil {
		t.Fatalf("resolve %s from the module graph: %v", QurlGoModulePath, err)
	}
	if err := VerifyQurlGoSelection(selection); err != nil {
		t.Fatalf("this build does not resolve the reviewed qurl-go artifact: %v\nselection: %+v", err, selection)
	}
}

func TestSelectedModuleReportsAnUnknownModuleAsAnError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// A module that is not in the graph must surface as an error, never as a
	// zero-valued selection that a verifier might read as "nothing wrong".
	if _, err := SelectedModule(ctx, "../..", "example.invalid/not/a/dependency"); err == nil {
		t.Fatal("an absent module resolved without error")
	}
}
