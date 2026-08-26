package strictproof

import (
	"os"
	"strings"
	"testing"
)

func reviewedSelection() ModuleSelection {
	return ModuleSelection{
		RequestedPath: QurlGoModulePath,
		Path:          QurlGoModulePath,
		Version:       QurlGoSelectedVersion,
		Sum:           QurlGoSelectedSum,
		GoModSum:      QurlGoSelectedGoModSum,
		VCS:           "git",
		RepoURL:       QurlGoRepoURL,
		CommitSHA:     QurlGoSelectedCommitSHA,
	}
}

func TestVerifyQurlGoSelectionAcceptsTheReviewedPin(t *testing.T) {
	if err := VerifyQurlGoSelection(reviewedSelection()); err != nil {
		t.Fatalf("reviewed selection rejected: %v", err)
	}
	// The .git suffix and a trailing slash are both ordinary origin spellings
	// for the same repository and must not change the verdict.
	for _, url := range []string{QurlGoRepoURL + ".git", QurlGoRepoURL + "/", QurlGoRepoURL + ".git/"} {
		selection := reviewedSelection()
		selection.RepoURL = url
		if err := VerifyQurlGoSelection(selection); err != nil {
			t.Errorf("origin URL %q rejected: %v", url, err)
		}
	}
	// Older warm module caches can retain the exact VCS/hash and checksums but
	// omit the optional Origin.URL field. Exact bytes and commit stay bound.
	withoutCachedURL := reviewedSelection()
	withoutCachedURL.RepoURL = ""
	if err := VerifyQurlGoSelection(withoutCachedURL); err != nil {
		t.Fatalf("reviewed selection without optional cached origin URL rejected: %v", err)
	}
}

func TestVerifyQurlGoSelectionRejectsEveryDrift(t *testing.T) {
	// Each case mutates exactly one field of an otherwise-passing selection, so
	// a green case can only mean that field is genuinely unchecked.
	for name, mutate := range map[string]func(*ModuleSelection){
		"wrong requested module":  func(s *ModuleSelection) { s.RequestedPath = "github.com/layervai/frp" },
		"replace directive":       func(s *ModuleSelection) { s.Replaced = true },
		"redirected path":         func(s *ModuleSelection) { s.Path = "example.com/fork/qurl-go" },
		"newer version":           func(s *ModuleSelection) { s.Version = "v0.3.1" },
		"earlier release tag":     func(s *ModuleSelection) { s.Version = "v0.2.0" },
		"retired tagless pin":     func(s *ModuleSelection) { s.Version = "v0.2.1-0.20260803201435-1e580fee7a98" },
		"untagged-base pseudo":    func(s *ModuleSelection) { s.Version = "v0.0.0-20260801231055-9515d5fda818" },
		"prerelease-base pseudo":  func(s *ModuleSelection) { s.Version = "v0.2.1-rc.1.0.20260801231055-9515d5fda818" },
		"empty version":           func(s *ModuleSelection) { s.Version = "" },
		"module sum drift":        func(s *ModuleSelection) { s.Sum = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
		"go.mod sum drift":        func(s *ModuleSelection) { s.GoModSum = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" },
		"missing go.mod sum":      func(s *ModuleSelection) { s.GoModSum = "" },
		"non-git origin":          func(s *ModuleSelection) { s.VCS = "hg" },
		"missing origin":          func(s *ModuleSelection) { s.VCS = ""; s.RepoURL = ""; s.CommitSHA = "" },
		"foreign repository":      func(s *ModuleSelection) { s.RepoURL = "https://github.com/attacker/qurl-go" },
		"lookalike host":          func(s *ModuleSelection) { s.RepoURL = "https://example.invalid/example-org/qurl-go-mirror" },
		"plaintext origin":        func(s *ModuleSelection) { s.RepoURL = "http://github.com/layervai/qurl-go" },
		"short origin commit":     func(s *ModuleSelection) { s.CommitSHA = QurlGoSelectedCommitSHA[:12] },
		"uppercase origin commit": func(s *ModuleSelection) { s.CommitSHA = strings.ToUpper(QurlGoSelectedCommitSHA) },
		"different origin commit": func(s *ModuleSelection) { s.CommitSHA = strings.Repeat("a", 40) },
		"empty origin commit":     func(s *ModuleSelection) { s.CommitSHA = "" },
		"pseudo-version selection": func(s *ModuleSelection) {
			s.Version = "v0.3.1-0.20260804231055-aaaaaaaaaaaa"
		},
	} {
		t.Run(name, func(t *testing.T) {
			selection := reviewedSelection()
			mutate(&selection)
			if err := VerifyQurlGoSelection(selection); err == nil {
				t.Fatalf("drift accepted: %+v", selection)
			}
		})
	}
}

func TestVerifyImmutableModuleVersion(t *testing.T) {
	for _, version := range []string{QurlGoSelectedVersion, "v0.8.0"} {
		if err := VerifyImmutableModuleVersion(version); err != nil {
			t.Fatalf("canonical version %q rejected: %v", version, err)
		}
	}
	for _, version := range []string{
		"v0.3.1-20260804000000-aaaaaaaaaaaa",
		"v0.3.1-0.2026080400000-aaaaaaaaaaaa",
		"v0.3.1-0.20260804000000-AAAAAAAAAAAA",
		"v0.3.0-rc.1",
		"v0.3.0+build.1",
		"0.3.0",
		"",
	} {
		if err := VerifyImmutableModuleVersion(version); err == nil {
			t.Errorf("version %q accepted as an immutable module version", version)
		}
	}
}

// TestQurlGoPinIsTheModuleThisRepositoryActuallyBuilds is the offline half of
// the exact-signed-qurl-go-selection row: it reads the committed
// go.mod and go.sum rather than trusting the constants above. It runs in the
// ordinary `make test` lane on every push, so a stray `go get -u` that moves
// qurl-go is caught immediately.
func TestQurlGoPinIsTheModuleThisRepositoryActuallyBuilds(t *testing.T) {
	goMod := readRepoFile(t, "go.mod")
	requireLine := "\t" + QurlGoModulePath + " " + QurlGoSelectedVersion
	if !strings.Contains(goMod, requireLine) {
		t.Errorf("go.mod does not select the declared module %s %s", QurlGoModulePath, QurlGoSelectedVersion)
	}
	// Exactly one selection: a second require or a replace line would make the
	// effective version ambiguous from the file alone.
	if got := strings.Count(goMod, QurlGoModulePath+" "); got != 1 {
		t.Errorf("go.mod names %s %d times, want exactly 1", QurlGoModulePath, got)
	}
	if strings.Contains(goMod, "replace "+QurlGoModulePath) {
		t.Errorf("go.mod carries a replace directive for %s", QurlGoModulePath)
	}

	goSum := readRepoFile(t, "go.sum")
	for _, want := range []string{
		QurlGoModulePath + " " + QurlGoSelectedVersion + " " + QurlGoSelectedSum,
		QurlGoModulePath + " " + QurlGoSelectedVersion + "/go.mod " + QurlGoSelectedGoModSum,
	} {
		if !strings.Contains(goSum, want) {
			t.Errorf("go.sum is missing the reviewed row %q", want)
		}
	}
	// Two rows and only two: an extra qurl-go row means another version is
	// still reachable in the module graph.
	if got := strings.Count(goSum, QurlGoModulePath+" "); got != 2 {
		t.Errorf("go.sum carries %d %s rows, want exactly 2", got, QurlGoModulePath)
	}
}

func readRepoFile(t *testing.T, relative string) string {
	t.Helper()
	// go test runs in the package directory: pkg/strictproof.
	raw, err := os.ReadFile("../../" + relative)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	return string(raw)
}
