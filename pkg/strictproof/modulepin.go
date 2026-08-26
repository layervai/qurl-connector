package strictproof

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Reviewed qurl-go pin. These constants are independent of go.mod/go.sum so
// the ordinary test lane catches unreviewed dependency-selection drift.
//
// This cutover selects the immutable qurl-go release produced only after its
// exact-main CI and CodeQL gates passed. Source identity remains bound to one
// exact reviewed commit in the LayerV-owned repository by both go.sum checksums
// and the download origin's VCS revision; the toolchain cannot silently
// substitute a different tag or commit.
const (
	QurlGoModulePath        = "github.com/layervai/qurl-go"
	QurlGoRepoURL           = "https://github.com/layervai/qurl-go"
	QurlGoSelectedCommitSHA = "d02c25995df085f0437c7a572714c26e907a8a59"
	QurlGoSelectedVersion   = "v0.8.0"
	QurlGoSelectedSum       = "h1:Tw8291djSj3LT+aGWPW7PPuIEBeAKcIG3h2CddxFlzk="
	QurlGoSelectedGoModSum  = "h1:zujbZnolKJzJEDyKwgUqulhHSi0sZeU2w1x+nle/yeM="
)

// Accepted versions are either a canonical release tag or Go's canonical
// pseudo-version form. Exact equality with QurlGoSelectedVersion and the origin
// SHA check below still select one reviewed artifact; these regexps only reject
// ambiguous/malformed version spellings.
var canonicalReleaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
var canonicalPseudoVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-0\.[0-9]{14}-[0-9a-f]{12}$`)

var lowercaseGitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ModuleSelection is the exact module identity the Go toolchain resolved for a
// build, as reported by `go list -m -json <path>` plus
// `go mod download -json <path>@<version>`.
//
// Path/Version/Sum/GoModSum come from the selected (post-`replace`) module;
// Replaced records whether a replace directive was in play at all, because a
// replace would mean the compiled code is not necessarily the reviewed commit
// even when every other field lines up.
type ModuleSelection struct {
	// RequestedPath is the module path the build asked for, before any replace.
	RequestedPath string
	// Path is the effective module path after any replace directive.
	Path string
	// Version is the effective selected version.
	Version string
	// Sum is the module zip checksum (h1:...) go.sum records for Version.
	Sum string
	// GoModSum is the checksum (h1:...) go.sum records for Version/go.mod.
	GoModSum string
	// Replaced reports whether a replace directive redirected the module.
	Replaced bool
	// VCS, RepoURL and CommitSHA come from the download Origin block and bind
	// the module zip back to a source revision. Go can omit RepoURL when it
	// serves metadata from an older warm module cache; when present it must be
	// the exact LayerV repository.
	VCS       string
	RepoURL   string
	CommitSHA string
}

// VerifyQurlGoSelection checks that a build resolves qurl-go to exactly the
// reviewed qurl-go commit that main declares in go.mod.
//
// Inventory row: exact-signed-qurl-go-selection.
//
// PROVEN here: the module path is unredirected; the selected version is the
// exact reviewed immutable version; both go.sum checksums are the exact reviewed
// values; the version is canonical rather than an arbitrary prerelease; and the
// downloaded zip's VCS origin is the reviewed commit. When the Go tool reports
// the optional origin URL, it must be the LayerV-owned qurl-go repository.
//
// NOT proven by this pure verifier:
//
//   - "signed" — commit signature verification is a forge-side property, not
//     something the Go toolchain reports.
//   - Forge-side reachability or tag state. The binding that holds here is the
//     origin commit plus the two go.sum checksums; release automation verifies
//     repository ownership, signature, and ancestry separately.
//   - That the NHP wire protocol this release speaks (1.1 as of v0.3.0) matches
//     the deployed receiver fleet. That is a deployment-ordering fact no
//     module-graph check can see.
//
// Release validation binds repository ownership and tag state independently,
// then combines those forge facts with this module-selection check.
func VerifyQurlGoSelection(selection ModuleSelection) error {
	if selection.RequestedPath != QurlGoModulePath {
		return fmt.Errorf("module selection is for %q, want %q", selection.RequestedPath, QurlGoModulePath)
	}
	// A replace directive is the one way every checksum below can match while
	// the compiled code comes from somewhere else entirely, so reject it before
	// looking at anything the replacement target controls.
	if selection.Replaced {
		return fmt.Errorf("%s is redirected by a replace directive; the built code is not provably the reviewed commit", QurlGoModulePath)
	}
	if selection.Path != QurlGoModulePath {
		return fmt.Errorf("effective module path is %q, want %q", selection.Path, QurlGoModulePath)
	}
	if selection.Version != QurlGoSelectedVersion {
		return fmt.Errorf("selected version is %q, want the selected module %q", selection.Version, QurlGoSelectedVersion)
	}
	if selection.Sum != QurlGoSelectedSum {
		return fmt.Errorf("module checksum is %q, want the selected %q", selection.Sum, QurlGoSelectedSum)
	}
	if selection.GoModSum != QurlGoSelectedGoModSum {
		return fmt.Errorf("go.mod checksum is %q, want the selected %q", selection.GoModSum, QurlGoSelectedGoModSum)
	}

	if err := VerifyImmutableModuleVersion(selection.Version); err != nil {
		return err
	}

	if selection.VCS != "git" {
		return fmt.Errorf("module origin VCS is %q, want %q", selection.VCS, "git")
	}
	if selection.RepoURL != "" && normalizeRepoURL(selection.RepoURL) != QurlGoRepoURL {
		return fmt.Errorf("module origin URL is %q, want the LayerV-owned %q", selection.RepoURL, QurlGoRepoURL)
	}
	if !lowercaseGitSHA.MatchString(selection.CommitSHA) {
		return fmt.Errorf("module origin commit %q is not an exact 40-character lowercase Git SHA", selection.CommitSHA)
	}
	if selection.CommitSHA != QurlGoSelectedCommitSHA {
		return fmt.Errorf("module origin commit is %s, want the selected signed commit %s", selection.CommitSHA, QurlGoSelectedCommitSHA)
	}
	return nil
}

// VerifyImmutableModuleVersion accepts only a canonical vX.Y.Z release tag or
// Go pseudo-version and rejects arbitrary prereleases, metadata, and empty
// versions. Exact selected-version and commit checks remain separate above.
func VerifyImmutableModuleVersion(version string) error {
	if version == "" {
		return errors.New("module version is empty")
	}
	if !canonicalReleaseTag.MatchString(version) && !canonicalPseudoVersion.MatchString(version) {
		return fmt.Errorf("version %q is not a canonical release tag or pseudo-version", version)
	}
	return nil
}

// normalizeRepoURL trims the optional .git suffix and any trailing slash so an
// origin URL written either way compares equal. It deliberately does not lower
// the scheme or host: an origin served over anything but https from the exact
// LayerV host must fail.
func normalizeRepoURL(raw string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimRight(raw, "/"), ".git"), "/")
}
