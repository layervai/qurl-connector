package strictproof

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// goListModule is the subset of `go list -m -json` this package reads.
type goListModule struct {
	Path     string        `json:"Path"`
	Version  string        `json:"Version"`
	Sum      string        `json:"Sum"`
	GoModSum string        `json:"GoModSum"`
	Replace  *goListModule `json:"Replace"`
}

// goDownloadModule is the subset of `go mod download -json` this package reads.
type goDownloadModule struct {
	Path    string `json:"Path"`
	Version string `json:"Version"`
	Sum     string `json:"Sum"`
	Error   string `json:"Error"`
	Origin  *struct {
		VCS  string `json:"VCS"`
		URL  string `json:"URL"`
		Hash string `json:"Hash"`
	} `json:"Origin"`
}

// SelectedModule asks the Go toolchain what a build rooted at dir actually
// resolves modulePath to, and binds that selection back to a source revision.
//
// It reads the module cache and never mutates go.mod or go.sum: `go list -m`
// runs with -mod=readonly, and `go mod download` is asked only about the exact
// version already selected, so a run in a populated cache needs no network.
//
// The returned ModuleSelection is raw observation. Nothing here decides whether
// the selection is the reviewed one — that is VerifyQurlGoSelection's job, so
// collection and judgement stay separable.
func SelectedModule(ctx context.Context, dir, modulePath string) (ModuleSelection, error) {
	var selected goListModule
	if err := runGoJSON(ctx, dir, &selected, "list", "-m", "-mod=readonly", "-json", modulePath); err != nil {
		return ModuleSelection{}, err
	}
	effective := selected
	replaced := false
	if selected.Replace != nil {
		effective = *selected.Replace
		replaced = true
	}
	if effective.Path == "" || effective.Version == "" {
		return ModuleSelection{}, fmt.Errorf("go list -m %s reported no effective path/version", modulePath)
	}

	var downloaded goDownloadModule
	if err := runGoJSON(ctx, dir, &downloaded, "mod", "download", "-json", effective.Path+"@"+effective.Version); err != nil {
		return ModuleSelection{}, err
	}
	if downloaded.Error != "" {
		return ModuleSelection{}, fmt.Errorf("go mod download %s@%s: %s", effective.Path, effective.Version, downloaded.Error)
	}

	selection := ModuleSelection{
		RequestedPath: modulePath,
		Path:          effective.Path,
		Version:       effective.Version,
		Sum:           effective.Sum,
		GoModSum:      effective.GoModSum,
		Replaced:      replaced,
	}
	if downloaded.Origin != nil {
		selection.VCS = downloaded.Origin.VCS
		selection.RepoURL = downloaded.Origin.URL
		selection.CommitSHA = downloaded.Origin.Hash
	}
	return selection, nil
}

// runGoJSON runs one `go` subcommand in dir and decodes its single JSON object.
// A trailing object is rejected rather than ignored, so a multi-module answer
// cannot be silently narrowed to whichever object came first.
func runGoJSON(ctx context.Context, dir string, into any, args ...string) error {
	command := exec.CommandContext(ctx, "go", args...)
	command.Dir = dir
	// Inspect the committed module graph, not a developer's surrounding
	// multi-repository workspace. A workspace main module has no selected
	// version and would make the release-selection observation meaningless.
	command.Env = append(os.Environ(), "GOWORK=off")
	var stderr strings.Builder
	command.Stderr = &stderr
	stdout, err := command.Output()
	if err != nil {
		return fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	decoder := json.NewDecoder(strings.NewReader(string(stdout)))
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("go %s: decode JSON: %w", strings.Join(args, " "), err)
	}
	if decoder.More() {
		return fmt.Errorf("go %s: returned more than one JSON object", strings.Join(args, " "))
	}
	return nil
}
