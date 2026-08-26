package scripts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConnectorReleaseIsSourceModuleOnly(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))

	goMod, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(goMod), "module github.com/layervai/qurl-connector\n") {
		t.Fatal("go.mod must declare the canonical public connector module path")
	}

	for _, path := range []string{
		".github/workflows/build-binaries.yml",
		".github/workflows/docker-publish.yml",
		".github/workflows/verify-release.yml",
		"docker/Dockerfile",
		"scripts/install.sh",
		"scripts/verify-release.sh",
		"docs/install-docker.md",
		"docs/install-single-container.md",
		"cmd/frpc/update.go",
		"pkg/selfupdate",
	} {
		_, err := os.Stat(filepath.Join(repoRoot, path))
		if err == nil {
			t.Errorf("%s reintroduces a customer connector artifact; users install only qurl", path)
		} else if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("stat %s: %v", path, err)
		}
	}

	readme, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, phrase := range []string{
		"Users install only the `qurl` CLI",
		"`cmd/frpc` is retained for development and diagnostics",
		"Go module source tags",
	} {
		if !strings.Contains(string(readme), phrase) {
			t.Errorf("README.md must state the source-only packaging boundary; missing %q", phrase)
		}
	}

	err = filepath.WalkDir(filepath.Join(repoRoot, ".github", "workflows"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, publisher := range []string{
			"docker/build-push-action",
			"softprops/action-gh-release",
			"gh release upload",
			"goreleaser",
		} {
			if strings.Contains(strings.ToLower(string(body)), publisher) {
				t.Errorf("%s publishes a forbidden connector artifact via %q", path, publisher)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
