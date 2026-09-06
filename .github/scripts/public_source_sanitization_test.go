package scripts

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	accountIDPattern = regexp.MustCompile(`\b[0-9]{12}\b`)
	appIDPattern     = regexp.MustCompile(`(?i)app[_ -]?(?:id|client[_ -]?id)[[:space:]]*[:=][[:space:]]*["']?([0-9]+)`)
	environmentHost  = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)*(?:sandbox|canary|prod|production|[a-z0-9-]+-(?:sandbox|canary|prod|production)|(?:sandbox|canary|prod|production)-[a-z0-9-]+)\.(?:[a-z0-9-]+\.)*[a-z]{2,}\b`)
	layerVRepoRef    = regexp.MustCompile(`(?i)\blayervai/([a-z0-9][a-z0-9-]*)`)
	layerVHost       = regexp.MustCompile(`(?i)\b(?:[a-z0-9-]+\.)*layerv\.(?:ai|xyz)\b`)
	// Find the exact upper-case parameter form and lower-case service paths
	// with at least two segments below the qurl-* namespace. The allowlist
	// below, not this expression, decides which private operational paths are
	// reviewed for public source. References into reviewed public qurl-* repos
	// are excluded separately after this deliberately broad match.
	operationalPath = regexp.MustCompile(`(?:^|[^A-Za-z0-9_.-])(/qurl-[a-z0-9-]+/(?:[A-Z][A-Z0-9_]*(?:/[A-Z][A-Z0-9_]*)*|[a-z0-9][a-z0-9-]*(?:/[a-z0-9](?:[a-z0-9-]*[a-z0-9])?){1,}))(?:[^A-Za-z0-9_/-]|$)`)
)

func findOperationalPaths(text string) []string {
	var paths []string
	for offset := 0; offset < len(text); {
		match := operationalPath.FindStringSubmatchIndex(text[offset:])
		if match == nil {
			break
		}
		paths = append(paths, text[offset+match[2]:offset+match[3]])
		offset += match[3]
	}
	return paths
}

func TestOperationalPathDetectorStaysBroaderThanAllowlist(t *testing.T) {
	for _, path := range []string{
		"/qurl-example-service/" + "nhp/bootstrap",
		"/qurl-example-service/" + "nhp/replica-z/bootstrap",
		"/qurl-example-service/" + "nhp/replica-z/bootstrap-legacy",
		"/qurl-example-service/" + "nhp/replica-z/key",
		"/qurl-example-service/" + "fileviewer-tunnel/replica-z/bootstrap",
		"/qurl-example-service/" + "PRIVATE_PARAMETER",
	} {
		got := findOperationalPaths(path)
		if len(got) != 1 || got[0] != path {
			t.Fatalf("findOperationalPaths(%q) = %q; new NHP service paths must reach the reviewed allowlist", path, got)
		}
	}
	if got := findOperationalPaths("/qurl-example-service/nhp/replica-{slot}/bootstrap"); len(got) != 0 {
		t.Fatalf("dynamic operational path matched incomplete token %q", got)
	}
	first := "/qurl-example-service/" + "nhp/replica-a/bootstrap"
	second := "/qurl-example-service/" + "nhp/replica-b/bootstrap"
	if got := findOperationalPaths(first + " " + second); len(got) != 2 || got[0] != first || got[1] != second {
		t.Fatalf("findOperationalPaths(adjacent paths) = %q, want both paths", got)
	}
}

func operationalPathBelongsToCurrentRepository(path string) bool {
	return strings.HasPrefix(path, "/qurl-connector/")
}

func TestOperationalPathPublicRepositoryExemptionIsExact(t *testing.T) {
	if !operationalPathBelongsToCurrentRepository("/qurl-connector/CONTRIBUTING") {
		t.Fatal("the current public repository must not be mistaken for a private operational path")
	}
	for _, path := range []string{
		"/qurl-connector-" + "private/CONTRIBUTING",
		"/qurl-go/" + "PRIVATE_PARAMETER",
	} {
		if operationalPathBelongsToCurrentRepository(path) {
			t.Fatalf("%q must not inherit the current-repository exemption", path)
		}
	}
}

func TestOperationalPathDetectorIgnoresRepositoryReferences(t *testing.T) {
	for _, reference := range []string{
		"github.com/layervai/qurl-go/relayknock/nativeudp",
		"https://github.com/layervai/qurl-connector/security/advisories/new",
	} {
		if got := findOperationalPaths(reference); len(got) != 0 {
			t.Fatalf("findOperationalPaths(%q) = %q, want repository reference ignored", reference, got)
		}
	}
}

func TestLayerVHostDetectorIncludesEveryReviewedSuffix(t *testing.T) {
	for _, host := range []string{
		"api." + "layerv.ai",
		"api." + "layerv." + "xyz",
	} {
		if got := layerVHost.FindString(host); got != host {
			t.Fatalf("layerVHost.FindString(%q) = %q", host, got)
		}
	}
}

func TestEnvironmentHostDetectorDoesNotConfuseWorkflowFilename(t *testing.T) {
	const workflowFilename = "rotate-tunnel-enrollment.yml"
	if got := environmentHost.FindString(workflowFilename); got != "" {
		t.Fatalf("environmentHost.FindString(%q) = %q, want no hostname", workflowFilename, got)
	}

	privateHost := "files-sand" + "box.internal.acme.io"
	if got := environmentHost.FindString(privateHost); got != privateHost {
		t.Fatalf("environmentHost.FindString(%q) = %q, want exact private host", privateHost, got)
	}
	if reservedEnvironmentHost(privateHost) {
		t.Fatalf("reservedEnvironmentHost(%q) = true, want false", privateHost)
	}

	reservedHost := "files-sand" + "box.example.com"
	if got := environmentHost.FindString(reservedHost); got != reservedHost {
		t.Fatalf("environmentHost.FindString(%q) = %q, want exact reserved host", reservedHost, got)
	}
	if !reservedEnvironmentHost(reservedHost) {
		t.Fatalf("reservedEnvironmentHost(%q) = false, want true", reservedHost)
	}
}

func TestPublicSourceContainsNoPrivateOperationalMaterial(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	reservedAccounts := map[string]bool{
		"111122" + "223333": true,
		"000000" + "000000": true,
	}
	publicRepositories := map[string]bool{
		"frp":                    true,
		"ops-routines-workflows": true,
		"qurl-conformance":       true,
		"qurl-connector":         true,
		"qurl-go":                true,
	}
	publicHosts := map[string]bool{
		"api." + "layerv.ai":     true,
		"hub.nhp." + "layerv.ai": true,
		"layerv.ai":              true,
	}
	privateNames := []string{
		"qurl-" + "service",
		"qurl-" + "reverse-tunnel-server",
		"traefik-" + "plugins",
		"qurl-" + "integrations-infra",
		"github.com/layervai/" + "nhp",
	}
	secretEndpoints := []string{
		"https://hooks" + ".slack.com/",
		"discord.com/api/" + "webhooks/",
		"execute-api" + ".amazonaws.com",
	}
	reviewedOperationalPaths := map[string]bool{
		"/qurl-s3-connector/fileviewer-nhp/replica-a/bootstrap": true,
		"/qurl-s3-connector/fileviewer-nhp/replica-b/bootstrap": true,
		"/qurl-s3-connector/fileviewer-nhp/replica-c/bootstrap": true,
		"/qurl-s3-connector/uploader-nhp/replica-a/bootstrap":   true,
		"/qurl-s3-connector/uploader-nhp/replica-b/bootstrap":   true,
		"/qurl-s3-connector/uploader-nhp/replica-c/bootstrap":   true,
		"/qurl-s3-connector/detect-nhp/replica-a/bootstrap":     true,
		"/qurl-s3-connector/detect-nhp/replica-b/bootstrap":     true,
		"/qurl-s3-connector/detect-nhp/replica-c/bootstrap":     true,
		"/qurl-watermark-service/nhp/replica-a/bootstrap":       true,
		"/qurl-watermark-service/nhp/replica-b/bootstrap":       true,
		"/qurl-watermark-service/nhp/replica-c/bootstrap":       true,
	}

	err := filepath.WalkDir(repoRoot, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch filepath.ToSlash(rel) {
			case ".git", "bin", ".github/scripts/__pycache__":
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "coverage.out" {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		lower := strings.ToLower(text)

		for _, id := range accountIDPattern.FindAllString(text, -1) {
			if !reservedAccounts[id] {
				t.Errorf("%s contains non-reserved 12-digit identifier %s", rel, id)
			}
		}
		if match := appIDPattern.FindStringSubmatch(text); match != nil {
			t.Errorf("%s contains literal GitHub App identifier %s", rel, match[1])
		}
		for _, name := range privateNames {
			if strings.Contains(lower, name) {
				t.Errorf("%s names private repository %q", rel, name)
			}
		}
		for _, match := range layerVRepoRef.FindAllStringSubmatch(text, -1) {
			if !publicRepositories[strings.ToLower(match[1])] {
				t.Errorf("%s refers to non-public or unreviewed LayerV repository %q", rel, match[0])
			}
		}
		for _, host := range layerVHost.FindAllString(lower, -1) {
			if !publicHosts[host] {
				t.Errorf("%s contains undocumented LayerV hostname %q", rel, host)
			}
		}
		for _, endpoint := range secretEndpoints {
			if strings.Contains(lower, endpoint) {
				t.Errorf("%s contains private webhook or cloud endpoint %q", rel, endpoint)
			}
		}
		for _, operational := range findOperationalPaths(text) {
			if operationalPathBelongsToCurrentRepository(operational) {
				continue
			}
			if !reviewedOperationalPaths[operational] {
				t.Errorf("%s contains unreviewed operational path %q", rel, operational)
			}
		}
		for _, host := range environmentHost.FindAllString(lower, -1) {
			if !reservedEnvironmentHost(host) {
				t.Errorf("%s contains non-reserved sandbox/canary/prod hostname %q", rel, host)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIntentionalPublicEndpointsAreDocumented(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	readme, err := os.ReadFile(filepath.Join(repoRoot, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{
		"https://api." + "layerv.ai/v1",
		"hub.nhp." + "layerv.ai:443",
	} {
		if !strings.Contains(string(readme), endpoint) {
			t.Errorf("README.md does not document intentional public endpoint %q", endpoint)
		}
	}
	for _, phrase := range []string{"Hostnames are not credentials", "No Hub public key is", "embedded"} {
		if !strings.Contains(string(readme), phrase) {
			t.Errorf("README.md does not explain public endpoint safety; missing %q", phrase)
		}
	}
}

func reservedEnvironmentHost(host string) bool {
	for _, suffix := range []string{
		".example.com",
		".example.net",
		".example.org",
		".example.internal",
		".test",
		".invalid",
	} {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}
