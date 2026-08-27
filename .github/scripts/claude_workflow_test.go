package scripts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	checkoutAction           = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	claudeAction             = "anthropics/claude-code-action@9d7150bc8a3dae8149739a88019d192b579ad90c"
	claudeModel              = "claude-opus-5"
	automaticAllowedTools    = "mcp__github__get_pull_request,mcp__github__get_pull_request_diff,mcp__github__get_pull_request_files,mcp__github__get_pull_request_review_comments,mcp__github__get_pull_request_reviews,mcp__github__get_pull_request_status,mcp__github__get_issue_comments,mcp__github__get_file_contents,mcp__github__search_code,mcp__github__get_commit,mcp__github__add_issue_comment,mcp__github_inline_comment__create_inline_comment"
	automaticDisallowedTools = "Bash,Read,Glob,Grep,LS,Task,Edit,Write,MultiEdit,NotebookEdit,WebFetch,WebSearch,mcp__github_file_ops__commit_files,mcp__github_file_ops__delete_files,mcp__github__create_or_update_file,mcp__github__push_files,mcp__github__delete_file"
)

type workflow struct {
	On          map[string]trigger `yaml:"on"`
	Permissions map[string]string  `yaml:"permissions"`
	Concurrency concurrency        `yaml:"concurrency"`
	Jobs        map[string]job     `yaml:"jobs"`
}

type trigger struct {
	Types []string `yaml:"types"`
}

type concurrency struct {
	Group            string `yaml:"group"`
	CancelInProgress bool   `yaml:"cancel-in-progress"`
}

type job struct {
	If             string            `yaml:"if"`
	TimeoutMinutes int               `yaml:"timeout-minutes"`
	Permissions    map[string]string `yaml:"permissions"`
	Steps          []step            `yaml:"steps"`
}

type step struct {
	Name string            `yaml:"name"`
	ID   string            `yaml:"id"`
	If   string            `yaml:"if"`
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	Env  map[string]string `yaml:"env"`
	With map[string]string `yaml:"with"`
}

func loadWorkflow(t *testing.T, name string) workflow {
	t.Helper()

	contents, err := os.ReadFile("../workflows/" + name)
	if err != nil {
		t.Fatalf("read workflow %s: %v", name, err)
	}

	var result workflow
	if err := yaml.Unmarshal(contents, &result); err != nil {
		t.Fatalf("parse workflow %s: %v", name, err)
	}
	return result
}

func findStep(t *testing.T, steps []step, name string) (step, int) {
	t.Helper()

	found := -1
	var result step
	for index, candidate := range steps {
		if candidate.Name != name {
			continue
		}
		if found != -1 {
			t.Fatalf("workflow contains more than one step named %q", name)
		}
		found = index
		result = candidate
	}
	if found == -1 {
		t.Fatalf("workflow does not contain step %q", name)
	}
	return result, found
}

func compact(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func selectedClaudeModel(args string) string {
	fields := strings.Fields(args)
	selected := ""
	for index, field := range fields {
		if field != "--model" {
			continue
		}
		if selected != "" || index+1 >= len(fields) {
			return ""
		}
		selected = fields[index+1]
	}
	return selected
}

func requireExpression(t *testing.T, got, want string) {
	t.Helper()
	if compact(got) != compact(want) {
		t.Errorf("expression = %q, want %q", compact(got), compact(want))
	}
}

func requireContains(t *testing.T, value string, fragments ...string) {
	t.Helper()
	for _, fragment := range fragments {
		if !strings.Contains(value, fragment) {
			t.Errorf("expected value to contain %q", fragment)
		}
	}
}

func requireExactKeys(t *testing.T, values map[string]string, keys ...string) {
	t.Helper()
	want := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		want[key] = struct{}{}
	}
	got := make(map[string]struct{}, len(values))
	for key := range values {
		got[key] = struct{}{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %v, want exactly %v", got, want)
	}
}

func requireBlockContains(t *testing.T, value, start, end, fragment string) {
	t.Helper()

	startIndex := strings.Index(value, start)
	if startIndex == -1 {
		t.Fatalf("expected value to contain block start %q", start)
	}
	block := value[startIndex:]
	endIndex := strings.Index(block, end)
	if endIndex == -1 {
		t.Fatalf("expected block starting with %q to contain end %q", start, end)
	}
	block = block[:endIndex]
	if !strings.Contains(block, fragment) {
		t.Errorf("expected block starting with %q to contain %q", start, fragment)
	}
}

func requireInOrder(t *testing.T, value string, fragments ...string) {
	t.Helper()

	offset := 0
	for _, fragment := range fragments {
		index := strings.Index(value[offset:], fragment)
		if index == -1 {
			t.Errorf("expected value after offset %d to contain %q", offset, fragment)
			return
		}
		offset += index + len(fragment)
	}
}

func requireNoStatusOverride(t *testing.T, job job) {
	t.Helper()

	conditions := []string{job.If}
	for _, workflowStep := range job.Steps {
		conditions = append(conditions, workflowStep.If)
	}
	for _, condition := range conditions {
		for _, forbidden := range []string{"always(", "failure(", "cancelled("} {
			if strings.Contains(strings.ToLower(condition), forbidden) {
				t.Errorf("condition %q must not use %s to bypass a failed guard", condition, forbidden)
			}
		}
	}
}

func requireEmptyTopLevelPermissions(t *testing.T, permissions map[string]string) {
	t.Helper()
	if permissions == nil || len(permissions) != 0 {
		t.Errorf("top-level permissions = %v, want explicit empty permissions", permissions)
	}
}

func requireNoShaValueEcho(t *testing.T, script string) {
	t.Helper()
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "echo") &&
			(strings.Contains(line, "${EXPECTED_HEAD_SHA}") ||
				strings.Contains(line, "${EXPECTED_BASE_SHA}") ||
				strings.Contains(line, "${current_head_sha}") ||
				strings.Contains(line, "${current_base_sha}") ||
				strings.Contains(line, "${local_head_sha}") ||
				strings.Contains(line, "${local_source_head_sha}") ||
				strings.Contains(line, "${local_source_base_sha}") ||
				strings.Contains(line, "${local_tracking_head_sha}") ||
				strings.Contains(line, "${local_tracking_base_sha}") ||
				strings.Contains(line, "${local_pinned_head_sha}") ||
				strings.Contains(line, "${local_pinned_base_sha}") ||
				strings.Contains(line, "${pinned_head_sha}") ||
				strings.Contains(line, "${pinned_base_sha}") ||
				strings.Contains(line, "${seeded_head_sha}") ||
				strings.Contains(line, "${seeded_base_sha}") ||
				// origin_url carries the action's x-access-token credential
				// once claude-code-action re-points the remote. origin_rest is
				// the intermediate that still holds it: origin_dest and the
				// final origin_authority have userinfo already stripped.
				strings.Contains(line, "${origin_url}") ||
				strings.Contains(line, "${origin_rest}") ||
				strings.Contains(line, "${origin_dest}") ||
				strings.Contains(line, "${origin_authority}") ||
				strings.Contains(line, "${CLAUDE_EXECUTION_FILE}")) {
			t.Errorf("SHA verifier must not print ref-derived values: %q", strings.TrimSpace(line))
		}
	}
}

func gitExitCode(t *testing.T, directory string, args ...string) int {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = directory
	err := command.Run()
	if err == nil {
		return 0
	}
	exitError, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return exitError.ExitCode()
}

func runGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func runBash(t *testing.T, directory, script string, environment map[string]string) (string, error) {
	t.Helper()

	command := exec.Command("bash", "-c", script)
	command.Dir = directory
	command.Env = os.Environ()
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	output, err := command.CombinedOutput()
	return string(output), err
}

func writeClaudeCommandAPIMocks(t *testing.T) string {
	t.Helper()

	mockBin := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(mockBin, "timeout"),
		[]byte("#!/usr/bin/env bash\nshift\nexec \"$@\"\n"),
		0o755,
	); err != nil {
		t.Fatalf("write timeout mock: %v", err)
	}
	ghScript := `#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *'.commits'* ]]; then
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${CURRENT_HEAD_REPO}" "${CURRENT_HEAD_SHA}" "${CURRENT_HEAD_REF}" \
    "${CURRENT_BASE_REPO}" "${CURRENT_DEFAULT_BRANCH}" "${CURRENT_BASE_SHA}" \
    "${CURRENT_BASE_REF}" "${CURRENT_COMMIT_COUNT}" "${CURRENT_PR_STATE}"
else
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${CURRENT_HEAD_REPO}" "${CURRENT_HEAD_SHA}" "${CURRENT_HEAD_REF}" \
    "${CURRENT_BASE_REPO}" "${CURRENT_DEFAULT_BRANCH}" "${CURRENT_BASE_SHA}" \
    "${CURRENT_BASE_REF}" "${CURRENT_PR_STATE}"
fi
`
	if err := os.WriteFile(filepath.Join(mockBin, "gh"), []byte(ghScript), 0o755); err != nil {
		t.Fatalf("write gh mock: %v", err)
	}
	return mockBin
}

func newGitSnapshotFixture(t *testing.T, commitCount int) (repository, baseSHA, headSHA string) {
	t.Helper()

	repository = t.TempDir()
	runGit(t, repository, "init", "--quiet")
	runGit(t, repository, "config", "user.name", "Claude workflow test")
	runGit(t, repository, "config", "user.email", "claude-workflow@example.invalid")

	runGit(t, repository, "commit", "--allow-empty", "--quiet", "-m", "base")
	baseSHA = runGit(t, repository, "rev-parse", "HEAD")
	for range commitCount {
		runGit(t, repository, "commit", "--allow-empty", "--quiet", "-m", "head")
	}
	headSHA = runGit(t, repository, "rev-parse", "HEAD")
	return repository, baseSHA, headSHA
}

func TestCredentialFreeOriginSupportsPinnedActionFetchSequence(t *testing.T) {
	const commitCount = 25
	repository, baseSHA, headSHA := newGitSnapshotFixture(t, commitCount)

	const (
		baseRef    = "base/snapshot"
		headRef    = "head/snapshot"
		trustedRef = "trusted/default"
	)
	runGit(t, repository, "branch", "--force", "--", trustedRef, baseSHA)
	runGit(t, repository, "checkout", "--quiet", trustedRef)
	trustedSHA := runGit(t, repository, "rev-parse", "HEAD")
	runGit(t, repository, "checkout", "--detach", "--quiet", trustedSHA)
	runGit(t, repository, "branch", "--force", "--", baseRef, baseSHA)
	runGit(t, repository, "branch", "--force", "--", headRef, headSHA)
	runGit(t, repository, "remote", "add", "origin", filepath.Join(repository, ".git"))
	runGit(t, repository, "config", "--local", "fetch.recurseSubmodules", "false")
	if got := runGit(t, repository, "rev-parse", "HEAD"); got != trustedSHA {
		t.Fatalf("pre-action HEAD = %q, want trusted snapshot %q", got, trustedSHA)
	}

	// The workflow leaves trusted default-branch bytes checked out through its
	// preflight. These then mirror the pinned action's setupBranch head fetch/checkout
	// and restoreConfigFromBase fetch, including their order and shapes.
	fetchDepth := 20
	if commitCount > fetchDepth {
		fetchDepth = commitCount
	}
	runGit(t, repository, "fetch", "origin", "--depth="+strconv.Itoa(fetchDepth), headRef)
	runGit(t, repository, "checkout", headRef, "--")
	runGit(t, repository, "fetch", "origin", baseRef, "--depth=1", "--no-recurse-submodules")

	if got := runGit(t, repository, "rev-parse", "HEAD"); got != headSHA {
		t.Errorf("checked-out head = %q, want %q", got, headSHA)
	}
	for ref, want := range map[string]string{
		"refs/heads/" + headRef:          headSHA,
		"refs/heads/" + baseRef:          baseSHA,
		"refs/remotes/origin/" + headRef: headSHA,
		"refs/remotes/origin/" + baseRef: baseSHA,
	} {
		if got := runGit(t, repository, "rev-parse", ref); got != want {
			t.Errorf("%s = %q, want %q", ref, got, want)
		}
	}
	if got, want := runGit(t, repository, "remote", "get-url", "origin"), filepath.Join(repository, ".git"); got != want {
		t.Errorf("origin = %q, want credential-free local origin %q", got, want)
	}
	if got := runGit(t, repository, "config", "--local", "--get", "fetch.recurseSubmodules"); got != "false" {
		t.Errorf("fetch.recurseSubmodules = %q, want false", got)
	}
	helperPattern := `^credential(\..*)?\.helper$`
	if got := gitExitCode(t, repository, "config", "--local", "--get-regexp", helperPattern); got != 1 {
		t.Fatalf("clean repository credential-helper query exit = %d, want 1", got)
	}
	runGit(t, repository, "config", "--local", "credential.https://github.com.helper", "store")
	if got := gitExitCode(t, repository, "config", "--local", "--get-regexp", helperPattern); got != 0 {
		t.Errorf("scoped credential-helper query exit = %d, want 0 so the workflow rejects it", got)
	}
}

func TestCredentialFreeOriginSupportsAutomaticAgentBaseRestore(t *testing.T) {
	repository, baseSHA, headSHA := newGitSnapshotFixture(t, 3)

	const (
		baseRef = "base/automatic"
		headRef = "head/automatic"
	)
	runGit(t, repository, "branch", "--force", "--", baseRef, baseSHA)
	runGit(t, repository, "branch", "--force", "--", headRef, headSHA)
	runGit(t, repository, "checkout", "--detach", "--quiet", baseSHA)
	runGit(t, repository, "remote", "add", "origin", filepath.Join(repository, ".git"))
	runGit(t, repository, "config", "--local", "fetch.recurseSubmodules", "false")

	// The first two fetches are the workflow's preflight. The final fetch is
	// the pinned action's restoreConfigFromBase in automatic agent mode.
	runGit(t, repository, "fetch", "origin", "--depth=1", headRef)
	runGit(t, repository, "fetch", "origin", baseRef, "--depth=1", "--no-recurse-submodules")
	runGit(t, repository, "fetch", "origin", baseRef, "--depth=1", "--no-recurse-submodules")

	for ref, want := range map[string]string{
		"HEAD":                           baseSHA,
		"refs/heads/" + headRef:          headSHA,
		"refs/heads/" + baseRef:          baseSHA,
		"refs/remotes/origin/" + headRef: headSHA,
		"refs/remotes/origin/" + baseRef: baseSHA,
	} {
		if got := runGit(t, repository, "rev-parse", ref); got != want {
			t.Errorf("%s = %q, want %q", ref, got, want)
		}
	}
	if got, want := runGit(t, repository, "remote", "get-url", "origin"), filepath.Join(repository, ".git"); got != want {
		t.Errorf("origin = %q, want credential-free local origin %q", got, want)
	}
	if got := runGit(t, repository, "config", "--local", "--get", "fetch.recurseSubmodules"); got != "false" {
		t.Errorf("fetch.recurseSubmodules = %q, want false", got)
	}
}

func TestAutomaticReviewTerminalRequiresPublishedReviewAndExactSnapshots(t *testing.T) {
	review := loadWorkflow(t, "claude-code-review.yml")
	job := review.Jobs["claude-review"]
	pinSnapshots, _ := findStep(t, job.Steps, "Pin automatic review snapshots")
	verify, _ := findStep(t, job.Steps, "Verify reviewed pull request snapshots")

	repository, baseSHA, headSHA := newGitSnapshotFixture(t, 3)
	const (
		baseRef    = "base/automatic"
		headRef    = "head/automatic"
		trustedRef = "trusted/default"
	)
	runGit(t, repository, "branch", "--force", "--", trustedRef, baseSHA)
	runGit(t, repository, "checkout", "--quiet", trustedRef)
	runGit(t, repository, "remote", "add", "origin", "https://example.invalid/layervai/qurl-connector.git")

	outputFile := filepath.Join(t.TempDir(), "github-output")
	pinEnvironment := map[string]string{
		"EXPECTED_HEAD_SHA": headSHA,
		"EXPECTED_HEAD_REF": headRef,
		"EXPECTED_BASE_SHA": baseSHA,
		"EXPECTED_BASE_REF": baseRef,
		"TRUSTED_REF":       trustedRef,
		"GITHUB_WORKSPACE":  repository,
		"GITHUB_OUTPUT":     outputFile,
	}
	if output, err := runBash(t, repository, pinSnapshots.Run, pinEnvironment); err != nil {
		t.Fatalf("automatic snapshot preparation failed: %v\n%s", err, output)
	}
	outputContents, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read automatic snapshot outputs: %v", err)
	}
	wantOutputs := "trusted_sha=" + baseSHA + "\nready=true\n"
	if got := string(outputContents); got != wantOutputs {
		t.Fatalf("automatic snapshot outputs = %q, want %q", got, wantOutputs)
	}

	mockBin := t.TempDir()
	timeoutPath := filepath.Join(mockBin, "timeout")
	if err := os.WriteFile(timeoutPath, []byte("#!/usr/bin/env bash\nshift\nexec \"$@\"\n"), 0o755); err != nil {
		t.Fatalf("write timeout mock: %v", err)
	}
	ghPath := filepath.Join(mockBin, "gh")
	ghScript := `#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  *'/pulls/'*)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
      "${CURRENT_HEAD_REPO}" "${CURRENT_HEAD_SHA}" "${CURRENT_HEAD_REF}" \
      "${CURRENT_BASE_REPO}" "${CURRENT_BASE_SHA}" "${CURRENT_BASE_REF}"
    ;;
  *'/issues/'*'/comments'*)
    if [[ "${COMMENTS_API_FAIL:-}" == "1" ]]; then
      exit 1
    fi
    printf '%s\n' "${COMMENTS_JSON}"
    ;;
  *)
    exit 1
    ;;
esac
`
	if err := os.WriteFile(ghPath, []byte(ghScript), 0o755); err != nil {
		t.Fatalf("write gh mock: %v", err)
	}

	executionFile := filepath.Join(t.TempDir(), "execution.json")
	if err := os.WriteFile(executionFile, []byte("{\"subtype\":\"success\"}\n"), 0o600); err != nil {
		t.Fatalf("write execution record: %v", err)
	}
	reviewMarker := "<!-- claude-review:layervai/qurl-connector:461:999:2:" + headSHA + " -->"
	commentsJSON := func(actor, body string) string {
		t.Helper()
		encoded, err := json.Marshal([][]map[string]any{{{
			"user": map[string]string{"login": actor},
			"body": body,
		}}})
		if err != nil {
			t.Fatalf("encode comments: %v", err)
		}
		return string(encoded)
	}
	validComments := commentsJSON("github-actions[bot]", "No findings.\n\n"+reviewMarker+"\n")
	baseEnvironment := map[string]string{
		"PATH":              mockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_TOKEN":          "test-token",
		"GITHUB_WORKSPACE":  repository,
		"GITHUB_REPOSITORY": "layervai/qurl-connector",
		// Set explicitly so the boundary arm resolves identically off-runner.
		"GITHUB_SERVER_URL":      "https://github.com",
		"PR_NUMBER":              "461",
		"EXPECTED_HEAD_SHA":      headSHA,
		"EXPECTED_HEAD_REF":      headRef,
		"EXPECTED_BASE_SHA":      baseSHA,
		"EXPECTED_BASE_REF":      baseRef,
		"EXPECTED_LOCAL_SHA":     baseSHA,
		"EXPECTED_REVIEW_MARKER": reviewMarker,
		"CLAUDE_EXECUTION_FILE":  executionFile,
		"CURRENT_HEAD_REPO":      "layervai/qurl-connector",
		"CURRENT_HEAD_SHA":       headSHA,
		"CURRENT_HEAD_REF":       headRef,
		"CURRENT_BASE_REPO":      "layervai/qurl-connector",
		"CURRENT_BASE_SHA":       baseSHA,
		"CURRENT_BASE_REF":       baseRef,
		"COMMENTS_JSON":          validComments,
	}
	cloneEnvironment := func(overrides map[string]string) map[string]string {
		result := make(map[string]string, len(baseEnvironment)+len(overrides))
		for key, value := range baseEnvironment {
			result[key] = value
		}
		for key, value := range overrides {
			result[key] = value
		}
		return result
	}
	runVerifier := func(overrides map[string]string) (string, error) {
		t.Helper()
		return runBash(t, repository, verify.Run, cloneEnvironment(overrides))
	}

	if output, err := runVerifier(nil); err != nil {
		t.Fatalf("valid automatic review rejected: %v\n%s", err, output)
	}

	publicationFailures := []struct {
		name      string
		overrides map[string]string
		wantError string
	}{
		{
			name:      "missing comment",
			overrides: map[string]string{"COMMENTS_JSON": "[[]]"},
			wantError: "did not publish the run-specific pull request comment",
		},
		{
			name: "marker only",
			overrides: map[string]string{
				"COMMENTS_JSON": commentsJSON("github-actions[bot]", " \n\t\n"+reviewMarker+"\n"),
			},
			wantError: "did not publish the run-specific pull request comment",
		},
		{
			name: "wrong actor",
			overrides: map[string]string{
				"COMMENTS_JSON": commentsJSON("claude[bot]", "Review.\n"+reviewMarker),
			},
			wantError: "did not publish the run-specific pull request comment",
		},
		{
			name: "stale marker",
			overrides: map[string]string{
				"COMMENTS_JSON": commentsJSON("github-actions[bot]", "Review.\n"+strings.Replace(reviewMarker, ":999:2:", ":999:1:", 1)),
			},
			wantError: "did not publish the run-specific pull request comment",
		},
		{
			name:      "comments API failure",
			overrides: map[string]string{"COMMENTS_API_FAIL": "1"},
			wantError: "Unable to verify Claude review publication",
		},
		{
			// The boundary comparison target is assembled from runner-provided
			// env. An empty one would silently degrade the destination
			// allowlist to "/<owner>/<repo>.git", so fail closed instead.
			name:      "empty server URL",
			overrides: map[string]string{"GITHUB_SERVER_URL": ""},
			wantError: "Runner-provided boundary comparison targets are unavailable",
		},
	}
	for _, testCase := range publicationFailures {
		t.Run(testCase.name, func(t *testing.T) {
			output, err := runVerifier(testCase.overrides)
			if err == nil {
				t.Fatalf("invalid publication unexpectedly passed\n%s", output)
			}
			if !strings.Contains(output, testCase.wantError) {
				t.Fatalf("verifier output = %q, want %q", output, testCase.wantError)
			}
		})
	}

	tamperedRefs := []struct {
		name string
		ref  string
	}{
		{name: "source head", ref: "refs/heads/" + headRef},
		{name: "pinned head", ref: "refs/automatic-review/head"},
	}
	for _, testCase := range tamperedRefs {
		t.Run(testCase.name, func(t *testing.T) {
			runGit(t, repository, "update-ref", testCase.ref, baseSHA)
			output, err := runVerifier(nil)
			if err == nil {
				t.Fatalf("tampered ref unexpectedly passed\n%s", output)
			}
			if !strings.Contains(output, "PR snapshots changed while Claude was running") {
				t.Fatalf("verifier output = %q, want stale-snapshot error", output)
			}
			runGit(t, repository, "update-ref", testCase.ref, headSHA)
		})
	}

	runGit(t, repository, "checkout", "--detach", "--quiet", headSHA)
	output, err := runVerifier(nil)
	if err == nil {
		t.Fatalf("tampered local HEAD unexpectedly passed\n%s", output)
	}
	if !strings.Contains(output, "PR snapshots changed while Claude was running") {
		t.Fatalf("verifier output = %q, want stale-snapshot error", output)
	}
	runGit(t, repository, "checkout", "--detach", "--quiet", baseSHA)

	// claude-code-action v1.0.187 re-points origin at an authenticated clone of
	// this repository before Claude's first token (replaceCheckoutCredentials in
	// src/modes/agent/index.ts). That is the action's own doing, not a boundary
	// escape, and it must not fail the review — it failed every run of #595/#596
	// when the verifier demanded the local pin survive.
	const boundaryError = "Automatic review Git boundary moved off this repository"
	actionOrigin := "https://x-access-token:ghs-test-token@github.com/layervai/qurl-connector.git"
	runGit(t, repository, "remote", "set-url", "origin", actionOrigin)
	if output, err := runVerifier(nil); err != nil {
		t.Fatalf("action-configured origin rejected: %v\n%s", err, output)
	}

	// The property the local pin bought still has to hold: origin may only ever
	// address this repository, never a destination data could be pushed to.
	offRepoOrigins := []struct {
		name   string
		remote string
	}{
		{name: "third-party host", remote: "https://x-access-token:t@evil.example.com/attacker/exfil.git"},
		{name: "same host other repo", remote: "https://x-access-token:t@github.com/attacker/exfil.git"},
		// The real host is evil.example.com; the repository path only looks
		// like userinfo. A naive strip-to-first-@ would accept this.
		{name: "userinfo lookalike path", remote: "https://evil.example.com/@github.com/layervai/qurl-connector.git"},
		{name: "other scheme", remote: "ssh://git@evil.example.com/layervai/qurl-connector.git"},
	}
	for _, testCase := range offRepoOrigins {
		t.Run(testCase.name, func(t *testing.T) {
			runGit(t, repository, "remote", "set-url", "origin", testCase.remote)
			output, err := runVerifier(nil)
			if err == nil {
				t.Fatalf("off-repository origin unexpectedly passed\n%s", output)
			}
			if !strings.Contains(output, boundaryError) {
				t.Fatalf("verifier output = %q, want %q", output, boundaryError)
			}
			if strings.Contains(output, "x-access-token") {
				t.Errorf("verifier leaked remote credentials into logs: %q", output)
			}
			runGit(t, repository, "remote", "set-url", "origin", actionOrigin)
		})
	}

	runGit(t, repository, "remote", "set-url", "origin", filepath.Join(repository, ".git"))
	runGit(t, repository, "config", "--local", "credential.https://github.com.helper", "store")
	output, err = runVerifier(nil)
	if err == nil {
		t.Fatalf("tampered credential configuration unexpectedly passed\n%s", output)
	}
	if !strings.Contains(output, boundaryError) {
		t.Fatalf("verifier output = %q, want credential-tamper error", output)
	}
}

func TestInteractiveSensitivePathGuardRejectsUnsafeGitObjects(t *testing.T) {
	_, job := interactiveJob(t)
	pinBranch, _ := findStep(t, job.Steps, "Pin Claude pull request snapshots")

	testCases := []struct {
		name       string
		prepare    func(*testing.T, string, string)
		wantError  string
		shouldPass bool
	}{
		{
			name: "regular files",
			prepare: func(t *testing.T, repository, _ string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(repository, ".claude"), 0o755); err != nil {
					t.Fatalf("create .claude: %v", err)
				}
				if err := os.WriteFile(filepath.Join(repository, ".claude", "settings.json"), []byte("{}\n"), 0o644); err != nil {
					t.Fatalf("write settings: %v", err)
				}
				if err := os.WriteFile(filepath.Join(repository, ".mcp.json"), []byte("{}\n"), 0o644); err != nil {
					t.Fatalf("write mcp config: %v", err)
				}
				runGit(t, repository, "add", ".claude/settings.json", ".mcp.json")
			},
			shouldPass: true,
		},
		{
			name: "root symlink",
			prepare: func(t *testing.T, repository, _ string) {
				t.Helper()
				if err := os.Symlink("/proc/self/environ", filepath.Join(repository, ".mcp.json")); err != nil {
					t.Fatalf("create root symlink: %v", err)
				}
				runGit(t, repository, "add", ".mcp.json")
			},
			wantError: "non-regular sensitive path",
		},
		{
			name: "nested symlink",
			prepare: func(t *testing.T, repository, _ string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Join(repository, ".claude"), 0o755); err != nil {
					t.Fatalf("create .claude: %v", err)
				}
				if err := os.Symlink("/proc/self/environ", filepath.Join(repository, ".claude", "settings.json")); err != nil {
					t.Fatalf("create nested symlink: %v", err)
				}
				runGit(t, repository, "add", ".claude/settings.json")
			},
			wantError: "non-regular sensitive descendant",
		},
		{
			name: "nested gitlink",
			prepare: func(t *testing.T, repository, baseSHA string) {
				t.Helper()
				runGit(t, repository, "update-index", "--add", "--cacheinfo", "160000,"+baseSHA+",.claude/dependency")
			},
			wantError: "non-regular sensitive descendant",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repository := t.TempDir()
			runGit(t, repository, "init", "--quiet", "--initial-branch=main")
			runGit(t, repository, "config", "user.name", "Claude workflow test")
			runGit(t, repository, "config", "user.email", "claude-workflow@example.invalid")
			runGit(t, repository, "commit", "--allow-empty", "--quiet", "-m", "trusted base")
			baseSHA := runGit(t, repository, "rev-parse", "HEAD")

			testCase.prepare(t, repository, baseSHA)
			runGit(t, repository, "commit", "--quiet", "-m", "candidate head")
			headSHA := runGit(t, repository, "rev-parse", "HEAD")
			runGit(t, repository, "branch", "feature/review", headSHA)
			runGit(t, repository, "checkout", "--detach", "--quiet", baseSHA)
			runGit(t, repository, "branch", "--force", "main", baseSHA)
			runGit(t, repository, "checkout", "--quiet", "main")
			const initialOrigin = "https://example.invalid/layervai/qurl-connector.git"
			runGit(t, repository, "remote", "add", "origin", initialOrigin)

			outputFile := filepath.Join(t.TempDir(), "github-output")
			output, err := runBash(t, repository, pinBranch.Run, map[string]string{
				"EXPECTED_HEAD_SHA":       headSHA,
				"PR_HEAD_REF":             "feature/review",
				"EXPECTED_BASE_SHA":       baseSHA,
				"PR_BASE_REF":             "main",
				"FETCH_DEPTH":             "20",
				"EXPECTED_DEFAULT_BRANCH": "main",
				"TRUSTED_REF":             "main",
				"GITHUB_WORKSPACE":        repository,
				"GITHUB_OUTPUT":           outputFile,
			})
			if testCase.shouldPass {
				if err != nil {
					t.Fatalf("safe fixture rejected: %v\n%s", err, output)
				}
				return
			}
			if err == nil {
				t.Fatalf("unsafe fixture unexpectedly passed\n%s", output)
			}
			if !strings.Contains(output, testCase.wantError) {
				t.Fatalf("guard output = %q, want %q", output, testCase.wantError)
			}
			if got := runGit(t, repository, "remote", "get-url", "origin"); got != initialOrigin {
				t.Fatalf("guard mutated origin to %q before rejecting unsafe head", got)
			}
		})
	}
}

func TestClaudeReviewIsTrustedBaseReadyOnlyAndImmutable(t *testing.T) {
	review := loadWorkflow(t, "claude-code-review.yml")
	job := review.Jobs["claude-review"]

	wantEvents := map[string]trigger{
		"pull_request_target": {Types: []string{"opened", "synchronize", "reopened", "ready_for_review"}},
	}
	if !reflect.DeepEqual(review.On, wantEvents) {
		t.Errorf("review triggers = %v, want %v", review.On, wantEvents)
	}
	if _, ok := review.On["pull_request"]; ok {
		t.Error("secrets-bearing automatic review must not execute a pull-request-authored workflow")
	}
	requireEmptyTopLevelPermissions(t, review.Permissions)
	requireExpression(t, job.If, `
		github.event.pull_request.user.type != 'Bot' &&
		github.event.pull_request.head.repo.full_name == github.repository &&
		github.event.pull_request.base.repo.full_name == github.repository &&
		github.event.pull_request.draft == false
	`)
	if got, want := review.Concurrency.Group, "claude-review-${{ github.event.pull_request.number }}"; got != want {
		t.Errorf("concurrency group = %q, want %q", got, want)
	}
	if !review.Concurrency.CancelInProgress {
		t.Error("review workflow must cancel a stale in-progress review")
	}
	if job.TimeoutMinutes != 20 {
		t.Errorf("review timeout = %d, want the Connector-specific 20-minute ceiling", job.TimeoutMinutes)
	}

	wantPermissions := map[string]string{
		"contents":      "read",
		"pull-requests": "write",
		"issues":        "read",
	}
	if !reflect.DeepEqual(job.Permissions, wantPermissions) {
		t.Errorf("review permissions = %v, want %v", job.Permissions, wantPermissions)
	}

	checkout, checkoutIndex := findStep(t, job.Steps, "Checkout trusted default branch history")
	pinSnapshots, pinIndex := findStep(t, job.Steps, "Pin automatic review snapshots")
	runClaude, runIndex := findStep(t, job.Steps, "Run Claude Code Review")
	verify, verifyIndex := findStep(t, job.Steps, "Verify reviewed pull request snapshots")
	if !(checkoutIndex < pinIndex && pinIndex < runIndex && runIndex < verifyIndex) {
		t.Errorf("review step order = %d, %d, %d, %d", checkoutIndex, pinIndex, runIndex, verifyIndex)
	}
	if len(job.Steps) != 4 {
		t.Errorf("automatic review steps = %d, want exactly 4", len(job.Steps))
	}
	if checkout.ID != "checkout" || checkout.Uses != checkoutAction {
		t.Errorf("checkout step = {id:%q uses:%q}, want {id:checkout uses:%q}", checkout.ID, checkout.Uses, checkoutAction)
	}
	if got, want := checkout.With["ref"], "${{ github.event.repository.default_branch }}"; got != want {
		t.Errorf("checkout ref = %q, want %q", got, want)
	}
	if got, want := checkout.With["fetch-depth"], "0"; got != want {
		t.Errorf("checkout fetch-depth = %q, want %q", got, want)
	}
	if got, want := checkout.With["persist-credentials"], "false"; got != want {
		t.Errorf("checkout persist-credentials = %q, want %q", got, want)
	}
	if pinSnapshots.ID != "pin_review_snapshots" || pinSnapshots.If != "steps.checkout.outcome == 'success'" {
		t.Errorf("automatic pin step = {id:%q if:%q}", pinSnapshots.ID, pinSnapshots.If)
	}
	wantPinEnv := map[string]string{
		"EXPECTED_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
		"EXPECTED_HEAD_REF": "${{ github.event.pull_request.head.ref }}",
		"EXPECTED_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
		"EXPECTED_BASE_REF": "${{ github.event.pull_request.base.ref }}",
		"TRUSTED_REF":       "${{ github.event.repository.default_branch }}",
	}
	if !reflect.DeepEqual(pinSnapshots.Env, wantPinEnv) {
		t.Errorf("automatic pin env = %v, want %v", pinSnapshots.Env, wantPinEnv)
	}
	requireContains(t, pinSnapshots.Run,
		`[[ ! "${EXPECTED_HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ ! "${EXPECTED_BASE_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ ! "${EXPECTED_HEAD_REF}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]`,
		`[[ ! "${EXPECTED_BASE_REF}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]`,
		`git check-ref-format "refs/heads/${EXPECTED_HEAD_REF}"`,
		`git check-ref-format "refs/heads/${EXPECTED_BASE_REF}"`,
		`git check-ref-format "refs/heads/${TRUSTED_REF}"`,
		`trusted_head_sha="$(git rev-parse --verify HEAD 2>/dev/null)"`,
		`trusted_branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)"`,
		`git checkout --detach --quiet "${trusted_head_sha}"`,
		`git cat-file -e "${EXPECTED_HEAD_SHA}^{commit}"`,
		`git cat-file -e "${EXPECTED_BASE_SHA}^{commit}"`,
		`git config --local --get-regexp '^http\..*\.extraheader$'`,
		`git config --local --get-regexp '^credential(\..*)?\.helper$'`,
		`git config --local fetch.recurseSubmodules false`,
		`git branch --force -- "${EXPECTED_BASE_REF}" "${EXPECTED_BASE_SHA}"`,
		`git branch --force -- "${EXPECTED_HEAD_REF}" "${EXPECTED_HEAD_SHA}"`,
		`git remote set-url origin "${GITHUB_WORKSPACE}/.git"`,
		`git fetch origin --depth=1 "${EXPECTED_HEAD_REF}"`,
		`git fetch origin "${EXPECTED_BASE_REF}" --depth=1 --no-recurse-submodules`,
		`refs/remotes/origin/${EXPECTED_HEAD_REF}^{commit}`,
		`refs/remotes/origin/${EXPECTED_BASE_REF}^{commit}`,
		// Tamper evidence lives in a namespace the Claude action never writes;
		// refs/remotes/origin/* is action-owned once the review starts.
		`git update-ref refs/automatic-review/head "${EXPECTED_HEAD_SHA}"`,
		`git update-ref refs/automatic-review/base "${EXPECTED_BASE_SHA}"`,
		`refs/automatic-review/head^{commit}`,
		`refs/automatic-review/base^{commit}`,
		`Automatic-review preparation checked out pull-request code before Claude`,
	)
	requireInOrder(t, pinSnapshots.Run,
		`git config --local fetch.recurseSubmodules false`,
		`git branch --force -- "${EXPECTED_BASE_REF}" "${EXPECTED_BASE_SHA}"`,
		`git branch --force -- "${EXPECTED_HEAD_REF}" "${EXPECTED_HEAD_SHA}"`,
		`git remote set-url origin "${GITHUB_WORKSPACE}/.git"`,
		`git fetch origin --depth=1 "${EXPECTED_HEAD_REF}"`,
		`git fetch origin "${EXPECTED_BASE_REF}" --depth=1 --no-recurse-submodules`,
		`git update-ref refs/automatic-review/head "${EXPECTED_HEAD_SHA}"`,
		`git update-ref refs/automatic-review/base "${EXPECTED_BASE_SHA}"`,
	)
	requireNoShaValueEcho(t, pinSnapshots.Run)
	if strings.Contains(pinSnapshots.Run, "github.token") || strings.Contains(pinSnapshots.Run, "GH_TOKEN") {
		t.Error("automatic local-origin shim must not embed a GitHub credential")
	}

	if got, want := runClaude.If, "steps.pin_review_snapshots.outcome == 'success'"; got != want {
		t.Errorf("review action condition = %q, want %q", got, want)
	}
	if got, want := runClaude.ID, "claude_review"; got != want {
		t.Errorf("review action id = %q, want %q", got, want)
	}
	if runClaude.Uses != claudeAction {
		t.Errorf("review action = %q, want %q", runClaude.Uses, claudeAction)
	}
	if got, want := runClaude.With["github_token"], "${{ github.token }}"; got != want {
		t.Errorf("review github_token = %q, want %q", got, want)
	}
	if got, want := runClaude.With["use_commit_signing"], "true"; got != want {
		t.Errorf("review use_commit_signing = %q, want %q", got, want)
	}
	if _, ok := runClaude.With["exclude_comments_by_actor"]; ok {
		t.Error("automatic agent mode must not carry an inert actor filter")
	}
	if got := selectedClaudeModel(runClaude.With["claude_args"]); got != claudeModel {
		t.Errorf("review Claude model = %q, want %q", got, claudeModel)
	}
	requireExactKeys(t, runClaude.With,
		"anthropic_api_key",
		"github_token",
		"use_commit_signing",
		"prompt",
		"claude_args",
	)
	wantArgs := `--model ` + claudeModel + ` --allowed-tools "` + automaticAllowedTools + `" --disallowed-tools "` + automaticDisallowedTools + `"`
	if got := compact(runClaude.With["claude_args"]); got != wantArgs {
		t.Errorf("automatic Claude args = %q, want exact read/comment-only boundary %q", got, wantArgs)
	}
	requireContains(t, runClaude.With["prompt"],
		"HEAD SHA: ${{ github.event.pull_request.head.sha }}",
		"BASE SHA: ${{ github.event.pull_request.base.sha }}",
		"using only the allowed\nGitHub MCP tools",
		"Do not use a moving branch or local workspace",
		"Read CLAUDE.md through mcp__github__get_file_contents at BASE SHA",
		"REVIEW MARKER: <!-- claude-review:${{ github.repository }}:${{ github.event.pull_request.number }}:${{ github.run_id }}:${{ github.run_attempt }}:${{ github.event.pull_request.head.sha }} -->",
		"that final comment with the REVIEW MARKER exactly as shown",
		"mcp__github__add_issue_comment",
		"mcp__github_inline_comment__create_inline_comment",
		"commit_id=HEAD SHA",
	)
	if verify.If != "" {
		t.Errorf("head verification condition = %q, want default success chaining", verify.If)
	}
	if got, want := verify.Env["EXPECTED_HEAD_SHA"], "${{ github.event.pull_request.head.sha }}"; got != want {
		t.Errorf("expected review SHA = %q, want %q", got, want)
	}
	if got, want := verify.Env["EXPECTED_HEAD_REF"], "${{ github.event.pull_request.head.ref }}"; got != want {
		t.Errorf("expected review head ref = %q, want %q", got, want)
	}
	if got, want := verify.Env["EXPECTED_BASE_SHA"], "${{ github.event.pull_request.base.sha }}"; got != want {
		t.Errorf("expected review base SHA = %q, want %q", got, want)
	}
	if got, want := verify.Env["EXPECTED_BASE_REF"], "${{ github.event.pull_request.base.ref }}"; got != want {
		t.Errorf("expected review base ref = %q, want %q", got, want)
	}
	if got, want := verify.Env["EXPECTED_LOCAL_SHA"], "${{ steps.pin_review_snapshots.outputs.trusted_sha }}"; got != want {
		t.Errorf("expected local review SHA = %q, want %q", got, want)
	}
	if got, want := verify.Env["EXPECTED_REVIEW_MARKER"], "<!-- claude-review:${{ github.repository }}:${{ github.event.pull_request.number }}:${{ github.run_id }}:${{ github.run_attempt }}:${{ github.event.pull_request.head.sha }} -->"; got != want {
		t.Errorf("expected publication marker = %q, want %q", got, want)
	}
	if got, want := verify.Env["CLAUDE_EXECUTION_FILE"], "${{ steps.claude_review.outputs.execution_file }}"; got != want {
		t.Errorf("review execution file = %q, want %q", got, want)
	}
	if got, want := verify.Env["GH_TOKEN"], "${{ github.token }}"; got != want {
		t.Errorf("review verifier GH_TOKEN = %q, want %q", got, want)
	}
	if got, want := verify.Env["PR_NUMBER"], "${{ github.event.pull_request.number }}"; got != want {
		t.Errorf("review verifier PR_NUMBER = %q, want %q", got, want)
	}
	if got := strings.Count(verify.Run, `timeout 30s gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"`); got != 1 {
		t.Errorf("review verifier API calls = %d, want one current-snapshot recheck", got)
	}
	requireContains(t, verify.Run,
		`[[ -z "${CLAUDE_EXECUTION_FILE}" ]]`,
		`[[ ! -f "${CLAUDE_EXECUTION_FILE}" ]]`,
		`[[ ! -s "${CLAUDE_EXECUTION_FILE}" ]]`,
		`[[ ! "${EXPECTED_HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ ! "${EXPECTED_BASE_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ ! "${EXPECTED_LOCAL_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`git check-ref-format "refs/heads/${EXPECTED_HEAD_REF}"`,
		`git check-ref-format "refs/heads/${EXPECTED_BASE_REF}"`,
		`git config --local --get-regexp '^http\..*\.extraheader$'`,
		`git config --local --get-regexp '^credential(\..*)?\.helper$'`,
		`git config --local --get fetch.recurseSubmodules`,
		`git remote get-url origin`,
		`${GITHUB_WORKSPACE}/.git`,
		`[.head.repo.full_name // "", .head.sha // "", .head.ref // "", .base.repo.full_name // "", .base.sha // "", .base.ref // ""] | @tsv`,
		`local_head_sha="$(git rev-parse --verify HEAD 2>/dev/null)"`,
		`refs/heads/${EXPECTED_HEAD_REF}^{commit}`,
		`refs/heads/${EXPECTED_BASE_REF}^{commit}`,
		`refs/automatic-review/head^{commit}`,
		`refs/automatic-review/base^{commit}`,
		// The Claude action owns origin from v1.0.187 on, so the boundary arm
		// checks the remote's destination rather than an exact pinned URL. The
		// authority is parsed explicitly so a path that merely looks like
		// userinfo cannot masquerade as this repository.
		`[[ -z "${GITHUB_SERVER_URL}" ]]`,
		`origin_url="$(git remote get-url origin 2>/dev/null || true)"`,
		`origin_authority="${origin_rest%%/*}"`,
		`origin_authority="${origin_authority##*@}"`,
		`[[ "${origin_dest}" != "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}.git" ]]`,
		`[[ ! "${current_head_sha}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ ! "${current_base_sha}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ "${current_head_repo}" != "${GITHUB_REPOSITORY}" ]]`,
		`[[ "${current_base_repo}" != "${GITHUB_REPOSITORY}" ]]`,
		`[[ "${current_head_ref}" != "${EXPECTED_HEAD_REF}" ]]`,
		`[[ "${current_base_ref}" != "${EXPECTED_BASE_REF}" ]]`,
		`[[ ! "${local_head_sha}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ "${current_head_sha}" != "${EXPECTED_HEAD_SHA}" ]]`,
		`[[ "${current_base_sha}" != "${EXPECTED_BASE_SHA}" ]]`,
		`[[ "${local_head_sha}" != "${EXPECTED_LOCAL_SHA}" ]]`,
		`[[ "${local_source_head_sha}" != "${EXPECTED_HEAD_SHA}" ]]`,
		`[[ "${local_source_base_sha}" != "${EXPECTED_BASE_SHA}" ]]`,
		`[[ "${local_pinned_head_sha}" != "${EXPECTED_HEAD_SHA}" ]]`,
		`[[ "${local_pinned_base_sha}" != "${EXPECTED_BASE_SHA}" ]]`,
		`timeout 30s gh api --paginate --slurp`,
		`select(.user.login == "github-actions[bot]")`,
		`rtrimstr("\n" + $marker)`,
		`gsub("[[:space:]]"; "")`,
		`length > 0`,
		`Claude review did not publish the run-specific pull request comment`,
		"exit 1",
	)
	requireBlockContains(t, verify.Run, `if [[ -z "${CLAUDE_EXECUTION_FILE}" ]]`, "\nfi", "exit 1")
	requireBlockContains(t, verify.Run, `if git config --local --get-regexp`, "\nfi", "exit 1")
	requireNoShaValueEcho(t, verify.Run)
	requireNoStatusOverride(t, job)
}

func interactiveJob(t *testing.T) (workflow, job) {
	t.Helper()
	interactive := loadWorkflow(t, "claude.yml")
	return interactive, interactive.Jobs["claude"]
}

func TestClaudeCommandsUseTrustedPRConversationCommentsOnly(t *testing.T) {
	interactive, job := interactiveJob(t)
	wantEvents := map[string]trigger{
		"issue_comment": {Types: []string{"created"}},
	}
	if !reflect.DeepEqual(interactive.On, wantEvents) {
		t.Errorf("interactive triggers = %v, want %v", interactive.On, wantEvents)
	}
	for _, event := range []string{"pull_request", "pull_request_review", "pull_request_review_comment"} {
		if _, ok := interactive.On[event]; ok {
			t.Errorf("secrets-bearing interactive workflow must not use untrusted %s event", event)
		}
	}
	requireEmptyTopLevelPermissions(t, interactive.Permissions)
	if got, want := interactive.Concurrency.Group, "claude-command-${{ github.event.issue.number }}"; got != want {
		t.Errorf("interactive concurrency group = %q, want %q", got, want)
	}
	if interactive.Concurrency.CancelInProgress {
		t.Error("interactive commands must finish in order instead of cancelling an in-flight result")
	}
	if job.TimeoutMinutes != 20 {
		t.Errorf("interactive timeout = %d, want a bounded 20-minute analysis window", job.TimeoutMinutes)
	}
	requireExpression(t, job.If, `
		github.event.issue.pull_request != null &&
		( github.event.comment.body == '@claude' || startsWith(github.event.comment.body, '@claude ') ) &&
		( github.event.comment.author_association == 'OWNER' || github.event.comment.author_association == 'MEMBER' || github.event.comment.author_association == 'COLLABORATOR' )
	`)
	if strings.Contains(job.If, "contains(") {
		t.Error("Claude command grammar must use an anchored @claude prefix")
	}
	wantPermissions := map[string]string{
		"contents": "read", "pull-requests": "read", "issues": "read",
		"actions": "read", "id-token": "write",
	}
	if !reflect.DeepEqual(job.Permissions, wantPermissions) {
		t.Errorf("interactive permissions = %v, want %v", job.Permissions, wantPermissions)
	}
	wantSteps := []string{
		"Validate Claude trigger actor permission", "Resolve Claude pull request context", "Checkout trusted default branch history",
		"Pin Claude pull request snapshots", "Run Claude Code", "Verify reviewed pull request snapshots",
	}
	if len(job.Steps) != len(wantSteps) {
		t.Fatalf("interactive steps = %d, want %d", len(job.Steps), len(wantSteps))
	}
	for index, name := range wantSteps {
		if job.Steps[index].Name != name {
			t.Errorf("interactive step %d = %q, want %q", index, job.Steps[index].Name, name)
		}
	}
	requireNoStatusOverride(t, job)
}

func TestClaudeCommandActorContract(t *testing.T) {
	_, job := interactiveJob(t)
	authorize, _ := findStep(t, job.Steps, "Validate Claude trigger actor permission")
	if authorize.ID != "claude_actor" {
		t.Errorf("authorization step id = %q, want claude_actor", authorize.ID)
	}
	wantEnv := map[string]string{
		"GH_TOKEN":      "${{ github.token }}",
		"TRIGGER_ACTOR": "${{ github.event.comment.user.login || github.actor }}",
	}
	if !reflect.DeepEqual(authorize.Env, wantEnv) {
		t.Errorf("authorization env = %v, want %v", authorize.Env, wantEnv)
	}
	requireContains(t, authorize.Run,
		`timeout 30s gh api "repos/${GITHUB_REPOSITORY}/collaborators/${TRIGGER_ACTOR}/permission"`,
		"Unable to resolve Claude trigger actor permission", "admin|maintain|write",
		"must have write access", "authorized=true",
	)
	requireBlockContains(t, authorize.Run, `if [[ -z "${TRIGGER_ACTOR}" ]]; then`, "\nfi", "exit 1")
	requireBlockContains(t, authorize.Run, `if ! actor_permission=`, "\nfi", "exit 1")
	requireBlockContains(t, authorize.Run, "*)", ";;", "exit 1")
}

func TestClaudeCommandResolverContract(t *testing.T) {
	_, job := interactiveJob(t)
	resolve, _ := findStep(t, job.Steps, "Resolve Claude pull request context")
	checkout, _ := findStep(t, job.Steps, "Checkout trusted default branch history")
	if resolve.ID != "claude_pr" || resolve.If != "" {
		t.Errorf("resolver = {id:%q if:%q}, want unconditional claude_pr", resolve.ID, resolve.If)
	}
	wantEnv := map[string]string{
		"GH_TOKEN":  "${{ github.token }}",
		"PR_NUMBER": "${{ github.event.issue.number }}",
	}
	if !reflect.DeepEqual(resolve.Env, wantEnv) {
		t.Errorf("resolver env = %v, want %v", resolve.Env, wantEnv)
	}
	if got := strings.Count(resolve.Run, `timeout 30s gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"`); got != 1 {
		t.Errorf("bounded resolver API calls = %d, want one", got)
	}
	forkGuard := `if [[ "${head_repo}" != "${GITHUB_REPOSITORY}" ]]; then`
	baseRepoGuard := `if [[ -z "${base_repo}" ]] || [[ "${base_repo}" != "${GITHUB_REPOSITORY}" ]]; then`
	headSHAGuard := `if [[ ! "${head_sha}" =~ ^[0-9a-f]{40}$ ]]; then`
	baseSHAGuard := `if [[ ! "${base_sha}" =~ ^[0-9a-f]{40}$ ]]; then`
	commitCountGuard := `if [[ ! "${commit_count}" =~ ^[0-9]+$ ]]; then`
	openGuard := `if [[ "${pr_state}" != "open" ]]; then`
	defaultBranchGuard := `if [[ ! "${default_branch}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]] ||`
	headRefGuard := `if [[ ! "${head_ref}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]] ||`
	defaultHeadGuard := `if [[ "${head_ref}" == "${default_branch}" ]]; then`
	baseRefGuard := `if [[ ! "${base_ref}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]] ||`
	overlapGuard := `if [[ "${head_ref}" == "${base_ref}" ]] ||`
	requireContains(t, resolve.Run,
		`[.head.repo.full_name // "", .head.sha // "", .head.ref // "", .base.repo.full_name // "", .base.repo.default_branch // "", .base.sha // "", .base.ref // "", .commits // "", .state // ""] | @tsv`,
		forkGuard, baseRepoGuard, headSHAGuard, baseSHAGuard, commitCountGuard,
		openGuard, defaultBranchGuard, `git check-ref-format "refs/heads/${default_branch}"`,
		`fetch_depth=20`, `10#${commit_count}`, headRefGuard, defaultHeadGuard, baseRefGuard,
		`[[ "${head_ref}" == "@" ]]`, `[[ "${base_ref}" == "@" ]]`, `[[ "${default_branch}" == "@" ]]`,
		`git check-ref-format "refs/heads/${head_ref}"`, `git check-ref-format "refs/heads/${base_ref}"`,
		overlapGuard, "head_sha=${head_sha}", "head_ref=${head_ref}",
		"base_sha=${base_sha}", "base_ref=${base_ref}", "default_branch=${default_branch}",
		"fetch_depth=${fetch_depth}", "checkout_allowed=true",
	)
	for _, guard := range []string{
		`if [[ -z "${PR_NUMBER}" ]]; then`, `if ! pr_context=`, `if [[ -z "${head_repo}" ]]; then`,
		forkGuard, baseRepoGuard, openGuard, defaultBranchGuard, headSHAGuard, baseSHAGuard, commitCountGuard,
		headRefGuard, defaultHeadGuard, baseRefGuard, overlapGuard,
	} {
		requireBlockContains(t, resolve.Run, guard, "\nfi", "exit 1")
	}
	if checkout.ID != "checkout" || checkout.Uses != checkoutAction {
		t.Errorf("checkout = {id:%q uses:%q}, want immutable checkout", checkout.ID, checkout.Uses)
	}
	requireExpression(t, checkout.If, `steps.claude_actor.outputs.authorized == 'true' && steps.claude_pr.outputs.checkout_allowed == 'true'`)
	wantCheckout := map[string]string{
		"ref": "${{ github.event.repository.default_branch }}", "fetch-depth": "0", "persist-credentials": "false",
	}
	if !reflect.DeepEqual(checkout.With, wantCheckout) {
		t.Errorf("checkout inputs = %v, want %v", checkout.With, wantCheckout)
	}
}

func TestClaudeCommandResolverRejectsUnsafeWriteTargets(t *testing.T) {
	_, job := interactiveJob(t)
	resolve, _ := findStep(t, job.Steps, "Resolve Claude pull request context")
	_, baseSHA, headSHA := newGitSnapshotFixture(t, 2)
	mockBin := writeClaudeCommandAPIMocks(t)
	outputFile := filepath.Join(t.TempDir(), "github-output")

	baseEnvironment := map[string]string{
		"PATH":                   mockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_TOKEN":               "test-token",
		"GITHUB_REPOSITORY":      "layervai/qurl-connector",
		"GITHUB_OUTPUT":          outputFile,
		"PR_NUMBER":              "461",
		"CURRENT_HEAD_REPO":      "layervai/qurl-connector",
		"CURRENT_HEAD_SHA":       headSHA,
		"CURRENT_HEAD_REF":       "feature/review",
		"CURRENT_BASE_REPO":      "layervai/qurl-connector",
		"CURRENT_DEFAULT_BRANCH": "main",
		"CURRENT_BASE_SHA":       baseSHA,
		"CURRENT_BASE_REF":       "main",
		"CURRENT_COMMIT_COUNT":   "2",
		"CURRENT_PR_STATE":       "open",
	}
	cloneEnvironment := func(overrides map[string]string) map[string]string {
		result := make(map[string]string, len(baseEnvironment)+len(overrides))
		for key, value := range baseEnvironment {
			result[key] = value
		}
		for key, value := range overrides {
			result[key] = value
		}
		return result
	}

	if output, err := runBash(t, t.TempDir(), resolve.Run, cloneEnvironment(nil)); err != nil {
		t.Fatalf("valid open feature PR rejected: %v\n%s", err, output)
	}
	outputContents, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("read resolver outputs: %v", err)
	}
	requireContains(t, string(outputContents), "default_branch=main", "checkout_allowed=true")

	testCases := []struct {
		name      string
		overrides map[string]string
		wantError string
	}{
		{
			name:      "closed pull request",
			overrides: map[string]string{"CURRENT_PR_STATE": "closed"},
			wantError: "currently open pull request",
		},
		{
			name: "default branch head",
			overrides: map[string]string{
				"CURRENT_HEAD_REF": "main",
				"CURRENT_BASE_REF": "release/stable",
			},
			wantError: "cannot write to the repository default branch",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			output, err := runBash(t, t.TempDir(), resolve.Run, cloneEnvironment(testCase.overrides))
			if err == nil {
				t.Fatalf("unsafe write target unexpectedly passed\n%s", output)
			}
			if !strings.Contains(output, testCase.wantError) {
				t.Fatalf("resolver output = %q, want %q", output, testCase.wantError)
			}
		})
	}
}

func TestClaudeCommandLocalOriginContract(t *testing.T) {
	_, job := interactiveJob(t)
	pinBranch, _ := findStep(t, job.Steps, "Pin Claude pull request snapshots")
	if pinBranch.ID != "pin_claude_branch" || pinBranch.If != "steps.checkout.outcome == 'success'" {
		t.Errorf("pin step = {id:%q if:%q}", pinBranch.ID, pinBranch.If)
	}
	wantEnv := map[string]string{
		"EXPECTED_HEAD_SHA":       "${{ steps.claude_pr.outputs.head_sha }}",
		"PR_HEAD_REF":             "${{ steps.claude_pr.outputs.head_ref }}",
		"EXPECTED_BASE_SHA":       "${{ steps.claude_pr.outputs.base_sha }}",
		"PR_BASE_REF":             "${{ steps.claude_pr.outputs.base_ref }}",
		"FETCH_DEPTH":             "${{ steps.claude_pr.outputs.fetch_depth }}",
		"EXPECTED_DEFAULT_BRANCH": "${{ steps.claude_pr.outputs.default_branch }}",
		"TRUSTED_REF":             "${{ github.event.repository.default_branch }}",
	}
	if !reflect.DeepEqual(pinBranch.Env, wantEnv) {
		t.Errorf("pin env = %v, want %v", pinBranch.Env, wantEnv)
	}
	requireContains(t, pinBranch.Run,
		`[[ ! "${EXPECTED_HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ ! "${EXPECTED_BASE_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ ! "${FETCH_DEPTH}" =~ ^[0-9]+$ ]]`, `(( 10#${FETCH_DEPTH} < 20 ))`,
		`[[ ! "${PR_HEAD_REF}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]`,
		`[[ ! "${PR_BASE_REF}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]`,
		`[[ "${PR_HEAD_REF}" == "@" ]]`, `[[ "${PR_BASE_REF}" == "@" ]]`,
		`git check-ref-format "refs/heads/${PR_HEAD_REF}"`, `git check-ref-format "refs/heads/${PR_BASE_REF}"`,
		`git check-ref-format "refs/heads/${TRUSTED_REF}"`,
		`[[ "${TRUSTED_REF}" != "${EXPECTED_DEFAULT_BRANCH}"`,
		`"${PR_HEAD_REF}" == "${EXPECTED_DEFAULT_BRANCH}"`,
		`trusted_head_sha="$(git rev-parse --verify HEAD 2>/dev/null)"`,
		`trusted_branch="$(git symbolic-ref --quiet --short HEAD 2>/dev/null)"`,
		`git checkout --detach --quiet "${trusted_head_sha}"`,
		`git cat-file -e "${EXPECTED_HEAD_SHA}^{commit}"`, `git cat-file -e "${EXPECTED_BASE_SHA}^{commit}"`,
		`sensitive_files=(`, `.mcp.json`, `.claude.json`, `.gitmodules`, `.ripgreprc`, `CLAUDE.md`, `CLAUDE.local.md`,
		`sensitive_directories=(.claude .husky)`,
		`git ls-tree`, `--format='%(objectmode) %(objecttype)'`,
		`"${EXPECTED_HEAD_SHA}" -- "${sensitive_path}"`,
		`"100644 blob"`, `"100755 blob"`, `"040000 tree"`, `git ls-tree -r`,
		`PR head contains a non-regular sensitive path`,
		`PR head contains a non-directory sensitive path`,
		`PR head contains a non-regular sensitive descendant`,
		`git config --local --get-regexp '^http\..*\.extraheader$'`,
		`git config --local --get-regexp '^credential(\..*)?\.helper$'`,
		`git config --local fetch.recurseSubmodules false`,
		`git branch --force -- "${PR_BASE_REF}" "${EXPECTED_BASE_SHA}"`,
		`git branch --force -- "${PR_HEAD_REF}" "${EXPECTED_HEAD_SHA}"`,
		`git remote set-url origin "${GITHUB_WORKSPACE}/.git"`,
		`git fetch origin --depth="${FETCH_DEPTH}" "${PR_HEAD_REF}"`,
		`git fetch origin "${PR_BASE_REF}" --depth=1 --no-recurse-submodules`,
		`refs/remotes/origin/${PR_HEAD_REF}^{commit}`, `refs/remotes/origin/${PR_BASE_REF}^{commit}`,
		// Tamper evidence lives in a namespace the Claude action never writes.
		`git update-ref refs/claude-command/head "${EXPECTED_HEAD_SHA}"`,
		`git update-ref refs/claude-command/base "${EXPECTED_BASE_SHA}"`,
		`refs/claude-command/head^{commit}`, `refs/claude-command/base^{commit}`,
		`Local-origin preparation checked out pull-request code before the pinned action`,
	)
	requireInOrder(t, pinBranch.Run,
		`git checkout --detach --quiet "${trusted_head_sha}"`,
		`sensitive_files=(`,
		`git config --local --get-regexp '^http\..*\.extraheader$'`,
		`git config --local fetch.recurseSubmodules false`,
		`git branch --force -- "${PR_BASE_REF}" "${EXPECTED_BASE_SHA}"`,
		`git branch --force -- "${PR_HEAD_REF}" "${EXPECTED_HEAD_SHA}"`,
		`git remote set-url origin "${GITHUB_WORKSPACE}/.git"`,
		`git fetch origin --depth="${FETCH_DEPTH}" "${PR_HEAD_REF}"`,
		`git fetch origin "${PR_BASE_REF}" --depth=1 --no-recurse-submodules`,
	)
	requireNoShaValueEcho(t, pinBranch.Run)
	if strings.Contains(pinBranch.Run, "github.token") || strings.Contains(pinBranch.Run, "GH_TOKEN") {
		t.Error("local-origin shim must not embed a GitHub credential")
	}
}

func TestClaudeCommandActionContract(t *testing.T) {
	_, job := interactiveJob(t)
	runClaude, _ := findStep(t, job.Steps, "Run Claude Code")
	if runClaude.ID != "claude" || runClaude.Uses != claudeAction || runClaude.If != "steps.pin_claude_branch.outcome == 'success'" {
		t.Errorf("interactive action = {id:%q uses:%q if:%q}", runClaude.ID, runClaude.Uses, runClaude.If)
	}
	wantInputs := map[string]string{
		"anthropic_api_key":         "${{ secrets.ANTHROPIC_API_KEY }}",
		"claude_args":               "--model " + claudeModel,
		"use_commit_signing":        "true",
		"exclude_comments_by_actor": "github-actions[bot]",
	}
	if !reflect.DeepEqual(runClaude.With, wantInputs) {
		t.Errorf("interactive action inputs = %v, want exactly %v", runClaude.With, wantInputs)
	}
	reviewClaude, _ := findStep(t, loadWorkflow(t, "claude-code-review.yml").Jobs["claude-review"].Steps, "Run Claude Code Review")
	if got, want := selectedClaudeModel(runClaude.With["claude_args"]), selectedClaudeModel(reviewClaude.With["claude_args"]); got != want || got != claudeModel {
		t.Errorf("interactive model = %q, automatic model = %q, want %q", got, want, claudeModel)
	}
}

func TestClaudeCommandTerminalContract(t *testing.T) {
	_, job := interactiveJob(t)
	verify, _ := findStep(t, job.Steps, "Verify reviewed pull request snapshots")
	if verify.If != "" {
		t.Errorf("snapshot verification condition = %q, want default success chaining", verify.If)
	}
	wantEnv := map[string]string{
		"GH_TOKEN":                "${{ github.token }}",
		"PR_NUMBER":               "${{ steps.claude_pr.outputs.number }}",
		"EXPECTED_HEAD_SHA":       "${{ steps.claude_pr.outputs.head_sha }}",
		"EXPECTED_HEAD_REF":       "${{ steps.claude_pr.outputs.head_ref }}",
		"EXPECTED_BASE_SHA":       "${{ steps.claude_pr.outputs.base_sha }}",
		"EXPECTED_BASE_REF":       "${{ steps.claude_pr.outputs.base_ref }}",
		"EXPECTED_DEFAULT_BRANCH": "${{ steps.claude_pr.outputs.default_branch }}",
		"CLAUDE_EXECUTION_FILE":   "${{ steps.claude.outputs.execution_file }}",
	}
	if !reflect.DeepEqual(verify.Env, wantEnv) {
		t.Errorf("terminal env = %v, want %v", verify.Env, wantEnv)
	}
	if got := strings.Count(verify.Run, `timeout 30s gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}"`); got != 1 {
		t.Errorf("bounded terminal API calls = %d, want one", got)
	}
	requireContains(t, verify.Run,
		`[[ -z "${CLAUDE_EXECUTION_FILE}" ]]`, `[[ ! -f "${CLAUDE_EXECUTION_FILE}" ]]`,
		`[[ ! -s "${CLAUDE_EXECUTION_FILE}" ]]`,
		`[[ ! "${EXPECTED_HEAD_SHA}" =~ ^[0-9a-f]{40}$ ]]`, `[[ ! "${EXPECTED_BASE_SHA}" =~ ^[0-9a-f]{40}$ ]]`,
		`[[ ! "${EXPECTED_HEAD_REF}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]`,
		`[[ ! "${EXPECTED_BASE_REF}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]`,
		`[[ ! "${EXPECTED_DEFAULT_BRANCH}" =~ ^[A-Za-z0-9@_][A-Za-z0-9/_.#+,@-]*$ ]]`,
		`[[ "${EXPECTED_HEAD_REF}" == "@" ]]`, `[[ "${EXPECTED_BASE_REF}" == "@" ]]`, `[[ "${EXPECTED_DEFAULT_BRANCH}" == "@" ]]`,
		`git check-ref-format "refs/heads/${EXPECTED_HEAD_REF}"`,
		`git check-ref-format "refs/heads/${EXPECTED_BASE_REF}"`,
		`git check-ref-format "refs/heads/${EXPECTED_DEFAULT_BRANCH}"`,
		`[[ "${EXPECTED_HEAD_REF}" == "${EXPECTED_DEFAULT_BRANCH}" ]]`,
		`git config --local --get-regexp '^http\..*\.extraheader$'`,
		`git config --local --get-regexp '^credential(\..*)?\.helper$'`,
		`git config --local --get fetch.recurseSubmodules`,
		`git remote get-url origin`, `${GITHUB_WORKSPACE}/.git`,
		`[.head.repo.full_name // "", .head.sha // "", .head.ref // "", .base.repo.full_name // "", .base.repo.default_branch // "", .base.sha // "", .base.ref // "", .state // ""] | @tsv`,
		`refs/heads/${EXPECTED_HEAD_REF}^{commit}`, `refs/heads/${EXPECTED_BASE_REF}^{commit}`,
		`refs/claude-command/head^{commit}`, `refs/claude-command/base^{commit}`,
		// The action owns origin from v1.0.187 on; the boundary arm checks the
		// remote's destination, parsing the authority so a userinfo-lookalike
		// path cannot masquerade as this repository.
		`[[ -z "${GITHUB_SERVER_URL}" ]]`,
		`origin_url="$(git remote get-url origin 2>/dev/null || true)"`,
		`origin_authority="${origin_authority##*@}"`,
		`[[ "${origin_dest}" != "${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}.git" ]]`,
		`[[ "${current_head_repo}" != "${GITHUB_REPOSITORY}" ]]`,
		`[[ "${current_base_repo}" != "${GITHUB_REPOSITORY}" ]]`,
		`[[ "${current_pr_state}" != "open" ]]`,
		`[[ "${current_default_branch}" != "${EXPECTED_DEFAULT_BRANCH}" ]]`,
		`[[ "${current_head_ref}" == "${current_default_branch}" ]]`,
		`[[ "${current_head_ref}" != "${EXPECTED_HEAD_REF}" ]]`,
		`[[ "${current_base_ref}" != "${EXPECTED_BASE_REF}" ]]`,
		`[[ "${current_head_sha}" != "${EXPECTED_HEAD_SHA}" ]]`,
		`[[ "${current_base_sha}" != "${EXPECTED_BASE_SHA}" ]]`,
		`[[ "${local_source_head_sha}" != "${EXPECTED_HEAD_SHA}" ]]`,
		`[[ "${local_source_base_sha}" != "${EXPECTED_BASE_SHA}" ]]`,
		`[[ "${local_pinned_head_sha}" != "${EXPECTED_HEAD_SHA}" ]]`,
		`[[ "${local_pinned_base_sha}" != "${EXPECTED_BASE_SHA}" ]]`,
	)
	requireBlockContains(t, verify.Run, `if [[ -z "${CLAUDE_EXECUTION_FILE}" ]]`, "\nfi", "exit 1")
	requireBlockContains(t, verify.Run, `if git config --local --get-regexp`, "\nfi", "exit 1")
	requireNoShaValueEcho(t, verify.Run)
}

func TestClaudeCommandTerminalRejectsUnsafeWriteTargets(t *testing.T) {
	_, job := interactiveJob(t)
	pinBranch, _ := findStep(t, job.Steps, "Pin Claude pull request snapshots")
	verify, _ := findStep(t, job.Steps, "Verify reviewed pull request snapshots")
	repository, baseSHA, headSHA := newGitSnapshotFixture(t, 2)
	const (
		baseRef    = "main"
		headRef    = "feature/review"
		trustedRef = "main"
	)
	runGit(t, repository, "branch", "--force", "--", baseRef, baseSHA)
	runGit(t, repository, "branch", "--force", "--", headRef, headSHA)
	runGit(t, repository, "checkout", "--quiet", baseRef)
	runGit(t, repository, "remote", "add", "origin", "https://example.invalid/layervai/qurl-connector.git")

	pinOutput := filepath.Join(t.TempDir(), "github-output")
	if output, err := runBash(t, repository, pinBranch.Run, map[string]string{
		"EXPECTED_HEAD_SHA":       headSHA,
		"PR_HEAD_REF":             headRef,
		"EXPECTED_BASE_SHA":       baseSHA,
		"PR_BASE_REF":             baseRef,
		"FETCH_DEPTH":             "20",
		"EXPECTED_DEFAULT_BRANCH": trustedRef,
		"TRUSTED_REF":             trustedRef,
		"GITHUB_WORKSPACE":        repository,
		"GITHUB_OUTPUT":           pinOutput,
	}); err != nil {
		t.Fatalf("prepare interactive snapshots: %v\n%s", err, output)
	}
	runGit(t, repository, "checkout", "--quiet", headRef)

	executionFile := filepath.Join(t.TempDir(), "execution.json")
	if err := os.WriteFile(executionFile, []byte("{\"subtype\":\"success\"}\n"), 0o600); err != nil {
		t.Fatalf("write execution record: %v", err)
	}
	mockBin := writeClaudeCommandAPIMocks(t)
	baseEnvironment := map[string]string{
		"PATH":                    mockBin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GH_TOKEN":                "test-token",
		"GITHUB_WORKSPACE":        repository,
		"GITHUB_REPOSITORY":       "layervai/qurl-connector",
		"PR_NUMBER":               "461",
		"EXPECTED_HEAD_SHA":       headSHA,
		"EXPECTED_HEAD_REF":       headRef,
		"EXPECTED_BASE_SHA":       baseSHA,
		"EXPECTED_BASE_REF":       baseRef,
		"EXPECTED_DEFAULT_BRANCH": trustedRef,
		"CLAUDE_EXECUTION_FILE":   executionFile,
		"CURRENT_HEAD_REPO":       "layervai/qurl-connector",
		"CURRENT_HEAD_SHA":        headSHA,
		"CURRENT_HEAD_REF":        headRef,
		"CURRENT_BASE_REPO":       "layervai/qurl-connector",
		"CURRENT_DEFAULT_BRANCH":  trustedRef,
		"CURRENT_BASE_SHA":        baseSHA,
		"CURRENT_BASE_REF":        baseRef,
		"CURRENT_PR_STATE":        "open",
		// Set explicitly so the boundary arm resolves identically off-runner.
		"GITHUB_SERVER_URL": "https://github.com",
	}
	cloneEnvironment := func(overrides map[string]string) map[string]string {
		result := make(map[string]string, len(baseEnvironment)+len(overrides))
		for key, value := range baseEnvironment {
			result[key] = value
		}
		for key, value := range overrides {
			result[key] = value
		}
		return result
	}

	if output, err := runBash(t, repository, verify.Run, cloneEnvironment(nil)); err != nil {
		t.Fatalf("valid terminal snapshot rejected: %v\n%s", err, output)
	}

	testCases := []struct {
		name      string
		overrides map[string]string
	}{
		{name: "pull request closed", overrides: map[string]string{"CURRENT_PR_STATE": "closed"}},
		{name: "head becomes default branch", overrides: map[string]string{"CURRENT_DEFAULT_BRANCH": headRef}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			output, err := runBash(t, repository, verify.Run, cloneEnvironment(testCase.overrides))
			if err == nil {
				t.Fatalf("unsafe terminal write target unexpectedly passed\n%s", output)
			}
			if !strings.Contains(output, "Current PR or local snapshot is invalid") {
				t.Fatalf("terminal output = %q, want unsafe-current-state error", output)
			}
		})
	}

	// Tag mode routes through the same replaceCheckoutCredentials() from
	// v1.0.187 on, so the interactive lane sees the identical origin rewrite
	// the review lane does. It must be accepted, and off-repository
	// destinations must still fail closed.
	const boundaryError = "Local Git boundary moved off this repository"
	actionOrigin := "https://x-access-token:ghs-test-token@github.com/layervai/qurl-connector.git"
	runGit(t, repository, "remote", "set-url", "origin", actionOrigin)
	if output, err := runBash(t, repository, verify.Run, cloneEnvironment(nil)); err != nil {
		t.Fatalf("action-configured origin rejected: %v\n%s", err, output)
	}

	offRepoOrigins := []struct {
		name   string
		remote string
	}{
		{name: "third-party host", remote: "https://x-access-token:t@evil.example.com/attacker/exfil.git"},
		{name: "same host other repo", remote: "https://x-access-token:t@github.com/attacker/exfil.git"},
		{name: "userinfo lookalike path", remote: "https://evil.example.com/@github.com/layervai/qurl-connector.git"},
		// Both lanes share the identical parser, so pin scheme enforcement on
		// this one too rather than only on the review lane.
		{name: "other scheme", remote: "ssh://git@evil.example.com/layervai/qurl-connector.git"},
	}
	for _, testCase := range offRepoOrigins {
		t.Run(testCase.name, func(t *testing.T) {
			runGit(t, repository, "remote", "set-url", "origin", testCase.remote)
			output, err := runBash(t, repository, verify.Run, cloneEnvironment(nil))
			if err == nil {
				t.Fatalf("off-repository origin unexpectedly passed\n%s", output)
			}
			if !strings.Contains(output, boundaryError) {
				t.Fatalf("terminal output = %q, want %q", output, boundaryError)
			}
			if strings.Contains(output, "x-access-token") {
				t.Errorf("verifier leaked remote credentials into logs: %q", output)
			}
			runGit(t, repository, "remote", "set-url", "origin", actionOrigin)
		})
	}
}
