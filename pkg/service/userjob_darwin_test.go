//go:build darwin

package service

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLaunchdOutputRunningRequiresStateAndPID(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{"running", "state = running\npid = 4242\n", true},
		{"loaded waiting", "state = waiting\nlast exit code = 0\n", false},
		{"state without process", "state = running\n", false},
		{"pid without running state", "state = exited\npid = 4242\n", false},
		{"zero pid", "state = running\npid = 0\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := launchdOutputRunning(tc.output); got != tc.want {
				t.Fatalf("launchdOutputRunning() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLaunchdEnsureLeavesMatchingRunningJobUntouched(t *testing.T) {
	dir := t.TempDir()
	job := testUserJob(dir, "daemon", "run", "--job-version", "1/test")
	content, err := RenderLaunchdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(dir, "job.plist")
	if err := os.WriteFile(plist, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		launchctlQuery: func(args ...string) (string, error) {
			calls = append(calls, append([]string(nil), args...))
			return "state = running\npid = 4242\n", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := [][]string{{"print", "gui/" + userIDForTest() + "/" + job.Label}}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("launchctl calls = %#v, want only the non-disruptive status read %#v", calls, want)
	}
}

func TestLaunchdReplaceReloadsMatchingRunningJob(t *testing.T) {
	dir := t.TempDir()
	job := testUserJob(dir, "daemon", "run", "--job-version", "1/test")
	content, err := RenderLaunchdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(dir, "job.plist")
	if err := os.WriteFile(plist, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		launchctlQuery: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "print" {
				return "state = running\npid = 4242\n", nil
			}
			return "", nil
		},
	}
	if err := manager.Replace(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"print", "bootout", "bootstrap", "kickstart"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("launchctl verbs = %v, want forced reload %v", verbs, want)
	}
}

func TestLaunchdEnsureReloadsChangedJobDefinition(t *testing.T) {
	dir := t.TempDir()
	oldJob := testUserJob(dir, "daemon", "run", "--job-version", "1/old")
	newJob := testUserJob(dir, "daemon", "run", "--job-version", "1/new")
	oldContent, err := RenderLaunchdUserJob(oldJob)
	if err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(dir, "job.plist")
	if err := os.WriteFile(plist, []byte(oldContent), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		launchctlQuery: func(args ...string) (string, error) {
			calls = append(calls, append([]string(nil), args...))
			if args[0] == "print" {
				return "state = running\npid = 4242\n", nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(newJob); err != nil {
		t.Fatal(err)
	}
	verbs := make([]string, 0, len(calls))
	for _, call := range calls {
		verbs = append(verbs, call[0])
	}
	if want := []string{"print", "bootout", "bootstrap", "kickstart"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("launchctl verbs = %v, want %v", verbs, want)
	}
	updated, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "1/new") || strings.Contains(string(updated), "1/old") {
		t.Fatalf("persisted definition was not replaced:\n%s", updated)
	}
}

func TestLaunchdEnsurePreservesOldDefinitionWhenBootoutFailsThenRetries(t *testing.T) {
	dir := t.TempDir()
	oldJob := testUserJob(dir, "daemon", "run", "--job-version", "1/old")
	newJob := testUserJob(dir, "daemon", "run", "--job-version", "1/new")
	oldContent, err := RenderLaunchdUserJob(oldJob)
	if err != nil {
		t.Fatal(err)
	}
	plist := filepath.Join(dir, "job.plist")
	if err := os.WriteFile(plist, []byte(oldContent), 0o600); err != nil {
		t.Fatal(err)
	}
	bootoutAttempts := 0
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		launchctlQuery: func(args ...string) (string, error) {
			switch args[0] {
			case "print":
				return "state = running\npid = 4242\n", nil
			case "bootout":
				bootoutAttempts++
				if bootoutAttempts == 1 {
					return "", errors.New("temporary launchd failure")
				}
			}
			return "", nil
		},
	}
	if err := manager.Ensure(newJob); err == nil {
		t.Fatal("first Ensure succeeded despite bootout failure")
	}
	stillOld, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stillOld, []byte(oldContent)) {
		t.Fatalf("bootout failure replaced the plist for the still-loaded old job:\n%s", stillOld)
	}
	if err := manager.Ensure(newJob); err != nil {
		t.Fatalf("retry Ensure: %v", err)
	}
	updated, err := os.ReadFile(plist)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "1/new") || strings.Contains(string(updated), "1/old") {
		t.Fatalf("retry did not install the new definition:\n%s", updated)
	}
}

func TestLaunchdEnsureRetriesBootstrapAfterConfirmedBootoutRace(t *testing.T) {
	dir := t.TempDir()
	job := testUserJob(dir, "daemon", "run", "--job-version", "1/new")
	plist := filepath.Join(dir, "job.plist")
	oldJob := testUserJob(dir, "daemon", "run", "--job-version", "1/old")
	oldContent, err := RenderLaunchdUserJob(oldJob)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte(oldContent), 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrapAttempts := 0
	printCalls := 0
	bootouts := 0
	var waited time.Duration
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		sleep:     func(delay time.Duration) { waited += delay },
		launchctlQuery: func(args ...string) (string, error) {
			switch args[0] {
			case "print":
				printCalls++
				if printCalls == 1 {
					return "state = running\npid = 4242\n", nil
				}
				return "", &launchctlError{args: append([]string(nil), args...), output: "Could not find service", err: errors.New("exit status 113")}
			case "bootout":
				bootouts++
			case "bootstrap":
				bootstrapAttempts++
				if bootstrapAttempts == 1 {
					return "", errors.New("transient launchd EIO")
				}
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if bootstrapAttempts != 2 || bootouts != 1 || waited != launchdBootstrapRetryDelay {
		t.Fatalf("bootstrap attempts=%d bootouts=%d wait=%s, want 2/1/%s",
			bootstrapAttempts, bootouts, waited, launchdBootstrapRetryDelay)
	}
}

func TestLaunchdEnsureConvergesAmbiguousLoadedBootstrapFailure(t *testing.T) {
	dir := t.TempDir()
	job := testUserJob(dir, "daemon", "run", "--job-version", "1/new")
	plist := filepath.Join(dir, "job.plist")
	printCalls := 0
	bootstrapAttempts := 0
	bootouts := 0
	loaded := false
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		sleep: func(delay time.Duration) {
			if delay != launchdBootstrapRetryDelay {
				t.Fatalf("bootstrap settle wait=%s, want %s", delay, launchdBootstrapRetryDelay)
			}
		},
		launchctlQuery: func(args ...string) (string, error) {
			switch args[0] {
			case "print":
				printCalls++
				if !loaded {
					return "", &launchctlError{args: append([]string(nil), args...), output: "Could not find service", err: errors.New("exit status 113")}
				}
				return "state = running\npid = 4242\n", nil
			case "bootout":
				bootouts++
				loaded = false
			case "bootstrap":
				bootstrapAttempts++
				if bootstrapAttempts == 1 {
					loaded = true
					return "", errors.New("ambiguous launchd failure")
				}
				loaded = true
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatalf("Ensure() = %v, want same-call convergence", err)
	}
	if bootstrapAttempts != 2 {
		t.Fatalf("bootstrap attempts=%d, want 2", bootstrapAttempts)
	}
	if retained, readErr := os.ReadFile(plist); readErr != nil || len(retained) == 0 {
		t.Fatalf("ambiguous bootstrap did not retain the replacement plist: %q/%v", retained, readErr)
	}
	if bootstrapAttempts != 2 || bootouts != 1 {
		t.Fatalf("same-call bootstrap attempts=%d bootouts=%d, want 2/1", bootstrapAttempts, bootouts)
	}
	if _, statErr := os.Lstat(plist); statErr != nil {
		t.Fatalf("successful retry did not restore plist: %v", statErr)
	}
}

func TestLaunchdBootstrapJoinsAmbiguousInspectionFailure(t *testing.T) {
	bootstrapErr := errors.New("bootstrap failed")
	inspectErr := errors.New("launchd status unavailable")
	manager := &launchdUserJobManager{
		sleep: func(time.Duration) {},
		launchctlQuery: func(args ...string) (string, error) {
			if args[0] == "bootstrap" {
				return "", bootstrapErr
			}
			return "", inspectErr
		},
	}
	stillLoaded, err := manager.bootstrapWithSettleRetry("gui/501", "gui/501/test", "/tmp/test.plist")
	if !errors.Is(err, bootstrapErr) || !errors.Is(err, inspectErr) {
		t.Fatalf("bootstrapWithSettleRetry() = %v, want joined bootstrap and inspection errors", err)
	}
	if !stillLoaded {
		t.Fatal("ambiguous inspection was reported as an absent service")
	}
}

func TestLaunchdBootstrapReportsLoadedAfterRetryError(t *testing.T) {
	firstErr := errors.New("launchd still settling")
	retryErr := errors.New("bootstrap returned EIO after loading")
	bootstrapAttempts := 0
	printCalls := 0
	manager := &launchdUserJobManager{
		sleep: func(time.Duration) {},
		launchctlQuery: func(args ...string) (string, error) {
			switch args[0] {
			case "bootstrap":
				bootstrapAttempts++
				if bootstrapAttempts == 1 {
					return "", firstErr
				}
				return "", retryErr
			case "print":
				printCalls++
				if printCalls == 1 {
					return "", &launchctlError{args: append([]string(nil), args...), output: "Could not find service", err: errors.New("exit status 113")}
				}
				return "state = running\npid = 4242\n", nil
			default:
				return "", nil
			}
		},
	}
	possiblyLoaded, err := manager.bootstrapWithSettleRetry("gui/501", "gui/501/test", "/tmp/test.plist")
	if !errors.Is(err, firstErr) || !errors.Is(err, retryErr) {
		t.Fatalf("bootstrapWithSettleRetry() = %v, want both bootstrap errors", err)
	}
	if !possiblyLoaded {
		t.Fatal("bootstrap retry loaded the service but reported it absent")
	}
	if bootstrapAttempts != 2 || printCalls != 2 {
		t.Fatalf("bootstrap attempts=%d print calls=%d, want 2/2", bootstrapAttempts, printCalls)
	}
}

func TestLaunchdEnsurePreservesChangedPlistWhenAmbiguousStatusCanBeUnloaded(t *testing.T) {
	dir := t.TempDir()
	job := testUserJob(dir, "daemon", "run", "--job-version", "1/new")
	plist := filepath.Join(dir, "job.plist")
	oldJob := testUserJob(dir, "daemon", "run", "--job-version", "1/old")
	oldContent, err := RenderLaunchdUserJob(oldJob)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte(oldContent), 0o600); err != nil {
		t.Fatal(err)
	}
	printCalls := 0
	bootouts := 0
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		sleep:     func(time.Duration) {},
		launchctlQuery: func(args ...string) (string, error) {
			switch args[0] {
			case "print":
				printCalls++
				if printCalls == 1 {
					return "state = running\npid = 4242\n", nil
				}
				return "", errors.New("launchd status unavailable")
			case "bootstrap":
				return "", errors.New("bootstrap failed")
			case "bootout":
				bootouts++
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err == nil ||
		!strings.Contains(err.Error(), "launchd status unavailable") {
		t.Fatalf("Ensure() = %v, want ambiguous status failure", err)
	}
	newContent, renderErr := RenderLaunchdUserJob(job)
	retained, readErr := os.ReadFile(plist)
	if renderErr != nil || readErr != nil || !bytes.Equal(retained, []byte(newContent)) || bootouts != 3 {
		t.Fatalf("ambiguous status recovery = content %q render %v read %v bootouts %d, want new plist and 3 bootouts",
			retained, renderErr, readErr, bootouts)
	}
}

func TestLaunchdEnsureRemovesChangedPlistWhenAmbiguousUnloadFails(t *testing.T) {
	dir := t.TempDir()
	job := testUserJob(dir, "daemon", "run", "--job-version", "1/new")
	plist := filepath.Join(dir, "job.plist")
	oldJob := testUserJob(dir, "daemon", "run", "--job-version", "1/old")
	oldContent, err := RenderLaunchdUserJob(oldJob)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte(oldContent), 0o600); err != nil {
		t.Fatal(err)
	}
	printCalls := 0
	bootouts := 0
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		sleep:     func(time.Duration) {},
		launchctlQuery: func(args ...string) (string, error) {
			switch args[0] {
			case "print":
				printCalls++
				if printCalls == 1 {
					return "state = running\npid = 4242\n", nil
				}
				return "", errors.New("launchd status unavailable")
			case "bootstrap":
				return "", errors.New("bootstrap failed")
			case "bootout":
				bootouts++
				if bootouts == 2 {
					return "", errors.New("ambiguous bootout failed")
				}
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err == nil ||
		!strings.Contains(err.Error(), "launchd status unavailable") ||
		!strings.Contains(err.Error(), "ambiguous bootout failed") {
		t.Fatalf("Ensure() = %v, want joined status and bootout failures", err)
	}
	if _, err := os.Lstat(plist); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ambiguous unload failure left a converged-looking plist: %v", err)
	}
}

func TestLaunchdEnsurePreservesMatchingPlistWhenBothBootstrapAttemptsFailAbsent(t *testing.T) {
	dir := t.TempDir()
	job := testUserJob(dir, "daemon", "run", "--job-version", "1/current")
	plist := filepath.Join(dir, "job.plist")
	content, err := RenderLaunchdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	bootstrapAttempts := 0
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		sleep:     func(time.Duration) {},
		launchctlQuery: func(args ...string) (string, error) {
			if args[0] == "print" {
				return "", &launchctlError{args: append([]string(nil), args...), output: "Could not find service", err: errors.New("exit status 113")}
			}
			if args[0] == "bootstrap" {
				bootstrapAttempts++
				return "", errors.New("launchd domain unavailable")
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err == nil || !strings.Contains(err.Error(), "launchd domain unavailable") {
		t.Fatalf("Ensure() = %v, want bootstrap failure", err)
	}
	if bootstrapAttempts != 2 {
		t.Fatalf("bootstrap attempts=%d, want 2", bootstrapAttempts)
	}
	retained, err := os.ReadFile(plist)
	if err != nil || !bytes.Equal(retained, []byte(content)) {
		t.Fatalf("matching plist after absent bootstrap failure = %q/%v, want retained", retained, err)
	}
}

func TestLaunchdEnsurePreservesChangedPlistWhenBothBootstrapAttemptsFailAbsent(t *testing.T) {
	dir := t.TempDir()
	job := testUserJob(dir, "daemon", "run", "--job-version", "1/new")
	plist := filepath.Join(dir, "job.plist")
	oldJob := testUserJob(dir, "daemon", "run", "--job-version", "1/old")
	oldContent, err := RenderLaunchdUserJob(oldJob)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte(oldContent), 0o600); err != nil {
		t.Fatal(err)
	}
	newContent, err := RenderLaunchdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapAttempts := 0
	manager := &launchdUserJobManager{
		plistPath: func(string) (string, error) { return plist, nil },
		sleep:     func(time.Duration) {},
		launchctlQuery: func(args ...string) (string, error) {
			if args[0] == "print" {
				return "", &launchctlError{args: append([]string(nil), args...), output: "Could not find service", err: errors.New("exit status 113")}
			}
			if args[0] == "bootstrap" {
				bootstrapAttempts++
				return "", errors.New("launchd domain unavailable")
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err == nil || !strings.Contains(err.Error(), "launchd domain unavailable") {
		t.Fatalf("Ensure() = %v, want bootstrap failure", err)
	}
	if bootstrapAttempts != 2 {
		t.Fatalf("bootstrap attempts=%d, want 2", bootstrapAttempts)
	}
	retained, err := os.ReadFile(plist)
	if err != nil || !bytes.Equal(retained, []byte(newContent)) {
		t.Fatalf("changed plist after absent bootstrap failure = %q/%v, want new content retained", retained, err)
	}
}

func testUserJob(dir string, args ...string) UserJob {
	return UserJob{
		Label: "ai.layerv.qurl.test", BinaryPath: "/opt/homebrew/bin/qurl", Arguments: args,
		StandardOut: filepath.Join(dir, "logs", "out.log"), StandardErr: filepath.Join(dir, "logs", "err.log"),
		RunAtLoad: true, KeepAlive: true, Umask: 0o077,
	}
}

func userIDForTest() string {
	// The production service identifier is deliberately per-user. Avoid
	// pinning a developer or CI runner's numeric uid in the assertion.
	return strconv.Itoa(os.Getuid())
}
