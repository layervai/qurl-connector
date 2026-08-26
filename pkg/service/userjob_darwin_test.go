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
