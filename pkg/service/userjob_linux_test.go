//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func linuxTestUserJob(t *testing.T) UserJob {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "qurl helper")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return UserJob{
		Label:       "ai.layerv.qurl.daemon",
		BinaryPath:  binary,
		Arguments:   []string{"daemon", "run", "value with spaces"},
		StandardOut: filepath.Join(dir, "logs", "daemon.log"),
		StandardErr: filepath.Join(dir, "logs", "daemon.err.log"),
		ExitTimeout: 15,
		Umask:       0o077,
		RunAtLoad:   true,
		KeepAlive:   true,
	}
}

func linuxSystemdState(unitPath, load, active, sub, reload string) string {
	return fmt.Sprintf(
		"LoadState=%s\nActiveState=%s\nSubState=%s\nFragmentPath=%s\nNeedDaemonReload=%s\n",
		load, active, sub, unitPath, reload,
	)
}

func TestRenderSystemdUserJobCredentialFreeAndEscaped(t *testing.T) {
	job := linuxTestUserJob(t)
	job.BinaryPath = filepath.Join(filepath.Dir(job.BinaryPath), `qurl with spaces`)
	if err := os.WriteFile(job.BinaryPath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	job.Arguments = []string{`daemon`, `$(touch /tmp/not-run)`, `%n`, `quote"slash\`}
	got, err := RenderSystemdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`ExecStart="`, `$$(`, `%%n`, `quote\"slash\\`,
		`Restart=on-failure`, `TimeoutStopSec=15s`, `UMask=0077`,
		`StandardOutput=append:`, `StandardError=append:`,
		`NoNewPrivileges=true`, `PrivateTmp=true`, `WantedBy=default.target`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("systemd unit missing %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"Environment=", "QURL_API_KEY", "Bearer", "ExecStart=/bin/sh"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("credential-free systemd unit contains %q", forbidden)
		}
	}
}

func TestRenderSystemdUserJobRejectsUnsupportedPathCharacters(t *testing.T) {
	job := linuxTestUserJob(t)
	for _, marker := range []string{"$HOME", "%n", `"quoted"`} {
		job.BinaryPath = filepath.Join(filepath.Dir(job.BinaryPath), "qurl-"+marker)
		if _, err := RenderSystemdUserJob(job); err == nil || !strings.Contains(err.Error(), "unsupported special character") {
			t.Fatalf("RenderSystemdUserJob(%q) error = %v", marker, err)
		}
	}
	job = linuxTestUserJob(t)
	job.StandardOut = filepath.Join(filepath.Dir(job.StandardOut), "stdout-%n.log")
	if _, err := RenderSystemdUserJob(job); err == nil || !strings.Contains(err.Error(), "unsupported character") {
		t.Fatalf("RenderSystemdUserJob(output path) error = %v", err)
	}
	job.StandardOut = filepath.Join(filepath.Dir(job.StandardOut), "stdout log")
	if _, err := RenderSystemdUserJob(job); err == nil || !strings.Contains(err.Error(), "unsupported character") {
		t.Fatalf("RenderSystemdUserJob(output whitespace) error = %v", err)
	}
}

func TestRenderSystemdUserJobRejectsControlCharacters(t *testing.T) {
	job := linuxTestUserJob(t)
	job.Arguments = []string{"daemon", "line\nbreak"}
	if _, err := RenderSystemdUserJob(job); err == nil || !strings.Contains(err.Error(), "control character") {
		t.Fatalf("RenderSystemdUserJob error = %v", err)
	}
}

func TestRenderSystemdUserJobRejectsOversizedDefinition(t *testing.T) {
	job := linuxTestUserJob(t)
	job.Arguments = []string{strings.Repeat("x", maxLinuxUserJobDefinitionBytes)}
	if _, err := RenderSystemdUserJob(job); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("RenderSystemdUserJob error = %v", err)
	}
}

func TestSystemdUserJobPath(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config")
	got, err := SystemdUserJobPath(config, "ai.layerv.qurl.daemon")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(config, "systemd", "user", "ai.layerv.qurl.daemon.service")
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
	if _, err := SystemdUserJobPath("relative", "ai.layerv.qurl.daemon"); err == nil {
		t.Fatal("relative config directory was accepted")
	}
	if _, err := SystemdUserJobPath("/tmp/config\nunit", "ai.layerv.qurl.daemon"); err == nil {
		t.Fatal("control character in config directory was accepted")
	}
}

func TestLinuxEnsureLeavesExactRunningJobUntouched(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := RenderSystemdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			calls = append(calls, append([]string(nil), args...))
			return linuxSystemdState(unitPath, "loaded", "active", "running", "no"), nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0][0] != "show" {
		t.Fatalf("systemctl calls = %#v, want one non-disruptive show", calls)
	}
}

func TestLinuxEnsureInstallsAbsentJobWithoutShellFallback(t *testing.T) {
	job := linuxTestUserJob(t)
	job.RunAtLoad = false
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	var verbs []string
	showCalls := 0
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				showCalls++
				if showCalls == 1 {
					return linuxSystemdState("", "not-found", "inactive", "dead", "no"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "daemon-reload", "disable", "start", "show"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
	content, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "/bin/sh") {
		t.Fatalf("installed unit uses a shell:\n%s", content)
	}
}

func TestLinuxEnsureReloadsMatchingFileWhenSystemdStateIsStale(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := RenderSystemdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	showCalls := 0
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				showCalls++
				if showCalls == 1 {
					return linuxSystemdState(unitPath, "loaded", "active", "running", "yes"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "stop", "daemon-reload", "enable", "start", "show"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
}

func TestLinuxEnsureRepairsBadSettingDefinition(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Service]\nExecStart=$unsupported\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	showCalls := 0
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				showCalls++
				if showCalls == 1 {
					return linuxSystemdState(unitPath, "bad-setting", "inactive", "dead", "no"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "daemon-reload", "enable", "start", "show"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
}

func TestLinuxEnsureReplacesChangedDefinitionAfterStopping(t *testing.T) {
	job := linuxTestUserJob(t)
	old := job
	old.Arguments = []string{"daemon", "run", "old"}
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	oldContent, err := RenderSystemdUserJob(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(oldContent), 0o600); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	showCalls := 0
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				showCalls++
				if showCalls == 1 {
					return linuxSystemdState(unitPath, "loaded", "active", "running", "no"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "stop", "daemon-reload", "enable", "start", "show"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
	updated, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes := string(updated); strings.Contains(bytes, " old") || !strings.Contains(bytes, "value with spaces") {
		t.Fatalf("definition was not replaced:\n%s", bytes)
	}
}

func TestLinuxEnsurePreservesOldDefinitionWhenStopFails(t *testing.T) {
	job := linuxTestUserJob(t)
	old := job
	old.Arguments = []string{"old"}
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	oldContent, err := RenderSystemdUserJob(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(oldContent), 0o600); err != nil {
		t.Fatal(err)
	}
	stopErr := errors.New("systemd stop failed")
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			if args[0] == "show" {
				return linuxSystemdState(unitPath, "loaded", "active", "running", "no"), nil
			}
			if args[0] == "stop" {
				return "", stopErr
			}
			t.Fatalf("unexpected systemctl call %v", args)
			return "", nil
		},
	}
	if err := manager.Ensure(job); !errors.Is(err, stopErr) {
		t.Fatalf("Ensure error = %v, want stop failure", err)
	}
	retained, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(retained) != oldContent {
		t.Fatal("failed stop replaced the loaded definition")
	}
}

func TestLinuxStatusAndRemoveAreExactAndIdempotent(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := RenderSystemdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				return linuxSystemdState(unitPath, "loaded", "active", "running", "no"), nil
			}
			return "", nil
		},
	}
	status, err := manager.Status(job.Label)
	if err != nil || !status.Installed || !status.Running {
		t.Fatalf("Status = %#v, %v", status, err)
	}
	if err := manager.Remove(job.Label); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit definition remains: %v", err)
	}
	if want := []string{"show", "show", "stop", "disable", "daemon-reload"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
}

func TestLinuxStatusRejectsLoadedUnitFromUnexpectedPath(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			return linuxSystemdState("/etc/systemd/user/"+job.Label+".service", "loaded", "active", "running", "no"), nil
		},
	}
	status, err := manager.Status(job.Label)
	if err == nil || !strings.Contains(err.Error(), "unexpected path") {
		t.Fatalf("Status = %#v, %v; want unexpected loaded path error", status, err)
	}
	if status.Installed || status.Running {
		t.Fatalf("Status reported an untrusted job as installed or running: %#v", status)
	}
}

func TestLinuxRemoveRejectsUntrustedDefinitionBeforeSystemdMutation(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(job.BinaryPath, unitPath); err != nil {
		t.Fatal(err)
	}
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			t.Fatalf("systemctl changed state before definition validation: %v", args)
			return "", nil
		},
	}
	if err := manager.Remove(job.Label); err == nil {
		t.Fatal("Remove accepted a symlinked systemd definition")
	}
	info, err := os.Lstat(unitPath)
	if err != nil {
		t.Fatalf("inspect untrusted definition after rejection: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("untrusted definition mode = %v, want symlink", info.Mode())
	}
}

func TestLinuxRemoveCleansBadSettingDefinition(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Service]\nExecStart=$unsupported\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				return linuxSystemdState(unitPath, "bad-setting", "inactive", "dead", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Remove(job.Label); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "disable", "daemon-reload"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
	if _, err := os.Lstat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bad-setting definition remains: %v", err)
	}
}

func TestLinuxUserJobRejectsUnsafeExecutableAndLogNamespace(t *testing.T) {
	job := linuxTestUserJob(t)
	if err := os.Chmod(job.BinaryPath, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := validateLinuxUserJobExecutable(job.BinaryPath); err == nil || !strings.Contains(err.Error(), "unsafe writable mode") {
		t.Fatalf("world-writable executable error = %v", err)
	}
	if err := os.Chmod(job.BinaryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(job.StandardOut), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(job.BinaryPath, job.StandardOut); err != nil {
		t.Fatal(err)
	}
	if err := ensureLinuxUserJobLogs(job.StandardOut); err == nil {
		t.Fatal("symlinked log path was accepted")
	}
}

func TestLinuxUserJobAcceptsTrustedStableExecutableSymlink(t *testing.T) {
	job := linuxTestUserJob(t)
	link := filepath.Join(filepath.Dir(job.BinaryPath), "qurl")
	if err := os.Symlink(job.BinaryPath, link); err != nil {
		t.Fatal(err)
	}
	if err := validateLinuxUserJobExecutable(link); err != nil {
		t.Fatalf("trusted stable executable symlink was rejected: %v", err)
	}
}

func TestLinuxUserJobManagerIntegration(t *testing.T) {
	if os.Getenv("QURL_LINUX_USER_JOB_INTEGRATION") != "1" {
		t.Skip("set QURL_LINUX_USER_JOB_INTEGRATION=1 with a real systemd user manager")
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(configDir, ".qurl-userjob-integration-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	specialDir := filepath.Join(dir, `unit with spaces`)
	if err := os.Mkdir(specialDir, 0o700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(specialDir, `daemon helper`)
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf ready > \"$1\"\nprintf 'stdout-ready\\n'\nprintf 'stderr-ready\\n' >&2\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(dir, `logs`, `stdout.log`)
	stderr := filepath.Join(dir, `logs`, `stderr.log`)
	job := UserJob{
		Label: "ai.layerv.qurl.integration", BinaryPath: helper,
		Arguments:   []string{filepath.Join(specialDir, `started one %n $HOME "quoted"`)},
		StandardOut: stdout,
		StandardErr: stderr,
		RunAtLoad:   true, KeepAlive: true,
	}
	manager := NewUserJobManager()
	defer func() { _ = manager.Remove(job.Label) }()
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	waitForLinuxUserJobMarker(t, job.Arguments[0])
	status, err := manager.Status(job.Label)
	if err != nil || !status.Installed || !status.Running {
		t.Fatalf("running integration status = %#v, %v", status, err)
	}
	waitForLinuxUserJobLog(t, stdout, "stdout-ready\n")
	waitForLinuxUserJobLog(t, stderr, "stderr-ready\n")
	job.Arguments = []string{filepath.Join(specialDir, `started two %n $HOME "quoted"`)}
	if err := manager.Replace(job); err != nil {
		t.Fatal(err)
	}
	waitForLinuxUserJobMarker(t, job.Arguments[0])
	if err := manager.Remove(job.Label); err != nil {
		t.Fatal(err)
	}
	status, err = manager.Status(job.Label)
	if err != nil || status.Installed || status.Running {
		t.Fatalf("removed integration status = %#v, %v", status, err)
	}
}

func waitForLinuxUserJobLog(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if content, err := os.ReadFile(path); err == nil && strings.Contains(string(content), want) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("systemd user job did not write %q to %s", want, path)
}

func waitForLinuxUserJobMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if content, err := os.ReadFile(path); err == nil && string(content) == "ready" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("systemd user job did not write %s", path)
}
