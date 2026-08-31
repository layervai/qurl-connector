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

func linuxSystemdState(unitPath, load, active, sub, unitFileState, reload string) string {
	return fmt.Sprintf(
		"LoadState=%s\nActiveState=%s\nSubState=%s\nUnitFileState=%s\nFragmentPath=%s\nNeedDaemonReload=%s\n",
		load, active, sub, unitFileState, unitPath, reload,
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
		`StartLimitIntervalSec=0`, `Type=exec`, `Restart=on-failure`, `RestartSec=10s`,
		`TimeoutStopSec=15s`, `UMask=0077`,
		`StandardOutput=append:`, `StandardError=append:`,
		`NoNewPrivileges=true`, `WantedBy=default.target`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("systemd unit missing %q:\n%s", want, got)
		}
	}
	for _, forbidden := range []string{
		"Type=simple", "Environment=", "QURL_API_KEY", "Bearer", "ExecStart=/bin/sh", "PrivateTmp=", "network-online.target",
	} {
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
	job.StandardOut = filepath.Join(filepath.Dir(job.StandardOut), "stdout log")
	if got, err := RenderSystemdUserJob(job); err != nil || !strings.Contains(got, "StandardOutput=append:"+job.StandardOut+"\n") {
		t.Fatalf("RenderSystemdUserJob(output space) = %q, %v", got, err)
	}
	base := filepath.Join(filepath.Dir(job.StandardOut), "stdout")
	for _, suffix := range []string{"-%n.log", "-$HOME.log", `-"quote.log`, `-back\slash.log`, "-tab\t.log", "-return\r.log", "-line\n[Service].log", "-trailing.log "} {
		job.StandardOut = base + suffix
		if _, err := RenderSystemdUserJob(job); err == nil {
			t.Fatalf("RenderSystemdUserJob(output path %q) succeeded", job.StandardOut)
		}
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
			return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0][0] != "show" {
		t.Fatalf("systemctl calls = %#v, want one non-disruptive show", calls)
	}
}

func TestLinuxEnsureAndStatusRejectMaskedDefinitionClearly(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", unitPath); err != nil {
		t.Fatal(err)
	}
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			t.Fatalf("masked definition reached systemctl: %v", args)
			return "", nil
		},
	}
	if err := manager.Ensure(job); err == nil || !strings.Contains(err.Error(), "is masked; remove the systemd mask") {
		t.Fatalf("Ensure masked error = %v", err)
	}
	status, err := manager.Status(job.Label)
	if err == nil || !strings.Contains(err.Error(), "is masked; remove the systemd mask") || !status.Installed {
		t.Fatalf("Status masked = %#v, %v", status, err)
	}
}

func TestLinuxEnsureRepairsOwnerDefinitionWithDriftedMode(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := RenderSystemdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			calls = append(calls, append([]string(nil), args...))
			return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("repaired unit mode = %04o, want 0600", info.Mode().Perm())
	}
	if len(calls) != 1 || calls[0][0] != "show" {
		t.Fatalf("systemctl calls = %#v, want one non-disruptive show", calls)
	}
}

func TestLinuxStatusRepairsOwnerDefinitionWithDriftedMode(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	content, err := RenderSystemdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			if args[0] != "show" {
				t.Fatalf("unexpected systemctl call %v", args)
			}
			return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
		},
	}
	status, err := manager.Status(job.Label)
	if err != nil || !status.Installed || !status.Running {
		t.Fatalf("Status = %#v, %v", status, err)
	}
	info, err := os.Stat(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("repaired unit mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestLinuxEnsureRepairsDisabledExactRunningJob(t *testing.T) {
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
				unitFileState := "disabled"
				if showCalls > 1 {
					unitFileState = "enabled"
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", unitFileState, "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "enable", "show"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
}

func TestLinuxEnsureDisablesUnexpectedRunAtLoadWithoutRestart(t *testing.T) {
	job := linuxTestUserJob(t)
	job.RunAtLoad = false
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
				unitFileState := "enabled"
				if showCalls > 1 {
					unitFileState = "disabled"
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", unitFileState, "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "disable", "show"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
}

func TestLinuxEnsureStartsMatchingEnabledStoppedJob(t *testing.T) {
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
					return linuxSystemdState(unitPath, "loaded", "inactive", "dead", "enabled", "no"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "reset-failed", "start", "show"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
}

func TestLinuxEnsureStopsWhenFailedStartLimitCannotReset(t *testing.T) {
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
	wantErr := errors.New("reset failed")
	var verbs []string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			switch args[0] {
			case "show":
				return linuxSystemdState(unitPath, "loaded", "inactive", "dead", "enabled", "no"), nil
			case "reset-failed":
				return "", wantErr
			default:
				t.Fatalf("unexpected systemctl call %v", args)
				return "", nil
			}
		},
	}
	if err := manager.Ensure(job); !errors.Is(err, wantErr) {
		t.Fatalf("Ensure error = %v, want reset-failed error", err)
	}
	if want := []string{"show", "reset-failed"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
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
					return linuxSystemdState("", "not-found", "inactive", "dead", "", "no"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "disabled", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "daemon-reload", "disable", "reset-failed", "start", "show"}; !reflect.DeepEqual(verbs, want) {
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
					return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "yes"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "stop", "daemon-reload", "enable", "reset-failed", "start", "show"}; !reflect.DeepEqual(verbs, want) {
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
					return linuxSystemdState(unitPath, "bad-setting", "inactive", "dead", "disabled", "no"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "daemon-reload", "enable", "reset-failed", "start", "show"}; !reflect.DeepEqual(verbs, want) {
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
					return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
				}
				return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "stop", "daemon-reload", "enable", "reset-failed", "start", "show"}; !reflect.DeepEqual(verbs, want) {
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
				return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
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
				return linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no"), nil
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
			return linuxSystemdState("/etc/systemd/user/"+job.Label+".service", "loaded", "active", "running", "enabled", "no"), nil
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

func TestLinuxStateRejectsMalformedManagerProperties(t *testing.T) {
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", "ai.layerv.qurl.daemon.service")
	valid := linuxSystemdState(unitPath, "loaded", "active", "running", "enabled", "no")
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{name: "duplicate", output: valid + "LoadState=loaded\n", want: "duplicate"},
		{name: "missing", output: strings.Replace(valid, "UnitFileState=enabled\n", "", 1), want: "omitted UnitFileState"},
		{name: "invalid reload", output: strings.Replace(valid, "NeedDaemonReload=no", "NeedDaemonReload=maybe", 1), want: "invalid daemon-reload"},
		{name: "masked load", output: strings.Replace(valid, "LoadState=loaded", "LoadState=masked", 1), want: "is masked; remove the systemd mask"},
		{name: "running not loaded", output: strings.Replace(valid, "LoadState=loaded", "LoadState=not-found", 1), want: "running without a loaded definition"},
		{name: "loaded no fragment", output: strings.Replace(valid, "FragmentPath="+unitPath, "FragmentPath=", 1), want: "no fragment path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager := &linuxUserJobManager{run: func(...string) (string, error) { return test.output, nil }}
			if _, err := manager.state("ai.layerv.qurl.daemon"); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("state error = %v, want %q", err, test.want)
			}
		})
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
				return linuxSystemdState(unitPath, "bad-setting", "inactive", "dead", "disabled", "no"), nil
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

func TestLinuxRemoveCleansOwnerDefinitionWithDriftedMode(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unitPath, []byte("[Service]\nType=exec\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				return linuxSystemdState(unitPath, "loaded", "inactive", "dead", "disabled", "no"), nil
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
		t.Fatalf("mode-drifted definition remains: %v", err)
	}
}

func TestLinuxRemoveStopsLoadedNonRunningUnitBeforeCleanup(t *testing.T) {
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
				return linuxSystemdState(unitPath, "loaded", "activating", "auto-restart", "enabled", "no"), nil
			}
			return "", nil
		},
	}
	if err := manager.Remove(job.Label); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "stop", "disable", "daemon-reload"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
	if _, err := os.Lstat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("activating unit definition remains: %v", err)
	}
}

func TestSystemctlUserOutputKeepsCommandChannelsSeparate(t *testing.T) {
	dir := t.TempDir()
	systemctl := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nif [ \"$2\" = fail ]; then\n  printf 'partial output\\n'\n  printf 'manager failure\\n' >&2\n  exit 1\nfi\nprintf 'manager warning\\n' >&2\nprintf 'LoadState=loaded\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	hostileDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostileDir, "systemctl"), []byte("#!/bin/sh\nprintf 'LoadState=hostile\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", hostileDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := systemctlUserOutputAt(systemctl, "show", "test.service")
	if err != nil {
		t.Fatal(err)
	}
	if output != "LoadState=loaded\n" {
		t.Fatalf("systemctl stdout = %q, want state only", output)
	}
	_, err = systemctlUserOutputAt(systemctl, "fail")
	if err == nil || !strings.Contains(err.Error(), "partial output") || !strings.Contains(err.Error(), "manager failure") {
		t.Fatalf("systemctl failure = %v, want stdout and stderr diagnostics", err)
	}
}

func TestResolveTrustedSystemctlRejectsPathAndUnsafeCandidates(t *testing.T) {
	dir := t.TempDir()
	trusted := filepath.Join(dir, "trusted-systemctl")
	if err := os.WriteFile(trusted, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := resolveTrustedSystemctl([]string{"relative-systemctl", filepath.Join(dir, "missing"), trusted})
	if err != nil || got != trusted {
		t.Fatalf("resolveTrustedSystemctl = %q, %v; want %q", got, err, trusted)
	}
	unsafe := filepath.Join(dir, "unsafe-systemctl")
	if err := os.WriteFile(unsafe, []byte("#!/bin/sh\nexit 0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTrustedSystemctl([]string{unsafe}); err == nil || !strings.Contains(err.Error(), "unsafe writable mode") {
		t.Fatalf("unsafe systemctl error = %v", err)
	}
}

func TestLinuxRemoveUnmasksManagedDefinitionBeforeCleanup(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", unitPath); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				return linuxSystemdState(unitPath, "masked", "inactive", "dead", "masked", "no"), nil
			}
			if args[0] == "unmask" {
				return "", os.Remove(unitPath)
			}
			return "", nil
		},
	}
	if err := manager.Remove(job.Label); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "disable", "unmask", "daemon-reload"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
	if _, err := os.Lstat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("masked definition remains: %v", err)
	}
}

func TestLinuxRemoveUnmasksDefinitionBeforeManagerCacheRefresh(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", unitPath); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				return linuxSystemdState("", "not-found", "inactive", "dead", "", "no"), nil
			}
			if args[0] == "unmask" {
				return "", os.Remove(unitPath)
			}
			return "", nil
		},
	}
	if err := manager.Remove(job.Label); err != nil {
		t.Fatal(err)
	}
	if want := []string{"show", "disable", "unmask", "daemon-reload"}; !reflect.DeepEqual(verbs, want) {
		t.Fatalf("systemctl verbs = %v, want %v", verbs, want)
	}
	if _, err := os.Lstat(unitPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("masked definition remains: %v", err)
	}
}

func TestLinuxRemoveDisablesDanglingEnablement(t *testing.T) {
	job := linuxTestUserJob(t)
	unitPath := filepath.Join(t.TempDir(), "systemd", "user", job.Label+".service")
	var verbs []string
	manager := &linuxUserJobManager{
		unitPath: func(string) (string, error) { return unitPath, nil },
		run: func(args ...string) (string, error) {
			verbs = append(verbs, args[0])
			if args[0] == "show" {
				return linuxSystemdState("", "not-found", "inactive", "dead", "enabled", "no"), nil
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

func TestLinuxUserJobRepairsOwnerLogWithDriftedMode(t *testing.T) {
	job := linuxTestUserJob(t)
	if err := os.MkdirAll(filepath.Dir(job.StandardOut), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(job.StandardOut, []byte("existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureLinuxUserJobLogs(job.StandardOut); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(job.StandardOut)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("repaired log mode = %04o, want 0600", info.Mode().Perm())
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
	manager := NewUserJobManager()
	restartHelper := filepath.Join(specialDir, `restart helper`)
	if err := os.WriteFile(restartHelper, []byte("#!/bin/sh\ncount=0\nif [ -f \"$1\" ]; then IFS= read -r count < \"$1\"; fi\ncount=$((count + 1))\nprintf '%s\\n' \"$count\" > \"$1\"\nif [ \"$count\" -eq 1 ]; then\n  printf ready > \"$3\"\n  while [ ! -f \"$2\" ]; do sleep 0.05; done\n  exit 1\nfi\nif [ \"$count\" -lt 6 ]; then exit 1; fi\nprintf ready > \"$4\"\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	restartCount := filepath.Join(specialDir, "restart-count")
	restartTrigger := filepath.Join(specialDir, "restart-trigger")
	restartInitial := filepath.Join(specialDir, "restart-initial-ready")
	restartMarker := filepath.Join(specialDir, "restart-ready")
	restartJob := UserJob{
		Label: "ai.layerv.qurl.integration", BinaryPath: restartHelper,
		Arguments:   []string{restartCount, restartTrigger, restartInitial, restartMarker},
		StandardOut: filepath.Join(specialDir, "restart stdout.log"),
		StandardErr: filepath.Join(specialDir, "restart stderr.log"),
		RunAtLoad:   true, KeepAlive: true,
	}
	defer func() { _ = manager.Remove(restartJob.Label) }()
	if err := manager.Ensure(restartJob); err != nil {
		t.Fatal(err)
	}
	waitForLinuxUserJobMarker(t, restartInitial)
	if err := os.WriteFile(restartTrigger, []byte("restart\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitForLinuxUserJobMarkerWithin(t, restartMarker, 70*time.Second)
	count, err := os.ReadFile(restartCount)
	if err != nil || strings.TrimSpace(string(count)) != "6" {
		t.Fatalf("restart attempts = %q, %v; want 6", count, err)
	}
	status, err := manager.Status(restartJob.Label)
	if err != nil || !status.Installed || !status.Running {
		t.Fatalf("restart recovery status = %#v, %v", status, err)
	}
	if err := manager.Remove(restartJob.Label); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(specialDir, `daemon helper`)
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nprintf ready > \"$1\"\nprintf 'stdout-ready\\n'\nprintf 'stderr-ready\\n' >&2\ntrap 'exit 0' TERM INT\nwhile :; do sleep 1; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	stdout := filepath.Join(specialDir, `logs`, `stdout log`)
	stderr := filepath.Join(specialDir, `logs`, `stderr log`)
	job := UserJob{
		Label: "ai.layerv.qurl.integration", BinaryPath: helper,
		Arguments:   []string{filepath.Join(specialDir, `started one %n $HOME "quoted"`)},
		StandardOut: stdout,
		StandardErr: stderr,
		RunAtLoad:   true, KeepAlive: true,
	}
	defer func() { _ = manager.Remove(job.Label) }()
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	requireSystemdUserJobEnabled(t, job.Label)
	if _, err := systemctlUserOutput("disable", systemdUserUnitName(job.Label)); err != nil {
		t.Fatalf("disable integration job before repair: %v", err)
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatalf("repair disabled integration job: %v", err)
	}
	requireSystemdUserJobEnabled(t, job.Label)
	waitForLinuxUserJobMarker(t, job.Arguments[0])
	status, err = manager.Status(job.Label)
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
	unitPath, err := SystemdUserJobPath(configDir, job.Label)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := systemctlUserOutput("stop", systemdUserUnitName(job.Label)); err != nil {
		t.Fatalf("stop integration job before persistent mask: %v", err)
	}
	// systemctl mask does not overwrite a regular unit in its highest-priority
	// user directory. Construct the exact durable mask it would otherwise use,
	// then make the real manager load and report that state.
	if err := os.Remove(unitPath); err != nil {
		t.Fatalf("remove integration definition before persistent mask: %v", err)
	}
	if err := os.Symlink("/dev/null", unitPath); err != nil {
		t.Fatalf("create persistent integration mask: %v", err)
	}
	if err := syncTrustedSystemdUnitDirectory(filepath.Dir(unitPath)); err != nil {
		t.Fatalf("make persistent integration mask durable: %v", err)
	}
	if _, err := systemctlUserOutput("daemon-reload"); err != nil {
		t.Fatalf("load persistent integration mask: %v", err)
	}
	if target, err := os.Readlink(unitPath); err != nil || target != "/dev/null" {
		t.Fatalf("persistent integration mask = %q, %v; want /dev/null symlink", target, err)
	}
	loadState, err := systemctlUserOutput("show", systemdUserUnitName(job.Label), "--property=LoadState")
	if err != nil || strings.TrimSpace(loadState) != "LoadState=masked" {
		t.Fatalf("persistent integration manager state = %q, %v; want LoadState=masked", loadState, err)
	}
	if err := manager.Remove(job.Label); err != nil {
		t.Fatal(err)
	}
	status, err = manager.Status(job.Label)
	if err != nil || status.Installed || status.Running {
		t.Fatalf("removed integration status = %#v, %v", status, err)
	}
}

func requireSystemdUserJobEnabled(t *testing.T, label string) {
	t.Helper()
	output, err := systemctlUserOutput("is-enabled", systemdUserUnitName(label))
	if err != nil {
		t.Fatalf("inspect systemd user job enablement: %v", err)
	}
	if state := strings.TrimSpace(output); state != "enabled" {
		t.Fatalf("systemd user job enablement = %q, want enabled", state)
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
	waitForLinuxUserJobMarkerWithin(t, path, 10*time.Second)
}

func waitForLinuxUserJobMarkerWithin(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if content, err := os.ReadFile(path); err == nil && string(content) == "ready" {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("systemd user job did not write %s", path)
}
