//go:build windows

package service

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

type windowsJobCall struct {
	name string
	args []string
}

func testWindowsUserJob(t *testing.T) UserJob {
	t.Helper()
	dir := t.TempDir()
	return UserJob{
		Label: "ai.layerv.qurl.daemon", BinaryPath: filepath.Join(dir, "qurl.exe"),
		Arguments:   []string{"--endpoint", "https://api.example.com", "daemon", "run", "--state-dir", filepath.Join(dir, "state with space")},
		StandardOut: filepath.Join(dir, "out.log"), StandardErr: filepath.Join(dir, "err.log"),
		RunAtLoad: true, KeepAlive: true,
	}
}

func TestWindowsUserJobRenderIsCredentialFreeAndEscaped(t *testing.T) {
	manager := &windowsUserJobManager{currentSID: func() (string, error) { return "S-1-5-21-1000", nil }}
	job := testWindowsUserJob(t)
	content, marker, err := manager.render(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{marker, "S-1-5-21-1000", "InteractiveToken", "LeastPrivilege", "RestartOnFailure", "powershell.exe", "-EncodedCommand"} {
		if !strings.Contains(content, want) {
			t.Fatalf("Windows task XML missing %q\n%s", want, content)
		}
	}
	encoded := strings.Split(strings.Split(content, "-EncodedCommand ")[1], "</Arguments>")[0]
	launcher := decodeWindowsPowerShellCommand(t, encoded)
	for _, want := range append([]string{job.BinaryPath, job.StandardOut, job.StandardErr}, job.Arguments...) {
		if !strings.Contains(launcher, windowsPowerShellLiteral(want)) {
			t.Fatalf("PowerShell launcher missing literal %q: %s", want, launcher)
		}
	}
	for _, forbidden := range []string{"QURL_API_KEY", "bearer", "credential"} {
		if strings.Contains(strings.ToLower(content), strings.ToLower(forbidden)) {
			t.Fatalf("Windows task XML contains forbidden %q", forbidden)
		}
	}
}

func TestWindowsUserJobEnsureCreateReuseReplaceAndRemove(t *testing.T) {
	job := testWindowsUserJob(t)
	var calls []windowsJobCall
	existing := ""
	running := false
	manager := &windowsUserJobManager{currentSID: func() (string, error) { return "S-1-5-21-1000", nil }}
	manager.run = func(name string, args ...string) (string, error) {
		calls = append(calls, windowsJobCall{name: name, args: append([]string(nil), args...)})
		joined := strings.Join(args, " ")
		switch {
		case name == "powershell.exe" && strings.Contains(joined, "$task.State"):
			if running {
				return "4\r\n", nil
			}
			return "3\r\n", nil
		case name == "powershell.exe":
			if existing == "" {
				return "0\r\n", nil
			}
			return "1\r\n", nil
		case strings.HasPrefix(joined, "/Query"):
			if existing == "" {
				return "", errors.New("not found")
			}
			return existing, nil
		case strings.HasPrefix(joined, "/Create"):
			for index, arg := range args {
				if arg == "/XML" && index+1 < len(args) {
					raw, err := os.ReadFile(args[index+1])
					if err != nil {
						return "", err
					}
					existing = string(raw)
				}
			}
			return "", nil
		case strings.HasPrefix(joined, "/Run"):
			running = true
			return "", nil
		case strings.HasPrefix(joined, "/End"):
			running = false
			return "", nil
		case strings.HasPrefix(joined, "/Delete"):
			existing = ""
			return "", nil
		default:
			return "", errors.New("unexpected command")
		}
	}

	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	createdCalls := len(calls)
	if existing == "" || !running {
		t.Fatal("Ensure did not install and start the task")
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	if len(calls) != createdCalls+3 { // Presence, XML, and numeric running-state queries.
		t.Fatalf("matching running Ensure made %d new calls, want 3", len(calls)-createdCalls)
	}
	if err := manager.Replace(job); err != nil {
		t.Fatal(err)
	}
	if !running {
		t.Fatal("Replace did not restart the task")
	}
	if err := manager.Remove(job.Label); err != nil {
		t.Fatal(err)
	}
	if existing != "" || running {
		t.Fatal("Remove left the Windows task installed or running")
	}
}

func TestWindowsUserJobStatusDoesNotHideSchedulerErrors(t *testing.T) {
	want := errors.New("scheduled task query failed")
	manager := &windowsUserJobManager{run: func(string, ...string) (string, error) { return "", want }}
	if _, err := manager.Status("ai.layerv.qurl.daemon"); !errors.Is(err, want) {
		t.Fatalf("Status error = %v, want scheduler failure", err)
	}
}

func TestWindowsUserJobIntegration(t *testing.T) {
	if os.Getenv("QURL_WINDOWS_USER_JOB_INTEGRATION") != "1" {
		t.Skip("set QURL_WINDOWS_USER_JOB_INTEGRATION=1 to exercise Task Scheduler")
	}
	binaryPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	readyPath := filepath.Join(dir, "ready")
	label := "ai.layerv.qurl.test." + strconv.Itoa(os.Getpid())
	manager := NewUserJobManager()
	t.Cleanup(func() {
		if err := manager.Remove(label); err != nil {
			t.Errorf("remove integration task: %v", err)
		}
	})
	job := UserJob{
		Label: label, BinaryPath: binaryPath,
		Arguments:   []string{"-test.run=^TestWindowsUserJobHelperProcess$", "--", readyPath},
		StandardOut: filepath.Join(dir, "stdout.log"), StandardErr: filepath.Join(dir, "stderr.log"),
		KeepAlive: false,
	}
	if err := manager.Ensure(job); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(readyPath); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("Windows user job did not start")
		}
		time.Sleep(100 * time.Millisecond)
	}
	status, err := manager.Status(label)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Installed || !status.Running {
		t.Fatalf("running status = %#v, want installed and running", status)
	}
	if err := manager.Remove(label); err != nil {
		t.Fatal(err)
	}
	status, err = manager.Status(label)
	if err != nil {
		t.Fatal(err)
	}
	if status != (ServiceStatus{}) {
		t.Fatalf("removed status = %#v, want absent", status)
	}
}

func TestWindowsUserJobHelperProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}
	if err := os.WriteFile(os.Args[separator+1], []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Second)
}

func decodeWindowsPowerShellCommand(t *testing.T, encoded string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw)%2 != 0 {
		t.Fatalf("encoded command byte count = %d, want even", len(raw))
	}
	units := make([]uint16, len(raw)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(raw[index*2:])
	}
	return string(utf16.Decode(units))
}
