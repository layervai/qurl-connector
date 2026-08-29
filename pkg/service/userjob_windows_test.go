//go:build windows

package service

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

type windowsJobCall struct {
	name string
	args []string
}

func testWindowsUserJob(t *testing.T) UserJob {
	t.Helper()
	dir := t.TempDir()
	logDir := filepath.Join(dir, "logs")
	return UserJob{
		Label: "ai.layerv.qurl.daemon", BinaryPath: filepath.Join(dir, "qurl.exe"),
		Arguments:   []string{"--endpoint", "https://api.example.com", "daemon", "run", "--state-dir", filepath.Join(dir, "state with space")},
		StandardOut: filepath.Join(logDir, "out.log"), StandardErr: filepath.Join(logDir, "err.log"),
		RunAtLoad: true, KeepAlive: true,
	}
}

func TestWindowsUserJobRenderIsCredentialFreeAndEscaped(t *testing.T) {
	manager := &windowsUserJobManager{}
	job := testWindowsUserJob(t)
	job.Arguments = append(job.Arguments, `value with spaces`, `quote"and\slash`)
	content, marker, err := manager.render(job, "S-1-5-21-1000")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{marker, "S-1-5-21-1000", "InteractiveToken", "LeastPrivilege", "RestartOnFailure", job.BinaryPath, xmlText(windows.EscapeArg("value with spaces"))} {
		if !strings.Contains(content, want) {
			t.Fatalf("Windows task XML missing %q\n%s", want, content)
		}
	}
	for _, forbidden := range []string{"powershell.exe", "-EncodedCommand", "QURL_API_KEY", "Authorization: Bearer", "example-secret-value"} {
		if strings.Contains(strings.ToLower(content), strings.ToLower(forbidden)) {
			t.Fatalf("Windows task launcher contains forbidden %q", forbidden)
		}
	}
}

func TestWindowsUserJobEnsureCreateReuseReplaceAndRemove(t *testing.T) {
	job := testWindowsUserJob(t)
	var calls []windowsJobCall
	existing := ""
	running := false
	enabled := true
	failCreate := false
	manager := &windowsUserJobManager{
		currentSID: currentWindowsUserSID,
		powerShell: func() (string, error) { return "powershell.exe", nil },
	}
	manager.run = func(name string, args ...string) (string, error) {
		calls = append(calls, windowsJobCall{name: name, args: append([]string(nil), args...)})
		joined := strings.Join(args, " ")
		switch {
		case strings.HasSuffix(strings.ToLower(name), "powershell.exe") && strings.Contains(joined, "$task.State"):
			if existing == "" {
				return "-1\r\n", nil
			}
			if running {
				return "4\r\n", nil
			}
			if !enabled {
				return "1\r\n", nil
			}
			return "3\r\n", nil
		case strings.HasPrefix(joined, "/Query"):
			if existing == "" {
				return "", errors.New("not found")
			}
			return string(windowsTaskXMLBytes(existing)), nil
		case strings.HasPrefix(joined, "/Create"):
			if failCreate {
				return "", errors.New("injected create failure")
			}
			for index, arg := range args {
				if arg == "/XML" && index+1 < len(args) {
					raw, err := os.ReadFile(args[index+1])
					if err != nil {
						return "", err
					}
					existing = decodeWindowsTaskXML(t, raw)
				}
			}
			enabled = true
			return "", nil
		case strings.HasPrefix(joined, "/Run"):
			running = true
			return "", nil
		case strings.HasPrefix(joined, "/Change") && strings.Contains(joined, "/Disable"):
			enabled = false
			return "", nil
		case strings.HasPrefix(joined, "/Change") && strings.Contains(joined, "/Enable"):
			enabled = true
			return "", nil
		case strings.HasPrefix(joined, "/End"):
			running = false
			return "", nil
		case strings.HasPrefix(joined, "/Delete"):
			existing = ""
			enabled = true
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
	if len(calls) != createdCalls+2 { // One state query and one XML definition query.
		t.Fatalf("matching running Ensure made %d new calls, want 2", len(calls)-createdCalls)
	}
	onDemand := job
	onDemand.RunAtLoad = false
	if err := manager.Ensure(onDemand); err != nil {
		t.Fatalf("install on-demand-only job: %v", err)
	}
	onDemandCalls := len(calls)
	if err := manager.Ensure(onDemand); err != nil {
		t.Fatalf("reuse on-demand-only job: %v", err)
	}
	if len(calls) != onDemandCalls+2 { // One state query and one XML definition query.
		t.Fatalf("matching on-demand Ensure made %d new calls, want 2", len(calls)-onDemandCalls)
	}
	existing = strings.Replace(existing, "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>",
		"<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>", 1)
	if err := manager.Ensure(onDemand); err != nil {
		t.Fatalf("repair drifted battery policy: %v", err)
	}
	if strings.Contains(existing, "<StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>") {
		t.Fatal("Ensure retained a marker-matching task with a changed battery policy")
	}
	existing = strings.Replace(existing, job.BinaryPath, filepath.Join(filepath.Dir(job.BinaryPath), "other.exe"), 1)
	if err := manager.Ensure(job); err != nil {
		t.Fatalf("Ensure did not replace a marker-matching task with a changed command: %v", err)
	}
	if !strings.Contains(existing, job.BinaryPath) || strings.Contains(existing, "other.exe") {
		t.Fatal("Ensure retained a marker-matching task with a changed command")
	}
	changed := job
	changed.Arguments = append(append([]string(nil), job.Arguments...), "--changed")
	failCreate = true
	if err := manager.Ensure(changed); err == nil || !strings.Contains(err.Error(), "injected create failure") {
		t.Fatalf("replacement create failure = %v, want injected failure", err)
	}
	failCreate = false
	if !enabled || !running {
		t.Fatal("failed replacement left the prior task disabled or stopped")
	}
	enabled, running = false, false
	if err := manager.Ensure(job); err != nil {
		t.Fatalf("Ensure did not repair a disabled matching task: %v", err)
	}
	if !enabled || !running {
		t.Fatal("Ensure did not re-register and start a disabled matching task")
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
	manager := &windowsUserJobManager{
		run:        func(string, ...string) (string, error) { return "", want },
		currentSID: func() (string, error) { return "S-1-5-21-1000", nil },
		powerShell: func() (string, error) { return "powershell.exe", nil },
	}
	if _, err := manager.Status("ai.layerv.qurl.daemon"); !errors.Is(err, want) {
		t.Fatalf("Status error = %v, want scheduler failure", err)
	}
}

func TestWindowsUserJobStatusDoesNotTreatEmptySchedulerOutputAsAbsent(t *testing.T) {
	manager := &windowsUserJobManager{
		run: func(_ string, args ...string) (string, error) {
			command := strings.Join(args, " ")
			for _, want := range []string{"Get-Command Get-ScheduledTask", "-ErrorAction Stop", "CmdletizationQuery_NotFound,Get-ScheduledTask", "ObjectNotFound", "throw"} {
				if !strings.Contains(command, want) {
					t.Fatalf("scheduler query missing %q: %s", want, command)
				}
			}
			if strings.Contains(command, "SilentlyContinue") {
				t.Fatalf("scheduler query can hide provider failures: %s", command)
			}
			return "", nil
		},
		currentSID: func() (string, error) { return "S-1-5-21-1000", nil },
		powerShell: func() (string, error) { return "powershell.exe", nil },
	}
	if _, err := manager.Status("ai.layerv.qurl.daemon"); err == nil || !strings.Contains(err.Error(), "parse Windows user job state") {
		t.Fatalf("Status error = %v, want empty scheduler output to fail visibly", err)
	}
}

func TestWindowsScopedTaskNameIsPerUserAndBounded(t *testing.T) {
	label := strings.Repeat("a", 128)
	first := windowsScopedTaskName(label, "S-1-5-21-1000")
	second := windowsScopedTaskName(label, "S-1-5-21-2000")
	if first == second {
		t.Fatal("Windows task names collide for different user SIDs")
	}
	if len(first) > 128 || !userJobLabelPattern.MatchString(first) {
		t.Fatalf("scoped Windows task name %q is invalid", first)
	}
	third := windowsScopedTaskName(strings.Repeat("a", 127)+"b", "S-1-5-21-1000")
	if first == third {
		t.Fatal("overlong Windows task labels with the same retained prefix collide")
	}
}

func TestWindowsUserJobMarkerChangesWithRenderedTemplate(t *testing.T) {
	job := testWindowsUserJob(t)
	_, first, err := renderWindowsUserJobDefinition(job, "S-1-5-21-1000", windowsUserJobTemplate)
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := renderWindowsUserJobDefinition(job, "S-1-5-21-1000", windowsUserJobTemplate+"\n<!-- definition revision -->")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("Windows user job marker did not change with the rendered task template")
	}
}

func TestWindowsUserJobDefinitionRejectsAddedBehavior(t *testing.T) {
	job := testWindowsUserJob(t)
	expected, _, err := renderWindowsUserJobDefinition(job, "S-1-5-21-1000", windowsUserJobTemplate)
	if err != nil {
		t.Fatal(err)
	}
	for name, registered := range map[string]string{
		"action":    strings.Replace(expected, `<Actions Context="Author">`, `<Actions Context="Author"><Exec><Command>C:\\extra.exe</Command></Exec>`, 1),
		"principal": strings.Replace(expected, `<Principals>`, `<Principals><Principal id="Extra"><UserId>S-1-5-21-1000</UserId></Principal>`, 1),
		"trigger":   strings.Replace(expected, `<Triggers>`, `<Triggers><TimeTrigger><Enabled>true</Enabled></TimeTrigger>`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			matches, err := matchingWindowsUserJobDefinition(registered, expected)
			if err != nil {
				t.Fatal(err)
			}
			if matches {
				t.Fatal("task definition with added behavior matched the expected definition")
			}
		})
	}
}

func TestDecodeWindowsCommandText(t *testing.T) {
	want := "<Description>layerv-qurl-user-job-sha256:abc</Description>"
	if got := decodeWindowsCommandText(string(windowsTaskXMLBytes(want))); got != want {
		t.Fatalf("decoded UTF-16 task XML = %q, want %q", got, want)
	}
	if got := decodeWindowsCommandText(want); got != want {
		t.Fatalf("decoded UTF-8 task XML = %q, want %q", got, want)
	}
}

func TestWindowsUserJobCommandOutputKeepsStdoutAndStderrSeparate(t *testing.T) {
	output, err := windowsJobCommandOutput("cmd.exe", "/d", "/s", "/c",
		`(echo scheduler-stdout)&(echo scheduler-stderr 1>&2)&exit /b 7`)
	if err == nil {
		t.Fatal("failing Windows command returned no error")
	}
	if output != "" {
		t.Fatalf("failing Windows command output = %q, want empty", output)
	}
	if !strings.Contains(err.Error(), "scheduler-stderr") || strings.Contains(err.Error(), "scheduler-stdout") {
		t.Fatalf("failing Windows command error mixed stdout and stderr: %v", err)
	}
}

func TestWindowsUserJobCommandOutputHasBoundedWait(t *testing.T) {
	_, err := windowsJobCommandOutputWithin(100*time.Millisecond, os.Args[0],
		"-test.run=^TestWindowsUserJobCommandTimeoutHelper$", "--", "windows-command-timeout-helper")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("bounded Windows command error = %v, want deadline exceeded", err)
	}
}

func TestWindowsUserJobCommandTimeoutHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-1] != "windows-command-timeout-helper" {
		return
	}
	time.Sleep(time.Minute)
}

func TestWindowsUserJobDirectoryRejectsReparsePoint(t *testing.T) {
	sid, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skip("Windows runner cannot create symlinks")
		}
		t.Fatal(err)
	}
	if err := ensureWindowsPrivateDirectory(link, sid); err == nil || !strings.Contains(err.Error(), "non-reparse") {
		t.Fatalf("reparse directory error = %v, want non-reparse rejection", err)
	}
}

func TestWindowsUserJobDirectoryRejectsMutableAncestor(t *testing.T) {
	sid, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	ancestor := filepath.Join(t.TempDir(), "mutable")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	path16, err := windows.UTF16PtrFromString(ancestor)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path16, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;WD)")
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatal(err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(ancestor, "logs")
	if err := ensureWindowsPrivateDirectory(logDir, sid); err == nil ||
		!strings.Contains(err.Error(), "unsafe access") {
		t.Fatalf("mutable ancestor error = %v, want unsafe-access rejection", err)
	}
	if _, err := os.Lstat(logDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected new log directory remained on disk: %v", err)
	}
}

func TestWindowsUserJobDoesNotRewriteExistingBroadLogDirectory(t *testing.T) {
	sid, err := currentWindowsUserSID()
	if err != nil {
		t.Fatal(err)
	}
	logDir := filepath.Join(t.TempDir(), "existing-logs")
	if err := os.Mkdir(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		t.Fatalf("read broad-directory owner: %v", err)
	}
	path16, err := windows.UTF16PtrFromString(logDir)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(path16, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatal(err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := ensureWindowsPrivateDirectory(logDir, sid); err == nil || !strings.Contains(err.Error(), "unsafe access") {
			t.Fatalf("broad existing directory attempt %d = %v, want fail-closed without ACL rewrite", attempt, err)
		}
	}
	inheritOnly, err := windows.SecurityDescriptorFromString(
		"O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")(A;OICIIO;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	inheritOnlyDACL, _, err := inheritOnly.DACL()
	if err != nil {
		t.Fatal(err)
	}
	path16, err = windows.UTF16PtrFromString(logDir)
	if err != nil {
		t.Fatal(err)
	}
	handle, err = windows.CreateFile(path16, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, inheritOnlyDACL, nil); err != nil {
		_ = windows.CloseHandle(handle)
		t.Fatal(err)
	}
	if err := windows.CloseHandle(handle); err != nil {
		t.Fatal(err)
	}
	if err := ensureWindowsPrivateDirectory(logDir, sid); err == nil || !strings.Contains(err.Error(), "unsafe access") {
		t.Fatalf("inherit-only broad existing directory = %v, want fail-closed", err)
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
	for _, tc := range []struct {
		name      string
		runAtLoad bool
		keepAlive bool
	}{
		{name: "durable", runAtLoad: true, keepAlive: true},
		{name: "on-demand", runAtLoad: false, keepAlive: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "path with spaces")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			readyPath := filepath.Join(dir, "ready")
			logDir := filepath.Join(dir, "logs")
			label := "ai.layerv.qurl.test." + tc.name + "." + strconv.Itoa(os.Getpid())
			manager := NewUserJobManager()
			t.Cleanup(func() {
				if err := manager.Remove(label); err != nil {
					t.Errorf("remove integration task: %v", err)
				}
			})
			job := UserJob{
				Label: label, BinaryPath: binaryPath,
				Arguments:   []string{"-test.run=^TestWindowsUserJobHelperProcess$", "--", readyPath},
				StandardOut: filepath.Join(logDir, "stdout.log"), StandardErr: filepath.Join(logDir, "stderr.log"),
				RunAtLoad: tc.runAtLoad, KeepAlive: tc.keepAlive,
			}
			if err := manager.Ensure(job); err != nil {
				t.Fatal(err)
			}
			sid, err := currentWindowsUserSID()
			if err != nil {
				t.Fatal(err)
			}
			scheduler, err := windowsTaskSchedulerExecutable()
			if err != nil {
				t.Fatal(err)
			}
			registered, err := windowsJobCommandOutput(scheduler, "/Query", "/TN", windowsScopedTaskName(label, sid), "/XML")
			if err != nil {
				t.Fatal(err)
			}
			registered = decodeWindowsCommandText(registered)
			for element, present := range map[string]bool{
				"<LogonTrigger>": tc.runAtLoad, "<RestartOnFailure>": tc.keepAlive, "<Count>999</Count>": tc.keepAlive,
			} {
				if got := strings.Contains(registered, element); got != present {
					t.Fatalf("registered production task XML contains %q = %v, want %v", element, got, present)
				}
			}
			expected, _, err := manager.(*windowsUserJobManager).render(job, sid)
			if err != nil {
				t.Fatal(err)
			}
			matches, err := matchingWindowsUserJobDefinition(registered, expected)
			if err != nil {
				t.Fatal(err)
			}
			if !matches {
				registeredDefinition, _ := parseWindowsUserJobDefinition(registered)
				expectedDefinition, _ := parseWindowsUserJobDefinition(expected)
				t.Fatalf("registered Task Scheduler definition differs from the expected job\nregistered: %#v\nexpected:   %#v", registeredDefinition, expectedDefinition)
			}
			deadline := time.Now().Add(30 * time.Second)
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
			if err := manager.Ensure(job); err != nil {
				t.Fatalf("second Ensure: %v", err)
			}
			// A changed-definition false positive stops and restarts the helper. Give
			// Task Scheduler enough time to expose that restart, then require one start.
			time.Sleep(2 * time.Second)
			starts, err := os.ReadFile(readyPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(strings.Fields(string(starts))); got != 1 {
				t.Fatalf("matching second Ensure started helper %d times, want 1", got)
			}
			helperPID, err := strconv.Atoi(strings.Fields(string(starts))[0])
			if err != nil {
				t.Fatalf("parse helper PID: %v", err)
			}
			if err := manager.Remove(label); err != nil {
				t.Fatal(err)
			}
			waitForWindowsProcessExit(t, uint32(helperPID))
			status, err = manager.Status(label)
			if err != nil {
				t.Fatal(err)
			}
			if status != (ServiceStatus{}) {
				t.Fatalf("removed status = %#v, want absent", status)
			}
		})
	}
}

func waitForWindowsProcessExit(t *testing.T, pid uint32) {
	t.Helper()
	process, err := windows.OpenProcess(windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return // The process exited before OpenProcess observed it.
	}
	if err != nil {
		t.Fatalf("open Windows helper process %d: %v", pid, err)
	}
	defer func() { _ = windows.CloseHandle(process) }()
	status, err := windows.WaitForSingleObject(process, 10_000)
	if err != nil {
		t.Fatalf("wait for Windows helper process %d: %v", pid, err)
	}
	if status != windows.WAIT_OBJECT_0 {
		t.Fatalf("Windows helper process %d did not exit after task removal (wait status %#x)", pid, status)
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
	file, err := os.OpenFile(os.Args[separator+1], os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(strconv.Itoa(os.Getpid()) + "\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Minute)
}

func decodeWindowsTaskXML(t *testing.T, raw []byte) string {
	t.Helper()
	if len(raw) < 2 || raw[0] != 0xff || raw[1] != 0xfe || len(raw)%2 != 0 {
		t.Fatalf("Windows task XML is not UTF-16LE with a BOM")
	}
	units := make([]uint16, (len(raw)-2)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(raw[2+index*2:])
	}
	return string(utf16.Decode(units))
}
