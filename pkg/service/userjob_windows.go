//go:build windows

package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsTaskDefinitionPrefix = "layerv-qurl-user-job-sha256:"

const windowsUserJobTemplate = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>{{xml .DefinitionMarker}}</Description>
  </RegistrationInfo>
  <Triggers>{{if .RunAtLoad}}
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{{xml .UserSID}}</UserId>
    </LogonTrigger>{{end}}
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{{xml .UserSID}}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>{{if .KeepAlive}}
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>{{end}}
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{{xml .BinaryPath}}</Command>
      <Arguments>{{xml .CommandLine}}</Arguments>
      <WorkingDirectory>{{xml .WorkingDirectory}}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
`

type windowsRenderedUserJob struct {
	UserSID          string
	DefinitionMarker string
	BinaryPath       string
	CommandLine      string
	WorkingDirectory string
	RunAtLoad        bool
	KeepAlive        bool
}

type windowsUserJobManager struct {
	run           func(string, ...string) (string, error)
	currentSID    func() (string, error)
	powerShell    func() (string, error)
	taskScheduler func() (string, error)
}

// NewUserJobManager returns a per-user Windows Task Scheduler manager.
func NewUserJobManager() UserJobManager {
	return &windowsUserJobManager{
		run: windowsJobCommandOutput, currentSID: currentWindowsUserSID,
		powerShell: windowsPowerShellExecutable, taskScheduler: windowsTaskSchedulerExecutable,
	}
}

func (m *windowsUserJobManager) Ensure(job UserJob) error {
	return m.ensure(job, false)
}

func (m *windowsUserJobManager) Replace(job UserJob) error {
	return m.ensure(job, true)
}

func (m *windowsUserJobManager) ensure(job UserJob, forceReplace bool) error {
	job, err := normalizeUserJob(job)
	if err != nil {
		return err
	}
	sid, taskName, err := m.identity(job.Label)
	if err != nil {
		return err
	}
	content, marker, err := m.render(job, sid)
	if err != nil {
		return err
	}
	for _, dir := range []string{filepath.Dir(job.StandardOut), filepath.Dir(job.StandardErr)} {
		if err := ensureWindowsPrivateDirectory(dir, sid); err != nil {
			return fmt.Errorf("create Windows user job directory %s: %w", dir, err)
		}
	}
	for _, path := range []string{job.StandardOut, job.StandardErr} {
		if err := ensureWindowsPrivateFile(path, sid); err != nil {
			return fmt.Errorf("create Windows user job log %s: %w", path, err)
		}
	}
	installed, err := m.installed(taskName)
	if err != nil {
		return fmt.Errorf("inspect Windows user job %s: %w", job.Label, err)
	}
	var existing string
	if installed {
		existing, err = m.runTaskScheduler("/Query", "/TN", taskName, "/XML")
		if err != nil {
			return fmt.Errorf("read Windows user job %s: %w", job.Label, err)
		}
		existing = decodeWindowsCommandText(existing)
	}
	if installed && !forceReplace && strings.Contains(existing, marker) {
		running, stateErr := m.running(taskName)
		if stateErr != nil {
			return fmt.Errorf("inspect Windows user job %s: %w", job.Label, stateErr)
		}
		if running {
			return nil
		}
		return m.start(job.Label, taskName)
	}
	if installed {
		// A changed definition or explicit replacement must stop the old process
		// before Task Scheduler replaces the durable task.
		running, stateErr := m.running(taskName)
		if stateErr != nil {
			return fmt.Errorf("inspect Windows user job %s before replacement: %w", job.Label, stateErr)
		}
		if running {
			if _, err := m.runTaskScheduler("/End", "/TN", taskName); err != nil {
				return fmt.Errorf("stop Windows user job %s before replacement: %w", job.Label, err)
			}
			if err := m.waitUntilStopped(taskName); err != nil {
				return fmt.Errorf("wait for Windows user job %s to stop before replacement: %w", job.Label, err)
			}
		}
	}
	definition, err := os.CreateTemp(filepath.Dir(job.StandardOut), ".qurl-user-job-*.xml")
	if err != nil {
		return fmt.Errorf("create temporary Windows user job definition: %w", err)
	}
	definitionPath := definition.Name()
	defer func() { _ = os.Remove(definitionPath) }()
	if err := protectWindowsUserJobPath(definitionPath, sid); err != nil {
		_ = definition.Close()
		return fmt.Errorf("protect temporary Windows user job definition: %w", err)
	}
	if _, err := definition.Write(windowsTaskXMLBytes(content)); err != nil {
		_ = definition.Close()
		return fmt.Errorf("write temporary Windows user job definition: %w", err)
	}
	if err := definition.Sync(); err != nil {
		_ = definition.Close()
		return fmt.Errorf("sync temporary Windows user job definition: %w", err)
	}
	if err := definition.Close(); err != nil {
		return fmt.Errorf("close temporary Windows user job definition: %w", err)
	}
	if _, err := m.runTaskScheduler("/Create", "/TN", taskName, "/XML", definitionPath, "/F"); err != nil {
		return fmt.Errorf("install Windows user job %s: %w", job.Label, err)
	}
	return m.start(job.Label, taskName)
}

func (m *windowsUserJobManager) start(label, taskName string) error {
	if _, err := m.runTaskScheduler("/Run", "/TN", taskName); err != nil {
		return fmt.Errorf("start Windows user job %s: %w", label, err)
	}
	return nil
}

func (m *windowsUserJobManager) Remove(label string) error {
	if !userJobLabelPattern.MatchString(label) {
		return fmt.Errorf("invalid Windows user job label %q", label)
	}
	_, taskName, err := m.identity(label)
	if err != nil {
		return err
	}
	installed, err := m.installed(taskName)
	if err != nil {
		return fmt.Errorf("inspect Windows user job %s: %w", label, err)
	}
	if !installed {
		return nil
	}
	running, err := m.running(taskName)
	if err != nil {
		return fmt.Errorf("inspect Windows user job %s before removal: %w", label, err)
	}
	if running {
		if _, err := m.runTaskScheduler("/End", "/TN", taskName); err != nil {
			return fmt.Errorf("stop Windows user job %s before removal: %w", label, err)
		}
		if err := m.waitUntilStopped(taskName); err != nil {
			return fmt.Errorf("wait for Windows user job %s to stop before removal: %w", label, err)
		}
	}
	if _, err := m.runTaskScheduler("/Delete", "/TN", taskName, "/F"); err != nil {
		return fmt.Errorf("remove Windows user job %s: %w", label, err)
	}
	return nil
}

func (m *windowsUserJobManager) Status(label string) (ServiceStatus, error) {
	if !userJobLabelPattern.MatchString(label) {
		return ServiceStatus{}, fmt.Errorf("invalid Windows user job label %q", label)
	}
	_, taskName, err := m.identity(label)
	if err != nil {
		return ServiceStatus{}, err
	}
	installed, err := m.installed(taskName)
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("inspect Windows user job %s: %w", label, err)
	}
	if !installed {
		return ServiceStatus{}, nil
	}
	running, err := m.running(taskName)
	if err != nil {
		return ServiceStatus{Installed: true}, err
	}
	return ServiceStatus{Installed: true, Running: running}, nil
}

func (m *windowsUserJobManager) installed(label string) (bool, error) {
	command := "$ErrorActionPreference='Stop'; $tasks = @(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop | " +
		"Where-Object { $_.TaskName -eq '" + label + "' }); if ($tasks.Count -eq 0) { '0' } " +
		"elseif ($tasks.Count -eq 1) { '1' } else { throw 'duplicate task name' }"
	output, err := m.runPowerShell(command)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(output) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("parse Windows user job presence %q", strings.TrimSpace(output))
	}
}

func (m *windowsUserJobManager) running(label string) (bool, error) {
	// ScheduledTaskState is a stable numeric enum: Running is 4. Numeric output
	// avoids localized schtasks status strings.
	command := "$task = Get-ScheduledTask -TaskName '" + label + "' -TaskPath '\\' -ErrorAction Stop; [int]$task.State"
	output, err := m.runPowerShell(command)
	if err != nil {
		return false, err
	}
	state, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil {
		return false, fmt.Errorf("parse Windows user job state %q: %w", strings.TrimSpace(output), err)
	}
	return state == 4, nil
}

func (m *windowsUserJobManager) waitUntilStopped(label string) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		running, err := m.running(label)
		if err != nil {
			return err
		}
		if !running {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("Task Scheduler still reports the task as running after 10 seconds")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (m *windowsUserJobManager) render(job UserJob, sid string) (string, string, error) {
	canonical, err := json.Marshal(struct {
		Job UserJob `json:"job"`
		SID string  `json:"sid"`
	}{Job: job, SID: sid})
	if err != nil {
		return "", "", fmt.Errorf("encode Windows user job definition: %w", err)
	}
	digest := sha256.Sum256(canonical)
	marker := windowsTaskDefinitionPrefix + hex.EncodeToString(digest[:])
	arguments := make([]string, 0, len(job.Arguments))
	for _, argument := range job.Arguments {
		arguments = append(arguments, windows.EscapeArg(argument))
	}
	view := windowsRenderedUserJob{
		UserSID: sid, DefinitionMarker: marker, BinaryPath: job.BinaryPath,
		CommandLine:      strings.Join(arguments, " "),
		WorkingDirectory: filepath.Dir(job.BinaryPath),
		RunAtLoad:        job.RunAtLoad, KeepAlive: job.KeepAlive,
	}
	tmpl, err := template.New("windows-user-job").Funcs(template.FuncMap{"xml": xmlText}).Parse(windowsUserJobTemplate)
	if err != nil {
		return "", "", fmt.Errorf("parse Windows user job template: %w", err)
	}
	var buffer bytes.Buffer
	if err := tmpl.Execute(&buffer, view); err != nil {
		return "", "", fmt.Errorf("render Windows user job: %w", err)
	}
	return buffer.String(), marker, nil
}

func (m *windowsUserJobManager) identity(label string) (string, string, error) {
	if m == nil || m.currentSID == nil {
		return "", "", errors.New("Windows user job manager is incomplete")
	}
	sid, err := m.currentSID()
	if err != nil {
		return "", "", err
	}
	return sid, windowsScopedTaskName(label, sid), nil
}

func (m *windowsUserJobManager) powerShellExecutable() (string, error) {
	if m != nil && m.powerShell != nil {
		return m.powerShell()
	}
	return windowsPowerShellExecutable()
}

func (m *windowsUserJobManager) runPowerShell(command string) (string, error) {
	executable, err := m.powerShellExecutable()
	if err != nil {
		return "", err
	}
	return m.run(executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command)
}

func (m *windowsUserJobManager) runTaskScheduler(arguments ...string) (string, error) {
	resolve := windowsTaskSchedulerExecutable
	if m != nil && m.taskScheduler != nil {
		resolve = m.taskScheduler
	}
	executable, err := resolve()
	if err != nil {
		return "", err
	}
	return m.run(executable, arguments...)
}

func windowsScopedTaskName(label, sid string) string {
	digest := sha256.Sum256([]byte(sid))
	suffix := hex.EncodeToString(digest[:8])
	const maxTaskName = 128
	if limit := maxTaskName - len(suffix) - 1; len(label) > limit {
		label = label[:limit]
	}
	return label + "." + suffix
}

func windowsTaskXMLBytes(content string) []byte {
	units := utf16.Encode([]rune(content))
	raw := make([]byte, 2+len(units)*2)
	raw[0], raw[1] = 0xff, 0xfe
	for index, unit := range units {
		binary.LittleEndian.PutUint16(raw[2+index*2:], unit)
	}
	return raw
}

func currentWindowsUserSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", fmt.Errorf("open current Windows user token: %w", err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current Windows user SID: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return "", errors.New("read current Windows user SID: token has no user SID")
	}
	return user.User.Sid.String(), nil
}

func windowsPowerShellExecutable() (string, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("locate Windows PowerShell: %w", err)
	}
	return filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe"), nil
}

func windowsTaskSchedulerExecutable() (string, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return "", fmt.Errorf("locate Windows Task Scheduler client: %w", err)
	}
	return filepath.Join(systemDirectory, "schtasks.exe"), nil
}

func ensureWindowsPrivateDirectory(path, sid string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return protectWindowsUserJobPath(path, sid)
}

func ensureWindowsPrivateFile(path, sid string) error {
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sG:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", sid, sid, sid))
	if err != nil {
		return fmt.Errorf("build protected Windows user job file ACL: %w", err)
	}
	security := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(path16,
		windows.FILE_APPEND_DATA|windows.READ_CONTROL|windows.WRITE_DAC|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		security, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return errors.New("Windows user job log must be a non-reparse, single-link file")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read protected Windows user job file ACL: %w", err)
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply protected Windows user job file ACL: %w", err)
	}
	return nil
}

func protectWindowsUserJobPath(path, sid string) error {
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sG:%sD:P(A;OICI;FA;;;%s)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", sid, sid, sid))
	if err != nil {
		return fmt.Errorf("build protected Windows user job ACL: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read protected Windows user job ACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply protected Windows user job ACL: %w", err)
	}
	return nil
}

func decodeWindowsCommandText(value string) string {
	raw := []byte(value)
	if len(raw) < 2 {
		return value
	}
	offset := 0
	switch {
	case raw[0] == 0xff && raw[1] == 0xfe:
		offset = 2
	case raw[0] == 0xfe && raw[1] == 0xff:
		units := make([]uint16, (len(raw)-2)/2)
		for index := range units {
			units[index] = binary.BigEndian.Uint16(raw[2+index*2:])
		}
		return string(utf16.Decode(units))
	case raw[1] != 0:
		return value
	}
	if (len(raw)-offset)%2 != 0 {
		return value
	}
	units := make([]uint16, (len(raw)-offset)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(raw[offset+index*2:])
	}
	return string(utf16.Decode(units))
}

func windowsJobCommandOutput(name string, args ...string) (string, error) {
	command := exec.Command(name, args...)
	output, err := command.CombinedOutput()
	if err == nil {
		return string(output), nil
	}
	return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
}
