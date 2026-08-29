//go:build windows

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
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

const (
	windowsTaskStateAbsent   = -1
	windowsTaskStateDisabled = 1
	windowsTaskStateRunning  = 4
)

const windowsTrustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

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

func (m *windowsUserJobManager) ensure(job UserJob, forceReplace bool) (retErr error) {
	job, err := normalizeUserJob(job)
	if err != nil {
		return err
	}
	sid, taskName, err := m.identity(job.Label)
	if err != nil {
		return err
	}
	content, _, err := m.render(job, sid)
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
	state, err := m.state(taskName)
	if err != nil {
		return fmt.Errorf("inspect Windows user job %s: %w", job.Label, err)
	}
	installed := state != windowsTaskStateAbsent
	definitionMatches := false
	if installed && !forceReplace && state != windowsTaskStateDisabled {
		existing, queryErr := m.runTaskScheduler("/Query", "/TN", taskName, "/XML")
		if queryErr != nil {
			return fmt.Errorf("read Windows user job %s: %w", job.Label, queryErr)
		}
		existing = decodeWindowsCommandText(existing)
		definitionMatches, err = matchingWindowsUserJobDefinition(existing, content)
		if err != nil {
			return fmt.Errorf("validate Windows user job %s definition: %w", job.Label, err)
		}
	}
	if definitionMatches {
		if state == windowsTaskStateRunning {
			return nil
		}
		return m.start(job.Label, taskName)
	}
	definition, err := os.CreateTemp(filepath.Dir(job.StandardOut), ".qurl-user-job-*.xml")
	if err != nil {
		return fmt.Errorf("create temporary Windows user job definition: %w", err)
	}
	definitionPath := definition.Name()
	defer func() {
		cleanupErr := removeWindowsUserJobDefinition(definitionPath)
		// A protected stale definition is inert. Do not report an established,
		// running task as failed only because an indexer or scanner still held the
		// temporary file after Task Scheduler consumed it.
		if retErr != nil {
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()
	if err := ensureWindowsPrivateFile(definitionPath, sid); err != nil {
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

	wasRunning := false
	restoreNeeded := false
	defer func() {
		if retErr != nil && restoreNeeded {
			retErr = errors.Join(retErr, m.restore(job.Label, taskName, wasRunning))
		}
	}()
	if installed {
		// A changed definition or explicit replacement must stop the old process
		// before Task Scheduler replaces the durable task. Disable it first so a
		// KeepAlive task cannot restart between /End and /Create.
		wasRunning = state == windowsTaskStateRunning
		restoreNeeded = true
		if _, err := m.runTaskScheduler("/Change", "/TN", taskName, "/Disable"); err != nil {
			return fmt.Errorf("disable Windows user job %s before replacement: %w", job.Label, err)
		}
		if wasRunning {
			if _, endErr := m.runTaskScheduler("/End", "/TN", taskName); endErr != nil {
				current, stateErr := m.state(taskName)
				if stateErr != nil || current == windowsTaskStateRunning {
					return errors.Join(fmt.Errorf("stop Windows user job %s before replacement: %w", job.Label, endErr), stateErr)
				}
			} else if err := m.waitUntilStopped(taskName); err != nil {
				return fmt.Errorf("wait for Windows user job %s to stop before replacement: %w", job.Label, err)
			}
		}
	}
	if _, err := m.runTaskScheduler("/Create", "/TN", taskName, "/XML", definitionPath, "/F"); err != nil {
		return fmt.Errorf("install Windows user job %s: %w", job.Label, err)
	}
	restoreNeeded = false
	return m.start(job.Label, taskName)
}

func removeWindowsUserJobDefinition(path string) error {
	err := os.Remove(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (m *windowsUserJobManager) restore(label, taskName string, wasRunning bool) error {
	if _, err := m.runTaskScheduler("/Change", "/TN", taskName, "/Enable"); err != nil {
		return fmt.Errorf("restore Windows user job %s after failed change: %w", label, err)
	}
	if wasRunning {
		if _, err := m.runTaskScheduler("/Run", "/TN", taskName); err != nil {
			return fmt.Errorf("restart Windows user job %s after failed change: %w", label, err)
		}
	}
	return nil
}

func (m *windowsUserJobManager) start(label, taskName string) error {
	if _, err := m.runTaskScheduler("/Run", "/TN", taskName); err != nil {
		return fmt.Errorf("start Windows user job %s: %w", label, err)
	}
	return nil
}

func (m *windowsUserJobManager) Remove(label string) (retErr error) {
	if !userJobLabelPattern.MatchString(label) {
		return fmt.Errorf("invalid Windows user job label %q", label)
	}
	_, taskName, err := m.identity(label)
	if err != nil {
		return err
	}
	state, err := m.state(taskName)
	if err != nil {
		return fmt.Errorf("inspect Windows user job %s: %w", label, err)
	}
	if state == windowsTaskStateAbsent {
		return nil
	}
	// Disable before /End so restart-on-failure cannot race task deletion.
	wasRunning := state == windowsTaskStateRunning
	restoreNeeded := true
	defer func() {
		if retErr != nil && restoreNeeded {
			retErr = errors.Join(retErr, m.restore(label, taskName, wasRunning))
		}
	}()
	if _, err := m.runTaskScheduler("/Change", "/TN", taskName, "/Disable"); err != nil {
		return fmt.Errorf("disable Windows user job %s before removal: %w", label, err)
	}
	if wasRunning {
		if _, endErr := m.runTaskScheduler("/End", "/TN", taskName); endErr != nil {
			current, stateErr := m.state(taskName)
			if stateErr != nil || current == windowsTaskStateRunning {
				return errors.Join(fmt.Errorf("stop Windows user job %s before removal: %w", label, endErr), stateErr)
			}
		} else if err := m.waitUntilStopped(taskName); err != nil {
			return fmt.Errorf("wait for Windows user job %s to stop before removal: %w", label, err)
		}
	}
	if _, err := m.runTaskScheduler("/Delete", "/TN", taskName, "/F"); err != nil {
		return fmt.Errorf("remove Windows user job %s: %w", label, err)
	}
	restoreNeeded = false
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
	state, err := m.state(taskName)
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("inspect Windows user job %s: %w", label, err)
	}
	if state == windowsTaskStateAbsent {
		return ServiceStatus{}, nil
	}
	return ServiceStatus{Installed: true, Running: state == windowsTaskStateRunning}, nil
}

func (m *windowsUserJobManager) state(taskName string) (int, error) {
	// taskName is derived from userJobLabelPattern plus a hex digest. The
	// pattern excludes PowerShell quoting and wildcard characters, so this is
	// one exact root-folder lookup rather than an enumeration.
	command := "$ErrorActionPreference='Stop'; try { $task = Get-ScheduledTask -TaskName '" + taskName +
		"' -TaskPath '\\' -ErrorAction Stop } catch { if ($_.CategoryInfo.Category -ne 'ObjectNotFound') { throw }; $task = $null }; " +
		"if ($null -eq $task) { '-1' } else { [int]$task.State }"
	output, err := m.runPowerShell(command)
	if err != nil {
		return 0, err
	}
	state, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil {
		return 0, fmt.Errorf("parse Windows user job state %q: %w", strings.TrimSpace(output), err)
	}
	if state < windowsTaskStateAbsent || state > windowsTaskStateRunning {
		return 0, fmt.Errorf("parse Windows user job state %q: value is outside the ScheduledTaskState range", strings.TrimSpace(output))
	}
	return state, nil
}

func (m *windowsUserJobManager) waitUntilStopped(taskName string) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		state, err := m.state(taskName)
		if err != nil {
			return err
		}
		if state != windowsTaskStateRunning {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("Task Scheduler still reports the task as running after 10 seconds")
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (m *windowsUserJobManager) render(job UserJob, sid string) (string, string, error) {
	return renderWindowsUserJobDefinition(job, sid, windowsUserJobTemplate)
}

func renderWindowsUserJobDefinition(job UserJob, sid, templateText string) (string, string, error) {
	arguments := make([]string, 0, len(job.Arguments))
	for _, argument := range job.Arguments {
		arguments = append(arguments, windows.EscapeArg(argument))
	}
	view := windowsRenderedUserJob{
		UserSID: sid, BinaryPath: job.BinaryPath,
		CommandLine:      strings.Join(arguments, " "),
		WorkingDirectory: filepath.Dir(job.StandardOut),
		RunAtLoad:        job.RunAtLoad, KeepAlive: job.KeepAlive,
	}
	tmpl, err := template.New("windows-user-job").Funcs(template.FuncMap{"xml": xmlText}).Parse(templateText)
	if err != nil {
		return "", "", fmt.Errorf("parse Windows user job template: %w", err)
	}
	render := func() (string, error) {
		var buffer bytes.Buffer
		if err := tmpl.Execute(&buffer, view); err != nil {
			return "", err
		}
		return buffer.String(), nil
	}
	canonical, err := render()
	if err != nil {
		return "", "", fmt.Errorf("render Windows user job: %w", err)
	}
	digest := sha256.Sum256([]byte(canonical))
	marker := windowsTaskDefinitionPrefix + hex.EncodeToString(digest[:])
	view.DefinitionMarker = marker
	content, err := render()
	if err != nil {
		return "", "", fmt.Errorf("render Windows user job: %w", err)
	}
	return content, marker, nil
}

type windowsUserJobDefinition struct {
	Registration struct {
		Description string `xml:"Description"`
	} `xml:"RegistrationInfo"`
	Triggers struct {
		Logon struct {
			Enabled string `xml:"Enabled"`
			UserID  string `xml:"UserId"`
		} `xml:"LogonTrigger"`
	} `xml:"Triggers"`
	Principals struct {
		Principal struct {
			ID        string `xml:"id,attr"`
			UserID    string `xml:"UserId"`
			LogonType string `xml:"LogonType"`
			RunLevel  string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		MultipleInstancesPolicy      string `xml:"MultipleInstancesPolicy"`
		DisallowStartIfOnBatteries   string `xml:"DisallowStartIfOnBatteries"`
		StopIfGoingOnBatteries       string `xml:"StopIfGoingOnBatteries"`
		AllowHardTerminate           string `xml:"AllowHardTerminate"`
		StartWhenAvailable           string `xml:"StartWhenAvailable"`
		RunOnlyIfNetworkAvailable    string `xml:"RunOnlyIfNetworkAvailable"`
		AllowStartOnDemand           string `xml:"AllowStartOnDemand"`
		Enabled                      string `xml:"Enabled"`
		Hidden                       string `xml:"Hidden"`
		RunOnlyIfIdle                string `xml:"RunOnlyIfIdle"`
		WakeToRun                    string `xml:"WakeToRun"`
		ExecutionTimeLimit           string `xml:"ExecutionTimeLimit"`
		Priority                     string `xml:"Priority"`
		RestartOnFailureInterval     string `xml:"RestartOnFailure>Interval"`
		RestartOnFailureAttemptCount string `xml:"RestartOnFailure>Count"`
	} `xml:"Settings"`
	Actions struct {
		Context string `xml:"Context,attr"`
		Exec    struct {
			Command          string `xml:"Command"`
			Arguments        string `xml:"Arguments"`
			WorkingDirectory string `xml:"WorkingDirectory"`
		} `xml:"Exec"`
	} `xml:"Actions"`
}

func matchingWindowsUserJobDefinition(registered, expected string) (bool, error) {
	registeredDefinition, err := parseWindowsUserJobDefinition(registered)
	if err != nil {
		return false, fmt.Errorf("parse registered task: %w", err)
	}
	expectedDefinition, err := parseWindowsUserJobDefinition(expected)
	if err != nil {
		return false, fmt.Errorf("parse expected task: %w", err)
	}
	if err := normalizeWindowsUserJobDefinition(&registeredDefinition); err != nil {
		return false, fmt.Errorf("normalize registered task: %w", err)
	}
	if err := normalizeWindowsUserJobDefinition(&expectedDefinition); err != nil {
		return false, fmt.Errorf("normalize expected task: %w", err)
	}
	return registeredDefinition == expectedDefinition, nil
}

func normalizeWindowsUserJobDefinition(definition *windowsUserJobDefinition) error {
	if definition == nil {
		return errors.New("Windows task definition is nil")
	}
	// An on-demand-only job has no LogonTrigger. Canonicalize that identity
	// only when the trigger exists; the principal identity is always required.
	if definition.Triggers.Logon.UserID != "" {
		canonical, err := canonicalWindowsTaskUserID(definition.Triggers.Logon.UserID)
		if err != nil {
			return fmt.Errorf("resolve logon trigger user: %w", err)
		}
		definition.Triggers.Logon.UserID = canonical
	}
	canonical, err := canonicalWindowsTaskUserID(definition.Principals.Principal.UserID)
	if err != nil {
		return fmt.Errorf("resolve principal user: %w", err)
	}
	definition.Principals.Principal.UserID = canonical
	// Task Scheduler omits these fields when they hold their schema defaults.
	// Normalize the documented Task Scheduler schema defaults before comparing
	// the registered behavior with the complete expected behavior.
	if definition.Triggers.Logon.UserID != "" && definition.Triggers.Logon.Enabled == "" {
		definition.Triggers.Logon.Enabled = "true"
	}
	if definition.Principals.Principal.RunLevel == "" {
		definition.Principals.Principal.RunLevel = "LeastPrivilege"
	}
	for _, field := range []struct {
		value        *string
		defaultValue string
	}{
		{&definition.Settings.MultipleInstancesPolicy, "IgnoreNew"},
		{&definition.Settings.DisallowStartIfOnBatteries, "true"},
		{&definition.Settings.StopIfGoingOnBatteries, "true"},
		{&definition.Settings.AllowHardTerminate, "true"},
		{&definition.Settings.StartWhenAvailable, "false"},
		{&definition.Settings.RunOnlyIfNetworkAvailable, "false"},
		{&definition.Settings.AllowStartOnDemand, "true"},
		{&definition.Settings.Enabled, "true"},
		{&definition.Settings.Hidden, "false"},
		{&definition.Settings.RunOnlyIfIdle, "false"},
		{&definition.Settings.WakeToRun, "false"},
		{&definition.Settings.ExecutionTimeLimit, "PT72H"},
		{&definition.Settings.Priority, "7"},
	} {
		if *field.value == "" {
			*field.value = field.defaultValue
		}
	}
	return nil
}

func canonicalWindowsTaskUserID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("Windows task user is empty")
	}
	if sid, err := windows.StringToSid(value); err == nil {
		return sid.String(), nil
	}
	sid, _, _, err := windows.LookupSID("", value)
	if err != nil {
		return "", err
	}
	if sid == nil || !sid.IsValid() {
		return "", errors.New("Windows account resolved without a valid SID")
	}
	return sid.String(), nil
}

func parseWindowsUserJobDefinition(content string) (windowsUserJobDefinition, error) {
	var definition windowsUserJobDefinition
	decoder := xml.NewDecoder(strings.NewReader(content))
	// schtasks reports UTF-16 XML. decodeWindowsCommandText already converted
	// its bytes to Go's UTF-8 string representation, so keep the decoded byte
	// stream when encoding/xml sees the original declaration.
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		if strings.EqualFold(label, "utf-16") || strings.EqualFold(label, "utf-8") {
			return input, nil
		}
		return nil, fmt.Errorf("unsupported Windows task XML encoding %q", label)
	}
	if err := decoder.Decode(&definition); err != nil {
		return windowsUserJobDefinition{}, err
	}
	return definition, nil
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
	// Include the complete label in the digest so two overlong labels with the
	// same retained prefix cannot address the same scheduled task.
	digest := sha256.Sum256([]byte(sid + "\x00" + label))
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
	_, err := os.Lstat(path)
	created := false
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		// The caller must provide an existing safe parent. Creating only the
		// dedicated leaf avoids taking ownership of a caller-supplied ancestor.
		if err := os.Mkdir(path, 0o700); err != nil {
			return err
		}
		created = true
	default:
		return err
	}
	if err := validateAndProtectWindowsDirectory(path, sid, created); err != nil {
		if created {
			removeErr := os.Remove(path)
			if removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				return errors.Join(err, fmt.Errorf("remove rejected Windows user job directory: %w", removeErr))
			}
		}
		return err
	}
	return nil
}

func ensureWindowsPrivateFile(path, sid string) error {
	descriptor, err := windowsUserJobSecurityDescriptor(sid, false)
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
		windows.FILE_APPEND_DATA|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.SYNCHRONIZE,
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
	if err := protectWindowsUserJobHandle(handle, sid, false); err != nil {
		return fmt.Errorf("apply protected Windows user job file identity: %w", err)
	}
	return nil
}

func windowsUserJobSecurityDescriptor(sid string, directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sG:%sD:P(A;%s;FA;;;%s)(A;%s;FA;;;SY)(A;%s;FA;;;BA)",
		sid, sid, inheritance, sid, inheritance, inheritance))
	if err != nil {
		return nil, fmt.Errorf("build protected Windows user job ACL: %w", err)
	}
	return descriptor, nil
}

func protectWindowsUserJobHandle(handle windows.Handle, sid string, directory bool) error {
	descriptor, err := windowsUserJobSecurityDescriptor(sid, directory)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read protected Windows user job ACL: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return errors.New("read protected Windows user job owner")
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply protected Windows user job ACL: %w", err)
	}
	return nil
}

const windowsUserJobAncestorMutation = windows.ACCESS_MASK(
	windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE |
		windows.GENERIC_ALL | 0x00000040) // FILE_DELETE_CHILD

const windowsUserJobAllAccess = windows.ACCESS_MASK(0x001f01ff)

type windowsUserJobACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	ACECount uint16
	Sbz2     uint16
}

func validateAndProtectWindowsDirectory(path, sidText string, protectCreatedLeaf bool) error { //nolint:gocyclo // One no-follow path and ACL authority fence.
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	if volume == "" || !filepath.IsAbs(clean) || strings.HasPrefix(clean, `\\?\`) || strings.HasPrefix(clean, `\\.\`) {
		return errors.New("Windows user job directory must be an absolute filesystem path")
	}
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, clean)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("Windows user job directory must be below a volume root")
	}
	currentSID, err := windows.StringToSid(sidText)
	if err != nil {
		return fmt.Errorf("parse current Windows user SID: %w", err)
	}
	adminSID, adminErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	systemSID, systemErr := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	installerSID, installerErr := windows.StringToSid(windowsTrustedInstallerSID)
	if adminErr != nil || systemErr != nil || installerErr != nil {
		return errors.New("build trusted Windows user job identities")
	}
	trustedAncestor := func(candidate *windows.SID) bool {
		return candidate != nil && (candidate.Equals(currentSID) || candidate.Equals(adminSID) ||
			candidate.Equals(systemSID) || candidate.Equals(installerSID))
	}
	trustedLeaf := func(candidate *windows.SID) bool {
		return candidate != nil && (candidate.Equals(currentSID) || candidate.Equals(adminSID) || candidate.Equals(systemSID))
	}
	components := strings.Split(relative, string(filepath.Separator))
	paths := make([]string, 0, len(components)+1)
	paths = append(paths, root)
	cursor := root
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return errors.New("Windows user job directory has an invalid component")
		}
		cursor = filepath.Join(cursor, component)
		paths = append(paths, cursor)
	}

	handles := make([]windows.Handle, 0, len(paths))
	defer func() {
		for index := len(handles) - 1; index >= 0; index-- {
			_ = windows.CloseHandle(handles[index])
		}
	}()
	for index, candidate := range paths {
		path16, conversionErr := windows.UTF16PtrFromString(candidate)
		if conversionErr != nil {
			return conversionErr
		}
		leaf := index == len(paths)-1
		access := uint32(windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL)
		if leaf && protectCreatedLeaf {
			access |= windows.WRITE_DAC | windows.WRITE_OWNER
		}
		handle, openErr := windows.CreateFile(path16, access,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if openErr != nil {
			return fmt.Errorf("open Windows user job directory component: %w", openErr)
		}
		handles = append(handles, handle)
		var info windows.ByHandleFileInformation
		if statErr := windows.GetFileInformationByHandle(handle, &info); statErr != nil {
			return fmt.Errorf("inspect Windows user job directory component: %w", statErr)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("Windows user job directory components must be non-reparse directories")
		}
		if leaf && protectCreatedLeaf {
			if protectErr := protectWindowsUserJobHandle(handle, sidText, true); protectErr != nil {
				return protectErr
			}
		}
		descriptor, securityErr := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if securityErr != nil || descriptor == nil {
			return fmt.Errorf("read Windows user job directory ACL: %w", securityErr)
		}
		owner, _, ownerErr := descriptor.Owner()
		if ownerErr != nil || owner == nil || (!leaf && !trustedAncestor(owner)) || (leaf && !owner.Equals(currentSID)) {
			return fmt.Errorf("Windows user job directory %s has an untrusted owner", candidate)
		}
		control, _, controlErr := descriptor.Control()
		if leaf && (controlErr != nil || control&windows.SE_DACL_PROTECTED == 0) {
			return errors.New("Windows user job directory ACL must be protected from inheritance")
		}
		dacl, _, daclErr := descriptor.DACL()
		if daclErr != nil || dacl == nil {
			return errors.New("Windows user job directory has no restrictive DACL")
		}
		header := (*windowsUserJobACLHeader)(unsafe.Pointer(dacl))
		var currentMask windows.ACCESS_MASK
		for aceIndex := uint32(0); aceIndex < uint32(header.ACECount); aceIndex++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if aceErr := windows.GetAce(dacl, aceIndex, &ace); aceErr != nil || ace == nil {
				return fmt.Errorf("inspect Windows user job directory DACL: %w", aceErr)
			}
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				if leaf {
					return errors.New("Windows user job directory has an unsupported deny entry")
				}
				continue
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
				return errors.New("Windows user job directory has an unsupported DACL entry")
			}
			principal := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if principal == nil || !principal.IsValid() {
				return errors.New("Windows user job directory has an invalid DACL identity")
			}
			// Inherit-only entries on an ancestor do not grant access to that
			// component, and each descendant is opened and checked independently.
			// On the leaf they can grant unsafe access to files created later, so
			// they must pass the same trusted-principal fence as direct entries.
			if !leaf && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
				continue
			}
			if leaf && !trustedLeaf(principal) {
				return errors.New("Windows user job directory grants unsafe access to another principal")
			}
			if !leaf && !trustedAncestor(principal) && ace.Mask&windowsUserJobAncestorMutation != 0 {
				return errors.New("Windows user job directory grants unsafe access to another principal")
			}
			if leaf && principal.Equals(currentSID) && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
				currentMask |= ace.Mask
			}
		}
		if leaf && currentMask&windowsUserJobAllAccess != windowsUserJobAllAccess && currentMask&windows.GENERIC_ALL == 0 {
			return errors.New("Windows user job directory does not grant the current user full control")
		}
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
	return windowsJobCommandOutputWithin(20*time.Second, name, args...)
}

func windowsJobCommandOutputWithin(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...) //nolint:gosec // G702: production callers resolve fixed System32 executables; tests inject exact helper paths.
	output, err := command.Output()
	if err == nil {
		return string(output), nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", fmt.Errorf("%s: %w", name, ctxErr)
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(exitError.Stderr)))
	}
	return "", fmt.Errorf("%s: %w", name, err)
}
