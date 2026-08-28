//go:build windows

package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
	"unicode/utf16"

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
	run        func(string, ...string) (string, error)
	currentSID func() (string, error)
}

// NewUserJobManager returns a per-user Windows Task Scheduler manager.
func NewUserJobManager() UserJobManager {
	return &windowsUserJobManager{run: windowsJobCommandOutput, currentSID: currentWindowsUserSID}
}

func (m *windowsUserJobManager) Ensure(job UserJob) error {
	return m.ensure(job, false)
}

func (m *windowsUserJobManager) Replace(job UserJob) error {
	return m.ensure(job, true)
}

func (m *windowsUserJobManager) ensure(job UserJob, forceReplace bool) error {
	content, marker, err := m.render(job)
	if err != nil {
		return err
	}
	for _, dir := range []string{filepath.Dir(job.StandardOut), filepath.Dir(job.StandardErr)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create Windows user job directory %s: %w", dir, err)
		}
	}
	installed, err := m.installed(job.Label)
	if err != nil {
		return fmt.Errorf("inspect Windows user job %s: %w", job.Label, err)
	}
	var existing string
	if installed {
		existing, err = m.run("schtasks.exe", "/Query", "/TN", job.Label, "/XML")
		if err != nil {
			return fmt.Errorf("read Windows user job %s: %w", job.Label, err)
		}
	}
	if installed && !forceReplace && strings.Contains(existing, marker) {
		running, stateErr := m.running(job.Label)
		if stateErr != nil {
			return fmt.Errorf("inspect Windows user job %s: %w", job.Label, stateErr)
		}
		if running {
			return nil
		}
		return m.start(job.Label)
	}
	if installed {
		// A changed definition or explicit replacement must stop the old process
		// before Task Scheduler replaces the durable task.
		running, stateErr := m.running(job.Label)
		if stateErr != nil {
			return fmt.Errorf("inspect Windows user job %s before replacement: %w", job.Label, stateErr)
		}
		if running {
			if _, err := m.run("schtasks.exe", "/End", "/TN", job.Label); err != nil {
				return fmt.Errorf("stop Windows user job %s before replacement: %w", job.Label, err)
			}
		}
	}
	definition, err := os.CreateTemp("", "qurl-user-job-*.xml")
	if err != nil {
		return fmt.Errorf("create temporary Windows user job definition: %w", err)
	}
	definitionPath := definition.Name()
	defer func() { _ = os.Remove(definitionPath) }()
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
	if _, err := m.run("schtasks.exe", "/Create", "/TN", job.Label, "/XML", definitionPath, "/F"); err != nil {
		return fmt.Errorf("install Windows user job %s: %w", job.Label, err)
	}
	return m.start(job.Label)
}

func (m *windowsUserJobManager) start(label string) error {
	if _, err := m.run("schtasks.exe", "/Run", "/TN", label); err != nil {
		return fmt.Errorf("start Windows user job %s: %w", label, err)
	}
	return nil
}

func (m *windowsUserJobManager) Remove(label string) error {
	if !userJobLabelPattern.MatchString(label) {
		return fmt.Errorf("invalid Windows user job label %q", label)
	}
	installed, err := m.installed(label)
	if err != nil {
		return fmt.Errorf("inspect Windows user job %s: %w", label, err)
	}
	if !installed {
		return nil
	}
	running, err := m.running(label)
	if err != nil {
		return fmt.Errorf("inspect Windows user job %s before removal: %w", label, err)
	}
	if running {
		if _, err := m.run("schtasks.exe", "/End", "/TN", label); err != nil {
			return fmt.Errorf("stop Windows user job %s before removal: %w", label, err)
		}
	}
	if _, err := m.run("schtasks.exe", "/Delete", "/TN", label, "/F"); err != nil {
		return fmt.Errorf("remove Windows user job %s: %w", label, err)
	}
	return nil
}

func (m *windowsUserJobManager) Status(label string) (ServiceStatus, error) {
	if !userJobLabelPattern.MatchString(label) {
		return ServiceStatus{}, fmt.Errorf("invalid Windows user job label %q", label)
	}
	installed, err := m.installed(label)
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("inspect Windows user job %s: %w", label, err)
	}
	if !installed {
		return ServiceStatus{}, nil
	}
	running, err := m.running(label)
	if err != nil {
		return ServiceStatus{Installed: true}, err
	}
	return ServiceStatus{Installed: true, Running: running}, nil
}

func (m *windowsUserJobManager) installed(label string) (bool, error) {
	command := "$ErrorActionPreference='Stop'; $tasks = @(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop | " +
		"Where-Object { $_.TaskName -eq '" + label + "' }); if ($tasks.Count -eq 0) { '0' } " +
		"elseif ($tasks.Count -eq 1) { '1' } else { throw 'duplicate task name' }"
	output, err := m.run("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command)
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
	output, err := m.run("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command)
	if err != nil {
		return false, err
	}
	state, err := strconv.Atoi(strings.TrimSpace(output))
	if err != nil {
		return false, fmt.Errorf("parse Windows user job state %q: %w", strings.TrimSpace(output), err)
	}
	return state == 4, nil
}

func (m *windowsUserJobManager) render(job UserJob) (string, string, error) {
	job, err := normalizeUserJob(job)
	if err != nil {
		return "", "", err
	}
	if m == nil || m.currentSID == nil {
		return "", "", errors.New("Windows user job manager is incomplete")
	}
	sid, err := m.currentSID()
	if err != nil {
		return "", "", err
	}
	canonical, err := json.Marshal(job)
	if err != nil {
		return "", "", fmt.Errorf("encode Windows user job definition: %w", err)
	}
	digest := sha256.Sum256(canonical)
	marker := windowsTaskDefinitionPrefix + hex.EncodeToString(digest[:])
	launcher := windowsPowerShellLauncher(job)
	view := windowsRenderedUserJob{
		UserSID: sid, DefinitionMarker: marker, BinaryPath: "powershell.exe",
		CommandLine:      "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand " + launcher,
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

func windowsPowerShellLauncher(job UserJob) string {
	parts := []string{"&", windowsPowerShellLiteral(job.BinaryPath)}
	for _, argument := range job.Arguments {
		parts = append(parts, windowsPowerShellLiteral(argument))
	}
	script := strings.Join(parts, " ") + " 1>> " + windowsPowerShellLiteral(job.StandardOut) +
		" 2>> " + windowsPowerShellLiteral(job.StandardErr) + "; exit $LASTEXITCODE"
	units := utf16.Encode([]rune(script))
	raw := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(raw[index*2:], unit)
	}
	return base64.StdEncoding.EncodeToString(raw)
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

func windowsPowerShellLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func currentWindowsUserSID() (string, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return "", fmt.Errorf("open current Windows user token: %w", err)
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", fmt.Errorf("read current Windows user SID: %w", err)
	}
	return user.User.Sid.String(), nil
}

func windowsJobCommandOutput(name string, args ...string) (string, error) {
	command := exec.Command(name, args...)
	output, err := command.CombinedOutput()
	if err == nil {
		return string(output), nil
	}
	return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
}
