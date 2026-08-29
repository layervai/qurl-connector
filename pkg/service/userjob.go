package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

// UserJob is a credential-free per-user background process. It is used by
// applications that embed the Connector runtime and need the native user job
// manager to keep that process alive without installing a second executable or
// requiring root.
//
// Environment variables are deliberately not part of this contract. A plist
// is durable, inspectable state and must never become a bearer-token store.
// Windows Task Scheduler starts BinaryPath directly so stopping the task also
// stops the real application process. The manager creates StandardOut and
// StandardErr with protected ACLs; a Windows application must open those paths
// itself when it needs file logging because Task Scheduler has no native
// stdout/stderr redirection fields. Each Windows log parent must be a dedicated
// directory below an existing safe parent. The manager creates and protects a
// missing log directory, but it only validates an existing directory and never
// rewrites that caller-owned directory's owner or ACL.
type UserJob struct {
	Label       string
	BinaryPath  string
	Arguments   []string
	StandardOut string
	StandardErr string
	// ExitTimeout and Umask are launchd controls. Windows Task Scheduler
	// terminates the direct child process and relies on protected NTFS ACLs.
	ExitTimeout int
	Umask       int
	RunAtLoad   bool
	// KeepAlive maps to launchd KeepAlive on macOS and restart-on-failure on
	// Windows. Task Scheduler does not restart a process after a successful exit.
	KeepAlive bool
}

// UserJobManager manages a native per-user background job. Ensure atomically
// installs the definition, leaves an already-running matching job untouched,
// and reloads the process only when its definition changed.
type UserJobManager interface {
	Ensure(UserJob) error
	// Replace reloads the process even when the persisted definition already
	// matches. Callers use it after an IPC version handshake proves the loaded
	// process is incompatible with that definition.
	Replace(UserJob) error
	Remove(label string) error
	Status(label string) (ServiceStatus, error)
}

// ServiceStatus distinguishes a persisted job definition from a running
// process.
type ServiceStatus struct {
	Installed bool
	Running   bool
}

var userJobLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)

const launchdUserJobTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{{xml .Label}}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{xml .BinaryPath}}</string>
        {{- range .Arguments}}
        <string>{{xml .}}</string>
        {{- end}}
    </array>
    <key>RunAtLoad</key>
    <{{if .RunAtLoad}}true{{else}}false{{end}}/>
    <key>KeepAlive</key>
    <{{if .KeepAlive}}true{{else}}false{{end}}/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>ExitTimeOut</key>
    <integer>{{.ExitTimeout}}</integer>
    <key>Umask</key>
    <integer>{{.Umask}}</integer>
    <key>StandardOutPath</key>
    <string>{{xml .StandardOut}}</string>
    <key>StandardErrorPath</key>
    <string>{{xml .StandardErr}}</string>
</dict>
</plist>
`

// RenderLaunchdUserJob validates and renders a launchd plist. The template
// escapes every interpolated value so paths and arguments containing XML
// metacharacters cannot produce a malformed or structurally altered plist.
func RenderLaunchdUserJob(job UserJob) (string, error) {
	job, err := normalizeUserJob(job)
	if err != nil {
		return "", err
	}
	tmpl, err := template.New("launchd-user-job").Funcs(template.FuncMap{"xml": xmlText}).Parse(launchdUserJobTemplate)
	if err != nil {
		return "", fmt.Errorf("parse launchd user-job template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, job); err != nil {
		return "", fmt.Errorf("render launchd user job: %w", err)
	}
	return buf.String(), nil
}

func xmlText(value string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(value))
	return buf.String()
}

func normalizeUserJob(job UserJob) (UserJob, error) {
	job.Label = strings.TrimSpace(job.Label)
	if !userJobLabelPattern.MatchString(job.Label) {
		return UserJob{}, fmt.Errorf("invalid user job label %q", job.Label)
	}
	for name, value := range map[string]string{
		"binary path": job.BinaryPath,
		"stdout path": job.StandardOut,
		"stderr path": job.StandardErr,
	} {
		if !filepath.IsAbs(value) {
			return UserJob{}, fmt.Errorf("user job %s must be absolute", name)
		}
		if strings.ContainsRune(value, 0) {
			return UserJob{}, fmt.Errorf("user job %s contains NUL", name)
		}
	}
	for _, arg := range job.Arguments {
		if strings.ContainsRune(arg, 0) {
			return UserJob{}, errors.New("user job argument contains NUL")
		}
	}
	if job.ExitTimeout == 0 {
		job.ExitTimeout = 15
	}
	if job.ExitTimeout < 1 || job.ExitTimeout > 300 {
		return UserJob{}, fmt.Errorf("user job exit timeout %d is outside 1..300 seconds", job.ExitTimeout)
	}
	if job.Umask == 0 {
		job.Umask = 0o077
	}
	if job.Umask < 0 || job.Umask > 0o777 {
		return UserJob{}, fmt.Errorf("user job umask %#o is outside 0000..0777", job.Umask)
	}
	return job, nil
}

// UserJobPlistPath returns the conventional per-user LaunchAgent path for a
// validated job label.
func UserJobPlistPath(home, label string) (string, error) {
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return "", errors.New("user home must be an absolute path")
	}
	if !userJobLabelPattern.MatchString(label) {
		return "", fmt.Errorf("invalid launchd job label %q", label)
	}
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), nil
}

func currentUserJobPlistPath(label string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("get user home: %w", err)
	}
	return UserJobPlistPath(home, label)
}
