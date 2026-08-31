//go:build linux

package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
	"github.com/layervai/qurl-connector/pkg/internal/atomicfile"
)

const maxLinuxUserJobDefinitionBytes = 64 << 10

const systemdUserJobTemplate = `[Unit]
Description=qURL background daemon - managed by qurl, do not edit

[Service]
Type=exec
ExecStart={{systemdExecutable .BinaryPath}}{{range .Arguments}} {{systemdExec .}}{{end}}
Restart={{if .KeepAlive}}on-failure{{else}}no{{end}}
RestartSec=1s
TimeoutStopSec={{.ExitTimeout}}s
KillMode=control-group
UMask={{printf "%04o" .Umask}}
StandardInput=null
StandardOutput=append:{{.StandardOut}}
StandardError=append:{{.StandardErr}}
NoNewPrivileges=true
RestrictSUIDSGID=true

[Install]
WantedBy=default.target
`

type linuxUserJobManager struct {
	unitPath func(string) (string, error)
	run      func(...string) (string, error)
}

type linuxUnitState struct {
	loaded           bool
	running          bool
	invalid          bool
	masked           bool
	unitFileState    string
	fragmentPath     string
	needDaemonReload bool
}

func (s linuxUnitState) runAtLoadMatches(runAtLoad bool) bool {
	if runAtLoad {
		return s.unitFileState == "enabled"
	}
	return s.unitFileState == "disabled"
}

// NewUserJobManager returns a per-user systemd manager. Linux hosts without a
// real systemd user manager fail clearly; the manager never substitutes an
// untracked child process that cannot honor login-time persistence or fencing.
func NewUserJobManager() UserJobManager {
	return &linuxUserJobManager{unitPath: currentSystemdUserJobPath, run: systemctlUserOutput}
}

// RenderSystemdUserJob validates and renders one credential-free systemd user
// service. Every command word is quoted without a shell, and systemd's `$` and
// `%` expansion markers are escaped before the definition becomes durable.
func RenderSystemdUserJob(job UserJob) (string, error) {
	job, err := normalizeUserJob(job)
	if err != nil {
		return "", err
	}
	stdout, err := systemdOutputPath(job.StandardOut)
	if err != nil {
		return "", fmt.Errorf("render systemd stdout path: %w", err)
	}
	stderr, err := systemdOutputPath(job.StandardErr)
	if err != nil {
		return "", fmt.Errorf("render systemd stderr path: %w", err)
	}
	values := struct {
		UserJob
		StandardOut string
		StandardErr string
	}{UserJob: job, StandardOut: stdout, StandardErr: stderr}
	tmpl, err := template.New("systemd-user-job").Funcs(template.FuncMap{
		"systemdExecutable": systemdExecutableWord,
		"systemdExec":       systemdExecWord,
	}).Parse(systemdUserJobTemplate)
	if err != nil {
		return "", fmt.Errorf("parse systemd user-job template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, values); err != nil {
		return "", fmt.Errorf("render systemd user job: %w", err)
	}
	if buf.Len() > maxLinuxUserJobDefinitionBytes {
		return "", errors.New("systemd user job definition is too large")
	}
	return buf.String(), nil
}

func systemdExecutableWord(value string) (string, error) {
	// systemd rejects special syntax in argv[0] even when it is escaped. Reject
	// it before any unit file or manager state changes instead of
	// persisting a definition that systemd cannot load.
	if strings.ContainsAny(value, "$%\"") {
		return "", errors.New("systemd executable path contains unsupported special character")
	}
	return systemdUnitWord(value)
}

func systemdOutputPath(path string) (string, error) {
	for _, r := range path {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("/._-+@:", r) {
			continue
		}
		return "", fmt.Errorf("systemd output path contains unsupported character %#U", r)
	}
	return path, nil
}

func systemdExecWord(value string) (string, error) {
	value = strings.ReplaceAll(value, "$", "$$")
	return systemdUnitWord(value)
}

func systemdUnitWord(value string) (string, error) {
	if !utf8.ValidString(value) {
		return "", errors.New("value is not valid UTF-8")
	}
	var result strings.Builder
	result.Grow(len(value) + 2)
	result.WriteByte('"')
	for _, r := range value {
		switch {
		case r == '\\':
			result.WriteString(`\\`)
		case r == '"':
			result.WriteString(`\"`)
		case r == '%':
			result.WriteString("%%")
		case r < 0x20 || r == 0x7f:
			return "", fmt.Errorf("value contains control character %#U", r)
		default:
			result.WriteRune(r)
		}
	}
	result.WriteByte('"')
	return result.String(), nil
}

func currentSystemdUserJobPath(label string) (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("get user config directory: %w", err)
	}
	return SystemdUserJobPath(configDir, label)
}

// SystemdUserJobPath returns the conventional systemd user-unit path for a
// validated job label.
func SystemdUserJobPath(configDir, label string) (string, error) {
	configDir = strings.TrimSpace(configDir)
	if configDir == "" || !filepath.IsAbs(configDir) {
		return "", errors.New("user config directory must be an absolute path")
	}
	if _, err := systemdUnitWord(configDir); err != nil {
		return "", fmt.Errorf("invalid user config directory: %w", err)
	}
	if !userJobLabelPattern.MatchString(label) {
		return "", fmt.Errorf("invalid systemd job label %q", label)
	}
	return filepath.Join(configDir, "systemd", "user", label+".service"), nil
}

func (m *linuxUserJobManager) Ensure(job UserJob) error {
	return m.ensure(job, false)
}

func (m *linuxUserJobManager) Replace(job UserJob) error {
	return m.ensure(job, true)
}

func (m *linuxUserJobManager) ensure(job UserJob, forceReplace bool) error {
	job, err := normalizeUserJob(job)
	if err != nil {
		return err
	}
	content, err := RenderSystemdUserJob(job)
	if err != nil {
		return err
	}
	unitPath, err := m.unitPath(job.Label)
	if err != nil {
		return err
	}
	if err := validateLinuxUserJobExecutable(job.BinaryPath); err != nil {
		return fmt.Errorf("validate Linux user job executable %s: %w", job.BinaryPath, err)
	}
	if err := ensureLinuxUserJobLogs(job.StandardOut, job.StandardErr); err != nil {
		return err
	}
	if err := ensureTrustedSystemdUnitDirectory(filepath.Dir(unitPath)); err != nil {
		return err
	}
	existing, installed, err := readLinuxUserJobDefinition(unitPath)
	if err != nil {
		return fmt.Errorf("read systemd user job %s: %w", job.Label, err)
	}
	state, err := m.state(job.Label, unitPath)
	if err != nil {
		return err
	}
	definitionChanged := !installed || !bytes.Equal(existing, []byte(content))
	loadedDefinitionMatches := state.loaded && !state.needDaemonReload && filepath.Clean(state.fragmentPath) == filepath.Clean(unitPath)
	if !forceReplace && !definitionChanged && loadedDefinitionMatches && state.runAtLoadMatches(job.RunAtLoad) {
		if state.running {
			return nil
		}
		return m.start(job.Label, unitPath, job.RunAtLoad)
	}
	if !forceReplace && !definitionChanged && loadedDefinitionMatches {
		if err := m.setRunAtLoad(job.Label, job.RunAtLoad); err != nil {
			return err
		}
		if state.running {
			return m.validateRunning(job.Label, unitPath, job.RunAtLoad)
		}
		return m.start(job.Label, unitPath, job.RunAtLoad)
	}

	// Stop the loaded process before changing its definition. If stop fails,
	// leave the old file intact so a retry cannot confuse an old process with a
	// newly persisted command.
	if state.loaded {
		if _, err := m.run("stop", systemdUserUnitName(job.Label)); err != nil {
			return fmt.Errorf("stop systemd user job %s before replacement: %w", job.Label, err)
		}
	}
	if definitionChanged {
		if err := atomicfile.Write(unitPath, []byte(content), 0o600); err != nil {
			return fmt.Errorf("write systemd user job %s: %w", job.Label, err)
		}
		if err := syncTrustedSystemdUnitDirectory(filepath.Dir(unitPath)); err != nil {
			return fmt.Errorf("make systemd user job %s durable: %w", job.Label, err)
		}
	}
	if _, err := m.run("daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd user manager after writing %s: %w", job.Label, err)
	}
	if err := m.setRunAtLoad(job.Label, job.RunAtLoad); err != nil {
		return err
	}
	return m.start(job.Label, unitPath, job.RunAtLoad)
}

func (m *linuxUserJobManager) setRunAtLoad(label string, runAtLoad bool) error {
	verb := "disable"
	if runAtLoad {
		verb = "enable"
	}
	if _, err := m.run(verb, systemdUserUnitName(label)); err != nil {
		return fmt.Errorf("%s systemd user job %s: %w", verb, label, err)
	}
	return nil
}

func (m *linuxUserJobManager) start(label, unitPath string, runAtLoad bool) error {
	if _, err := m.run("reset-failed", systemdUserUnitName(label)); err != nil {
		return fmt.Errorf("reset failed-start limit for systemd user job %s: %w", label, err)
	}
	if _, err := m.run("start", systemdUserUnitName(label)); err != nil {
		return fmt.Errorf("start systemd user job %s: %w", label, err)
	}
	return m.validateRunning(label, unitPath, runAtLoad)
}

func (m *linuxUserJobManager) validateRunning(label, unitPath string, runAtLoad bool) error {
	state, err := m.state(label, unitPath)
	if err != nil {
		return err
	}
	if !state.loaded || !state.running || !state.runAtLoadMatches(runAtLoad) || state.needDaemonReload ||
		filepath.Clean(state.fragmentPath) != filepath.Clean(unitPath) {
		return fmt.Errorf("systemd user job %s did not reach the exact running definition", label)
	}
	return nil
}

func (m *linuxUserJobManager) Remove(label string) error {
	unitPath, err := m.unitPath(label)
	if err != nil {
		return err
	}
	if err := validateRemovableLinuxUserJobDefinition(unitPath); err != nil {
		return fmt.Errorf("validate systemd user job %s before removal: %w", label, err)
	}
	state, err := m.removalState(label, unitPath)
	if err != nil {
		return err
	}
	unit := systemdUserUnitName(label)
	if state.running {
		if _, err := m.run("stop", unit); err != nil {
			return fmt.Errorf("stop systemd user job %s: %w", label, err)
		}
	}
	if state.masked {
		if _, err := m.run("unmask", unit); err != nil {
			return fmt.Errorf("unmask systemd user job %s before removal: %w", label, err)
		}
		if err := syncTrustedSystemdUnitDirectory(filepath.Dir(unitPath)); err != nil {
			return fmt.Errorf("make unmasked systemd user job %s durable: %w", label, err)
		}
	}
	if state.loaded || state.invalid || state.masked || state.unitFileState != "" {
		if _, err := m.run("disable", unit); err != nil {
			return fmt.Errorf("disable systemd user job %s: %w", label, err)
		}
	}
	if err := removeLinuxUserJobDefinition(unitPath); err != nil {
		return fmt.Errorf("remove systemd user job %s: %w", label, err)
	}
	if state.loaded || state.invalid || state.masked || state.unitFileState != "" {
		if _, err := m.run("daemon-reload"); err != nil {
			return fmt.Errorf("reload systemd user manager after removing %s: %w", label, err)
		}
	}
	return nil
}

func (m *linuxUserJobManager) Status(label string) (ServiceStatus, error) {
	unitPath, err := m.unitPath(label)
	if err != nil {
		return ServiceStatus{}, err
	}
	_, installed, err := readLinuxUserJobDefinition(unitPath)
	if err != nil {
		return ServiceStatus{}, fmt.Errorf("inspect systemd user job %s: %w", label, err)
	}
	state, err := m.state(label, unitPath)
	if err != nil {
		return ServiceStatus{Installed: installed}, err
	}
	if state.loaded && filepath.Clean(state.fragmentPath) != filepath.Clean(unitPath) {
		return ServiceStatus{Installed: installed}, fmt.Errorf(
			"systemd user job %s is loaded from unexpected path %s", label, state.fragmentPath,
		)
	}
	if state.invalid {
		return ServiceStatus{Installed: installed}, fmt.Errorf("systemd user job %s has invalid settings", label)
	}
	return ServiceStatus{Installed: installed, Running: state.running}, nil
}

func (m *linuxUserJobManager) state(label, unitPath string) (linuxUnitState, error) {
	return m.inspectState(label, unitPath, false)
}

func (m *linuxUserJobManager) removalState(label, unitPath string) (linuxUnitState, error) {
	return m.inspectState(label, unitPath, true)
}

func (m *linuxUserJobManager) inspectState(label, unitPath string, allowMasked bool) (linuxUnitState, error) {
	unit := systemdUserUnitName(label)
	output, err := m.run(
		"show", unit, "--no-pager",
		"--property=LoadState", "--property=ActiveState", "--property=SubState",
		"--property=UnitFileState", "--property=FragmentPath", "--property=NeedDaemonReload",
	)
	if err != nil {
		return linuxUnitState{}, fmt.Errorf("inspect systemd user job %s: %w", label, err)
	}
	properties := make(map[string]string, 6)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			return linuxUnitState{}, fmt.Errorf("parse systemd user job %s state", label)
		}
		if _, duplicate := properties[key]; duplicate {
			return linuxUnitState{}, fmt.Errorf("parse duplicate systemd user job %s property %s", label, key)
		}
		properties[key] = value
	}
	for _, key := range []string{"LoadState", "ActiveState", "SubState", "UnitFileState", "FragmentPath", "NeedDaemonReload"} {
		if _, present := properties[key]; !present {
			return linuxUnitState{}, fmt.Errorf("systemd user job %s state omitted %s", label, key)
		}
	}
	if properties["NeedDaemonReload"] != "yes" && properties["NeedDaemonReload"] != "no" {
		return linuxUnitState{}, fmt.Errorf("systemd user job %s returned invalid daemon-reload state", label)
	}
	state := linuxUnitState{
		loaded:           properties["LoadState"] == "loaded",
		running:          properties["ActiveState"] == "active" && properties["SubState"] == "running",
		invalid:          properties["LoadState"] == "bad-setting",
		masked:           properties["LoadState"] == "masked" || strings.HasPrefix(properties["UnitFileState"], "masked"),
		unitFileState:    properties["UnitFileState"],
		fragmentPath:     properties["FragmentPath"],
		needDaemonReload: properties["NeedDaemonReload"] == "yes",
	}
	if !state.loaded && !state.invalid && properties["LoadState"] != "not-found" && !(allowMasked && state.masked) {
		return linuxUnitState{}, fmt.Errorf("systemd user job %s has unsupported load state %q", label, properties["LoadState"])
	}
	if state.running && !state.loaded && !(allowMasked && state.masked) {
		return linuxUnitState{}, fmt.Errorf("systemd user job %s is running without a loaded definition", label)
	}
	if state.loaded && state.fragmentPath == "" {
		return linuxUnitState{}, fmt.Errorf("systemd user job %s has no fragment path", label)
	}
	return state, nil
}

func systemdUserUnitName(label string) string { return label + ".service" }

func ensureTrustedSystemdUnitDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create systemd user unit directory %s: %w", path, err)
	}
	dir, err := pinnedfs.OpenTrusted(path)
	if err != nil {
		return fmt.Errorf("validate systemd user unit directory %s: %w", path, err)
	}
	return dir.Close()
}

func syncTrustedSystemdUnitDirectory(path string) error {
	dir, err := pinnedfs.OpenTrusted(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

func readLinuxUserJobDefinition(path string) ([]byte, bool, error) {
	dir, err := pinnedfs.OpenTrusted(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = dir.Close() }()
	file, err := dir.OpenFile(filepath.Base(path), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()
	if _, err := pinnedfs.ValidateRegularFile(dir, filepath.Base(path), file, "systemd user job definition", 0o600); err != nil {
		return nil, false, err
	}
	content, err := io.ReadAll(io.LimitReader(file, maxLinuxUserJobDefinitionBytes+1))
	if err != nil {
		return nil, false, err
	}
	if len(content) > maxLinuxUserJobDefinitionBytes {
		return nil, false, errors.New("systemd user job definition is too large")
	}
	return content, true, nil
}

func removeLinuxUserJobDefinition(path string) (retErr error) {
	dir, err := pinnedfs.OpenTrusted(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, dir.Close()) }()
	name := filepath.Base(path)
	file, err := dir.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := pinnedfs.ValidateOwnerRegularFile(dir, name, file, "systemd user job definition"); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := dir.Remove(name); err != nil {
		return err
	}
	return dir.Sync()
}

func validateRemovableLinuxUserJobDefinition(path string) (retErr error) {
	dir, err := pinnedfs.OpenTrusted(filepath.Dir(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, dir.Close()) }()
	name := filepath.Base(path)
	entry, err := dir.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if entry.Mode()&os.ModeSymlink != 0 {
		return validateSystemdMaskSymlink(dir, name, entry)
	}
	file, err := dir.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	_, validateErr := pinnedfs.ValidateOwnerRegularFile(dir, name, file, "systemd user job definition")
	return errors.Join(validateErr, file.Close())
}

func validateSystemdMaskSymlink(dir *pinnedfs.Directory, name string, entry os.FileInfo) error {
	const maskTarget = "/dev/null"
	if err := pinnedfs.RequireCurrentOwnerInfo(entry, "systemd user job mask"); err != nil {
		return err
	}
	if err := pinnedfs.RequireSingleLinkInfo(entry, "systemd user job mask"); err != nil {
		return err
	}
	target, err := dir.Readlink(name)
	if err != nil {
		return err
	}
	if target != maskTarget {
		return fmt.Errorf("systemd user job definition symlink targets %q, want exact systemd mask %q", target, maskTarget)
	}
	latest, err := dir.Lstat(name)
	if err != nil {
		return err
	}
	if latest.Mode()&os.ModeSymlink == 0 || !os.SameFile(entry, latest) {
		return errors.New("systemd user job mask changed during validation")
	}
	if err := pinnedfs.RequireCurrentOwnerInfo(latest, "systemd user job mask"); err != nil {
		return err
	}
	if err := pinnedfs.RequireSingleLinkInfo(latest, "systemd user job mask"); err != nil {
		return err
	}
	return dir.ValidateCurrent()
}

func ensureLinuxUserJobLogs(paths ...string) error {
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		dirPath := filepath.Dir(path)
		if _, ok := seen[dirPath]; !ok {
			dir, err := pinnedfs.EnsurePrivate(dirPath, 0o700)
			if err != nil {
				return fmt.Errorf("create Linux user job log directory %s: %w", dirPath, err)
			}
			if err := dir.Close(); err != nil {
				return err
			}
			seen[dirPath] = struct{}{}
		}
		dir, err := pinnedfs.OpenPrivate(dirPath, 0o700)
		if err != nil {
			return err
		}
		file, openErr := dir.OpenFile(filepath.Base(path), os.O_CREATE|os.O_APPEND|os.O_WRONLY|unix.O_NOFOLLOW, 0o600)
		if openErr != nil {
			_ = dir.Close()
			return fmt.Errorf("create Linux user job log %s: %w", path, openErr)
		}
		_, validateErr := pinnedfs.ValidateRegularFile(dir, filepath.Base(path), file, "Linux user job log", 0o600)
		closeErr := errors.Join(file.Close(), dir.Close())
		if err := errors.Join(validateErr, closeErr); err != nil {
			return fmt.Errorf("validate Linux user job log %s: %w", path, err)
		}
	}
	return nil
}

func validateLinuxUserJobExecutable(path string) error {
	entryDir, err := pinnedfs.OpenTrusted(filepath.Dir(path))
	if err != nil {
		return err
	}
	entry, entryErr := entryDir.Lstat(filepath.Base(path))
	closeErr := entryDir.Close()
	if err := errors.Join(entryErr, closeErr); err != nil {
		return err
	}
	if !entry.Mode().IsRegular() && entry.Mode()&os.ModeSymlink == 0 {
		return errors.New("Linux user job executable must be a regular file or a trusted stable symlink")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	resolvedDir, err := pinnedfs.OpenTrusted(filepath.Dir(resolved))
	if err != nil {
		return err
	}
	defer func() { _ = resolvedDir.Close() }()
	file, err := resolvedDir.OpenFile(filepath.Base(resolved), os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	info, err := pinnedfs.ValidateTrustedReadOnlyFile(resolvedDir, filepath.Base(resolved), file, "Linux user job executable")
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o111 == 0 {
		return errors.New("Linux user job executable is not executable")
	}
	return nil
}

type systemctlUserError struct {
	args   []string
	output string
	err    error
}

func (e *systemctlUserError) Error() string {
	return fmt.Sprintf("systemctl --user %s: %v: %s", strings.Join(e.args, " "), e.err, e.output)
}

func (e *systemctlUserError) Unwrap() error { return e.err }

func systemctlUserOutput(args ...string) (string, error) {
	cmdArgs := append([]string{"--user"}, args...)
	cmd := exec.Command("systemctl", cmdArgs...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), nil
	}
	return "", &systemctlUserError{
		args: append([]string(nil), args...), output: strings.TrimSpace(string(output)), err: err,
	}
}
