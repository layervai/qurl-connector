//go:build darwin

package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/layervai/qurl-connector/pkg/internal/atomicfile"
)

type launchdUserJobManager struct {
	plistPath      func(string) (string, error)
	launchctlQuery func(...string) (string, error)
	sleep          func(time.Duration)
}

const (
	launchdBootstrapRetryDelay = 250 * time.Millisecond
	// Each cycle can make two bootstrap attempts. The full failure budget is
	// therefore eight attempts and seven waits, or 1.75 seconds of settle time.
	launchdBootstrapMaxCycles = 4
)

// NewUserJobManager returns a per-user launchd manager.
func NewUserJobManager() UserJobManager {
	return &launchdUserJobManager{
		plistPath: currentUserJobPlistPath, launchctlQuery: launchctlOutput, sleep: time.Sleep,
	}
}

func (m *launchdUserJobManager) Ensure(job UserJob) error {
	return m.ensure(job, false)
}

func (m *launchdUserJobManager) Replace(job UserJob) error {
	return m.ensure(job, true)
}

func (m *launchdUserJobManager) ensure(job UserJob, forceReplace bool) error {
	content, err := RenderLaunchdUserJob(job)
	if err != nil {
		return err
	}
	plistPath, err := m.plistPath(job.Label)
	if err != nil {
		return err
	}
	for _, dir := range []string{filepath.Dir(plistPath), filepath.Dir(job.StandardOut), filepath.Dir(job.StandardErr)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create launchd job directory %s: %w", dir, err)
		}
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	service := domain + "/" + job.Label
	existing, readErr := os.ReadFile(plistPath)
	definitionChanged := readErr != nil || !bytes.Equal(existing, []byte(content))
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return fmt.Errorf("read launchd job %s: %w", job.Label, readErr)
	}
	printOutput, printErr := m.launchctlQuery("print", service)
	loaded := printErr == nil
	if printErr != nil && !isLaunchdNotFound(printErr) {
		return fmt.Errorf("inspect launchd job %s: %w", job.Label, printErr)
	}
	if !forceReplace && !definitionChanged && loaded {
		if launchdOutputRunning(printOutput) {
			return nil
		}
		if _, err := m.launchctlQuery("kickstart", "-k", service); err != nil {
			return fmt.Errorf("start launchd job %s: %w", job.Label, err)
		}
		return nil
	}
	// launchd retains a loaded job's ProgramArguments when its plist changes,
	// so a changed definition must be booted out before the replacement plist
	// is written. Keeping the old plist intact when bootout fails ensures the
	// next Ensure cannot mistake an incompatible loaded process for a matching
	// definition.
	if loaded {
		if _, err := m.launchctlQuery("bootout", service); err != nil && !isLaunchdNotFound(err) {
			return fmt.Errorf("reload launchd job %s: %w", job.Label, err)
		}
	}
	if definitionChanged {
		if err := atomicfile.Write(plistPath, []byte(content), 0o600); err != nil {
			return fmt.Errorf("write launchd job %s: %w", job.Label, err)
		}
	}
	err = m.bootstrapWithLaunchdSettleRecovery(domain, service, plistPath, definitionChanged)
	if err != nil {
		return fmt.Errorf("bootstrap launchd job %s: %w", job.Label, err)
	}
	if _, err := m.launchctlQuery("kickstart", "-k", service); err != nil {
		return fmt.Errorf("start launchd job %s: %w", job.Label, err)
	}
	return nil
}

// bootstrapWithLaunchdSettleRecovery converges launchd label reuse within one
// bounded call. A failed bootstrap can leave the service absent while launchd
// still holds the old label, or it can leave a service loaded whose exact
// arguments are not proven. Unload only the ambiguous service, let launchd
// settle, and retry without ever accepting an uncertain process. The fixed
// cycle budget covers rapid Remove-then-Ensure and definition replacement
// without turning a persistent launchd failure into an unbounded wait.
// launchctl does not expose stable machine-readable error categories, so state
// checks, not localized error text, decide whether an unload is required.
func (m *launchdUserJobManager) bootstrapWithLaunchdSettleRecovery(
	domain, service, plistPath string,
	definitionChanged bool,
) error {
	var lastErr error
	for cycle := 0; cycle < launchdBootstrapMaxCycles; cycle++ {
		possiblyLoaded, err := m.bootstrapWithSettleRetry(domain, service, plistPath)
		if err == nil {
			return nil
		}
		lastErr = err
		if possiblyLoaded {
			what := "ambiguous"
			if cycle > 0 {
				what = "retry-ambiguous"
			}
			if unloadErr := m.unloadAmbiguous(service, plistPath, what, definitionChanged); unloadErr != nil {
				return errors.Join(
					fmt.Errorf("launchd bootstrap failed during settle cycle %d: %w", cycle+1, err),
					unloadErr,
				)
			}
		}
		if cycle+1 < launchdBootstrapMaxCycles {
			m.settle()
		}
	}
	return fmt.Errorf("launchd bootstrap did not settle after %d cycles: %w", launchdBootstrapMaxCycles, lastErr)
}

func (m *launchdUserJobManager) settle() {
	sleep := m.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	sleep(launchdBootstrapRetryDelay)
}

// unloadAmbiguous boots out a job whose loaded definition cannot be proven.
// If launchd cannot confirm the unload, remove a changed plist so a later
// Ensure cannot mistake the stale process for the replacement definition.
func (m *launchdUserJobManager) unloadAmbiguous(service, plistPath, what string, definitionChanged bool) error {
	_, err := m.launchctlQuery("bootout", service)
	if err == nil || isLaunchdNotFound(err) {
		return nil
	}
	joined := fmt.Errorf("unload %s launchd job: %w", what, err)
	if definitionChanged {
		if removeErr := os.Remove(plistPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			joined = errors.Join(joined, fmt.Errorf("remove unconverged launchd job definition: %w", removeErr))
		}
	}
	return joined
}

// bootstrapWithSettleRetry retries once only when launchd confirms the service
// is absent. macOS can briefly return EIO after a successful bootout while it
// finishes removing the prior job. The read between attempts also tells the
// caller when a loaded or unreadable service state makes the result ambiguous.
func (m *launchdUserJobManager) bootstrapWithSettleRetry(domain, service, plistPath string) (bool, error) {
	_, firstErr := m.launchctlQuery("bootstrap", domain, plistPath)
	if firstErr == nil {
		return false, nil
	}
	m.settle()
	if _, statusErr := m.launchctlQuery("print", service); statusErr == nil {
		return true, firstErr
	} else if !isLaunchdNotFound(statusErr) {
		// An unreadable service state is ambiguous, not absent. Tell the caller
		// to remove a changed plist so a later Ensure cannot confuse an old
		// loaded job with the replacement definition.
		return true, errors.Join(firstErr, fmt.Errorf("inspect launchd job after bootstrap failure: %w", statusErr))
	}
	if _, retryErr := m.launchctlQuery("bootstrap", domain, plistPath); retryErr != nil {
		// bootstrap can return an error after launchd has accepted the job. Check
		// the retry result exactly as we check the first attempt so the caller can
		// unload an ambiguous replacement instead of reporting false convergence.
		if _, statusErr := m.launchctlQuery("print", service); statusErr == nil {
			return true, errors.Join(firstErr, retryErr)
		} else if !isLaunchdNotFound(statusErr) {
			return true, errors.Join(
				firstErr, retryErr,
				fmt.Errorf("inspect launchd job after bootstrap retry failure: %w", statusErr),
			)
		}
		return false, errors.Join(firstErr, retryErr)
	}
	return false, nil
}

func (m *launchdUserJobManager) Remove(label string) error {
	plistPath, err := m.plistPath(label)
	if err != nil {
		return err
	}
	domain := "gui/" + strconv.Itoa(os.Getuid())
	service := domain + "/" + label
	if _, err := m.launchctlQuery("bootout", service); err != nil && !isLaunchdNotFound(err) {
		return fmt.Errorf("stop launchd job %s: %w", label, err)
	}
	if err := os.Remove(plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove launchd job %s: %w", label, err)
	}
	return nil
}

func (m *launchdUserJobManager) Status(label string) (ServiceStatus, error) {
	plistPath, err := m.plistPath(label)
	if err != nil {
		return ServiceStatus{}, err
	}
	status := ServiceStatus{}
	if _, err := os.Stat(plistPath); err == nil {
		status.Installed = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return status, fmt.Errorf("inspect launchd job %s: %w", label, err)
	}
	service := "gui/" + strconv.Itoa(os.Getuid()) + "/" + label
	if output, err := m.launchctlQuery("print", service); err == nil {
		status.Running = launchdOutputRunning(output)
	} else if !isLaunchdNotFound(err) {
		return status, fmt.Errorf("inspect launchd job %s: %w", label, err)
	}
	return status, nil
}

type launchctlError struct {
	args   []string
	output string
	err    error
}

func (e *launchctlError) Error() string {
	return fmt.Sprintf("launchctl %s: %v: %s", strings.Join(e.args, " "), e.err, e.output)
}

func (e *launchctlError) Unwrap() error { return e.err }

func runLaunchctl(args ...string) error {
	_, err := launchctlOutput(args...)
	return err
}

func launchctlOutput(args ...string) (string, error) {
	cmd := exec.Command("launchctl", args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), nil
	}
	return "", &launchctlError{args: append([]string(nil), args...), output: strings.TrimSpace(string(output)), err: err}
}

func launchdOutputRunning(output string) bool {
	stateRunning := false
	pidPresent := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "state = running":
			stateRunning = true
		case strings.HasPrefix(line, "pid = "):
			pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "pid = ")))
			pidPresent = err == nil && pid > 0
		}
	}
	return stateRunning && pidPresent
}

func isLaunchdNotFound(err error) bool {
	var launchErr *launchctlError
	if !errors.As(err, &launchErr) {
		return false
	}
	output := bytes.ToLower([]byte(launchErr.output))
	return bytes.Contains(output, []byte("could not find service")) ||
		bytes.Contains(output, []byte("no such process")) ||
		bytes.Contains(output, []byte("service not found"))
}
