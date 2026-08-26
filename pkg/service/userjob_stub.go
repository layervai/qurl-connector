//go:build !darwin

package service

import "fmt"

type unsupportedUserJobManager struct{}

// NewUserJobManager returns a manager whose operations clearly report that
// per-user LaunchAgents are available only on macOS.
func NewUserJobManager() UserJobManager { return &unsupportedUserJobManager{} }

func (m *unsupportedUserJobManager) Ensure(UserJob) error {
	return fmt.Errorf("per-user launchd jobs are not supported on this platform")
}

func (m *unsupportedUserJobManager) Replace(UserJob) error {
	return fmt.Errorf("per-user launchd jobs are not supported on this platform")
}

func (m *unsupportedUserJobManager) Remove(string) error {
	return fmt.Errorf("per-user launchd jobs are not supported on this platform")
}

func (m *unsupportedUserJobManager) Status(string) (ServiceStatus, error) {
	return ServiceStatus{}, fmt.Errorf("per-user launchd jobs are not supported on this platform")
}
