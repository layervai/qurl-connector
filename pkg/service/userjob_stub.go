//go:build !darwin && !linux && !windows

package service

import "fmt"

type unsupportedUserJobManager struct{}

// NewUserJobManager returns a manager whose operations clearly report that no
// reviewed native per-user job manager is available on this platform.
func NewUserJobManager() UserJobManager { return &unsupportedUserJobManager{} }

func (m *unsupportedUserJobManager) Ensure(UserJob) error {
	return fmt.Errorf("per-user background jobs are not supported on this platform")
}

func (m *unsupportedUserJobManager) Replace(UserJob) error {
	return fmt.Errorf("per-user background jobs are not supported on this platform")
}

func (m *unsupportedUserJobManager) Remove(string) error {
	return fmt.Errorf("per-user background jobs are not supported on this platform")
}

func (m *unsupportedUserJobManager) Status(string) (ServiceStatus, error) {
	return ServiceStatus{}, fmt.Errorf("per-user background jobs are not supported on this platform")
}
