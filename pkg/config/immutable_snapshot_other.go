//go:build !darwin && !linux

package config

import (
	"fmt"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

// ImmutableConfigSnapshot is unavailable where the process cannot prove the
// required no-follow, ownership, and descriptor-entry contracts.
type ImmutableConfigSnapshot struct{}

func OpenImmutableConfigSnapshot(string) (*Config, *ImmutableConfigSnapshot, error) {
	return nil, nil, fmt.Errorf("open immutable config snapshot: %w", pinnedfs.ErrUnsupported)
}

func (*ImmutableConfigSnapshot) Path() string                      { return "" }
func (*ImmutableConfigSnapshot) ValidateCurrent() error            { return pinnedfs.ErrUnsupported }
func (*ImmutableConfigSnapshot) RequireSiblingAbsent(string) error { return pinnedfs.ErrUnsupported }
func (*ImmutableConfigSnapshot) Close() error                      { return nil }
