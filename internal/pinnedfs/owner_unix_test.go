//go:build unix

package pinnedfs

import (
	"os"
	"syscall"
	"testing"
	"time"
)

type foreignOwnerFileInfo struct {
	stat syscall.Stat_t
}

func (f foreignOwnerFileInfo) Name() string       { return "foreign" }
func (f foreignOwnerFileInfo) Size() int64        { return 0 }
func (f foreignOwnerFileInfo) Mode() os.FileMode  { return os.ModeDir | 0o755 }
func (f foreignOwnerFileInfo) ModTime() time.Time { return time.Time{} }
func (f foreignOwnerFileInfo) IsDir() bool        { return true }
func (f foreignOwnerFileInfo) Sys() any           { return &f.stat }

func TestValidateCurrentOwnerRejectsForeignUID(t *testing.T) {
	foreignUID := uint32(os.Geteuid() + 1)
	info := foreignOwnerFileInfo{stat: syscall.Stat_t{Uid: foreignUID}}
	if err := validateCurrentOwner(info, "foreign namespace"); err == nil {
		t.Fatal("validateCurrentOwner accepted a foreign-owned namespace")
	}
}

func TestTrustedReadOnlyValidationRejectsForeignOwner(t *testing.T) {
	foreignUID := uint32(os.Geteuid() + 1)
	info := foreignOwnerFileInfo{stat: syscall.Stat_t{Uid: foreignUID}}
	if err := validateTrustedDirectory(info, "foreign namespace", true); err == nil {
		t.Fatal("validateTrustedDirectory accepted a foreign-owned namespace")
	}
	if err := validateTrustedReadOnlyInfo(info, "foreign config"); err == nil {
		t.Fatal("validateTrustedReadOnlyInfo accepted a foreign-owned config")
	}
}
