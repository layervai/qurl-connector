//go:build windows

package pinnedfs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsFileCreated         = uintptr(2)
	windowsFileAllAccess       = windows.ACCESS_MASK(0x001f01ff)
	windowsFileAddFile         = windows.ACCESS_MASK(0x00000002)
	windowsFileAddSubdirectory = windows.ACCESS_MASK(0x00000004)
	windowsFileDeleteChild     = windows.ACCESS_MASK(0x00000040)
	windowsTrustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

type windowsACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	ACECount uint16
	Sbz2     uint16
}

type windowsFileIdentity struct {
	volume uint32
	index  uint64
}

type windowsSecurityMaterial struct {
	current    *windows.SID
	admin      *windows.SID
	system     *windows.SID
	installer  *windows.SID
	descriptor *windows.SECURITY_DESCRIPTOR
}

var loadWindowsSecurityMaterial = sync.OnceValues(func() (*windowsSecurityMaterial, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current Windows user SID: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return nil, errors.New("current Windows token has no user SID")
	}
	current, err := windows.StringToSid(user.User.Sid.String())
	if err != nil {
		return nil, fmt.Errorf("copy current Windows user SID: %w", err)
	}
	sidText := current.String()
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sG:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", sidText, sidText, sidText))
	if err != nil {
		return nil, fmt.Errorf("build protected Windows state ACL: %w", err)
	}
	admin, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("build Windows Administrators SID: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("build Windows SYSTEM SID: %w", err)
	}
	installer, err := windows.StringToSid(windowsTrustedInstallerSID)
	if err != nil {
		return nil, fmt.Errorf("build Windows TrustedInstaller SID: %w", err)
	}
	return &windowsSecurityMaterial{
		current: current, admin: admin, system: system,
		installer: installer, descriptor: descriptor,
	}, nil
})

func requireSupportedPlatform() error { return nil }

func validateAbsoluteDirectoryPath(path string) error {
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, `\\?\`) || strings.HasPrefix(clean, `\\.\`) {
		return fmt.Errorf("directory path %s uses an unsupported Windows device namespace", path)
	}
	if filepath.VolumeName(clean) == "" || !filepath.IsAbs(clean) {
		return fmt.Errorf("directory path %s is not an absolute Windows path", path)
	}
	return nil
}

func directoryWalkAnchor(path string) string {
	return filepath.VolumeName(path) + string(filepath.Separator)
}

func supportsConfinedRecovery() bool { return false }

// shouldRetryDirectoryEdgeSync identifies a directory edge created with this
// package's exact protected ACL. Such an edge can be visible after an earlier
// uncertain parent flush, so a retry must flush it again. Ordinary volume,
// profile, and LocalAppData ancestors retain their inherited ACLs and are not
// reopened with write access.
func shouldRetryDirectoryEdgeSync(root *os.Root, label string) (bool, error) {
	file, err := root.Open(".")
	if err != nil {
		return false, fmt.Errorf("open existing directory edge %s for durability classification: %w", label, err)
	}
	handle := windows.Handle(file.Fd())
	if _, err := validateWindowsDirectoryHandle(handle, label); err != nil {
		runtime.KeepAlive(file)
		return false, errors.Join(err, file.Close())
	}
	match, classifyErr := matchesCreatedWindowsACL(handle, label)
	runtime.KeepAlive(file)
	closeErr := file.Close()
	if classifyErr != nil || closeErr != nil {
		var wrappedClassifyErr error
		if classifyErr != nil {
			wrappedClassifyErr = fmt.Errorf("classify existing directory edge %s for durability retry: %w", label, classifyErr)
		}
		return false, errors.Join(
			wrappedClassifyErr,
			closeErr,
		)
	}
	return match, nil
}

func windowsRelativeName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return errors.New("invalid Windows pinned-state entry name")
	}
	return nil
}

func windowsNTPath(path string) (string, error) {
	clean := filepath.Clean(path)
	if err := validateAbsoluteDirectoryPath(clean); err != nil {
		return "", err
	}
	volume := filepath.VolumeName(clean)
	if strings.HasPrefix(volume, `\\`) {
		return `\??\UNC\` + strings.TrimPrefix(clean, `\\`), nil
	}
	return `\??\` + clean, nil
}

func currentWindowsSecurity() (*windows.SID, *windows.SECURITY_DESCRIPTOR, error) {
	security, err := loadWindowsSecurityMaterial()
	if err != nil {
		return nil, nil, err
	}
	return security.current, security.descriptor, nil
}

func ntOpenWindowsObject(root windows.Handle, name string, access uint32, disposition uint32, options uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, bool, error) {
	if root != 0 {
		if err := windowsRelativeName(name); err != nil {
			return windows.InvalidHandle, false, err
		}
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, false, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		RootDirectory:      root,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: sd,
	}
	oa.Length = uint32(unsafe.Sizeof(*oa))
	var handle windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	allocation := int64(0)
	err = windows.NtCreateFile(
		&handle,
		access,
		oa,
		&iosb,
		&allocation,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		disposition,
		options|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		0,
		0,
	)
	if err != nil {
		return windows.InvalidHandle, false, normalizeWindowsOpenError(err)
	}
	return handle, iosb.Information == windowsFileCreated, nil
}

func normalizeWindowsOpenError(err error) error {
	switch {
	case errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION), errors.Is(err, windows.ERROR_ALREADY_EXISTS):
		return windows.ERROR_ALREADY_EXISTS
	case errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND), errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND), errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return windows.ERROR_FILE_NOT_FOUND
	default:
		return err
	}
}

func windowsHandleIdentity(handle windows.Handle) (windowsFileIdentity, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return windowsFileIdentity{}, info, err
	}
	return windowsFileIdentity{
		volume: info.VolumeSerialNumber,
		index:  uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
	}, info, nil
}

func validateWindowsDirectoryHandle(handle windows.Handle, label string) (windowsFileIdentity, error) {
	identity, info, err := windowsHandleIdentity(handle)
	if err != nil {
		return windowsFileIdentity{}, fmt.Errorf("stat %s: %w", label, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return windowsFileIdentity{}, fmt.Errorf("%s must be a non-reparse directory", label)
	}
	return identity, nil
}

func openWindowsDirectoryAbsolute(path string, access uint32) (windows.Handle, error) {
	ntPath, err := windowsNTPath(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, _, err := ntOpenWindowsObject(0, ntPath, access, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
	return handle, err
}

func openValidatedWindowsDirectory(root *os.Root, access uint32, label string) (windows.Handle, error) {
	retained, err := root.Open(".")
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("open retained %s: %w", label, err)
	}
	want, wantErr := validateWindowsDirectoryHandle(windows.Handle(retained.Fd()), label)
	closeErr := retained.Close()
	if wantErr != nil || closeErr != nil {
		return windows.InvalidHandle, errors.Join(wantErr, closeErr)
	}
	reopened, err := openWindowsDirectoryAbsolute(root.Name(), access)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("reopen %s: %w", label, err)
	}
	got, gotErr := validateWindowsDirectoryHandle(reopened, label)
	if gotErr != nil || got != want {
		_ = windows.CloseHandle(reopened)
		return windows.InvalidHandle, errors.Join(gotErr, fmt.Errorf("%s namespace changed while pinned", label))
	}
	return reopened, nil
}

func createPinnedDirectory(parent *os.Root, name, _ string, _ os.FileMode) error {
	_, secureSD, err := currentWindowsSecurity()
	if err != nil {
		return err
	}
	parentHandle, err := openValidatedWindowsDirectory(parent,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		"Windows pinned-state parent")
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(parentHandle) }()
	child, _, err := ntOpenWindowsObject(parentHandle, name,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, secureSD)
	if err != nil {
		return err
	}
	return windows.CloseHandle(child)
}

func syncPinnedDirectory(root *os.Root, label string) error {
	handle, err := openValidatedWindowsDirectory(root,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		label)
	if err != nil {
		return err
	}
	return errors.Join(windows.FlushFileBuffers(handle), windows.CloseHandle(handle))
}

func windowsTrustedSIDs() (admin, system, installer *windows.SID, err error) {
	security, err := loadWindowsSecurityMaterial()
	if err != nil {
		return nil, nil, nil, err
	}
	return security.admin, security.system, security.installer, nil
}

func windowsHandleSecurity(handle windows.Handle, label string) (*windows.SECURITY_DESCRIPTOR, *windows.SID, error) {
	current, _, err := currentWindowsSecurity()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve current Windows identity for %s: %w", label, err)
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s ACL: %w", label, err)
	}
	if sd == nil {
		return nil, nil, fmt.Errorf("read %s ACL: empty security descriptor", label)
	}
	return sd, current, nil
}

func windowsHandleCreatedSecurity(handle windows.Handle, label string) (*windows.SECURITY_DESCRIPTOR, *windows.SID, error) {
	current, _, err := currentWindowsSecurity()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve current Windows identity for %s: %w", label, err)
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s creation ACL: %w", label, err)
	}
	if sd == nil {
		return nil, nil, fmt.Errorf("read %s creation ACL: empty security descriptor", label)
	}
	return sd, current, nil
}

// matchesCreatedWindowsACL reports whether handle has the exact access policy
// installed by createPinnedDirectory. A successfully inspected but different
// ACL is an ordinary ancestor and returns false. Inspection and descriptor
// parsing failures remain hard errors so a retry cannot silently lose its
// durability guarantee.
func matchesCreatedWindowsACL(handle windows.Handle, label string) (bool, error) {
	sd, current, err := windowsHandleCreatedSecurity(handle, label)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, fmt.Errorf("read %s ACL owner: %w", label, err)
	}
	if owner == nil || !owner.Equals(current) {
		return false, nil
	}
	group, _, err := sd.Group()
	if err != nil {
		return false, fmt.Errorf("read %s ACL group: %w", label, err)
	}
	if group == nil || !group.Equals(current) {
		return false, nil
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, fmt.Errorf("read %s ACL control: %w", label, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, fmt.Errorf("read %s DACL: %w", label, err)
	}
	if dacl == nil {
		return false, nil
	}
	admin, system, _, err := windowsTrustedSIDs()
	if err != nil {
		return false, fmt.Errorf("build trusted Windows SIDs for %s: %w", label, err)
	}
	header := (*windowsACLHeader)(unsafe.Pointer(dacl))
	if header.ACECount != 3 {
		return false, nil
	}
	var userSeen, adminSeen, systemSeen bool
	for index := uint32(0); index < uint32(header.ACECount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return false, fmt.Errorf("inspect %s DACL entry %d: %w", label, index, err)
		}
		if ace == nil {
			return false, fmt.Errorf("inspect %s DACL entry %d: empty entry", label, index)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != windowsFileAllAccess {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return false, fmt.Errorf("inspect %s DACL entry %d: invalid SID", label, index)
		}
		switch {
		case sid.Equals(current):
			if userSeen {
				return false, nil
			}
			userSeen = true
		case sid.Equals(admin):
			if adminSeen {
				return false, nil
			}
			adminSeen = true
		case sid.Equals(system):
			if systemSeen {
				return false, nil
			}
			systemSeen = true
		default:
			return false, nil
		}
	}
	return userSeen && adminSeen && systemSeen, nil
}

func validateSecureWindowsACL(handle windows.Handle, label string) error {
	sd, current, err := windowsHandleSecurity(handle, label)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read %s ACL owner: %w", label, err)
	}
	if owner == nil || !owner.Equals(current) {
		return fmt.Errorf("%s is not owned by the current Windows user", label)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("read %s ACL control: %w", label, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%s ACL must be protected from inheritance", label)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read %s DACL: %w", label, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s has no restrictive DACL", label)
	}
	admin, system, _, err := windowsTrustedSIDs()
	if err != nil {
		return fmt.Errorf("build trusted Windows SIDs for %s: %w", label, err)
	}
	header := (*windowsACLHeader)(unsafe.Pointer(dacl))
	var userMask windows.ACCESS_MASK
	for index := uint32(0); index < uint32(header.ACECount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("inspect %s DACL entry %d: %w", label, index, err)
		}
		if ace == nil {
			return fmt.Errorf("%s has an empty DACL entry %d", label, index)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 {
			return fmt.Errorf("%s has an unsupported, inherited, or deny ACE", label)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return fmt.Errorf("%s has an invalid DACL SID", label)
		}
		switch {
		case sid.Equals(current):
			userMask |= ace.Mask
		case sid.Equals(admin), sid.Equals(system):
		default:
			return fmt.Errorf("%s grants access to another Windows principal", label)
		}
	}
	if userMask&windowsFileAllAccess != windowsFileAllAccess && userMask&windows.GENERIC_ALL == 0 {
		return fmt.Errorf("%s does not grant the current Windows user full control", label)
	}
	return nil
}

func validateTrustedWindowsACL(handle windows.Handle, label string, requireCurrentOwner bool) error {
	sd, current, err := windowsHandleSecurity(handle, label)
	if err != nil {
		return err
	}
	admin, system, installer, err := windowsTrustedSIDs()
	if err != nil {
		return fmt.Errorf("build trusted Windows SIDs for %s: %w", label, err)
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(current) || sid.Equals(admin) || sid.Equals(system) || sid.Equals(installer))
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read %s ACL owner: %w", label, err)
	}
	if owner == nil {
		return fmt.Errorf("%s has no Windows owner", label)
	}
	if requireCurrentOwner {
		if owner.Equals(current) {
			// Continue with the namespace-mutation checks below.
		} else if trusted(owner) {
			return fmt.Errorf("%w: %s is not owned by the current Windows user", ErrNamespaceNotOwned, label)
		} else {
			return fmt.Errorf("%s is not owned by a trusted Windows principal", label)
		}
	} else if !trusted(owner) {
		return fmt.Errorf("%s is not owned by a trusted Windows principal", label)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read %s DACL: %w", label, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s has no Windows DACL", label)
	}
	// An ancestor may permit creation of unrelated names. Existing components
	// are still safe because replacement needs delete/ACL control, and missing
	// components are created atomically with a protected ACL. The final owned
	// namespace is stricter because an untrusted principal must not race lock or
	// transaction entry creation inside it.
	mutation := windows.ACCESS_MASK(windows.DELETE|windows.WRITE_DAC|windows.WRITE_OWNER|windows.GENERIC_ALL) |
		windowsFileDeleteChild
	if requireCurrentOwner {
		mutation |= windows.ACCESS_MASK(windows.GENERIC_WRITE) | windowsFileAddFile | windowsFileAddSubdirectory
	}
	header := (*windowsACLHeader)(unsafe.Pointer(dacl))
	for index := uint32(0); index < uint32(header.ACECount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return fmt.Errorf("inspect %s DACL entry %d: %w", label, index, err)
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("%s has an unsupported Windows ACE", label)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return fmt.Errorf("%s has an invalid DACL SID", label)
		}
		if !trusted(sid) && ace.Mask&mutation != 0 {
			return fmt.Errorf("%s grants namespace mutation to an untrusted Windows principal", label)
		}
	}
	return nil
}

func validateTrustedDirectoryRoot(root *os.Root, _ os.FileInfo, label string, _ bool) error {
	file, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s for ACL validation: %w", label, err)
	}
	defer file.Close()
	if _, err := validateWindowsDirectoryHandle(windows.Handle(file.Fd()), label); err != nil {
		return err
	}
	return validateTrustedWindowsACL(windows.Handle(file.Fd()), label, false)
}

func validateFinalDirectory(root *os.Root, _ os.FileInfo, label string, exactMode *os.FileMode, requireOwner, requireTrust bool) error {
	file, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s for final validation: %w", label, err)
	}
	defer file.Close()
	handle := windows.Handle(file.Fd())
	if _, err := validateWindowsDirectoryHandle(handle, label); err != nil {
		return err
	}
	if exactMode != nil || requireOwner {
		return validateSecureWindowsACL(handle, label)
	}
	if requireTrust {
		return validateTrustedWindowsACL(handle, label, false)
	}
	return nil
}

func validateOwnedDirectory(root *os.Root, _ os.FileInfo, label string) error {
	file, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open %s for ownership validation: %w", label, err)
	}
	defer file.Close()
	return validateTrustedWindowsACL(windows.Handle(file.Fd()), label, true)
}

func openPinnedFile(root *os.Root, name string, flag int, perm os.FileMode) (*os.File, error) {
	if flag&os.O_CREATE == 0 {
		return root.OpenFile(name, flag, perm)
	}
	if flag&os.O_APPEND != 0 {
		return nil, errors.New("create Windows pinned-state file with O_APPEND is unsupported")
	}
	_, secureSD, err := currentWindowsSecurity()
	if err != nil {
		return nil, err
	}
	parent, err := openValidatedWindowsDirectory(root,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		"Windows pinned-state directory")
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(parent) }()
	access := uint32(windows.SYNCHRONIZE | windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES)
	switch flag & (os.O_RDONLY | os.O_WRONLY | os.O_RDWR) {
	case os.O_WRONLY:
		access |= windows.FILE_GENERIC_WRITE
	case os.O_RDWR:
		access |= windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE
	default:
		access |= windows.FILE_GENERIC_READ
	}
	disposition := uint32(windows.FILE_OPEN_IF)
	if flag&os.O_EXCL != 0 {
		disposition = windows.FILE_CREATE
	}
	handle, _, err := ntOpenWindowsObject(parent, name, access, disposition, windows.FILE_NON_DIRECTORY_FILE, secureSD)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(handle), filepath.Join(root.Name(), name))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("wrap Windows pinned-state file handle")
	}
	if flag&os.O_TRUNC != 0 {
		if err := windows.SetEndOfFile(handle); err != nil {
			return nil, errors.Join(err, file.Close())
		}
	}
	return file, nil
}
