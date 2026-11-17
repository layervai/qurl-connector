//go:build windows

package agentstate

import (
	"errors"
	"runtime"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var localKeyKernel32 = windows.NewLazySystemDLL("kernel32.dll")
var localKeyGetStartupInfo = localKeyKernel32.NewProc("GetStartupInfoW")
var localKeyPeekNamedPipe = localKeyKernel32.NewProc("PeekNamedPipe")
var localKeyGetHandleInformation = localKeyKernel32.NewProc("GetHandleInformation")
var windowsLocalKeyAttempt sync.Once

// x/sys omits the CRT-reserved fields; retain the Windows STARTUPINFOW layout.
type localKeyStartupInfo struct {
	Size                                                               uint32
	Reserved, Desktop, Title                                           *uint16
	X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags uint32
	ShowWindow, ReservedSize                                           uint16
	ReservedData                                                       *byte
	StdInput, StdOutput, StdErr                                        windows.Handle
}

var _ [unsafe.Sizeof(windows.StartupInfo{})]byte = [unsafe.Sizeof(localKeyStartupInfo{})]byte{}

func readLocalWrappingKey(fdValue string) ([]byte, error) {
	fd, err := strconv.Atoi(fdValue)
	if err != nil || fd < 3 {
		return nil, errors.New("local wrapping key requires an inherited descriptor >= 3")
	}
	var startup localKeyStartupInfo
	_, _, _ = localKeyGetStartupInfo.Call(uintptr(unsafe.Pointer(&startup)))
	if startup.ReservedData == nil || startup.ReservedSize == 0 {
		return nil, errors.New("missing inherited pipe table")
	}
	// The CRT table is immutable: after consuming or rejecting its entry, a
	// retry must never inspect a handle number Windows may have recycled.
	allowed := false
	windowsLocalKeyAttempt.Do(func() { allowed = true })
	if !allowed {
		return nil, errors.New("inherited wrapping-key handle already consumed")
	}
	table := unsafe.Slice(startup.ReservedData, int(startup.ReservedSize))
	raw, err := inheritedCRTHandle(table, fd, int(unsafe.Sizeof(uintptr(0))))
	if err != nil {
		return nil, err
	}

	handle := windows.Handle(raw)
	var handleFlags uint32
	inherited, _, _ := localKeyGetHandleInformation.Call(uintptr(handle), uintptr(unsafe.Pointer(&handleFlags)))
	if inherited == 0 || handleFlags&windows.HANDLE_FLAG_INHERIT == 0 {
		return nil, errors.New("wrapping key handle was not inherited")
	}
	kind, err := windows.GetFileType(handle)
	if err != nil || kind != windows.FILE_TYPE_PIPE {
		return nil, errors.New("wrapping key descriptor is not a pipe")
	}
	var flags, instances uint32
	if err := windows.GetNamedPipeInfo(handle, &flags, nil, nil, &instances); err != nil || instances != 1 || flags&windows.PIPE_TYPE_MESSAGE != 0 {
		return nil, errors.New("wrapping key requires one connected byte pipe")
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return nil, errors.New("cannot inspect wrapping key pipe owner")
	}
	owner, _, err := descriptor.Owner()
	user, userErr := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || userErr != nil || owner == nil || user == nil || !owner.Equals(user.User.Sid) && !isLocalKeyTokenOwner(owner) {
		return nil, errors.New("wrapping key pipe is not owned by the current token")
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	return readWindowsLocalKeyPipe(handle, time.Now().Add(5*time.Second))
}

// The inherited libuv client handle is synchronous. Peek before each bounded
// read, so an unclosed writer cannot strand a goroutine or a live OS read.
func readWindowsLocalKeyPipe(handle windows.Handle, deadline time.Time) ([]byte, error) {
	key := make([]byte, 0, localWrappingKeySize+1)
	for time.Now().Before(deadline) {
		var available uint32
		ok, _, err := localKeyPeekNamedPipe.Call(uintptr(handle), 0, 0, 0, uintptr(unsafe.Pointer(&available)), 0)
		if ok == 0 {
			if errors.Is(err, windows.ERROR_BROKEN_PIPE) && len(key) == localWrappingKeySize {
				return key, nil
			}
			scrubBytes(key)
			return nil, errors.New("wrapping key pipe closed without exactly 32 bytes")
		}
		if available == 0 {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		count := min(int(available), localWrappingKeySize+1-len(key))
		chunk := make([]byte, count)
		var read uint32
		err = windows.ReadFile(handle, chunk, &read, nil)
		key = append(key, chunk[:read]...)
		scrubBytes(chunk)
		if err != nil || len(key) > localWrappingKeySize {
			scrubBytes(key)
			return nil, errors.New("invalid wrapping key pipe contents")
		}
	}
	scrubBytes(key)
	return nil, errors.New("wrapping key pipe did not close before the deadline")
}

// Elevated tokens can create Administrators-owned libuv pipes. Only the
// process token's own default owner is accepted in addition to its user SID.
func isLocalKeyTokenOwner(owner *windows.SID) bool {
	var size uint32
	token := windows.GetCurrentProcessToken()
	err := windows.GetTokenInformation(token, windows.TokenOwner, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || size == 0 || size > 4096 {
		return false
	}
	buffer := make([]byte, size)
	if windows.GetTokenInformation(token, windows.TokenOwner, &buffer[0], size, &size) != nil {
		return false
	}
	tokenOwner := *(**windows.SID)(unsafe.Pointer(&buffer[0])) // #nosec G103 -- TOKEN_OWNER returned by Windows.
	matches := tokenOwner != nil && tokenOwner.IsValid() && owner.Equals(tokenOwner)
	runtime.KeepAlive(buffer)
	return matches
}
