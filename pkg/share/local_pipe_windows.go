//go:build windows

package share

import (
	"context"
	"errors"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// DialLocalPipe opens a canonical local pipe and verifies the connected handle's
// owner before returning it. It never sends bytes to an unverified server.
func DialLocalPipe(ctx context.Context, name string) (net.Conn, error) {
	return dialLocalPipe(ctx, name, verifyLocalPipeOwner)
}

func dialLocalPipe(ctx context.Context, name string, verify func(net.Conn) error) (net.Conn, error) {
	if err := ValidateLocalPipeName(name); err != nil {
		return nil, err
	}
	// Anonymous SQOS is pinned explicitly rather than relying on go-winio's
	// (currently identical) default: the owner check runs after connect, so an
	// unverified server must never be able to impersonate this client.
	conn, err := winio.DialPipeAccessImpLevel(ctx, name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, winio.PipeImpLevelAnonymous)
	if err != nil {
		return nil, localPipeOpenError(err)
	}
	if err := verify(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// localPipeOpenError keeps the failure class operators need (a stopped origin
// versus a foreign pipe) as a fixed string that never names the pipe. go-winio
// retries a busy pipe until the deadline, so busy surfaces as timeout.
func localPipeOpenError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return errors.New("open local named-pipe origin failed: not found")
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return errors.New("open local named-pipe origin failed: access denied")
	case errors.Is(err, winio.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return errors.New("open local named-pipe origin failed: timeout")
	case errors.Is(err, context.Canceled):
		return errors.New("open local named-pipe origin failed: canceled")
	default:
		return errors.New("open local named-pipe origin failed")
	}
}

func verifyLocalPipeOwner(conn net.Conn) error {
	handle, ok := conn.(interface{ Fd() uintptr })
	if !ok || handle.Fd() == 0 || windows.Handle(handle.Fd()) == windows.InvalidHandle {
		return errors.New("local named-pipe handle is invalid")
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return errors.New("read local named-pipe owner failed")
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return errors.New("read local named-pipe owner failed")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil {
		return errors.New("read local named-pipe client identity failed")
	}
	return checkLocalPipeOwner(owner, user.User.Sid)
}

func checkLocalPipeOwner(owner, current *windows.SID) error {
	if owner == nil || current == nil || !owner.Equals(current) {
		return errors.New("local named-pipe owner is not the current user")
	}
	return nil
}
