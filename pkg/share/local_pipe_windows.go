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
	conn, err := winio.DialPipeAccess(ctx, name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL)
	if err != nil {
		return nil, errors.New("open local named-pipe origin failed")
	}
	if err := verify(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
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
