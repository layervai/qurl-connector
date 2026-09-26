//go:build !windows

package share

import (
	"context"
	"errors"
	"net"
)

// DialLocalPipe fails closed on platforms without Windows named pipes.
func DialLocalPipe(context.Context, string) (net.Conn, error) {
	return nil, errors.New("local named-pipe origins require Windows")
}
