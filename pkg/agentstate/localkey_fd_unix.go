//go:build unix

package agentstate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
)

const localWrappingKeyReadTimeout = 5 * time.Second

func readLocalWrappingKey(fdValue string) ([]byte, error) {
	return readLocalWrappingKeyUntil(fdValue, time.Now().Add(localWrappingKeyReadTimeout))
}

func readLocalWrappingKeyUntil(fdValue string, deadline time.Time) ([]byte, error) {
	fd, err := strconv.Atoi(fdValue)
	if err != nil || fd < 3 {
		return nil, fmt.Errorf("%s must be an inherited descriptor number >= 3; got %q", EnvLocalKeyFD, fdValue)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("inspect %s=%d: %w", EnvLocalKeyFD, fd, err)
	}
	if err := validateLocalKeyDescriptor(fd, &stat); err != nil {
		return nil, fmt.Errorf("%s=%d: %w", EnvLocalKeyFD, fd, err)
	}
	// os.NewFile can register an already-nonblocking pipe or socket with Go's
	// network poller, which makes SetReadDeadline reliable here.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("prepare %s=%d for bounded read: %w", EnvLocalKeyFD, fd, err)
	}
	file := os.NewFile(uintptr(fd), "qurl-local-wrapping-key")
	defer file.Close()
	if err := file.SetReadDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set %s=%d read deadline: %w", EnvLocalKeyFD, fd, err)
	}
	key, readErr := io.ReadAll(io.LimitReader(file, localWrappingKeySize+1))
	if errors.Is(readErr, os.ErrDeadlineExceeded) {
		scrubBytes(key)
		return nil, fmt.Errorf("read %s=%d: timed out waiting for the wrapping-key pipe to close", EnvLocalKeyFD, fd)
	}
	if readErr != nil {
		scrubBytes(key)
		return nil, fmt.Errorf("read %s=%d: %w", EnvLocalKeyFD, fd, readErr)
	}
	if len(key) != localWrappingKeySize {
		scrubBytes(key)
		return nil, fmt.Errorf("%s=%d contained %d bytes (want exactly %d)", EnvLocalKeyFD, fd, len(key), localWrappingKeySize)
	}
	return key, nil
}

func validateLocalKeyDescriptor(fd int, stat *syscall.Stat_t) error {
	switch stat.Mode & syscall.S_IFMT {
	case syscall.S_IFIFO:
		return validateAnonymousLocalKeyFIFO(fd, stat)
	case syscall.S_IFSOCK:
		socketType, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err != nil {
			return fmt.Errorf("inspect inherited socket type: %w", err)
		}
		if socketType != syscall.SOCK_STREAM {
			return fmt.Errorf("inherited local socket must be SOCK_STREAM")
		}
		local, err := syscall.Getsockname(fd)
		if err != nil {
			return fmt.Errorf("inspect inherited socket address: %w", err)
		}
		localUnix, ok := local.(*syscall.SockaddrUnix)
		if !ok {
			return fmt.Errorf("inherited socket is not local AF_UNIX")
		}
		if !isAnonymousLocalKeySocketAddress(fd, false, localUnix.Name) {
			return fmt.Errorf("inherited AF_UNIX stream is named, not an anonymous socketpair")
		}
		peer, err := syscall.Getpeername(fd)
		if err != nil {
			// The external qURL Desktop app's Electron runtime writes the
			// complete key and closes its socketpair end immediately. On
			// Darwin, getpeername can then return EINVAL even though the key
			// and EOF are already buffered. The unnamed local endpoint plus
			// the exact-length-and-EOF read below is still the intended
			// one-shot transport. Other address/type errors fail.
			if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTCONN) {
				return nil
			}
			return fmt.Errorf("inherited AF_UNIX stream is not connected: %w", err)
		}
		peerUnix, ok := peer.(*syscall.SockaddrUnix)
		if !ok {
			return fmt.Errorf("inherited socket peer is not local AF_UNIX")
		}
		if !isAnonymousLocalKeySocketAddress(fd, true, peerUnix.Name) {
			return fmt.Errorf("inherited AF_UNIX peer is named, not an anonymous socketpair")
		}
		return nil
	default:
		return fmt.Errorf("descriptor is not an inherited pipe or connected local socket")
	}
}
