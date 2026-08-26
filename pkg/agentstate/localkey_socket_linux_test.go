//go:build linux

package agentstate

import (
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestReadLocalWrappingKeyRejectsNamedAbstractUnixSocketWithoutClosingIt(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: "@qurl-local-key-test"}); err != nil {
		t.Fatalf("Bind abstract AF_UNIX socket: %v", err)
	}

	_, readErr := readLocalWrappingKey(strconv.Itoa(fd))
	if readErr == nil || !strings.Contains(readErr.Error(), "named, not an anonymous socketpair") {
		t.Fatalf("readLocalWrappingKey error = %v, want named abstract-socket rejection", readErr)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		t.Fatalf("rejected abstract socket descriptor was closed: %v", err)
	}
}

func TestReadLocalWrappingKeyRejectsEmptyNamedAbstractUnixSocket(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	defer syscall.Close(fd)
	// Linux represents both this bound zero-byte abstract name and an unnamed
	// socketpair endpoint as "@"; the kernel sockaddr length distinguishes them.
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: "@"}); err != nil {
		t.Fatalf("Bind empty abstract AF_UNIX socket: %v", err)
	}

	_, readErr := readLocalWrappingKey(strconv.Itoa(fd))
	if readErr == nil || !strings.Contains(readErr.Error(), "named, not an anonymous socketpair") {
		t.Fatalf("readLocalWrappingKey error = %v, want empty abstract-socket rejection", readErr)
	}
}
