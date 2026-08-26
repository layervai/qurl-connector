//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

const (
	immutableConfigPrivilegeDropHelper = "QURL_TEST_IMMUTABLE_CONFIG_PRIVILEGE_DROP"
	immutableConfigPrivilegeDropPath   = "QURL_TEST_IMMUTABLE_CONFIG_PATH"
)

func TestCanonicalDockerImmutableConfigAsNonRoot(t *testing.T) {
	if os.Getenv(immutableConfigPrivilegeDropHelper) == "1" {
		path := os.Getenv(immutableConfigPrivilegeDropPath)
		access, err := acquireConnectorRunConfigAccess(t.Context(), path)
		if err != nil {
			t.Fatal(err)
		}
		if access == nil || access.snapshot == nil || access.transaction != nil || access.writeErr == nil {
			t.Fatalf("access = %#v, want root-owned immutable snapshot", access)
		}
		if access.config == nil || len(access.config.Routes) != 1 || access.config.Routes[0].ID != "customer-web" {
			t.Fatalf("config = %#v", access.config)
		}
		if err := access.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("non-root immutable read created sibling lock: %v", err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("root is required to construct a root-owned namespace and drop privileges")
	}

	rootDir := filepath.Join("/", fmt.Sprintf("qurl-connector-immutable-config-test-%d", os.Getpid()))
	if err := os.Mkdir(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })
	if err := os.Chmod(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(rootDir, "qurl-proxy.yaml")
	raw := []byte("routes:\n  - id: customer-web\n    type: http\n    local_ip: 127.0.0.1\n    local_port: 8080\n")
	if err := os.WriteFile(configPath, raw, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o444); err != nil {
		t.Fatal(err)
	}

	source, err := os.Open(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	testBinaryPath := filepath.Join(rootDir, "connector.test")
	destination, err := os.OpenFile(testBinaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		_ = source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := errors.Join(destination.Close(), source.Close())
	if copyErr != nil || closeErr != nil {
		t.Fatal(errors.Join(copyErr, closeErr))
	}
	if err := os.Chmod(testBinaryPath, 0o755); err != nil {
		t.Fatal(err)
	}

	before, err := os.Stat(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(testBinaryPath, "-test.run=^TestCanonicalDockerImmutableConfigAsNonRoot$")
	cmd.Env = append(os.Environ(),
		immutableConfigPrivilegeDropHelper+"=1",
		immutableConfigPrivilegeDropPath+"="+configPath,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: 65534, Gid: 65534},
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("privilege-dropped immutable config read: %v\n%s", err, output)
	}
	after, err := os.Stat(rootDir)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("privilege-dropped immutable read changed namespace mtime: before=%v after=%v", before.ModTime(), after.ModTime())
	}
	if _, err := os.Lstat(configPath + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("privilege-dropped immutable read created sibling lock: %v", err)
	}
}
