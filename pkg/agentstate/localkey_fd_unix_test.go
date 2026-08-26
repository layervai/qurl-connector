//go:build unix

package agentstate

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	qurl "github.com/layervai/qurl-go/qurl"
)

func duplicateTestFD(t testing.TB, file *os.File) uintptr {
	t.Helper()
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		t.Fatalf("duplicate inherited descriptor: %v", err)
	}
	return uintptr(fd)
}

func replaceTestFD(t testing.TB, file *os.File, target uintptr) {
	t.Helper()
	if err := syscall.Dup2(int(file.Fd()), int(target)); err != nil {
		t.Fatalf("replace inherited descriptor: %v", err)
	}
}

func reserveTestFD(t testing.TB, target uintptr) {
	t.Helper()
	placeholder, err := syscall.Open(os.DevNull, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("reserve inherited descriptor: %v", err)
	}
	if placeholder == int(target) {
		return
	}
	if err := syscall.Dup2(placeholder, int(target)); err != nil {
		_ = syscall.Close(placeholder)
		t.Fatalf("reserve inherited descriptor target: %v", err)
	}
	if err := syscall.Close(placeholder); err != nil {
		t.Fatalf("close inherited descriptor placeholder: %v", err)
	}
}

func inheritedKeyFD(t testing.TB, key []byte) string {
	t.Helper()
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	inheritedFD := duplicateTestFD(t, readEnd)
	_ = readEnd.Close()
	go func() {
		_, _ = writeEnd.Write(key)
		_ = writeEnd.Close()
	}()
	return strconv.FormatUint(uint64(inheritedFD), 10)
}

func inheritedSocketpairKeyFD(t testing.TB, key []byte) string {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	writer := os.NewFile(uintptr(fds[1]), "test-local-key-writer")
	go func() {
		_, _ = writer.Write(key)
		_ = writer.Close()
	}()
	return strconv.Itoa(fds[0])
}

func TestLocalKeyProviderReadsExactInheritedDescriptorOnce(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, localWrappingKeySize)
	t.Setenv(EnvKeyProvider, KeyProviderLocalKey)
	t.Setenv(EnvLocalKeyFD, inheritedKeyFD(t, key))
	resetLocalKeyProviderCache(t)

	first, err := newLocalKeyProviderFromEnv()
	if err != nil {
		t.Fatalf("first newLocalKeyProviderFromEnv: %v", err)
	}
	second, err := newLocalKeyProviderFromEnv()
	if err != nil {
		t.Fatalf("second newLocalKeyProviderFromEnv: %v", err)
	}
	firstProvider := first.(localKeyProvider)
	secondProvider := second.(localKeyProvider)
	if !bytes.Equal(firstProvider.key, secondProvider.key) {
		t.Fatal("cached descriptor key changed")
	}
	if &firstProvider.key[0] == &secondProvider.key[0] {
		t.Fatal("providers alias the same cached key buffer")
	}
}

func TestReadLocalWrappingKeyAcceptsElectronUnixSocketpair(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, localWrappingKeySize)
	got, err := readLocalWrappingKey(inheritedSocketpairKeyFD(t, key))
	if err != nil {
		t.Fatalf("readLocalWrappingKey from AF_UNIX socketpair: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("AF_UNIX socketpair key changed")
	}
}

func TestLocalKeyProviderCacheSwitchDoesNotScrubExistingProvider(t *testing.T) {
	t.Setenv(EnvKeyProvider, KeyProviderLocalKey)
	resetLocalKeyProviderCache(t)

	firstKey := bytes.Repeat([]byte{0x31}, localWrappingKeySize)
	t.Setenv(EnvLocalKeyFD, inheritedKeyFD(t, firstKey))
	rawFirst, err := newLocalKeyProviderFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	first := rawFirst.(localKeyProvider)
	sealed, err := first.Seal(
		context.Background(),
		bytes.Repeat([]byte{0x72}, StateDEKSize),
		sdkKeyEncryptionContext(localKeyTestBinding("agent-a")),
	)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv(EnvLocalKeyFD, inheritedKeyFD(t, bytes.Repeat([]byte{0x32}, localWrappingKeySize)))
	if _, err := newLocalKeyProviderFromEnv(); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Unseal(context.Background(), sealed); err != nil {
		t.Fatalf("existing provider was scrubbed by cache switch: %v", err)
	}
}

func TestLocalKeyProviderRetriesFailedDescriptorRead(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("first Pipe: %v", err)
	}
	inheritedFD := duplicateTestFD(t, readEnd)
	_ = readEnd.Close()
	if _, err := writeEnd.Write([]byte("short")); err != nil {
		t.Fatalf("write short key: %v", err)
	}
	_ = writeEnd.Close()

	t.Setenv(EnvKeyProvider, KeyProviderLocalKey)
	t.Setenv(EnvLocalKeyFD, strconv.FormatUint(uint64(inheritedFD), 10))
	resetLocalKeyProviderCache(t)
	if _, err := newLocalKeyProviderFromEnv(); err == nil {
		t.Fatal("first newLocalKeyProviderFromEnv accepted a short key")
	}

	// The failed read closed inheritedFD. Reserve that number before creating
	// the retry pipe so the OS cannot reuse it for the new pipe's write end;
	// Dup2 would otherwise close the writer while replacing the target.
	reserveTestFD(t, inheritedFD)
	retryReadEnd, retryWriteEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("retry Pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = retryReadEnd.Close()
		_ = retryWriteEnd.Close()
	})
	replaceTestFD(t, retryReadEnd, inheritedFD)
	retryKey := bytes.Repeat([]byte{0x52}, localWrappingKeySize)
	go func() {
		_, _ = retryWriteEnd.Write(retryKey)
		_ = retryWriteEnd.Close()
	}()

	provider, err := newLocalKeyProviderFromEnv()
	if err != nil {
		t.Fatalf("retry newLocalKeyProviderFromEnv: %v", err)
	}
	if !bytes.Equal(provider.(localKeyProvider).key, retryKey) {
		t.Fatal("retry provider did not use the replacement descriptor key")
	}
}

func TestReadLocalWrappingKeyRejectsStdioAndWrongLength(t *testing.T) {
	if _, err := readLocalWrappingKey("1"); err == nil {
		t.Fatal("readLocalWrappingKey accepted stdout")
	}
	for _, size := range []int{localWrappingKeySize - 1, localWrappingKeySize + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			_, readErr := readLocalWrappingKey(inheritedKeyFD(t, bytes.Repeat([]byte{0x31}, size)))
			if readErr == nil || !strings.Contains(readErr.Error(), "want exactly 32") {
				t.Fatalf("readLocalWrappingKey error = %v, want exact-length rejection", readErr)
			}
		})
	}
}

func TestReadLocalWrappingKeyRejectsRegularFileWithoutClosingIt(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "not-a-pipe"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer file.Close()

	_, readErr := readLocalWrappingKey(strconv.FormatUint(uint64(file.Fd()), 10))
	if readErr == nil || !strings.Contains(readErr.Error(), "not an inherited pipe or connected local socket") {
		t.Fatalf("readLocalWrappingKey error = %v, want regular-file rejection", readErr)
	}
	if _, err := file.WriteString("still open"); err != nil {
		t.Fatalf("rejected descriptor was closed or mutated: %v", err)
	}
}

func TestReadLocalWrappingKeyRejectsNamedFIFOWithoutClosingIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "named-key.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	fifo, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile named FIFO: %v", err)
	}
	defer fifo.Close()

	_, readErr := readLocalWrappingKey(strconv.FormatUint(uint64(fifo.Fd()), 10))
	if readErr == nil || !strings.Contains(readErr.Error(), "anonymous") {
		t.Fatalf("readLocalWrappingKey error = %v, want named-FIFO rejection", readErr)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(fifo.Fd()), &stat); err != nil {
		t.Fatalf("rejected named FIFO was closed: %v", err)
	}
}

func TestReadLocalWrappingKeyRejectsNetworkSocketWithoutClosingIt(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	defer syscall.Close(fd)

	_, readErr := readLocalWrappingKey(strconv.Itoa(fd))
	if readErr == nil || !strings.Contains(readErr.Error(), "not local AF_UNIX") {
		t.Fatalf("readLocalWrappingKey error = %v, want network-socket rejection", readErr)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		t.Fatalf("rejected network descriptor was closed: %v", err)
	}
}

func TestReadLocalWrappingKeyRejectsNamedUnixSocketWithoutClosingIt(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	defer syscall.Close(fd)
	placeholder, err := os.CreateTemp("", "qurl-local-key-*.sock")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	socketPath := placeholder.Name()
	if err := placeholder.Close(); err != nil {
		t.Fatalf("close socket-path placeholder: %v", err)
	}
	if err := os.Remove(socketPath); err != nil {
		t.Fatalf("remove socket-path placeholder: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	if err := syscall.Bind(fd, &syscall.SockaddrUnix{Name: socketPath}); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	_, readErr := readLocalWrappingKey(strconv.Itoa(fd))
	if readErr == nil || !strings.Contains(readErr.Error(), "named, not an anonymous socketpair") {
		t.Fatalf("readLocalWrappingKey error = %v, want named-socket rejection", readErr)
	}
	var stat syscall.Stat_t
	if err := syscall.Fstat(fd, &stat); err != nil {
		t.Fatalf("rejected named socket descriptor was closed: %v", err)
	}
}

func TestReadLocalWrappingKeyTimesOutWhenWriterNeverCloses(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = readEnd.Close()
		_ = writeEnd.Close()
	})
	inheritedFD := duplicateTestFD(t, readEnd)
	if _, err := writeEnd.Write(bytes.Repeat([]byte{0x31}, localWrappingKeySize)); err != nil {
		t.Fatalf("write key: %v", err)
	}

	_, readErr := readLocalWrappingKeyUntil(
		strconv.FormatUint(uint64(inheritedFD), 10),
		time.Now().Add(25*time.Millisecond),
	)
	if readErr == nil || !strings.Contains(readErr.Error(), "timed out") {
		t.Fatalf("readLocalWrappingKeyUntil err = %v, want timeout", readErr)
	}
}

func TestReadLocalWrappingKeyTimesOutOnElectronSocketpairWhenWriterNeverCloses(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	writer := os.NewFile(uintptr(fds[1]), "test-local-key-writer")
	t.Cleanup(func() { _ = writer.Close() })
	if _, err := writer.Write(bytes.Repeat([]byte{0x31}, localWrappingKeySize)); err != nil {
		t.Fatalf("write key: %v", err)
	}

	_, readErr := readLocalWrappingKeyUntil(
		strconv.Itoa(fds[0]),
		time.Now().Add(25*time.Millisecond),
	)
	if readErr == nil || !strings.Contains(readErr.Error(), "timed out") {
		t.Fatalf("readLocalWrappingKeyUntil err = %v, want socketpair timeout", readErr)
	}
}

func TestNewSDKStoreLocalKeySealsCompleteQURLGoState(t *testing.T) {
	key := bytes.Repeat([]byte{0x61}, localWrappingKeySize)
	t.Setenv(EnvKeyProvider, KeyProviderLocalKey)
	t.Setenv(EnvLocalKeyFD, inheritedKeyFD(t, key))
	resetLocalKeyProviderCache(t)

	dir := filepath.Join(realSDKTempDir(t), "state")
	store, err := NewSDKStore(dir, "desktop-profile-one")
	if err != nil {
		t.Fatalf("NewSDKStore: %v", err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Errorf("close local-key SDK store: %v", err)
		}
	})
	stateStore, err := store.Handoff()
	if err != nil {
		t.Fatalf("Handoff: %v", err)
	}
	state := &qurl.AgentState{
		AgentID:       "desktop-profile-one",
		PrivateKeyB64: "private-secret",
		PublicKeyB64:  "public-identity",
		DeviceAPIKey:  "device-secret",
	}
	if err := stateStore.SaveAgentState(context.Background(), state); err != nil {
		t.Fatalf("SaveAgentState: %v", err)
	}
	loaded, err := stateStore.LoadAgentState(context.Background())
	if err != nil {
		t.Fatalf("LoadAgentState: %v", err)
	}
	if !reflect.DeepEqual(loaded, state) {
		t.Fatalf("sealed state round trip = %#v, want %#v", loaded, state)
	}

	sealedPath := filepath.Join(dir, SealedAgentStateFile)
	sealedBytes, err := os.ReadFile(sealedPath)
	if err != nil {
		t.Fatalf("read sealed state: %v", err)
	}
	for _, secret := range []string{state.PrivateKeyB64, state.DeviceAPIKey} {
		if bytes.Contains(sealedBytes, []byte(secret)) {
			t.Fatalf("%s contains plaintext state secret %q", SealedAgentStateFile, secret)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, AgentStateFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s exists or stat failed: %v", AgentStateFile, err)
	}
	for _, legacy := range []string{AgentIDFile, PrivateKeyFile, PublicKeyFile, SealedPrivateKeyFile} {
		if _, err := os.Stat(filepath.Join(dir, legacy)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy %s exists or stat failed: %v", legacy, err)
		}
	}

	clearLocalKeyProviderCache()
	t.Setenv(EnvLocalKeyFD, inheritedKeyFD(t, bytes.Repeat([]byte{0x62}, localWrappingKeySize)))
	wrongKeyStore, err := NewSDKStore(dir, "desktop-profile-one")
	if err != nil {
		t.Fatalf("NewSDKStore with wrong key: %v", err)
	}
	t.Cleanup(func() {
		if err := wrongKeyStore.Close(); err != nil {
			t.Errorf("close wrong-key SDK store: %v", err)
		}
	})
	wrongKeyStateStore, err := wrongKeyStore.Handoff()
	if err != nil {
		t.Fatalf("Handoff with wrong key: %v", err)
	}
	if _, err := wrongKeyStateStore.LoadAgentState(context.Background()); err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("LoadAgentState with wrong OS-keystore key error = %v, want authentication failure", err)
	}
}
