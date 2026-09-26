//go:build windows

package share

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	plugin "github.com/fatedier/frp/pkg/plugin/client"
	"golang.org/x/sys/windows"
)

func listenTestLocalPipe(t *testing.T) net.Listener {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	name := localPipePrefix + strings.Repeat("a", 64) + "-" + hex.EncodeToString(nonce)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	listener, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: "O:" + sid + "D:P(A;;GA;;;" + sid + ")"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func TestHermeticNamedPipeOriginHeadersAndMissingOrigin(t *testing.T) {
	testHermeticRuntimeHeadersReachOnlyTheirOrigin(t, true, listenTestLocalPipe(t))
}

func TestLocalPipeOwnerAndMissingOrigin(t *testing.T) {
	listener := listenTestLocalPipe(t)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, _ := listener.Accept()
		accepted <- conn
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := DialLocalPipe(ctx, listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	var server net.Conn
	select {
	case server = <-accepted:
		if server == nil {
			t.Fatal("named-pipe accept failed")
		}
	case <-ctx.Done():
		t.Fatal("named-pipe accept timed out")
	}
	defer server.Close()
	_ = server.SetReadDeadline(time.Now().Add(time.Second))
	data := make([]byte, 1)
	if n, _ := server.Read(data); n != 0 {
		t.Fatal("verification sent bytes")
	}
	_ = listener.Close()
	if conn, err := DialLocalPipe(ctx, listener.Addr().String()); conn != nil || err == nil || strings.Contains(err.Error(), listener.Addr().String()) || !strings.HasSuffix(err.Error(), ": not found") {
		t.Fatalf("missing pipe did not fail closed as not found: %v", err)
	}
	for cause, class := range map[error]string{
		windows.ERROR_ACCESS_DENIED: ": access denied",
		windows.ERROR_PIPE_BUSY:     ": busy",
		winio.ErrTimeout:            ": timeout",
		context.DeadlineExceeded:    ": timeout",
		context.Canceled:            ": canceled",
		errors.New("other"):         "open local named-pipe origin failed",
	} {
		if got := localPipeOpenError(cause).Error(); !strings.HasSuffix(got, class) {
			t.Fatalf("open error class for %v = %q", cause, got)
		}
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	other, err := windows.StringToSid("S-1-0-0")
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []*windows.SID{nil, other} {
		if checkLocalPipeOwner(owner, user.User.Sid) == nil {
			t.Fatal("invalid owner accepted")
		}
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	if verifyLocalPipeOwner(left) == nil {
		t.Fatal("connection without handle accepted")
	}
	incoming, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&localPipePlugin{name: listener.Addr().String()}).Handle(ctx, &plugin.ConnectionInfo{Conn: incoming})
	}()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := client.Read(data); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("plugin did not close failed stream: %d %v", n, err)
	}
	<-done
}

// Inject only the owner decision, after a real Windows pipe handle was opened.
// Both missing and wrong owner must close that handle without writing a byte.
func TestLocalPipeRejectedOwnerSendsNoBytes(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	other, err := windows.StringToSid("S-1-0-0")
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []*windows.SID{nil, other} {
		listener := listenTestLocalPipe(t)
		received := make(chan int, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				received <- -1
				return
			}
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 1)
			n, _ := conn.Read(buf)
			received <- n
		}()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := dialLocalPipe(ctx, listener.Addr().String(), func(conn net.Conn) error {
			if err := verifyLocalPipeOwner(conn); err != nil {
				t.Error(err)
			}
			return checkLocalPipeOwner(owner, user.User.Sid)
		})
		cancel()
		if err == nil || conn != nil {
			t.Fatal("unverified connection returned")
		}
		if n := <-received; n != 0 {
			t.Fatalf("owner rejection sent %d bytes", n)
		}
	}
}

// Node uses libuv's default pipe DACL, as Desktop does. Elevated accounts may
// create an Administrators-owned pipe; those must fail closed, never waive the
// current-user check. Node is supplied by the Windows CI lane.
func TestLocalPipeNodeDefaultSecurity(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("Node is required for Windows private-origin interoperability tests in CI")
		}
		t.Skip("Node is not installed; the Windows CI lane runs this interoperability test")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	name := localPipePrefix + strings.Repeat("c", 64) + "-" + hex.EncodeToString(nonce)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "-e", `require('http').createServer((req,res)=>res.end('node-private-file')).listen(process.argv[1],()=>console.log('ready'))`, name)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || strings.TrimSpace(line) != "ready" {
		t.Fatalf("Node pipe readiness: %v", err)
	}
	raw, err := winio.DialPipeAccess(ctx, name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL)
	if err != nil {
		t.Fatal("Node default pipe did not allow same-user duplex and owner inspection")
	}
	handle, ok := raw.(interface{ Fd() uintptr })
	if !ok {
		_ = raw.Close()
		t.Fatal("Node pipe handle is unavailable")
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		_ = raw.Close()
		t.Fatal("Node pipe owner query failed")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		_ = raw.Close()
		t.Fatal("Node pipe owner SID is unavailable")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		_ = raw.Close()
		t.Fatal("Node pipe client SID is unavailable")
	}
	ownerMatches := owner.Equals(user.User.Sid)
	_ = raw.Close()
	conn, err := DialLocalPipe(ctx, name)
	if !ownerMatches {
		if err == nil || conn != nil {
			t.Fatal("Node non-current-user owner accepted")
		}
		t.Log("Node default pipe owner is not the process user; verified dial correctly refused it")
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request, _ := http.NewRequest(http.MethodGet, "http://localhost/", nil)
	if err := request.Write(conn); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "node-private-file" {
		t.Fatal("Node pipe HTTP interoperability failed")
	}
	t.Log("verified Node HTTP request succeeded")
}
