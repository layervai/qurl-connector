package share

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"strings"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/client"
	"gopkg.in/yaml.v3"
)

func testLocalPipeName() string {
	return localPipePrefix + strings.Repeat("a", 64) + "-" + strings.Repeat("b", 32)
}

func TestLocalPipeRouteContract(t *testing.T) {
	name := testLocalPipeName()
	route := groupTestRoutes("alpha")[0]
	route.LocalIP, route.LocalPort, route.LocalPipeName = "", 0, name
	if err := validateLocalHTTPRoute(route); (err == nil) != (runtime.GOOS == "windows") {
		t.Fatalf("platform validation: %v", err)
	}
	for _, invalid := range []string{"", strings.ToUpper(name), name + "x", strings.Replace(name, `\\.\`, `\\host\`, 1), localPipePrefix + strings.Repeat("a", 97), name + "\x00", localPipePrefix + strings.Repeat("a", 63) + `\` + "-" + strings.Repeat("b", 32), localPipePrefix + strings.Repeat("a", 64) + "-" + strings.Repeat("G", 32)} {
		if err := ValidateLocalPipeName(invalid); err == nil || strings.Contains(err.Error(), name) {
			t.Fatal("invalid pipe accepted or disclosed")
		}
	}
	for _, mutate := range []func(*LocalHTTPRoute){func(r *LocalHTTPRoute) { r.LocalIP = "127.0.0.1" }, func(r *LocalHTTPRoute) { r.LocalPort = 1234 }, func(r *LocalHTTPRoute) { r.LocalSocketPath = "/tmp/file.sock" }} {
		invalid := route
		mutate(&invalid)
		if validateLocalHTTPRoute(invalid) == nil {
			t.Fatal("mixed transport accepted")
		}
	}
	other := route
	other.LocalPipeName = name[:len(name)-1] + "c"
	if route.Equal(other) {
		t.Fatal("pipe replacement ignored")
	}
	both := route
	both.LocalSocketPath = "/tmp/file.sock"
	if rendered := buildRouteProxy(both, "both").Plugin; rendered.ClientPluginOptions != nil || rendered.Type != "" {
		t.Fatal("renderer let one private transport overwrite the other")
	}
	proxy := buildRouteProxy(route, "pipe-test")
	var message msg.NewProxy
	proxy.MarshalToMsg(&message)
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), strings.TrimPrefix(name, localPipePrefix)) {
		t.Fatal("named-pipe origin escaped into NewProxy")
	}
	cloned := proxy.Clone().(*v1.HTTPProxyConfig)
	opts, ok := cloned.Plugin.ClientPluginOptions.(*localPipeOptions)
	if !ok || opts.PipeName != name || cloned.LocalPort != 0 || cloned.LocalIP != "" {
		t.Fatal("typed clone lost private origin")
	}
	opts.PipeName = "modified"
	if proxy.Plugin.ClientPluginOptions.(*localPipeOptions).PipeName != name {
		t.Fatal("clone aliased options")
	}
	for _, value := range []any{route, proxy.Plugin.ClientPluginOptions} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), name) {
				t.Fatal("format leaked pipe")
			}
		}
		for _, marshal := range []func(any) ([]byte, error){json.Marshal, yaml.Marshal} {
			data, err := marshal(value)
			if err != nil || strings.Contains(string(data), name) {
				t.Fatal("serialization leaked pipe")
			}
		}
	}
	common := &v1.ClientCommonConfig{}
	common.WebServer.Port = 7400
	if routeTransportError(common, false, route.hasPrivateOrigin()) == nil {
		t.Fatal("private admin accepted")
	}
	if runtime.GOOS != "windows" {
		if conn, err := DialLocalPipe(context.Background(), name); err == nil || conn != nil {
			t.Fatal("non-Windows dial accepted")
		}
	}
}

func TestLocalPipeHandleLogsRedactedDialFailure(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	name := testLocalPipeName()
	local, remote := net.Pipe()
	defer remote.Close()
	(&localPipePlugin{name: name}).Handle(context.Background(), &plugin.ConnectionInfo{Conn: local})
	out := logs.String()
	if !strings.Contains(out, "local named-pipe origin is unavailable") || strings.Contains(out, strings.TrimPrefix(name, localPipePrefix)) {
		t.Fatalf("dial failure log missing or leaked pipe: %q", out)
	}
}
