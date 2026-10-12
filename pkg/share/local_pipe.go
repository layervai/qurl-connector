package share

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	plugin "github.com/fatedier/frp/pkg/plugin/client"
	libio "github.com/fatedier/golib/io"
)

const localPipePluginName = "layerv_private_named_pipe"
const localPipePrefix = `\\.\pipe\layerv-qurl-file-`

// The canonical suffix is <64 hex>-<32 hex>.
const (
	localPipeHeadLen   = 64
	localPipeNonceLen  = 32
	localPipeSuffixLen = localPipeHeadLen + 1 + localPipeNonceLen
)

// ValidateLocalPipeName accepts only canonical private file-origin pipe names
// on Windows: localPipePrefix followed by 64 lowercase hex digits, '-', and 32
// lowercase hex digits. Windows compares pipe names case-insensitively, but
// this grammar is deliberately lowercase-only so producers (Desktop, the CLI)
// have exactly one spelling. Errors never include the supplied name.
func ValidateLocalPipeName(name string) error {
	if runtime.GOOS != "windows" {
		return errors.New("local named-pipe origins require Windows")
	}
	suffix, ok := strings.CutPrefix(name, localPipePrefix)
	if !ok || len(suffix) != localPipeSuffixLen || suffix[localPipeHeadLen] != '-' {
		return errors.New("local named-pipe target is invalid")
	}
	for i, ch := range suffix {
		if i == localPipeHeadLen {
			continue
		}
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return errors.New("local named-pipe target is invalid")
		}
	}
	return nil
}

// Only typed FRP configuration is supported: its JSON decoder cannot restore
// custom options. Private routes prohibit the FRP admin server accordingly.
type localPipeOptions struct {
	PipeName string `json:"-" yaml:"-"`
}

func (*localPipeOptions) Complete()                       {}
func (p *localPipeOptions) Clone() v1.ClientPluginOptions { out := *p; return &out }
func (*localPipeOptions) String() string                  { return "private named-pipe options [REDACTED]" }
func (p *localPipeOptions) GoString() string              { return p.String() }

func init() {
	plugin.Register(localPipePluginName, func(_ plugin.PluginContext, options v1.ClientPluginOptions) (plugin.Plugin, error) {
		opts, ok := options.(*localPipeOptions)
		if !ok || opts == nil {
			return nil, errors.New("invalid private named-pipe options")
		}
		if err := ValidateLocalPipeName(opts.PipeName); err != nil {
			return nil, err
		}
		return &localPipePlugin{name: opts.PipeName}, nil
	})
}

type localPipePlugin struct{ name string }

func (*localPipePlugin) Name() string { return localPipePluginName }
func (*localPipePlugin) Close() error { return nil }
func (p *localPipePlugin) Handle(ctx context.Context, info *plugin.ConnectionInfo) {
	defer info.Conn.Close()
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := DialLocalPipe(dialCtx, p.name)
	if err != nil {
		// Pipe names identify private local origins. DialLocalPipe errors are
		// fixed strings that never include the name, so only the class is logged.
		slog.WarnContext(ctx, "local named-pipe origin is unavailable", "err", err)
		return
	}
	defer conn.Close()
	if info.ProxyProtocolHeader != nil {
		if _, err := info.ProxyProtocolHeader.WriteTo(conn); err != nil {
			return
		}
	}
	libio.Join(conn, info.Conn)
}
