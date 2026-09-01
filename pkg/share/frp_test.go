package share

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	frpproxy "github.com/fatedier/frp/client/proxy"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"gopkg.in/yaml.v3"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func encryptedFRPCommon() *v1.ClientCommonConfig {
	enabled := true
	common := &v1.ClientCommonConfig{}
	common.Transport.TLS.Enable = &enabled
	return common
}

func TestLocalHTTPRouteFormattingRedactsRuntimeRequestHeaders(t *testing.T) {
	const headerName = "X-QURL-Desktop-Proxy-Token"
	const headerValue = "runtime-secret-do-not-format"
	route := LocalHTTPRoute{
		RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
		ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
		RequestHeaders: map[string]string{headerName: headerValue},
	}
	config := FRPFactoryConfig{Common: encryptedFRPCommon(), Route: route}
	factory := &FRPSessionFactory{cfg: config}

	for _, test := range []struct {
		name   string
		format string
		value  any
	}{
		{name: "route default", format: "%v", value: route},
		{name: "route fields", format: "%+v", value: route},
		{name: "route Go syntax", format: "%#v", value: route},
		{name: "config default", format: "%v", value: config},
		{name: "config fields", format: "%+v", value: config},
		{name: "config Go syntax", format: "%#v", value: config},
		{name: "factory default", format: "%v", value: factory},
		{name: "factory fields", format: "%+v", value: factory},
		{name: "factory Go syntax", format: "%#v", value: factory},
		{name: "factory value default", format: "%v", value: *factory},
		{name: "factory value fields", format: "%+v", value: *factory},
		{name: "factory value Go syntax", format: "%#v", value: *factory},
	} {
		t.Run(test.name, func(t *testing.T) {
			formatted := fmt.Sprintf(test.format, test.value)
			if !strings.Contains(formatted, "RequestHeaders:[REDACTED]") {
				t.Fatalf("formatted route omitted the redaction marker: %s", formatted)
			}
			for _, secret := range []string{headerName, headerValue} {
				if strings.Contains(formatted, secret) {
					t.Fatalf("formatted route disclosed runtime request headers: %s", formatted)
				}
			}
		})
	}
}

func TestLocalHTTPRouteSerializationOmitsRuntimeRequestHeaders(t *testing.T) {
	const headerName = "X-QURL-Desktop-Proxy-Token"
	const headerValue = "runtime-secret-do-not-marshal"
	route := LocalHTTPRoute{
		RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
		ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
		RequestHeaders: map[string]string{headerName: headerValue},
	}

	for _, valueTest := range []struct {
		name  string
		value any
	}{
		{name: "route", value: route},
		{name: "factory config", value: FRPFactoryConfig{Common: encryptedFRPCommon(), Route: route}},
	} {
		t.Run(valueTest.name, func(t *testing.T) {
			for _, codecTest := range []struct {
				name    string
				marshal func(any) ([]byte, error)
			}{
				{name: "JSON", marshal: json.Marshal},
				{name: "YAML", marshal: yaml.Marshal},
			} {
				t.Run(codecTest.name, func(t *testing.T) {
					encoded, err := codecTest.marshal(valueTest.value)
					if err != nil {
						t.Fatal(err)
					}
					for _, forbidden := range []string{"RequestHeaders", "requestheaders", headerName, headerValue} {
						if strings.Contains(string(encoded), forbidden) {
							t.Fatalf("serialization disclosed runtime request headers: %s", encoded)
						}
					}
				})
			}
		})
	}
}

func TestNewFRPSessionFactoryRequiresEncryptedTransportForRuntimeRequestHeaders(t *testing.T) {
	secretName := "X-QURL-Desktop-Proxy-Token"
	secretValue := "runtime-secret-value"
	for _, test := range []struct {
		name   string
		common *v1.ClientCommonConfig
	}{
		{name: "unset TLS", common: &v1.ClientCommonConfig{}},
		{name: "explicitly disabled TLS", common: func() *v1.ClientCommonConfig {
			disabled := false
			common := &v1.ClientCommonConfig{}
			common.Transport.TLS.Enable = &disabled
			return common
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewFRPSessionFactory(FRPFactoryConfig{
				Common: test.common,
				Route: LocalHTTPRoute{
					RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
					ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
					RequestHeaders: map[string]string{secretName: secretValue},
				},
			})
			if err == nil {
				t.Fatal("runtime request headers were accepted without encrypted FRP transport")
			}
			const wantErr = "build FRP session factory: runtime request headers require encrypted FRP transport"
			if got := err.Error(); got != wantErr {
				t.Fatalf("validation error = %q, want fixed error %q", got, wantErr)
			}
			for _, secret := range []string{secretName, secretValue} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("validation error disclosed runtime request-header input: %q", err)
				}
			}
		})
	}
}

func TestNewFRPSessionFactoryAcceptsEncryptedTransportForRuntimeRequestHeaders(t *testing.T) {
	for _, test := range []struct {
		name   string
		common func() *v1.ClientCommonConfig
	}{
		{name: "explicit TLS", common: encryptedFRPCommon},
		{name: "secure websocket", common: func() *v1.ClientCommonConfig {
			common := &v1.ClientCommonConfig{}
			common.Transport.Protocol = "wss"
			return common
		}},
		{name: "QUIC", common: func() *v1.ClientCommonConfig {
			common := &v1.ClientCommonConfig{}
			common.Transport.Protocol = "quic"
			return common
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewFRPSessionFactory(FRPFactoryConfig{
				Common: test.common(),
				Route: LocalHTTPRoute{
					RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
					ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
					RequestHeaders: map[string]string{"X-QURL-Desktop-Proxy-Token": "runtime-secret"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if factory == nil {
				t.Fatal("encrypted FRP transport did not create a runtime-header factory")
			}
		})
	}
}

func TestFRPSessionFactoryRejectsLateTransportEncryptionDisablement(t *testing.T) {
	common := encryptedFRPCommon()
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: common,
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: map[string]string{"X-QURL-Desktop-Proxy-Token": "runtime-secret"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	common.Transport.TLS.Enable = &disabled

	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
	}
	_, _, _, err = factory.BuildConfig(admission)
	if err == nil {
		t.Fatal("runtime request headers were accepted after FRP transport encryption was disabled")
	}
	const wantErr = "render FRP session config: runtime request headers require encrypted FRP transport"
	if got := err.Error(); got != wantErr {
		t.Fatalf("validation error = %q, want fixed error %q", got, wantErr)
	}
	for _, secret := range []string{"X-QURL-Desktop-Proxy-Token", "runtime-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validation error disclosed runtime request-header input: %q", err)
		}
	}
}

func TestFRPSessionFactoryBuildConfigClonesTransportEncryptionSetting(t *testing.T) {
	common := encryptedFRPCommon()
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: common,
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: map[string]string{"X-QURL-Desktop-Proxy-Token": "runtime-secret"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
	}
	rendered, _, _, err := factory.BuildConfig(admission)
	if err != nil {
		t.Fatal(err)
	}
	if rendered.Transport.TLS.Enable == common.Transport.TLS.Enable {
		t.Fatal("rendered TLS enablement aliases the caller-owned pointer")
	}

	*common.Transport.TLS.Enable = false
	if rendered.Transport.TLS.Enable == nil || !*rendered.Transport.TLS.Enable {
		t.Fatal("caller mutation disabled transport encryption after config rendering")
	}
}

func TestFRPSessionFactoryBuildConfigSetsRuntimeRequestHeaders(t *testing.T) {
	route := LocalHTTPRoute{
		RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
		ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
		RequestHeaders: map[string]string{
			"X-QURL-Share-Token": "runtime-secret",
			"X-Request-Source":   "desktop",
		},
	}

	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: encryptedFRPCommon(), Route: route,
	})
	if err != nil {
		t.Fatal(err)
	}
	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
	}
	_, proxies, _, err := factory.BuildConfig(admission)
	if err != nil {
		t.Fatal(err)
	}
	proxy, ok := proxies[0].(*v1.HTTPProxyConfig)
	if !ok {
		t.Fatalf("proxy type = %T", proxies[0])
	}
	want := map[string]string{
		"X-QURL-Share-Token": "runtime-secret",
		"X-Request-Source":   "desktop",
	}
	if !reflect.DeepEqual(proxy.RequestHeaders.Set, want) {
		t.Fatalf("request headers = %#v, want %#v", proxy.RequestHeaders.Set, want)
	}
}

func TestFRPSessionFactoryClonesRequestHeadersAtConstruction(t *testing.T) {
	requestHeaders := map[string]string{"X-QURL-Share-Token": "original-secret"}
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: encryptedFRPCommon(),
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: requestHeaders,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	requestHeaders["X-QURL-Share-Token"] = "mutated-secret"
	requestHeaders["X-Added-Later"] = "unexpected"

	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
	}
	_, proxies, _, err := factory.BuildConfig(admission)
	if err != nil {
		t.Fatal(err)
	}
	proxy, ok := proxies[0].(*v1.HTTPProxyConfig)
	if !ok {
		t.Fatalf("proxy type = %T", proxies[0])
	}
	want := map[string]string{"X-QURL-Share-Token": "original-secret"}
	if !reflect.DeepEqual(proxy.RequestHeaders.Set, want) {
		t.Fatalf("request headers after caller mutation = %#v, want %#v", proxy.RequestHeaders.Set, want)
	}
}

func TestFRPSessionFactoryBuildConfigClonesRequestHeadersPerCycle(t *testing.T) {
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: encryptedFRPCommon(),
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: map[string]string{"X-QURL-Share-Token": "original-secret"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	build := func(sessionID uint64) *v1.HTTPProxyConfig {
		t.Helper()
		admission := Admission{
			KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
			RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
			SessionID: sessionID, SessionReceipt: testSessionReceipt(sessionID, "run", 1), OpenTime: time.Minute,
		}
		_, proxies, _, err := factory.BuildConfig(admission)
		if err != nil {
			t.Fatal(err)
		}
		proxy, ok := proxies[0].(*v1.HTTPProxyConfig)
		if !ok {
			t.Fatalf("proxy type = %T", proxies[0])
		}
		return proxy
	}
	first := build(101)
	first.RequestHeaders.Set["X-QURL-Share-Token"] = "mutated-secret"
	first.RequestHeaders.Set["X-Added-Later"] = "unexpected"
	second := build(102)
	want := map[string]string{"X-QURL-Share-Token": "original-secret"}
	if !reflect.DeepEqual(second.RequestHeaders.Set, want) {
		t.Fatalf("second-cycle request headers = %#v, want %#v", second.RequestHeaders.Set, want)
	}
}

func TestNewFRPSessionFactoryRejectsInvalidRequestHeadersWithoutDisclosingThem(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantErr string
		secrets []string
	}{
		{
			name: "invalid name",
			headers: map[string]string{
				"X Invalid top-secret-name": "top-secret-value",
			},
			wantErr: "build FRP session factory: request header name is invalid",
			secrets: []string{"top-secret-name", "top-secret-value"},
		},
		{
			name:    "empty name",
			headers: map[string]string{"": "top-secret-value"},
			wantErr: "build FRP session factory: request header name is invalid",
			secrets: []string{"top-secret-value"},
		},
		{
			name: "carriage return and line feed",
			headers: map[string]string{
				"X-QURL-Share-Token": "top-secret-value\r\nX-Injected: true",
			},
			wantErr: "build FRP session factory: request header value is invalid",
			secrets: []string{"top-secret-value"},
		},
		{
			name:    "bare line feed",
			headers: map[string]string{"X-QURL-Share-Token": "top-secret-value\n"},
			wantErr: "build FRP session factory: request header value is invalid",
			secrets: []string{"top-secret-value"},
		},
		{
			name:    "delete control byte",
			headers: map[string]string{"X-QURL-Share-Token": "top-secret-value\x7f"},
			wantErr: "build FRP session factory: request header value is invalid",
			secrets: []string{"top-secret-value"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewFRPSessionFactory(FRPFactoryConfig{
				Common: &v1.ClientCommonConfig{},
				Route: LocalHTTPRoute{
					RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
					ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
					RequestHeaders: test.headers,
				},
			})
			if err == nil {
				t.Fatal("invalid request headers were accepted")
			}
			if got := err.Error(); got != test.wantErr {
				t.Fatalf("validation error = %q, want fixed error %q", got, test.wantErr)
			}
			for _, secret := range test.secrets {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("validation error disclosed request-header input: %q", err)
				}
			}
		})
	}
}

func TestNewFRPSessionFactoryAcceptsTransportSafeRequestHeaderValues(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
	}{
		{name: "horizontal tab", value: "left\tright"},
		{name: "obs text", value: "caf\u00e9"},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewFRPSessionFactory(FRPFactoryConfig{
				Common: encryptedFRPCommon(),
				Route: LocalHTTPRoute{
					RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
					ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
					RequestHeaders: map[string]string{"X-QURL-Metadata": test.value},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if factory == nil {
				t.Fatal("transport-safe request header did not create a factory")
			}
		})
	}
}

func TestNewFRPSessionFactoryValidatesRequestHeadersDeterministically(t *testing.T) {
	headers := map[string]string{
		"A-Bad-Value": "top-secret-value\n",
		"B Bad Name":  "top-secret-value",
		"Connection":  "top-secret-value",
		"X-Duplicate": "top-secret-value",
		"x-duplicate": "second-secret-value",
	}
	const wantErr = "build FRP session factory: request header value is invalid"
	for i := 0; i < 128; i++ {
		_, err := NewFRPSessionFactory(FRPFactoryConfig{
			Common: &v1.ClientCommonConfig{},
			Route: LocalHTTPRoute{
				RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
				ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
				RequestHeaders: headers,
			},
		})
		if err == nil {
			t.Fatal("multiply-invalid request headers were accepted")
		}
		if got := err.Error(); got != wantErr {
			t.Fatalf("validation pass %d returned %q, want deterministic error %q", i, got, wantErr)
		}
	}
}

func TestNewFRPSessionFactoryBoundsRuntimeRequestHeaders(t *testing.T) {
	const (
		wantMaxHeaderCount = 16
		wantMaxHeaderBytes = 1024
		wantLimitError     = "build FRP session factory: request headers exceed runtime limits"
	)
	countHeaders := func(count int) map[string]string {
		headers := make(map[string]string, count)
		for i := 0; i < count; i++ {
			headers["X-Empty-"+string(rune('A'+i))] = ""
		}
		return headers
	}
	aggregateName := "X-Limit"
	tests := []struct {
		name    string
		headers map[string]string
		wantErr string
	}{
		{
			name:    "exact header count with empty values",
			headers: countHeaders(wantMaxHeaderCount),
		},
		{
			name:    "over header count",
			headers: countHeaders(wantMaxHeaderCount + 1),
			wantErr: wantLimitError,
		},
		{
			name: "exact aggregate bytes",
			headers: map[string]string{
				aggregateName: strings.Repeat("s", wantMaxHeaderBytes-len(aggregateName)),
			},
		},
		{
			name: "over aggregate bytes",
			headers: map[string]string{
				aggregateName: strings.Repeat("s", wantMaxHeaderBytes-len(aggregateName)+1),
			},
			wantErr: wantLimitError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewFRPSessionFactory(FRPFactoryConfig{
				Common: encryptedFRPCommon(),
				Route: LocalHTTPRoute{
					RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
					ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
					RequestHeaders: test.headers,
				},
			})
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if factory == nil {
					t.Fatal("request headers at the runtime limit did not create a factory")
				}
				return
			}
			if err == nil {
				t.Fatal("request headers over the runtime limit were accepted")
			}
			if got := err.Error(); got != test.wantErr {
				t.Fatalf("limit error = %q, want fixed error %q", got, test.wantErr)
			}
			if strings.Contains(err.Error(), aggregateName) || strings.Contains(err.Error(), "ssss") {
				t.Fatalf("limit error disclosed request-header input: %q", err)
			}
		})
	}
}

func TestFRPSessionFactoryMaximumRuntimeRequestHeadersFitPinnedControlMessage(t *testing.T) {
	headers := make(map[string]string, maxRuntimeRequestHeaderCount)
	aggregateBytes := 0
	for i := 0; i < maxRuntimeRequestHeaderCount; i++ {
		name := "X-Wire-" + string(rune('A'+i))
		headers[name] = ""
		aggregateBytes += len(name)
	}
	headers["X-Wire-A"] = strings.Repeat("&", maxRuntimeRequestHeaderBytes-aggregateBytes)
	if len(headers) != maxRuntimeRequestHeaderCount {
		t.Fatalf("header count = %d, want exact limit %d", len(headers), maxRuntimeRequestHeaderCount)
	}
	aggregateBytes = 0
	for name, value := range headers {
		aggregateBytes += len(name) + len(value)
	}
	if aggregateBytes != maxRuntimeRequestHeaderBytes {
		t.Fatalf("aggregate header bytes = %d, want exact limit %d", aggregateBytes, maxRuntimeRequestHeaderBytes)
	}

	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: encryptedFRPCommon(),
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: headers,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
	}
	_, proxies, _, err := factory.BuildConfig(admission)
	if err != nil {
		t.Fatal(err)
	}
	proxy, ok := proxies[0].(*v1.HTTPProxyConfig)
	if !ok {
		t.Fatalf("proxy type = %T", proxies[0])
	}
	wireProxy := &msg.NewProxy{}
	proxy.MarshalToMsg(wireProxy)
	wireJSON, err := json.Marshal(wireProxy)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wireJSON), `\u0026`) {
		t.Fatal("maximum-size wire assertion did not exercise JSON string expansion")
	}
	const pinnedControlMessageLimit = 10240
	if len(wireJSON) > pinnedControlMessageLimit {
		t.Fatalf("NewProxy JSON length = %d, exceeds pinned control-message limit %d", len(wireJSON), pinnedControlMessageLimit)
	}
}

func TestNewFRPSessionFactoryRejectsCaseInsensitiveDuplicateRequestHeaderNames(t *testing.T) {
	secretName := "X-QURL-Share-Token"
	secretValue := "runtime-secret-value"
	_, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: &v1.ClientCommonConfig{},
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: map[string]string{
				secretName:           secretValue,
				"x-qurl-share-token": "second-secret-value",
			},
		},
	})
	if err == nil {
		t.Fatal("case-insensitive duplicate request header names were accepted")
	}
	const wantErr = "build FRP session factory: request header names are duplicated"
	if got := err.Error(); got != wantErr {
		t.Fatalf("validation error = %q, want fixed error %q", got, wantErr)
	}
	for _, secret := range []string{secretName, secretValue, "second-secret-value"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validation error disclosed request-header input: %q", err)
		}
	}
}

func TestNewFRPSessionFactoryRejectsSpecialRequestHeaderNames(t *testing.T) {
	for _, headerName := range []string{
		"Host",
		"Content-Length",
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"Forwarded",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Real-IP",
		"X-Forwarded-Port",
	} {
		headerName := headerName
		t.Run(headerName, func(t *testing.T) {
			_, err := NewFRPSessionFactory(FRPFactoryConfig{
				Common: &v1.ClientCommonConfig{},
				Route: LocalHTTPRoute{
					RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
					ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
					RequestHeaders: map[string]string{
						strings.ToLower(headerName): "runtime-secret-value",
					},
				},
			})
			if err == nil {
				t.Fatalf("special request header %q was accepted", headerName)
			}
			const wantErr = "build FRP session factory: request header name is reserved"
			if got := err.Error(); got != wantErr {
				t.Fatalf("validation error = %q, want fixed error %q", got, wantErr)
			}
			for _, secret := range []string{headerName, "runtime-secret-value"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("validation error disclosed request-header input: %q", err)
				}
			}
		})
	}
}

func TestNewFRPSessionFactoryRejectsRuntimeRequestHeadersWhenWebServerEnabled(t *testing.T) {
	secretName := "X-QURL-Share-Token"
	secretValue := "runtime-secret-value"
	common := encryptedFRPCommon()
	common.WebServer.Port = 7400
	_, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: common,
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: map[string]string{secretName: secretValue},
		},
	})
	if err == nil {
		t.Fatal("runtime request headers were accepted with the FRP web server enabled")
	}
	const wantErr = "build FRP session factory: runtime request headers require FRP web server to be disabled"
	if got := err.Error(); got != wantErr {
		t.Fatalf("validation error = %q, want fixed error %q", got, wantErr)
	}
	for _, secret := range []string{secretName, secretValue} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validation error disclosed runtime request-header input: %q", err)
		}
	}
}

func TestNewFRPSessionFactoryAllowsHeaderlessRouteWhenWebServerEnabled(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "nil map"},
		{name: "empty non-nil map", headers: map[string]string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewFRPSessionFactory(FRPFactoryConfig{
				Common: &v1.ClientCommonConfig{WebServer: v1.WebServerConfig{Port: 7400}},
				Route: LocalHTTPRoute{
					RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
					ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
					RequestHeaders: test.headers,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if factory == nil {
				t.Fatal("headerless route did not create a factory")
			}
		})
	}
}

func TestFRPSessionFactoryRejectsLateWebServerEnablementWithRuntimeRequestHeaders(t *testing.T) {
	common := encryptedFRPCommon()
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: common,
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: map[string]string{"X-QURL-Share-Token": "runtime-secret"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	common.WebServer.Port = 7400

	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
	}
	_, _, _, err = factory.BuildConfig(admission)
	if err == nil {
		t.Fatal("runtime request headers were accepted after the FRP web server was enabled")
	}
	const wantErr = "render FRP session config: runtime request headers require FRP web server to be disabled"
	if got := err.Error(); got != wantErr {
		t.Fatalf("validation error = %q, want fixed error %q", got, wantErr)
	}
	for _, secret := range []string{"X-QURL-Share-Token", "runtime-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validation error disclosed runtime request-header input: %q", err)
		}
	}
}

func TestFRPSessionFactoryReadsCurrentCommonForHeaderlessRoute(t *testing.T) {
	common := &v1.ClientCommonConfig{}
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: common,
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	common.WebServer.Port = 7400

	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
	}
	builtCommon, _, _, err := factory.BuildConfig(admission)
	if err != nil {
		t.Fatal(err)
	}
	if got := builtCommon.WebServer.Port; got != 7400 {
		t.Fatalf("built web server port = %d, want current value 7400", got)
	}
}

func TestFRPSessionFactoryBuildConfigKeepsHeaderlessProxyWireContract(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "nil map"},
		{name: "empty non-nil map", headers: map[string]string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewFRPSessionFactory(FRPFactoryConfig{
				Common: &v1.ClientCommonConfig{},
				Route: LocalHTTPRoute{
					RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
					ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
					RequestHeaders: test.headers,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			admission := Admission{
				KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
				RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
				SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
			}
			_, proxies, _, err := factory.BuildConfig(admission)
			if err != nil {
				t.Fatal(err)
			}
			proxy, ok := proxies[0].(*v1.HTTPProxyConfig)
			if !ok {
				t.Fatalf("proxy type = %T", proxies[0])
			}
			wireProxy := &msg.NewProxy{}
			proxy.MarshalToMsg(wireProxy)
			got, err := json.Marshal(wireProxy)
			if err != nil {
				t.Fatal(err)
			}
			const want = `{"proxy_name":"local-app-nhp2t","proxy_type":"http","group":"routing-resource","group_key":"routing-resource","metas":{"resource_id":"public-resource"},"subdomain":"routing-resource"}`
			if string(got) != want {
				t.Fatalf("headerless proxy wire bytes = %s, want %s", got, want)
			}
		})
	}
}

func TestFRPSessionFactoryBuildConfigRendersRuntimeRequestHeadersOnWire(t *testing.T) {
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: encryptedFRPCommon(),
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
			RequestHeaders: map[string]string{
				"X-QURL-Share-Token": "runtime-secret",
				"X-Request-Source":   "desktop",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
		SessionID: 101, SessionReceipt: testSessionReceipt(101, "run", 1), OpenTime: time.Minute,
	}
	_, proxies, _, err := factory.BuildConfig(admission)
	if err != nil {
		t.Fatal(err)
	}
	proxy, ok := proxies[0].(*v1.HTTPProxyConfig)
	if !ok {
		t.Fatalf("proxy type = %T", proxies[0])
	}
	wireProxy := &msg.NewProxy{}
	proxy.MarshalToMsg(wireProxy)
	got, err := json.Marshal(wireProxy)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"proxy_name":"local-app-nhp2t","proxy_type":"http","group":"routing-resource","group_key":"routing-resource","metas":{"resource_id":"public-resource"},"subdomain":"routing-resource","headers":{"X-QURL-Share-Token":"runtime-secret","X-Request-Source":"desktop"}}`
	if string(got) != want {
		t.Fatalf("headered proxy wire bytes = %s, want %s", got, want)
	}
}

func TestFRPSessionFactoryBuildsOverlapSafeResourceCycles(t *testing.T) {
	common := &v1.ClientCommonConfig{Metadatas: map[string]string{"preserved": "value"}}
	factory, err := NewFRPSessionFactory(FRPFactoryConfig{
		Common: common,
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
		},
		ClientVersion: "v1.2.3",
	})
	if err != nil {
		t.Fatal(err)
	}
	build := func(sessionID uint64) (*v1.ClientCommonConfig, *v1.HTTPProxyConfig, string) {
		t.Helper()
		admission := Admission{
			KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
			RunID: "run", RunAttempt: 1, Token: "token", ResourceHost: "frp.example:7000",
			SessionID: sessionID, SessionReceipt: testSessionReceipt(sessionID, "run", 1), OpenTime: 2,
		}
		cycleCommon, proxies, names, err := factory.BuildConfig(admission)
		if err != nil {
			t.Fatal(err)
		}
		proxy, ok := proxies[0].(*v1.HTTPProxyConfig)
		if !ok {
			t.Fatalf("proxy type = %T", proxies[0])
		}
		return cycleCommon, proxy, names[0]
	}
	commonA, proxyA, nameA := build(101)
	commonB, proxyB, nameB := build(102)
	if nameA == nameB || proxyA.Name == proxyB.Name {
		t.Fatalf("overlap cycles reused proxy name %q", nameA)
	}
	for label, proxy := range map[string]*v1.HTTPProxyConfig{"a": proxyA, "b": proxyB} {
		if proxy.SubDomain != "routing-resource" || proxy.LoadBalancer.Group != "routing-resource" || proxy.LoadBalancer.GroupKey != "routing-resource" {
			t.Errorf("cycle %s routing changed: %+v", label, proxy)
		}
		if proxy.LocalIP != "127.0.0.1" || proxy.LocalPort != 3000 {
			t.Errorf("cycle %s target changed: %s:%d", label, proxy.LocalIP, proxy.LocalPort)
		}
		if got := proxy.Metadatas[nhpconfig.MetaResourceID]; got != "public-resource" {
			t.Errorf("cycle %s public resource metadata = %q", label, got)
		}
	}
	for label, cycleCommon := range map[string]*v1.ClientCommonConfig{"a": commonA, "b": commonB} {
		if cycleCommon.ServerAddr != "frp.example" || cycleCommon.ServerPort != 7000 {
			t.Errorf("cycle %s admitted server = %s:%d", label, cycleCommon.ServerAddr, cycleCommon.ServerPort)
		}
		if cycleCommon.Metadatas[nhpconfig.MetaQURLKnockToken] != "token" || cycleCommon.Metadatas["preserved"] != "value" {
			t.Errorf("cycle %s Login metadata = %#v", label, cycleCommon.Metadatas)
		}
	}
	if _, ok := common.Metadatas[nhpconfig.MetaQURLKnockToken]; ok {
		t.Fatal("cycle token mutated the caller's common config")
	}
}

func TestFRPSessionFactoryRejectsUnsafeAdmittedHosts(t *testing.T) {
	tlsOn := true
	base := FRPFactoryConfig{
		Common: &v1.ClientCommonConfig{},
		Route: LocalHTTPRoute{
			RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
			ResourceID: "public-resource", ConnectorRoutingID: "routing-resource",
		},
	}
	admission := Admission{
		KnockResourceID: "q_catalog_key", ResourceID: "public-resource",
		RunID: "run", RunAttempt: 1, Token: "token", SessionID: 1,
		SessionReceipt: testSessionReceipt(1, "run", 1), OpenTime: time.Minute,
	}
	for _, resourceHost := range []string{"frp.example", "2001:db8::1", ":7000", "frp.example:0", "frp.example:65536"} {
		t.Run(resourceHost, func(t *testing.T) {
			factory, err := NewFRPSessionFactory(base)
			if err != nil {
				t.Fatal(err)
			}
			admission.ResourceHost = resourceHost
			if _, _, _, err := factory.BuildConfig(admission); err == nil {
				t.Fatal("unsafe admitted host was accepted")
			}
		})
	}

	t.Run("IP literal under implicit TLS SNI", func(t *testing.T) {
		cfg := base
		cfg.Common = &v1.ClientCommonConfig{}
		cfg.Common.Transport.TLS.Enable = &tlsOn
		factory, err := NewFRPSessionFactory(cfg)
		if err != nil {
			t.Fatal(err)
		}
		admission.ResourceHost = "127.0.0.1:7000"
		if _, _, _, err := factory.BuildConfig(admission); err == nil {
			t.Fatal("IP literal with TLS and no explicit server name was accepted")
		}
	})

	t.Run("bracketed IPv6 stays dialable", func(t *testing.T) {
		factory, err := NewFRPSessionFactory(base)
		if err != nil {
			t.Fatal(err)
		}
		admission.ResourceHost = "[2001:db8::1]:7000"
		common, _, _, err := factory.BuildConfig(admission)
		if err != nil {
			t.Fatal(err)
		}
		if common.ServerAddr != "[2001:db8::1]" || common.ServerPort != 7000 {
			t.Fatalf("admitted endpoint = %s:%d", common.ServerAddr, common.ServerPort)
		}
	})
}

type statusMap map[string]*frpproxy.WorkingStatus

func (s statusMap) GetProxyStatus(name string) (*frpproxy.WorkingStatus, bool) {
	item, ok := s[name]
	return item, ok
}

func TestServingReadinessRequiresEveryExactProxyRunning(t *testing.T) {
	status := statusMap{
		"cycle-a": {Phase: frpproxy.ProxyPhaseRunning},
		"cycle-b": {Phase: frpproxy.ProxyPhaseStartErr},
		"stale":   {Phase: frpproxy.ProxyPhaseRunning},
	}
	if proxiesRunning(status, []string{"cycle-a", "cycle-b"}) {
		t.Fatal("readiness accepted a configured proxy in start error")
	}
	status["cycle-b"].Phase = frpproxy.ProxyPhaseRunning
	if !proxiesRunning(status, []string{"cycle-a", "cycle-b"}) {
		t.Fatal("readiness rejected the exact configured running set")
	}
	delete(status, "cycle-b")
	if proxiesRunning(status, []string{"cycle-a", "cycle-b"}) {
		t.Fatal("readiness substituted an unrelated running proxy")
	}
}

func TestProxyStartErrorTaxonomy(t *testing.T) {
	tests := []struct {
		name string
		err  string
		want error
	}{
		{name: "stale knock", err: "knock_invalid: knock token expired", want: ErrAdmissionStale},
		{name: "missing owner", err: "owner_missing: connector identity missing", want: ErrAdmissionStale},
		{name: "serving session stale", err: "session_stale: serving session is stale", want: ErrAdmissionStale},
		{name: "gone", err: "resource_not_found: resource not found", want: ErrResourceGone},
		{name: "registration transient", err: "registration_failed: device registration unavailable"},
		{name: "rate transient", err: "rate_limited: retry later"},
		{name: "circuit transient", err: "circuit_open: control plane unavailable"},
		{name: "auth transient", err: "auth_error: validation unavailable"},
		{name: "embedded tag", err: "proxy knock_invalid: knock token expired"},
		{name: "leading whitespace", err: " knock_invalid: knock token expired"},
		{name: "missing exact delimiter", err: "knock_invalid:knock token expired"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status := statusMap{"cycle": {Phase: frpproxy.ProxyPhaseStartErr, Err: test.err}}
			running, err := inspectProxyStatuses(status, []string{"cycle"})
			if running {
				t.Fatal("start error reported running")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("inspect error = %v, want %v", err, test.want)
			}
			if test.want == nil && err != nil {
				t.Fatalf("transient/malformed tag terminated cycle: %v", err)
			}
		})
	}
}

type blockingFRPService struct{}

func (blockingFRPService) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (blockingFRPService) GracefulClose(time.Duration) {}

type closeDurationFRPService struct {
	duration chan time.Duration
}

func (s *closeDurationFRPService) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
func (s *closeDurationFRPService) GracefulClose(duration time.Duration) {
	s.duration <- duration
}

func TestFRPSessionRetirementDoesNotBlockReplacementRenewal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	service := &closeDurationFRPService{duration: make(chan time.Duration, 1)}
	session := &frpServingSession{
		svc: service, status: statusMap{}, names: []string{"cycle"}, poll: time.Millisecond,
		ready: make(chan struct{}), done: make(chan struct{}), cancel: cancel,
	}
	go session.run(ctx)
	if err := session.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if duration := <-service.duration; duration != 4*time.Second {
		t.Fatalf("retired FRP cycle grace duration = %v, want 4s", duration)
	}
}

type lockedStatus struct {
	mu   sync.Mutex
	item *frpproxy.WorkingStatus
}

func (s *lockedStatus) GetProxyStatus(string) (*frpproxy.WorkingStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copy := *s.item
	return &copy, true
}

func (s *lockedStatus) set(phase, err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.item.Phase = phase
	s.item.Err = err
}

func TestFRPSessionStatusTransitionsDriveExactLifecycle(t *testing.T) {
	start := func(status *lockedStatus) *frpServingSession {
		ctx, cancel := context.WithCancel(context.Background())
		session := &frpServingSession{
			svc: blockingFRPService{}, status: status, names: []string{"cycle"},
			poll: time.Millisecond, ready: make(chan struct{}), done: make(chan struct{}), cancel: cancel,
		}
		go session.run(ctx)
		return session
	}

	t.Run("transient remains same session", func(t *testing.T) {
		status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseStartErr, Err: "rate_limited: retry later"}}
		session := start(status)
		select {
		case <-session.Done():
			t.Fatalf("transient status ended session: %v", session.Err())
		case <-time.After(10 * time.Millisecond):
		}
		status.set(frpproxy.ProxyPhaseRunning, "")
		select {
		case <-session.Ready():
		case <-time.After(time.Second):
			t.Fatal("session did not become ready after same-session retry")
		}
		_ = session.Stop(context.Background())
	})

	t.Run("running session later loses admission", func(t *testing.T) {
		status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseRunning}}
		session := start(status)
		select {
		case <-session.Ready():
		case <-time.After(time.Second):
			t.Fatal("initial running status did not report ready")
		}
		status.set(frpproxy.ProxyPhaseStartErr, "knock_invalid: knock token expired")
		select {
		case <-session.Done():
		case <-time.After(time.Second):
			t.Fatal("later terminal status did not end the serving cycle")
		}
		if !errors.Is(session.Err(), ErrAdmissionStale) {
			t.Fatalf("session error = %v, want stale admission", session.Err())
		}
	})

	t.Run("running session later becomes stale", func(t *testing.T) {
		status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseRunning}}
		session := start(status)
		select {
		case <-session.Ready():
		case <-time.After(time.Second):
			t.Fatal("initial running status did not report ready")
		}
		status.set(frpproxy.ProxyPhaseStartErr, "session_stale: serving session is stale")
		select {
		case <-session.Done():
		case <-time.After(time.Second):
			t.Fatal("later stale-session status did not end the serving cycle")
		}
		if !errors.Is(session.Err(), ErrAdmissionStale) {
			t.Fatalf("session error = %v, want stale admission", session.Err())
		}
	})

	for name, test := range map[string]struct {
		statusErr string
		want      error
	}{
		"stale admission": {statusErr: "owner_missing: connector identity missing", want: ErrAdmissionStale},
		"gone resource":   {statusErr: "resource_not_found: resource not found", want: ErrResourceGone},
	} {
		t.Run(name, func(t *testing.T) {
			status := &lockedStatus{item: &frpproxy.WorkingStatus{Phase: frpproxy.ProxyPhaseStartErr, Err: test.statusErr}}
			session := start(status)
			select {
			case <-session.Done():
			case <-time.After(time.Second):
				t.Fatal("terminal start error did not end FRP cycle")
			}
			if !errors.Is(session.Err(), test.want) {
				t.Fatalf("session error = %v, want %v", session.Err(), test.want)
			}
		})
	}
}
