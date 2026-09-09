package share

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"strings"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"gopkg.in/yaml.v3"
)

// Names and values below are chosen to be recognizable in any output they
// leak into; no test constant is a real credential.
const (
	testProxyTokenHeader = "X-QURL-Desktop-Proxy-Token"
	testProxyTokenValue  = "runtime-secret-do-not-disclose"
)

func headeredTestRoute() LocalHTTPRoute {
	return LocalHTTPRoute{
		RouteID: "local-app", LocalIP: "127.0.0.1", LocalPort: 3000,
		ResourcePublicKey: "public-resource", ConnectorRoutingID: "routing-resource",
		RequestHeaders: map[string]string{testProxyTokenHeader: testProxyTokenValue},
	}
}

func TestLocalHTTPRouteStringRedactsHeaders(t *testing.T) {
	route := headeredTestRoute()
	group := GroupRoute{LocalHTTPRoute: route, Generation: 7}
	state := RouteState{Route: group, ProxyName: "local-app-nhp2t-r7", Phase: RouteServing}
	for _, test := range []struct {
		name  string
		value any
	}{
		{name: "route", value: route},
		{name: "route pointer", value: &route},
		{name: "group route", value: group},
		{name: "group route pointer", value: &group},
		{name: "route state", value: state},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
				formatted := fmt.Sprintf(format, test.value)
				if !strings.Contains(formatted, "RequestHeaders:[REDACTED]") {
					t.Fatalf("%s omitted the redaction marker: %s", format, formatted)
				}
				for _, secret := range []string{testProxyTokenHeader, testProxyTokenValue} {
					if strings.Contains(formatted, secret) {
						t.Fatalf("%s disclosed runtime request headers: %s", format, formatted)
					}
				}
				if !strings.Contains(formatted, "local-app") {
					t.Fatalf("%s lost the route identity: %s", format, formatted)
				}
			}
		})
	}
	if formatted := fmt.Sprintf("%v", group); !strings.Contains(formatted, "Generation:7") {
		t.Fatalf("group route formatting lost its generation: %s", formatted)
	}
}

func TestLocalHTTPRouteSerializationOmitsRequestHeaders(t *testing.T) {
	route := headeredTestRoute()
	for _, valueTest := range []struct {
		name  string
		value any
	}{
		{name: "route", value: route},
		{name: "group route", value: GroupRoute{LocalHTTPRoute: route, Generation: 1}},
	} {
		t.Run(valueTest.name, func(t *testing.T) {
			for _, codec := range []struct {
				name    string
				marshal func(any) ([]byte, error)
			}{
				{name: "JSON", marshal: json.Marshal},
				{name: "YAML", marshal: yaml.Marshal},
			} {
				t.Run(codec.name, func(t *testing.T) {
					encoded, err := codec.marshal(valueTest.value)
					if err != nil {
						t.Fatal(err)
					}
					for _, forbidden := range []string{"RequestHeaders", "requestheaders", testProxyTokenHeader, testProxyTokenValue} {
						if strings.Contains(string(encoded), forbidden) {
							t.Fatalf("serialization disclosed runtime request headers: %s", encoded)
						}
					}
					if !strings.Contains(string(encoded), "local-app") {
						t.Fatalf("serialization lost the route identity: %s", encoded)
					}
				})
			}
		})
	}
}

func TestValidateRequestHeadersRejectsInvalidWithoutDisclosingThem(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		wantErr string
		secrets []string
	}{
		{
			name:    "invalid name",
			headers: map[string]string{"X Invalid top-secret-name": "top-secret-value"},
			wantErr: "request header name is invalid",
			secrets: []string{"top-secret-name", "top-secret-value"},
		},
		{
			name:    "empty name",
			headers: map[string]string{"": "top-secret-value"},
			wantErr: "request header name is invalid",
			secrets: []string{"top-secret-value"},
		},
		{
			name:    "carriage return and line feed",
			headers: map[string]string{"X-QURL-Share-Token": "top-secret-value\r\nX-Injected: true"},
			wantErr: "request header value is invalid",
			secrets: []string{"top-secret-value", "X-Injected"},
		},
		{
			name:    "bare line feed",
			headers: map[string]string{"X-QURL-Share-Token": "top-secret-value\n"},
			wantErr: "request header value is invalid",
			secrets: []string{"top-secret-value"},
		},
		{
			name:    "delete control byte",
			headers: map[string]string{"X-QURL-Share-Token": "top-secret-value\x7f"},
			wantErr: "request header value is invalid",
			secrets: []string{"top-secret-value"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateRequestHeaders(test.headers)
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

func TestValidateRequestHeadersAcceptsTransportSafeValues(t *testing.T) {
	for _, test := range []struct {
		name    string
		headers map[string]string
	}{
		{name: "nil map"},
		{name: "empty map", headers: map[string]string{}},
		{name: "empty value", headers: map[string]string{"X-QURL-Marker": ""}},
		{name: "horizontal tab", headers: map[string]string{"X-QURL-Metadata": "left\tright"}},
		{name: "obs text", headers: map[string]string{"X-QURL-Metadata": "café"}},
		{name: "token name characters", headers: map[string]string{"x-qurl.token_1!#$%&'*+^`|~": "value"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateRequestHeaders(test.headers); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestValidateRequestHeadersIsDeterministic(t *testing.T) {
	headers := map[string]string{
		"A-Bad-Value": "top-secret-value\n",
		"B Bad Name":  "top-secret-value",
		"Connection":  "top-secret-value",
		"X-Duplicate": "top-secret-value",
		"x-duplicate": "second-secret-value",
	}
	const wantErr = "request header value is invalid"
	for i := 0; i < 128; i++ {
		err := ValidateRequestHeaders(headers)
		if err == nil {
			t.Fatal("multiply-invalid request headers were accepted")
		}
		if got := err.Error(); got != wantErr {
			t.Fatalf("validation pass %d returned %q, want deterministic error %q", i, got, wantErr)
		}
	}
}

func TestValidateRequestHeadersBoundsCountAndBytes(t *testing.T) {
	const (
		wantMaxHeaderCount = 16
		wantMaxHeaderBytes = 1024
		wantLimitError     = "request headers exceed runtime limits"
	)
	if maxRuntimeRequestHeaderCount != wantMaxHeaderCount || maxRuntimeRequestHeaderBytes != wantMaxHeaderBytes {
		t.Fatalf("runtime limits = %d entries, %d bytes; want %d, %d", maxRuntimeRequestHeaderCount, maxRuntimeRequestHeaderBytes, wantMaxHeaderCount, wantMaxHeaderBytes)
	}
	countHeaders := func(count int) map[string]string {
		headers := make(map[string]string, count)
		for i := 0; i < count; i++ {
			headers["X-Empty-"+string(rune('A'+i))] = ""
		}
		return headers
	}
	const aggregateName = "X-Limit"
	tests := []struct {
		name    string
		headers map[string]string
		wantErr string
	}{
		{name: "exact header count with empty values", headers: countHeaders(wantMaxHeaderCount)},
		{name: "over header count", headers: countHeaders(wantMaxHeaderCount + 1), wantErr: wantLimitError},
		{
			name:    "exact aggregate bytes",
			headers: map[string]string{aggregateName: strings.Repeat("s", wantMaxHeaderBytes-len(aggregateName))},
		},
		{
			name:    "over aggregate bytes",
			headers: map[string]string{aggregateName: strings.Repeat("s", wantMaxHeaderBytes-len(aggregateName)+1)},
			wantErr: wantLimitError,
		},
		{
			name:    "over aggregate bytes by name alone",
			headers: map[string]string{strings.Repeat("X", wantMaxHeaderBytes+1): ""},
			wantErr: wantLimitError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateRequestHeaders(test.headers)
			if test.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("request headers over the runtime limit were accepted")
			}
			if got := err.Error(); got != test.wantErr {
				t.Fatalf("limit error = %q, want fixed error %q", got, test.wantErr)
			}
			if strings.Contains(err.Error(), aggregateName) || strings.Contains(err.Error(), "ssss") || strings.Contains(err.Error(), "XXXX") {
				t.Fatalf("limit error disclosed request-header input: %q", err)
			}
		})
	}
}

func TestValidateRequestHeadersRejectsCaseInsensitiveDuplicateNames(t *testing.T) {
	err := ValidateRequestHeaders(map[string]string{
		"X-QURL-Share-Token": "runtime-secret-value",
		"x-qurl-share-token": "second-secret-value",
	})
	if err == nil {
		t.Fatal("case-insensitive duplicate request header names were accepted")
	}
	const wantErr = "request header names are duplicated"
	if got := err.Error(); got != wantErr {
		t.Fatalf("validation error = %q, want fixed error %q", got, wantErr)
	}
	for _, secret := range []string{"X-QURL-Share-Token", "runtime-secret-value", "second-secret-value"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("validation error disclosed request-header input: %q", err)
		}
	}
}

func TestValidateRequestHeadersRejectsReservedNames(t *testing.T) {
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
		for _, spelled := range []string{headerName, strings.ToLower(headerName), strings.ToUpper(headerName)} {
			t.Run(spelled, func(t *testing.T) {
				err := ValidateRequestHeaders(map[string]string{spelled: "runtime-secret-value"})
				if err == nil {
					t.Fatalf("reserved request header %q was accepted", spelled)
				}
				const wantErr = "request header name is reserved"
				if got := err.Error(); got != wantErr {
					t.Fatalf("validation error = %q, want fixed error %q", got, wantErr)
				}
				for _, secret := range []string{spelled, "runtime-secret-value"} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("validation error disclosed request-header input: %q", err)
					}
				}
			})
		}
	}
}

func TestRequestHeadersDigest(t *testing.T) {
	if got := RequestHeadersDigest(nil); got != "" {
		t.Fatalf("digest of nil = %q, want empty", got)
	}
	if got := RequestHeadersDigest(map[string]string{}); got != "" {
		t.Fatalf("digest of empty map = %q, want empty", got)
	}
	// The format is pinned so another process can reproduce a digest: the
	// entries as sorted name=value lines, SHA-256, lowercase hex.
	sum := sha256.Sum256([]byte("A=1\nB=2\n"))
	want := hex.EncodeToString(sum[:])
	if got := RequestHeadersDigest(map[string]string{"B": "2", "A": "1"}); got != want {
		t.Fatalf("digest = %q, want %q", got, want)
	}
	base := RequestHeadersDigest(map[string]string{"X-A": "1", "X-B": "2"})
	for name, headers := range map[string]map[string]string{
		"changed value":   {"X-A": "1", "X-B": "3"},
		"changed name":    {"X-A": "1", "X-C": "2"},
		"changed case":    {"x-a": "1", "X-B": "2"},
		"dropped entry":   {"X-A": "1"},
		"added entry":     {"X-A": "1", "X-B": "2", "X-C": ""},
		"moved separator": {"X-A": "1\nX-B", "X-B": "2"},
	} {
		if got := RequestHeadersDigest(headers); got == base || len(got) != 64 {
			t.Fatalf("%s: digest %q did not distinguish the header set from %q", name, got, base)
		}
	}
}

// LocalHTTPRoute is not comparable with == once it carries a map, so the
// runner's change detection is a method. This guards it against a field
// added later and forgotten there: a route that differs in any field is a
// different registration.
func TestLocalHTTPRouteEqualCoversEveryField(t *testing.T) {
	base := headeredTestRoute()
	if !base.Equal(base) {
		t.Fatal("a route is not equal to itself")
	}
	typ := reflect.TypeOf(base)
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		changed := base
		changed.RequestHeaders = maps.Clone(base.RequestHeaders)
		value := reflect.ValueOf(&changed).Elem().Field(i)
		switch value.Kind() {
		case reflect.String:
			value.SetString(value.String() + "-changed")
		case reflect.Int:
			value.SetInt(value.Int() + 1)
		case reflect.Map:
			value.SetMapIndex(reflect.ValueOf(testProxyTokenHeader), reflect.ValueOf("changed"))
		default:
			t.Fatalf("field %s has kind %s; teach this test how to perturb it", field.Name, value.Kind())
		}
		if base.Equal(changed) {
			t.Fatalf("equal ignores field %s", field.Name)
		}
	}
	headerless := headeredTestRoute()
	headerless.RequestHeaders = nil
	empty := headeredTestRoute()
	empty.RequestHeaders = map[string]string{}
	if !headerless.Equal(empty) || !empty.Equal(headerless) {
		t.Fatal("nil and empty request headers are the same headerless registration")
	}
	if headerless.Equal(base) {
		t.Fatal("a headerless route equals a headered one")
	}
	generation := GroupRoute{LocalHTTPRoute: base, Generation: 1}
	if generation.Equal(GroupRoute{LocalHTTPRoute: base}) {
		t.Fatal("group route equality ignores the generation")
	}
	if !generation.Equal(GroupRoute{LocalHTTPRoute: headeredTestRoute(), Generation: 1}) {
		t.Fatal("group routes with the same registration are unequal")
	}
}

func TestBuildAdmittedCommonClonesTransportEncryptionSetting(t *testing.T) {
	enabled := true
	common := &v1.ClientCommonConfig{}
	common.Transport.TLS.Enable = &enabled
	rendered, err := buildAdmittedCommon(common, groupTestAdmission(101), "")
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
