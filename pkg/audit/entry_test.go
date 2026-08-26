package audit

import "testing"

// TestEventWireValues pins the audit event taxonomy to its exact emitted
// strings. The `event` field is a stable wire surface: external log
// pipelines, dashboards, and the public audit-logging docs all filter on
// these literals (see the Event* godoc in entry.go). Every other audit
// test references these constants symbolically, so they pass regardless
// of the constant *values* — this test is the only thing in CI that
// catches an accidental rename of the wire string itself.
func TestEventWireValues(t *testing.T) {
	cases := []struct {
		got  string
		want string
	}{
		{EventBootstrapSuccess, "qurl.connector.bootstrap.success"},
		{EventBootstrapDeny, "qurl.connector.bootstrap.deny"},
		{EventBootstrapError, "qurl.connector.bootstrap.error"},
		{EventKnockSuccess, "qurl.connector.knock.success"},
		{EventKnockDeny, "qurl.connector.knock.deny"},
		{EventKnockError, "qurl.connector.knock.error"},
		{EventLoginSuccess, "qurl.connector.login.success"},
		{EventLoginDeny, "qurl.connector.login.deny"},
		{EventLoginError, "qurl.connector.login.error"},
		{EventProxyAllow, "qurl.connector.proxy.allow"},
		{EventProxyDeny, "qurl.connector.proxy.deny"},
		{EventProxyError, "qurl.connector.proxy.error"},
		{EventTeardown, "qurl.connector.teardown"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("audit event wire value = %q, want %q", c.got, c.want)
		}
	}
}
