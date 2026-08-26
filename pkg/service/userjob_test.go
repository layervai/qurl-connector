package service

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderLaunchdUserJobCredentialFreeContract(t *testing.T) {
	job := UserJob{
		Label:       "ai.layerv.qurl.daemon",
		BinaryPath:  "/opt/homebrew/bin/qurl",
		Arguments:   []string{"daemon", "run"},
		StandardOut: "/Users/dev/Library/Logs/qurl/daemon.log",
		StandardErr: "/Users/dev/Library/Logs/qurl/daemon.err",
		RunAtLoad:   true,
		KeepAlive:   true,
	}
	got, err := RenderLaunchdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<string>ai.layerv.qurl.daemon</string>",
		"<string>/opt/homebrew/bin/qurl</string>",
		"<string>daemon</string>",
		"<string>run</string>",
		"<key>RunAtLoad</key>\n    <true/>",
		"<key>KeepAlive</key>\n    <true/>",
		"<integer>15</integer>",
		"<key>Umask</key>\n    <integer>63</integer>",
		"<string>Background</string>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rendered plist missing %q\n%s", want, got)
		}
	}
	for _, forbidden := range []string{"EnvironmentVariables", "QURL_API_KEY", "token"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("credential-free plist contains %q", forbidden)
		}
	}
}

func TestRenderLaunchdUserJobEscapesXML(t *testing.T) {
	got, err := RenderLaunchdUserJob(UserJob{
		Label:       "ai.layerv.qurl.daemon",
		BinaryPath:  "/Applications/qurl & tools/qurl",
		Arguments:   []string{"daemon", "run", "a<b"},
		StandardOut: "/tmp/qurl & daemon/out.log",
		StandardErr: "/tmp/qurl & daemon/err.log",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "qurl & tools") || strings.Contains(got, "a<b") {
		t.Fatalf("XML metacharacters were not escaped:\n%s", got)
	}
	if !strings.Contains(got, "qurl &amp; tools") || !strings.Contains(got, "a&lt;b") {
		t.Fatalf("escaped values missing:\n%s", got)
	}
}

func TestRenderLaunchdUserJobRejectsUnsafeShape(t *testing.T) {
	base := UserJob{
		Label:       "ai.layerv.qurl.daemon",
		BinaryPath:  "/usr/local/bin/qurl",
		StandardOut: "/tmp/out.log",
		StandardErr: "/tmp/err.log",
	}
	cases := []struct {
		name string
		edit func(*UserJob)
	}{
		{"invalid label", func(j *UserJob) { j.Label = "../../job" }},
		{"relative binary", func(j *UserJob) { j.BinaryPath = "qurl" }},
		{"relative stdout", func(j *UserJob) { j.StandardOut = "out.log" }},
		{"bad timeout", func(j *UserJob) { j.ExitTimeout = 301 }},
		{"bad umask", func(j *UserJob) { j.Umask = 0o1000 }},
		{"nul argument", func(j *UserJob) { j.Arguments = []string{"daemon\x00run"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			job := base
			tc.edit(&job)
			if _, err := RenderLaunchdUserJob(job); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestUserJobPlistPath(t *testing.T) {
	home := filepath.Join(string(filepath.Separator), "Users", "dev")
	got, err := UserJobPlistPath(home, "ai.layerv.qurl.daemon")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "Library", "LaunchAgents", "ai.layerv.qurl.daemon.plist")
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}
