package service

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderLaunchdUserJobCredentialFreeContract(t *testing.T) {
	dir := t.TempDir()
	job := UserJob{
		Label:       "ai.layerv.qurl.daemon",
		BinaryPath:  filepath.Join(dir, "qurl"),
		Arguments:   []string{"daemon", "run"},
		StandardOut: filepath.Join(dir, "daemon.log"),
		StandardErr: filepath.Join(dir, "daemon.err"),
		RunAtLoad:   true,
		KeepAlive:   true,
	}
	got, err := RenderLaunchdUserJob(job)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<string>ai.layerv.qurl.daemon</string>",
		"<string>" + job.BinaryPath + "</string>",
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
	dir := t.TempDir()
	got, err := RenderLaunchdUserJob(UserJob{
		Label:       "ai.layerv.qurl.daemon",
		BinaryPath:  filepath.Join(dir, "qurl & tools", "qurl"),
		Arguments:   []string{"daemon", "run", "a<b"},
		StandardOut: filepath.Join(dir, "qurl & daemon", "out.log"),
		StandardErr: filepath.Join(dir, "qurl & daemon", "err.log"),
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
	dir := t.TempDir()
	base := UserJob{
		Label:       "ai.layerv.qurl.daemon",
		BinaryPath:  filepath.Join(dir, "qurl"),
		StandardOut: filepath.Join(dir, "out.log"),
		StandardErr: filepath.Join(dir, "err.log"),
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
	home := t.TempDir()
	got, err := UserJobPlistPath(home, "ai.layerv.qurl.daemon")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, "Library", "LaunchAgents", "ai.layerv.qurl.daemon.plist")
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}
