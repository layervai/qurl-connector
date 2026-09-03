package main

import (
	goast "go/ast"
	goparser "go/parser"
	gotoken "go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// withColorEnabled forces the color gate for one test and restores whatever
// init() resolved from the real stdout afterwards.
//
// Every test here forces the gate explicitly rather than reading it, because
// the ambient answer under `go test` depends on whether the test binary's
// stdout is a pipe — true under `make test`, not necessarily true when a
// developer runs the binary directly. A test that inherited that would assert
// different things on different machines.
func withColorEnabled(t *testing.T, enabled bool) {
	t.Helper()
	previous := colorEnabled
	setColorEnabled(enabled)
	t.Cleanup(func() { setColorEnabled(previous) })
}

func TestColorOutputEnabled(t *testing.T) {
	// NO_COLOR's contract (https://no-color.org/) is presence-based, not
	// value-based: "0" and "false" disable color exactly like "1" does, and
	// only unset — or set to the empty string — defers to the terminal check.
	// Getting that backwards is the classic implementation bug, so the
	// falsey-looking values are pinned individually.
	for _, tc := range []struct {
		name    string
		isTTY   bool
		env     map[string]string
		want    bool
		because string
	}{
		{name: "terminal without NO_COLOR", isTTY: true, want: true,
			because: "an interactive operator is the one case color is for"},
		{name: "pipe without NO_COLOR", isTTY: false, want: false,
			because: "docker logs and the journal capture a pipe"},
		{name: "terminal with NO_COLOR=1", isTTY: true, env: map[string]string{envNoColor: "1"}, want: false},
		{name: "terminal with NO_COLOR=0", isTTY: true, env: map[string]string{envNoColor: "0"}, want: false,
			because: "NO_COLOR is presence-based; 0 still means no color"},
		{name: "terminal with NO_COLOR=false", isTTY: true, env: map[string]string{envNoColor: "false"}, want: false,
			because: "NO_COLOR is presence-based regardless of value"},
		{name: "terminal with empty NO_COLOR", isTTY: true, env: map[string]string{envNoColor: ""}, want: true,
			because: "the spec exempts the empty string, so the terminal check still decides"},
		{name: "pipe with NO_COLOR", isTTY: false, env: map[string]string{envNoColor: "1"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lookup := func(key string) (string, bool) {
				v, ok := tc.env[key]
				return v, ok
			}
			if got := colorOutputEnabled(tc.isTTY, lookup); got != tc.want {
				t.Fatalf("colorOutputEnabled(%v, %v) = %v, want %v: %s", tc.isTTY, tc.env, got, tc.want, tc.because)
			}
		})
	}
}

func TestColorOutputEnabledReadsOnlyNoColor(t *testing.T) {
	// Guards against a future edit reaching for os.Getenv directly (which
	// would make the decision untestable) or growing a second variable
	// without a test: any lookup other than NO_COLOR fails here.
	var seen []string
	lookup := func(key string) (string, bool) {
		seen = append(seen, key)
		return "", false
	}
	colorOutputEnabled(true, lookup)
	if len(seen) != 1 || seen[0] != envNoColor {
		t.Fatalf("looked up %v, want exactly [%s]", seen, envNoColor)
	}
}

func TestSetColorEnabledFlipsEveryEscapeTogether(t *testing.T) {
	// Named pairs so a newly added escape that someone forgets to blank in
	// the disabled branch fails here rather than leaking into a journal.
	escapes := func() []struct {
		name string
		got  *string
		want string
	} {
		return []struct {
			name string
			got  *string
			want string
		}{
			{"colorReset", &colorReset, ansiReset},
			{"colorGreen", &colorGreen, ansiGreen},
			{"colorYellow", &colorYellow, ansiYellow},
			{"colorCyan", &colorCyan, ansiCyan},
			{"colorBold", &colorBold, ansiBold},
		}
	}

	withColorEnabled(t, true)
	if !colorEnabled {
		t.Fatal("colorEnabled = false after setColorEnabled(true)")
	}
	for _, e := range escapes() {
		if *e.got != e.want {
			t.Fatalf("%s = %q with color enabled, want %q", e.name, *e.got, e.want)
		}
	}

	setColorEnabled(false)
	if colorEnabled {
		t.Fatal("colorEnabled = true after setColorEnabled(false)")
	}
	for _, e := range escapes() {
		if *e.got != "" {
			t.Fatalf("%s = %q with color disabled, want empty", e.name, *e.got)
		}
	}
}

func TestStdoutIsTerminal(t *testing.T) {
	// os.Stdout is swapped rather than mocked because the production call
	// reads os.Stdout directly at init; the swap is what proves the
	// character-device check, not a stand-in for it. Not parallel-safe, like
	// the other stdout-swapping tests in this package.
	orig := os.Stdout
	t.Cleanup(func() { os.Stdout = orig })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = w.Close()
		_ = r.Close()
	})
	os.Stdout = w
	if stdoutIsTerminal() {
		t.Fatal("stdoutIsTerminal() = true for a pipe; this is the docker logs / journald case that must report false")
	}

	regular, err := os.Create(filepath.Join(t.TempDir(), "stdout.log"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = regular.Close() })
	os.Stdout = regular
	if stdoutIsTerminal() {
		t.Fatal("stdoutIsTerminal() = true for a regular file, want false")
	}

	if runtime.GOOS == "windows" {
		return
	}
	// A character device is the positive branch. /dev/null is one without
	// needing a controlling terminal, which a test process is not guaranteed
	// to have — so this covers the true path that would otherwise go
	// unexercised in CI.
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = devNull.Close() })
	os.Stdout = devNull
	if !stdoutIsTerminal() {
		t.Fatalf("stdoutIsTerminal() = false for the character device %s, want true", os.DevNull)
	}
}

func TestPrintBannerHonorsColorGate(t *testing.T) {
	withColorEnabled(t, true)
	colored, err := withCapturedStdout(t, func() error {
		printBanner()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colored, ansiBold) || !strings.Contains(colored, ansiCyan) {
		t.Fatalf("banner lost its color with the gate on:\n%q", colored)
	}

	setColorEnabled(false)
	plain, err := withCapturedStdout(t, func() error {
		printBanner()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertNoANSI(t, "printBanner", plain)
	// The gate must remove escapes, not content: the banner art and the
	// version line still have to reach the journal.
	if !strings.Contains(plain, "Connector") {
		t.Fatalf("banner art missing with color off:\n%q", plain)
	}
	if !strings.Contains(plain, "qurl-connector") {
		t.Fatalf("version line missing with color off:\n%q", plain)
	}
}

func TestRunStatusHumanOutputHonorsColorGate(t *testing.T) {
	dir := realPrivateConnectorTestDir(t)
	isolateConnectorStateForTest(t, dir)
	cfgPath := filepath.Join(dir, "qurl-proxy.yaml")
	// admin stays disabled so status renders the on-disk view and never
	// probes a listener; the colored surface here is the header, the
	// Service/Hint lines, and the route table's per-status color.
	if err := os.WriteFile(cfgPath, []byte("routes:\n  - id: web\n    type: http\n    local_ip: 127.0.0.1\n    local_port: 8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previousCfgFile, previousJSON := cfgFile, statusJSON
	cfgFile, statusJSON = cfgPath, false
	t.Cleanup(func() { cfgFile, statusJSON = previousCfgFile, previousJSON })

	withColorEnabled(t, true)
	colored, err := withCapturedStdout(t, func() error { return runStatus(nil, nil) })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(colored, ansiBold) {
		t.Fatalf("status header lost its color with the gate on:\n%q", colored)
	}

	setColorEnabled(false)
	plain, err := withCapturedStdout(t, func() error { return runStatus(nil, nil) })
	if err != nil {
		t.Fatal(err)
	}
	assertNoANSI(t, "runStatus", plain)
	if !strings.Contains(plain, "qURL Connector Status") {
		t.Fatalf("status header text missing with color off:\n%q", plain)
	}
	if !strings.Contains(plain, "web") {
		t.Fatalf("route row missing with color off:\n%q", plain)
	}
}

func TestReadyBlockHonorsColorGate(t *testing.T) {
	// The readiness block is the print this gate exists for. It is designed to
	// be read by non-interactive log consumers, so escapes in it land squarely
	// in the stream least able to render them.
	live := []readyRoute{
		{routeID: "web", target: "127.0.0.1:8080"},
		{routeID: "internal-api", target: "127.0.0.1:9000"},
	}
	announcer := newReadyAnnouncer(live, nil, true)

	withColorEnabled(t, true)
	announcer.interactive = true
	colored := announcer.render(live, nil)
	if !strings.Contains(colored, ansiGreen) || !strings.Contains(colored, ansiCyan) {
		t.Fatalf("ready block lost its color with the gate on:\n%q", colored)
	}

	// interactive is a separate axis from color: NO_COLOR on a real terminal
	// still leaves a Ctrl+C to press, and a pipe has neither. Both are checked
	// so a future edit cannot collapse the two into one flag.
	setColorEnabled(false)
	for _, interactive := range []bool{true, false} {
		announcer.interactive = interactive
		plain := announcer.render(live, nil)
		assertNoANSI(t, "readyAnnouncer.render", plain)
		for _, want := range []string{"Connector is running", "2 route(s) live", "web", "internal-api", "127.0.0.1:9000"} {
			if !strings.Contains(plain, want) {
				t.Fatalf("interactive=%v: ready block dropped %q with color off:\n%q", interactive, want, plain)
			}
		}
		if got := strings.Contains(plain, "Ctrl+C"); got != interactive {
			t.Fatalf("interactive=%v: Ctrl+C present = %v, want %v", interactive, got, interactive)
		}
	}
}

func TestApplyLogPresentationTracksColorGate(t *testing.T) {
	// FRP's console stream carries its own color switch. If this drifts from
	// the gate, `docker logs` gets our lines clean and FRP's still escaped,
	// which is the same defect with a smaller blast radius.
	for _, useColor := range []bool{true, false} {
		common := &v1.ClientCommonConfig{}
		applyLogPresentation(common, "warn", useColor)
		if common.Log.Level != "warn" {
			t.Fatalf("Log.Level = %q, want warn", common.Log.Level)
		}
		if want := !useColor; common.Log.DisablePrintColor != want {
			t.Fatalf("useColor=%v: Log.DisablePrintColor = %v, want %v", useColor, common.Log.DisablePrintColor, want)
		}
	}
}

// escANSI is the byte an ANSI sequence opens with. Detection decodes string
// literals down to this rather than pattern-matching their source form, so
// "\033[", "\x1b[", "\u001b[", and a raw ESC pasted into a literal are all
// one case.
const escANSI = '\x1b'

// ansiEscapeLines parses Go source and returns the 1-based lines of any string
// or rune literal that decodes to text containing ESC.
//
// It parses rather than scans lines because prose legitimately mentions these
// sequences — this file's own comments do, and so does the one in
// applyLogPresentation explaining why FRP's stream is gated too. A line-based
// scanner flags those, and a guard that cries wolf gets deleted.
func ansiEscapeLines(t *testing.T, filename string, src []byte) []int {
	t.Helper()
	fset := gotoken.NewFileSet()
	parsed, err := goparser.ParseFile(fset, filename, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}
	var lines []int
	goast.Inspect(parsed, func(n goast.Node) bool {
		lit, ok := n.(*goast.BasicLit)
		if !ok || (lit.Kind != gotoken.STRING && lit.Kind != gotoken.CHAR) {
			return true
		}
		// An unquote failure means a literal form this check does not
		// understand; the compiler already rejects genuinely invalid ones, so
		// skipping is safe here rather than a hole.
		value, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if strings.ContainsRune(value, escANSI) {
			lines = append(lines, fset.Position(lit.Pos()).Line)
		}
		return true
	})
	return lines
}

func TestNoRawANSIEscapesOutsideColorGate(t *testing.T) {
	// The gate holds only while every print site goes through the color
	// variables. A new fmt.Printf with an escape baked into the format string
	// would be invisible to the tests above — it would look right in a
	// terminal and corrupt the journal — so the source is checked as well as
	// the behavior.
	//
	// This is what makes the change repo-wide rather than a fix to the three
	// files that happened to carry escapes when it was written: it covers
	// files that do not exist yet, including the readiness block still in
	// flight on its own branch.
	repoRoot := testRepoRoot(t)
	allowed := filepath.ToSlash(filepath.Join("cmd", "frpc", "color.go"))

	var offenders []string
	for _, dir := range []string{"cmd", "pkg", "internal"} {
		root := filepath.Join(repoRoot, dir)
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			rel = filepath.ToSlash(rel)
			if rel == allowed {
				return nil
			}
			src, readErr := os.ReadFile(path) //nolint:gosec // G304: repo-local path produced by the walk above
			if readErr != nil {
				return readErr
			}
			for _, line := range ansiEscapeLines(t, path, src) {
				offenders = append(offenders, rel+":"+strconv.Itoa(line))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("ANSI escapes in string literals outside %s at %v\n"+
			"Print sites must use the colorReset/colorGreen/colorYellow/colorCyan/colorBold\n"+
			"variables so the escape disappears when stdout is a pipe (docker logs, journald)\n"+
			"or NO_COLOR is set. A genuinely new escape belongs in %s, not at the call site.",
			allowed, offenders, allowed)
	}
}

func TestANSIEscapeDetectorFindsEveryLiteralForm(t *testing.T) {
	// The guard above is only as good as this detector, and a detector that
	// quietly stopped matching would leave it permanently green.
	for _, form := range []string{
		`fmt.Printf("\033[32mok\033[0m")`,
		`const green = "\x1b[32m"`,
		`const green = "\x1B[32m"`,
		`const green = "\u001b[32m"`,
		"const green = `" + "\x1b" + "[32m`", // raw ESC byte inside a raw string literal
		`const esc = '\x1b'`,
	} {
		src := []byte("package p\n\nfunc f() {\n\t" + form + "\n}\n")
		if got := ansiEscapeLines(t, "form.go", src); len(got) == 0 {
			t.Fatalf("detector missed %s", form)
		}
	}

	benign := []byte("package p\n\n" +
		"// Prose may name \\033[32m and \\x1b[0m without being an offender.\n" +
		"func f() {\n" +
		"\tfmt.Printf(\"  Config: %s%s%s\\n\", colorCyan, cfgPath, colorReset)\n" +
		"\tre := regexp.MustCompile(\"^[a-z]+$\")\n" +
		"}\n")
	if got := ansiEscapeLines(t, "benign.go", benign); len(got) != 0 {
		t.Fatalf("detector false-positived on lines %v of gated call sites and prose", got)
	}
}

// assertNoANSI fails when out carries an ESC byte, checking the rendered
// output rather than the source: this is the byte a log consumer actually
// receives.
func assertNoANSI(t *testing.T, what, out string) {
	t.Helper()
	if strings.ContainsRune(out, '\x1b') {
		t.Fatalf("%s emitted ANSI escapes with color disabled; a piped journal would carry them literally:\n%q", what, out)
	}
}
