package main

import "os"

// ANSI color gating for every line this CLI prints itself.
//
// Stdout is a terminal only some of the time. The customer install runs
// `qurl-connector run` in the foreground of a container or under
// systemd/launchd, where stdout is a pipe feeding `docker logs` or the journal
// — and an escape sequence written there is not color, it is a literal
// `\x1b[32m` wedged into the operator's log search and their grep patterns.
//
// So the escapes live in variables resolved once at process start, empty
// whenever stdout is not a terminal or NO_COLOR is set. Call sites keep the
// shape they already had:
//
//	fmt.Printf("  %sNative registration OK%s\n", colorGreen, colorReset)
//
// which formats to a bare `Native registration OK` when color is off. That is
// what makes the gate hold across the whole binary rather than one print block
// at a time: a new call site is gated by construction, and adding a raw escape
// instead is what TestNoRawANSIEscapesOutsideColorGate exists to catch.
const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
)

// envNoColor is the cross-vendor opt-out from https://no-color.org/. Present
// and non-empty disables color *regardless of its value*, so `NO_COLOR=0` and
// `NO_COLOR=false` turn color off like every other value — the presence of the
// variable is the signal, not what it says. Only unset (or set to the empty
// string) leaves the terminal check in charge.
const envNoColor = "NO_COLOR"

// The escapes as the print sites see them. Empty strings when color is off.
//
// Deliberately variables rather than constants: the whole point is that their
// value depends on where stdout goes, which is not known until the process
// starts. Nothing mutates them after init outside tests.
var (
	colorReset  string
	colorGreen  string
	colorYellow string
	colorCyan   string
	colorBold   string
)

// colorEnabled is the resolved decision, retained so subsystems carrying a
// color switch of their own get handed the same answer instead of drifting
// from it. Today that is FRP's console log stream, whose
// Log.DisablePrintColor startFRPFromConfig sets from this — otherwise a
// journal would come out half-gated, our lines clean and FRP's still escaped.
var colorEnabled bool

func init() {
	setColorEnabled(colorOutputEnabled(stdoutIsTerminal(), os.LookupEnv))
}

// colorOutputEnabled decides whether to emit ANSI escapes. Its inputs are
// parameters rather than reads of the ambient process so the decision is
// testable without a terminal and without mutating the environment.
func colorOutputEnabled(stdoutIsTTY bool, lookupEnv func(string) (string, bool)) bool {
	if v, ok := lookupEnv(envNoColor); ok && v != "" {
		return false
	}
	return stdoutIsTTY
}

// setColorEnabled points every escape variable at its sequence or at the empty
// string, together. One writer for all of them: a partial flip would emit a
// colorReset with no opening escape, or worse leave a terminal colored after
// the line ended.
func setColorEnabled(enabled bool) {
	colorEnabled = enabled
	if !enabled {
		colorReset, colorGreen, colorYellow, colorCyan, colorBold = "", "", "", "", ""
		return
	}
	colorReset, colorGreen, colorYellow, colorCyan, colorBold = ansiReset, ansiGreen, ansiYellow, ansiCyan, ansiBold
}

// stdoutIsTerminal reports whether stdout is attached to a terminal, using the
// character-device check rather than adding a terminal dependency. A pipe, a
// file, or a systemd/launchd-captured stream all report false.
//
// Character device is a slightly wider set than "terminal" — `> /dev/null`
// also reports true — but the only cost there is escapes written to output
// that is being discarded, whereas the failure this check exists to prevent
// (escapes in a captured log) is genuinely a pipe every time.
func stdoutIsTerminal() bool {
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
