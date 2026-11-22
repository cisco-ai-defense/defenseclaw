// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects_test

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/effects"
)

// DET111 R1 SYNTAX cause (owner 11-22: drive unknown to zero for every cause
// we control): a POSIX text the parser cannot read in full. Two classes:
// a non-interactive bash has already run every command on the lines before a
// syntax error, and bash ends a here-document inside a command substitution
// at the line that closes the substitution (DELIM) or DELIM `). Fail-before:
// red at a64bfdb931 (the whole text is one invalid_syntax unknown, no effect).

func det111SyntaxRun(cmd string) effects.Result {
	return effects.Extract(effects.Call{Surface: effects.SurfaceShell, Tool: "Bash", Command: cmd},
		effects.Options{Flavor: effects.FlavorPOSIX, Dialect: effects.DialectPOSIX, Home: "/home/alice", CWD: "/home/alice/proj"})
}

func det111SyntaxHas(res effects.Result, kind effects.Kind, path string) bool {
	for _, e := range res.Effects {
		if e.Kind == kind && e.Target.Path == path {
			return true
		}
	}
	return false
}

func det111SyntaxUnknown(res effects.Result) bool {
	for _, u := range res.Unknowns {
		if u.Code == effects.ReasonInvalidSyntax {
			return true
		}
	}
	return false
}

func det111SyntaxDump(res effects.Result) string {
	var b strings.Builder
	for _, e := range res.Effects {
		b.WriteString("\n  " + string(e.Kind) + " " + e.Target.Path + " prog=" + e.Origin.Program)
		for _, r := range e.Reasons {
			b.WriteString(" " + string(r.Code))
		}
	}
	for _, u := range res.Unknowns {
		b.WriteString("\n  U " + string(u.Code))
	}
	return b.String()
}

func TestDET111R1SyntaxErrorLinesBeforeItRan(t *testing.T) {
	const state = "/home/alice/.defenseclaw"
	for _, tc := range []struct {
		name, cmd string
		ran       bool // bash ran the rm before the error
	}{
		{"line before the error", "rm -rf ~/.defenseclaw\nfi", true},
		{"lines before an unclosed quote", "cd ~\nrm -rf .defenseclaw\necho \"oops", true},
		{"nested body", "bash -c 'rm -rf ~/.defenseclaw\nfi fi'", true},
		{"heredoc shell body", "bash <<'E'\nrm -rf ~/.defenseclaw\ndone\nE", true},
		{"same line as the error", "rm -rf ~/.defenseclaw; fi", false},
		{"compound open at the error", "if true; then\nrm -rf ~/.defenseclaw\nfi fi", false},
		{"error on the first line", "fi # don't\nrm -rf ~/.defenseclaw", false},
	} {
		res := det111SyntaxRun(tc.cmd)
		got := det111SyntaxHas(res, effects.KindDelete, state)
		if got != tc.ran {
			t.Errorf("%s: %q: delete of %s = %v, want %v%s", tc.name, tc.cmd, state, got, tc.ran, det111SyntaxDump(res))
		}
		if !det111SyntaxUnknown(res) {
			t.Errorf("%s: %q: the unread rest must stay an invalid_syntax unknown%s", tc.name, tc.cmd, det111SyntaxDump(res))
		}
	}
}

func TestDET111R1SyntaxNestedErrorCarriesTheUnreadText(t *testing.T) {
	res := det111SyntaxRun("bash -c 'rm -rf ~/.defenseclaw\nfi fi'")
	for _, e := range res.Effects {
		if e.Kind == effects.KindExec && e.Data != nil && e.Data.Text == "fi fi" {
			return
		}
	}
	t.Errorf("want one opaque exec carrying the unread line %q%s", "fi fi", det111SyntaxDump(res))
}

func TestDET111R1SyntaxComsubHeredocClose(t *testing.T) {
	for _, tc := range []struct{ name, cmd, path string }{
		{"delimiter then )", "x=$(cat <<EOF\nhi\nEOF); rm -rf ~/.defenseclaw", "/home/alice/.defenseclaw"},
		{"delimiter, blank, )", "echo $(cat <<'EOF'\nhi\nEOF ) && rm -rf ~/.defenseclaw", "/home/alice/.defenseclaw"},
		{"tab-stripped delimiter", "echo $(cat <<-EOF\n\thi\n\tEOF)\nrm -rf ~/.defenseclaw", "/home/alice/.defenseclaw"},
		{"backtick", "echo `cat <<EOF\nhi\nEOF`; rm -rf ~/.defenseclaw", "/home/alice/.defenseclaw"},
		{"GAP-0662 dollar-paren", "echo $(cp /tmp/x ~/.defenseclaw/config.yaml <<'EOF'\nimport sys\nEOF)", "/home/alice/.defenseclaw/config.yaml"},
	} {
		res := det111SyntaxRun(tc.cmd)
		if det111SyntaxUnknown(res) {
			t.Errorf("%s: %q: bash reads it; want no invalid_syntax%s", tc.name, tc.cmd, det111SyntaxDump(res))
		}
		found := false
		for _, e := range res.Effects {
			found = found || e.Target.Path == tc.path
		}
		if !found {
			t.Errorf("%s: %q: want an effect on %s%s", tc.name, tc.cmd, tc.path, det111SyntaxDump(res))
		}
	}
}

// A here-document with an unquoted delimiter and a here-string are fed to the
// shell after the shell's own backslash reading; the parser keeps every
// backslash of the source, so a body read raw is not what runs (census row
// r1/heredoc-plain wsh/variant/1030494d35489287: the doubled backslashes of a
// heredoc-plain body made the nested text unparsable).
func TestDET111R1HeredocBodyIsWhatTheShellReads(t *testing.T) {
	const state = "/home/alice/.defenseclaw"
	for _, tc := range []struct{ name, cmd string }{
		{"heredoc \\\\", "bash <<E\nrm -rf ~/.defense\\\\claw\nE"},
		{"heredoc line join", "bash <<E\nrm -rf \\\n  ~/.defenseclaw\nE"},
		{"heredoc-plain sh -c body", "bash <<E\nsh -c 'rm -rf '\\\\''/home/alice/.defenseclaw'\\\\'''\nE"},
		{"here-string escaped blanks", "bash <<< rm\\ -rf\\ /home/alice/.defenseclaw"},
		{"here-string escaped quotes", "bash <<< \"rm -rf \\\"/home/alice/.defenseclaw\\\"\""},
	} {
		res := det111SyntaxRun(tc.cmd)
		if !det111SyntaxHas(res, effects.KindDelete, state) {
			t.Errorf("%s: %q: want the delete of %s%s", tc.name, tc.cmd, state, det111SyntaxDump(res))
		}
	}
	// a quoted delimiter keeps its body as written: \\claw stays two bytes, so
	// the inner shell deletes ~/.defense\claw, not the state folder
	if res := det111SyntaxRun("bash <<'E'\nrm -rf ~/.defense\\\\claw\nE"); det111SyntaxHas(res, effects.KindDelete, state) {
		t.Errorf("quoted delimiter body was unescaped%s", det111SyntaxDump(res))
	}
}
