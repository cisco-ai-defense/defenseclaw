// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0744, GAP-0745, GAP-0746 (review s7-syntchk). The shapes are
// built in code from the controls of gap0486Blocked:
//   - C1/C4: the control, then n list statements or n pipeline stages, then
//     a line holding only the closing keyword (the statement read before the
//     error is over the statement budget on its own);
//   - P35: n no-op lines, the control, then the closing keyword;
//   - H1: the closing keyword, then a here-document of 12 lines whose body
//     holds the control as data.
func gap0744Shapes() map[string]func(string) string {
	shapes := map[string]func(string) string{}
	for _, n := range []int{127, 130, 200, 260} {
		shapes[fmt.Sprintf("C1-%03d", n)] = func(s string) string { return s + strings.Repeat("; :", n) + "\nfi" }
		shapes[fmt.Sprintf("C4-%03d", n)] = func(s string) string { return s + strings.Repeat(" | cat", n) + "\nfi" }
	}
	shapes["P35"] = func(s string) string { return strings.Repeat(":\n", 130) + s + "\nfi" }
	return shapes
}

// A control read before the error blocks in every tier, whatever the length
// of the statement it is in (GAP-0744: rel blocks these from the raw text).
func TestGAP0744ReadStatementOverTheBudgetStillBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	shapes := gap0744Shapes()
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			cwd := t.TempDir()
			for _, id := range gap0526SortedIDs(shapes) {
				command := shapes[id](gap0486Blocked["B3"])
				if out := gap0437Hook(t, hook, cwd, p.name+id, command); out["action"] != "block" {
					t.Errorf("%s %s-B3: action %v, want block: %v", p.name, id, out["action"], out["rule_ids"])
				}
			}
		})
	}
}

// A syntax-error remainder shellparse.ReadSyntaxTail cannot read (here the
// leading fi) is never a silent allow: the call carries the detection-only
// ACTION-PARSE-FAILURE record in every pack, the record alone never blocks,
// and a control read before the error still blocks. Rows P10, P11, P31 and
// P38 of s7-syntchk: a body of more than syntaxTailRunWindow pieces after a
// leading fi, read whole since rel-1-0-10:GAP-0745
// (TestGAP0745StatementPastTheRunWindowIsRead).
func TestGAP0745UnreadRunWindowIsRecordedNeverSilent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	pad := strings.Repeat(": ; ", 12)
	shapes := map[string]func(string) string{
		"P10": func(s string) string { return "fi\nfor i in 1; do " + s + "; " + pad + "; done" },
		"P11": func(s string) string { return "fi\nif true; then " + s + "; " + pad + "; fi" },
		"P31": func(s string) string { return "fi\nf() { " + s + "; " + pad + "; }; f" },
		"P38": func(s string) string { return "fi\nwhile true; do " + s + "; " + pad + "; break; done" },
	}
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			cwd := t.TempDir()
			for _, id := range gap0526SortedIDs(shapes) {
				benign := gap0437Hook(t, hook, cwd, p.name+id+"benign", shapes[id]("ls"))
				if !gap0526Names(benign, parseFailureRuleID) {
					t.Errorf("%s %s benign: the unread remainder is not recorded: %v", p.name, id, benign)
				}
				if benign["action"] == "block" {
					t.Errorf("%s %s benign: action block, the record alone never blocks: %v", p.name, id, benign["rule_ids"])
				}
				// A control read before the error blocks whatever follows.
				before := gap0437Hook(t, hook, cwd, p.name+id+"before", gap0486Blocked["B3"]+"\n"+shapes[id]("ls"))
				if before["action"] != "block" {
					t.Errorf("%s %s control before the error: action %v, want block", p.name, id, before["action"])
				}
			}
		})
	}
}

// A here-document after the error is data: its body lines are not judged as
// commands (GAP-0746), as rel does not judge them.
func TestGAP0746HereDocumentAfterTheErrorIsData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, id := range []string{"B1", "B3"} {
			body := strings.Repeat("line\n", 11) + gap0486Blocked[id] + "\n"
			command := "fi\ncat <<'EOF'\n" + body + "EOF"
			out := gap0437Hook(t, hook, cwd, p.name+"h1"+id, command)
			if out["action"] == "block" {
				t.Errorf("%s H1-%s: the here-document body was judged as commands: %v", p.name, id, out["rule_ids"])
			}
		}
	}
}

// gap0876Script is the GAP-0876 shape built from a fixture (the shellparse
// test of the same name): a quoted here-document of consumer, inside a
// single-quoted argument of a program, whose body has a lone apostrophe and a
// parenthesis (a syntax error of the outer text) before body.
func gap0876Script(consumer, body string) string {
	return "tool - '" + consumer + " <<'\"'\"'EOF'\"'\"'\nit's (x)\n" + body + "\nEOF\necho after'"
}

// rel-1-0-10:GAP-0876. A quoted here-document is its command's input: a
// blocking fixture in the body of a non-shell command is data (never a
// block; allowed where nothing scans the unread text), in the body of a
// shell it is read and blocks (GAP-0526), and in the body of a command that
// is not known it is the unknown tier (the unresolved-body alert, never a
// block), in every pack.
func TestGAP0876QuotedHereDocBodyIsItsCommandsInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, id := range []string{"B1", "B3"} {
			control := gap0526ControlRule(t, p.name+" "+id, gap0437Hook(t, hook, cwd, p.name+"c"+id, gap0486Blocked[id]))
			for _, consumer := range []string{"cat > notes.txt", "$P"} {
				command := gap0876Script(consumer, gap0486Blocked[id])
				gap0526HasSyntaxError(t, id, command)
				out := gap0437Hook(t, hook, cwd, p.name+consumer+id, command)
				where := p.name + " " + id + " " + consumer
				if out["action"] == "block" {
					t.Errorf("%s: the here-document body was judged as commands: %v", where, out)
				}
				// Outside strict and managed nothing scans the unread text: the
				// body of cat is data, with no finding above the record.
				if consumer != "$P" && !p.managed && p.pack != "strict" && (out["action"] != "allow" || gap0526Names(out, "CRITICAL")) {
					t.Errorf("%s: action %v, want allow (the body is data): %v", where, out["action"], out)
				}
				if consumer == "$P" && (out["action"] != "alert" || !gap0526Names(out, unresolvedBodyTitle)) {
					t.Errorf("%s: action %v, want the unknown tier (alert): %v", where, out["action"], out)
				}
			}
			out := gap0437Hook(t, hook, cwd, p.name+"sh"+id, gap0876Script("bash", gap0486Blocked[id]))
			if out["action"] != "block" || !gap0526Names(out, control) {
				t.Errorf("%s %s bash: action %v, want block with %s (GAP-0526): %v", p.name, id, out["action"], control, out)
			}
		}
	}
}
