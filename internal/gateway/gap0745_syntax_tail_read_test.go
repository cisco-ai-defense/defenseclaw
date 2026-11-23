// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"strings"
	"testing"
)

// gap0745Shapes are the s7-syntchk rows of rel-1-0-10:GAP-0745: after a
// leading syntax error, a statement of more pieces than the run window (a
// loop, an if, a brace group, a subshell, a function, a case of many arms),
// and a comment holding an apostrophe after the error, plain and as a
// bash -c script.
func gap0745Shapes() map[string]func(string) string {
	pad := ":;:;:;:;:;:;:;:;:"
	return map[string]func(string) string{
		"P10": func(s string) string { return "fi\nfor i in 1; do " + s + "; " + pad + "; done" },
		"P11": func(s string) string { return "fi\nif true; then " + s + "; " + pad + "; fi" },
		"P12": func(s string) string { return "fi\n{ " + s + "; " + pad + "; }" },
		"P13": func(s string) string { return "fi\n( " + s + "; " + pad + " )" },
		"P28": func(s string) string { return "fi # don" + "\x27" + "t\n" + s },
		"P31": func(s string) string { return "fi\nf() { " + s + "; " + pad + "; }; f" },
		"P37": func(s string) string { return "bash -c " + gap0745Quote("fi # don"+"\x27"+"t\n"+s) },
		"P38": func(s string) string { return "fi\nwhile true; do " + s + "; " + pad + "; break; done" },
		"M1": func(s string) string {
			return "fi\ncase x in\n" + strings.Repeat("a) :;;\n", 10) + "x) " + s + ";;\nesac"
		},
		"C6-100": func(s string) string { return "fi\nfor i in 1; do " + s + strings.Repeat("; :", 100) + "; done" },
		"C6-127": func(s string) string { return "fi\nfor i in 1; do " + s + strings.Repeat("; :", 127) + "; done" },
	}
}

func gap0745Quote(s string) string {
	return "\x27" + strings.ReplaceAll(s, "\x27", "\x27\\\x27\x27") + "\x27"
}

var gap0745ActionRank = map[any]int{"allow": 0, "alert": 1, "block": 2}

// A control inside a statement longer than the run window after a syntax
// error is read: it gets at least the verdict the control gets alone, in
// every pack (the bound rule: the statement is read, or the cap reports
// TRUNCATED). The run window and the cut-back tries stopped silently before
// and the control was allowed in every pack, strict too. The same shapes
// around a benign command never block.
func TestGAP0745StatementPastTheRunWindowIsRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	shapes := gap0745Shapes()
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			cwd := t.TempDir()
			alone := gap0437Hook(t, hook, cwd, p.name+"alone", gap0486Blocked["B1"])
			for _, id := range gap0526SortedIDs(shapes) {
				out := gap0437Hook(t, hook, cwd, p.name+id, shapes[id](gap0486Blocked["B1"]))
				if gap0745ActionRank[out["action"]] < gap0745ActionRank[alone["action"]] {
					t.Errorf("%s %s-B1: action %v, want %v as the control alone: %v", p.name, id, out["action"], alone["action"], out["rule_ids"])
				}
				benign := gap0437Hook(t, hook, cwd, p.name+id+"benign", shapes[id]("ls -la"))
				if benign["action"] == "block" {
					t.Errorf("%s %s benign: action block: %v", p.name, id, benign["rule_ids"])
				}
			}
		})
	}
}
