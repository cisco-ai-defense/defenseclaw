// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The content proofs judge every apply_patch envelope the shell text of an
// exec_command (Codex) or Bash (Claude Code) call carries on the file headers
// of the envelope, wherever the text puts it that the shell can run it: at the
// top level, in the body of a function a call runs, behind a condition, after
// the commands that define, call or remove a function of the same name. An
// envelope that targets a protected file is blocked, an envelope that only
// touches ordinary files is allowed, and a call of a function that has no
// envelope is never judged by this rule. The body of a function that nothing
// in the text calls runs nothing: the default and permissive tiers do not
// judge it, and the strict tier judges its envelope whether or not the text
// calls the function (rel-1-0-6:GAP-0928 review 12).
func TestShellApplyPatchEnvelopeIsJudgedWhereverTheTextHasIt(t *testing.T) {
	home, project := hermesPatchHome(t)
	const (
		loader = "persistence.global_ld_preload_install"
		begin  = "*** Begin Patch\n"
		end    = "*** End Patch\n"
	)
	protected := begin + "*** Add File: /etc/ld.so.preload\n+/usr/local/lib/libreview.so\n" + end
	ordinary := begin + "*** Add File: notes-context.txt\n+hello\n" + end
	envelope := func(patch string) string { return "apply_patch <<'PATCH'\n" + patch + "PATCH\n" }
	rows := []struct {
		name    string
		command func(patch string) string
		protect bool // the row is blocked when the envelope targets a protected file
		// uncalled is a row whose envelope is in a function body no call runs:
		// only the strict tier blocks it.
		uncalled bool
		noPatch  bool // the row has no envelope at all and is always allowed
	}{
		{name: "top level", command: envelope, protect: true},
		{name: "function body", command: func(p string) string { return "f() {\n" + envelope(p) + "}\nf\n" }, protect: true},
		{name: "function called by a variable", command: func(p string) string { return "f() {\n" + envelope(p) + "}\nx=f\n$x\n" }, protect: true},
		{name: "function called by eval", command: func(p string) string { return "f() {\n" + envelope(p) + "}\neval f\n" }, protect: true},
		{name: "function called in a pipeline", command: func(p string) string { return "f() {\n" + envelope(p) + "}\nf | cat\n" }, protect: true},
		{name: "function called in a condition", command: func(p string) string { return "f() {\n" + envelope(p) + "}\nif f; then :; fi\n" }, protect: true},
		{name: "function called after a loop", command: func(p string) string { return "f() {\n" + envelope(p) + "}\nfor i in 1 2; do f; done\n" }, protect: true},
		{name: "exported function called by a child shell", command: func(p string) string { return "f() {\n" + envelope(p) + "}\nexport -f f\nbash -c f\n" }, protect: true},
		{name: "function called through xargs", command: func(p string) string {
			return "f() {\n" + envelope(p) + "}\nexport -f f\necho x | xargs -I{} bash -c f\n"
		}, protect: true},
		{name: "function called by source", command: func(p string) string {
			return "f() {\n" + envelope(p) + "}\ndeclare -f f > fdef.sh\nsource fdef.sh\nf\n"
		}, protect: true},
		{name: "function body that nothing in the text calls", uncalled: true, command: func(p string) string { return "f() {\n" + envelope(p) + "}\n" }, protect: true},
		{name: "subshell function that nothing in the text calls", uncalled: true, command: func(p string) string { return "f() (\n" + envelope(p) + ")\n" }, protect: true},
		{name: "function nested in an uncalled function", uncalled: true, command: func(p string) string {
			return "g() {\nf() {\n" + envelope(p) + "}\n}\n"
		}, protect: true},
		{name: "function nested in a called function", uncalled: true, command: func(p string) string {
			return "g() {\nf() {\n" + envelope(p) + "}\n}\ng\n"
		}, protect: true},
		{name: "and list", command: func(p string) string { return "test -d . && " + envelope(p) }, protect: true},
		{name: "or list", command: func(p string) string { return "test -d nowhere || " + envelope(p) }, protect: true},
		{name: "if branch", command: func(p string) string { return "if test -d .; then\n" + envelope(p) + "fi\n" }, protect: true},
		{name: "else branch", command: func(p string) string { return "if test -d nowhere; then :; else\n" + envelope(p) + "fi\n" }, protect: true},
		{name: "subshell", command: func(p string) string { return "(\n" + envelope(p) + ")\n" }, protect: true},
		{name: "brace group", command: func(p string) string { return "{\n" + envelope(p) + "}\n" }, protect: true},
		{name: "after a function of the same name", command: func(p string) string { return "apply_patch() { :; }\n" + envelope(p) }, protect: true},
		{name: "after unset of the function", command: func(p string) string { return "apply_patch() { :; }\nunset -f apply_patch\n" + envelope(p) }, protect: true},
		{name: "after unset defined later", command: func(p string) string {
			return "apply_patch() { :; }\nunset -f apply_patch\n" + envelope(p) + "unset() { :; }\n"
		}, protect: true},
		{name: "after unset defined in a subshell", command: func(p string) string {
			return "apply_patch() { :; }\n(unset() { :; })\nunset -f apply_patch\n" + envelope(p)
		}, protect: true},
		{name: "after builtin unset past a function", command: func(p string) string {
			return "apply_patch() { :; }\nunset() { :; }\nbuiltin unset -f apply_patch\n" + envelope(p)
		}, protect: true},
		{name: "after command unset past a function", command: func(p string) string {
			return "apply_patch() { :; }\nunset() { :; }\ncommand unset -f apply_patch\n" + envelope(p)
		}, protect: true},
		{name: "after a helper redefined after its call", command: func(p string) string {
			return "apply_patch() { :; }\nhelper() { :; }\nhelper\nhelper() { unset -f apply_patch; }\n" + envelope(p)
		}, protect: true},
		{name: "after a helper called before its definition", command: func(p string) string {
			return "apply_patch() { :; }\nhelper\nhelper() { unset -f apply_patch; }\n" + envelope(p)
		}, protect: true},
		{name: "after a function that only mentions unset", command: func(p string) string {
			return "apply_patch() { :; }\nunused() { unset -f apply_patch; }\n" + envelope(p)
		}, protect: true},
		{name: "after unset of a variable", command: func(p string) string {
			return "apply_patch() { :; }\nunset -v apply_patch\n" + envelope(p)
		}, protect: true},
		{name: "after a word unset as data", command: func(p string) string {
			return "apply_patch() { :; }\ngrep unset notes.txt >/dev/null\n" + envelope(p)
		}, protect: true},
		{name: "after alias settings", command: func(p string) string {
			return "apply_patch() { :; }\nshopt -s expand_aliases\nalias apply_patch='command apply_patch'\n" + envelope(p)
		}, protect: true},
		{name: "uncalled function, program named by a variable", uncalled: true, command: func(p string) string {
			return "p=apply_patch\nf() {\n\"$p\" <<'PATCH'\n" + p + "PATCH\n}\n"
		}, protect: true},
		{name: "uncalled function, variable reset after the definition", uncalled: true, command: func(p string) string {
			return "p=apply_patch\nf() {\n\"$p\" <<'PATCH'\n" + p + "PATCH\n}\np=ls\n"
		}, protect: true},
		{name: "uncalled function, program set in the body", uncalled: true, command: func(p string) string {
			return "f() {\np=apply_patch\n\"$p\" <<'PATCH'\n" + p + "PATCH\n}\n"
		}, protect: true},
		{name: "uncalled function with no envelope", noPatch: true, command: func(string) string {
			return "f() {\n  echo ready\n}\n"
		}},
		{name: "function defined and called with no envelope", noPatch: true, command: func(string) string {
			return "apply_patch() { :; }\napply_patch\n"
		}},
		{name: "function called after unset with no envelope", noPatch: true, command: func(string) string {
			return "apply_patch() { :; }\nunset -f apply_patch\napply_patch\n"
		}},
		{name: "helper called and redefined with no envelope", noPatch: true, command: func(string) string {
			return "apply_patch() { :; }\nhelper() { :; }\nhelper\nhelper() { unset -f apply_patch; }\napply_patch\n"
		}},
		{name: "helper called before its definition with no envelope", noPatch: true, command: func(string) string {
			return "apply_patch() { :; }\nhelper\nhelper() { unset -f apply_patch; }\napply_patch\n"
		}},
		{name: "protected text read by another program", noPatch: true, command: func(string) string {
			return "cat <<'TEXT'\n" + protected + "TEXT\n"
		}},
	}
	for _, connector := range []string{"codex", "claudecode"} {
		for _, pack := range []string{"", "strict"} {
			for _, row := range rows {
				for _, patch := range []struct {
					name, text string
					block      bool
				}{{"protected", protected, row.protect}, {"ordinary", ordinary, false}} {
					if row.noPatch && patch.name == "ordinary" {
						continue
					}
					want := patch.block && (pack == "strict" || !row.uncalled)
					t.Run(connector+"/"+packName(pack)+"/"+row.name+"/"+patch.name, func(t *testing.T) {
						command := row.command(patch.text)
						tool, input := "Bash", map[string]any{"command": command}
						if connector == "codex" {
							tool, input = "exec_command", map[string]any{"cmd": command}
						}
						body := mustJSON(t, map[string]any{
							"session_id": "shell-patch-context", "hook_event_name": "PreToolUse", "cwd": project,
							"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu-shell-patch-context",
							"tool_input": input,
						})
						got := overLimitHostHookInPack(t, connector, pack, home, string(body), hookpaths.Resolve(body))
						blocked := overLimitHookAction(t, got) == "block"
						if blocked != want || blocked && !strings.Contains(got, loader) {
							t.Fatalf("blocked=%t, want block=%t by %q: %.500s", blocked, want, loader, got)
						}
					})
				}
			}
		}
	}
}

// packName names the policy tier of a rule pack for a subtest.
func packName(pack string) string {
	if pack == "" {
		return "default"
	}
	return pack
}

// A relative file header of an envelope in an uncalled function is read from
// the directory the text has where it defines the function or in the body, as
// it is when a call runs the body. A call that runs the body is judged in
// every tier; a body no call runs is judged only in the strict tier. The benign
// twin names an ordinary file the same way and stays allowed, and the directory
// a body sets stays in the body.
func TestShellApplyPatchEnvelopeOfAnUncalledFunctionKeepsItsDirectory(t *testing.T) {
	home, project := hermesPatchHome(t)
	const loader = "persistence.global_ld_preload_install"
	relative := "*** Begin Patch\n*** Add File: ld.so.preload\n+/usr/local/lib/libreview.so\n*** End Patch\n"
	envelope := "apply_patch <<'PATCH'\n" + relative + "PATCH\n"
	for _, row := range []struct {
		name, command string
		// strict and balanced are the verdicts of the strict and the default tier.
		strict, balanced bool
	}{
		{"cd in the body", "f() {\ncd /etc\n" + envelope + "}\n", true, false},
		{"cd in the body, called", "f() {\ncd /etc\n" + envelope + "}\nf\n", true, true},
		{"cd before the definition", "cd /etc\nf() {\n" + envelope + "}\n", true, false},
		{"cd before the definition, called", "cd /etc\nf() {\n" + envelope + "}\nf\n", true, true},
		{"cd named by a variable", "c=cd\nf() {\n$c /etc\n" + envelope + "}\n", true, false},
		{"cd in a condition of the body", "f() {\nif true; then\ncd /etc\n" + envelope + "fi\n}\n", true, false},
		{"cd to an ordinary directory", "f() {\ncd /tmp\n" + envelope + "}\n", false, false},
		{"cd to /etc after the body", "f() {\ncd /tmp\n" + envelope + "}\ncd /etc\n", false, false},
		{"cd of another function does not leak", "g() {\ncd /etc\n}\nf() {\n" + envelope + "}\n", false, false},
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			for _, pack := range []string{"", "strict"} {
				want := row.balanced
				if pack == "strict" {
					want = row.strict
				}
				t.Run(connector+"/"+packName(pack)+"/"+row.name, func(t *testing.T) {
					tool, input := "Bash", map[string]any{"command": row.command}
					if connector == "codex" {
						tool, input = "exec_command", map[string]any{"cmd": row.command}
					}
					body := mustJSON(t, map[string]any{
						"session_id": "shell-patch-directory", "hook_event_name": "PreToolUse", "cwd": project,
						"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu-shell-patch-directory",
						"tool_input": input,
					})
					got := overLimitHostHookInPack(t, connector, pack, home, string(body), hookpaths.Resolve(body))
					blocked := overLimitHookAction(t, got) == "block"
					if blocked != want || blocked && !strings.Contains(got, loader) {
						t.Fatalf("blocked=%t, want block=%t by %q: %.500s", blocked, want, loader, got)
					}
				})
			}
		}
	}
}

// Code in the body of a function that nothing in the text calls is no state
// and no command of the call in the default and permissive tiers: a directory
// change, a nested definition or a command such as eval in it does not reach an
// ordinary patch envelope the text runs, and the envelope of an ordinary file
// is allowed (rel-1-0-6:GAP-0928 review 12). The strict tier keeps reading
// every body, and an envelope that names a protected file blocks in both.
func TestShellApplyPatchEnvelopeIgnoresStateOfAnUncalledFunction(t *testing.T) {
	home, project := hermesPatchHome(t)
	const loader = "persistence.global_ld_preload_install"
	relative := "*** Begin Patch\n*** Add File: ld.so.preload\n+/usr/local/lib/libreview.so\n*** End Patch\n"
	envelope := "apply_patch <<'PATCH'\n" + relative + "PATCH\n"
	protected := "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: /etc/ld.so.preload\n+/usr/local/lib/libreview.so\n*** End Patch\nPATCH\n"
	for _, row := range []struct {
		name, command    string
		strict, balanced bool
		// strictBy is the rule that blocks the row in the strict tier when it
		// is not the loader rule: the strict tier reads the command text of an
		// uncalled body too.
		strictBy string
	}{
		// A later uncalled function defines a helper that changes the directory;
		// neither definition runs.
		{"nested definition of an uncalled function", "h() {\ng\n" + envelope + "}\nf() {\ng() { cd /etc; }\n}\n", true, false, ""},
		{"nested definition of an uncalled function, h called", "h() {\ng\n" + envelope + "}\nf() {\ng() { cd /etc; }\n}\nh\n", false, false, ""},
		{"nested definition, h called before it is defined", "h() {\ng\n" + envelope + "}\nh\nf() {\ng() { cd /etc; }\n}\n", false, false, ""},
		{"eval in an uncalled body before the envelope", "f() {\neval 'rm -rf /'\n" + envelope + "}\n", true, false, "CMD-RM-RF"},
		{"command in an uncalled body before the envelope", "f() {\ncommand rm -rf /\n" + envelope + "}\n", true, false, "CMD-RM-RF"},
		{"eval in an uncalled body, envelope at the top level", "f() {\neval 'rm -rf /'\n}\n" + envelope, false, false, ""},
		{"directory of an uncalled body, envelope at the top level", "f() {\ncd /etc\n}\n" + envelope, false, false, ""},
		{"directory of an uncalled body, envelope in a called one", "f() {\ncd /etc\n}\nh() {\n" + envelope + "}\nh\n", false, false, ""},
		// What the shell runs is read in every tier.
		{"directory change at the top level", "cd /etc\n" + envelope, true, true, ""},
		{"directory change in a called function", "f() {\ncd /etc\n}\nf\n" + envelope, true, true, ""},
		{"called function holds the envelope after a directory change", "h() {\ncd /etc\n" + envelope + "}\nh\n", true, true, ""},
		{"protected envelope at the top level", protected, true, true, ""},
		{"protected envelope in a called function", "h() {\n" + protected + "}\nh\n", true, true, ""},
	} {
		for _, connector := range []string{"codex", "claudecode"} {
			for _, pack := range []string{"", "strict"} {
				want, by := row.balanced, loader
				if pack == "strict" {
					want = row.strict
					if row.strictBy != "" {
						by = row.strictBy
					}
				}
				t.Run(connector+"/"+packName(pack)+"/"+row.name, func(t *testing.T) {
					tool, input := "Bash", map[string]any{"command": row.command}
					if connector == "codex" {
						tool, input = "exec_command", map[string]any{"cmd": row.command}
					}
					body := mustJSON(t, map[string]any{
						"session_id": "shell-patch-state", "hook_event_name": "PreToolUse", "cwd": project,
						"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu-shell-patch-state",
						"tool_input": input,
					})
					got := overLimitHostHookInPack(t, connector, pack, home, string(body), hookpaths.Resolve(body))
					blocked := overLimitHookAction(t, got) == "block"
					if blocked != want || blocked && !strings.Contains(got, by) {
						t.Fatalf("blocked=%t, want block=%t by %q: %.500s", blocked, want, by, got)
					}
				})
			}
		}
	}
}
