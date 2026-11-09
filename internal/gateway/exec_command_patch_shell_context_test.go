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
// of the envelope, wherever the text puts it: at the top level, in the body of
// a function, behind a condition, after the commands that define, call or
// remove a function of the same name. An envelope that targets a protected
// file is blocked, an envelope that only touches ordinary files is allowed,
// and a call of a function that has no envelope is never judged by this rule.
// A function that nothing in the text calls runs nothing, so a text that only
// defines it has no command to judge.
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
		noPatch bool // the row has no envelope at all and is always allowed
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
		{name: "function body that nothing in the text calls", command: func(p string) string { return "f() {\n" + envelope(p) + "}\n" }},
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
		for _, row := range rows {
			for _, patch := range []struct {
				name, text string
				block      bool
			}{{"protected", protected, row.protect}, {"ordinary", ordinary, false}} {
				if row.noPatch && patch.name == "ordinary" {
					continue
				}
				t.Run(connector+"/"+row.name+"/"+patch.name, func(t *testing.T) {
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
					got := overLimitHostHookWithEvidence(t, connector, home, string(body), hookpaths.Resolve(body))
					blocked := overLimitHookAction(t, got) == "block"
					if blocked != patch.block || blocked && !strings.Contains(got, loader) {
						t.Fatalf("blocked=%t, want block=%t by %q: %.500s", blocked, patch.block, loader, got)
					}
				})
			}
		}
	}
}
