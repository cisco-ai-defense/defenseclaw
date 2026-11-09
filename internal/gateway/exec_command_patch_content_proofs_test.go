// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Codex sends its apply_patch tool as an exec_command whose text is a quoted
// here-document, and Claude Code can send the same text as Bash. The loader,
// profile, PAM and Docker content proofs read the envelope of that shell form
// as they read the typed tool, so both get the verdict of the typed call, also
// when the patch names another file first, goes through a link, is placed by a
// cd, or has other commands around it. Ordinary patches stay allowed.
func TestShellFormApplyPatchGetsTheContentProofVerdictOfTheTypedTool(t *testing.T) {
	home, project := hermesPatchHome(t)
	if err := os.Symlink("/etc/ld.so.preload", filepath.Join(project, "lnk-preload")); err != nil {
		t.Fatal(err)
	}
	const (
		lib      = "/usr/local/lib/libreview.so"
		loader   = "persistence.global_ld_preload_install"
		pam      = "tamper.pam_permit_authentication_bypass"
		registry = "tamper.docker_insecure_http_registry"
		sudoers  = "privilege.sudoers_unrestricted_nopasswd"
		begin    = "*** Begin Patch\n"
		end      = "*** End Patch\n"
	)
	padding := strings.Repeat("+# padding line of ordinary text\n", 600)
	rows := []struct {
		name, patch, rule string
		shellAround       func(command string) string
	}{
		{name: "loader", patch: begin + "*** Add File: /etc/ld.so.preload\n+" + lib + "\n" + end, rule: loader},
		{name: "profile", patch: begin + "*** Add File: /etc/profile.d/review.sh\n+export LD_PRELOAD=" + lib + "\n" + end, rule: loader},
		{name: "pam", patch: begin + "*** Update File: /etc/pam.d/sshd\n@@\n+auth sufficient pam_permit.so\n" + end, rule: pam},
		{name: "docker", patch: begin + "*** Add File: /etc/docker/daemon.json\n+{\"insecure-registries\":[\"http://registry.example.test:5000\"]}\n" + end, rule: registry},
		{name: "sudoers", patch: begin + "*** Add File: /etc/sudoers.d/review\n+reviewer ALL=(ALL) NOPASSWD: ALL\n" + end, rule: sudoers},
		{name: "link", patch: begin + "*** Update File: lnk-preload\n@@\n+" + lib + "\n" + end, rule: loader},
		{name: "after an ordinary file", patch: begin + "*** Add File: notes-two.txt\n+hello\n*** Add File: /etc/ld.so.preload\n+" + lib + "\n" + end, rule: loader},
		{name: "padded", patch: begin + "*** Add File: /etc/ld.so.preload\n" + padding + "+" + lib + "\n" + end, rule: loader},
		{name: "relative after cd", patch: begin + "*** Add File: ld.so.preload\n+" + lib + "\n" + end, rule: loader,
			shellAround: func(command string) string { return "cd /etc && " + command }},
		{name: "with a command after it", patch: begin + "*** Add File: /etc/ld.so.preload\n+" + lib + "\n" + end, rule: loader,
			shellAround: func(command string) string { return command + "\ncat notes.txt\n" }},
		{name: "ordinary file", patch: begin + "*** Add File: notes-c875.txt\n+hello\n" + end},
		{name: "ordinary relative after cd", patch: begin + "*** Add File: notes-three.txt\n+hello\n" + end,
			shellAround: func(command string) string { return "cd " + project + " && " + command }},
		{name: "ordinary profile fragment", patch: begin + "*** Add File: /etc/profile.d/review.sh\n+export EDITOR=vi\n" + end},
		{name: "pam comment", patch: begin + "*** Update File: /etc/pam.d/sshd\n@@\n+# reviewed by the team\n" + end},
		{name: "daemon.json without a registry", patch: begin + "*** Add File: /etc/docker/daemon.json\n+{\"log-level\":\"warn\"}\n" + end},
		{name: "daemon.json with a loopback registry", patch: begin + "*** Add File: /etc/docker/daemon.json\n+{\"insecure-registries\":[\"http://127.0.0.1:5000\"]}\n" + end},
		{name: "link to an ordinary file", patch: begin + "*** Update File: lnk-notes\n@@\n+hello\n" + end},
	}
	if err := os.Symlink(filepath.Join(project, "notes.txt"), filepath.Join(project, "lnk-notes")); err != nil {
		t.Fatal(err)
	}
	for _, connector := range []string{"codex", "claudecode"} {
		for _, row := range rows {
			for _, shape := range []string{"typed", "shell"} {
				if shape == "typed" && (row.shellAround != nil || connector != "codex") {
					continue
				}
				t.Run(connector+"/"+row.name+"/"+shape, func(t *testing.T) {
					tool, input := "apply_patch", map[string]any{"command": row.patch}
					if shape == "shell" {
						command := "apply_patch <<\x27PATCH\x27\n" + row.patch + "PATCH\n"
						if row.shellAround != nil {
							command = row.shellAround(command)
						}
						tool, input = "Bash", map[string]any{"command": command}
						if connector == "codex" {
							tool, input = "exec_command", map[string]any{"cmd": command}
						}
					}
					body := mustJSON(t, map[string]any{
						"session_id": "shell-patch-proofs", "hook_event_name": "PreToolUse", "cwd": project,
						"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu-shell-patch-proofs",
						"tool_input": input,
					})
					got := overLimitHostHookWithEvidence(t, connector, home, string(body), hookpaths.Resolve(body))
					blocked := overLimitHookAction(t, got) == "block"
					if blocked != (row.rule != "") || row.rule != "" && !strings.Contains(got, row.rule) {
						t.Fatalf("blocked=%t, want block=%t by %q: %.500s", blocked, row.rule != "", row.rule, got)
					}
				})
			}
		}
	}
}

// A shell function the action defined for certain takes the name apply_patch
// and consumes the here-document itself: the call runs that function, which
// writes nothing of the patch, and the call is allowed in the default profile.
// A call the action may still send to the program is read as the program: a
// definition after the call, in a subshell, a name unset, a function that
// forwards to the program.
func TestShellFunctionNamedApplyPatchIsNotReadAsThePatchProgram(t *testing.T) {
	home, project := hermesPatchHome(t)
	const (
		patch  = "apply_patch <<\x27PATCH\x27\n*** Begin Patch\n*** Add File: /etc/ld.so.preload\n+/usr/local/lib/libreview.so\n*** End Patch\nPATCH\n"
		loader = "persistence.global_ld_preload_install"
	)
	rows := []struct {
		name, command string
		block         bool
	}{
		{name: "program alone", command: patch, block: true},
		{name: "function that does nothing", command: "apply_patch() { :; }\n" + patch},
		{name: "function that writes an ordinary file", command: "apply_patch() { cat > notes.txt; }\n" + patch},
		{name: "function after a cd", command: "apply_patch() { :; }\ncd " + project + " && " + patch},
		{name: "function defined after the call", command: patch + "apply_patch() { :; }\n", block: true},
		{name: "function defined in a subshell", command: "( apply_patch() { :; } )\n" + patch, block: true},
		{name: "function unset", command: "apply_patch() { :; }\nunset -f apply_patch\n" + patch, block: true},
		{name: "function body prints the program name", command: "apply_patch() { printf 'apply_patch notes' > notes.txt; }\n" + patch},
		{name: "builtin with the word unset after the call", command: "apply_patch() { :; }\n" + patch + ": unset\n"},
		{name: "program name printed after the call", command: "apply_patch() { :; }\n" + patch + "printf apply_patch > notes.txt\n"},
		{name: "unset of a variable after the call", command: "apply_patch() { :; }\n" + patch + "unset TMPFILE\n"},
		{name: "unset of the function in a loop around the call", command: "apply_patch() { :; }\nfor i in 1 2; do\n" + patch + "unset -f apply_patch\ndone\n", block: true},
		{name: "unset of the function through command", command: "apply_patch() { :; }\ncommand unset -f apply_patch\n" + patch, block: true},
		{name: "function that forwards to the program", command: "apply_patch() { exec apply_patch; }\n" + patch, block: true},
		{name: "function that forwards by path", command: "apply_patch() { /usr/bin/apply_patch; }\n" + patch, block: true},
		{name: "uncalled function unsets it, declared before", command: "apply_patch() { :; }\nunused() { unset -f apply_patch; }\n" + patch},
		{name: "uncalled function unsets it through eval", command: "apply_patch() { :; }\nunused() { eval \x27unset -f apply_patch\x27; }\n" + patch},
		{name: "uncalled function forwards to the program", command: "apply_patch() { :; }\nunused() { exec apply_patch; }\n" + patch},
		{name: "uncalled function runs the program through command", command: "apply_patch() { :; }\nunused() { command apply_patch; }\n" + patch},
		{name: "uncalled function declared after the call", command: "apply_patch() { :; }\n" + patch + "unused() { unset -f apply_patch; }\n"},
		{name: "function that unsets it, called before", command: "apply_patch() { :; }\nunused() { unset -f apply_patch; }\nunused\n" + patch, block: true},
		{name: "function that unsets it, called through another function", command: "apply_patch() { :; }\nunused() { unset -f apply_patch; }\nhelper() { unused; }\nhelper\n" + patch, block: true},
		{name: "function that unsets it, called after the call", command: "apply_patch() { :; }\nunused() { unset -f apply_patch; }\n" + patch + "unused\n"},
		{name: "function that unsets itself, called before", command: "apply_patch() { unset -f apply_patch; }\napply_patch\n" + patch, block: true},
		{name: "unset of a variable of that name", command: "apply_patch() { :; }\nunset -v apply_patch\n" + patch},
		{name: "unset of a nameref of that name", command: "apply_patch() { :; }\nunset -n apply_patch\n" + patch},
		{name: "unset of a variable after the end of options", command: "apply_patch() { :; }\nunset -v -- apply_patch\n" + patch},
		{name: "unset of the name after the end of options", command: "apply_patch() { :; }\nunset -- apply_patch\n" + patch, block: true},
		{name: "unset of the name without an option", command: "apply_patch() { :; }\nunset apply_patch\n" + patch, block: true},
		{name: "unset with both a function and a variable option", command: "apply_patch() { :; }\nunset -fv apply_patch\n" + patch, block: true},
		{name: "builtin unset of the function", command: "apply_patch() { :; }\nbuiltin unset -f apply_patch\n" + patch, block: true},
		{name: "command -p unset of the function", command: "apply_patch() { :; }\ncommand -p unset -f apply_patch\n" + patch, block: true},
		{name: "builtin unset of a variable", command: "apply_patch() { :; }\nbuiltin unset -v apply_patch\n" + patch},
		{name: "command -v only looks a name up", command: "apply_patch() { :; }\ncommand -v unset\n" + patch},
		{name: "grep for the word unset", command: "apply_patch() { :; }\ngrep unset notes.txt\n" + patch},
		{name: "env with an assignment that holds the word unset", command: "apply_patch() { :; }\nenv NOTE=unset true\n" + patch},
		{name: "test command before the call", command: "apply_patch() { :; }\n[ -n \"$HOME\" ]\n" + patch},
		{name: "function body greps for the program name", command: "apply_patch() { grep -q apply_patch notes.txt; }\n" + patch},
		{name: "ordinary patch after a function", command: "apply_patch() { :; }\napply_patch <<\x27PATCH\x27\n*** Begin Patch\n*** Add File: notes-fn.txt\n+hello\n*** End Patch\nPATCH\n"},
	}
	for _, connector := range []string{"codex", "claudecode"} {
		for _, row := range rows {
			t.Run(connector+"/"+row.name, func(t *testing.T) {
				tool, input := "Bash", map[string]any{"command": row.command}
				if connector == "codex" {
					tool, input = "exec_command", map[string]any{"cmd": row.command}
				}
				body := mustJSON(t, map[string]any{
					"session_id": "shell-function-patch", "hook_event_name": "PreToolUse", "cwd": project,
					"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu-shell-function-patch",
					"tool_input": input,
				})
				got := overLimitHostHookWithEvidence(t, connector, home, string(body), hookpaths.Resolve(body))
				blocked := overLimitHookAction(t, got) == "block"
				if blocked != row.block || row.block && !strings.Contains(got, loader) {
					t.Fatalf("blocked=%t, want block=%t by %q: %.500s", blocked, row.block, loader, got)
				}
			})
		}
	}
}
