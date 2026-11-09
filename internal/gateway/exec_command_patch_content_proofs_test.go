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
		{name: "pam of chsh", patch: begin + "*** Update File: /etc/pam.d/chsh\n@@\n+auth sufficient pam_permit.so\n" + end, rule: pam},
		{name: "padded and through a link", patch: begin + "*** Update File: lnk-preload\n@@\n" + padding + "+" + lib + "\n" + end, rule: loader},
		{name: "ordinary file then a link", patch: begin + "*** Add File: notes-two.txt\n+hello\n*** Update File: lnk-preload\n@@\n+" + lib + "\n" + end, rule: loader},
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
