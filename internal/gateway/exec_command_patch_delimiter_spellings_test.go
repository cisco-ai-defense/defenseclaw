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

// An apply_patch here-document gets the verdict of the typed tool whatever the
// spelling of its delimiter (unquoted, double-quoted, quoted by a backslash,
// single-quoted, each also with <<- and tab-indented lines), in the default and
// the strict tier, for Codex (exec_command) and Claude Code (Bash). A body the
// shell expands is judged on the text it shows. Ordinary patches stay allowed.
func TestShellApplyPatchHereDocumentSpellingsGetTheVerdictOfTheTypedTool(t *testing.T) {
	home, project := hermesPatchHome(t)
	if err := os.Symlink("/etc/ld.so.preload", filepath.Join(project, "lnk-preload")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(project, "notes.txt"), filepath.Join(project, "lnk-notes")); err != nil {
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
	bodies := []struct{ name, patch, rule string }{
		{"loader", begin + "*** Add File: /etc/ld.so.preload\n+" + lib + "\n" + end, loader},
		{"profile", begin + "*** Add File: /etc/profile.d/review.sh\n+export LD_PRELOAD=" + lib + "\n" + end, loader},
		{"pam", begin + "*** Update File: /etc/pam.d/sshd\n@@\n+auth sufficient pam_permit.so\n" + end, pam},
		{"docker", begin + "*** Add File: /etc/docker/daemon.json\n+{\"insecure-registries\":[\"http://registry.example.test:5000\"]}\n" + end, registry},
		{"sudoers", begin + "*** Add File: /etc/sudoers.d/review\n+reviewer ALL=(ALL) NOPASSWD: ALL\n" + end, sudoers},
		{"link", begin + "*** Update File: lnk-preload\n@@\n+" + lib + "\n" + end, loader},
		{"loader beside an expansion", begin + "*** Add File: notes-spell.txt\n+echo $HOME\n*** Add File: /etc/ld.so.preload\n+" + lib + "\n" + end, loader},
		{"loader beside a substitution", begin + "*** Add File: /etc/ld.so.preload\n+" + lib + "\n+# $(date)\n" + end, loader},
		{"ordinary file", begin + "*** Add File: notes-spell.txt\n+hello\n" + end, ""},
		{"ordinary file with an expansion", begin + "*** Add File: notes-spell.txt\n+echo $HOME $(date)\n" + end, ""},
		{"ordinary file with a literal escape", begin + "*** Add File: notes-spell.txt\n+printf(\"a\\n\");\n" + end, ""},
		{"ordinary profile fragment", begin + "*** Add File: /etc/profile.d/review.sh\n+export EDITOR=vi\n" + end, ""},
		{"pam comment", begin + "*** Update File: /etc/pam.d/sshd\n@@\n+# reviewed by the team\n" + end, ""},
		{"daemon.json with a loopback registry", begin + "*** Add File: /etc/docker/daemon.json\n+{\"insecure-registries\":[\"http://127.0.0.1:5000\"]}\n" + end, ""},
		{"link to an ordinary file", begin + "*** Update File: lnk-notes\n@@\n+hello\n" + end, ""},
	}
	spellings := []struct{ name, open, close, indent string }{
		{"single quoted", "<<\x27PATCH\x27", "PATCH", ""},
		{"unquoted", "<<PATCH", "PATCH", ""},
		{"double quoted", "<<\"PATCH\"", "PATCH", ""},
		{"backslash", "<<\\PATCH", "PATCH", ""},
		{"dash unquoted", "<<-PATCH", "PATCH", ""},
		{"dash unquoted with tabs", "<<-PATCH", "\tPATCH", "\t"},
		{"dash double quoted with tabs", "<<-\"PATCH\"", "\tPATCH", "\t"},
	}
	for _, connector := range []string{"codex", "claudecode"} {
		for _, pack := range []string{"", "strict"} {
			for _, spelling := range spellings {
				for _, row := range bodies {
					t.Run(connector+"/"+pack+"/"+spelling.name+"/"+row.name, func(t *testing.T) {
						patch := row.patch
						if spelling.indent != "" {
							patch = spelling.indent + strings.ReplaceAll(strings.TrimSuffix(patch, "\n"), "\n", "\n"+spelling.indent) + "\n"
						}
						command := "apply_patch " + spelling.open + "\n" + patch + spelling.close + "\n"
						tool, input := "Bash", map[string]any{"command": command}
						if connector == "codex" {
							tool, input = "exec_command", map[string]any{"cmd": command}
						}
						body := mustJSON(t, map[string]any{
							"session_id": "shell-patch-spellings", "hook_event_name": "PreToolUse", "cwd": project,
							"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu-shell-patch-spellings",
							"tool_input": input,
						})
						got := overLimitHostHookInPack(t, connector, pack, home, string(body), hookpaths.Resolve(body))
						blocked := overLimitHookAction(t, got) == "block"
						if blocked != (row.rule != "") || row.rule != "" && !strings.Contains(got, row.rule) {
							t.Fatalf("blocked=%t, want block=%t by %q: %.500s", blocked, row.rule != "", row.rule, got)
						}
					})
				}
			}
		}
	}
}
