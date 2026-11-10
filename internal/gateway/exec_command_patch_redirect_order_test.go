// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// An apply_patch here-document gets the verdict of the typed tool when it is
// the stdin the shell leaves (the last input redirect of descriptor 0), and an
// ordinary call whose stdin is another file stays allowed; a protected file
// beside a context line that shows an expansion is still judged.
func TestShellApplyPatchRedirectOrderDecidesWhichStdinIsJudged(t *testing.T) {
	home, project := hermesPatchHome(t)
	const (
		lib    = "/usr/local/lib/libreview.so"
		loader = "persistence.global_ld_preload_install"
		begin  = "*** Begin Patch\n"
		end    = "*** End Patch\n"
	)
	protected := begin + "*** Add File: /etc/ld.so.preload\n+" + lib + "\n" + end
	decoy := begin + "*** Add File: /etc/ld.so.preload\n+" + lib + "\n+# built by $USER\n" + end
	ordinary := begin + "*** Add File: notes-order.txt\n+hello\n" + end
	context := begin + "*** Update File: notes-order.txt\n@@\n *** $USER\n+hello\n"
	rows := []struct{ name, command, rule string }{
		{"document after a null input", "apply_patch </dev/null <<EOF\n" + protected + "EOF\n", loader},
		{"document after a descriptor 0 input", "apply_patch 0</dev/null <<EOF\n" + protected + "EOF\n", loader},
		{"quoted document after a null input", "apply_patch </dev/null <<\x27EOF\x27\n" + protected + "EOF\n", loader},
		{"ordinary document after a null input", "apply_patch </dev/null <<EOF\n" + ordinary + "EOF\n", ""},
		{"file after the document", "apply_patch <<EOF < ordinary.patch\n" + decoy + "EOF\n", ""},
		{"descriptor 0 file after the document", "apply_patch <<EOF 0< ordinary.patch\n" + decoy + "EOF\n", ""},
		{"file after the literal document", "apply_patch <<EOF < ordinary.patch\n" + protected + "EOF\n", ""},
		{"protected file beside an expanding context line", "apply_patch <<EOF\n" + context + "*** Add File: /etc/ld.so.preload\n+" + lib + "\n" + end + "EOF\n", loader},
		{"ordinary file beside an expanding context line", "apply_patch <<EOF\n" + context + "*** Add File: other-order.txt\n+hello\n" + end + "EOF\n", ""},
	}
	for _, connector := range []string{"codex", "claudecode"} {
		for _, pack := range []string{"", "strict"} {
			for _, row := range rows {
				t.Run(connector+"/"+pack+"/"+row.name, func(t *testing.T) {
					tool, input := "Bash", map[string]any{"command": row.command}
					if connector == "codex" {
						tool, input = "exec_command", map[string]any{"cmd": row.command}
					}
					body := mustJSON(t, map[string]any{
						"session_id": "shell-patch-redirect-order", "hook_event_name": "PreToolUse", "cwd": project,
						"permission_mode": "default", "tool_name": tool, "tool_use_id": "toolu-shell-patch-redirect-order",
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
