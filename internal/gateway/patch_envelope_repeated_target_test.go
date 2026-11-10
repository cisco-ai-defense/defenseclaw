// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestPatchEnvelopeRepeatedTargetKeepsContentRuleVerdict pins that an
// apply_patch envelope naming one protected file in two blocks is blocked in
// the default and the strict tier by every route that carries the envelope (a
// typed Codex call, a Codex shell here-document, a Claude Code shell
// here-document), whichever block holds the protected text, however the second
// name is spelled and with the envelope padded. Each block is applied, so each
// is judged on its own and the blocks together. The same repetition of an
// ordinary file stays allowed.
func TestPatchEnvelopeRepeatedTargetKeepsContentRuleVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	const (
		preload = "/etc/ld.so.preload"
		library = "/usr/local/lib/liblogger.so"
	)
	block := func(kind, target, line string) string {
		return "*** " + kind + " File: " + target + "\n@@\n+" + line + "\n"
	}
	add := func(target, line string) string {
		return "*** Add File: " + target + "\n+" + line + "\n"
	}
	ordinary := filepath.Join(project, "notes.txt")
	for _, row := range []struct {
		name, blocks string
		rule         string // empty: the patch is ordinary and stays allowed
	}{
		{"single block", add(preload, library), "persistence.global_ld_preload_install"},
		{"add twice, protected second", add(preload, "# comment") + add(preload, library), "persistence.global_ld_preload_install"},
		{"add twice, protected first", add(preload, library) + add(preload, "# comment"), "persistence.global_ld_preload_install"},
		{"add twice, dot spelling", add(preload, "# comment") + add("/etc/./ld.so.preload", library), "persistence.global_ld_preload_install"},
		{"update twice", block("Update", preload, "# comment") + block("Update", preload, library), "persistence.global_ld_preload_install"},
		{"add then delete", add(preload, library) + "*** Delete File: " + preload + "\n", "persistence.global_ld_preload_install"},
		{"profile.d twice", add("/etc/profile.d/logger.sh", "export CLICOLOR=1") + add("/etc/profile.d/logger.sh", "export LD_PRELOAD="+library), "persistence.global_ld_preload_install"},
		{"pam.d twice", block("Update", "/etc/pam.d/sshd", "auth required pam_unix.so") + block("Update", "/etc/pam.d/sshd", "auth sufficient pam_permit.so"), "tamper.pam_permit_authentication_bypass"},
		{"ordinary file twice", add(ordinary, "# comment") + add(ordinary, "hello"), ""},
		{"ordinary update twice", block("Update", ordinary, "one") + block("Update", ordinary, "two"), ""},
	} {
		for _, pad := range []struct{ name, before, after string }{
			{"exact", "", ""},
			{"padded", " \n", "\n \t\n"},
		} {
			patch := pad.before + "*** Begin Patch\n" + row.blocks + "*** End Patch\n" + pad.after
			for _, pack := range []string{"", "strict"} {
				for _, route := range []string{"typed", "codex heredoc", "claudecode heredoc"} {
					t.Run(fmt.Sprintf("%s/%s/%q/%s", row.name, pad.name, pack, route), func(t *testing.T) {
						connector, tool, input := "codex", "apply_patch", map[string]any{"command": patch}
						if route != "typed" {
							command := "apply_patch <<'PATCH'\n" + patch + "PATCH"
							if route == "codex heredoc" {
								tool, input = "exec_command", map[string]any{"cmd": command}
							} else {
								connector, tool, input = "claudecode", "Bash", map[string]any{"command": command}
							}
						}
						body := (nativeWriteCall{connector, tool, func(string) map[string]any { return input }}).body(t, project, project)
						got := overLimitHostHookInPack(t, connector, pack, home, body,
							hookpaths.ResolveConnector(connector, "", "preToolUse", []byte(body)))
						action := overLimitHookAction(t, got)
						if row.rule != "" && (action != "block" || !strings.Contains(got, row.rule)) {
							t.Fatalf("not blocked by %s: %.600s", row.rule, got)
						}
						if row.rule == "" && action == "block" {
							t.Fatalf("ordinary repeated patch blocked: %.600s", got)
						}
					})
				}
			}
		}
	}
}
