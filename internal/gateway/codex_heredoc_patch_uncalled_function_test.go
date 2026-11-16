// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX files and links.

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// TestCodexHeredocPatchInAFunctionNoCallRunsFollowsTheTier: a patch of a
// closed-folder key link inside a function body is a write only when a call
// runs the body. The balanced tiers read no body that no call runs, so the
// text that defines the function and runs another command is allowed; the
// strict tier reads every body and blocks it; a call to the function blocks in
// every tier.
func TestCodexHeredocPatchInAFunctionNoCallRunsFollowsTheTier(t *testing.T) {
	patch := codexHeredocPatch("Add File", "keys-link", "+ssh-ed25519 AAAA review\n")
	rows := []struct {
		name, command string
		blocked       map[string]bool
	}{
		{"function never called", "f() {\n" + patch + "}\ntrue\n",
			map[string]bool{"default": false, "permissive": false, "strict": true}},
		{"function called", "f() {\n" + patch + "}\nf\n",
			map[string]bool{"default": true, "permissive": true, "strict": true}},
		{"function never called, ordinary file", "f() {\n" + codexHeredocPatch("Add File", "notes-review.txt", "+notes\n") + "}\ntrue\n",
			map[string]bool{"default": false, "permissive": false, "strict": false}},
	}
	for _, managed := range []bool{false, true} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			for _, row := range rows {
				name := map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + profile + "/" + row.name
				t.Run(name, func(t *testing.T) {
					blocked, body := postConnectorHookBehindProtectHome(t, "codex", managed, profile, func(home, project string) map[string]any {
						closedKeyFolderProject(t, home, project)
						return codexBashCall(row.command)(project)
					})
					if blocked != row.blocked[profile] {
						t.Fatalf("blocked = %t, want %t: %.500s", blocked, row.blocked[profile], body)
					}
					if blocked && !strings.Contains(body, authorizedKeysRuleID) {
						t.Fatalf("blocked without %s: %.500s", authorizedKeysRuleID, body)
					}
				})
			}
		}
	}
}
