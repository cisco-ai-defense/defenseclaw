// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A link named by the command can be retargeted between two scans of one
// gateway evaluation, which share a TargetMemo. The balanced verdict names the
// link as it is when the decision is made: a link that now leads to the keys
// file is blocked, a link that now leads to an ordinary file is allowed
// (rel-1-0-9:GAP-0943).
func TestGatewayJudgesARetargetedLinkAsItIsNow(t *testing.T) {
	for _, tc := range []struct {
		name          string
		first, second string
		wantBlock     bool
	}{
		{"a link retargeted from an ordinary file to the keys file is blocked", "ordinary", "keys", true},
		{"a link retargeted from the keys file to an ordinary file is allowed", "keys", "ordinary", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			project := filepath.Join(home, "project")
			targets := map[string]string{
				"keys":     filepath.Join(home, ".ssh", "authorized_keys"),
				"ordinary": filepath.Join(project, "ordinary"),
			}
			alias := filepath.Join(project, "alias")
			for _, dir := range []string{project, filepath.Join(home, ".ssh")} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, path := range targets {
				if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(targets[tc.first], alias); err != nil {
				t.Skipf("symlink: %v", err)
			}
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			installDefaultProfileConnector(t, "codex")
			memo := hookpaths.NewTargetMemo()
			if memo.ActionStateTargetMention("touch alias", project, home) {
				t.Fatal("the alias was taken for active state")
			}
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(targets[tc.second], alias); err != nil {
				t.Fatal(err)
			}
			args, err := json.Marshal(map[string]string{"command": "touch alias"})
			if err != nil {
				t.Fatal(err)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: actionfacts.Input{
					Tool: "Bash", Args: args, Command: "touch alias", CWD: project,
					ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
				},
				LegacyText: string(args), Connector: "codex", EnforcementCapable: true,
				targetMemo: memo,
			})
			if blocked := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; blocked != tc.wantBlock {
				t.Fatalf("blocked=%v, want %v (findings %v)", blocked, tc.wantBlock, FindingStrings(findings))
			}
		})
	}
}
