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

// The scans of one gateway evaluation share a TargetMemo (state scan, keys
// proof, action decision). A file that becomes or stops being a hard link to
// the user authorized-keys file between two of them is judged as it is when
// the decision is made, with or without the memo (rel-1-0-9:GAP-0943).
func TestGatewayJudgesAHardLinkChangedBetweenScansAsItIsNow(t *testing.T) {
	for _, tc := range []struct {
		name           string
		protectedAtEnd bool
	}{
		{"an ordinary file that became a hard link to the keys file is blocked", true},
		{"a hard link to the keys file that became an ordinary file is allowed", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			project := filepath.Join(home, "project")
			keys := filepath.Join(home, ".ssh", "authorized_keys")
			alias := filepath.Join(project, "alias")
			for _, dir := range []string{project, filepath.Dir(keys)} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(keys, []byte("key\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.protectedAtEnd {
				if err := os.WriteFile(alias, []byte("ordinary"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Link(keys, alias); err != nil {
				t.Skipf("hard link: %v", err)
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
			if tc.protectedAtEnd {
				if err := os.Link(keys, alias); err != nil {
					t.Skipf("hard link: %v", err)
				}
			} else if err := os.WriteFile(alias, []byte("ordinary"), 0o600); err != nil {
				t.Fatal(err)
			}
			args, err := json.Marshal(map[string]string{"command": "touch alias"})
			if err != nil {
				t.Fatal(err)
			}
			input := actionfacts.Input{
				Tool: "Bash", Args: args, Command: "touch alias", CWD: project,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: "codex", EnforcementCapable: true,
				targetMemo: memo,
			})
			if blocked := buildVerdict(findings, "tool_call").Action == guardrailActionBlock; blocked != tc.protectedAtEnd {
				t.Fatalf("blocked=%v, want %v (findings %v)", blocked, tc.protectedAtEnd, FindingStrings(findings))
			}
		})
	}
}
