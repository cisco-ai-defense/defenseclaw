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

// The keys file itself can be created or replaced between two scans of one
// gateway evaluation, which share a TargetMemo. The verdict names the file as
// it is when the decision is made: a name linked to a keys file created after
// the first scan is blocked, a name linked to the keys file that was replaced
// is ordinary and allowed (rel-1-0-9:GAP-0943).
func TestGatewayJudgesAReplacedKeysFileAsItIsNow(t *testing.T) {
	for _, tc := range []struct {
		name               string
		keysAtStart        bool
		aliasToKeysAtStart bool
		wantBlock          bool
	}{
		{"a name linked to a keys file created after the first scan is blocked", false, false, true},
		{"a name linked to the keys file before it was replaced is allowed", true, true, false},
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
			if tc.keysAtStart {
				if err := os.WriteFile(keys, []byte("old key"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.aliasToKeysAtStart {
				if err := os.Link(keys, alias); err != nil {
					t.Skipf("hard link: %v", err)
				}
			} else if err := os.WriteFile(alias, []byte("ordinary"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			installDefaultProfileConnector(t, "codex")
			memo := hookpaths.NewTargetMemo()
			if memo.ActionStateTargetMention("touch alias", project, home) {
				t.Fatal("the alias was taken for active state")
			}
			if tc.keysAtStart {
				if err := os.Remove(keys); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(keys, []byte("new key"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !tc.aliasToKeysAtStart {
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(keys, alias); err != nil {
					t.Skipf("hard link: %v", err)
				}
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
