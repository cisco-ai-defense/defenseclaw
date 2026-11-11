// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-6:GAP-1064: a shell write whose operand reaches a managed agent
// settings file DefenseClaw publishes through an existing project link (a
// link to the vendor folder, to the file, to another link) is the same state
// mutation as the direct path, in every profile, per-user and managed, on
// both hooks. The decision is the file the operand reaches, not the link
// name. A link to an ordinary folder, another file in the vendor folder and
// a read through the link stay allowed.
func TestManagedAgentSettingsThroughProjectLinkAreSelfProtection(t *testing.T) {
	home, project := dynamicWordParityProject(t)
	if err := os.Mkdir(filepath.Join(project, "ordinary"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{
		"lnk-cc":           "/etc/claude-code",
		"lnk-mac":          "/Library/Application Support/ClaudeCode",
		"lnk-codex-file":   "/etc/codex/requirements.toml",
		"lnk-chain":        filepath.Join(project, "lnk-cc"),
		"lnk-ordinary":     filepath.Join(project, "ordinary"),
		"lnk-codex-folder": "/etc/codex",
	} {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	protected := []string{
		"printf x > lnk-cc/managed-settings.json",
		"echo x >> lnk-mac/managed-settings.d/50-defenseclaw.json",
		"sed -i d lnk-cc/managed-settings.json",
		"sed -i --follow-symlinks d lnk-codex-file",
		"cp a.txt lnk-codex-folder/requirements.toml",
		"rm lnk-mac/managed-settings.json",
		"printf x > lnk-codex-file",
		"printf x > lnk-chain/managed-settings.json",
		"cd lnk-cc && printf x > managed-settings.json",
	}
	allowed := []string{
		"printf x > lnk-ordinary/managed-settings.json",
		"sed -i d lnk-ordinary/managed-settings.json",
		"printf x > lnk-cc/notes.txt",
		"cat lnk-cc/managed-settings.json",
		"cp lnk-cc/managed-settings.json copy.txt",
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, pack := range []string{"", "strict"} {
			for _, managed := range []bool{false, true} {
				for _, command := range protected {
					got := postManagedSettingsShellCell(t, home, project, connector, pack, managed, command)
					if !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, "tamper.detector_state_write") {
						t.Errorf("%s managed=%t pack=%q: %s = %.160s, want protected block", connector, managed, pack, command, got)
					}
				}
				if pack == "strict" {
					continue
				}
				for _, command := range allowed {
					if got := postManagedSettingsShellCell(t, home, project, connector, pack, managed, command); strings.HasPrefix(got, `{"action":"block"`) {
						t.Errorf("%s managed=%t pack=%q: %s = %.160s, want allow", connector, managed, pack, command, got)
					}
				}
			}
		}
	}
}
