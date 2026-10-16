// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// rel-1-0-1:GAP-0009: an orphaned entry is found by the hook script path it
// runs, in any wrapping, and never by a longer name that starts with it.
func TestCommandNamesScriptMatchesWholePathsOnly(t *testing.T) {
	scripts := []string{"/home/u/.defenseclaw/hooks/claude-code-hook.sh"}
	for command, want := range map[string]bool{
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh":                                                     true,
		"'/home/u/.defenseclaw/hooks/claude-code-hook.sh' --event Stop":                                      true,
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh || { rc=$?; exit 2; }":                               true,
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh.bak":                                                 false,
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh2":                                                    false,
		"/home/u/.defenseclaw/hooks/claude-code-hook.sh.old; /home/u/.defenseclaw/hooks/claude-code-hook.sh": true,
		"/opt/operator/hooks/claude-code-hook.sh":                                                            false,
	} {
		if got := commandNamesScript(command, scripts); got != want {
			t.Errorf("commandNamesScript(%q) = %v, want %v", command, got, want)
		}
	}
}

func TestHookCommandRunsScriptLooksOnlyAtCommands(t *testing.T) {
	scripts := []string{"/d/hooks/codex-hook.sh"}
	doc := map[string]interface{}{
		"description": "/d/hooks/codex-hook.sh",
		"hooks": map[string]interface{}{
			"Stop": []interface{}{map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"command": "/usr/bin/true"}}}},
		},
	}
	if hookCommandRunsScript(doc, scripts) {
		t.Fatal("a non-command field counted as a hook entry")
	}
	doc["hooks"].(map[string]interface{})["Stop"] = []interface{}{
		map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"command": "/d/hooks/codex-hook.sh"}}},
	}
	if !hookCommandRunsScript(doc, scripts) {
		t.Fatal("the hook entry that runs the script was not found")
	}
}

// rel-1-0-1:GAP-0009 for a plugin-file connector: the managed plugin is an
// orphan only when it is DefenseClaw's (ownership marker on the first line)
// and reads its credential from this data directory's hooks folder.
func TestOrphanedPluginArtifactNeedsTheMarkerAndThisDataDirectory(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	dataDir := filepath.Join(root, "dc")
	pluginPath := filepath.Join(root, "plugins", "defenseclaw.js")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	tokenLine := func(path string) string {
		encoded, err := json.Marshal(path)
		if err != nil {
			t.Fatal(err)
		}
		return "const DC_TOKEN_FILE = " + string(encoded) + ";\n"
	}
	ours := tokenLine(filepath.Join(dataDir, "hooks", ".hook-opencode.token"))
	opts := SetupOpts{DataDir: dataDir}
	for name, tc := range map[string]struct {
		body string
		want bool
	}{
		"DefenseClaw plugin of this data dir": {"// defenseclaw-managed-plugin v7\n" + ours, true},
		"an older DefenseClaw plugin":         {"// defenseclaw-managed-plugin v3\r\n" + ours, true},
		"another data dir":                    {"// defenseclaw-managed-plugin v7\n" + tokenLine(filepath.Join(root, "other", "hooks", ".hook-opencode.token")), false},
		"a credential deeper in the folder":   {"// defenseclaw-managed-plugin v7\n" + tokenLine(filepath.Join(dataDir, "hooks", "x", ".hook-opencode.token")), false},
		"no ownership marker first":           {"// operator plugin\n// defenseclaw-managed-plugin v7\n" + ours, false},
		"a sandbox render (no credential)":    {"// defenseclaw-managed-plugin v7\nconst DC_HOOK_SOCKET = \"\";\n", false},
		"a relative credential path":          {"// defenseclaw-managed-plugin v7\nconst DC_TOKEN_FILE = \"hooks/.hook-opencode.token\";\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(pluginPath, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := OrphanedHookConfigPaths(NewOpenCodeConnector(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) == 1 && got[0] == pluginPath) != tc.want || len(got) > 1 {
				t.Fatalf("OrphanedHookConfigPaths = %v, want the plugin: %v", got, tc.want)
			}
		})
	}
	if err := os.Remove(pluginPath); err != nil {
		t.Fatal(err)
	}
	if got, err := OrphanedHookConfigPaths(NewOpenCodeConnector(), opts); err != nil || len(got) != 0 {
		t.Fatalf("no plugin: OrphanedHookConfigPaths = %v, %v", got, err)
	}
}

// The Amp TypeScript render declares the credential without a semicolon.
func TestManagedPluginTokenFileReadsTheJavaScriptAndTypeScriptRenders(t *testing.T) {
	token := filepath.Join(testenv.PrivateTempDir(t), "Defense\"Claw", "hooks", ".hook-amp.token")
	encoded, err := json.Marshal(token)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"const DC_TOKEN_FILE = " + string(encoded) + "\n", "const DC_TOKEN_FILE = " + string(encoded) + ";\r\n"} {
		got, ok := managedPluginTokenFile([]byte("// defenseclaw-managed-plugin v2\nconst DC_API_ADDR = \"127.0.0.1:1\"\n" + line))
		if !ok || got != token {
			t.Fatalf("managedPluginTokenFile(%q) = %q, %v", line, got, ok)
		}
	}
}
