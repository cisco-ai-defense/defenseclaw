// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOpenClawModelOutagePromptHookGrantFollowsHostVersion(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"2026.3.24", false},
		{"2026.4.23", false},
		{"2026.4.24", true},
		{"2026.4.26", true},
		{"2026.5.12", true},
		{"", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			allowed := openClawConversationHooksSupported(tc.version)
			if allowed != tc.want {
				t.Fatalf("conversation hook support = %t, want %t", allowed, tc.want)
			}
			root := t.TempDir()
			configPath := filepath.Join(root, "openclaw.json")
			if err := patchOpenClawConfig(configPath, filepath.Join(root, "extensions", "defenseclaw"), false, false, allowed); err != nil {
				t.Fatal(err)
			}
			content, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]interface{}
			if err := json.Unmarshal(content, &config); err != nil {
				t.Fatal(err)
			}
			plugins, _ := config["plugins"].(map[string]interface{})
			entries, _ := plugins["entries"].(map[string]interface{})
			entry, _ := entries["defenseclaw"].(map[string]interface{})
			hooks, present := entry["hooks"].(map[string]interface{})
			if present != tc.want {
				t.Fatalf("conversation hook config present = %t, want %t", present, tc.want)
			}
			if present && hooks["allowConversationAccess"] != true {
				t.Fatalf("conversation hook grant = %v, want true", hooks["allowConversationAccess"])
			}
		})
	}
}

// GAP-0580 with GAP-0596: the conversation-hook grant merges into the
// operator's hooks object, and an operator's own value of the key stays.
func TestOpenClawConversationHookGrantKeepsOperatorHooks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		hooks map[string]interface{}
		want  map[string]interface{}
	}{
		{
			name:  "operator timeouts",
			hooks: map[string]interface{}{"timeouts": map[string]interface{}{"before_tool_call": float64(60000)}},
			want: map[string]interface{}{
				"timeouts":                map[string]interface{}{"before_tool_call": float64(60000)},
				"allowConversationAccess": true,
			},
		},
		{
			name:  "operator disabled the grant",
			hooks: map[string]interface{}{"allowConversationAccess": false},
			want:  map[string]interface{}{"allowConversationAccess": false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			configPath := filepath.Join(root, "openclaw.json")
			writeOpenClawJSON(t, configPath, map[string]interface{}{
				"plugins": map[string]interface{}{
					"entries": map[string]interface{}{"defenseclaw": map[string]interface{}{"hooks": tc.hooks}},
				},
			})
			for i := 0; i < 2; i++ {
				if err := patchOpenClawConfig(configPath, filepath.Join(root, "extensions", "defenseclaw"), false, false, true); err != nil {
					t.Fatal(err)
				}
			}
			entry, _ := readOpenClawEntries(t, configPath)["defenseclaw"].(map[string]interface{})
			if got := entry["hooks"]; !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("plugins.entries.defenseclaw.hooks = %v, want %v", got, tc.want)
			}
			if entry["enabled"] != true {
				t.Fatalf("plugins.entries.defenseclaw.enabled = %v, want true", entry["enabled"])
			}
		})
	}
}
