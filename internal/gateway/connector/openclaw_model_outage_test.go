// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
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
