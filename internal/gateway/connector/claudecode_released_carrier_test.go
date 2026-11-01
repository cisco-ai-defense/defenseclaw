// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// oss-outage-open round h (GAP-1422 class): the Claude Code settings env is
// one of the product-owned fail-mode carriers. testdata/released-carriers
// holds the real ~/.claude/settings.json and claudecode_backup.json that the
// published 1.0.2 (DEFENSECLAW_FAIL_MODE=open) and 1.0.3 (=closed) installers
// left after a per-user install with Claude Code, captured on RHEL 9.8 (home
// path and bearer tokens replaced). The upgrade's per-user setup must leave
// no product-owned fail mode there, whichever value the release wrote, run
// after run, keep the user's own env keys, and keep a carrier value the user
// changed after the release wrote it (the user owns it then).
func TestClaudeCodeUpgradeFromReleasedSettingsTakesBackTheFailModeCarrier(t *testing.T) {
	const carrier = "DEFENSECLAW_FAIL_MODE"
	for _, tc := range []struct {
		release  string
		wrote    string
		userSets string // "" keeps the release's value
		want     string // "" for absent
	}{
		{release: "1.0.2", wrote: "open"},
		{release: "1.0.3", wrote: "closed"},
		{release: "1.0.2", wrote: "open", userSets: "closed", want: "closed"},
		{release: "1.0.3", wrote: "closed", userSets: "open", want: "open"},
	} {
		name := tc.release + " wrote " + tc.wrote
		if tc.userSets != "" {
			name += ", user set " + tc.userSets
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			dataDir := filepath.Join(home, ".defenseclaw")
			settingsPath := filepath.Join(home, ".claude", "settings.json")
			for _, dir := range []string{dataDir, filepath.Dir(settingsPath)} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			released := func(name string) []byte {
				t.Helper()
				data, err := os.ReadFile(filepath.Join("testdata", "released-carriers", tc.release, name))
				if err != nil {
					t.Fatal(err)
				}
				return bytes.ReplaceAll(data, []byte("__HOME__"), []byte(filepath.ToSlash(home)))
			}
			settings := map[string]interface{}{}
			if err := json.Unmarshal(released("claude-settings.json"), &settings); err != nil {
				t.Fatal(err)
			}
			env := settings["env"].(map[string]interface{})
			if env[carrier] != tc.wrote {
				t.Fatalf("released %s settings env %s = %v, want %q", tc.release, carrier, env[carrier], tc.wrote)
			}
			env["MY_OWN_FLAG"] = "kept"
			if tc.userSets != "" {
				env[carrier] = tc.userSets
			}
			data, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dataDir, "claudecode_backup.json"), released("claudecode_backup.json"), 0o600); err != nil {
				t.Fatal(err)
			}
			previous := ClaudeCodeSettingsPathOverride
			ClaudeCodeSettingsPathOverride = settingsPath
			t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
			c := NewClaudeCodeConnector()
			opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", HookFailMode: "open"}
			for run := 1; run <= 2; run++ {
				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatalf("setup run %d: %v", run, err)
				}
				data, err := os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				after := map[string]interface{}{}
				if err := json.Unmarshal(data, &after); err != nil {
					t.Fatal(err)
				}
				env, _ := after["env"].(map[string]interface{})
				got, present := env[carrier]
				switch {
				case tc.want == "" && present:
					t.Fatalf("run %d: the %s settings env keeps the product-owned %s=%v", run, tc.release, carrier, got)
				case tc.want != "" && got != tc.want:
					t.Fatalf("run %d: settings env %s = %v, want the user's %q", run, carrier, got, tc.want)
				}
				if env["MY_OWN_FLAG"] != "kept" {
					t.Fatalf("run %d: the user's own env key was not kept: %v", run, env["MY_OWN_FLAG"])
				}
			}
		})
	}
}
