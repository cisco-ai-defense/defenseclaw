// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// oss-outage-open review (round g, loop round 2): a per-user Claude Code
// setup wrote DEFENSECLAW_FAIL_MODE=closed into ~/.claude/settings.json on
// every run, so after a 1.0.2 upgrade (or a fresh install) the settings kept a
// product-owned closed while an unset default-tier outage opens, and status
// reported claude-env-closed. No 1.0.4 render reads that variable. A per-user
// setup now writes no carrier and takes back the value an earlier setup or
// release wrote, unchanged; a value the user set stays. Managed and Secure
// Client installs keep theirs.
func TestClaudeCodePerUserSetupTakesBackTheFailModeCarrier(t *testing.T) {
	const carrier = "DEFENSECLAW_FAIL_MODE"
	for _, tc := range []struct {
		name     string
		opts     func(SetupOpts) SetupOpts
		recorded string // what an earlier setup wrote and recorded; "" for a fresh install
		absent   bool   // the backup records the carrier taken away; current is written back over it
		current  string // what settings.json holds before the setup ("" for absent)
		want     string // "" for absent
	}{
		{name: "fresh per-user install"},
		{name: "1.0.2 upgrade, product-owned closed", recorded: "closed", current: "closed"},
		{name: "1.0.3 upgrade, product-owned open of a saved open", recorded: "open", current: "open"},
		{name: "earlier 1.0.4 build, product-owned closed", recorded: "closed", current: "closed"},
		{name: "the user changed it", recorded: "closed", current: "open", want: "open"},
		// GAP-2388: rollback to 1.0.3 and roll forward. The live backup is the
		// one this setup wrote (carrier recorded absent); the 1.0.3 gateway put
		// the saved mode back.
		{name: "an earlier release wrote back the saved mode", absent: true, current: "open"},
		{name: "a different value after the absence stays", absent: true, current: "closed", want: "closed"},
		{name: "managed install keeps the administrator's mode",
			opts: func(o SetupOpts) SetupOpts { o.ManagedEnterprise = true; o.HookFailMode = "open"; return o },
			want: "open"},
		{name: "Secure Client keeps its carrier",
			opts: func(o SetupOpts) SetupOpts { o.SecureClientHookDelivery = true; o.HookFailMode = "open"; return o },
			want: "closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			settingsPath := filepath.Join(dir, "claude", "settings.json")
			if err := os.MkdirAll(filepath.Dir(settingsPath), 0o700); err != nil {
				t.Fatal(err)
			}
			previous := ClaudeCodeSettingsPathOverride
			ClaudeCodeSettingsPathOverride = settingsPath
			t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })
			c := NewClaudeCodeConnector()
			opts := SetupOpts{DataDir: dir, APIAddr: "127.0.0.1:18970", HookFailMode: "open"}
			if tc.opts != nil {
				opts = tc.opts(opts)
			}
			readEnv := func() map[string]interface{} {
				t.Helper()
				data, err := os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				var settings map[string]interface{}
				if err := json.Unmarshal(data, &settings); err != nil {
					t.Fatal(err)
				}
				env, _ := settings["env"].(map[string]interface{})
				return env
			}
			if err := c.Setup(context.Background(), opts); err != nil {
				t.Fatal(err)
			}
			if tc.absent {
				data, err := os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				var settings map[string]interface{}
				if err := json.Unmarshal(data, &settings); err != nil {
					t.Fatal(err)
				}
				env, _ := settings["env"].(map[string]interface{})
				if env == nil {
					env = map[string]interface{}{}
					settings["env"] = env
				}
				env[carrier] = tc.current
				if data, err = json.Marshal(settings); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.recorded != "" {
				// The settings and backup an earlier setup or release left.
				data, err := os.ReadFile(settingsPath)
				if err != nil {
					t.Fatal(err)
				}
				var settings map[string]interface{}
				if err := json.Unmarshal(data, &settings); err != nil {
					t.Fatal(err)
				}
				env := settings["env"].(map[string]interface{})
				env[carrier] = tc.current
				if data, err = json.Marshal(settings); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
					t.Fatal(err)
				}
				backup, err := c.loadBackup(dir)
				if err != nil {
					t.Fatal(err)
				}
				backup.ManagedEnv[carrier] = tc.recorded
				absent := backup.ManagedAbsentEnv[:0]
				for _, key := range backup.ManagedAbsentEnv {
					if key != carrier {
						absent = append(absent, key)
					}
				}
				backup.ManagedAbsentEnv = absent
				if err := c.saveBackup(dir, backup); err != nil {
					t.Fatal(err)
				}
			}
			// The upgrade's setup, and one more run: the result is stable.
			for run := 1; run <= 2; run++ {
				if err := c.Setup(context.Background(), opts); err != nil {
					t.Fatalf("setup run %d: %v", run, err)
				}
				got, present := readEnv()[carrier]
				switch {
				case tc.want == "" && present:
					t.Fatalf("run %d: settings env keeps %s=%v, want it taken back", run, carrier, got)
				case tc.want != "" && got != tc.want:
					t.Fatalf("run %d: settings env %s = %v, want %q", run, carrier, got, tc.want)
				}
			}
		})
	}
}
