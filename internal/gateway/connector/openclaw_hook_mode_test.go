// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"testing"
)

func TestResolveOpenClawHookMode(t *testing.T) {
	prev := openClawHooksGOOS
	t.Cleanup(func() { openClawHooksGOOS = prev })
	cases := []struct{ goos, configured, version, want string }{
		{"linux", "auto", "2026.11.3", OpenClawHookModeHybrid},
		{"linux", "auto", "2026.8.35", OpenClawHookModeHybrid},
		{"linux", "auto", "2026.8.34", OpenClawHookModeProxy},
		{"linux", "auto", "", OpenClawHookModeProxy},
		{"darwin", "proxy", "2026.11.3", OpenClawHookModeProxy},
		{"windows", "auto", "2026.11.3", OpenClawHookModeNative},
		{"windows", "auto", "", OpenClawHookModeNative},
	}
	for _, tc := range cases {
		openClawHooksGOOS = tc.goos
		if got := ResolveOpenClawHookMode(tc.configured, tc.version); got != tc.want {
			t.Errorf("%s %s %q: got %s, want %s", tc.goos, tc.configured, tc.version, got, tc.want)
		}
	}
}

// Setup writes config.hookMode for the native hooks and teardown takes it out
// again; the proxy mode leaves a 1.0.9 openclaw.json as it was.
func TestOpenClawSetupWritesAndRemovesHookMode(t *testing.T) {
	prev := openClawHooksGOOS
	openClawHooksGOOS = "linux"
	t.Cleanup(func() { openClawHooksGOOS = prev })
	for _, tc := range []struct{ version, want string }{{"2026.11.3", "hybrid"}, {"2026.6.8", ""}} {
		_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
		original := "{\"plugins\": {\"entries\": {\"defenseclaw\": {\"config\": {\"agent\": {\"id\": \"a\"}}}}}}\n"
		if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
			t.Fatal(err)
		}
		opts.AgentVersion = tc.version
		opts.OpenClawHooksMode = "auto"
		c := NewOpenClawConnector()
		if err := c.Setup(context.Background(), opts); err != nil {
			t.Fatalf("%s Setup: %v", tc.version, err)
		}
		cfg := readOpenClawJSON5(t, configPath)
		entry := cfg["plugins"].(map[string]interface{})["entries"].(map[string]interface{})["defenseclaw"].(map[string]interface{})
		got, _ := entry["config"].(map[string]interface{})[openClawHookModeKey].(string)
		if got != tc.want {
			t.Fatalf("%s: hookMode = %q, want %q", tc.version, got, tc.want)
		}
		if err := c.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("%s Teardown: %v", tc.version, err)
		}
		if got := mustReadFileString(t, configPath); got != original {
			t.Fatalf("%s: teardown left %q, want the original", tc.version, got)
		}
	}
}

// The plugin reads only the scoped credential, so setup must not fall back
// to the master gateway token for openclaw.
func TestOpenClawRequiresScopedPluginCredential(t *testing.T) {
	if !RequiresScopedHookToken(NewOpenClawConnector()) {
		t.Fatal("openclaw must require the connector-scoped plugin credential")
	}
}

// rel-1-0-10 GAP-0069: plugins.allow is an exclusive allowlist, so setup
// joins one the operator has and creates none; a list with only
// defenseclaw that an earlier setup created is taken out again.
func TestOpenClawSetupCreatesNoAllowlist(t *testing.T) {
	cases := []struct{ name, before, wantAllow string }{
		{"no list", "{\"plugins\": {}}\n", ""},
		{"operator list", "{\"plugins\": {\"allow\": [\"browser\"]}}\n", "browser,defenseclaw"},
	}
	for _, tc := range cases {
		_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
		if err := os.WriteFile(configPath, []byte(tc.before), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := NewOpenClawConnector().Setup(context.Background(), opts); err != nil {
			t.Fatalf("%s: Setup: %v", tc.name, err)
		}
		plugins := readOpenClawJSON5(t, configPath)["plugins"].(map[string]interface{})
		got := ""
		if list, ok := plugins["allow"].([]interface{}); ok {
			for i, v := range list {
				if i > 0 {
					got += ","
				}
				got += v.(string)
			}
		}
		if got != tc.wantAllow {
			t.Errorf("%s: plugins.allow = %q, want %q", tc.name, got, tc.wantAllow)
		}
	}
}
