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
	"path/filepath"
	"strings"
	"testing"
)

// Native Windows OpenClaw (O2): Setup installs and registers the plugin in
// native hook mode, writes the scoped plugin credential and no bash PATH
// shims, and teardown restores openclaw.json.
func TestOpenClawWindowsNativeSetupInstallsPluginWithoutShims(t *testing.T) {
	t.Cleanup(PinOpenClawHooksGOOSForTest("windows"))
	dir := t.TempDir()
	_, configPath, opts := openClawJSON5Fixture(t, dir)
	original := "{\"gateway\": {\"port\": 18789}}\n"
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	token, err := EnsureHookAPIToken(dir, "openclaw")
	if err != nil {
		t.Fatalf("EnsureHookAPIToken: %v", err)
	}
	opts.HookAPIToken, opts.HookAPITokenScoped = token, true
	opts.APIToken = token
	opts.AgentVersion = "2026.11.3"
	c := NewOpenClawConnector()
	if got := c.SubprocessPolicy(); got != SubprocessNone {
		t.Fatalf("SubprocessPolicy on Windows = %q, want none", got)
	}
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	cfg := readOpenClawJSON5(t, configPath)
	entry := cfg["plugins"].(map[string]interface{})["entries"].(map[string]interface{})["defenseclaw"].(map[string]interface{})
	if got, _ := entry["config"].(map[string]interface{})[openClawHookModeKey].(string); got != OpenClawHookModeNative {
		t.Fatalf("hookMode = %q, want native", got)
	}
	if !openClawExtensionMatchesBundle(c.pathsFor(opts).pluginDir()) {
		t.Fatal("the plugin under the OpenClaw home is not the bundled plugin")
	}
	if _, err := os.Stat(filepath.Join(dir, "shims")); !os.IsNotExist(err) {
		t.Fatalf("native Windows setup wrote PATH shims (stat err %v)", err)
	}
	if got, err := LoadHookAPIToken(dir, "openclaw"); err != nil || got != token {
		t.Fatalf("scoped plugin credential = %q, %v; want the issued token", got, err)
	}
	paths := c.AgentPaths(opts)
	if len(paths.GeneratedExecutables) != 0 || len(paths.GeneratedFiles) != 0 {
		t.Fatalf("AgentPaths lists shim files on Windows: %+v", paths)
	}
	for _, d := range paths.CreatedDirs {
		if strings.Contains(d, "shims") {
			t.Fatalf("AgentPaths lists the shim folder on Windows: %s", d)
		}
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if got := mustReadFileString(t, configPath); got != original {
		t.Fatalf("teardown left %q, want the original", got)
	}
}

// Windows refuses an OpenClaw without the native hooks and a managed
// (enterprise) install before anything is written.
func TestOpenClawWindowsSetupRefusals(t *testing.T) {
	t.Cleanup(PinOpenClawHooksGOOSForTest("windows"))
	for _, tc := range []struct {
		name    string
		version string
		managed bool
		want    string
	}{
		{"old OpenClaw", "2026.8.34", false, OpenClawNativeHooksSince},
		{"managed Windows", "2026.11.3", true, "managed Windows are not in this release"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
			opts.AgentVersion = tc.version
			opts.ManagedEnterprise = tc.managed
			err := NewOpenClawConnector().Setup(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Setup error = %v, want it to name %q", err, tc.want)
			}
			if _, statErr := os.Stat(configPath); !os.IsNotExist(statErr) {
				t.Fatalf("refused setup wrote %s (stat err %v)", configPath, statErr)
			}
		})
	}
}

// Linux and macOS keep the PATH shims and the proxy (1.0.9 behaviour).
func TestOpenClawUnixKeepsShimsAndProxy(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		restore := PinOpenClawHooksGOOSForTest(goos)
		c := NewOpenClawConnector()
		if got := c.SubprocessPolicy(); got != SubprocessShims {
			t.Errorf("%s SubprocessPolicy = %q, want shims", goos, got)
		}
		if !UsesGuardrailProxy("openclaw") {
			t.Errorf("%s: OpenClaw must keep the guardrail proxy", goos)
		}
		restore()
	}
}
