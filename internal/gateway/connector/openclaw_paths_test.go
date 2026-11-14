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
	"testing"
)

// Setup and Teardown act on the OpenClaw home and openclaw.json config.yaml
// names (claw.home_dir, claw.config_file), not on ~/.openclaw of the process
// account, and the methods without SetupOpts follow the last layout.
func TestOpenClawSetupHonoursConfiguredHome(t *testing.T) {
	requireOpenClawExtensionBundle(t)
	dir := t.TempDir()
	t.Setenv("HOME", filepath.Join(dir, "account"))
	t.Setenv("USERPROFILE", filepath.Join(dir, "account"))
	home := filepath.Join(dir, "srv", "openclaw")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970",
		OpenClawHome: home, OpenClawConfigPath: filepath.Join(home, "openclaw.json")}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	c := NewOpenClawConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "extensions", "defenseclaw", "package.json")); err != nil {
		t.Fatalf("plugin not installed in the configured home: %v", err)
	}
	if !openClawConfigRegistersDefenseClaw(filepath.Join(home, "openclaw.json")) {
		t.Fatal("configured openclaw.json does not register the plugin")
	}
	if _, err := os.Stat(filepath.Join(dir, "account", ".openclaw")); !os.IsNotExist(err) {
		t.Fatalf("setup touched ~/.openclaw of the process account: %v", err)
	}
	if got, want := c.BundledPluginDir(), filepath.Join(home, "extensions", "defenseclaw"); got != want {
		t.Fatalf("BundledPluginDir = %q, want %q", got, want)
	}
	if got := c.ComponentTargets("")["config"]; len(got) != 1 || got[0] != filepath.Join(home, "openclaw.json") {
		t.Fatalf("ComponentTargets config = %v", got)
	}
	// A caller that names no paths (CLI teardown) acts on the same layout.
	bare := opts
	bare.OpenClawHome, bare.OpenClawConfigPath = "", ""
	if err := c.Teardown(context.Background(), bare); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "extensions", "defenseclaw")); !os.IsNotExist(err) {
		t.Fatalf("teardown left the plugin in the configured home: %v", err)
	}
}

func TestResolveOpenClawPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	def := filepath.Join(dir, ".openclaw")
	cases := []struct{ home, config, wantHome, wantConfig string }{
		{"", "", def, filepath.Join(def, "openclaw.json")},
		{"/srv/oc", "", filepath.Clean("/srv/oc"), filepath.Join(filepath.Clean("/srv/oc"), "openclaw.json")},
		{"/srv/oc", "/etc/oc/main.json", filepath.Clean("/srv/oc"), filepath.Clean("/etc/oc/main.json")},
	}
	for _, tc := range cases {
		p := resolveOpenClawPaths(tc.home, tc.config, "")
		if p.home != tc.wantHome || p.config != tc.wantConfig {
			t.Errorf("resolveOpenClawPaths(%q, %q) = %+v, want %q %q", tc.home, tc.config, p, tc.wantHome, tc.wantConfig)
		}
	}
}
