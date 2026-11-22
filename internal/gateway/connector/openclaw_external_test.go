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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openClawExternalFixture(t *testing.T) (dir string, opts SetupOpts, home string) {
	t.Helper()
	requireOpenClawExtensionBundle(t)
	root := t.TempDir()
	home = filepath.Join(root, "oc-home")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(root, "opt", "defenseclaw")
	if err := ExportOpenClawPlugin(dir); err != nil {
		t.Fatalf("export: %v", err)
	}
	prev := openClawPluginTreeTrusted
	openClawPluginTreeTrusted = func(string) error { return nil }
	t.Cleanup(func() { openClawPluginTreeTrusted = prev })
	dataDir := filepath.Join(root, "dc")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	opts = SetupOpts{DataDir: dataDir, ProxyAddr: "127.0.0.1:4000", APIAddr: "127.0.0.1:18970",
		OpenClawHome: home, OpenClawPluginDir: dir}
	return dir, opts, home
}

// An administrator-installed plugin is registered, never written or deleted.
func TestOpenClawExternalPluginRegisteredNotWritten(t *testing.T) {
	dir, opts, home := openClawExternalFixture(t)
	before := openClawTreeDigest(t, dir)
	c := NewOpenClawConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "extensions", "defenseclaw")); !os.IsNotExist(err) {
		t.Fatalf("external mode wrote a managed copy: %v", err)
	}
	cfg := readOpenClawJSON5(t, filepath.Join(home, "openclaw.json"))
	paths := cfg["plugins"].(map[string]interface{})["load"].(map[string]interface{})["paths"].([]interface{})
	if len(paths) != 1 || paths[0] != dir {
		t.Fatalf("load.paths = %v, want [%s]", paths, dir)
	}
	if got := c.BundledPluginDir(); got != dir {
		t.Fatalf("BundledPluginDir = %q, want %q", got, dir)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if after := openClawTreeDigest(t, dir); after != before {
		t.Fatal("teardown changed the administrator-installed plugin")
	}
}

// A plugin that is not exactly this build (a file missing, added or changed)
// is refused before openclaw.json changes.
func TestOpenClawExternalPluginMustMatchBundleExactly(t *testing.T) {
	for _, damage := range []string{"missing", "extra", "changed"} {
		t.Run(damage, func(t *testing.T) {
			dir, opts, home := openClawExternalFixture(t)
			switch damage {
			case "missing":
				if err := os.Remove(filepath.Join(dir, "openclaw.plugin.json")); err != nil {
					t.Fatal(err)
				}
			case "extra":
				if err := os.WriteFile(filepath.Join(dir, "dist", "extra.js"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "changed":
				if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{\"version\":\"0.0.1\"}"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(home, "openclaw.json")
			if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			err := NewOpenClawConnector().Setup(context.Background(), opts)
			if !errors.Is(err, errOpenClawPreflight) || !strings.Contains(err.Error(), "export-plugin") {
				t.Fatalf("Setup err = %v, want a preflight refusal naming export-plugin", err)
			}
			if got := mustReadFileString(t, configPath); got != "{}\n" {
				t.Fatalf("openclaw.json changed: %q", got)
			}
		})
	}
}

// A plugin folder the account does not own (an administrator copy in the
// managed location) stops setup before anything changes.
func TestOpenClawPreflightRefusesForeignManagedPlugin(t *testing.T) {
	_, configPath, opts := openClawJSON5Fixture(t, t.TempDir())
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	managedDir := filepath.Join(filepath.Dir(configPath), "extensions", "defenseclaw")
	if err := os.MkdirAll(managedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prev := openClawPathOwnedForWrite
	openClawPathOwnedForWrite = func(p string) error {
		if p == managedDir {
			return errors.New("owner uid 0")
		}
		return nil
	}
	t.Cleanup(func() { openClawPathOwnedForWrite = prev })
	err := NewOpenClawConnector().Setup(context.Background(), opts)
	if !errors.Is(err, errOpenClawPreflight) || !strings.Contains(err.Error(), "plugin_install external") {
		t.Fatalf("Setup err = %v, want the external-mode hint", err)
	}
	if got := mustReadFileString(t, configPath); got != "{}\n" {
		t.Fatalf("openclaw.json changed: %q", got)
	}
}

func openClawTreeDigest(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p)
		b.WriteString(p)
		b.Write(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
