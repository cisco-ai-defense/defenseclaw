// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The connector guards that resolve a path and then check it is below a root
// follow a junction as they follow a symbolic link: a standard user makes a
// junction without any privilege (rel-1-0-10:GAP-2182).
func TestConnectorRootGuardsFollowAJunctionOutOfTheRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "inner"), outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{filepath.Join(outside, "plugin.so"), filepath.Join(root, "inner", "plugin.so")} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	escape := filepath.Join(root, "escape")
	twin := filepath.Join(root, "twin")
	makeGAP2182ConnectorJunction(t, escape, outside)
	makeGAP2182ConnectorJunction(t, twin, filepath.Join(root, "inner"))

	t.Run("plugin path", func(t *testing.T) {
		if err := validatePluginPath(filepath.Join(escape, "plugin.so"), root); err == nil {
			t.Error("validatePluginPath accepted a plugin reached through a junction out of the root")
		}
		if err := validatePluginPath(filepath.Join(twin, "plugin.so"), root); err != nil {
			t.Errorf("validatePluginPath refused a junction that stays inside the root: %v", err)
		}
	})
	t.Run("remove below parent", func(t *testing.T) {
		if err := safeRemoveAll(escape, root); err == nil {
			t.Error("safeRemoveAll accepted a junction out of the parent")
		}
		if _, err := os.Stat(filepath.Join(outside, "plugin.so")); err != nil {
			t.Fatalf("the junction target lost its file: %v", err)
		}
		if err := safeRemoveAll(twin, root); err != nil {
			t.Errorf("safeRemoveAll refused a junction that stays inside the parent: %v", err)
		}
	})
	t.Run("workspace outside data dir", func(t *testing.T) {
		data := filepath.Join(base, "data")
		if err := os.MkdirAll(filepath.Join(data, "ws"), 0o700); err != nil {
			t.Fatal(err)
		}
		into := filepath.Join(base, "into-data")
		makeGAP2182ConnectorJunction(t, into, filepath.Join(data, "ws"))
		if workspaceRootOutsideDataDir(into, data) {
			t.Error("a workspace reached through a junction into the data dir was judged outside it")
		}
	})
}

func makeGAP2182ConnectorJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
	}
}
