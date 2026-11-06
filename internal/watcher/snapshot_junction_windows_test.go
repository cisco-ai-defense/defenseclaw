// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func makeSnapshotTestJunction(t *testing.T, junction, target string) {
	t.Helper()
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", junction, target, err, output)
	}
}

// An admitted plugin peer can be a junction, which Go reports as
// ModeIrregular rather than ModeSymlink. Its target is part of the plugin
// snapshot: retargeting it rescans, and an unchanged junction does not.
func TestR109G501BPluginSnapshotRecordsJunctionTarget(t *testing.T) {
	base := t.TempDir()
	plugin := filepath.Join(base, "provider")
	if err := os.MkdirAll(filepath.Join(plugin, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "package.json"), []byte(`{"name":"provider"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	targets := map[string]string{}
	for _, name := range []string{"ordinary", "other-ordinary", ".ssh", "foreign"} {
		dir := filepath.Join(base, name, "openclaw")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		packageName := "openclaw"
		if name == "foreign" {
			packageName = "foreign"
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"`+packageName+`"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		targets[name] = dir
	}
	peer := filepath.Join(plugin, "node_modules", "openclaw")
	makeSnapshotTestJunction(t, peer, targets["ordinary"])

	before, err := snapshotTarget(plugin, true)
	if err != nil {
		t.Fatal(err)
	}
	baseline := &audit.SnapshotRow{
		ContentHash: before.ContentHash, ScanID: "scan-1", ScannerFingerprint: "scanner-1",
	}
	again, err := snapshotTarget(plugin, true)
	if err != nil {
		t.Fatal(err)
	}
	if rescan, reason := shouldRescan(baseline, again, "scanner-1", true); rescan {
		t.Fatalf("unchanged junction rescanned: %s", reason)
	}

	for _, name := range []string{"other-ordinary", ".ssh", "foreign"} {
		t.Run(name, func(t *testing.T) {
			if err := os.Remove(peer); err != nil {
				t.Fatal(err)
			}
			makeSnapshotTestJunction(t, peer, targets[name])
			t.Cleanup(func() {
				_ = os.Remove(peer)
				makeSnapshotTestJunction(t, peer, targets["ordinary"])
			})
			after, err := snapshotTarget(plugin, true)
			if err != nil {
				t.Fatal(err)
			}
			if rescan, _ := shouldRescan(baseline, after, "scanner-1", true); !rescan {
				t.Fatalf("junction retarget to %s kept the plugin snapshot %s", name, after.ContentHash)
			}
		})
	}

	restored, err := snapshotTarget(plugin, true)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ContentHash != before.ContentHash {
		t.Fatal("restoring the ordinary junction did not restore the plugin snapshot")
	}
}

// A junction peer whose target directory is replaced at the same path, with
// the same manifest, rescans; the unchanged target does not.
func TestR109G610PluginSnapshotBindsJunctionPeerFileIdentity(t *testing.T) {
	base := t.TempDir()
	plugin := filepath.Join(base, "provider")
	target := filepath.Join(base, "peer")
	for _, dir := range []string{filepath.Join(plugin, "node_modules"), target} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	manifest := []byte(`{"name":"openclaw"}`)
	if err := os.WriteFile(filepath.Join(target, "package.json"), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	makeSnapshotTestJunction(t, filepath.Join(plugin, "node_modules", "openclaw"), target)
	assertPeerFileIdentityBound(t, plugin, target, manifest)
}
