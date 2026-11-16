// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func replaceSnapshotTestLink(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// Plugin admission validates a peer link by every link on the way to its
// target, outside the plugin root too, and by the package manifest there. The
// plugin snapshot binds the same inputs: changing any of them rescans, an
// unchanged chain does not, and the Secure Client snapshot scope is unchanged.
func TestR109G610PluginSnapshotBindsPeerResolution(t *testing.T) {
	base := t.TempDir()
	plugin := filepath.Join(base, "provider")
	if err := os.MkdirAll(filepath.Join(plugin, "node_modules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugin, "package.json"), []byte(`{"name":"provider"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ordinary", "other-ordinary", ".ssh"} {
		dir := filepath.Join(base, name, "node_modules", "openclaw")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"openclaw"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// peer -> alias/node_modules/openclaw; alias -> hop; hop -> ordinary.
	alias, hop := filepath.Join(base, "alias"), filepath.Join(base, "hop")
	replaceSnapshotTestLink(t, hop, "ordinary")
	replaceSnapshotTestLink(t, alias, hop)
	replaceSnapshotTestLink(t, filepath.Join(plugin, "node_modules", "openclaw"),
		filepath.Join(alias, "node_modules", "openclaw"))
	manifest := filepath.Join(base, "ordinary", "node_modules", "openclaw", "package.json")

	before, err := snapshotTarget(plugin, true)
	if err != nil {
		t.Fatal(err)
	}
	legacyBefore, err := snapshotTarget(plugin, false)
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
		t.Fatalf("unchanged peer chain rescanned: %s", reason)
	}

	changes := []struct {
		name            string
		change, restore func(t *testing.T)
	}{
		{"alias-to-protected",
			func(t *testing.T) { replaceSnapshotTestLink(t, alias, filepath.Join(base, ".ssh")) },
			func(t *testing.T) { replaceSnapshotTestLink(t, alias, hop) }},
		{"hop-to-protected",
			func(t *testing.T) { replaceSnapshotTestLink(t, hop, ".ssh") },
			func(t *testing.T) { replaceSnapshotTestLink(t, hop, "ordinary") }},
		{"hop-names-protected-same-destination",
			func(t *testing.T) { replaceSnapshotTestLink(t, hop, ".ssh/../ordinary") },
			func(t *testing.T) { replaceSnapshotTestLink(t, hop, "ordinary") }},
		{"hop-to-other-ordinary",
			func(t *testing.T) { replaceSnapshotTestLink(t, hop, "other-ordinary") },
			func(t *testing.T) { replaceSnapshotTestLink(t, hop, "ordinary") }},
		{"peer-manifest-foreign",
			func(t *testing.T) {
				if err := os.WriteFile(manifest, []byte(`{"name":"foreign"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			func(t *testing.T) {
				if err := os.WriteFile(manifest, []byte(`{"name":"openclaw"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
	}
	for _, change := range changes {
		t.Run(change.name, func(t *testing.T) {
			change.change(t)
			defer change.restore(t)
			after, err := snapshotTarget(plugin, true)
			if err != nil {
				t.Fatal(err)
			}
			if rescan, _ := shouldRescan(baseline, after, "scanner-1", true); !rescan {
				t.Fatalf("%s kept the plugin snapshot %s", change.name, after.ContentHash)
			}
			legacy, err := snapshotTarget(plugin, false)
			if err != nil {
				t.Fatal(err)
			}
			if legacy.ContentHash != legacyBefore.ContentHash {
				t.Fatalf("%s changed the Secure Client snapshot scope", change.name)
			}
		})
	}

	restored, err := snapshotTarget(plugin, true)
	if err != nil {
		t.Fatal(err)
	}
	if restored.ContentHash != before.ContentHash {
		t.Fatal("restoring the peer chain did not restore the plugin snapshot")
	}
}

// Plugin admission binds a validated peer target by its volume and file ID.
// A different directory at the same path, with the same manifest, rescans;
// the unchanged target does not.
func TestR109G610PluginSnapshotBindsPeerFileIdentity(t *testing.T) {
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
	if err := os.Symlink(target, filepath.Join(plugin, "node_modules", "openclaw")); err != nil {
		t.Fatal(err)
	}
	assertPeerFileIdentityBound(t, plugin, target, manifest)
}
