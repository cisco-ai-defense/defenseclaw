// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests use only the watcher API of da4177e225, so they compile on it
// (rel-1-0-10:GAP-0765, code-close bar).

// scannerChanged rewrites the stored baseline of path as a scanner of another
// release (an upgrade, or a rule pack or scanner binary change) would have
// left it: the same bytes and scan, another scanner fingerprint, and the same
// admission digest, so the next rescan sees scanner-fingerprint-changed.
func (f *hermesPluginFixture) scannerChanged(path string) {
	f.t.Helper()
	row, err := f.store.GetTargetSnapshot("plugin", path)
	if err != nil || row == nil || row.ScanID == "" {
		f.t.Fatalf("baseline of %s: %#v, %v; want a stored scan", path, row, err)
	}
	fingerprint := "scanner-of-another-release"
	if i := strings.Index(row.ScannerFingerprint, admissionDigestMark); i >= 0 {
		fingerprint += row.ScannerFingerprint[i:]
	}
	if err := f.store.SetTargetSnapshot("plugin", path, row.ContentHash, row.DependencyHashes,
		row.ConfigHashes, row.NetworkEndpoints, row.ScanID, fingerprint); err != nil {
		f.t.Fatal(err)
	}
}

// hermesBytecode writes the cache file CPython 3.12 writes for the
// __init__.py of a shipped plugin when Hermes imports it.
func hermesBytecode(t *testing.T, path, body string) {
	t.Helper()
	writePluginFile(t, filepath.Join(path, "__pycache__", "__init__.cpython-312.pyc"), "\xcb\x0d\x0d\x0a"+body)
}

// rel-1-0-10:GAP-0765: Hermes writes bytecode for every shipped plugin it
// imports, so every plugin of a Hermes that has run holds a cache file and is
// not vendor content (GAP-0808). It is scanned once, and a scanner change (an
// upgrade of DefenseClaw, a rule pack) does not scan it again while its
// source still matches its release digest and its bytecode is the bytecode
// that scan saw. On da4177e225 every scanner change scanned it again
// (dc-rhel dcr-std2: 79 shipped plugins after the 1.0.5 upgrade).
func TestHermesVendorSourceWithBytecodeIsScannedOnceAcrossScannerChanges(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.hermesReleasePlugin("0.23.1")
	hermesBytecode(t, path, "bytecode of the release __init__.py")
	ctx := context.Background()
	f.w.runRescanCycle(ctx)
	if n := f.scan.scans(path); n != 1 {
		t.Fatalf("first sight scans = %d, want 1", n)
	}
	first, err := f.store.GetTargetSnapshot("plugin", path)
	if err != nil {
		t.Fatal(err)
	}
	for change := 1; change <= 3; change++ {
		f.scannerChanged(path)
		f.w.runRescanCycle(ctx)
		f.w.runRescanCycle(ctx)
		if n := f.scan.scans(path); n != 1 {
			t.Fatalf("scans after scanner change %d = %d, want 1 (no rescan of vendor source with the bytecode its scan saw)", change, n)
		}
	}
	row, err := f.store.GetTargetSnapshot("plugin", path)
	if err != nil {
		t.Fatal(err)
	}
	if row.ScanID != first.ScanID || row.ScannerFingerprint != first.ScannerFingerprint {
		t.Fatalf("baseline after the scanner changes = %#v, want scan %s under the current fingerprint %s", row, first.ScanID, first.ScannerFingerprint)
	}
	if _, err := hermesPluginTreeDigest(path); err == nil {
		t.Fatal("a tree with bytecode has a vendor digest")
	}
}

// rel-1-0-10:GAP-0765: a plugin whose stored scan was made by an earlier
// release, which kept no record of the bytecode it saw (the 1.0.5 to 1.0.10
// upgrade), is scanned once at the first scanner change and not at the next.
func TestHermesVendorSourceWithBytecodeScannedBeforeUpgradeIsScannedOncePerUpgrade(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.hermesReleasePlugin("0.23.1")
	hermesBytecode(t, path, "bytecode of the release __init__.py")
	ctx := context.Background()
	f.w.runRescanCycle(ctx)
	// The row of the bytecode a scan saw is new: a store of an earlier
	// release has none.
	if err := f.store.DeleteTargetSnapshot("hermes_plugin_bytecode", path); err != nil {
		t.Fatal(err)
	}
	f.scannerChanged(path)
	f.w.runRescanCycle(ctx)
	if n := f.scan.scans(path); n != 2 {
		t.Fatalf("scans at the first scanner change after the upgrade = %d, want 2", n)
	}
	f.scannerChanged(path)
	f.w.runRescanCycle(ctx)
	f.w.runRescanCycle(ctx)
	if n := f.scan.scans(path); n != 2 {
		t.Fatalf("scans at the next scanner change = %d, want 2", n)
	}
}

// rel-1-0-10:GAP-0765, no fail-open: bytecode is never vouched for. Bytecode
// that differs from what the stored scan saw, a cache file with no source, a
// cache entry CPython does not write, or an edited source is scanned at the
// scanner change; an edited source is admitted and refused for its HIGH
// finding. None of them is vendor content.
func TestHermesBytecodeTheScanDidNotSeeIsScannedAtAScannerChange(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, path string)
		// refused is true when the change must reach admission and be
		// refused for the HIGH finding, not only a scan.
		refused bool
	}{
		{name: "bytecode rewritten", change: func(t *testing.T, path string) {
			hermesBytecode(t, path, "bytecode Python would run in place of the verified source")
		}},
		{name: "bytecode added", change: func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "__pycache__", "__init__.cpython-313.pyc"), "\xf3\x0d\x0d\x0aother")
		}},
		{name: "bytecode of a missing source", change: func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "__pycache__", "helper.cpython-312.pyc"), "\xcb\x0d\x0d\x0asourceless")
		}},
		{name: "bytecode left after its source was removed", change: func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "sub", "mod.py"), "X = 1\n")
			writePluginFile(t, filepath.Join(path, "sub", "__pycache__", "mod.cpython-312.pyc"), "\xcb\x0d\x0d\x0amod")
			if err := os.Remove(filepath.Join(path, "sub", "mod.py")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "file in a cache that CPython does not write", change: func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "__pycache__", "__init__.pyc"), "\xcb\x0d\x0d\x0anot a cache name")
		}},
		{name: "folder in a cache", change: func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "__pycache__", "nested", "__init__.cpython-312.pyc"), "\xcb\x0d\x0d\x0anested")
		}},
		{name: "cache folder in another case", change: func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "__PYCACHE__", "__init__.cpython-312.pyc"), "\xcb\x0d\x0d\x0acase")
		}},
		{name: "cache file extension in another case", change: func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "__pycache__", "__init__.cpython-312.PYC"), "\xcb\x0d\x0d\x0acase")
		}},
		{name: "source edited", refused: true, change: func(t *testing.T, path string) {
			writePluginFile(t, filepath.Join(path, "__init__.py"), "import os\nos.system('id')\n")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newHermesPluginFixture(t)
			path := f.hermesReleasePlugin("0.23.1")
			hermesBytecode(t, path, "bytecode of the release __init__.py")
			ctx := context.Background()
			f.w.runRescanCycle(ctx)
			tc.change(t, path)
			if !tc.refused {
				// A cycle without a scanner change records no bytecode for
				// the stored scan. (A change the content hash covers, such
				// as a folder named __PYCACHE__ on a case-sensitive file
				// system, is admitted here.)
				f.w.runRescanCycle(ctx)
			}
			before := f.scan.scans(path)
			f.scannerChanged(path)
			f.w.runRescanCycle(ctx)
			if n := f.scan.scans(path); n != before+1 {
				t.Fatalf("scans after %s and a scanner change = %d, want %d", tc.name, n, before+1)
			}
			if tc.refused {
				f.refused(path)
			}
			if _, err := hermesPluginTreeDigest(path); err == nil {
				t.Fatalf("%s: the tree has a vendor digest", tc.name)
			}
		})
	}
}

// rel-1-0-10:GAP-0765, no fail-open: a link in a bytecode cache is not
// bytecode of a source; the plugin is scanned at every scanner change.
func TestHermesLinkInBytecodeCacheIsScannedAtAScannerChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need a privilege on Windows")
	}
	f := newHermesPluginFixture(t)
	path := f.hermesReleasePlugin("0.23.1")
	outside := filepath.Join(t.TempDir(), "payload.pyc")
	writePluginFile(t, outside, "\xcb\x0d\x0d\x0aoutside")
	if err := os.MkdirAll(filepath.Join(path, "__pycache__"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, "__pycache__", "__init__.cpython-312.pyc")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f.w.runRescanCycle(ctx)
	for change := 1; change <= 2; change++ {
		f.scannerChanged(path)
		f.w.runRescanCycle(ctx)
		if n := f.scan.scans(path); n != 1+change {
			t.Fatalf("scans after scanner change %d = %d, want %d", change, n, 1+change)
		}
	}
}

// rel-1-0-10:GAP-0765: Secure Client keeps its rescan of every shipped
// plugin at a scanner change, and with content gating off every cycle scans.
func TestHermesBytecodeScanOnceKeepsSecureClientAndUngatedRescans(t *testing.T) {
	for _, secureClient := range []bool{true, false} {
		t.Run(map[bool]string{true: "secure client", false: "gating off"}[secureClient], func(t *testing.T) {
			f := newHermesPluginFixture(t)
			if secureClient {
				f.cfg.DeploymentMode = "managed_enterprise"
				f.cfg.Enterprise.Profile = "secure_client"
				if !f.w.secureClientActive() {
					t.Fatal("the Secure Client profile is not active")
				}
			} else {
				f.cfg.Watch.RescanContentGated = false
			}
			path := f.hermesReleasePlugin("0.23.1")
			hermesBytecode(t, path, "bytecode of the release __init__.py")
			ctx := context.Background()
			f.w.runRescanCycle(ctx)
			first := f.scan.scans(path)
			if first != 1 {
				t.Fatalf("first sight scans = %d, want 1", first)
			}
			for change := 1; change <= 2; change++ {
				f.scannerChanged(path)
				f.w.runRescanCycle(ctx)
				if n := f.scan.scans(path); n != 1+change {
					t.Fatalf("scans after scanner change %d = %d, want %d", change, n, 1+change)
				}
			}
		})
	}
}

// rel-1-0-10:GAP-0765: a plugin that is not a shipped plugin keeps its
// rescan at every scanner change, bytecode or not, and so does a shipped
// plugin whose source matches no release.
func TestPluginOutsideVendorSourceIsScannedAtEveryScannerChange(t *testing.T) {
	for _, shipped := range []bool{false, true} {
		t.Run(map[bool]string{false: "user plugin", true: "shipped plugin with edited source"}[shipped], func(t *testing.T) {
			f := newHermesPluginFixture(t)
			var path string
			if shipped {
				path = f.hermesReleasePlugin("0.23.1")
				writePluginFile(t, filepath.Join(path, "__init__.py"), "EDITED = True\n")
			} else {
				path = f.plugin(f.userRoot, "notes")
				writePluginFile(t, filepath.Join(path, "__init__.py"), "X = 1\n")
			}
			hermesBytecode(t, path, "bytecode")
			ctx := context.Background()
			f.w.runRescanCycle(ctx)
			for change := 1; change <= 2; change++ {
				f.scannerChanged(path)
				f.w.runRescanCycle(ctx)
				if n := f.scan.scans(path); n != 1+change {
					t.Fatalf("scans after scanner change %d = %d, want %d", change, n, 1+change)
				}
			}
		})
	}
}
