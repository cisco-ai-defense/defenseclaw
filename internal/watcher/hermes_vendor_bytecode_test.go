// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// plantBytecode writes a bytecode cache file for the __init__.py of a
// shipped plugin. Hermes imports a plugin with spec_from_file_location and
// exec_module (hermes_cli/plugins_loader.py), so CPython loads such a file in
// place of the verified source whenever its header names the source mtime
// and size, or the source hash, or is an unchecked hash pyc
// (f5-pyc-proof in the GAP-0765 evidence). Its bytes are what runs.
func plantBytecode(t *testing.T, path string) {
	t.Helper()
	writePluginFile(t, filepath.Join(path, "__pycache__", "__init__.cpython-312.pyc"), "\x0d\x0d\x0d\x0aplanted bytecode")
}

// rel-1-0-10:GAP-0765 review F5 (GAP-0808): a shipped plugin whose source
// tree is the release tree but whose bytecode cache holds a file is not
// vendor content: the digest proves the source, not the bytecode Python runs.
// It is scanned on first sight.
func TestHermesShippedPluginWithBytecodeIsNotVendor(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.hermesReleasePlugin("0.23.1")
	plantBytecode(t, path)
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(path); n != 1 {
		t.Fatalf("release plugin with a bytecode cache file scans = %d, want 1", n)
	}
	if _, err := hermesPluginTreeDigest(path); err == nil {
		t.Fatal("a tree with a bytecode cache file has a vendor digest")
	}
}

// rel-1-0-10:GAP-0765 review F5 (GAP-0808): bytecode written into a plugin
// after it was taken as vendor content is a change: the next cycle admits it
// and refuses it for its HIGH finding, as an edit of the source would be.
func TestHermesVendorPluginBytecodeWrittenLaterIsAdmitted(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.hermesReleasePlugin("0.23.1")
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
	plantBytecode(t, path)
	f.w.runRescanCycle(context.Background())
	if n := f.scan.scans(path); n != 1 {
		t.Fatalf("vendor plugin scans after a bytecode write = %d, want 1", n)
	}
	f.refused(path)
}

// The release tree stays vendor content with an empty bytecode cache folder,
// and the digest of a clean release tree is the one shipped for it.
func TestHermesReleasePluginWithEmptyCacheFolderIsVendor(t *testing.T) {
	f := newHermesPluginFixture(t)
	path := f.hermesReleasePlugin("0.23.1")
	if err := os.MkdirAll(filepath.Join(path, "__pycache__"), 0o700); err != nil {
		t.Fatal(err)
	}
	f.w.runRescanCycle(context.Background())
	f.w.runRescanCycle(context.Background())
	f.unscannedVendor(path)
}
