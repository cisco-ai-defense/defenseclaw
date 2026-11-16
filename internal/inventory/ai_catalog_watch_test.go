// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// A signature-pack glob with a wildcard folder names the folders a new pack
// can appear in: its fixed folder before any match exists, then each
// matching folder (GAP-0858).
func TestSignaturePackWildcardFolderGlobIsWatched(t *testing.T) {
	root := t.TempDir()
	entry := filepath.Join(root, "packs", "*", "pack.json")
	if err := os.MkdirAll(filepath.Join(root, "packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	files, dirs := SignaturePackEntry(entry)
	if len(files) != 0 || !slices.Equal(dirs, []string{filepath.Join(root, "packs")}) || SignaturePackWildcardDirs(entry) != nil {
		t.Fatalf("before any match: files %v, watch %v, wildcard dirs %v", files, dirs, SignaturePackWildcardDirs(entry))
	}
	team := filepath.Join(root, "packs", "team")
	mustWrite(t, filepath.Join(team, "pack.json"), `{"version":1}`)
	files, dirs = SignaturePackEntry(entry)
	if !slices.Equal(files, []string{filepath.Join(team, "pack.json")}) || !slices.Contains(dirs, team) ||
		!slices.Equal(SignaturePackWildcardDirs(entry), []string{team}) {
		t.Fatalf("after a match: files %v, watch %v, wildcard dirs %v", files, dirs, SignaturePackWildcardDirs(entry))
	}
	plain := filepath.Join(root, "packs", "*.json")
	if _, dirs := SignaturePackEntry(plain); !slices.Equal(dirs, []string{filepath.Join(root, "packs")}) || SignaturePackWildcardDirs(plain) != nil {
		t.Fatalf("a glob with a fixed folder: watch %v", dirs)
	}
}
