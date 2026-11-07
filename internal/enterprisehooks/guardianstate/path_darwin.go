//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"os"
	"path/filepath"
)

// pathForDataDir matches the macOS guardian writer. The managed install
// keeps data_dir at <root>/runtime and the guardian's manifest folder at
// <root>/hook-guardian, where the guardian writes its state next to
// targets.yaml. That sibling is used when it is a real folder; any other
// layout keeps the data-dir subdirectory convention.
func pathForDataDir(dataDir string) string {
	clean := filepath.Clean(dataDir)
	if filepath.Base(clean) == "runtime" {
		sibling := filepath.Join(filepath.Dir(clean), StateDirName)
		if info, err := os.Lstat(sibling); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return PathForStateRoot(sibling)
		}
	}
	return filepath.Join(dataDir, StateDirName, FileName)
}

func readStatePathTrusted(path string) (bool, error) {
	info, err := os.Lstat(path)
	return err != nil || info.Mode()&os.ModeSymlink == 0, nil
}
