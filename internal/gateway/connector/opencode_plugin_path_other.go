// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"
)

// createOpenCodePluginArtifactDestination makes the plugin folder of path
// and checks the plugin target (see prepareOpenCodePluginArtifactDestination).
func createOpenCodePluginArtifactDestination(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("plugin target must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin target must be a regular file: %s", path)
	}
	return nil
}
