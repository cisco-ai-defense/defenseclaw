// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func prepareOpenCodePluginArtifactDestination(path string) error {
	dir := filepath.Dir(path)
	created, err := safefile.CreatePrivateDirectory(dir)
	if err != nil {
		return fmt.Errorf("create private OpenCode plugin directory: %w", err)
	}
	// A directory created for this registration must retain its private DACL.
	// An existing OpenCode plugin directory may harmlessly grant read/list
	// access, but it must be current-user owned, non-reparse throughout its
	// ancestry, and free of foreign write authority.
	if created {
		err = safefile.ValidatePrivateDirectory(dir)
	} else {
		err = safefile.ValidatePrivateDirectoryOwnership(dir)
	}
	if err != nil {
		return fmt.Errorf("validate OpenCode plugin directory custody: %w", err)
	}

	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect OpenCode managed plugin target: %w", err)
	}
	if err := safefile.ValidatePrivateFileOwnership(path); err != nil {
		return fmt.Errorf("validate OpenCode managed plugin target: %w", err)
	}
	return nil
}
