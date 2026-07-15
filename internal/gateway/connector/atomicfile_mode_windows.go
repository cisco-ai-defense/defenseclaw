// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func atomicFileProtectionMatches(file *os.File, info os.FileInfo, perm os.FileMode) bool {
	if perm.Perm()&0o077 == 0 {
		return validateAtomicTransformBoundFilePrivatePlatform(file) == nil
	}
	return info.Mode().Perm() == perm.Perm()
}

func atomicFileValidateStagedProtection(file *os.File, perm os.FileMode) error {
	if perm.Perm()&0o077 != 0 {
		return nil
	}
	return validateAtomicTransformBoundFilePrivatePlatform(file)
}

// atomicFileBeforePrivatePublish is a Windows-only test seam invoked after the
// staged file and its DACL have been bound to handles but before publication.
var atomicFileBeforePrivatePublish func(string) error

func atomicFilePublish(source, destination string, stagedInfo os.FileInfo, perm os.FileMode) error {
	if perm.Perm()&0o077 != 0 {
		return safefile.ReplaceFile(source, destination)
	}
	if !atomicTransformPathsEqualPlatform(filepath.Dir(source), filepath.Dir(destination)) {
		return fmt.Errorf("private atomic publication crosses directories")
	}

	parent, err := openAtomicTransformBoundDirectoryPlatform(filepath.Dir(destination))
	if err != nil {
		return fmt.Errorf("open bound publication directory: %w", err)
	}
	defer parent.Close()
	stage, err := openAtomicTransformBoundFilePlatform(parent, filepath.Base(source), true)
	if err != nil {
		return fmt.Errorf("open bound staged file: %w", err)
	}
	defer stage.Close()
	openedInfo, err := stage.Stat()
	if err != nil {
		return fmt.Errorf("stat bound staged file: %w", err)
	}
	if !os.SameFile(stagedInfo, openedInfo) {
		return fmt.Errorf("staged private file changed before publication")
	}
	if err := validateAtomicTransformBoundFilePrivatePlatform(stage); err != nil {
		return fmt.Errorf("validate bound staged file: %w", err)
	}
	if atomicFileBeforePrivatePublish != nil {
		if err := atomicFileBeforePrivatePublish(destination); err != nil {
			return err
		}
	}

	// Private publication deliberately replaces the destination with the
	// already-private staged inode. Unlike ReplaceFileW, changed writes do not
	// retain destination metadata such as alternate data streams, EFS state, or
	// its DACL. Identical writes return before this point and preserve metadata.
	if err := renameAtomicTransformBoundFilePlatform(parent, stage, filepath.Base(destination), true); err != nil {
		return err
	}
	published, err := openAtomicTransformBoundFilePlatform(parent, filepath.Base(destination), false)
	if err != nil {
		return fmt.Errorf("open published private file: %w", err)
	}
	publishedInfo, statErr := published.Stat()
	privateErr := validateAtomicTransformBoundFilePrivatePlatform(published)
	closeErr := published.Close()
	if statErr != nil {
		return fmt.Errorf("stat published private file: %w", statErr)
	}
	if !os.SameFile(openedInfo, publishedInfo) {
		return fmt.Errorf("published private file identity changed")
	}
	if privateErr != nil {
		return fmt.Errorf("validate published private file: %w", privateErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close published private file: %w", closeErr)
	}
	return nil
}
