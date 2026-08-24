// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
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

// atomicFileCreateTemp creates private Windows staging files with the
// effective user as their explicit owner in the create operation. An elevated
// user's token can otherwise choose BUILTIN\Administrators as the default
// owner, leaving a foreign-owned pathname that the subsequent fail-closed
// protection check must reject. Creating through the already handle-bound
// NT path also prevents a parent-directory name swap from redirecting the
// staged object.
func atomicFileCreateTemp(dir string, perm os.FileMode) (*os.File, string, error) {
	if perm.Perm()&0o077 != 0 {
		file, err := os.CreateTemp(dir, ".tmp-*")
		if err != nil {
			return nil, "", err
		}
		return file, file.Name(), nil
	}

	parent, err := openAtomicTransformBoundDirectoryPlatform(dir)
	if err != nil {
		return nil, "", fmt.Errorf("open private staging directory: %w", err)
	}
	defer parent.Close()
	if err := validateAtomicTransformBoundDirectoryPlatform(parent, false); err != nil {
		return nil, "", fmt.Errorf("validate private staging directory: %w", err)
	}

	for attempt := 0; attempt < 128; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate private staging name: %w", err)
		}
		name := ".tmp-" + hex.EncodeToString(random[:])
		file, err := createAtomicTransformBoundFilePlatform(parent, name, perm)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create private staging file: %w", err)
		}
		return file, filepath.Join(dir, name), nil
	}
	return nil, "", fmt.Errorf("create private staging file: exhausted collision retries")
}

// atomicFileBeforePrivatePublish is a Windows-only test seam invoked after the
// staged file and its DACL have been bound to handles but before publication.
var atomicFileBeforePrivatePublish func(string) error

func atomicFilePublish(source, destination string, stagedInfo os.FileInfo, perm os.FileMode) error {
	if perm.Perm()&0o077 != 0 {
		return safefile.ReplaceFile(source, destination)
	}
	return atomicFilePublishPrivateBound(
		source,
		destination,
		stagedInfo,
		validateAtomicTransformBoundFilePrivatePlatform,
		false,
	)
}

func atomicFilePublishHookAPIToken(
	source, destination string,
	stagedInfo os.FileInfo,
	perm os.FileMode,
) error {
	if perm.Perm()&0o077 != 0 {
		return fmt.Errorf("hook API token publication requires a private file mode")
	}
	return atomicFilePublishPrivateBound(
		source,
		destination,
		stagedInfo,
		validateHookAPITokenBoundFileCustodyPlatform,
		true,
	)
}

func atomicFilePublishPrivateBound(
	source, destination string,
	stagedInfo os.FileInfo,
	validate func(*os.File) error,
	preserveExactHookProtection bool,
) error {
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
	if err := validate(stage); err != nil {
		return fmt.Errorf("validate bound staged file: %w", err)
	}
	stageProtection := hookAPITokenPublishProtection{}
	if preserveExactHookProtection {
		stageProtection, _, err = captureHookAPITokenPublishProtectionPlatform(stage, openedInfo)
		if err != nil {
			return fmt.Errorf("capture bound staged hook-token protection: %w", err)
		}
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
	if preserveExactHookProtection {
		afterRename, _, protectionErr := captureHookAPITokenPublishProtectionPlatform(stage, openedInfo)
		if protectionErr != nil {
			return fmt.Errorf("capture renamed hook-token protection: %w", protectionErr)
		}
		if !hookAPITokenPublishProtectionsEqual(stageProtection, afterRename) {
			// The held rename handle excludes metadata writers for this freshly
			// staged inode. If NTFS inheritance bookkeeping normalized its DACL,
			// restore the authenticated stage descriptor before releasing it.
			if err := applyHookAPITokenPublishProtectionPlatform(stage, stageProtection); err != nil {
				return fmt.Errorf("restore renamed hook-token protection: %w", err)
			}
			afterRename, _, protectionErr = captureHookAPITokenPublishProtectionPlatform(stage, openedInfo)
			if protectionErr != nil {
				return fmt.Errorf("recapture renamed hook-token protection: %w", protectionErr)
			}
			if !hookAPITokenPublishProtectionsEqual(stageProtection, afterRename) {
				return fmt.Errorf("renamed hook-token protection does not match its staged inode")
			}
		}
	}
	published, err := openAtomicTransformBoundFilePlatform(parent, filepath.Base(destination), false)
	if err != nil {
		return fmt.Errorf("open published private file: %w", err)
	}
	publishedInfo, statErr := published.Stat()
	privateErr := validate(published)
	publishedProtection := hookAPITokenPublishProtection{}
	var protectionErr error
	if statErr == nil && privateErr == nil && preserveExactHookProtection {
		publishedProtection, _, protectionErr = captureHookAPITokenPublishProtectionPlatform(published, publishedInfo)
	}
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
	if protectionErr != nil {
		return fmt.Errorf("capture published hook-token protection: %w", protectionErr)
	}
	if preserveExactHookProtection {
		if !hookAPITokenPublishProtectionsEqual(stageProtection, publishedProtection) {
			return fmt.Errorf("published hook-token protection does not match its staged inode")
		}
	}
	if closeErr != nil {
		return fmt.Errorf("close published private file: %w", closeErr)
	}
	return nil
}
