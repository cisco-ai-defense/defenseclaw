// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package redaction

import (
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func loadOrCreateCorrelationKeyPlatform(dataDir string, entropy keyEntropyReader, hooks keyStoreHooks) (CorrelationKey, error) {
	if dataDir == "" {
		return CorrelationKey{}, keyStoreError(KeyStoreErrorInvalidDataDir)
	}

	dirFD, err := unix.Open(
		dataDir,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return CorrelationKey{}, keyStoreError(KeyStoreErrorInvalidDataDir)
		}
		return CorrelationKey{}, keyStoreError(KeyStoreErrorUnavailable)
	}
	dir := os.NewFile(uintptr(dirFD), correlationKeyFilename)
	if dir == nil {
		_ = unix.Close(dirFD)
		return CorrelationKey{}, keyStoreError(KeyStoreErrorUnavailable)
	}
	defer func() { _ = dir.Close() }()
	dirFD = int(dir.Fd())

	for attempt := 0; attempt < keyInstallAttempts; attempt++ {
		key, found, loadErr := loadExistingCorrelationKey(dirFD, hooks)
		if loadErr != nil {
			return CorrelationKey{}, loadErr
		}
		if found {
			return key, nil
		}

		var material [hashV1KeySize]byte
		if _, err := io.ReadFull(entropy, material[:]); err != nil {
			return CorrelationKey{}, keyStoreError(KeyStoreErrorEntropy)
		}
		candidate := newCorrelationKey(material)
		installed, installErr := installCorrelationKey(dirFD, candidate, entropy, hooks)
		if installErr != nil {
			return CorrelationKey{}, installErr
		}
		if installed {
			return candidate, nil
		}
		// Another creator won the no-replace link race. Loop through the same
		// no-follow validation path and converge on that key.
	}

	return CorrelationKey{}, keyStoreError(KeyStoreErrorInstall)
}

func loadExistingCorrelationKey(dirFD int, hooks keyStoreHooks) (CorrelationKey, bool, error) {
	fd, err := unix.Openat(
		dirFD,
		correlationKeyFilename,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		switch {
		case errors.Is(err, unix.ENOENT):
			return CorrelationKey{}, false, nil
		case errors.Is(err, unix.ELOOP):
			return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnsafeType)
		default:
			return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
		}
	}

	file := os.NewFile(uintptr(fd), correlationKeyFilename)
	if file == nil {
		_ = unix.Close(fd)
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
	}
	defer func() { _ = file.Close() }()

	var before unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
	}
	if err := validateCorrelationKeyStat(&before); err != nil {
		return CorrelationKey{}, false, err
	}
	if err := runAfterExistingValidation(hooks); err != nil {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
	}

	var material [hashV1KeySize]byte
	if _, err := io.ReadFull(file, material[:]); err != nil {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorInvalidLength)
	}
	var extra [1]byte
	if n, err := file.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorInvalidLength)
	}

	var after unix.Stat_t
	if err := unix.Fstat(fd, &after); err != nil {
		return CorrelationKey{}, false, keyStoreError(KeyStoreErrorUnavailable)
	}
	if err := validateCorrelationKeyStat(&after); err != nil {
		return CorrelationKey{}, false, err
	}
	return newCorrelationKey(material), true, nil
}

func validateCorrelationKeyStat(stat *unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return keyStoreError(KeyStoreErrorUnsafeType)
	}
	if int(stat.Uid) != os.Geteuid() {
		return keyStoreError(KeyStoreErrorUnsafeOwner)
	}
	if stat.Mode&0o077 != 0 {
		return keyStoreError(KeyStoreErrorUnsafePermissions)
	}
	if stat.Size != hashV1KeySize {
		return keyStoreError(KeyStoreErrorInvalidLength)
	}
	return nil
}

// installCorrelationKey writes and syncs a same-directory 0600 temporary file,
// then installs it with linkat(2). A hard-link create is an atomic no-replace
// operation on every supported Unix target: EEXIST means a concurrent winner.
func installCorrelationKey(dirFD int, candidate CorrelationKey, entropy keyEntropyReader, hooks keyStoreHooks) (bool, error) {
	var suffix [keyTempRandomBytes]byte
	if _, err := io.ReadFull(entropy, suffix[:]); err != nil {
		return false, keyStoreError(KeyStoreErrorEntropy)
	}
	tempName := correlationKeyTempPrefix + hex.EncodeToString(suffix[:])

	tempFD, err := unix.Openat(
		dirFD,
		tempName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return false, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	tempPresent := true
	cleanup := func() {
		if !tempPresent {
			return
		}
		_ = unix.Unlinkat(dirFD, tempName, 0)
		_ = unix.Fsync(dirFD)
		tempPresent = false
	}
	defer cleanup()

	temp := os.NewFile(uintptr(tempFD), tempName)
	if temp == nil {
		_ = unix.Close(tempFD)
		return false, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	closed := false
	closeTemp := func() error {
		if closed {
			return nil
		}
		closed = true
		return temp.Close()
	}
	defer func() { _ = closeTemp() }()

	if err := unix.Fchmod(tempFD, 0o600); err != nil {
		return false, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	material, ok := candidate.Material()
	if !ok {
		return false, keyStoreError(KeyStoreErrorInstall)
	}
	if err := writeAll(temp, material[:]); err != nil {
		return false, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	if err := temp.Sync(); err != nil {
		return false, keyStoreError(KeyStoreErrorSync)
	}
	if err := closeTemp(); err != nil {
		return false, keyStoreError(KeyStoreErrorTemporaryFile)
	}
	if err := runAfterTempSync(hooks); err != nil {
		return false, keyStoreError(KeyStoreErrorInstall)
	}

	if err := unix.Linkat(dirFD, tempName, dirFD, correlationKeyFilename, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, keyStoreError(KeyStoreErrorInstall)
	}
	if err := runAfterLink(hooks); err != nil {
		return false, keyStoreError(KeyStoreErrorSync)
	}
	if err := unix.Fsync(dirFD); err != nil {
		return false, keyStoreError(KeyStoreErrorSync)
	}
	if err := unix.Unlinkat(dirFD, tempName, 0); err != nil {
		return false, keyStoreError(KeyStoreErrorInstall)
	}
	tempPresent = false
	if err := unix.Fsync(dirFD); err != nil {
		return false, keyStoreError(KeyStoreErrorSync)
	}
	return true, nil
}
