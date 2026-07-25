// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"errors"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// ReadSetupPostureAt reads the effective activation posture for the native
// installer without letting an already fail-closed state strand repair or
// uninstall. A malformed state, digest mismatch, or DACL drift is inactive:
// the stable launcher rejects the same input, and the installer writer will
// repair protection before publishing disabled state. Reparse points, foreign
// ownership, non-canonical paths, and other unsafe topology remain hard
// failures.
func ReadSetupPostureAt(paths Paths, executable string) (state State, recognized bool, err error) {
	if err := validatePaths(paths); err != nil {
		return State{}, false, err
	}
	if !samePath(executable, paths.Launcher) {
		return State{}, false, nil
	}
	for _, target := range []struct {
		path      string
		directory bool
	}{
		{path: paths.Root, directory: true},
		{path: paths.Launcher},
		{path: paths.State},
	} {
		var ownershipErr error
		if target.directory {
			ownershipErr = safefile.ValidatePrivateDirectoryOwnership(target.path)
		} else {
			ownershipErr = safefile.ValidatePrivateFileOwnership(target.path)
		}
		if errors.Is(ownershipErr, os.ErrNotExist) {
			return State{}, true, nil
		}
		if ownershipErr != nil {
			return State{}, true, ownershipErr
		}
	}
	state, recognized, err = readTrustedAt(paths, executable)
	if err != nil {
		// Ownership and topology were independently validated above. Any
		// remaining reader failure is already a no-op to the stable launcher
		// and can be repaired safely by the installer writer.
		return State{}, recognized, nil
	}
	return state, recognized, nil
}
