//go:build !windows && !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import "errors"

// publishedSessionVolumeIsReadOnly cannot tell here, which blocks.
func publishedSessionVolumeIsReadOnly(string) (bool, error) {
	return false, errors.New("the volume state cannot be read on this platform")
}

// publishedSessionFolderIsLocked cannot tell here, which blocks.
func publishedSessionFolderIsLocked(string) (bool, error) {
	return false, errors.New("the folder flags cannot be read on this platform")
}
