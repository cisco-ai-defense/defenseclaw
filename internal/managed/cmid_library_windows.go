// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"path/filepath"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Both version directories under this root move with Secure Client
// upgrades that DefenseClaw does not participate in, so the path cannot
// be baked in at install time.
const cmidVendorRelativeRoot = `Cisco\Cisco Secure Client\CM`

// DiscoverCMIDLibrary returns the newest Cloud Management identity
// library present on this machine, or "" when Secure Client has not
// installed one. Callers treat the empty result as "no override" and
// leave the provider to its own default.
func DiscoverCMIDLibrary() string {
	programFiles, err := winpath.TrustedProgramFiles()
	if err != nil {
		return ""
	}
	return discoverCMIDLibraryIn(filepath.Join(programFiles, cmidVendorRelativeRoot), cmidArchDirectory())
}

// cmidArchDirectory maps the running architecture onto the leaf
// directory Secure Client ships it under.
func cmidArchDirectory() string {
	if runtime.GOARCH == "arm64" {
		return "arm64"
	}
	return "x64"
}

// rejectCMIDLibraryReparse rejects any Windows reparse point (junction,
// symbolic link, mount point) at path. The version-directory walk in
// discoverCMIDLibraryIn calls this on each candidate directory and on
// the final library file so an attacker who can plant a junction under
// Program Files\Cisco cannot redirect the CMID lookup off the trusted
// Secure Client tree.
//
// Note: this checks the single element at `path`, not its ancestor
// chain. `TrustedProgramFiles()` (used by DiscoverCMIDLibrary above)
// already anchors the walk at a known-trusted Windows root, so
// per-element rejection is sufficient to prevent redirection into an
// attacker-controlled subtree.
func rejectCMIDLibraryReparse(path string) error {
	return rejectWindowsReparsePoint(path, "cmid library")
}
