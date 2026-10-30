// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"
	"time"
)

// SetupPathKind says whether a path the enterprise Setup trust rule checks is
// a regular file or a directory.
type SetupPathKind int

const (
	// SetupPathFile is a regular file with exactly one hard link.
	SetupPathFile SetupPathKind = iota
	// SetupPathDirectory is a directory.
	SetupPathDirectory
	// SetupPathSystemFile is a regular file the Windows component store
	// services, such as powershell.exe. Those are hard-linked into WinSxS by
	// design, so the one-link rule does not apply; every other rule does.
	SetupPathSystemFile
)

// Leftover staging directories. The enterprise Setup and the CLI each create
// a randomly named protected directory under ProgramData (or ProgramData\Cisco)
// for one lifecycle run and remove it afterwards. A crash, a power loss or an
// endpoint product holding a file open can leave one behind; the next run
// sweeps those that are older than any run can last.
const (
	// SetupStagePrefix names the outer Setup's staging directory.
	SetupStagePrefix = "DefenseClaw-Enterprise-Setup-"
	// SetupPowerShellTempPrefix names the CLI's elevated PowerShell temp.
	SetupPowerShellTempPrefix = "DefenseClaw-PowerShell-"
	// SetupInstallerStagePrefix names the CLI's embedded-installer staging.
	SetupInstallerStagePrefix = "DefenseClaw-Installer-"

	// SetupLeftoverMaxAge is the longest bounded lifecycle timeout (2 h)
	// plus a margin for staging, cleanup and clock skew. A directory younger
	// than this may belong to a run still in progress and is never swept.
	SetupLeftoverMaxAge = 2*time.Hour + 30*time.Minute
)

// SetupLeftoverPrefixes lists every staging directory prefix a sweep may
// remove.
func SetupLeftoverPrefixes() []string {
	return []string{SetupStagePrefix, SetupPowerShellTempPrefix, SetupInstallerStagePrefix}
}

// IsSetupLeftoverName reports whether name is exactly one of prefixes followed
// by a 128-bit lowercase hexadecimal capability, the only shape the creators
// produce. Anything else in ProgramData is never touched.
func IsSetupLeftoverName(name string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		capability := name[len(prefix):]
		if len(capability) != 32 {
			return false
		}
		for _, char := range capability {
			if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
				return false
			}
		}
		return true
	}
	return false
}

// SetupLeftoverExpired reports whether a leftover created at created and last
// written at modified is older than SetupLeftoverMaxAge at now. The later of
// the two times counts, so a directory a live run is still writing into is
// never expired by an old creation time alone.
func SetupLeftoverExpired(created, modified, now time.Time) bool {
	newest := created
	if modified.After(newest) {
		newest = modified
	}
	if newest.IsZero() {
		return false
	}
	return now.Sub(newest) > SetupLeftoverMaxAge
}

// Reparse tags a regular file can carry without redirecting anything: the
// data still lives in the file itself, compressed or deduplicated or managed
// by a cloud-files provider, or the file is an AF_UNIX socket.
const (
	reparseTagWOF          uint32 = 0x80000017
	reparseTagDedup        uint32 = 0x80000013
	reparseTagAFUnix       uint32 = 0x80000023
	reparseTagCloudMask    uint32 = 0xFFFF0FFF
	reparseTagCloudPattern uint32 = 0x9000001A
)

// IsBenignFileReparseTag reports whether tag is one of the storage reparse
// tags that is safe on a regular file: WOF compression, data deduplication,
// AF_UNIX sockets and every cloud-files placeholder variant. Symbolic links,
// mount points and unknown tags are not benign, and no tag is benign on a
// directory; callers check the object type themselves.
func IsBenignFileReparseTag(tag uint32) bool {
	switch tag {
	case reparseTagWOF, reparseTagDedup, reparseTagAFUnix:
		return true
	}
	return tag&reparseTagCloudMask == reparseTagCloudPattern
}
