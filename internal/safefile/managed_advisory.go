// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

import "os"

// ManagedModeAdvisory lets a managed install downgrade a group/other mode
// verdict on one of its own paths to an advisory. It returns true when the
// verdict was reported and the caller should continue. The managed package
// installs it (AIFW-34262: the managed release line ships its macOS runtime
// directory root:wheel 0750 and never enforced these modes); nil keeps every
// verdict fatal. Owner, type and symlink verdicts never go through it.
var ManagedModeAdvisory func(path, reason string) bool

// ManagedWriteModeAdvisory, when set, names the paths where a group or world
// write bit still goes to ManagedModeAdvisory: the Secure Client install,
// which keeps its earlier rule (Secure Client is out of scope for GAP-0026).
// The managed package installs it; nil keeps write bits fatal everywhere.
var ManagedWriteModeAdvisory func(path string) bool

// groupOtherWrite is the part of a too-broad mode that is never an advisory
// outside ManagedWriteModeAdvisory: a group or world write bit lets someone
// other than the owner change the path, which is exactly what the
// private-path check exists to refuse.
const groupOtherWrite os.FileMode = 0o022

func relaxModeVerdict(path string, perm os.FileMode, verdict error) error {
	if verdict == nil {
		return nil
	}
	if perm&groupOtherWrite != 0 && !managedWriteModeAdvisory(path) {
		return verdict
	}
	if hook := ManagedModeAdvisory; hook != nil && hook(path, verdict.Error()) {
		return nil
	}
	return verdict
}

func managedWriteModeAdvisory(path string) bool {
	hook := ManagedWriteModeAdvisory
	return hook != nil && hook(path)
}
