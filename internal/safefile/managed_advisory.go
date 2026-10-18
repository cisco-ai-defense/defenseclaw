// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

// ManagedModeAdvisory lets a managed install downgrade a group/other mode
// verdict on one of its own paths to an advisory. It returns true when the
// verdict was reported and the caller should continue. The managed package
// installs it (AIFW-34262: the managed release line ships its macOS runtime
// directory root:wheel 0750 and never enforced these modes); nil keeps every
// verdict fatal. Owner, type and symlink verdicts never go through it.
var ManagedModeAdvisory func(path, reason string) bool

func relaxModeVerdict(path string, verdict error) error {
	if verdict == nil {
		return nil
	}
	if hook := ManagedModeAdvisory; hook != nil && hook(path, verdict.Error()) {
		return nil
	}
	return verdict
}
