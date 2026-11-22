// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import "fmt"

// modeStrictness orders the transformation modes from the one that keeps the
// most of a value to the one that keeps nothing.
func modeStrictness(mode TransformationMode) int {
	switch mode {
	case ModePreserve:
		return 0
	case ModeDetect:
		return 1
	case ModeHash:
		return 2
	case ModeWhole:
		return 3
	case ModeRemove:
		return 4
	default:
		return -1
	}
}

// dominates reports whether a keeps no more of any field than b: every
// class at least as strict, every detector group of b, and the personal
// identifier removal of b.
func dominates(a, b Profile) bool {
	for index := range a.modes {
		if modeStrictness(a.modes[index]) < modeStrictness(b.modes[index]) {
			return false
		}
	}
	for index := range a.groups {
		if b.groups[index] && !a.groups[index] {
			return false
		}
	}
	return a.RemovesPersonalIdentifiers() || !b.RemovesPersonalIdentifiers()
}

// StricterProfile returns a profile that keeps no more of any field than
// either a or b: a or b itself when one already is that, else a profile
// named name with, per field class, the stricter of the two modes, the
// detector groups of both and strict's personal identifier removal when
// either removes them. The rejected-record store (#1442) uses it to keep a
// refused record no more readable than the record's own local bucket would
// keep it, and never less redacted than the sensitive profile.
func StricterProfile(name ProfileName, a, b Profile) (Profile, error) {
	if !validProfile(a) || !validProfile(b) {
		return Profile{}, fmt.Errorf("stricter redaction profile: input profile is not valid")
	}
	if dominates(a, b) {
		return a, nil
	}
	if dominates(b, a) {
		return b, nil
	}
	if err := validateProfileName(name); err != nil {
		return Profile{}, err
	}
	if _, reserved := builtInProfileTable()[name]; reserved {
		return Profile{}, fmt.Errorf("stricter redaction profile name is reserved")
	}
	combined := Profile{name: name, base: ProfileSensitive}
	if a.RemovesPersonalIdentifiers() || b.RemovesPersonalIdentifiers() {
		combined.base = ProfileStrict
	}
	for index := range combined.modes {
		combined.modes[index] = a.modes[index]
		if modeStrictness(b.modes[index]) > modeStrictness(a.modes[index]) {
			combined.modes[index] = b.modes[index]
		}
	}
	for index := range combined.groups {
		combined.groups[index] = a.groups[index] || b.groups[index]
	}
	if err := validateResolvedProfile(combined, true); err != nil {
		return Profile{}, err
	}
	combined.fingerprint = profileFingerprint(combined)
	return combined, nil
}
