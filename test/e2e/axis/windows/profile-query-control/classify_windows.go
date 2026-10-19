// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import "slices"

// Diagnostic facts only. No returned path becomes a filesystem grant or an
// accepted child expectation. ASCII folding describes code units, not NTFS
// case-sensitivity or object identity.
type pathClasses struct {
	WellFormed             bool  `json:"well_formed_local_disk_paths"`
	KnownExtended          bool  `json:"known_base_extended_prefix"`
	NativeExtended         bool  `json:"native_folder_extended_prefix"`
	KnownExact             *bool `json:"known_packages_prefix_exact"`
	KnownASCIIFold         *bool `json:"known_packages_prefix_ascii_fold"`
	PrivateExact           *bool `json:"private_packages_prefix_exact"`
	PrivateASCIIFold       *bool `json:"private_packages_prefix_ascii_fold"`
	NativePackageTailShape *bool `json:"native_packages_profile_ac_tail_shape"`
	KnownEqualsPrivate     *bool `json:"known_base_equals_private_exact"`
	KnownEqualsPrivateFold *bool `json:"known_base_equals_private_ascii_fold"`
}

func fixedSelector(args []string) bool { return slices.Equal(args, []string{"--query-fixed"}) }

func localUnits(value []uint16) ([]uint16, bool, bool) {
	extended := len(value) >= 4 && slices.Equal(value[:4], []uint16{92, 92, 63, 92})
	if extended {
		value = value[4:]
	}
	if len(value) < 4 || len(value) > 2048 || value[1] != ':' || value[2] != '\\' ||
		!((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) {
		return nil, extended, false
	}
	for _, unit := range value {
		if unit < 32 || unit == '/' {
			return nil, extended, false
		}
	}
	for _, part := range splitUnits(value[3:]) {
		if len(part) == 0 || slices.Equal(part, []uint16{'.'}) || slices.Equal(part, []uint16{'.', '.'}) ||
			part[len(part)-1] == ' ' || part[len(part)-1] == '.' {
			return nil, extended, false
		}
		for _, unit := range part {
			if unit == ':' {
				return nil, extended, false
			}
		}
	}
	return slices.Clone(value), extended, true
}

func splitUnits(value []uint16) [][]uint16 {
	var result [][]uint16
	start := 0
	for index, unit := range value {
		if unit == '\\' {
			result = append(result, value[start:index])
			start = index + 1
		}
	}
	return append(result, value[start:])
}

func asciiFold(value []uint16) []uint16 {
	result := slices.Clone(value)
	for index, unit := range result {
		if unit >= 'A' && unit <= 'Z' {
			result[index] = unit + ('a' - 'A')
		}
	}
	return result
}

func startsWith(value, prefix []uint16) bool {
	return len(value) >= len(prefix) && slices.Equal(value[:len(prefix)], prefix)
}

func boolFact(value bool) *bool { return &value }

func packageTail(value []uint16) bool {
	parts := splitUnits(value)
	if len(parts) < 3 || !slices.Equal(parts[len(parts)-3], []uint16{'P', 'a', 'c', 'k', 'a', 'g', 'e', 's'}) ||
		!slices.Equal(parts[len(parts)-1], []uint16{'A', 'C'}) {
		return false
	}
	profile := parts[len(parts)-2]
	if len(profile) == 0 || len(profile) > 128 {
		return false
	}
	for _, unit := range profile {
		if !((unit >= 'A' && unit <= 'Z') || (unit >= 'a' && unit <= 'z') ||
			(unit >= '0' && unit <= '9') || unit == '-' || unit == '_' || unit == '.') {
			return false
		}
	}
	return true
}

func classify(private, known, native []uint16) pathClasses {
	private, _, privateOK := localUnits(private)
	known, knownExtended, knownOK := localUnits(known)
	native, nativeExtended, nativeOK := localUnits(native)
	result := pathClasses{KnownExtended: knownExtended, NativeExtended: nativeExtended,
		WellFormed: privateOK && knownOK && nativeOK}
	if !result.WellFormed {
		return result // Unknown comparisons remain null, never a measured false.
	}
	suffix := []uint16{'\\', 'P', 'a', 'c', 'k', 'a', 'g', 'e', 's', '\\'}
	knownPrefix := append(slices.Clone(known), suffix...)
	privatePrefix := append(slices.Clone(private), suffix...)
	result.KnownExact = boolFact(startsWith(native, knownPrefix))
	result.KnownASCIIFold = boolFact(startsWith(asciiFold(native), asciiFold(knownPrefix)))
	result.PrivateExact = boolFact(startsWith(native, privatePrefix))
	result.PrivateASCIIFold = boolFact(startsWith(asciiFold(native), asciiFold(privatePrefix)))
	result.NativePackageTailShape = boolFact(packageTail(native))
	result.KnownEqualsPrivate = boolFact(slices.Equal(known, private))
	result.KnownEqualsPrivateFold = boolFact(slices.Equal(asciiFold(known), asciiFold(private)))
	return result
}
