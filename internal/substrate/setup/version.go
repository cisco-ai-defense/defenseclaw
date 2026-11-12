// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"strconv"
	"strings"
)

// Version is a release version, major.minor.patch with an optional
// pre-release that sorts before the release.
type Version struct {
	Major, Minor, Patch int
	Pre                 string
}

// ParseVersion reads "1.0.10", "v1.0.0" and "1.1.0-rc.1".
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	core, pre, _ := strings.Cut(s, "-")
	core, _, _ = strings.Cut(core, "+")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("version %q: want major.minor.patch", s)
	}
	var n [3]int
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return Version{}, fmt.Errorf("version %q: %q is not a number", s, p)
		}
		n[i] = v
	}
	return Version{Major: n[0], Minor: n[1], Patch: n[2], Pre: pre}, nil
}

// Compare returns -1, 0 or 1. A pre-release sorts before its release;
// pre-releases compare as text.
func (v Version) Compare(o Version) int {
	for _, d := range [3]int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.Pre == o.Pre:
		return 0
	case v.Pre == "":
		return 1
	case o.Pre == "":
		return -1
	}
	return strings.Compare(v.Pre, o.Pre)
}

func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// InRange reports whether version satisfies a range of space-separated
// comparisons (">=1.0.0 <1.1.0"), the substrate.supported_versions form.
func InRange(version, rng string) (bool, error) {
	v, err := ParseVersion(version)
	if err != nil {
		return false, err
	}
	fields := strings.Fields(rng)
	if len(fields) == 0 {
		return false, fmt.Errorf("version range %q is empty", rng)
	}
	for _, f := range fields {
		i := strings.IndexAny(f, "0123456789v")
		if i < 0 {
			return false, fmt.Errorf("version range %q: %q has no version", rng, f)
		}
		op := f[:i]
		bound, err := ParseVersion(f[i:])
		if err != nil {
			return false, fmt.Errorf("version range %q: %w", rng, err)
		}
		c := v.Compare(bound)
		var ok bool
		switch op {
		case ">=":
			ok = c >= 0
		case ">":
			ok = c > 0
		case "<=":
			ok = c <= 0
		case "<":
			ok = c < 0
		case "=", "==", "":
			ok = c == 0
		default:
			return false, fmt.Errorf("version range %q: unknown operator %q", rng, op)
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}
