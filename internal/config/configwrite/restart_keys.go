// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package configwrite

import (
	"regexp"
	"slices"
	"strings"
)

// MaxRestartSettingPatterns bounds the settings RestartSettingPatterns
// returns.
const MaxRestartSettingPatterns = 32

// restartSettingPatternShape is what a reported setting may look like:
// schema key names, "*" and dots.
var restartSettingPatternShape = regexp.MustCompile(`^[a-z_*.]{1,96}$`)

// RestartSettingPatterns names the settings behind restart-required change
// paths (ManagedRestartRequired), never the paths: a change path can carry
// an administrator's map key, such as a profile, a group or a connector
// name. A path is reported as the restartKeys entry it matched, cut at the
// path's depth when the whole block above it changed ("guardrail"); a
// connector set change as guardrail.connectors.*.enabled; the rest of the
// enterprise block as enterprise.<section>. The result is sorted, without
// duplicates, and at most MaxRestartSettingPatterns long.
func RestartSettingPatterns(paths []string) []string {
	var out []string
	for _, path := range paths {
		pattern := restartSettingPattern(restartSegments(path))
		if restartSettingPatternShape.MatchString(pattern) && !slices.Contains(out, pattern) {
			out = append(out, pattern)
		}
	}
	slices.Sort(out)
	if len(out) > MaxRestartSettingPatterns {
		out = out[:MaxRestartSettingPatterns]
	}
	return out
}

// restartSettingPattern is the setting a restart-required path belongs to,
// in the order ManagedRestartRequired classifies it; "" for a path it does
// not classify.
func restartSettingPattern(segs []string) string {
	if len(segs) == 0 {
		return ""
	}
	cut := func(key []string) string { return strings.Join(key[:min(len(segs), len(key))], ".") }
	for _, key := range restartKeys {
		if parts := strings.Split(key, "."); restartKeyMatches(segs, parts) {
			return cut(parts)
		}
	}
	if connector := []string{"guardrail", "connectors", "*", "enabled"}; restartKeyMatches(segs, connector) {
		return cut(connector)
	}
	if segs[0] == "enterprise" {
		return strings.Join(segs[:min(len(segs), 2)], ".")
	}
	return ""
}
