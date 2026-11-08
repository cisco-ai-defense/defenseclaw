// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// windowsLinkTarget gives a target read from a Windows link the absolute
// spelling the walk follows. A target that starts with one separator
// (\Users\x) names the root of the drive or share the link lives on, not a
// folder beside the link. Go reads it as a relative name, so appending it to
// the link folder would judge a file that is not the one the link reaches
// (GAP-0855). Targets Go reads as absolute (drive, UNC, extended) are
// returned as they are. A target with a drive and no root (C:x) is relative
// to the working directory of that drive, which the hook cannot know: ok is
// false and the link stays unresolved, like any link the walk cannot prove.
func windowsLinkTarget(base, target string) (string, bool) {
	if target == "" {
		return target, true
	}
	switch {
	case strings.HasPrefix(target, `\??\`):
		// The NT spelling of an absolute drive path.
		rest := target[len(`\??\`):]
		if len(rest) >= 3 && windowsDriveLetter(rest[0]) && rest[1] == ':' && windowsSeparator(rest[2]) {
			return rest, true
		}
		return "", false
	case len(target) >= 2 && windowsSeparator(target[0]) && windowsSeparator(target[1]):
		return target, true
	case windowsSeparator(target[0]):
		volume := windowsVolumePrefix(base)
		if volume == "" {
			return "", false
		}
		return volume + target, true
	case len(target) >= 2 && windowsDriveLetter(target[0]) && target[1] == ':' &&
		(len(target) == 2 || !windowsSeparator(target[2])):
		return "", false
	}
	return target, true
}

func windowsSeparator(b byte) bool { return b == '\\' || b == '/' }

func windowsDriveLetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// windowsVolumePrefix returns the volume part of an absolute Windows path:
// "C:", \\server\share, or the extended forms \\?\C:, \\?\UNC\server\share
// and \\?\Volume{id}. It is empty for a path that has none.
func windowsVolumePrefix(path string) string {
	if len(path) >= 2 && windowsDriveLetter(path[0]) && path[1] == ':' {
		return path[:2]
	}
	if len(path) < 3 || !windowsSeparator(path[0]) || !windowsSeparator(path[1]) {
		return ""
	}
	// \\server\share, or after the extended marker \\?\ (or \\.\) one
	// volume component, or UNC\server\share.
	offset, count := 2, 2
	if len(path) >= 4 && (path[2] == '?' || path[2] == '.') && windowsSeparator(path[3]) {
		offset, count = 4, 1
		if len(path) >= 8 && strings.EqualFold(path[4:7], "UNC") && windowsSeparator(path[7]) {
			offset, count = 8, 2
		}
	}
	return windowsComponents(path, offset, count)
}

// windowsComponents returns path up to the end of count components that
// start at index start, or "" when the path has fewer or one is empty.
func windowsComponents(path string, start, count int) string {
	end := start
	for i := 0; i < count; i++ {
		if i > 0 {
			if end >= len(path) {
				return ""
			}
			end++
		}
		next := end
		for next < len(path) && !windowsSeparator(path[next]) {
			next++
		}
		if next == end {
			return ""
		}
		end = next
	}
	return path[:end]
}
