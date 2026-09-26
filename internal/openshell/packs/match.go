// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package packs

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// MatchHost reports whether host matches a host glob: "*" matches every
// host, "*.example.com" matches every subdomain of example.com (not the apex),
// anything else matches exactly. Matching is case-insensitive and ignores a
// trailing dot and IPv6 brackets.
func MatchHost(glob, host string) bool {
	g := strings.Trim(config.NormalizeOpenShellHostGlob(glob), "[]")
	h := strings.Trim(config.NormalizeOpenShellHostGlob(host), "[]")
	if g == "" || h == "" {
		return false
	}
	if g == "*" {
		return true
	}
	if suffix, ok := strings.CutPrefix(g, "*."); ok {
		return strings.HasSuffix(h, "."+suffix)
	}
	return g == h
}

// MatchAnyHost reports whether any glob matches host.
func MatchAnyHost(globs []string, host string) bool {
	for _, glob := range globs {
		if MatchHost(glob, host) {
			return true
		}
	}
	return false
}

// matchProjectPath reports whether an admin require_copy_for pattern covers
// project: the pattern matches the project directory or one of its
// ancestors. "~/" expands to home, "*" and "?" match within one path
// segment, and "**" matches any number of segments. A pattern without
// wildcards therefore covers that directory and everything below it.
func matchProjectPath(pattern, project, home string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || project == "" {
		return false
	}
	if pattern == "~" || strings.HasPrefix(pattern, "~/") {
		if home == "" {
			return false
		}
		pattern = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(pattern, "~"), "/"))
	}
	pat := splitPath(filepath.ToSlash(filepath.Clean(pattern)))
	proj := splitPath(filepath.ToSlash(filepath.Clean(project)))
	for n := len(proj); n >= 0; n-- {
		if matchSegments(pat, proj[:n]) {
			return true
		}
	}
	return false
}

// patternSpellings returns a require_copy_for pattern with "~/" expanded and,
// when its literal prefix (the segments before the first wildcard) resolves
// through a symbolic link, the same pattern over the resolved prefix.
func patternSpellings(pattern, home string) []string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "~" || strings.HasPrefix(pattern, "~/") {
		if home == "" {
			return nil
		}
		pattern = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(pattern, "~"), "/"))
	}
	if pattern == "" {
		return nil
	}
	out := []string{pattern}
	segments := strings.Split(filepath.ToSlash(filepath.Clean(pattern)), "/")
	literal := len(segments)
	for i, segment := range segments {
		if strings.ContainsAny(segment, "*?[") {
			literal = i
			break
		}
	}
	prefix := strings.Join(segments[:literal], "/")
	if prefix == "" || !filepath.IsAbs(filepath.FromSlash(prefix)) {
		return out
	}
	resolved, err := filepath.EvalSymlinks(filepath.FromSlash(prefix))
	if err != nil || filepath.ToSlash(resolved) == prefix {
		return out
	}
	rest := strings.Join(segments[literal:], "/")
	return append(out, filepath.Join(resolved, filepath.FromSlash(rest)))
}

func splitPath(p string) []string {
	var out []string
	for _, segment := range strings.Split(p, "/") {
		if segment != "" {
			out = append(out, segment)
		}
	}
	return out
}

func matchSegments(pattern, segments []string) bool {
	if len(pattern) == 0 {
		return len(segments) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(segments); i++ {
			if matchSegments(pattern[1:], segments[i:]) {
				return true
			}
		}
		return false
	}
	if len(segments) == 0 {
		return false
	}
	ok, err := path.Match(pattern[0], segments[0])
	if err != nil || !ok {
		return false
	}
	return matchSegments(pattern[1:], segments[1:])
}
