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
	"golang.org/x/net/publicsuffix"
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

// IsBroadAllowGlob reports an allow-list host glob that covers every host
// ("*") or a whole public suffix ("*.com", "*.co.uk"). Such an entry turns an
// allowlist into an open network and exempts whole top-level domains from the
// blocklist feeds, so packs refuse it and Resolve ignores it.
func IsBroadAllowGlob(glob string) bool {
	g := strings.Trim(config.NormalizeOpenShellHostGlob(glob), "[]")
	if g == "*" {
		return true
	}
	suffix, ok := strings.CutPrefix(g, "*.")
	if !ok || suffix == "" {
		return false
	}
	ps, icann := publicsuffix.PublicSuffix(suffix)
	return icann && ps == suffix
}

// matchProjectPath reports whether an admin require_copy_for pattern covers
// a mount of dir: the pattern matches dir, one of its ancestors, or a path
// below it (mounting a parent folder exposes the covered one). "~/" expands
// to home, "*" and "?" match within one path segment, and "**" matches any
// number of segments, so a pattern without wildcards covers that directory
// and everything below it. Matching ignores case: a differently cased
// spelling reaches the same folder on case-insensitive file systems (macOS,
// Windows), and on case-sensitive ones the error is toward copy mode.
func matchProjectPath(pattern, dir, home string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || dir == "" {
		return false
	}
	if pattern == "~" || strings.HasPrefix(pattern, "~/") {
		if home == "" {
			return false
		}
		pattern = filepath.Join(home, strings.TrimPrefix(strings.TrimPrefix(pattern, "~"), "/"))
	}
	pat := splitPath(strings.ToLower(filepath.ToSlash(filepath.Clean(pattern))))
	segments := splitPath(strings.ToLower(filepath.ToSlash(filepath.Clean(dir))))
	for n := len(segments); n >= 0; n-- {
		if matchSegments(pat, segments[:n]) {
			return true
		}
	}
	return matchesBelow(pat, segments)
}

// matchesBelow reports whether pattern can match a path strictly below
// segments: segments match a prefix of the pattern and pattern segments
// remain. It errs toward a match, because the caller then requires copy mode.
func matchesBelow(pattern, segments []string) bool {
	for i, segment := range segments {
		if i >= len(pattern) {
			return false
		}
		if pattern[i] == "**" {
			return true
		}
		if ok, err := path.Match(pattern[i], segment); err != nil || !ok {
			return false
		}
	}
	return len(pattern) > len(segments)
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
