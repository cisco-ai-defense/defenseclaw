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

package extproc

import (
	"errors"
	"strings"
	"unicode/utf8"
)

// errAmbiguousPath is a path an origin may read in more than one way: an
// encoded slash, backslash, NUL, percent sign or control character, a
// malformed percent escape, or a form that is not origin-form.
var errAmbiguousPath = errors.New("ambiguous path encoding")

// canonicalPath returns the form URL rules match (GAP-0046), from the path
// part of :path (no query or fragment):
//   - path parameters (";..." in a segment) are dropped, as servers that
//     honour them do; a segment that is empty, "." or ".." once its
//     parameters are dropped ("..;", ".;x", ";x") is errAmbiguousPath,
//     because origins that keep parameters read it as a name and origins
//     that drop them as a dot segment (GAP-0046);
//   - each segment is percent-decoded once; an escape that decodes to a
//     slash, a backslash, NUL, "%" (double encoding), ";" or a control
//     character, a malformed escape, a raw backslash or a raw control
//     character is errAmbiguousPath, so no origin can read the request as a
//     different path than the one matched; so is a segment that is not
//     UTF-8 once decoded (%c0%ae is an overlong "." to old decoders);
//   - empty segments are merged (//a is /a) and "." segments removed,
//     escaped spellings included;
//   - a ".." segment, literal or escaped, is errAmbiguousPath: origins and
//     proxies that route the raw path read /admin/../public under /admin,
//     while RFC 3986 resolution reads /public, so no single canonical form
//     is right for both (GAP-0046);
//   - a trailing slash is kept, so /admin/ still matches a /admin/ prefix.
//
// "*" (OPTIONS *) is returned as is; any other path that does not start
// with "/" is errAmbiguousPath.
func canonicalPath(raw string) (string, error) {
	if raw == "*" {
		return raw, nil
	}
	if raw == "" {
		return "/", nil
	}
	if raw[0] != '/' {
		return "", errAmbiguousPath
	}
	parts := strings.Split(raw[1:], "/")
	segs := make([]string, 0, len(parts))
	trailing := false
	for i, p := range parts {
		last := i == len(parts)-1
		params := false
		if j := strings.IndexByte(p, ';'); j >= 0 {
			p, params = p[:j], true
		}
		seg, err := decodeSegment(p)
		if err != nil {
			return "", err
		}
		if params && (seg == "" || seg == "." || seg == "..") {
			return "", errAmbiguousPath
		}
		switch seg {
		case "", ".":
			trailing = last
		case "..":
			return "", errAmbiguousPath
		default:
			segs = append(segs, seg)
			trailing = false
		}
	}
	out := "/" + strings.Join(segs, "/")
	if trailing && len(segs) > 0 {
		out += "/"
	}
	return out, nil
}

func decodeSegment(s string) (string, error) {
	if strings.IndexByte(s, '%') < 0 {
		for i := 0; i < len(s); i++ {
			if c := s[i]; c < 0x20 || c == 0x7f || c == '\\' {
				return "", errAmbiguousPath
			}
		}
		if !utf8.ValidString(s) {
			return "", errAmbiguousPath
		}
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' {
			if i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2]) {
				return "", errAmbiguousPath
			}
			c = unhex(s[i+1])<<4 | unhex(s[i+2])
			i += 2
			if c == '/' || c == '\\' || c == '%' || c == ';' {
				return "", errAmbiguousPath
			}
		}
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "", errAmbiguousPath
		}
		b.WriteByte(c)
	}
	if !utf8.ValidString(b.String()) {
		return "", errAmbiguousPath
	}
	return b.String(), nil
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	}
	return c - '0'
}

// pathOnly drops the query and fragment of a :path.
func pathOnly(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		return p[:i]
	}
	return p
}

// pathHasPrefix matches a canonical path against a canonical rule prefix on
// segment boundaries: /admin matches /admin and /admin/x, not /administrator;
// a prefix ending in "/" matches everything under it.
func pathHasPrefix(p, prefix string) bool {
	if prefix == "" || prefix == "/" {
		return true
	}
	if !strings.HasPrefix(p, prefix) {
		return false
	}
	return len(p) == len(prefix) || strings.HasSuffix(prefix, "/") || p[len(prefix)] == '/'
}
