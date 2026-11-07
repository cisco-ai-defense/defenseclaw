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

package watcher

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// hermesManifestCandidates returns every string that manifests may hold as a
// file name. It is the answer used while the plugin scanner, the one reader
// of the manifest grammar, cannot be asked and the policy lets ordinary
// activity continue (the per-user default and permissive tiers). It does not
// read the grammar: it takes each quoted string, each plain word, each line
// and each value after a key, in the text as written and with the backslash
// escapes of JSON and YAML double-quoted strings decoded, and leaves it to the
// caller to resolve each one as a path under the plugin. That is a superset
// of what the scanner reads, so a file a manifest names stays bound however it
// spells the name (an escape, an alias of an escaped value, dot segments, a
// link); a file that no string resolves to is not declared, so an ordinary
// generated cache file is not rejected because its base name appears in
// prose or as an entrypoint in another folder.
func hermesManifestCandidates(manifests map[string][]byte) []string {
	names := make([]string, 0, len(manifests))
	for name := range manifests {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := map[string]bool{}
	var out []string
	add := func(value string) {
		if value = strings.TrimSpace(value); value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	for _, name := range names {
		text := string(manifests[name])
		for _, variant := range []string{text, hermesUnescapeManifest(text)} {
			hermesManifestStrings(variant, add)
		}
	}
	return out
}

// hermesManifestStrings calls add for each string of text that may be a name.
func hermesManifestStrings(text string, add func(string)) {
	addValue := func(value string) {
		value = strings.TrimSpace(value)
		add(value)
		for {
			switch {
			case strings.HasPrefix(value, "- "):
				value = strings.TrimSpace(value[2:])
			case value != "" && (value[0] == '&' || value[0] == '!'):
				// a YAML anchor or tag in front of a plain value
				i := strings.IndexAny(value, " \t")
				if i < 0 {
					return
				}
				value = strings.TrimSpace(value[i:])
			case strings.HasSuffix(value, ":"):
				value = strings.TrimSpace(strings.TrimSuffix(value, ":"))
			default:
				return
			}
			add(value)
		}
	}
	for _, segment := range strings.FieldsFunc(text, func(r rune) bool { return strings.ContainsRune("\n\r\"',[]{}", r) }) {
		addValue(segment)
		for _, piece := range strings.Split(segment, ": ") {
			addValue(piece)
		}
		for _, word := range strings.Fields(segment) {
			addValue(word)
		}
	}
}

// hermesEscapes are the single-character escapes of JSON and of YAML
// double-quoted strings.
var hermesEscapes = map[byte]string{
	'0': "\x00", 'a': "\a", 'b': "\b", 't': "\t", '\t': "\t", 'n': "\n", 'v': "\v", 'f': "\f", 'r': "\r",
	'e': "\x1b", ' ': " ", '"': "\"", '/': "/", '\\': "\\", 'N': "\u0085", '_': "\u00a0", 'L': "\u2028", 'P': "\u2029",
}

// hermesUnescapeManifest decodes every backslash escape of JSON and YAML
// double-quoted strings in text, wherever it occurs; a backslash that starts
// no escape stays. A backslash before a line break joins the lines.
func hermesUnescapeManifest(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); {
		if text[i] != '\\' || i+1 >= len(text) {
			out.WriteByte(text[i])
			i++
			continue
		}
		switch next := text[i+1]; next {
		case 'x', 'u', 'U':
			width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[next]
			if r, ok := hermesHexRune(text[i+2:], width); ok {
				i += 2 + width
				if next == 'u' && utf16.IsSurrogate(r) && strings.HasPrefix(text[i:], `\u`) {
					if low, ok := hermesHexRune(text[i+2:], 4); ok {
						if pair := utf16.DecodeRune(r, low); pair != utf8.RuneError {
							r = pair
							i += 6
						}
					}
				}
				out.WriteRune(r)
				continue
			}
		case '\n', '\r':
			i += 2
			if next == '\r' && i < len(text) && text[i] == '\n' {
				i++
			}
			for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
				i++
			}
			continue
		default:
			if value, ok := hermesEscapes[next]; ok {
				out.WriteString(value)
				i += 2
				continue
			}
		}
		out.WriteByte('\\')
		i++
	}
	return out.String()
}

// hermesHexRune reads width hexadecimal digits at the start of text.
func hermesHexRune(text string, width int) (rune, bool) {
	if len(text) < width {
		return 0, false
	}
	value, err := strconv.ParseUint(text[:width], 16, 32)
	if err != nil || value > utf8.MaxRune {
		return 0, false
	}
	return rune(value), true
}
