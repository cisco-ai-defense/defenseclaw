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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// hermesEntrypointKeys are the manifest keys that name code to run
// (_EXECUTABLE_MANIFEST_KEYS in plugin_scanner/scanner.py;
// TestHermesEntrypointKeysMatchScanner keeps them equal). The four keys whose
// values the scanner declares as entrypoints (main, bin, entry, entrypoint)
// are among them. Text under any other key (a description, a title, a
// keyword) is prose: the scanner does not read a file from it.
var hermesEntrypointKeys = []string{
	"hooks", "mcpServers", "lspServers", "main", "bin", "scripts", "exports", "module", "browser",
	"entry", "entrypoint", "entrypoints", "command", "extensions", "runtime",
}

// hermesEntrypointKeyPattern finds a mapping key of hermesEntrypointKeys in
// the text of a manifest, plain or quoted, up to and including its colon. A
// name that only ends in one of the keys (submain) is not a match.
var hermesEntrypointKeyPattern = func() *regexp.Regexp {
	keys := strings.Join(hermesEntrypointKeys, "|")
	return regexp.MustCompile(`(?:^|[^\w$./\\-])(?:"(?:` + keys + `)"|'(?:` + keys + `)'|(?:` + keys + `))[ \t\r\n]*:`)
}()

// hermesAnchorPattern finds a YAML anchor definition.
var hermesAnchorPattern = regexp.MustCompile(`&([^\s,\[\]{}&*]+)`)

// hermesManifestCandidates returns the strings that manifests hold as the
// value of an entrypoint key. It is the answer used while the plugin scanner,
// the one reader of the manifest grammar, cannot be asked and the policy lets
// ordinary activity continue (the per-user default and permissive tiers). It
// does not read the grammar: it finds each entrypoint key in the text as
// written and with the backslash escapes of JSON and YAML double-quoted
// strings decoded, and takes every string of the value that follows it (a
// quoted string whole, whatever punctuation it holds; the items of a flow
// collection; the lines of a block; the value an alias points to), leaving it
// to the caller to resolve each one as a path under the plugin. That is a
// superset of what the scanner reads, so a file a manifest names stays bound
// however it spells the name (an escape, an alias of an escaped value, dot
// segments, a link, a comma or bracket in the name); a file that no such
// string resolves to is not declared, so an ordinary generated cache file is
// not rejected because its name appears in prose, such as a description, or
// as an entrypoint in another folder.
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
			newHermesManifestReader(variant, add).entrypointValues()
		}
	}
	return out
}

// hermesManifestReader takes the values of the entrypoint keys out of one
// spelling of a manifest.
type hermesManifestReader struct {
	text    string
	add     func(string)
	anchors map[string][]int // anchor name -> offsets just after its definition
	aliases map[string]bool  // aliases already followed, so a cycle ends
}

func newHermesManifestReader(text string, add func(string)) *hermesManifestReader {
	r := &hermesManifestReader{text: text, add: add, anchors: map[string][]int{}, aliases: map[string]bool{}}
	for _, m := range hermesAnchorPattern.FindAllStringSubmatchIndex(text, -1) {
		name := text[m[2]:m[3]]
		r.anchors[name] = append(r.anchors[name], m[1])
	}
	return r
}

// entrypointValues adds the value of every entrypoint key. A key inside a
// value already taken is skipped: its text is part of that value.
func (r *hermesManifestReader) entrypointValues() {
	covered := 0
	for _, m := range hermesEntrypointKeyPattern.FindAllStringIndex(r.text, -1) {
		if m[0] < covered {
			continue
		}
		covered = max(covered, r.value(m[1], r.indent(m[1])))
	}
}

// indent is the indentation of the line holding offset i, counting the "- "
// of a sequence item as indentation.
func (r *hermesManifestReader) indent(i int) int {
	start := strings.LastIndexByte(r.text[:i], '\n') + 1
	n := 0
	for start+n < len(r.text) && strings.IndexByte(" \t-", r.text[start+n]) >= 0 {
		n++
	}
	return n
}

// value reads the value that starts at offset i, adds its strings, and
// returns the offset where it ends.
func (r *hermesManifestReader) value(i, indent int) int {
	for {
		for i < len(r.text) && (r.text[i] == ' ' || r.text[i] == '\t') {
			i++
		}
		if i >= len(r.text) {
			return len(r.text)
		}
		c := r.text[i]
		switch c {
		case '&', '!':
			// an anchor or a tag in front of the value
			for i < len(r.text) && r.text[i] != ' ' && r.text[i] != '\t' && r.text[i] != '\n' && r.text[i] != '\r' {
				i++
			}
		case '*':
			end := i + 1
			for end < len(r.text) && strings.IndexByte(" \t\r\n,]}", r.text[end]) < 0 {
				end++
			}
			r.alias(r.text[i+1 : end])
			return end
		case '"', '\'':
			content, end := hermesQuoted(r.text, i)
			r.addQuoted(content, c)
			return end
		case '[', '{':
			end := r.flowEnd(i)
			r.span(r.text[i:end])
			return end
		default:
			return r.block(i, indent)
		}
	}
}

// block reads the rest of the line at i and the lines under it: those
// indented deeper than the key, and sequence items at its indentation. A
// quoted string or flow collection on a later line is read where it stands,
// as JSON may place the value of a key on the next line at any indentation.
func (r *hermesManifestReader) block(i, indent int) int {
	end := strings.IndexByte(r.text[i:], '\n')
	if end < 0 {
		r.span(r.text[i:])
		return len(r.text)
	}
	end += i
	last := end
	for pos := end; pos < len(r.text); {
		start := pos + 1
		next := strings.IndexByte(r.text[start:], '\n')
		stop := len(r.text)
		if next >= 0 {
			stop = start + next
		}
		line := r.text[min(start, len(r.text)):stop]
		trimmed := strings.TrimLeft(line, " \t")
		if strings.TrimSpace(line) == "" {
			pos = stop
			continue
		}
		depth := len(line) - len(trimmed)
		if depth > indent || (depth == indent && strings.HasPrefix(trimmed, "- ")) {
			last, pos = stop, stop
			continue
		}
		if last == end && (trimmed[0] == '"' || trimmed[0] == '\'' || trimmed[0] == '[' || trimmed[0] == '{') && strings.TrimSpace(r.text[i:end]) == "" {
			return r.value(start+depth, indent)
		}
		break
	}
	r.span(r.text[i:last])
	return last
}

// flowEnd returns the offset after the bracket that closes the flow
// collection opened at i, skipping quoted strings; the end of the text when
// it never closes.
func (r *hermesManifestReader) flowEnd(i int) int {
	depth := 0
	prev := byte(' ')
	for j := i; j < len(r.text); j++ {
		c := r.text[j]
		switch {
		case hermesOpensQuote(c, prev):
			_, j = hermesQuoted(r.text, j)
			j--
			prev = '"'
			continue
		case c == '[' || c == '{':
			depth++
		case c == ']' || c == '}':
			if depth--; depth == 0 {
				return j + 1
			}
		}
		if c == '\n' {
			prev = ' '
		} else if c != ' ' && c != '\t' && c != '\r' {
			prev = c
		}
	}
	return len(r.text)
}

// hermesOpensQuote reports whether the quote character c, after the last
// significant byte prev, begins a quoted string and not an apostrophe inside
// a plain word.
func hermesOpensQuote(c, prev byte) bool {
	return (c == '"' || c == '\'') && strings.IndexByte(" [{,:-?", prev) >= 0
}

// hermesQuoted reads the quoted string that opens at text[i] and returns its
// content as written (escapes not decoded) and the offset after it. A string
// that never closes ends at the end of its line.
func hermesQuoted(text string, i int) (string, int) {
	quote := text[i]
	for j := i + 1; j < len(text); j++ {
		switch {
		case quote == '"' && text[j] == '\\':
			j++
		case quote == '\'' && text[j] == '\'' && j+1 < len(text) && text[j+1] == '\'':
			j++
		case text[j] == quote:
			return text[i+1 : j], j + 1
		}
	}
	rest := text[i+1:]
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		return rest[:nl], i + 1 + nl
	}
	return rest, len(text)
}

// addQuoted adds a quoted string as written and with its escapes decoded.
func (r *hermesManifestReader) addQuoted(content string, quote byte) {
	if quote == '\'' {
		r.add(strings.ReplaceAll(content, "''", "'"))
		return
	}
	r.add(content)
	r.add(hermesUnescapeManifest(content))
}

// alias adds the value each definition of the anchor holds.
func (r *hermesManifestReader) alias(name string) {
	if r.aliases[name] {
		return
	}
	r.aliases[name] = true
	for _, at := range r.anchors[name] {
		r.value(at, r.indent(at))
	}
}

// span adds the strings of a value: each quoted string whole, then, from what
// is left, each line, each piece of a line that a comma, bracket or ": "
// separates, and each word, so a plain name that holds punctuation is taken
// both whole and in pieces. Comments are dropped. The words that are aliases
// add what they point to.
func (r *hermesManifestReader) span(text string) {
	var rest strings.Builder
	prev := byte(' ')
	for i := 0; i < len(text); {
		c := text[i]
		if hermesOpensQuote(c, prev) {
			content, end := hermesQuoted(text, i)
			r.addQuoted(content, c)
			rest.WriteByte('\n')
			i, prev = end, '"'
			continue
		}
		rest.WriteByte(c)
		switch c {
		case '\n':
			prev = ' '
		case ' ', '\t', '\r':
		default:
			prev = c
		}
		i++
	}
	var plain []string
	for _, line := range strings.Split(rest.String(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if cut := strings.Index(line, " #"); cut >= 0 {
			line = line[:cut]
		}
		plain = append(plain, line)
	}
	r.plainStrings(strings.Join(plain, "\n"))
}

// plainStrings calls add for each string of unquoted text that may be a name.
func (r *hermesManifestReader) plainStrings(text string) {
	addValue := func(value string) {
		value = strings.TrimSpace(value)
		r.add(value)
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
			r.add(value)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		addValue(line)
	}
	for _, segment := range strings.FieldsFunc(text, func(c rune) bool { return strings.ContainsRune("\n\r,[]{}", c) }) {
		addValue(segment)
		for _, piece := range strings.Split(segment, ": ") {
			addValue(piece)
		}
		for _, word := range strings.Fields(segment) {
			addValue(word)
			if strings.HasPrefix(word, "*") && len(word) > 1 {
				r.alias(word[1:])
			}
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
