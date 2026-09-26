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

package openshell

import (
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

// ErrTOMLEdit means a TOML document could not be edited without risking
// its other content (for example the target keys are spelled as dotted
// keys or inline tables). Nothing was written; the operator edits by hand.
var ErrTOMLEdit = errors.New("openshell: cannot edit the TOML document safely")

// tomlSetting is one scalar assignment: table path, key, value (bool or
// int64).
type tomlSetting struct {
	Table []string
	Key   string
	Value any
}

func (s tomlSetting) String() string {
	return fmt.Sprintf("[%s] %s = %s", formatTOMLPath(s.Table), formatTOMLKey(s.Key), tomlLiteral(s.Value))
}

// editTOML applies settings to src, keeping every comment, blank line and
// unrelated byte in place: existing values are replaced in their span,
// missing keys are appended to their table, missing tables are added next
// to their closest relative. The result is then decoded and must equal the
// decoded original plus exactly the settings, or ErrTOMLEdit is returned.
func editTOML(src []byte, settings []tomlSetting) ([]byte, error) {
	var before map[string]any
	if err := toml.Unmarshal(src, &before); err != nil {
		return nil, fmt.Errorf("openshell: parse TOML: %w", err)
	}
	doc := newTOMLDoc(src)
	for _, s := range settings {
		if len(s.Table) == 0 || s.Key == "" {
			return nil, fmt.Errorf("%w: setting needs a table and a key", ErrTOMLEdit)
		}
		if err := doc.set(s.Table, s.Key, tomlLiteral(s.Value)); err != nil {
			return nil, err
		}
	}
	out := doc.bytes()

	var after map[string]any
	if err := toml.Unmarshal(out, &after); err != nil {
		return nil, fmt.Errorf("%w: the edited document does not parse (%v)", ErrTOMLEdit, err)
	}
	want, err := applyTOMLSettings(before, settings)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(normalizeTOML(want), normalizeTOML(after)) {
		return nil, fmt.Errorf("%w: the edit would change more than the requested keys", ErrTOMLEdit)
	}
	return out, nil
}

// applyTOMLSettings returns a deep copy of doc with settings applied.
func applyTOMLSettings(doc map[string]any, settings []tomlSetting) (map[string]any, error) {
	out := deepCopyTOML(doc).(map[string]any)
	for _, s := range settings {
		m := out
		for _, part := range s.Table {
			next, ok := m[part]
			if !ok {
				child := map[string]any{}
				m[part] = child
				m = child
				continue
			}
			child, ok := next.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: %s is not a table", ErrTOMLEdit, formatTOMLPath(s.Table))
			}
			m = child
		}
		m[s.Key] = s.Value
	}
	return out, nil
}

// lookupTOML returns the value at table.key in a decoded document.
func lookupTOML(doc map[string]any, table []string, key string) (any, bool) {
	m := doc
	for _, part := range table {
		child, ok := m[part].(map[string]any)
		if !ok {
			return nil, false
		}
		m = child
	}
	v, ok := m[key]
	return v, ok
}

func deepCopyTOML(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, vv := range t {
			out[k] = deepCopyTOML(vv)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, vv := range t {
			out[i] = deepCopyTOML(vv)
		}
		return out
	default:
		return v
	}
}

// normalizeTOML makes a nil document comparable with an empty one.
func normalizeTOML(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func tomlLiteral(v any) string {
	switch t := v.(type) {
	case bool:
		return strconv.FormatBool(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case int:
		return strconv.Itoa(t)
	default:
		panic(fmt.Sprintf("openshell: unsupported TOML literal %T", v))
	}
}

var bareTOMLKey = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func formatTOMLKey(k string) string {
	if bareTOMLKey.MatchString(k) {
		return k
	}
	return strconv.Quote(k)
}

func formatTOMLPath(path []string) string {
	parts := make([]string, len(path))
	for i, p := range path {
		parts[i] = formatTOMLKey(p)
	}
	return strings.Join(parts, ".")
}

// tomlDoc is a TOML document as lines, for surgical edits.
type tomlDoc struct {
	lines []string
	// cr is "\r" when the document uses CRLF line endings.
	cr string
}

func newTOMLDoc(src []byte) *tomlDoc {
	s := string(src)
	d := &tomlDoc{lines: strings.Split(s, "\n")}
	if strings.Contains(s, "\r\n") {
		d.cr = "\r"
	}
	return d
}

func (d *tomlDoc) bytes() []byte {
	out := strings.Join(d.lines, "\n")
	if out != "" && !strings.HasSuffix(out, "\n") {
		out += d.cr + "\n"
	}
	return []byte(out)
}

func (d *tomlDoc) insert(at int, lines ...string) {
	for i := range lines {
		lines[i] += d.cr
	}
	d.lines = append(d.lines[:at], append(lines, d.lines[at:]...)...)
}

func (d *tomlDoc) set(table []string, key, literal string) error {
	lines, err := scanTOMLLines(d.lines)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTOMLEdit, err)
	}
	header := -1
	for i, l := range lines {
		if l.kind == tomlTable && equalPath(l.path, table) {
			header = i
			break
		}
	}
	if header < 0 {
		d.addTable(lines, table, key, literal)
		return nil
	}
	end := sectionEnd(lines, header)
	last, indent := header, ""
	for i := header + 1; i < end; i++ {
		l := lines[i]
		if l.kind == tomlKeyValue {
			if equalPath(l.path, []string{key}) {
				if l.multiline {
					return fmt.Errorf("%w: %s.%s spans several lines", ErrTOMLEdit, formatTOMLPath(table), key)
				}
				line := d.lines[i]
				d.lines[i] = line[:l.valStart] + literal + line[l.valEnd:]
				return nil
			}
			indent = leadingSpace(d.lines[i])
		}
		if l.kind == tomlKeyValue || l.kind == tomlContinuation {
			last = i
		}
	}
	d.insert(last+1, indent+formatTOMLKey(key)+" = "+literal)
	return nil
}

// addTable appends a new table after the section of its closest relative
// (the last header sharing the longest path prefix), else at the end.
func (d *tomlDoc) addTable(lines []tomlLine, table []string, key, literal string) {
	best, bestLen := -1, 0
	for i, l := range lines {
		if l.kind != tomlTable && l.kind != tomlArrayTable {
			continue
		}
		if n := commonPrefix(l.path, table); n > 0 && n >= bestLen {
			best, bestLen = i, n
		}
	}
	at := lastContent(lines, 0, len(lines)) + 1
	if best >= 0 {
		at = lastContent(lines, best, sectionEnd(lines, best)) + 1
	}
	block := []string{"[" + formatTOMLPath(table) + "]", formatTOMLKey(key) + " = " + literal}
	if at > 0 && strings.TrimSpace(d.lines[at-1]) != "" {
		block = append([]string{""}, block...)
	}
	if at < len(lines) && strings.TrimSpace(d.lines[at]) != "" {
		block = append(block, "")
	}
	d.insert(at, block...)
}

func leadingSpace(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

func equalPath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func commonPrefix(a, b []string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

// sectionEnd returns the index of the next header after header.
func sectionEnd(lines []tomlLine, header int) int {
	for i := header + 1; i < len(lines); i++ {
		if lines[i].kind == tomlTable || lines[i].kind == tomlArrayTable {
			return i
		}
	}
	return len(lines)
}

// lastContent returns the last non-blank line in [from, to), or from-1.
func lastContent(lines []tomlLine, from, to int) int {
	for i := to - 1; i >= from; i-- {
		if lines[i].kind != tomlBlank {
			return i
		}
	}
	return from - 1
}

type tomlLineKind int

const (
	tomlBlank tomlLineKind = iota // empty or comment only
	tomlTable
	tomlArrayTable
	tomlKeyValue
	tomlContinuation // inside a multi-line string or array
)

type tomlLine struct {
	kind tomlLineKind
	path []string
	// valStart and valEnd delimit a single-line value in the line.
	valStart, valEnd int
	multiline        bool
}

const (
	scanNone = iota
	scanMultiBasic
	scanMultiLiteral
)

type tomlScanState struct {
	mode  int
	depth int
}

func (s *tomlScanState) open() bool { return s.mode != scanNone || s.depth != 0 }

// scanTOMLLines classifies each line. It understands enough TOML to never
// mistake string or array content for a header or key.
func scanTOMLLines(src []string) ([]tomlLine, error) {
	out := make([]tomlLine, len(src))
	var st tomlScanState
	for i, line := range src {
		if st.open() {
			out[i].kind = tomlContinuation
			if _, err := scanTOMLValue(line, 0, &st); err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			continue
		}
		body := strings.TrimLeft(line, " \t")
		off := len(line) - len(body)
		switch {
		case strings.TrimSpace(body) == "" || body[0] == '#':
			out[i].kind = tomlBlank
		case body[0] == '[':
			l, err := scanTOMLHeader(body)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			out[i] = l
		default:
			path, j, err := scanTOMLKey(body, 0)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			j = skipTOMLSpace(body, j)
			if j >= len(body) || body[j] != '=' {
				return nil, fmt.Errorf("line %d: expected '=' after key", i+1)
			}
			j = skipTOMLSpace(body, j+1)
			end, err := scanTOMLValue(body, j, &st)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", i+1, err)
			}
			l := tomlLine{kind: tomlKeyValue, path: path, multiline: st.open()}
			if !l.multiline {
				if end <= j {
					return nil, fmt.Errorf("line %d: missing value", i+1)
				}
				l.valStart, l.valEnd = off+j, off+end
			}
			out[i] = l
		}
	}
	if st.open() {
		return nil, errors.New("unterminated multi-line value")
	}
	return out, nil
}

func scanTOMLHeader(body string) (tomlLine, error) {
	l := tomlLine{kind: tomlTable}
	i, closer := 1, "]"
	if strings.HasPrefix(body, "[[") {
		l.kind, i, closer = tomlArrayTable, 2, "]]"
	}
	path, j, err := scanTOMLKey(body, i)
	if err != nil {
		return l, err
	}
	j = skipTOMLSpace(body, j)
	if !strings.HasPrefix(body[j:], closer) {
		return l, fmt.Errorf("unterminated table header")
	}
	rest := strings.TrimSpace(body[j+len(closer):])
	if rest != "" && rest[0] != '#' {
		return l, fmt.Errorf("unexpected text after table header")
	}
	l.path = path
	return l, nil
}

func skipTOMLSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// scanTOMLKey reads a dotted key starting at i.
func scanTOMLKey(s string, i int) ([]string, int, error) {
	var path []string
	for {
		i = skipTOMLSpace(s, i)
		if i >= len(s) {
			return nil, i, errors.New("missing key")
		}
		switch s[i] {
		case '"':
			j := closeTOMLBasic(s, i+1)
			if j < 0 {
				return nil, i, errors.New("unterminated quoted key")
			}
			raw := s[i+1 : j]
			key, err := strconv.Unquote(`"` + raw + `"`)
			if err != nil {
				key = raw
			}
			path = append(path, key)
			i = j + 1
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return nil, i, errors.New("unterminated quoted key")
			}
			path = append(path, s[i+1:i+1+j])
			i += j + 2
		default:
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '-' || (s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			if j == i {
				return nil, i, fmt.Errorf("invalid key character %q", s[i])
			}
			path = append(path, s[i:j])
			i = j
		}
		i = skipTOMLSpace(s, i)
		if i < len(s) && s[i] == '.' {
			i++
			continue
		}
		return path, i, nil
	}
}

// closeTOMLBasic returns the index of the quote closing a basic string
// whose content starts at i, or -1.
func closeTOMLBasic(s string, i int) int {
	for ; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}

// scanTOMLValue scans value text from i to the end of the line (or a
// comment), updating st for multi-line strings and brackets. It returns
// the index just past the last value byte on the line.
func scanTOMLValue(s string, i int, st *tomlScanState) (int, error) {
	end := i
	for i < len(s) {
		switch st.mode {
		case scanMultiBasic:
			j := i
			for j < len(s) && !strings.HasPrefix(s[j:], `"""`) {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				return len(s), nil
			}
			i = absorbQuotes(s, j+3, '"')
			st.mode, end = scanNone, i
			continue
		case scanMultiLiteral:
			j := strings.Index(s[i:], "'''")
			if j < 0 {
				return len(s), nil
			}
			i = absorbQuotes(s, i+j+3, '\'')
			st.mode, end = scanNone, i
			continue
		}
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			return end, nil
		case strings.HasPrefix(s[i:], `"""`):
			st.mode, i = scanMultiBasic, i+3
			end = i
		case strings.HasPrefix(s[i:], "'''"):
			st.mode, i = scanMultiLiteral, i+3
			end = i
		case c == '"':
			j := closeTOMLBasic(s, i+1)
			if j < 0 {
				return 0, errors.New("unterminated string")
			}
			i, end = j+1, j+1
		case c == '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return 0, errors.New("unterminated string")
			}
			i = i + j + 2
			end = i
		case c == '[' || c == '{':
			st.depth++
			i++
			end = i
		case c == ']' || c == '}':
			st.depth--
			if st.depth < 0 {
				return 0, errors.New("unbalanced bracket")
			}
			i++
			end = i
		default:
			i++
			end = i
		}
	}
	return end, nil
}

// absorbQuotes skips up to two further quote characters, which TOML
// allows inside the closing delimiter of a multi-line string.
func absorbQuotes(s string, i int, q byte) int {
	for n := 0; n < 2 && i < len(s) && s[i] == q; n++ {
		i++
	}
	return i
}
