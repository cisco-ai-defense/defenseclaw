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
	"strings"
	"unicode/utf8"
)

// pyJSONMaxDepth bounds the nesting the reader follows; json in Python raises
// RecursionError, not a decode error, at a depth near the recursion limit.
const pyJSONMaxDepth = 256

// pyJSON reads text as Python json.loads does: RFC 8259 JSON plus the
// literals NaN, Infinity and -Infinity, a dict with the last of a repeated
// key, and an error for a trailing comma, a single-quoted string, a control
// character in a string, a leading zero or any text after the value. The
// plugin scanner reads a .json manifest this way, so a JSON manifest it
// refuses declares nothing, and is not read as YAML.
type pyJSON struct {
	text  string
	i     int
	depth int
}

// hermesPyJSON returns the value of a JSON manifest, errPyLoad when
// json.loads refuses the text and errPyUnknown when the reader cannot tell.
func hermesPyJSON(data []byte) (*pyValue, error) {
	if !utf8.Valid(data) {
		return nil, errPyUnknown
	}
	p := &pyJSON{text: string(data)}
	p.space()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	if p.space(); p.i != len(p.text) {
		return nil, errPyLoad // extra data
	}
	return v, nil
}

func (p *pyJSON) space() {
	for p.i < len(p.text) && strings.IndexByte(" \t\n\r", p.text[p.i]) >= 0 {
		p.i++
	}
}

func (p *pyJSON) value() (*pyValue, error) {
	if p.i >= len(p.text) {
		return nil, errPyLoad
	}
	switch c := p.text[p.i]; {
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return pyString(s), nil
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '-' || c >= '0' && c <= '9':
		if strings.HasPrefix(p.text[p.i:], "-Infinity") {
			p.i += len("-Infinity")
		} else if !p.number() {
			return nil, errPyLoad
		}
	default:
		for _, literal := range []string{"null", "true", "false", "NaN", "Infinity"} {
			if strings.HasPrefix(p.text[p.i:], literal) {
				p.i += len(literal)
				return &pyValue{kind: pyScalar}, nil
			}
		}
		return nil, errPyLoad
	}
	return &pyValue{kind: pyScalar}, nil
}

// number consumes -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?; whatever
// follows is left for the caller, which refuses it.
func (p *pyJSON) number() bool {
	digits := func() int {
		start := p.i
		for p.i < len(p.text) && p.text[p.i] >= '0' && p.text[p.i] <= '9' {
			p.i++
		}
		return p.i - start
	}
	if p.text[p.i] == '-' {
		p.i++
	}
	switch {
	case p.i < len(p.text) && p.text[p.i] == '0':
		p.i++
	case digits() == 0:
		return false
	}
	if p.i+1 < len(p.text) && p.text[p.i] == '.' && p.text[p.i+1] >= '0' && p.text[p.i+1] <= '9' {
		p.i++
		digits()
	}
	if p.i < len(p.text) && (p.text[p.i] == 'e' || p.text[p.i] == 'E') {
		save := p.i
		p.i++
		if p.i < len(p.text) && (p.text[p.i] == '+' || p.text[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			p.i = save
		}
	}
	return true
}

// str reads a string with the cursor on its opening quote.
func (p *pyJSON) str() (string, error) {
	var out strings.Builder
	for p.i++; p.i < len(p.text); {
		c := p.text[p.i]
		switch {
		case c == '"':
			p.i++
			return out.String(), nil
		case c < 0x20:
			return "", errPyLoad // invalid control character
		case c != '\\':
			out.WriteByte(c)
			p.i++
			continue
		}
		p.i++
		if p.i >= len(p.text) {
			break
		}
		escape := p.text[p.i]
		p.i++
		if r := strings.IndexByte("\"\\/bfnrt", escape); r >= 0 {
			out.WriteByte("\"\\/\b\f\n\r\t"[r])
			continue
		}
		if escape != 'u' {
			return "", errPyLoad // invalid escape
		}
		code, ok := p.hex4()
		if !ok {
			return "", errPyLoad
		}
		if code >= 0xd800 && code < 0xdc00 && strings.HasPrefix(p.text[p.i:], "\\u") {
			save := p.i
			p.i += 2
			if low, ok := p.hex4(); ok && low >= 0xdc00 && low < 0xe000 {
				code = 0x10000 + (code-0xd800)<<10 + low - 0xdc00
			} else {
				p.i = save
			}
		}
		out.WriteRune(rune(code))
	}
	return "", errPyLoad // unterminated string
}

func (p *pyJSON) hex4() (code int, ok bool) {
	if p.i+4 > len(p.text) {
		return 0, false
	}
	for _, c := range []byte(p.text[p.i : p.i+4]) {
		d := strings.IndexByte("0123456789abcdef", c|0x20)
		if d < 0 || c != '0'+byte(d) && c != 'a'+byte(d-10) && c != 'A'+byte(d-10) {
			return 0, false
		}
		code = code<<4 | d
	}
	p.i += 4
	return code, true
}

func (p *pyJSON) enter() error {
	if p.depth++; p.depth > pyJSONMaxDepth {
		return errPyUnknown
	}
	return nil
}

func (p *pyJSON) object() (*pyValue, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	v := &pyValue{kind: pyMap}
	p.i++
	if p.space(); p.i < len(p.text) && p.text[p.i] == '}' {
		p.i++
		return v, nil
	}
	for {
		p.space()
		if p.i >= len(p.text) || p.text[p.i] != '"' {
			return nil, errPyLoad // property name must be a double-quoted string
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		if p.space(); p.i >= len(p.text) || p.text[p.i] != ':' {
			return nil, errPyLoad
		}
		p.i++
		p.space()
		value, err := p.value()
		if err != nil {
			return nil, err
		}
		v.set("s:"+key, value)
		p.space()
		if p.i >= len(p.text) {
			return nil, errPyLoad
		}
		switch p.text[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return v, nil
		default:
			return nil, errPyLoad
		}
	}
}

func (p *pyJSON) array() (*pyValue, error) {
	if err := p.enter(); err != nil {
		return nil, err
	}
	defer func() { p.depth-- }()
	p.i++
	if p.space(); p.i < len(p.text) && p.text[p.i] == ']' {
		p.i++
		return &pyValue{kind: pyList}, nil
	}
	for {
		p.space()
		if _, err := p.value(); err != nil {
			return nil, err
		}
		p.space()
		if p.i >= len(p.text) {
			return nil, errPyLoad
		}
		switch p.text[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return &pyValue{kind: pyList}, nil
		default:
			return nil, errPyLoad
		}
	}
}
