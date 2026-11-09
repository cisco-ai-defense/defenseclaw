// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package jsonc

import (
	"bytes"
	"fmt"
	"sort"
	"unicode/utf8"
)

// Value is a JSON5 value located in its source text: Start and End are byte
// offsets into the data given to Parse. A caller that must change a user's
// file and keep its comments, quoting and key order finds the members it
// wants here and cuts only their bytes (RemoveChild, Apply), instead of
// writing the whole document back from a parsed copy.
type Value struct {
	Start, End int
	Object     bool
	Array      bool
	// Children are the members of an object or the elements of an array, in
	// source order.
	Children []Child
}

// Child is one member of an object (Key is its decoded name) or one element
// of an array. Start is where the member or element begins (the key for a
// member). Comma is the offset of the comma that follows it, or -1.
type Child struct {
	Key   string
	Start int
	Value *Value
	Comma int
}

// Span is the byte range [Start, End) of a document.
type Span struct{ Start, End int }

// Lookup returns the index of the last member named key, the one a JSON
// reader keeps when a key repeats.
func (v *Value) Lookup(key string) (int, bool) {
	if !v.Object {
		return 0, false
	}
	for i := len(v.Children) - 1; i >= 0; i-- {
		if v.Children[i].Key == key {
			return i, true
		}
	}
	return 0, false
}

// Parse locates the values of a JSON5 document. It is a locator, not a
// validator: a caller parses the document with UnmarshalJSON5 first and uses
// Parse only to find where its values sit.
func Parse(data []byte) (*Value, error) {
	s := &spanScanner{d: data}
	if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		s.i = 3
	}
	if err := s.skip(); err != nil {
		return nil, err
	}
	v, err := s.value()
	if err != nil {
		return nil, err
	}
	if err := s.skip(); err != nil {
		return nil, err
	}
	if s.i != len(data) {
		return nil, s.fail("text after the document")
	}
	return v, nil
}

type spanScanner struct {
	d []byte
	i int
}

func (s *spanScanner) fail(what string) error {
	return fmt.Errorf("json5 locate: %s at byte %d", what, s.i)
}

// skip moves past white space and comments.
func (s *spanScanner) skip() error {
	for s.i < len(s.d) {
		b := s.d[s.i]
		switch {
		case b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f':
			s.i++
		case b == '/' && s.i+1 < len(s.d) && (s.d[s.i+1] == '/' || s.d[s.i+1] == '*'):
			next, closed := skipJSON5Comment(s.d, s.i)
			if !closed {
				return s.fail("unterminated comment")
			}
			s.i = next
		case b >= utf8.RuneSelf:
			r, size := utf8.DecodeRune(s.d[s.i:])
			if !isJSON5Space(r) {
				return nil
			}
			s.i += size
		default:
			return nil
		}
	}
	return nil
}

func (s *spanScanner) str() error {
	quote := s.d[s.i]
	s.i++
	for s.i < len(s.d) {
		switch s.d[s.i] {
		case quote:
			s.i++
			return nil
		case '\\':
			s.i++
		}
		s.i++
	}
	return s.fail("unterminated string")
}

func (s *spanScanner) value() (*Value, error) {
	if s.i >= len(s.d) {
		return nil, s.fail("missing value")
	}
	v := &Value{Start: s.i}
	switch c := s.d[s.i]; c {
	case '{', '[':
		v.Object, v.Array = c == '{', c == '['
		closer := byte('}')
		if v.Array {
			closer = ']'
		}
		s.i++
		for {
			if err := s.skip(); err != nil {
				return nil, err
			}
			if s.i >= len(s.d) {
				return nil, s.fail("unterminated container")
			}
			if s.d[s.i] == closer {
				s.i++
				break
			}
			child := Child{Start: s.i, Comma: -1}
			if v.Object {
				if err := s.key(&child); err != nil {
					return nil, err
				}
			}
			val, err := s.value()
			if err != nil {
				return nil, err
			}
			child.Value = val
			if err := s.skip(); err != nil {
				return nil, err
			}
			if s.i < len(s.d) && s.d[s.i] == ',' {
				child.Comma = s.i
				s.i++
			} else if s.i >= len(s.d) || s.d[s.i] != closer {
				return nil, s.fail("missing comma or closing bracket")
			}
			v.Children = append(v.Children, child)
		}
	case '"', '\'':
		if err := s.str(); err != nil {
			return nil, err
		}
	default:
		for s.i < len(s.d) {
			b := s.d[s.i]
			if b == ',' || b == ']' || b == '}' || b == ':' || b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f' ||
				b == '/' && s.i+1 < len(s.d) && (s.d[s.i+1] == '/' || s.d[s.i+1] == '*') {
				break
			}
			size := 1
			if b >= utf8.RuneSelf {
				var r rune
				if r, size = utf8.DecodeRune(s.d[s.i:]); isJSON5Space(r) {
					break
				}
			}
			s.i += size
		}
		if s.i == v.Start {
			return nil, s.fail("missing value")
		}
	}
	v.End = s.i
	return v, nil
}

// key reads a member name and the colon after it.
func (s *spanScanner) key(c *Child) error {
	start := s.i
	if s.d[s.i] == '"' || s.d[s.i] == '\'' {
		if err := s.str(); err != nil {
			return err
		}
	} else if end := scanJSON5Identifier(s.d, s.i); end > s.i {
		s.i = end
	} else {
		return s.fail("member name expected")
	}
	// A key is decoded the way the reader decodes it: as the name of a
	// one-member object.
	var one map[string]int
	probe := append(append([]byte("{"), s.d[start:s.i]...), ":0}"...)
	if err := UnmarshalJSON5(probe, &one); err != nil || len(one) != 1 {
		return s.fail("member name that does not decode")
	}
	for k := range one {
		c.Key = k
	}
	if err := s.skip(); err != nil {
		return err
	}
	if s.i >= len(s.d) || s.d[s.i] != ':' {
		return s.fail("colon expected")
	}
	s.i++
	return s.skip()
}

// RemoveChild returns the ranges to cut from data to drop child i of v and
// nothing else: the member or element and the comma that goes with it, and
// the whole line when it stands alone on one. Comments around it stay.
func (v *Value) RemoveChild(data []byte, i int) []Span {
	c := v.Children[i]
	start, end := c.Start, c.Value.End
	var spans []Span
	if c.Comma >= 0 {
		end = c.Comma + 1
	} else if i > 0 && v.Children[i-1].Comma >= 0 {
		// The last child has no comma of its own: the one before it goes.
		p := v.Children[i-1].Comma
		spans = append(spans, Span{p, p + 1})
	}
	return append(spans, lineSpan(data, start, end))
}

// lineSpan widens [start, end) to the whole line when only blanks share the
// line with it, and otherwise past the blanks that follow it.
func lineSpan(data []byte, start, end int) Span {
	lead := start
	for lead > 0 && (data[lead-1] == ' ' || data[lead-1] == '\t') {
		lead--
	}
	leadBlank := lead == 0 || data[lead-1] == '\n' || data[lead-1] == '\r'
	blanks := end
	for blanks < len(data) && (data[blanks] == ' ' || data[blanks] == '\t') {
		blanks++
	}
	next := blanks
	switch {
	case next >= len(data):
	case data[next] == '\n':
		next++
	case data[next] == '\r':
		next++
		if next < len(data) && data[next] == '\n' {
			next++
		}
	default:
		return Span{start, blanks}
	}
	if leadBlank {
		return Span{lead, next}
	}
	return Span{start, blanks}
}

// Apply returns data without the given ranges.
func Apply(data []byte, spans []Span) []byte {
	sorted := append([]Span(nil), spans...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].Start > sorted[b].Start })
	out := append([]byte(nil), data...)
	for _, sp := range sorted {
		out = append(out[:sp.Start], out[sp.End:]...)
	}
	return out
}
