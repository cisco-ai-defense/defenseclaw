// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"reflect"
)

// spliceDevinProjectHooks returns the project hooks.v1.json document data
// with each event in events set to its new list, editing only those members:
// every other byte, the operator's // and /* */ comments and foreign event
// lists included, is kept (GAP-0192). Setup rewrote the whole file with
// json.MarshalIndent, which dropped the comments. ok is false when the
// document cannot be edited in place (not a JSONC object, a duplicate key),
// or when the edit would not decode to want; the caller then renders want.
func spliceDevinProjectHooks(data []byte, events []string, want map[string]interface{}) ([]byte, bool) {
	members, closing, ok := scanJSONCObjectMembers(data)
	if !ok {
		return nil, false
	}
	seen := map[string]jsoncMember{}
	for _, member := range members {
		if _, dup := seen[member.key]; dup {
			return nil, false
		}
		seen[member.key] = member
	}
	type edit struct {
		start, end int
		text       []byte
	}
	var edits []edit
	var inserted [][]byte
	for _, event := range events {
		value, err := json.MarshalIndent(want[event], "  ", "  ")
		if err != nil {
			return nil, false
		}
		if member, exists := seen[event]; exists {
			edits = append(edits, edit{member.valueStart, member.valueEnd, value})
			continue
		}
		key, _ := json.Marshal(event)
		inserted = append(inserted, append(append(append([]byte("\n  "), key...), ": "...), value...))
	}
	var out bytes.Buffer
	last := 0
	for _, e := range edits {
		out.Write(data[last:e.start])
		out.Write(e.text)
		last = e.end
	}
	if len(inserted) > 0 {
		insertAt, comma := closing, len(members) > 0
		if len(members) > 0 {
			insertAt = members[len(members)-1].valueEnd
			if next := skipJSONCSpace(data, insertAt); next < len(data) && data[next] == ',' {
				// A trailing comma stays one: the new members follow it.
				insertAt, comma = next+1, false
			}
		}
		out.Write(data[last:insertAt])
		for i, member := range inserted {
			if comma || i > 0 {
				out.WriteByte(',')
			}
			out.Write(member)
		}
		if len(members) == 0 {
			out.WriteByte('\n')
		}
		last = insertAt
	}
	out.Write(data[last:])
	spliced := out.Bytes()
	normalized, err := normalizeCopilotJSONC(spliced)
	if err != nil {
		return nil, false
	}
	var got map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if decoder.Decode(&got) != nil || !reflect.DeepEqual(devinJSONPlain(got), devinJSONPlain(want)) {
		return nil, false
	}
	return spliced, true
}

// devinJSONPlain gives a value its plain JSON decoding, so a json.Number and
// the number it names compare equal.
func devinJSONPlain(v interface{}) interface{} {
	data, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out interface{}
	if json.Unmarshal(data, &out) != nil {
		return nil
	}
	return out
}

type jsoncMember struct {
	key                  string
	valueStart, valueEnd int
}

// scanJSONCObjectMembers lists the members of the JSONC object data holds
// and the index of its closing brace.
func scanJSONCObjectMembers(data []byte) ([]jsoncMember, int, bool) {
	i := skipJSONCSpace(data, 0)
	if i >= len(data) || data[i] != '{' {
		return nil, 0, false
	}
	i++
	var members []jsoncMember
	for {
		i = skipJSONCSpace(data, i)
		if i >= len(data) {
			return nil, 0, false
		}
		if data[i] == '}' {
			if skipJSONCSpace(data, i+1) != len(data) {
				return nil, 0, false
			}
			return members, i, true
		}
		if data[i] == ',' && len(members) > 0 {
			i++
			continue
		}
		if data[i] != '"' {
			return nil, 0, false
		}
		end := skipJSONCString(data, i)
		if end < 0 {
			return nil, 0, false
		}
		var key string
		if json.Unmarshal(data[i:end], &key) != nil {
			return nil, 0, false
		}
		i = skipJSONCSpace(data, end)
		if i >= len(data) || data[i] != ':' {
			return nil, 0, false
		}
		start := skipJSONCSpace(data, i+1)
		valueEnd := skipJSONCValue(data, start)
		if valueEnd < 0 {
			return nil, 0, false
		}
		members = append(members, jsoncMember{key: key, valueStart: start, valueEnd: valueEnd})
		i = skipJSONCSpace(data, valueEnd)
		if i < len(data) && data[i] == ',' {
			i++
		} else if i >= len(data) || data[i] != '}' {
			return nil, 0, false
		}
	}
}

func skipJSONCSpace(data []byte, i int) int {
	for i < len(data) {
		switch {
		case data[i] == ' ' || data[i] == '\t' || data[i] == '\n' || data[i] == '\r':
			i++
		case data[i] == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case data[i] == '/' && i+1 < len(data) && data[i+1] == '*':
			end := bytes.Index(data[i+2:], []byte("*/"))
			if end < 0 {
				return len(data)
			}
			i += end + 4
		default:
			return i
		}
	}
	return i
}

func skipJSONCString(data []byte, i int) int {
	for i++; i < len(data); i++ {
		switch data[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return -1
}

// skipJSONCValue returns the end of the JSONC value at i, or -1.
func skipJSONCValue(data []byte, i int) int {
	if i >= len(data) {
		return -1
	}
	switch data[i] {
	case '"':
		return skipJSONCString(data, i)
	case '{', '[':
		depth := 0
		for i < len(data) {
			switch data[i] {
			case '"':
				end := skipJSONCString(data, i)
				if end < 0 {
					return -1
				}
				i = end
				continue
			case '/':
				if next := skipJSONCSpace(data, i); next != i {
					i = next
					continue
				}
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return i + 1
				}
			}
			i++
		}
		return -1
	default:
		start := i
		for i < len(data) && !bytes.ContainsRune([]byte(",}] \t\r\n/"), rune(data[i])) {
			i++
		}
		if i == start {
			return -1
		}
		return i
	}
}
