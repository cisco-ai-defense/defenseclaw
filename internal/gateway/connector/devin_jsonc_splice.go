// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
)

// spliceDevinProjectHooks returns the project hooks.v1.json document data
// with each event in events set to its new list, editing only those members:
// every other byte, the operator's // and /* */ comments and foreign event
// lists included, is kept (GAP-0192). Setup rewrote the whole file with
// json.MarshalIndent, which dropped the comments. ok is false when the
// document cannot be edited in place (not a JSONC object, a duplicate key),
// or when the edit would not decode to want; the caller then renders want.
// An event that want no longer has is removed with its member, so teardown
// keeps the operator's comments too. A leading UTF-8 BOM (Windows
// PowerShell 5.1 writes one) is kept (GAP-1944).
func spliceDevinProjectHooks(data []byte, events []string, want map[string]interface{}) ([]byte, bool) {
	bom := []byte{0xEF, 0xBB, 0xBF}
	hasBOM := bytes.HasPrefix(data, bom)
	data = bytes.TrimPrefix(data, bom)
	members, closing, ok := scanJSONCObjectMembers(data)
	if !ok {
		return nil, false
	}
	seen := map[string]int{}
	for index, member := range members {
		if _, dup := seen[member.key]; dup {
			return nil, false
		}
		seen[member.key] = index
	}
	type edit struct {
		start, end int
		text       []byte
	}
	var edits []edit
	var inserted [][]byte
	removed := map[int]bool{}
	for _, event := range events {
		index, exists := seen[event]
		if _, keep := want[event]; !keep {
			if exists {
				removed[index] = true
			}
			continue
		}
		value, err := json.MarshalIndent(want[event], "  ", "  ")
		if err != nil {
			return nil, false
		}
		if exists {
			member := members[index]
			edits = append(edits, edit{member.valueStart, member.valueEnd, value})
			continue
		}
		key, _ := json.Marshal(event)
		inserted = append(inserted, append(append(append([]byte("\n  "), key...), ": "...), value...))
	}
	// A removed member goes with the comma before it (the first member with
	// the comma before the first member that stays). The comma and the
	// member are cut apart, so a comment between them stays.
	commaBefore := func(index int) int {
		if at := skipJSONCSpace(data, members[index-1].valueEnd); at < len(data) && data[at] == ',' {
			return at
		}
		return -1
	}
	for index := range members {
		if !removed[index] {
			continue
		}
		comma := index
		if index == 0 {
			for comma = 1; comma < len(members) && removed[comma]; comma++ {
			}
		}
		start, end := members[index].keyStart, members[index].valueEnd
		if comma < len(members) {
			at := commaBefore(comma)
			if at < 0 {
				return nil, false
			}
			if comma == index && len(bytes.TrimSpace(data[at+1:start])) == 0 {
				// Nothing but layout between the comma and the member.
				edits = append(edits, edit{at, end, nil})
				continue
			}
			edits = append(edits, edit{at, at + 1, nil})
		}
		start, end = wholeJSONCLines(data, start, end)
		edits = append(edits, edit{start, end, nil})
	}
	// Members are edited in document order, whatever the event order.
	sort.Slice(edits, func(a, b int) bool { return edits[a].start < edits[b].start })
	var out bytes.Buffer
	last := 0
	for _, e := range edits {
		if e.start < last {
			// Two removals share a comma; render the whole file instead.
			return nil, false
		}
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
		if insertAt < last {
			return nil, false
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
	if hasBOM {
		spliced = append(append([]byte{}, bom...), spliced...)
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
	key                            string
	keyStart, valueStart, valueEnd int
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
		keyStart := i
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
		members = append(members, jsoncMember{key: key, keyStart: keyStart, valueStart: start, valueEnd: valueEnd})
		i = skipJSONCSpace(data, valueEnd)
		if i < len(data) && data[i] == ',' {
			i++
		} else if i >= len(data) || data[i] != '}' {
			return nil, 0, false
		}
	}
}

// wholeJSONCLines widens [start, end) to the lines it fills when only
// spaces and tabs share those lines, so a removed member leaves no blank
// line behind.
func wholeJSONCLines(data []byte, start, end int) (int, int) {
	from := start
	for from > 0 && (data[from-1] == ' ' || data[from-1] == '\t') {
		from--
	}
	if from > 0 && data[from-1] != '\n' {
		return start, end
	}
	to := end
	for to < len(data) && (data[to] == ' ' || data[to] == '\t' || data[to] == '\r') {
		to++
	}
	if to >= len(data) || data[to] != '\n' {
		return start, end
	}
	return from, to + 1
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
