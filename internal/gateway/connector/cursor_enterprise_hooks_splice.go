// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// ErrWindowsCursorHooksNotEditableInPlace is the refusal of
// SpliceWindowsCursorEnterpriseHooksInPlace: the document cannot take
// DefenseClaw's entries without a new render of the whole file.
var ErrWindowsCursorHooksNotEditableInPlace = errors.New("only a new render of the whole file could register the guard in it, " +
	"which would change entries DefenseClaw did not write (for example a duplicate key)")

// SpliceWindowsCursorEnterpriseHooks returns the document
// MergeWindowsCursorEnterpriseHooks returns, but it edits only DefenseClaw's
// own entries in existing: every other hook entry, key and value keeps its
// exact bytes. The machine guard rebuild uses it, so the hooks an
// administrator keeps in the shared C:\ProgramData\Cursor\hooks.json come
// back byte for byte. existing is returned unchanged when it already is the
// merged document. A document the splice cannot edit in place, such as one
// with a duplicate key, gets the merged render, which keeps the same hooks.
func SpliceWindowsCursorEnterpriseHooks(existing []byte, adapterPath, failMode string) ([]byte, error) {
	return spliceWindowsCursorEnterpriseHooksDocument(existing, adapterPath, failMode, false)
}

// SpliceWindowsCursorEnterpriseHooksInPlace is SpliceWindowsCursorEnterpriseHooks
// for a recovery (the machine guard rebuild): a document the splice cannot
// edit in place is refused with ErrWindowsCursorHooksNotEditableInPlace
// instead of rendered again, so only DefenseClaw's own entries ever change.
// A duplicate key would otherwise lose the administrator's earlier value.
// An empty document and {} take the merged render: they hold nothing else.
func SpliceWindowsCursorEnterpriseHooksInPlace(existing []byte, adapterPath, failMode string) ([]byte, error) {
	return spliceWindowsCursorEnterpriseHooksDocument(existing, adapterPath, failMode, true)
}

func spliceWindowsCursorEnterpriseHooksDocument(existing []byte, adapterPath, failMode string, inPlace bool) ([]byte, error) {
	merged, err := MergeWindowsCursorEnterpriseHooks(existing, adapterPath, failMode)
	if err != nil {
		return nil, err
	}
	if trimmed := bytes.TrimSpace(existing); len(trimmed) == 0 || bytes.Equal(trimmed, []byte("{}")) {
		// A new document: the merge's render.
		return merged, nil
	}
	if WindowsCursorEnterpriseHooksSemanticallyEqual(existing, merged) {
		return append([]byte(nil), existing...), nil
	}
	spliced, ok := spliceCursorEnterpriseHooks(existing, adapterPath, failMode, false)
	if !ok || !WindowsCursorEnterpriseHooksSemanticallyEqual(spliced, merged) {
		if inPlace {
			return nil, ErrWindowsCursorHooksNotEditableInPlace
		}
		return merged, nil
	}
	return spliced, nil
}

// SpliceRemoveWindowsCursorEnterpriseHooks returns the document
// RemoveWindowsCursorEnterpriseHooks returns, but it edits only DefenseClaw's
// own entries in existing: every other hook entry, key and value keeps its
// exact bytes. Every DefenseClaw edit of the shared machine hooks.json that
// takes the guard out (teardown, rollback, orphan reclaim) uses it. existing
// is returned unchanged when it has no DefenseClaw entry. A document the
// splice cannot edit in place gets the removal's render, which keeps the
// same hooks.
func SpliceRemoveWindowsCursorEnterpriseHooks(existing []byte, adapterPath string) ([]byte, error) {
	removed, err := RemoveWindowsCursorEnterpriseHooks(existing, adapterPath)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(removed, existing) {
		return removed, nil
	}
	spliced, ok := spliceCursorEnterpriseHooks(existing, adapterPath, "", true)
	if !ok || !WindowsCursorEnterpriseHooksSemanticallyEqual(spliced, removed) {
		return removed, nil
	}
	return spliced, nil
}

// cursorJSONMember is one object member: the key starts at start, and its
// value runs from valueStart to end.
type cursorJSONMember struct {
	key                    string
	start, valueStart, end int
}

type cursorJSONSpan struct{ start, end int }

// spliceCursorEnterpriseHooks removes DefenseClaw's entries from data and,
// unless remove is set, appends its entry to every managed event.
func spliceCursorEnterpriseHooks(data []byte, adapterPath, failMode string, remove bool) ([]byte, bool) {
	command, legacyCommand, err := windowsCursorEnterpriseHookCommands(adapterPath)
	if err != nil {
		return nil, false
	}
	owned := map[string]bool{
		command:       true,
		legacyCommand: true,
		previousWindowsCursorEnterpriseHookCommand(adapterPath): true,
	}
	entry := ""
	if !remove {
		encoded, err := json.Marshal(windowsCursorEnterpriseHookEntry(command, failMode))
		if err != nil {
			return nil, false
		}
		entry = string(encoded)
	}
	open := skipCursorJSONSpace(data, 0)
	members, closing, ok := scanCursorJSONObject(data, open)
	if !ok || skipCursorJSONSpace(data, closing+1) != len(data) {
		return nil, false
	}
	seen := map[string]bool{}
	spans := make([]cursorJSONSpan, 0, len(members))
	items := make([]string, 0, len(members)+2)
	for _, member := range members {
		if seen[member.key] {
			return nil, false
		}
		seen[member.key] = true
		spans = append(spans, cursorJSONSpan{member.start, member.end})
		prefix := string(data[member.start:member.valueStart])
		value := string(data[member.valueStart:member.end])
		switch member.key {
		case "version":
			if value == "null" && !remove {
				value = "1"
			}
		case "hooks":
			value, ok = spliceCursorEnterpriseHookEvents(data, member, owned, entry)
			if !ok {
				return nil, false
			}
		}
		items = append(items, prefix+value)
	}
	if !seen["version"] && !remove {
		items = append([]string{`"version": 1`}, items...)
	}
	if !seen["hooks"] && !remove {
		events, _ := spliceCursorEnterpriseHookEvents(nil, cursorJSONMember{}, owned, entry)
		items = append(items, `"hooks": `+events)
	}
	var out bytes.Buffer
	out.Write(data[:open])
	out.WriteString(renderCursorJSONContainer(data, open, closing, spans, items))
	out.Write(data[closing+1:])
	return out.Bytes(), true
}

// spliceCursorEnterpriseHookEvents renders the hooks object of member with
// DefenseClaw's entries removed from every event and its entry appended to
// each managed event. An event this release no longer registers that held
// only DefenseClaw's entry is dropped, as the merge drops it. An empty entry
// only removes: every event left without an entry is dropped, as the removal
// drops it. Every other member and entry keeps its bytes. A nil data renders
// a new hooks object.
func spliceCursorEnterpriseHookEvents(
	data []byte,
	member cursorJSONMember,
	owned map[string]bool,
	entry string,
) (string, bool) {
	var members []cursorJSONMember
	closing := 0
	if data != nil && string(data[member.valueStart:member.end]) != "null" {
		var ok bool
		members, closing, ok = scanCursorJSONObject(data, member.valueStart)
		if !ok || closing+1 != member.end {
			return "", false
		}
	}
	seen := map[string]bool{}
	spans := make([]cursorJSONSpan, 0, len(members))
	items := make([]string, 0, len(members)+len(cursorEnterpriseHookEvents))
	changed := false
	for _, event := range members {
		if seen[event.key] {
			return "", false
		}
		seen[event.key] = true
		spans = append(spans, cursorJSONSpan{event.start, event.end})
		original := string(data[event.start:event.end])
		prefix := string(data[event.start:event.valueStart])
		managed := entry != "" && cursorHookEventManaged(event.key)
		switch data[event.valueStart] {
		case 'n':
			if managed {
				items = append(items, prefix+"["+entry+"]")
				changed = true
			} else {
				items = append(items, original)
			}
			continue
		case '[':
		default:
			if managed {
				return "", false
			}
			items = append(items, original)
			continue
		}
		elements, arrayClosing, ok := scanCursorJSONArray(data, event.valueStart)
		if !ok || arrayClosing+1 != event.end {
			return "", false
		}
		kept := make([]string, 0, len(elements)+1)
		removed := 0
		for _, element := range elements {
			var decoded interface{}
			if err := json.Unmarshal(data[element.start:element.end], &decoded); err != nil {
				return "", false
			}
			if owned[cursorHookCommand(decoded)] {
				removed++
				continue
			}
			kept = append(kept, string(data[element.start:element.end]))
		}
		switch {
		case managed:
			kept = append(kept, entry)
		case removed == 0:
			items = append(items, original)
			continue
		case len(kept) == 0:
			changed = true
			continue
		}
		changed = true
		items = append(items, prefix+renderCursorJSONContainer(data, event.valueStart, arrayClosing, elements, kept))
	}
	for _, event := range cursorEnterpriseHookEvents {
		if !seen[event] && entry != "" {
			key, _ := json.Marshal(event)
			items = append(items, string(key)+": ["+entry+"]")
			changed = true
		}
	}
	if data == nil || string(data[member.valueStart:member.end]) == "null" {
		return "{" + strings.Join(items, ",") + "}", true
	}
	if !changed {
		return string(data[member.valueStart:member.end]), true
	}
	return renderCursorJSONContainer(data, member.valueStart, closing, spans, items), true
}

// renderCursorJSONContainer renders the object or array that opens at
// data[open] and closes at data[closing] with items in place of the original
// members at spans, reusing the original whitespace around and between them.
func renderCursorJSONContainer(data []byte, open, closing int, spans []cursorJSONSpan, items []string) string {
	if len(items) == 0 {
		return string(data[open]) + string(data[closing])
	}
	lead, separator, trail := "", ",", ""
	if len(spans) > 0 {
		lead = string(data[open+1 : spans[0].start])
		trail = string(data[spans[len(spans)-1].end:closing])
		separator = "," + lead
		if len(spans) > 1 {
			separator = string(data[spans[0].end:spans[1].start])
		}
	}
	return string(data[open]) + lead + strings.Join(items, separator) + trail + string(data[closing])
}

func skipCursorJSONSpace(data []byte, index int) int {
	for index < len(data) && strings.IndexByte(" \t\r\n", data[index]) >= 0 {
		index++
	}
	return index
}

// skipCursorJSONValue returns the index just past the JSON value that starts
// at data[index], or -1. The document has already been decoded, so this only
// finds the value's end.
func skipCursorJSONValue(data []byte, index int) int {
	if index >= len(data) {
		return -1
	}
	switch data[index] {
	case '"':
		for next := index + 1; next < len(data); next++ {
			switch data[next] {
			case '\\':
				next++
			case '"':
				return next + 1
			}
		}
		return -1
	case '{', '[':
		depth := 0
		for next := index; next < len(data); next++ {
			switch data[next] {
			case '"':
				end := skipCursorJSONValue(data, next)
				if end < 0 {
					return -1
				}
				next = end - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return next + 1
				}
			}
		}
		return -1
	default:
		end := index
		for end < len(data) && strings.IndexByte(",]} \t\r\n", data[end]) < 0 {
			end++
		}
		if end == index {
			return -1
		}
		return end
	}
}

// scanCursorJSONObject returns the members of the object that opens at
// data[open] and the index of its closing brace.
func scanCursorJSONObject(data []byte, open int) ([]cursorJSONMember, int, bool) {
	if open >= len(data) || data[open] != '{' {
		return nil, 0, false
	}
	index := skipCursorJSONSpace(data, open+1)
	if index < len(data) && data[index] == '}' {
		return nil, index, true
	}
	var members []cursorJSONMember
	for index < len(data) && data[index] == '"' {
		keyEnd := skipCursorJSONValue(data, index)
		if keyEnd < 0 {
			return nil, 0, false
		}
		var key string
		if err := json.Unmarshal(data[index:keyEnd], &key); err != nil {
			return nil, 0, false
		}
		colon := skipCursorJSONSpace(data, keyEnd)
		if colon >= len(data) || data[colon] != ':' {
			return nil, 0, false
		}
		valueStart := skipCursorJSONSpace(data, colon+1)
		valueEnd := skipCursorJSONValue(data, valueStart)
		if valueEnd < 0 {
			return nil, 0, false
		}
		members = append(members, cursorJSONMember{key: key, start: index, valueStart: valueStart, end: valueEnd})
		index = skipCursorJSONSpace(data, valueEnd)
		if index >= len(data) {
			return nil, 0, false
		}
		if data[index] == '}' {
			return members, index, true
		}
		if data[index] != ',' {
			return nil, 0, false
		}
		index = skipCursorJSONSpace(data, index+1)
	}
	return nil, 0, false
}

// scanCursorJSONArray returns the elements of the array that opens at
// data[open] and the index of its closing bracket.
func scanCursorJSONArray(data []byte, open int) ([]cursorJSONSpan, int, bool) {
	if open >= len(data) || data[open] != '[' {
		return nil, 0, false
	}
	index := skipCursorJSONSpace(data, open+1)
	if index < len(data) && data[index] == ']' {
		return nil, index, true
	}
	var elements []cursorJSONSpan
	for index < len(data) {
		end := skipCursorJSONValue(data, index)
		if end < 0 {
			return nil, 0, false
		}
		elements = append(elements, cursorJSONSpan{index, end})
		index = skipCursorJSONSpace(data, end)
		if index >= len(data) {
			return nil, 0, false
		}
		if data[index] == ']' {
			return elements, index, true
		}
		if data[index] != ',' {
			return nil, 0, false
		}
		index = skipCursorJSONSpace(data, index+1)
	}
	return nil, 0, false
}
