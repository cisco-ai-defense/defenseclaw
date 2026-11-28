// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// renderCodexRequirementsPreserving renders cfg, the Codex machine
// requirements after DefenseClaw edited raw, and keeps raw's bytes for every
// entry the edit did not change, so the administrator's comments, key order,
// spelling and layout survive install, repair and removal (GAP-1737, #898).
// Only a changed entry is written again, in its place: a root key, or a key
// of a table (features.hooks, hooks.windows_managed_dir, hooks.<event>). A
// hook list DefenseClaw only appended to keeps its groups' bytes, and the new
// groups follow them. The result must decode to exactly cfg; a layout the
// editor cannot narrow (a table written as an inline table, say) is rendered
// whole, as before.
func renderCodexRequirementsPreserving(raw []byte, cfg map[string]interface{}) ([]byte, error) {
	full, err := toml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	full = retainCodexTOMLBOM(raw, full)
	if edited, ok := editCodexRequirementsInPlace(raw, cfg); ok {
		return edited, nil
	}
	return full, nil
}

type codexReqLine struct {
	text    string
	path    []string // the entry the line belongs to: one or two keys; nil at the root
	header  bool
	array   bool // [[...]] header
	key     bool // a key = value line (or its continuation)
	rootKey bool // a key line outside every table
	comment bool // blank or comment-only line
	elem    int  // index of the [[top.sub]] block the line is in, else -1
}

func codexReqPathKey(path []string) string { return strings.Join(path, "\x00") }

// codexReqTableLike reports a value TOML renders as a table or an array of
// tables rather than as one key = value line.
func codexReqTableLike(value interface{}) bool {
	switch v := value.(type) {
	case map[string]interface{}:
		return true
	case []interface{}:
		if len(v) == 0 {
			return false
		}
		for _, item := range v {
			if _, ok := item.(map[string]interface{}); !ok {
				return false
			}
		}
		return true
	}
	return false
}

func codexReqKeyText(parts []string) string {
	quoted := make([]string, len(parts))
	for i, part := range parts {
		bare := part != ""
		for j := 0; j < len(part); j++ {
			if !isTOMLBareKeyByte(part[j]) {
				bare = false
				break
			}
		}
		if bare {
			quoted[i] = part
		} else {
			quoted[i] = strconv.Quote(part)
		}
	}
	return strings.Join(quoted, ".")
}

// codexReqValueLine renders one key = value line.
func codexReqValueLine(keyParts []string, value interface{}) (string, error) {
	encoded, err := toml.Marshal(map[string]interface{}{"v": value})
	if err != nil {
		return "", err
	}
	text := strings.TrimRight(string(encoded), "\n")
	if !strings.HasPrefix(text, "v = ") || strings.Contains(text, "\n") {
		return "", fmt.Errorf("value of %s does not render as one line", codexReqKeyText(keyParts))
	}
	return codexReqKeyText(keyParts) + " = " + strings.TrimPrefix(text, "v = ") + "\n", nil
}

// codexReqTableBlock renders {top: {sub: value}} (or {top: value} when sub is
// empty) as tables, without a bare [top] header that carries no keys: the
// administrator's [top] table, if any, stays where it is.
func codexReqTableBlock(top, sub string, value interface{}) (string, error) {
	doc := map[string]interface{}{top: value}
	if sub != "" {
		doc = map[string]interface{}{top: map[string]interface{}{sub: value}}
	}
	encoded, err := toml.Marshal(doc)
	if err != nil {
		return "", err
	}
	if sub == "" {
		return string(encoded), nil
	}
	var out strings.Builder
	bare := "[" + codexReqKeyText([]string{top}) + "]"
	for _, line := range strings.SplitAfter(string(encoded), "\n") {
		if strings.TrimSpace(line) == bare {
			continue
		}
		out.WriteString(line)
	}
	return strings.TrimLeft(out.String(), "\n"), nil
}

func editCodexRequirementsInPlace(raw []byte, cfg map[string]interface{}) ([]byte, bool) {
	bom := []byte(nil)
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		bom, raw = []byte{0xef, 0xbb, 0xbf}, raw[3:]
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, false
	}
	before := map[string]interface{}{}
	if parseCodexTOML(raw, &before) != nil {
		return nil, false
	}
	// cfg in the types a decoder gives (int64, not int), so a value compares
	// equal to the one read back from the file.
	normalized, err := toml.Marshal(cfg)
	if err != nil {
		return nil, false
	}
	want := map[string]interface{}{}
	if parseCodexTOML(normalized, &want) != nil {
		return nil, false
	}

	// The plan: which entries are written again, and which hook lists only
	// gained groups at their end.
	changed := map[string][]string{}
	appended := map[string][]interface{}{}
	removed := map[string]map[int]bool{}
	for _, top := range codexReqUnion(before, want) {
		oldValue, hadOld := before[top]
		newValue, hasNew := want[top]
		oldTable, oldIsTable := oldValue.(map[string]interface{})
		newTable, newIsTable := newValue.(map[string]interface{})
		if hadOld && hasNew && oldIsTable && newIsTable {
			for _, sub := range codexReqUnion(oldTable, newTable) {
				oldSub, hadSub := oldTable[sub]
				newSub, hasSub := newTable[sub]
				if hadSub == hasSub && codexValueMatches(oldSub, newSub) {
					continue
				}
				path := []string{top, sub}
				oldList, oldIsList := oldSub.([]interface{})
				newList, newIsList := newSub.([]interface{})
				if hadSub && hasSub && oldIsList && newIsList && len(newList) > len(oldList) &&
					codexReqTableLike(newSub) && codexValueMatches(oldList, newList[:len(oldList)]) {
					appended[codexReqPathKey(path)] = newList[len(oldList):]
					continue
				}
				if gone := codexReqRemovedItems(oldList, newList); hadSub && hasSub && oldIsList && newIsList &&
					codexReqTableLike(oldSub) && len(newList) > 0 && gone != nil {
					removed[codexReqPathKey(path)] = gone
					continue
				}
				changed[codexReqPathKey(path)] = path
			}
			continue
		}
		if hadOld == hasNew && codexValueMatches(oldValue, newValue) {
			continue
		}
		changed[codexReqPathKey([]string{top})] = []string{top}
	}
	if len(changed) == 0 && len(appended) == 0 && len(removed) == 0 {
		return append(bom, raw...), true
	}

	newline := "\n"
	if bytes.Contains(raw, []byte("\r\n")) {
		newline = "\r\n"
	}
	lines := classifyCodexRequirementLines(string(raw))
	if lines == nil {
		return nil, false
	}
	pathDropped := func(path []string) bool {
		if len(path) == 0 {
			return false
		}
		if _, ok := changed[codexReqPathKey(path[:1])]; ok {
			return true
		}
		_, ok := changed[codexReqPathKey(path[:min(2, len(path))])]
		return len(path) >= 2 && ok
	}
	// A root key that holds a table whose keys changed (an inline table, or
	// a dotted key one level up), or a hook list that grew but is not
	// written as [[top.sub]] blocks, cannot be narrowed.
	arrayForm := map[string]bool{}
	plainHeader := map[string]bool{}
	// A table the administrator wrote as dotted keys at the root
	// (hooks.windows_managed_dir = ..., features.web_search = ...) cannot
	// take a [top] header later; its new keys are dotted root keys too
	// (GAP-2119).
	dottedRoot := map[string]bool{}
	for _, line := range lines {
		if line.key && line.rootKey && len(line.path) == 2 {
			dottedRoot[line.path[0]] = true
		}
		if line.header && line.array && len(line.path) == 2 {
			arrayForm[codexReqPathKey(line.path)] = true
		}
		if line.header && !line.array && len(line.path) == 1 {
			plainHeader[line.path[0]] = true
		}
	}
	for key := range appended {
		if !arrayForm[key] {
			return nil, false
		}
	}
	for key := range removed {
		if !arrayForm[key] {
			return nil, false
		}
	}
	dropped := func(line codexReqLine) bool {
		if pathDropped(line.path) {
			return true
		}
		if len(line.path) == 2 && line.elem >= 0 {
			return removed[codexReqPathKey(line.path)][line.elem]
		}
		return false
	}
	for _, line := range lines {
		if line.key && len(line.path) == 1 {
			for _, path := range changed {
				if len(path) == 2 && path[0] == line.path[0] {
					return nil, false
				}
			}
			for key := range appended {
				if strings.HasPrefix(key, line.path[0]+"\x00") {
					return nil, false
				}
			}
		}
	}

	type piece struct {
		text string
		slot string // a changed or appended entry rendered here
	}
	var pieces []piece
	placed := map[string]bool{}
	rootPlaced := map[string]bool{}
	appendAt := map[string]int{}
	var pending []codexReqLine
	pendingDropped := false
	lastDropped := false
	rootSlotPlaced := false
	flush := func(nextDropped bool) {
		if !pendingDropped || !nextDropped {
			for _, line := range pending {
				pieces = append(pieces, piece{text: line.text})
			}
		}
		pending, pendingDropped = nil, false
	}
	for _, line := range lines {
		if line.comment {
			if len(pending) == 0 {
				pendingDropped = lastDropped
			}
			pending = append(pending, line)
			continue
		}
		if line.header {
			if !rootSlotPlaced {
				pieces = append(pieces, piece{slot: "\x01root"})
				rootSlotPlaced = true
			}
		}
		isDropped := dropped(line)
		flush(isDropped)
		lastDropped = isDropped
		if isDropped && !pathDropped(line.path) {
			continue // a removed [[top.sub]] block
		}
		if isDropped {
			key := codexReqPathKey(line.path[:min(2, len(line.path))])
			if _, ok := changed[key]; !ok {
				key = codexReqPathKey(line.path[:1])
			}
			// A table-like value goes where its old table started; a value
			// written as a key goes where that key was. Anything else is
			// rendered at the end.
			if !placed[key] {
				newValue, hasNew := codexReqLookup(want, changed[key])
				fits := !hasNew || !codexReqTableLike(newValue) && line.key || codexReqTableLike(newValue) && line.header
				if fits {
					pieces = append(pieces, piece{slot: key})
					placed[key] = true
					rootPlaced[key] = line.rootKey
				}
			}
			continue
		}
		pieces = append(pieces, piece{text: line.text})
		if len(line.path) >= 2 {
			key := codexReqPathKey(line.path[:2])
			if _, ok := appended[key]; ok {
				appendAt[key] = len(pieces)
			}
		}
		if line.header && !line.array && len(line.path) == 1 {
			// New scalar keys of this table go right after its header.
			pieces = append(pieces, piece{slot: "\x03" + line.path[0]})
		}
	}
	tail := pending
	tailDropped := pendingDropped
	if !rootSlotPlaced {
		for _, line := range tail {
			pieces = append(pieces, piece{text: line.text})
		}
		tail = nil
		pieces = append(pieces, piece{slot: "\x01root"})
	}

	// Render every slot.
	rendered := map[string]string{}
	var end []string
	var rootNew strings.Builder
	headerNew := map[string]*strings.Builder{}
	for key, path := range changed {
		value, present := codexReqLookup(want, path)
		if !present {
			continue
		}
		if placed[key] {
			var text string
			var err error
			switch {
			case codexReqTableLike(value) && len(path) == 2:
				text, err = codexReqTableBlock(path[0], path[1], value)
			case codexReqTableLike(value):
				text, err = codexReqTableBlock(path[0], "", value)
			default:
				keyParts := path[len(path)-1:]
				if rootPlaced[key] {
					keyParts = path
				}
				text, err = codexReqValueLine(keyParts, value)
			}
			if err != nil {
				return nil, false
			}
			rendered[key] = text
			continue
		}
		switch {
		case !codexReqTableLike(value) && len(path) == 1:
			text, err := codexReqValueLine(path, value)
			if err != nil {
				return nil, false
			}
			rootNew.WriteString(text)
		case !codexReqTableLike(value) && len(path) == 2 && dottedRoot[path[0]] && !plainHeader[path[0]]:
			text, err := codexReqValueLine(path, value)
			if err != nil {
				return nil, false
			}
			rootNew.WriteString(text)
		case !codexReqTableLike(value) && len(path) == 2 && plainHeader[path[0]]:
			text, err := codexReqValueLine(path[1:], value)
			if err != nil {
				return nil, false
			}
			if headerNew[path[0]] == nil {
				headerNew[path[0]] = &strings.Builder{}
			}
			headerNew[path[0]].WriteString(text)
		case !codexReqTableLike(value) && len(path) == 2:
			text, err := codexReqValueLine(path[1:], value)
			if err != nil {
				return nil, false
			}
			end = append(end, "["+codexReqKeyText(path[:1])+"]\n"+text)
		default:
			sub := ""
			if len(path) == 2 {
				sub = path[1]
			}
			text, err := codexReqTableBlock(path[0], sub, value)
			if err != nil {
				return nil, false
			}
			end = append(end, text)
		}
	}
	appendedText := map[int]string{}
	for key, items := range appended {
		path := strings.SplitN(key, "\x00", 2)
		text, err := codexReqTableBlock(path[0], path[1], items)
		if err != nil {
			return nil, false
		}
		at, ok := appendAt[key]
		if !ok {
			return nil, false
		}
		appendedText[at] += text
	}

	var out strings.Builder
	write := func(text string) {
		if text == "" {
			return
		}
		if out.Len() != 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteString(newline)
		}
		out.WriteString(strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", newline))
	}
	writeKept := func(text string) {
		if out.Len() != 0 && !strings.HasSuffix(out.String(), "\n") {
			out.WriteString(newline)
		}
		out.WriteString(text)
	}
	for i, p := range pieces {
		switch {
		case p.slot == "\x01root":
			write(rootNew.String())
		case strings.HasPrefix(p.slot, "\x03"):
			if b := headerNew[strings.TrimPrefix(p.slot, "\x03")]; b != nil {
				write(b.String())
			}
		case p.slot != "":
			write(rendered[p.slot])
		default:
			writeKept(p.text)
		}
		if text, ok := appendedText[i+1]; ok {
			write(text)
		}
	}
	if !tailDropped || strings.TrimSpace(codexReqJoin(tail)) != "" {
		for _, line := range tail {
			writeKept(line.text)
		}
	}
	for _, text := range end {
		if out.Len() != 0 {
			write(newline)
		}
		write(text)
	}
	result := []byte(out.String())
	check := map[string]interface{}{}
	if parseCodexTOML(result, &check) != nil {
		return nil, false
	}
	// A table whose last dotted root key went away is still in cfg, empty;
	// spell it as an empty [top] table, as the whole render does (GAP-2119).
	tops := codexReqUnion(want, nil)
	slices.Sort(tops)
	for _, top := range tops {
		table, isTable := want[top].(map[string]interface{})
		if _, present := check[top]; !isTable || len(table) != 0 || present {
			continue
		}
		if len(result) != 0 && !bytes.HasSuffix(result, []byte("\n")) {
			result = append(result, newline...)
		}
		result = append(result, newline+"["+codexReqKeyText([]string{top})+"]"+newline...)
	}
	check = map[string]interface{}{}
	if parseCodexTOML(result, &check) != nil || !codexValueMatches(check, want) {
		return nil, false
	}
	return append(bom, result...), true
}

func codexReqJoin(lines []codexReqLine) string {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(line.text)
	}
	return b.String()
}

// codexReqRemovedItems returns the indexes of oldList that newList dropped
// when newList is oldList with some items removed (order kept), else nil.
func codexReqRemovedItems(oldList, newList []interface{}) map[int]bool {
	if len(newList) >= len(oldList) {
		return nil
	}
	gone := map[int]bool{}
	j := 0
	for i, item := range oldList {
		if j < len(newList) && codexValueMatches(item, newList[j]) {
			j++
			continue
		}
		gone[i] = true
	}
	if j != len(newList) {
		return nil
	}
	return gone
}

func codexReqLookup(doc map[string]interface{}, path []string) (interface{}, bool) {
	value, ok := doc[path[0]]
	if !ok || len(path) == 1 {
		return value, ok
	}
	table, isTable := value.(map[string]interface{})
	if !isTable {
		return nil, false
	}
	value, ok = table[path[1]]
	return value, ok
}

func codexReqUnion(a, b map[string]interface{}) []string {
	seen := map[string]bool{}
	var keys []string
	for _, doc := range []map[string]interface{}{a, b} {
		for key := range doc {
			if !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// classifyCodexRequirementLines splits raw into lines and names the entry
// each one belongs to. It returns nil for a layout it cannot read.
func classifyCodexRequirementLines(raw string) []codexReqLine {
	var syntax tomlEditSyntax
	var lines []codexReqLine
	section := []string(nil)
	var last codexReqLine
	elems := map[string]int{}
	elem, elemPath := -1, ""
	for _, text := range strings.SplitAfter(raw, "\n") {
		if text == "" {
			continue
		}
		if syntax.multiline != 0 || syntax.arrayDepth != 0 {
			syntax.visible(text)
			cont := last
			cont.text = text
			lines = append(lines, cont)
			continue
		}
		visible := strings.TrimSpace(syntax.visible(text))
		line := codexReqLine{text: text, elem: -1}
		switch {
		case visible == "":
			line.comment = true
		case strings.HasPrefix(visible, "[") && strings.HasSuffix(visible, "]"):
			line.header = true
			line.array = strings.HasPrefix(visible, "[[")
			section = tomlKeyPath(strings.TrimLeft(strings.TrimLeft(text, " \t"), "["))
			if len(section) == 0 {
				return nil
			}
			line.path = section[:min(2, len(section))]
			switch {
			case line.array && len(section) == 2:
				key := codexReqPathKey(section)
				elem, elemPath = elems[key], key
				elems[key]++
			case len(section) < 3:
				elem, elemPath = -1, ""
			}
			if len(section) >= 2 && codexReqPathKey(section[:2]) == elemPath {
				line.elem = elem
			}
		case strings.Contains(visible, "="):
			key := tomlKeyPath(text)
			if len(key) == 0 {
				return nil
			}
			full := append(append([]string(nil), section...), key...)
			line.key = true
			line.rootKey = len(section) == 0
			line.path = full[:min(2, len(full))]
			if len(section) >= 2 && codexReqPathKey(section[:2]) == elemPath {
				line.elem = elem
			}
		default:
			return nil
		}
		last = line
		lines = append(lines, line)
	}
	if syntax.multiline != 0 || syntax.arrayDepth != 0 {
		return nil
	}
	return lines
}
