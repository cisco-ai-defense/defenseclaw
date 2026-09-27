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

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// A user who ran per-user DefenseClaw setup for Cursor before the endpoint
// moved to the managed deployment still has that setup's registrations in
// ~/.cursor/hooks.json. The managed preToolUse hook treats them as foreign
// hooks, because they run an adapter from the user's own data directory, so
// it denies every tool call until they are removed. The managed installer
// removes the commands per-user teardown run by that user would remove and
// leaves the rest of the file as it was.

// CursorUserHookRemoval names one registration removed from a user's Cursor
// hooks.json.
type CursorUserHookRemoval struct {
	Event   string
	Command string
}

var utf8ByteOrderMark = []byte{0xef, 0xbb, 0xbf}

// CursorPerUserInstall names the per-user DefenseClaw installation whose
// Cursor registrations RemoveCursorPerUserHookRegistrations removes.
type CursorPerUserInstall struct {
	// DataDir is the per-user DefenseClaw data directory.
	DataDir string
	// LocalAppData and UserProgramFiles are the user's LocalAppData and
	// per-user Programs Known Folders, which hold the executables of the
	// older direct native commands. The connector's own Known Folder lookups
	// use the process token, so a caller acting for another user resolves
	// these from that user's token. An empty folder adds no commands.
	LocalAppData     string
	UserProgramFiles string
}

// RemoveCursorPerUserHookRegistrations returns data without the Cursor hook
// registrations that per-user DefenseClaw setup writes for install. It uses
// the exact-command rule of per-user teardown (cursorOwnedHookCommands): the
// PowerShell adapter command for install.DataDir and the older direct native
// commands, together with the older direct native commands for the Known
// Folders in install, so that it finds what per-user teardown run by that
// user finds. Only entries of the event arrays in the top-level "hooks"
// object are removed. Every other byte of data is kept, including the other
// entries, their order and the text between them, so an event array whose
// entries were all removed stays as an empty array.
//
// With nothing to remove it returns data and no removals. It returns an error
// when data is not one JSON object, repeats a key in the top-level or "hooks"
// object, or exceeds the Cursor hooks size limit. Some older native commands
// name paths in the user's home, so a caller acting for another user runs it
// inside WithUserHomeDir.
func RemoveCursorPerUserHookRegistrations(data []byte, install CursorPerUserInstall) ([]byte, []CursorUserHookRemoval, error) {
	if strings.TrimSpace(install.DataDir) == "" {
		return nil, nil, errors.New("connector: the per-user DefenseClaw data directory is required")
	}
	owned := newCursorHookCommandMatcher(append(
		cursorOwnedHookCommands(SetupOpts{DataDir: install.DataDir}),
		cursorNativeHookCommandsInUserFolders(install.LocalAppData, install.UserProgramFiles)...,
	))
	return removeCursorHookRegistrations(data, owned)
}

// cursorNativeHookCommandsInUserFolders returns the older direct native Cursor
// commands whose executables are in the given Known Folders: the HookRuntime
// launcher under LocalAppData and the per-user installation's launcher and
// gateway under UserProgramFiles. For the process user these are the commands
// legacyCursorNativeHookCommands builds from canonicalNativeWindowsHookBinary,
// canonicalNativeWindowsInstalledHookBinary and
// canonicalNativeWindowsInstalledGatewayBinary.
func cursorNativeHookCommandsInUserFolders(localAppData, userProgramFiles string) []string {
	binaries := nativeHookBinariesInUserFolders(localAppData, userProgramFiles)
	commands := make([]string, 0, len(binaries))
	for _, binary := range binaries {
		commands = append(commands, windowsQuoteExe(binary)+" "+nativeHookFlag+"cursor")
	}
	return commands
}

// nativeHookBinariesInUserFolders returns DefenseClaw's executables in the
// given Known Folders that per-user setup registered directly: the
// HookRuntime launcher under LocalAppData and the per-user installation's
// launcher and gateway under UserProgramFiles. An empty folder adds none.
func nativeHookBinariesInUserFolders(localAppData, userProgramFiles string) []string {
	var binaries []string
	if localAppData = strings.TrimSpace(localAppData); localAppData != "" {
		binaries = append(binaries, filepath.Join(localAppData, "DefenseClaw", "HookRuntime", windowsHookBinaryName))
	}
	if userProgramFiles = strings.TrimSpace(userProgramFiles); userProgramFiles != "" {
		bin := filepath.Join(userProgramFiles, "DefenseClaw", "bin")
		binaries = append(binaries, filepath.Join(bin, windowsHookBinaryName), filepath.Join(bin, windowsGatewayBinaryName))
	}
	return binaries
}

func removeCursorHookRegistrations(data []byte, owned cursorHookCommandMatcher) ([]byte, []CursorUserHookRemoval, error) {
	base := 0
	if bytes.HasPrefix(data, utf8ByteOrderMark) {
		base = len(utf8ByteOrderMark)
	}
	body := data[base:]
	original, err := decodeCursorHooksJSON(body)
	if err != nil {
		return nil, nil, err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return data, nil, nil
	}
	members, err := jsonObjectMemberSpans(body)
	if err != nil {
		return nil, nil, fmt.Errorf("Cursor hooks JSON: %w", err)
	}
	hooksValue, found := jsonMemberValue(members, "hooks")
	if !found || body[hooksValue.start] != '{' {
		return data, nil, nil
	}
	events, err := jsonObjectMemberSpans(body[hooksValue.start:hooksValue.end])
	if err != nil {
		return nil, nil, fmt.Errorf("Cursor hooks JSON hooks object: %w", err)
	}
	type edit struct {
		span jsonSpan
		text []byte
	}
	var edits []edit
	var removed []CursorUserHookRemoval
	editedEvents := make(map[string]struct{})
	for _, event := range events {
		value := jsonSpan{start: hooksValue.start + event.value.start, end: hooksValue.start + event.value.end}
		array := body[value.start:value.end]
		if array[0] != '[' {
			continue
		}
		elements, err := jsonArrayElementSpans(array)
		if err != nil {
			return nil, nil, fmt.Errorf("Cursor hooks JSON %s entries: %w", event.key, err)
		}
		keep := make([]bool, len(elements))
		dropped := 0
		for index, element := range elements {
			entry, err := decodeCursorJSONValue(array[element.start:element.end])
			if err != nil {
				return nil, nil, fmt.Errorf("Cursor hooks JSON %s entry: %w", event.key, err)
			}
			command, matched := owned.matchedCursorHookCommand(entry)
			keep[index] = !matched
			if matched {
				dropped++
				removed = append(removed, CursorUserHookRemoval{Event: event.key, Command: command})
			}
		}
		if dropped == 0 {
			continue
		}
		editedEvents[event.key] = struct{}{}
		edits = append(edits, edit{span: value, text: jsonArrayWithout(array, elements, keep)})
	}
	if len(edits) == 0 {
		return data, nil, nil
	}
	out := make([]byte, 0, len(data))
	out = append(out, data[:base]...)
	cursor := 0
	for _, change := range edits {
		out = append(out, body[cursor:change.span.start]...)
		out = append(out, change.text...)
		cursor = change.span.end
	}
	out = append(out, body[cursor:]...)

	// The result must be the original document with only the removed
	// entries gone.
	updated, err := decodeCursorHooksJSON(out[base:])
	if err != nil {
		return nil, nil, fmt.Errorf("Cursor hooks JSON after removing DefenseClaw entries: %w", err)
	}
	hooks, _ := original["hooks"].(map[string]interface{})
	for event := range editedEvents {
		entries, _ := hooks[event].([]interface{})
		kept := make([]interface{}, 0, len(entries))
		for _, entry := range entries {
			if _, matched := owned.matchedCursorHookCommand(entry); !matched {
				kept = append(kept, entry)
			}
		}
		hooks[event] = kept
	}
	if !cursorJSONValuesEqual(original, updated) {
		return nil, nil, errors.New("Cursor hooks JSON: removing DefenseClaw entries would change other content")
	}
	return out, removed, nil
}

// matchedCursorHookCommand returns the command field value by which matcher
// owns raw, under the same rule as matches.
func (matcher cursorHookCommandMatcher) matchedCursorHookCommand(raw interface{}) (string, bool) {
	if !matcher.matches(raw) {
		return "", false
	}
	entry, _ := raw.(map[string]interface{})
	for _, key := range []string{"command", "bash", "powershell"} {
		command, _ := entry[key].(string)
		command = strings.TrimSpace(command)
		if _, ok := matcher[command]; ok && command != "" {
			return command, true
		}
	}
	return "", true
}

// jsonSpan is a byte range [start, end) of one JSON value.
type jsonSpan struct {
	start, end int
}

type jsonMemberSpan struct {
	key   string
	value jsonSpan
}

// jsonObjectMemberSpans returns the members of the JSON object that object
// holds, in document order, with the byte range of each value. A key that
// appears twice is an error, because readers disagree on which value wins.
func jsonObjectMemberSpans(object []byte) ([]jsonMemberSpan, error) {
	decoder := json.NewDecoder(bytes.NewReader(object))
	if err := expectJSONDelim(decoder, '{'); err != nil {
		return nil, err
	}
	var members []jsonMemberSpan
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("object key is not a string")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("key %q appears more than once", key)
		}
		seen[key] = struct{}{}
		value, err := nextJSONValueSpan(decoder)
		if err != nil {
			return nil, err
		}
		members = append(members, jsonMemberSpan{key: key, value: value})
	}
	if err := expectJSONDelim(decoder, '}'); err != nil {
		return nil, err
	}
	return members, nil
}

func jsonMemberValue(members []jsonMemberSpan, key string) (jsonSpan, bool) {
	for _, member := range members {
		if member.key == key {
			return member.value, true
		}
	}
	return jsonSpan{}, false
}

// jsonArrayElementSpans returns the byte range of each element of the JSON
// array that array holds.
func jsonArrayElementSpans(array []byte) ([]jsonSpan, error) {
	decoder := json.NewDecoder(bytes.NewReader(array))
	if err := expectJSONDelim(decoder, '['); err != nil {
		return nil, err
	}
	var elements []jsonSpan
	for decoder.More() {
		element, err := nextJSONValueSpan(decoder)
		if err != nil {
			return nil, err
		}
		elements = append(elements, element)
	}
	if err := expectJSONDelim(decoder, ']'); err != nil {
		return nil, err
	}
	return elements, nil
}

func expectJSONDelim(decoder *json.Decoder, want json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); !ok || delim != want {
		return fmt.Errorf("expected %q", want)
	}
	return nil
}

// nextJSONValueSpan reads the next value. A json.RawMessage holds exactly
// the value's bytes, without the whitespace around it, and the decoder's
// offset is then just past the value.
func nextJSONValueSpan(decoder *json.Decoder) (jsonSpan, error) {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return jsonSpan{}, err
	}
	end := int(decoder.InputOffset())
	return jsonSpan{start: end - len(raw), end: end}, nil
}

// jsonArrayWithout returns array without the elements whose keep flag is
// false. Each kept element keeps its own bytes and the separator that came
// before it; the first kept element takes the text after the opening bracket.
// An array with no kept element becomes [].
func jsonArrayWithout(array []byte, elements []jsonSpan, keep []bool) []byte {
	return jsonArrayRewrite(array, elements, keep, nil)
}

// jsonArrayRewrite is jsonArrayWithout with each kept element whose
// replacement is not nil written as that replacement instead of its own
// bytes. replacements is nil or has one entry per element.
func jsonArrayRewrite(array []byte, elements []jsonSpan, keep []bool, replacements [][]byte) []byte {
	out := []byte{'['}
	last := -1
	for index, element := range elements {
		if !keep[index] {
			continue
		}
		if last < 0 {
			out = append(out, array[1:elements[0].start]...)
		} else {
			out = append(out, array[elements[index-1].end:element.start]...)
		}
		if replacements != nil && replacements[index] != nil {
			out = append(out, replacements[index]...)
		} else {
			out = append(out, array[element.start:element.end]...)
		}
		last = index
	}
	if last < 0 {
		return append(out, ']')
	}
	out = append(out, array[elements[len(elements)-1].end:len(array)-1]...)
	return append(out, ']')
}
