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
	"errors"
	"fmt"
	"path/filepath"
)

// A user who ran per-user DefenseClaw setup for Claude Code on Windows before
// the endpoint moved to the managed deployment still has that setup's hook
// registrations in ~/.claude/settings.json. Cursor also loads hooks from that
// file, so the managed Cursor preToolUse hook checks it and denies every tool
// call while the per-user PreToolUse registration remains: it runs the
// user's own launcher without --enterprise-managed. The managed installer
// removes the registrations per-user setup writes and leaves the rest of the
// file as it was.

// ClaudeCodeUserHookRemoval names one hook handler removed from a user's
// Claude Code settings.json.
type ClaudeCodeUserHookRemoval struct {
	Event   string
	Command string
}

// ClaudeCodePerUserInstall names the per-user DefenseClaw installation whose
// Claude Code registrations RemoveClaudeCodePerUserHookRegistrations removes.
// LocalAppData and UserProgramFiles are the user's LocalAppData and per-user
// Programs Known Folders, as in CursorPerUserInstall.
type ClaudeCodePerUserInstall struct {
	LocalAppData     string
	UserProgramFiles string
}

// claudeCodePerUserHookArgs are the arguments per-user setup on Windows
// passes to the launcher (claudeCodeHookInvocation).
var claudeCodePerUserHookArgs = [...]string{"hook", "--connector", "claudecode"}

// RemoveClaudeCodePerUserHookRegistrations returns data without the Claude
// Code hook handlers that per-user DefenseClaw setup writes on Windows: a
// "command" handler that runs one of DefenseClaw's own launcher or gateway
// executables with exactly the arguments hook --connector claudecode, written
// as command and args by current releases and as the one command string
// "<executable>" hook --connector claudecode by earlier ones. The executables
// are the ones the per-user Cursor cleanup matches: DefenseClaw's installer
// and legacy locations, and its locations in the Known Folders in install.
// Matching is exact. A handler is never matched by file name, script marker or
// part of a command, and a registration with --enterprise-managed is not
// matched.
//
// A matched handler is removed from its matcher group, and a group left with
// no handlers is removed, as per-user teardown does. Every other byte of data
// is kept, including the other groups and handlers, their order and the text
// between them, so an event array whose groups were all removed stays as an
// empty array. Only the event arrays of the top-level "hooks" object are
// edited; "env" and every other setting stay.
//
// With nothing to remove it returns data and no removals. It returns an error
// when data is not one JSON object, repeats a key in the top-level or "hooks"
// object or in a group it edits, or exceeds the Claude Code settings size
// limit. Some executables are in the user's home, so a caller acting for
// another user runs it inside WithUserHomeDir.
func RemoveClaudeCodePerUserHookRegistrations(data []byte, install ClaudeCodePerUserInstall) ([]byte, []ClaudeCodeUserHookRemoval, error) {
	return removeClaudeCodeHookRegistrations(data, newClaudeCodePerUserHookMatcher(append(
		legacyNativeHookBinaries(),
		nativeHookBinariesInUserFolders(install.LocalAppData, install.UserProgramFiles)...,
	)))
}

// claudeCodePerUserHookMatcher holds the executables whose per-user Claude
// Code registrations are DefenseClaw's own and the command strings earlier
// releases wrote for them.
type claudeCodePerUserHookMatcher struct {
	executables map[string]struct{}
	commands    map[string]struct{}
}

func newClaudeCodePerUserHookMatcher(executables []string) claudeCodePerUserHookMatcher {
	matcher := claudeCodePerUserHookMatcher{
		executables: make(map[string]struct{}, len(executables)),
		commands:    make(map[string]struct{}, len(executables)),
	}
	for _, executable := range uniqueNonEmptyStrings(executables) {
		// A bare name is resolved through PATH and is not one location.
		if !filepath.IsAbs(executable) && !isWindowsDriveAbsolutePath(executable) {
			continue
		}
		matcher.executables[executable] = struct{}{}
		matcher.commands[windowsQuoteExe(executable)+" "+nativeHookFlag+"claudecode"] = struct{}{}
	}
	return matcher
}

// owns reports whether raw is a handler per-user setup wrote and returns its
// command.
func (matcher claudeCodePerUserHookMatcher) owns(raw interface{}) (string, bool) {
	handler, ok := raw.(map[string]interface{})
	if !ok {
		return "", false
	}
	if kind, _ := handler["type"].(string); kind != "command" {
		return "", false
	}
	command, _ := handler["command"].(string)
	if command == "" {
		return "", false
	}
	rawArgs, hasArgs := handler["args"]
	if !hasArgs {
		_, owned := matcher.commands[command]
		return command, owned
	}
	args, ok := rawArgs.([]interface{})
	if !ok || len(args) != len(claudeCodePerUserHookArgs) {
		return "", false
	}
	for index, want := range claudeCodePerUserHookArgs {
		if arg, _ := args[index].(string); arg != want {
			return "", false
		}
	}
	_, owned := matcher.executables[command]
	return command, owned
}

// groupHasOwnedHandler reports whether a decoded matcher group holds a
// handler matcher owns.
func (matcher claudeCodePerUserHookMatcher) groupHasOwnedHandler(raw interface{}) bool {
	group, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	handlers, ok := group["hooks"].([]interface{})
	if !ok {
		return false
	}
	for _, handler := range handlers {
		if _, owned := matcher.owns(handler); owned {
			return true
		}
	}
	return false
}

// withoutOwnedHandlers is the decoded counterpart of the byte edit: the event
// value raw without the handlers matcher owns and without the groups left
// with no handlers.
func (matcher claudeCodePerUserHookMatcher) withoutOwnedHandlers(raw interface{}) interface{} {
	groups, ok := raw.([]interface{})
	if !ok {
		return raw
	}
	out := make([]interface{}, 0, len(groups))
	for _, rawGroup := range groups {
		if !matcher.groupHasOwnedHandler(rawGroup) {
			out = append(out, rawGroup)
			continue
		}
		group := rawGroup.(map[string]interface{})
		var kept []interface{}
		for _, handler := range group["hooks"].([]interface{}) {
			if _, owned := matcher.owns(handler); !owned {
				kept = append(kept, handler)
			}
		}
		if len(kept) == 0 {
			continue
		}
		edited := make(map[string]interface{}, len(group))
		for key, value := range group {
			edited[key] = value
		}
		edited["hooks"] = kept
		out = append(out, edited)
	}
	return out
}

func removeClaudeCodeHookRegistrations(data []byte, owned claudeCodePerUserHookMatcher) ([]byte, []ClaudeCodeUserHookRemoval, error) {
	if int64(len(data)) > claudeCodeSettingsReadLimit {
		return nil, nil, fmt.Errorf("Claude Code settings JSON exceeds %d bytes", claudeCodeSettingsReadLimit)
	}
	base := 0
	if bytes.HasPrefix(data, utf8ByteOrderMark) {
		base = len(utf8ByteOrderMark)
	}
	body := data[base:]
	if len(bytes.TrimSpace(body)) == 0 {
		return data, nil, nil
	}
	original, err := decodeClaudeCodeSettings(body, "settings JSON")
	if err != nil {
		return nil, nil, err
	}
	members, err := jsonObjectMemberSpans(body)
	if err != nil {
		return nil, nil, fmt.Errorf("Claude Code settings JSON: %w", err)
	}
	hooksValue, found := jsonMemberValue(members, "hooks")
	if !found || body[hooksValue.start] != '{' {
		return data, nil, nil
	}
	events, err := jsonObjectMemberSpans(body[hooksValue.start:hooksValue.end])
	if err != nil {
		return nil, nil, fmt.Errorf("Claude Code settings JSON hooks object: %w", err)
	}
	type edit struct {
		span jsonSpan
		text []byte
	}
	var edits []edit
	var removed []ClaudeCodeUserHookRemoval
	editedEvents := make(map[string]struct{})
	for _, event := range events {
		value := jsonSpan{start: hooksValue.start + event.value.start, end: hooksValue.start + event.value.end}
		array := body[value.start:value.end]
		if array[0] != '[' {
			continue
		}
		text, eventRemoved, err := removeClaudeCodeEventHandlers(event.key, array, owned)
		if err != nil {
			return nil, nil, err
		}
		if len(eventRemoved) == 0 {
			continue
		}
		editedEvents[event.key] = struct{}{}
		removed = append(removed, eventRemoved...)
		edits = append(edits, edit{span: value, text: text})
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
	// handlers, and the groups they emptied, gone.
	updated, err := decodeClaudeCodeSettings(out[base:], "settings JSON after removing DefenseClaw handlers")
	if err != nil {
		return nil, nil, err
	}
	hooks, _ := original["hooks"].(map[string]interface{})
	for event := range editedEvents {
		hooks[event] = owned.withoutOwnedHandlers(hooks[event])
	}
	if !cursorJSONValuesSameText(original, updated) {
		return nil, nil, errors.New("Claude Code settings JSON: removing DefenseClaw handlers would change other content")
	}
	return out, removed, nil
}

// removeClaudeCodeEventHandlers returns the event array array without the
// handlers owned matches and without the groups left with no handlers. A
// group it edits must not repeat a key. It returns no text and no removals
// when nothing in array matches.
func removeClaudeCodeEventHandlers(event string, array []byte, owned claudeCodePerUserHookMatcher) ([]byte, []ClaudeCodeUserHookRemoval, error) {
	groups, err := jsonArrayElementSpans(array)
	if err != nil {
		return nil, nil, fmt.Errorf("Claude Code settings JSON %s groups: %w", event, err)
	}
	keep := make([]bool, len(groups))
	replacements := make([][]byte, len(groups))
	var removed []ClaudeCodeUserHookRemoval
	for index, span := range groups {
		keep[index] = true
		group := array[span.start:span.end]
		value, err := decodeCursorJSONValue(group)
		if err != nil {
			return nil, nil, fmt.Errorf("Claude Code settings JSON %s group: %w", event, err)
		}
		if !owned.groupHasOwnedHandler(value) {
			continue
		}
		members, err := jsonObjectMemberSpans(group)
		if err != nil {
			return nil, nil, fmt.Errorf("Claude Code settings JSON %s group: %w", event, err)
		}
		handlersValue, _ := jsonMemberValue(members, "hooks")
		list := group[handlersValue.start:handlersValue.end]
		handlers, err := jsonArrayElementSpans(list)
		if err != nil {
			return nil, nil, fmt.Errorf("Claude Code settings JSON %s handlers: %w", event, err)
		}
		keepHandler := make([]bool, len(handlers))
		kept := 0
		for handlerIndex, handlerSpan := range handlers {
			handler, err := decodeCursorJSONValue(list[handlerSpan.start:handlerSpan.end])
			if err != nil {
				return nil, nil, fmt.Errorf("Claude Code settings JSON %s handler: %w", event, err)
			}
			command, matched := owned.owns(handler)
			keepHandler[handlerIndex] = !matched
			if matched {
				removed = append(removed, ClaudeCodeUserHookRemoval{Event: event, Command: command})
				continue
			}
			kept++
		}
		if kept == 0 {
			keep[index] = false
			continue
		}
		replacement := make([]byte, 0, len(group))
		replacement = append(replacement, group[:handlersValue.start]...)
		replacement = append(replacement, jsonArrayWithout(list, handlers, keepHandler)...)
		replacements[index] = append(replacement, group[handlersValue.end:]...)
	}
	if len(removed) == 0 {
		return nil, nil, nil
	}
	return jsonArrayRewrite(array, groups, keep, replacements), removed, nil
}
