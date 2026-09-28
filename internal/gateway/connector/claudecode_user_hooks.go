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
	"reflect"
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

// claudeCodeGroupHandlerFields are the fields that make a matcher group a
// handler of its own for the managed Cursor hook (foreignHookHasHandlerFields
// in hookexec): Cursor, reading the group in its own layout, runs the group's
// command and ignores its hooks array.
var claudeCodeGroupHandlerFields = [...]string{"type", "command", "url", "prompt"}

// claudeCodeGroupIsAHandler reports whether a decoded matcher group has
// handler fields of its own, and so stays when its hooks array is emptied.
func claudeCodeGroupIsAHandler(group map[string]interface{}) bool {
	for _, key := range claudeCodeGroupHandlerFields {
		if _, ok := group[key]; ok {
			return true
		}
	}
	return false
}

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
// no handlers is removed, as per-user teardown does. A group that also has
// handler fields of its own (claudeCodeGroupHandlerFields) is kept with an
// empty hooks array instead: Cursor runs such a group's own command, so the
// managed Cursor hook checks it. Every other byte of data is kept, including
// the other groups and handlers, their order and the text between them, so an
// event array whose groups were all removed stays as an empty array. Only the
// event arrays of the top-level "hooks" object are edited; "env" and every
// other setting stay.
//
// With nothing to remove it returns data and no removals. data is read as the
// managed Cursor hook reads it, where a repeated key has its last value, so a
// file that repeats a key but holds nothing to remove is returned as it is.
// It returns an error when data is not one JSON object or exceeds the Claude
// Code settings size limit, or when it holds a handler to remove and repeats
// a key in the top-level or "hooks" object or in a group it edits. Some
// executables are in the user's home, so a caller acting for another user
// runs it inside WithUserHomeDir.
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

// holdsOwnedHandler reports whether a decoded settings document has a
// handler matcher owns in an event array of its top-level "hooks" object.
func (matcher claudeCodePerUserHookMatcher) holdsOwnedHandler(settings map[string]interface{}) bool {
	hooks, _ := settings["hooks"].(map[string]interface{})
	for _, event := range hooks {
		groups, _ := event.([]interface{})
		for _, group := range groups {
			if matcher.groupHasOwnedHandler(group) {
				return true
			}
		}
	}
	return false
}

// withoutOwnedHandlers is the decoded counterpart of the byte edit: the event
// value raw without the handlers matcher owns and without the groups left
// with no handlers that are not handlers themselves.
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
		kept := []interface{}{}
		for _, handler := range group["hooks"].([]interface{}) {
			if _, owned := matcher.owns(handler); !owned {
				kept = append(kept, handler)
			}
		}
		if len(kept) == 0 && !claudeCodeGroupIsAHandler(group) {
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
	// The checks below that the file can be edited exactly apply only to a
	// file with something to remove. A file without DefenseClaw's handlers,
	// decoded as the managed Cursor hook decodes it, is not why that hook
	// denies, so it is not reported.
	if !owned.holdsOwnedHandler(original) {
		return data, nil, nil
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
	if !reflect.DeepEqual(original, updated) {
		return nil, nil, errors.New("Claude Code settings JSON: removing DefenseClaw handlers would change other content")
	}
	return out, removed, nil
}

// removeClaudeCodeEventHandlers returns the event array array without the
// handlers owned matches and without the groups left with no handlers,
// except a group that is a handler itself, which stays with an empty hooks
// array. A group it edits must not repeat a key. It returns no text and no
// removals when nothing in array matches.
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
		if kept == 0 && !claudeCodeGroupIsAHandler(value.(map[string]interface{})) {
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
