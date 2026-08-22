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
	"fmt"
	"io"
	"math/big"
	"strings"
)

var cursorHookEvents = []string{
	"sessionStart",
	"sessionEnd",
	"preToolUse",
	"postToolUse",
	"postToolUseFailure",
	"subagentStart",
	"subagentStop",
	"beforeShellExecution",
	"beforeMCPExecution",
	"afterShellExecution",
	"afterMCPExecution",
	"beforeReadFile",
	"beforeTabFileRead",
	"afterFileEdit",
	"afterTabFileEdit",
	"beforeSubmitPrompt",
	"afterAgentResponse",
	"afterAgentThought",
	"stop",
	"preCompact",
	"workspaceOpen",
}

const (
	windowsCursorEnterpriseHookTimeoutSeconds = 30
	windowsCursorEnterpriseHooksJSONMax       = 4 << 20
)

// IsBuiltinCursorConnector reports whether conn is the package's concrete
// Cursor connector. The concrete type is intentionally unexported: privileged
// enterprise callers can certify the built-in implementation without
// accepting an arbitrary Connector that merely returns the name "cursor".
func IsBuiltinCursorConnector(conn Connector) bool {
	cursor, ok := conn.(*hookOnlyConnector)
	return ok && cursor != nil && cursor.name == "cursor"
}

// RenderWindowsCursorEnterpriseAdapter renders the shared, token-free adapter
// installed in Cursor's protected machine hook directory. Managed enterprise
// hooks are always fail closed; an explicit request for fail-open is rejected
// rather than silently weakening the administrator-owned policy.
func RenderWindowsCursorEnterpriseAdapter(hookBinary, failMode string) ([]byte, error) {
	if err := validateAbsoluteLocalWindowsPath("Cursor hook executable", hookBinary); err != nil {
		return nil, err
	}
	if normalizeHookFailMode(failMode) != "closed" {
		return nil, fmt.Errorf("Windows Cursor enterprise adapter must use fail mode closed")
	}
	return renderWindowsCursorAdapter(hookBinary, "closed", true, cursorAdapterTimeoutMS)
}

func renderWindowsCursorAdapter(hookBinary, failMode string, managed bool, timeoutMS int) ([]byte, error) {
	if strings.TrimSpace(hookBinary) == "" {
		return nil, fmt.Errorf("Cursor hook executable is empty")
	}
	if timeoutMS <= 0 {
		return nil, fmt.Errorf("Cursor hook adapter timeout must be positive")
	}
	tmpl, err := hookFS.ReadFile("hooks/cursor-hook.ps1")
	if err != nil {
		return nil, fmt.Errorf("read Cursor adapter template: %w", err)
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		FailMode:      normalizeHookFailMode(failMode),
		Managed:       managed,
		HookBinaryPS:  strings.ReplaceAll(hookBinary, "'", "''"),
		HookTimeoutMS: timeoutMS,
	})
	if err != nil {
		return nil, fmt.Errorf("render Cursor adapter template: %w", err)
	}
	return []byte(rendered), nil
}

// MergeWindowsCursorEnterpriseHooks returns a Cursor hooks.json containing
// exactly one DefenseClaw entry for every supported event. Existing unrelated
// top-level fields, hook events, and hook entries retain their JSON semantics
// and order. Enterprise mode is always fail closed.
func MergeWindowsCursorEnterpriseHooks(existing []byte, adapterPath, failMode string) ([]byte, error) {
	command, err := windowsCursorEnterpriseHookCommand(adapterPath)
	if err != nil {
		return nil, err
	}
	if normalizeHookFailMode(failMode) != "closed" {
		return nil, fmt.Errorf("Windows Cursor enterprise hooks must use fail mode closed")
	}
	cfg, err := decodeCursorHooksJSON(existing)
	if err != nil {
		return nil, err
	}
	if err := requireCursorHooksVersionOne(cfg, true); err != nil {
		return nil, err
	}
	hooks, err := cursorHooksObject(cfg, true)
	if err != nil {
		return nil, err
	}

	// Remove stale copies of this exact protected adapter from every event,
	// including events retired by a future Cursor contract revision. Ownership
	// is deliberately not inferred from product words or filename fragments.
	for event, raw := range hooks {
		entries, ok := cursorHookEntryList(raw)
		if !ok {
			if cursorHookEventManaged(event) {
				return nil, fmt.Errorf("Cursor hooks event %q must be an array", event)
			}
			continue
		}
		filtered := removeCursorHookCommand(entries, command)
		if len(filtered) != len(entries) {
			hooks[event] = filtered
		}
	}

	for _, event := range cursorHookEvents {
		entries, ok := cursorHookEntryList(hooks[event])
		if !ok {
			return nil, fmt.Errorf("Cursor hooks event %q must be an array", event)
		}
		hooks[event] = append(entries, windowsCursorEnterpriseHookEntry(command))
	}
	return encodeCursorHooksJSON(cfg)
}

// VerifyWindowsCursorEnterpriseHooks validates exact writer/reader parity for
// the protected machine configuration while allowing unrelated hook entries.
func VerifyWindowsCursorEnterpriseHooks(existing []byte, adapterPath, failMode string) error {
	command, err := windowsCursorEnterpriseHookCommand(adapterPath)
	if err != nil {
		return err
	}
	if normalizeHookFailMode(failMode) != "closed" {
		return fmt.Errorf("Windows Cursor enterprise hooks must use fail mode closed")
	}
	cfg, err := decodeCursorHooksJSON(existing)
	if err != nil {
		return err
	}
	if err := requireCursorHooksVersionOne(cfg, false); err != nil {
		return err
	}
	hooks, err := cursorHooksObject(cfg, false)
	if err != nil {
		return err
	}

	for _, event := range cursorHookEvents {
		entries, ok := cursorHookEntryList(hooks[event])
		if !ok {
			return fmt.Errorf("Cursor hooks event %q must be an array", event)
		}
		owned := 0
		for _, raw := range entries {
			if cursorHookCommand(raw) != command {
				continue
			}
			owned++
			if !isExactWindowsCursorEnterpriseHookEntry(raw, command) {
				return fmt.Errorf("Cursor hooks event %q has a drifted DefenseClaw entry", event)
			}
		}
		if owned != 1 {
			return fmt.Errorf("Cursor hooks event %q has %d DefenseClaw entries, want exactly 1", event, owned)
		}
	}
	for event, raw := range hooks {
		if cursorHookEventManaged(event) {
			continue
		}
		entries, ok := cursorHookEntryList(raw)
		if !ok {
			continue
		}
		for _, entry := range entries {
			if cursorHookCommand(entry) == command {
				return fmt.Errorf("Cursor hooks event %q has an unexpected DefenseClaw entry", event)
			}
		}
	}
	return nil
}

// RemoveWindowsCursorEnterpriseHooks removes only entries whose command is the
// exact protected adapter invocation. Unrelated hooks and top-level settings
// remain untouched. If there is nothing to remove, the original bytes are
// returned unchanged.
func RemoveWindowsCursorEnterpriseHooks(existing []byte, adapterPath string) ([]byte, error) {
	command, err := windowsCursorEnterpriseHookCommand(adapterPath)
	if err != nil {
		return nil, err
	}
	cfg, err := decodeCursorHooksJSON(existing)
	if err != nil {
		return nil, err
	}
	hooks, err := cursorHooksObject(cfg, false)
	if err != nil {
		return nil, err
	}
	changed := false
	for event, raw := range hooks {
		entries, ok := cursorHookEntryList(raw)
		if !ok {
			continue
		}
		filtered := removeCursorHookCommand(entries, command)
		if len(filtered) == len(entries) {
			continue
		}
		changed = true
		if len(filtered) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = filtered
		}
	}
	if !changed {
		return append([]byte(nil), existing...), nil
	}
	return encodeCursorHooksJSON(cfg)
}

// WindowsCursorEnterpriseHooksSemanticallyEqual compares two hooks.json
// documents independent of whitespace, object key order, and equivalent JSON
// number spellings. Invalid JSON never compares equal.
func WindowsCursorEnterpriseHooksSemanticallyEqual(left, right []byte) bool {
	leftValue, err := decodeCursorJSONValue(left)
	if err != nil {
		return false
	}
	rightValue, err := decodeCursorJSONValue(right)
	if err != nil {
		return false
	}
	return cursorJSONValuesEqual(leftValue, rightValue)
}

// WindowsCursorEnterpriseHooksOwnedRemainderEqual compares a hooks document
// after DefenseClaw entries were removed with the protected pre-install
// document. It ignores only empty version-1 scaffolding that the merge had to
// create, including empty managed event arrays. All foreign values and any
// non-empty hook entry must still match exactly by JSON semantics.
func WindowsCursorEnterpriseHooksOwnedRemainderEqual(cleaned, original []byte) bool {
	cleanedConfig, err := decodeCursorHooksJSON(cleaned)
	if err != nil {
		return false
	}
	originalConfig, err := decodeCursorHooksJSON(original)
	if err != nil {
		return false
	}
	if !normalizeCursorOwnedRemainder(cleanedConfig) ||
		!normalizeCursorOwnedRemainder(originalConfig) {
		return false
	}
	return cursorJSONValuesEqual(cleanedConfig, originalConfig)
}

func normalizeCursorOwnedRemainder(config map[string]interface{}) bool {
	if rawVersion, exists := config["version"]; exists && rawVersion != nil {
		number, ok := rawVersion.(json.Number)
		if !ok {
			return false
		}
		version, err := number.Int64()
		if err != nil || version != 1 {
			return false
		}
		delete(config, "version")
	}

	rawHooks, exists := config["hooks"]
	if !exists || rawHooks == nil {
		delete(config, "hooks")
		return true
	}
	hooks, ok := rawHooks.(map[string]interface{})
	if !ok {
		return false
	}
	for _, event := range cursorHookEvents {
		entries, exists := hooks[event]
		if !exists {
			continue
		}
		if entries == nil {
			delete(hooks, event)
			continue
		}
		list, ok := entries.([]interface{})
		if !ok {
			return false
		}
		if len(list) == 0 {
			delete(hooks, event)
		}
	}
	if len(hooks) == 0 {
		delete(config, "hooks")
	}
	return true
}

// WindowsCursorEnterpriseHooksEmpty reports whether data is exactly the
// supported empty Cursor contract: version 1, an empty hooks object, and no
// unrelated top-level settings.
func WindowsCursorEnterpriseHooksEmpty(data []byte) bool {
	cfg, err := decodeCursorHooksJSON(data)
	if err != nil || len(cfg) != 2 {
		return false
	}
	version, ok := cfg["version"].(json.Number)
	if !ok {
		return false
	}
	versionNumber, err := version.Int64()
	if err != nil || versionNumber != 1 {
		return false
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	return ok && len(hooks) == 0
}

func windowsCursorEnterpriseHookCommand(adapterPath string) (string, error) {
	if err := validateAbsoluteLocalWindowsPath("Cursor enterprise adapter", adapterPath); err != nil {
		return "", err
	}
	return "& " + powershellQuoteLiteral(adapterPath), nil
}

func validateAbsoluteLocalWindowsPath(label, value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("%s path must be non-empty with no surrounding whitespace", label)
	}
	if len(value) > 32_767 {
		return fmt.Errorf("%s path exceeds the Windows path length limit", label)
	}
	for _, r := range value {
		if r < 0x20 || strings.ContainsRune(`<>"|?*/`, r) {
			return fmt.Errorf("%s path contains an invalid character", label)
		}
	}
	// Enterprise executables and policy adapters must live on a local drive.
	// Reject UNC/device paths and drive-relative forms. This check is explicit
	// rather than filepath.IsAbs so C:\ paths can be tested on Unix builders.
	if len(value) < 4 || !isASCIIAlpha(value[0]) || value[1] != ':' || value[2] != '\\' {
		return fmt.Errorf("%s path must be an absolute local Windows drive path", label)
	}
	for _, component := range strings.Split(value[3:], `\`) {
		if component == "" || component == "." || component == ".." ||
			strings.Contains(component, ":") || strings.HasSuffix(component, " ") ||
			strings.HasSuffix(component, ".") || isReservedWindowsPathComponent(component) {
			return fmt.Errorf("%s path is not canonical", label)
		}
	}
	return nil
}

func isReservedWindowsPathComponent(component string) bool {
	base := component
	if index := strings.IndexByte(base, '.'); index >= 0 {
		base = base[:index]
	}
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		return true
	}
	if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) &&
		base[3] >= '1' && base[3] <= '9' {
		return true
	}
	// Win32 also treats the superscript 1, 2, and 3 spellings as reserved
	// device names (for example COM¹ and LPT²).
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		suffix := strings.TrimPrefix(strings.TrimPrefix(base, "COM"), "LPT")
		return suffix == "¹" || suffix == "²" || suffix == "³"
	}
	return false
}

func isASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}

func decodeCursorHooksJSON(data []byte) (map[string]interface{}, error) {
	if len(data) > windowsCursorEnterpriseHooksJSONMax {
		return nil, fmt.Errorf("Cursor hooks JSON exceeds %d bytes", windowsCursorEnterpriseHooksJSONMax)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]interface{}{}, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var cfg map[string]interface{}
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse Cursor hooks JSON: %w", err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse Cursor hooks JSON: multiple JSON values")
		}
		return nil, fmt.Errorf("parse Cursor hooks JSON trailing data: %w", err)
	}
	if cfg == nil {
		return map[string]interface{}{}, nil
	}
	return cfg, nil
}

func decodeCursorJSONValue(data []byte) (interface{}, error) {
	if len(data) > windowsCursorEnterpriseHooksJSONMax {
		return nil, fmt.Errorf("Cursor hooks JSON exceeds %d bytes", windowsCursorEnterpriseHooksJSONMax)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("Cursor hooks JSON is empty")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("multiple JSON values")
		}
		return nil, err
	}
	return value, nil
}

func cursorJSONValuesEqual(left, right interface{}) bool {
	switch leftValue := left.(type) {
	case nil:
		return right == nil
	case bool:
		rightValue, ok := right.(bool)
		return ok && leftValue == rightValue
	case string:
		rightValue, ok := right.(string)
		return ok && leftValue == rightValue
	case json.Number:
		rightValue, ok := right.(json.Number)
		if !ok {
			return false
		}
		leftNumber, leftOK := new(big.Rat).SetString(leftValue.String())
		rightNumber, rightOK := new(big.Rat).SetString(rightValue.String())
		return leftOK && rightOK && leftNumber.Cmp(rightNumber) == 0
	case []interface{}:
		rightValue, ok := right.([]interface{})
		if !ok || len(leftValue) != len(rightValue) {
			return false
		}
		for index := range leftValue {
			if !cursorJSONValuesEqual(leftValue[index], rightValue[index]) {
				return false
			}
		}
		return true
	case map[string]interface{}:
		rightValue, ok := right.(map[string]interface{})
		if !ok || len(leftValue) != len(rightValue) {
			return false
		}
		for key, value := range leftValue {
			rightItem, exists := rightValue[key]
			if !exists || !cursorJSONValuesEqual(value, rightItem) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func encodeCursorHooksJSON(cfg map[string]interface{}) ([]byte, error) {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Cursor hooks JSON: %w", err)
	}
	return append(data, '\n'), nil
}

func requireCursorHooksVersionOne(cfg map[string]interface{}, create bool) error {
	raw, exists := cfg["version"]
	if !exists || raw == nil {
		if !create {
			return fmt.Errorf("Cursor hooks version is missing")
		}
		cfg["version"] = 1
		return nil
	}
	number, ok := raw.(json.Number)
	if !ok {
		return fmt.Errorf("Cursor hooks version must be the integer 1")
	}
	version, err := number.Int64()
	if err != nil || version != 1 {
		return fmt.Errorf("Cursor hooks version must be the integer 1")
	}
	cfg["version"] = 1
	return nil
}

func cursorHooksObject(cfg map[string]interface{}, create bool) (map[string]interface{}, error) {
	raw, exists := cfg["hooks"]
	if !exists || raw == nil {
		if !create {
			return map[string]interface{}{}, nil
		}
		hooks := map[string]interface{}{}
		cfg["hooks"] = hooks
		return hooks, nil
	}
	hooks, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("Cursor hooks must be a JSON object")
	}
	return hooks, nil
}

func cursorHookEntryList(raw interface{}) ([]interface{}, bool) {
	if raw == nil {
		return []interface{}{}, true
	}
	entries, ok := raw.([]interface{})
	return entries, ok
}

func windowsCursorEnterpriseHookEntry(command string) map[string]interface{} {
	return map[string]interface{}{
		"type":       "command",
		"command":    command,
		"timeout":    windowsCursorEnterpriseHookTimeoutSeconds,
		"failClosed": true,
	}
}

func removeCursorHookCommand(entries []interface{}, command string) []interface{} {
	filtered := make([]interface{}, 0, len(entries))
	for _, entry := range entries {
		if cursorHookCommand(entry) == command {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func cursorHookCommand(raw interface{}) string {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return ""
	}
	command, _ := entry["command"].(string)
	return strings.TrimSpace(command)
}

func isExactWindowsCursorEnterpriseHookEntry(raw interface{}, command string) bool {
	entry, ok := raw.(map[string]interface{})
	if !ok || len(entry) != 4 || cursorHookCommand(entry) != command {
		return false
	}
	typeName, _ := entry["type"].(string)
	failClosed, _ := entry["failClosed"].(bool)
	timeout, ok := entry["timeout"].(json.Number)
	if !ok {
		return false
	}
	timeoutSeconds, err := timeout.Int64()
	return err == nil && typeName == "command" && failClosed && timeoutSeconds == windowsCursorEnterpriseHookTimeoutSeconds
}

func cursorHookEventManaged(event string) bool {
	for _, candidate := range cursorHookEvents {
		if event == candidate {
			return true
		}
	}
	return false
}
