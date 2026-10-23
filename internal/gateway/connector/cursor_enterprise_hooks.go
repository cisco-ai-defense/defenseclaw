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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
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

// cursorEnterpriseRetiredHookEvents are events earlier releases registered in
// the Windows machine policy (C:\ProgramData\Cursor\hooks.json) and this
// release no longer does. The Cursor Agent CLI fires afterAgentThought once
// per streamed reasoning chunk and awaits each command hook before it reads
// the next chunk. A machine hook is a Windows PowerShell process (about 1.2 s
// per call), so the CLI stalls its model stream until the server drops it
// ("Connection lost ... WritableIterable is closed"). The event is
// observe-only for DefenseClaw and afterAgentResponse already carries the
// model output, so the machine policy omits it. The gateway still decodes an
// incoming afterAgentThought, and the user-level (OSS) hooks.json keeps the
// full cursorHookEvents roster.
//
// Merge removes DefenseClaw's entry from a retired event (and drops the event
// key when nothing else remains), migration verification accepts one exact
// entry there so a pre-upgrade policy stays callable until it is repaired, and
// strict verification rejects it so reconcile always rewrites the file.
var cursorEnterpriseRetiredHookEvents = []string{"afterAgentThought"}

// cursorEnterpriseHookEvents is the roster the Windows machine policy
// registers: cursorHookEvents minus cursorEnterpriseRetiredHookEvents, in the
// same order.
var cursorEnterpriseHookEvents = cursorHookEventsExcept(cursorEnterpriseRetiredHookEvents)

func cursorHookEventsExcept(retired []string) []string {
	out := make([]string, 0, len(cursorHookEvents))
	for _, event := range cursorHookEvents {
		keep := true
		for _, candidate := range retired {
			if event == candidate {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, event)
		}
	}
	return out
}

const (
	windowsCursorEnterpriseHookTimeoutSeconds = 30
	windowsCursorEnterpriseHooksJSONMax       = 4 << 20
	windowsCursorTargetModesJSON64Max         = 256 << 10
)

// IsBuiltinCursorConnector reports whether conn is the package's concrete
// Cursor connector. The concrete type is intentionally unexported: privileged
// enterprise callers can certify the built-in implementation without
// accepting an arbitrary Connector that merely returns the name "cursor".
func IsBuiltinCursorConnector(conn Connector) bool {
	cursor, ok := conn.(*hookOnlyConnector)
	return ok && cursor != nil && cursor.name == "cursor"
}

// IsBuiltinHookOnlyConnector reports whether conn is the built-in hook-only
// implementation registered under name. Enterprise guardians use it as a
// concrete-type allowlist: a plugin connector can claim a built-in name.
func IsBuiltinHookOnlyConnector(conn Connector, name string) bool {
	builtin, ok := conn.(*hookOnlyConnector)
	return ok && builtin != nil && builtin.name == name
}

// IsBuiltinAMPConnector reports whether conn is the built-in Amp connector.
func IsBuiltinAMPConnector(conn Connector) bool {
	amp, ok := conn.(*AMPConnector)
	return ok && amp != nil && amp.hookOnlyConnector != nil && amp.name == "amp"
}

// RenderWindowsCursorEnterpriseAdapter renders the shared, token-free adapter
// installed in Cursor's protected machine hook directory. Managed enterprise
// delivery policy is selected by the administrator-owned installation state.
func RenderWindowsCursorEnterpriseAdapter(hookBinary, failMode string) ([]byte, error) {
	if err := validateAbsoluteLocalWindowsPath("Cursor hook executable", hookBinary); err != nil {
		return nil, err
	}
	return renderWindowsCursorAdapter(hookBinary, normalizeHookFailMode(failMode), true, cursorAdapterTimeoutMS)
}

func renderWindowsCursorAdapter(hookBinary, failMode string, managed bool, timeoutMS int) ([]byte, error) {
	return renderWindowsCursorAdapterWithTargets(hookBinary, failMode, managed, timeoutMS, "")
}

// RenderWindowsCursorEnterpriseAdapterForTargets selects delivery fallback by
// process SID, not by the last user to reconcile the singleton machine policy.
func RenderWindowsCursorEnterpriseAdapterForTargets(hookBinary string, modes map[string]string) ([]byte, error) {
	if err := validateAbsoluteLocalWindowsPath("Cursor hook executable", hookBinary); err != nil {
		return nil, err
	}
	if len(modes) == 0 || len(modes) > 1024 {
		return nil, errors.New("cursor adapter requires a bounded target mode map")
	}
	for sid, mode := range modes {
		if len(sid) > 184 || !windowsCursorAdapterSIDPattern.MatchString(sid) || (mode != "open" && mode != "closed") {
			return nil, errors.New("cursor adapter has an invalid target mode")
		}
	}
	body, err := json.Marshal(modes)
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(body)
	if len(encoded) > windowsCursorTargetModesJSON64Max {
		return nil, errors.New("cursor target mode map exceeds size limit")
	}
	return renderWindowsCursorAdapterWithTargets(hookBinary, "closed", true, cursorAdapterTimeoutMS, encoded)
}

var windowsCursorAdapterSIDPattern = regexp.MustCompile(`^S-[0-9]+(?:-[0-9]+)+$`)
var windowsCursorAdapterModesPattern = regexp.MustCompile(`(?m)^        \$targetModesJSON64 = '([A-Za-z0-9+/=]+)'\r?$`)

// WindowsCursorEnterpriseAdapterTargetModes recognizes only exact canonical
// mapped adapters. Used to authenticate partial publication rollback before
// its protected state file exists; it does not accept arbitrary script bodies.
func WindowsCursorEnterpriseAdapterTargetModes(adapter []byte, hookBinary string) (map[string]string, error) {
	if len(adapter) > 1<<20 {
		return nil, errors.New("cursor adapter exceeds size limit")
	}
	match := windowsCursorAdapterModesPattern.FindSubmatch(adapter)
	if len(match) != 2 || len(match[1]) > windowsCursorTargetModesJSON64Max {
		return nil, errors.New("cursor adapter has no bounded target mode map")
	}
	body, err := base64.StdEncoding.DecodeString(string(match[1]))
	if err != nil {
		return nil, err
	}
	var modes map[string]string
	if err := json.Unmarshal(body, &modes); err != nil {
		return nil, err
	}
	expected, err := RenderWindowsCursorEnterpriseAdapterForTargets(hookBinary, modes)
	if err != nil || !bytes.Equal(expected, adapter) {
		return nil, errors.New("cursor mapped adapter identity changed")
	}
	return modes, nil
}

func renderWindowsCursorAdapterWithTargets(hookBinary, failMode string, managed bool, timeoutMS int, targetModesJSON64 string) ([]byte, error) {
	if strings.TrimSpace(hookBinary) == "" {
		return nil, fmt.Errorf("Cursor hook executable is empty") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	if timeoutMS <= 0 {
		return nil, fmt.Errorf("Cursor hook adapter timeout must be positive") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	tmpl, err := hookFS.ReadFile("hooks/cursor-hook.ps1")
	if err != nil {
		return nil, fmt.Errorf("read Cursor adapter template: %w", err)
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		FailMode:                normalizeHookFailMode(failMode),
		Managed:                 managed,
		HookBinaryPS:            strings.ReplaceAll(hookBinary, "'", "''"),
		HookTimeoutMS:           timeoutMS,
		CursorTargetModesJSON64: targetModesJSON64,
	})
	if err != nil {
		return nil, fmt.Errorf("render Cursor adapter template: %w", err)
	}
	return []byte(rendered), nil
}

// MergeWindowsCursorEnterpriseHooks returns a Cursor hooks.json containing
// exactly one DefenseClaw entry for every machine-policy event
// (cursorEnterpriseHookEvents) and none on any other event, including a
// retired one an earlier release registered. Existing unrelated
// top-level fields, hook events, and hook entries retain their JSON semantics
// and order. The failMode argument is retained for the caller's outage-policy
// parity; the host flag always closes an unanswered hook outside Secure Client.
func MergeWindowsCursorEnterpriseHooks(existing []byte, adapterPath, _ string) ([]byte, error) {
	command, legacyCommand, err := windowsCursorEnterpriseHookCommands(adapterPath)
	if err != nil {
		return nil, err
	}
	previousEncodedCommand := previousWindowsCursorEnterpriseHookCommand(adapterPath)
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
				return nil, fmt.Errorf("Cursor hooks event %q must be an array", event) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
			}
			continue
		}
		filtered := removeCursorHookCommands(entries, command, legacyCommand, previousEncodedCommand)
		if len(filtered) == len(entries) {
			continue
		}
		if len(filtered) == 0 && !cursorHookEventManaged(event) {
			// An event this release no longer registers (afterAgentThought)
			// held only DefenseClaw's entry: drop the key, as removal does,
			// so teardown restores the pre-install document exactly.
			delete(hooks, event)
			continue
		}
		hooks[event] = filtered
	}

	for _, event := range cursorEnterpriseHookEvents {
		entries, ok := cursorHookEntryList(hooks[event])
		if !ok {
			return nil, fmt.Errorf("Cursor hooks event %q must be an array", event) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		hooks[event] = append(entries, windowsCursorEnterpriseHookEntry(command))
	}
	return encodeCursorHooksJSON(cfg)
}

// VerifyWindowsCursorEnterpriseHooks validates exact writer/reader parity for
// the protected machine configuration while allowing unrelated hook entries.
// A DefenseClaw entry on a retired event (afterAgentThought) fails it, so a
// reconcile treats a pre-upgrade policy as needing a rewrite.
func VerifyWindowsCursorEnterpriseHooks(existing []byte, adapterPath, failMode string) error {
	return verifyWindowsCursorEnterpriseHooks(existing, adapterPath, failMode, false, false)
}

// VerifyWindowsCursorEnterpriseHooksForMigration accepts the exact encoded
// command written by the immediately preceding release, and one exact
// DefenseClaw entry on an event this release retired, while reading a
// protected policy before upgrade or restoring a journaled one. New policies
// use strict verification.
func VerifyWindowsCursorEnterpriseHooksForMigration(existing []byte, adapterPath, failMode string) error {
	return verifyWindowsCursorEnterpriseHooks(existing, adapterPath, failMode, true, true)
}

// VerifyWindowsCursorEnterpriseHooksRegistered reports whether the current
// command is registered on every machine-policy event, accepting a
// not-yet-repaired DefenseClaw entry on a retired event. Presence checks use
// it: a pre-upgrade policy is still DefenseClaw's installed registration.
func VerifyWindowsCursorEnterpriseHooksRegistered(existing []byte, adapterPath, failMode string) error {
	return verifyWindowsCursorEnterpriseHooks(existing, adapterPath, failMode, false, true)
}

func verifyWindowsCursorEnterpriseHooks(existing []byte, adapterPath, failMode string, allowPrevious, allowRetired bool) error {
	command, legacyCommand, err := windowsCursorEnterpriseHookCommands(adapterPath)
	if err != nil {
		return err
	}
	previousEncodedCommand := previousWindowsCursorEnterpriseHookCommand(adapterPath)
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

	selectedCommand := ""
	countOwned := func(event string, entries []interface{}) (int, error) {
		owned := 0
		for _, raw := range entries {
			entryCommand := cursorHookCommand(raw)
			if entryCommand == legacyCommand {
				return 0, fmt.Errorf("cursor hooks event %q still has the legacy PowerShell-only DefenseClaw command", event)
			}
			if entryCommand == previousEncodedCommand && !allowPrevious {
				return 0, fmt.Errorf("cursor hooks event %q still has the previous encoded DefenseClaw command", event)
			}
			if entryCommand != command && (!allowPrevious || entryCommand != previousEncodedCommand) {
				continue
			}
			owned++
			if !isExactWindowsCursorEnterpriseHookEntry(raw, entryCommand,
				allowPrevious && normalizeHookFailMode(failMode) == "open") {
				return 0, fmt.Errorf("cursor hooks event %q has a drifted DefenseClaw entry", event)
			}
			if selectedCommand != "" && selectedCommand != entryCommand {
				return 0, fmt.Errorf("cursor hooks event %q mixes DefenseClaw command versions", event)
			}
			selectedCommand = entryCommand
		}
		return owned, nil
	}
	for _, event := range cursorEnterpriseHookEvents {
		entries, ok := cursorHookEntryList(hooks[event])
		if !ok {
			return fmt.Errorf("cursor hooks event %q must be an array", event)
		}
		owned, err := countOwned(event, entries)
		if err != nil {
			return err
		}
		if owned != 1 {
			return fmt.Errorf("Cursor hooks event %q has %d DefenseClaw entries, want exactly 1", event, owned) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
	}
	if allowRetired {
		// A policy written before the event was retired carries one exact
		// entry there; the next merge removes it.
		for _, event := range cursorEnterpriseRetiredHookEvents {
			entries, ok := cursorHookEntryList(hooks[event])
			if !ok {
				continue // foreign shape; the unexpected-entry scan below skips it too
			}
			owned, err := countOwned(event, entries)
			if err != nil {
				return err
			}
			if owned > 1 {
				return fmt.Errorf("cursor hooks event %q has %d DefenseClaw entries, want at most 1", event, owned)
			}
		}
	}
	for event, raw := range hooks {
		if cursorHookEventManaged(event) || (allowRetired && cursorEnterpriseHookEventRetired(event)) {
			continue
		}
		entries, ok := cursorHookEntryList(raw)
		if !ok {
			continue
		}
		for _, entry := range entries {
			entryCommand := cursorHookCommand(entry)
			if entryCommand == command || entryCommand == legacyCommand || entryCommand == previousEncodedCommand {
				if cursorEnterpriseHookEventRetired(event) {
					return fmt.Errorf("cursor hooks event %q still has the DefenseClaw entry an earlier release registered; this release no longer registers it and the next publish removes it", event)
				}
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
	command, legacyCommand, err := windowsCursorEnterpriseHookCommands(adapterPath)
	if err != nil {
		return nil, err
	}
	previousEncodedCommand := previousWindowsCursorEnterpriseHookCommand(adapterPath)
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
		filtered := removeCursorHookCommands(entries, command, legacyCommand, previousEncodedCommand)
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
	// cursorHookEvents is the superset of the machine-policy roster and the
	// retired events, so empty scaffolding an earlier release created for
	// afterAgentThought is ignored too.
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

// windowsCursorEnterpriseHookCommands returns the shell-neutral command this
// build writes plus the legacy PowerShell-only command that earlier builds
// wrote. Merge, verify, and remove all need both so a protected installation
// can be migrated without disturbing unrelated Cursor hooks.
func windowsCursorEnterpriseHookCommands(adapterPath string) (string, string, error) {
	if err := validateAbsoluteLocalWindowsPath("Cursor enterprise adapter", adapterPath); err != nil {
		return "", "", err
	}
	// Cursor can evaluate Windows command hooks through either PowerShell or
	// Git Bash. Keep the outer command free of shell metacharacters, and encode
	// the PowerShell wrapper so adapter paths cannot be reinterpreted by either
	// host. Windows PowerShell decodes $input before an encoded command can set
	// Console.InputEncoding, so reading $input would corrupt non-ASCII Cursor
	// JSON on machines whose OEM code page is not UTF-8. Read the inherited
	// standard-input stream as strict UTF-8 instead. Remove a leading UTF-8 BOM
	// when present. An outer Windows PowerShell host can also consume the first
	// opening brace before the child reads stdin; restore it only when the next
	// character begins a JSON object key. The gateway still validates the JSON.
	powerShell := strings.ReplaceAll(windowsSystemPowerShellExe(), `\`, "/")
	script := "$reader=[IO.StreamReader]::new([Console]::OpenStandardInput()," +
		"[Text.UTF8Encoding]::new($false,$true),$false);" +
		"try{$payload=$reader.ReadToEnd()}finally{$reader.Dispose()};" +
		"if($payload.StartsWith([string][char]0xFEFF)){$payload=$payload.Substring(1)};" +
		"if($payload.TrimStart().StartsWith([string][char]0x22)){$payload=([string][char]0x7B)+$payload};" +
		"$payload | & " + powershellQuoteLiteral(adapterPath)
	command := powerShell + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + powershellEncodedCommand(script)
	legacyCommand := "& " + powershellQuoteLiteral(adapterPath)
	return command, legacyCommand, nil
}

// previousWindowsCursorEnterpriseHookCommand reconstructs the exact
// shell-neutral command installed before leading UTF-8 BOM handling was added.
// It is recognized only for protected-policy migration and removal.
func previousWindowsCursorEnterpriseHookCommand(adapterPath string) string {
	powerShell := strings.ReplaceAll(windowsSystemPowerShellExe(), `\`, "/")
	script := "$reader=[IO.StreamReader]::new([Console]::OpenStandardInput()," +
		"[Text.UTF8Encoding]::new($false,$true),$false);" +
		"try{$payload=$reader.ReadToEnd()}finally{$reader.Dispose()};" +
		"$payload | & " + powershellQuoteLiteral(adapterPath)
	return powerShell + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + powershellEncodedCommand(script)
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
		return nil, fmt.Errorf("Cursor hooks JSON exceeds %d bytes", windowsCursorEnterpriseHooksJSONMax) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
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
		return nil, fmt.Errorf("Cursor hooks JSON exceeds %d bytes", windowsCursorEnterpriseHooksJSONMax) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("Cursor hooks JSON is empty") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
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
			return fmt.Errorf("Cursor hooks version is missing") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		cfg["version"] = 1
		return nil
	}
	number, ok := raw.(json.Number)
	if !ok {
		return fmt.Errorf("Cursor hooks version must be the integer 1") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	version, err := number.Int64()
	if err != nil || version != 1 {
		return fmt.Errorf("Cursor hooks version must be the integer 1") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
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
		return nil, fmt.Errorf("Cursor hooks must be a JSON object") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
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

// removeCursorHookCommands drops the hook entries whose command exactly matches
// one of the DefenseClaw-owned commands. Matching is exact so an operator's own
// entry that merely mentions the adapter path is preserved.
func removeCursorHookCommands(entries []interface{}, commands ...string) []interface{} {
	owned := make(map[string]struct{}, len(commands))
	for _, command := range commands {
		owned[command] = struct{}{}
	}
	filtered := make([]interface{}, 0, len(entries))
	for _, entry := range entries {
		if _, ok := owned[cursorHookCommand(entry)]; ok {
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

func isExactWindowsCursorEnterpriseHookEntry(raw interface{}, command string, allowLegacyOpen bool) bool {
	entry, ok := raw.(map[string]interface{})
	if !ok || len(entry) != 4 || cursorHookCommand(entry) != command {
		return false
	}
	typeName, _ := entry["type"].(string)
	failClosed, validFailMode := entry["failClosed"].(bool)
	timeout, ok := entry["timeout"].(json.Number)
	if !ok {
		return false
	}
	timeoutSeconds, err := timeout.Int64()
	return err == nil && typeName == "command" && validFailMode && (failClosed || allowLegacyOpen) && timeoutSeconds == windowsCursorEnterpriseHookTimeoutSeconds
}

// cursorHookEventManaged reports whether the Windows machine policy registers
// event.
func cursorHookEventManaged(event string) bool {
	for _, candidate := range cursorEnterpriseHookEvents {
		if event == candidate {
			return true
		}
	}
	return false
}

func cursorEnterpriseHookEventRetired(event string) bool {
	for _, candidate := range cursorEnterpriseRetiredHookEvents {
		if event == candidate {
			return true
		}
	}
	return false
}
