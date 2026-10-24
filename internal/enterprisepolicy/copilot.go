// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GitHub Copilot CLI loads machine-wide policy hooks from policy.d before
// every other source; users cannot disable them with disableAllHooks and
// they apply regardless of folder trust. There is no managed-only lock, so
// user and repository hooks still run (preToolUse can return modifiedArgs);
// the foreign-hook guard governs those. DefenseClaw owns one drop-in.
const copilotConnector = ConnectorCopilot

type copilotTarget struct{}

func (copilotTarget) Name() string { return copilotConnector }

func copilotDropInPath(opts Options) (string, error) {
	dir, err := CopilotPolicyDir(opts)
	if err != nil {
		return "", err
	}
	return joinFor(opts, dir, DefenseClawDropInName), nil
}

func (copilotTarget) Paths(opts Options) ([]string, error) {
	path, err := copilotDropInPath(opts)
	if err != nil {
		return nil, err
	}
	return []string{path}, nil
}

func copilotHandler(opts Options, event string, timeout int) *object {
	handler := newObject()
	handler.set("type", "command")
	if opts.goos() == "windows" {
		args := []string{"hook", "--connector", "copilot", "--enterprise-managed", "--event", event}
		// Copilot evaluates the powershell field itself. The awaited
		// statements keep the GUI-subsystem hook synchronous and return its
		// exit code, also when the hook exits at once.
		// The guard keeps a registration Copilot still holds after
		// uninstall inert (connector.CopilotRemovedDeploymentGuardPowerShell).
		handler.set("powershell", strings.Join(append([]string{
			"$ErrorActionPreference='Stop'",
			"$env:NoDefaultCurrentDirectoryInExePath='1'",
			connector.CopilotRemovedDeploymentGuardPowerShell(opts.HookBinary),
		}, connector.WindowsAwaitedHookStatements(opts.HookBinary, args)...), "; "))
	} else {
		handler.set("bash", connector.CopilotRemovedDeploymentGuardPOSIX(opts.HookBinary)+
			shellQuote(opts.HookBinary)+" hook --connector copilot --enterprise-managed --event "+shellQuote(event))
	}
	handler.set("timeoutSec", json.Number(fmt.Sprint(timeout)))
	return handler
}

func renderCopilotDropIn(opts Options) ([]byte, error) {
	groups, err := connector.ManagedHookGroupsForOS(copilotConnector, opts.agentVersion(copilotConnector), opts.goos())
	if err != nil {
		return nil, err
	}
	doc := newObject()
	doc.set("version", json.Number("1"))
	hooks := newObject()
	for _, group := range groups {
		hooks.set(group.Event, []any{copilotHandler(opts, group.Event, group.Timeout)})
	}
	doc.set("hooks", hooks)
	return encodeOrdered(doc)
}

func copilotHandlerIsOwned(opts Options, raw any) bool {
	field := "bash"
	if opts.goos() == "windows" {
		field = "powershell"
	}
	// The registered command identifies this entry even when other fields
	// were changed or added. Independent commands in separate entries stay.
	command := stringField(raw, field)
	if opts.goos() == "windows" {
		return strings.Contains(command, connector.PowerShellQuoteLiteral(opts.HookBinary)) &&
			strings.Contains(command, "'--enterprise-managed'") && strings.Contains(command, "'copilot'")
	}
	// A drop-in a 1.0 pre-release wrote has no removed-deployment guard;
	// ensure rewrites it.
	command = strings.TrimPrefix(command, connector.CopilotRemovedDeploymentGuardPOSIX(opts.HookBinary))
	return strings.HasPrefix(command, shellQuote(opts.HookBinary)+" hook --connector copilot --enterprise-managed --event ")
}

// copilotRecordedHandlerIsOwned recognizes a handler from an earlier binary
// path only inside a drop-in DefenseClaw has published. The exact command
// must match the old render, and a command present in the administrator's
// recorded preimage remains independent.
func copilotRecordedHandlerIsOwned(opts Options, record *ownershipRecord, path, event string, raw any) bool {
	if copilotHandlerIsOwned(opts, raw) {
		return true
	}
	if !publishedByRecord(record, path) {
		return false
	}
	field := "bash"
	if opts.goos() == "windows" {
		field = "powershell"
	}
	command := stringField(raw, field)
	oldBinary := copilotRecordedBinary(opts.goos(), command)
	if oldBinary == "" || oldBinary == opts.HookBinary || copilotPreimageHasCommand(record, event, field, command) {
		return false
	}
	previous := opts
	previous.HookBinary = oldBinary
	if err := previous.Validate(); err != nil {
		return false
	}
	expected := stringField(copilotHandler(previous, event, 0), field)
	if strings.HasPrefix(command, expected) {
		return true
	}
	if opts.goos() == "windows" {
		expected = strings.Replace(expected, connector.CopilotRemovedDeploymentGuardPowerShell(oldBinary)+"; ", "", 1)
	} else {
		expected = strings.TrimPrefix(expected, connector.CopilotRemovedDeploymentGuardPOSIX(oldBinary))
	}
	return strings.HasPrefix(command, expected)
}

func copilotRecordedBinary(goos, command string) string {
	if goos == "windows" {
		const start = "$hookStart=[System.Diagnostics.ProcessStartInfo]::new("
		_, tail, found := strings.Cut(command, start)
		if !found {
			return ""
		}
		return copilotQuotedBinary(tail)
	}
	const marker = " hook --connector copilot --enterprise-managed --event "
	before, _, found := strings.Cut(command, marker)
	if !found {
		return ""
	}
	if strings.HasPrefix(before, "[ -e ") {
		return copilotQuotedBinary(strings.TrimPrefix(before, "[ -e "))
	}
	return copilotQuotedBinary(before)
}

// HookBinary paths cannot contain quotes (Options.Validate). Both shell
// renderers start a path with one single-quoted literal.
func copilotQuotedBinary(text string) string {
	if !strings.HasPrefix(text, "'") {
		return ""
	}
	end := strings.IndexByte(text[1:], '\'')
	if end < 0 {
		return ""
	}
	return text[1 : end+1]
}

func copilotPreimageHasCommand(record *ownershipRecord, event, field, command string) bool {
	if !record.PreimageExisted {
		return false
	}
	doc, err := decodeOrderedObject(record.Preimage)
	if err != nil {
		return false
	}
	value, _ := doc.get("hooks")
	hooks, ok := value.(*object)
	if !ok {
		return false
	}
	value, _ = hooks.get(event)
	list, ok := value.([]any)
	if !ok {
		return false
	}
	for _, handler := range list {
		if stringField(handler, field) == command {
			return true
		}
	}
	return false
}

// copilotHandlerHasUnexpectedFields reports changes beyond the rendered
// contract fields in an entry identified by DefenseClaw's command path.
func copilotHandlerHasUnexpectedFields(opts Options, raw any) bool {
	field := "bash"
	if opts.goos() == "windows" {
		field = "powershell"
	}
	var keys []string
	switch value := raw.(type) {
	case *object:
		keys = value.keys
	case map[string]any:
		for key := range value {
			keys = append(keys, key)
		}
	default:
		return true
	}
	for _, key := range keys {
		if key != "type" && key != field && key != "timeoutSec" {
			return true
		}
	}
	return false
}

// copilotHandlerIsIntact reports a DefenseClaw handler whose command is the
// one DefenseClaw renders for event, byte for byte. Copilot runs the field
// through a shell, so the prefix match that identifies DefenseClaw's
// handler also accepted trailing shell text (a redirection and an || true
// fallback) that discards the hook's deny while verify reported coverage
// (GAP-1348).
func copilotHandlerIsIntact(opts Options, event string, raw any) bool {
	field := "bash"
	if opts.goos() == "windows" {
		field = "powershell"
	}
	return stringField(raw, "type") == "command" && stringField(raw, field) == stringField(copilotHandler(opts, event, 0), field)
}

// copilotHandlerTimeout returns the handler's timeoutSec as written, or ""
// when it is absent. Copilot lets the tool call proceed when a policy hook
// times out, so a shorter timeout than DefenseClaw publishes leaves calls
// unchecked while the command still matches (GAP-1406).
func copilotHandlerTimeout(raw any) string {
	var value any
	switch v := raw.(type) {
	case *object:
		value = v.values["timeoutSec"]
	case map[string]any:
		value = v["timeoutSec"]
	}
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func copilotHandlerTimeoutIsCurrent(raw any, want int) bool {
	var value any
	switch handler := raw.(type) {
	case *object:
		value, _ = handler.get("timeoutSec")
	case map[string]any:
		value = handler["timeoutSec"]
	}
	number, ok := value.(json.Number)
	return ok && number.String() == fmt.Sprint(want)
}

func inspectCopilot(opts Options, state *State) error {
	var record *ownershipRecord
	if opts.StateDir != "" {
		var err error
		record, err = loadRecord(opts, copilotConnector)
		if err != nil {
			return err
		}
	}
	dir, err := CopilotPolicyDir(opts)
	if err != nil {
		return err
	}
	groups, err := connector.ManagedHookGroupsForOS(copilotConnector, opts.agentVersion(copilotConnector), opts.goos())
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(platformPath(opts, dir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := validatePolicyLeafDir(opts, platformPath(opts, dir)); err != nil {
		state.conflict("%v; unprivileged users can add policy files there that Copilot may load for every user", err)
	}
	names := []string{}
	for _, entry := range entries {
		if effectivePolicyDropIn(entry) {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	ownedPerEvent := map[string]int{}
	timeouts := map[string]int{}
	for _, group := range groups {
		timeouts[group.Event] = group.Timeout
	}
	for _, name := range names {
		file := joinFor(opts, dir, name)
		data, exists, err := readPolicyFile(opts, file)
		if err != nil {
			// Copilot itself skips policy files that are not root-owned or
			// are group/world-writable, so an untrusted file is not in force.
			switch {
			case name == DefenseClawDropInName:
				state.conflict("%v; Copilot silently ignores policy files that are not root-owned or are group/world-writable", err)
			case opts.goos() == "windows":
				// Copilot's handling of policy files an unprivileged user
				// controls is only verified on unix; on Windows such a file
				// may run as machine policy for every user.
				state.conflict("%s is not administrator-controlled and Copilot may load it as a policy hook for every user; remove it: %v", file, err)
			default:
				state.detail("%s is not trusted and Copilot ignores it: %v", file, err)
			}
			continue
		}
		if !exists {
			continue
		}
		doc, err := decodeOrderedObject(data)
		if err != nil {
			state.conflict("%s is not valid JSON: %v", file, err)
			continue
		}
		hooksValue, _ := doc.get("hooks")
		hooks, _ := hooksValue.(*object)
		if hooks == nil {
			continue
		}
		for _, event := range hooks.keys {
			value, _ := hooks.get(event)
			list, ok := value.([]any)
			if !ok {
				if name == DefenseClawDropInName {
					state.entryConflict("%s: Copilot event %s is not a handler list", file, event)
				} else {
					state.conflict("%s: Copilot event %s is not a handler list and is outside DefenseClaw ownership; repair this policy source separately", file, event)
				}
				continue
			}
			for _, handler := range list {
				if name == DefenseClawDropInName && copilotRecordedHandlerIsOwned(opts, record, file, event, handler) {
					state.OwnedEntries++
					ownedPerEvent[event]++
					repair := "the next lifecycle run that applies changes (ensure, repair or reconcile) rewrites it"
					if copilotHandlerHasUnexpectedFields(opts, handler) {
						state.entryConflict("%s: the DefenseClaw policy hook for Copilot event %s has unexpected fields; %s", file, event, repair)
					}
					if !copilotHandlerIsIntact(opts, event, handler) {
						state.entryConflict("%s: the DefenseClaw policy hook for Copilot event %s is not the command DefenseClaw publishes, so it may not enforce; %s", file, event, repair)
					}
					if _, published := timeouts[event]; !published {
						// Intact compares the command with the one rendered
						// for this key, so a DefenseClaw command bound to an
						// event DefenseClaw does not publish (or to no
						// Copilot event at all) passed as intact.
						state.entryConflict("%s: a DefenseClaw policy hook is registered for Copilot event %q, which DefenseClaw does not publish; %s", file, event, repair)
					}
					if want, ok := timeouts[event]; ok && !copilotHandlerTimeoutIsCurrent(handler, want) {
						state.entryConflict("%s: the DefenseClaw policy hook for Copilot event %s has timeoutSec %q, DefenseClaw publishes %d; Copilot lets the tool call proceed when the hook times out, so deploy the exported value; %s", file, event, copilotHandlerTimeout(handler), want, repair)
					}
				} else {
					state.ForeignEntries++
				}
			}
		}
	}
	for _, group := range groups {
		if ownedPerEvent[group.Event] != 1 {
			state.entryConflict("Copilot event %s has %d DefenseClaw policy hooks, want exactly one", group.Event, ownedPerEvent[group.Event])
		}
	}
	state.detail("Copilot has no managed-only lock: user (~/.copilot), repository (.github/hooks) and Claude-format hooks still run and can return modifiedArgs; the foreign-hook guard applies")
	state.detail("residual: Copilot fails open when a command hook times out, including policy hooks")
	if opts.goos() == "windows" {
		state.detail(`Copilot also loads policy hooks from HKLM\Software\Policies\GitHub\Copilot\<subkey> (Policy); those administrator hooks run beside DefenseClaw's policy.d drop-in`)
	}
	return nil
}

func newCopilotState(policy config.ResolvedConnectorPolicy, paths []string) State {
	return State{
		Connector:    copilotConnector,
		Route:        RouteMachinePolicy,
		Ownership:    policy.Ownership,
		ForeignHooks: policy.ForeignHooks,
		Paths:        paths,
	}
}

func (t copilotTarget) Reconcile(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(copilotConnector)
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := newCopilotState(policy, paths)
	switch policy.Ownership {
	case config.MachinePolicyOwnershipOff:
		state.Route = RouteUnsupported
		return state, nil
	case config.MachinePolicyOwnershipMerge:
		created, err := takeBackPolicyPath(opts, paths[0], &state)
		if err != nil {
			return state, err
		}
		displaceUntrustedPolicyFiles(opts, platformPath(opts, dirFor(opts, paths[0])), DefenseClawDropInName, &state)
		current, exists, err := readPolicyFile(opts, paths[0])
		var untrusted *untrustedPolicyFileError
		if errors.As(err, &untrusted) && validateTrustedAncestors(opts, platformPath(opts, paths[0])) == nil {
			// DefenseClaw owns this drop-in name, and its directory is
			// trusted: a file there that an unprivileged principal controls is
			// neither DefenseClaw's nor the administrator's. Replace it.
			state.detail("replacing %s: %v", paths[0], untrusted.err)
			current, exists, err = nil, true, state.replaceUntrustedPolicyFile(opts, paths[0])
		}
		if err != nil {
			return state, err
		}
		record, err := loadRecord(opts, copilotConnector)
		if err != nil {
			return state, err
		}
		rendered, err := mergeCopilotDropInWithRecord(opts, current, record, paths[0])
		if err != nil {
			return state, fmt.Errorf("cannot merge Copilot policy without changing independent handlers in %s: %w", paths[0], err)
		}
		changed, err := publishWithRecord(opts, copilotConnector, paths[0], current, exists, rendered, exists && bytes.Equal(current, rendered), copilotStripWithRecord(opts, record, paths[0]), &state, created...)
		if err != nil {
			return state, err
		}
		state.Changed = changed
	}
	if err := copilotEditorPolicy(opts, &state, policy.Ownership == config.MachinePolicyOwnershipMerge); err != nil {
		return state, err
	}
	if err := inspectCopilot(opts, &state); err != nil {
		return state, err
	}
	if policy.Ownership == config.MachinePolicyOwnershipVerifyOnly && state.OwnedEntries == 0 {
		state.detail("missing_defenseclaw_hooks: deploy the output of `defenseclaw-gateway enterprise policy export --connector copilot` through your policy tool")
	}
	state.finish()
	return state, nil
}

func (t copilotTarget) Verify(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(copilotConnector)
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := newCopilotState(policy, paths)
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		return state, nil
	}
	verifyWindowsHookExecutable(opts, "Copilot", &state)
	if err := copilotEditorPolicy(opts, &state, false); err != nil {
		return state, err
	}
	if err := inspectCopilot(opts, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

// copilotEditorPolicy reconciles (write) or inspects the VS Code device
// policies and Copilot managed settings that govern Copilot in VS Code, and
// reports the VS Code status. A CLI-only policy (opts.CopilotCLIPolicyOnly)
// has none.
func copilotEditorPolicy(opts Options, state *State, write bool) error {
	if opts.CopilotCLIPolicyOnly {
		return nil
	}
	if err := vscodeDevicePolicy(opts, state, write); err != nil {
		return err
	}
	if err := copilotManagedSettings(opts, state, write); err != nil {
		return err
	}
	if write {
		// The guardian removes old per-user files after policy publication.
		// Verify and status report them until that pass completes.
		opts.CopilotOutOfScopeHomes = nil
	}
	copilotVSCodeStatus(opts, state)
	return nil
}

func (t copilotTarget) RemoveOwned(opts Options) (State, error) {
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := State{Connector: copilotConnector, Route: RouteMachinePolicy, Paths: paths}
	record, err := loadRecord(opts, copilotConnector)
	if err != nil {
		return state, err
	}
	err = restoreOrStrip(opts, copilotConnector, paths[0], copilotStripWithRecord(opts, record, paths[0]), true, &state)
	return state, errors.Join(err, removeVSCodeDevicePolicy(opts, &state), removeCopilotManagedSettings(opts, &state))
}

// copilotStrip removes DefenseClaw's handlers within its drop-in. An
// administrator can add independent handlers to the same event or another
// event; uninstall and the next reconcile must retain them.
func copilotStrip(opts Options) stripFunc {
	return copilotStripWithRecord(opts, nil, "")
}

func copilotStripWithRecord(opts Options, record *ownershipRecord, path string) stripFunc {
	return func(current []byte) ([]byte, bool, error) {
		if len(bytes.TrimSpace(current)) == 0 {
			return current, false, nil
		}
		doc, err := decodeOrderedObject(current)
		if err != nil {
			// No handler can be recognized in malformed JSON. A first
			// publication keeps these original bytes; later damage must not
			// replace the recorded administrator preimage.
			return current, false, nil
		}
		hooksValue, _ := doc.get("hooks")
		hooks, _ := hooksValue.(*object)
		if hooks == nil {
			return current, false, nil
		}
		owned := false
		for _, event := range append([]string(nil), hooks.keys...) {
			value, _ := hooks.get(event)
			list, ok := value.([]any)
			if !ok {
				continue
			}
			remaining := make([]any, 0, len(list))
			for _, handler := range list {
				if copilotRecordedHandlerIsOwned(opts, record, path, event, handler) {
					owned = true
					continue
				}
				remaining = append(remaining, handler)
			}
			if len(remaining) == 0 && len(list) > 0 {
				hooks.delete(event)
			} else if len(remaining) != len(list) {
				hooks.set(event, remaining)
			}
		}
		if !owned {
			return current, false, nil
		}
		if hooks.len() == 0 {
			doc.delete("hooks")
		}
		if doc.len() == 0 || (doc.len() == 1 && doc.keys[0] == "version") {
			return nil, true, nil
		}
		admin, err := encodeOrdered(doc)
		return admin, true, err
	}
}

// copilotPostPublicationMalformed distinguishes a broken published drop-in
// from parseable administrator edits when updating the removal preimage.
func copilotPostPublicationMalformed(current []byte) bool {
	if len(bytes.TrimSpace(current)) == 0 {
		return true
	}
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return true
	}
	value, present := doc.get("hooks")
	if !present {
		return false
	}
	hooks, ok := value.(*object)
	if !ok {
		return true
	}
	for _, event := range hooks.keys {
		value, _ := hooks.get(event)
		if _, ok := value.([]any); !ok {
			return true
		}
	}
	return false
}

func mergeCopilotDropIn(opts Options, current []byte) ([]byte, error) {
	return mergeCopilotDropInWithRecord(opts, current, nil, "")
}

func mergeCopilotDropInWithRecord(opts Options, current []byte, record *ownershipRecord, path string) ([]byte, error) {
	rendered, err := renderCopilotDropIn(opts)
	if err != nil || len(bytes.TrimSpace(current)) == 0 {
		return rendered, err
	}
	_, err = decodeOrderedObject(current)
	if err != nil {
		// This is DefenseClaw's own drop-in, with no parseable handler to
		// retain. An existing publication record keeps its earlier preimage.
		return rendered, nil
	}
	admin, _, err := copilotStripWithRecord(opts, record, path)(current)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(admin)) == 0 {
		return rendered, nil
	}
	doc, err := decodeOrderedObject(admin)
	if err != nil {
		return nil, err
	}
	want, err := decodeOrderedObject(rendered)
	if err != nil {
		return nil, err
	}
	doc.set("version", json.Number("1"))
	wantValue, _ := want.get("hooks")
	wantHooks := wantValue.(*object)
	value, present := doc.get("hooks")
	hooks, ok := value.(*object)
	if present && value != nil && !ok {
		// A non-object cannot hold any handler. Keep independent keys at
		// the document root while restoring the rendered hooks.
		doc.set("hooks", wantHooks)
		return encodeOrdered(doc)
	}
	if !present || value == nil {
		hooks = newObject()
		doc.set("hooks", hooks)
	}
	invalidEvent := ""
	hasHandlerEntries := false
	for _, event := range hooks.keys {
		value, _ := hooks.get(event)
		list, ok := value.([]any)
		if !ok && invalidEvent == "" {
			invalidEvent = event
		}
		if ok && len(list) > 0 {
			hasHandlerEntries = true
		}
	}
	if invalidEvent != "" {
		if hasHandlerEntries {
			return nil, fmt.Errorf("event %s is not a handler list", invalidEvent)
		}
		doc.set("hooks", wantHooks)
		return encodeOrdered(doc)
	}
	for _, event := range wantHooks.keys {
		value, _ := wantHooks.get(event)
		currentValue, present := hooks.get(event)
		if !present {
			hooks.set(event, value)
			continue
		}
		list := currentValue.([]any)
		hooks.set(event, append(list, value.([]any)...))
	}
	return encodeOrdered(doc)
}

func (copilotTarget) Export(opts Options, format string) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if format != "" && format != "json" {
		return nil, fmt.Errorf("copilot policy export supports format json, not %q", format)
	}
	return renderCopilotDropIn(opts)
}
