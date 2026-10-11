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
	"encoding/json"
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Cursor runs hooks from every source (enterprise, team, project, user) and
// merges permissions with deny winning, so it has no managed-only lock:
// foreign preToolUse hooks can still rewrite input (updated_input). The
// enterprise hooks.json is one shared administrator file; DefenseClaw
// merges exactly one entry per event and preserves every other key, event
// and entry in order.
const (
	cursorConnector          = ConnectorCursor
	cursorWindowsAdapterName = "defenseclaw-hook.ps1"
)

type cursorTarget struct{}

func (cursorTarget) Name() string { return cursorConnector }

func (cursorTarget) Paths(opts Options) ([]string, error) {
	path, err := CursorEnterpriseHooksPath(opts)
	if err != nil {
		return nil, err
	}
	paths := []string{path}
	if opts.goos() == "windows" {
		paths = append(paths, joinFor(opts, dirFor(opts, path), cursorWindowsAdapterName))
	}
	return paths, nil
}

func cursorCommand(opts Options) string {
	return shellQuote(opts.HookBinary) + " hook --connector cursor --enterprise-managed"
}

func cursorEntry(opts Options, group connector.ManagedHookGroup) *object {
	entry := newObject()
	entry.set("type", "command")
	entry.set("command", cursorCommand(opts))
	entry.set("timeout", json.Number(fmt.Sprint(group.Timeout)))
	entry.set("failClosed", true)
	return entry
}

func cursorEntryIsOwned(opts Options, raw any) bool {
	return stringField(raw, "command") == cursorCommand(opts)
}

// mergeCursorHooks returns the merged document and whether DefenseClaw's
// entries were already exactly present.
func mergeCursorHooks(opts Options, current []byte) ([]byte, bool, error) {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return nil, false, fmt.Errorf("parse Cursor enterprise hooks: %w", err)
	}
	if version, ok := doc.get("version"); ok {
		if number, isNumber := version.(json.Number); !isNumber || number.String() != "1" {
			return nil, false, fmt.Errorf("Cursor enterprise hooks version %v is not supported", version)
		}
	} else {
		doc.set("version", json.Number("1"))
	}
	hooksValue, _ := doc.get("hooks")
	hooks, ok := hooksValue.(*object)
	if hooksValue != nil && !ok {
		return nil, false, fmt.Errorf("Cursor enterprise hooks field has unsupported type %T", hooksValue)
	}
	if hooks == nil {
		hooks = newObject()
	}
	groups, err := connector.ManagedHookGroupsForOS(cursorConnector, opts.agentVersion(cursorConnector), opts.goos())
	if err != nil {
		return nil, false, err
	}
	alreadyExact := true
	for _, group := range groups {
		existing, _ := hooks.get(group.Event)
		list, _ := existing.([]any)
		if existing != nil && list == nil {
			return nil, false, fmt.Errorf("Cursor enterprise hooks.%s has unsupported type %T", group.Event, existing)
		}
		want := cursorEntry(opts, group)
		kept := make([]any, 0, len(list)+1)
		found := false
		for _, item := range list {
			if cursorEntryIsOwned(opts, item) {
				if !found && string(canonicalJSON(item)) == string(canonicalJSON(want)) {
					kept = append(kept, item)
					found = true
					continue
				}
				alreadyExact = false
				continue
			}
			kept = append(kept, item)
		}
		if !found {
			kept = append(kept, want)
			alreadyExact = false
		}
		hooks.set(group.Event, kept)
	}
	doc.set("hooks", hooks)
	rendered, err := encodeOrdered(doc)
	return rendered, alreadyExact, err
}

// stripCursorHooks is the ownership stripFunc for the enterprise
// hooks.json: it removes DefenseClaw's entries and returns an administrator
// file without them untouched (no re-indenting or re-escaping).
func stripCursorHooks(opts Options, current []byte) ([]byte, bool, error) {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return nil, false, err
	}
	hooksValue, _ := doc.get("hooks")
	hooks, _ := hooksValue.(*object)
	owned := false
	if hooks != nil {
		for _, event := range append([]string(nil), hooks.keys...) {
			value, _ := hooks.get(event)
			list, _ := value.([]any)
			kept := make([]any, 0, len(list))
			for _, item := range list {
				if !cursorEntryIsOwned(opts, item) {
					kept = append(kept, item)
				}
			}
			if len(kept) == len(list) {
				continue
			}
			owned = true
			if len(kept) == 0 {
				hooks.delete(event)
			} else {
				hooks.set(event, kept)
			}
		}
	}
	if !owned {
		return current, false, nil
	}
	if hooks.len() == 0 {
		// Only DefenseClaw's content (plus the version marker) remained.
		onlyVersion := true
		for _, key := range doc.keys {
			if key != "version" && key != "hooks" {
				onlyVersion = false
			}
		}
		if onlyVersion {
			return nil, true, nil
		}
	}
	rendered, err := encodeOrdered(doc)
	return rendered, true, err
}

func inspectCursor(opts Options, current []byte, state *State) error {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return fmt.Errorf("parse Cursor enterprise hooks: %w", err)
	}
	groups, err := connector.ManagedHookGroupsForOS(cursorConnector, opts.agentVersion(cursorConnector), opts.goos())
	if err != nil {
		return err
	}
	hooksValue, _ := doc.get("hooks")
	hooks, _ := hooksValue.(*object)
	owned, foreign := 0, 0
	if hooks != nil {
		for _, event := range hooks.keys {
			value, _ := hooks.get(event)
			list, _ := value.([]any)
			for _, item := range list {
				if cursorEntryIsOwned(opts, item) {
					owned++
				} else {
					foreign++
				}
			}
		}
	}
	for _, group := range groups {
		count := 0
		if hooks != nil {
			value, _ := hooks.get(group.Event)
			list, _ := value.([]any)
			for _, item := range list {
				if cursorEntryIsOwned(opts, item) {
					count++
					if closed, ok := boolField(item, "failClosed"); !ok || !closed {
						state.conflict("Cursor %s DefenseClaw hook is not failClosed", group.Event)
					}
				}
			}
		}
		if count != 1 {
			state.entryConflict("Cursor event %s has %d DefenseClaw enterprise hooks, want exactly one", group.Event, count)
		}
	}
	state.OwnedEntries = owned
	state.ForeignEntries = foreign
	state.EffectiveLock = ""
	if foreign > 0 {
		state.detail("%d foreign Cursor enterprise hook entries run beside DefenseClaw; Cursor has no managed-only lock, so the foreign-hook guard governs user and project hooks", foreign)
	}
	return nil
}

func newCursorState(policy config.ResolvedConnectorPolicy, paths []string) State {
	return State{
		Connector:    cursorConnector,
		Route:        RouteMachinePolicy,
		Ownership:    policy.Ownership,
		ForeignHooks: policy.ForeignHooks,
		Paths:        paths,
	}
}

func (t cursorTarget) Reconcile(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	if opts.goos() == "windows" {
		return windowsCursorReconcile(opts)
	}
	policy := opts.PolicyFor(cursorConnector)
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := newCursorState(policy, paths)
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		return state, nil
	}
	path := paths[0]
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return state, err
	}
	if policy.Ownership == config.MachinePolicyOwnershipMerge {
		rendered, exact, err := mergeCursorHooks(opts, current)
		if err != nil {
			state.conflict("%v; DefenseClaw cannot merge into this file (use ownership: verify_only)", err)
			state.finish()
			return state, nil
		}
		changed, err := publishWithRecord(opts, cursorConnector, path, current, exists, rendered, exact, func(current []byte) ([]byte, bool, error) {
			return stripCursorHooks(opts, current)
		}, &state)
		if err != nil {
			return state, err
		}
		state.Changed = changed
		current = rendered
	}
	if err := inspectCursor(opts, current, &state); err != nil {
		return state, err
	}
	if policy.Ownership == config.MachinePolicyOwnershipVerifyOnly && state.OwnedEntries == 0 {
		state.detail("missing_defenseclaw_hooks: deploy the output of `defenseclaw-gateway enterprise policy export --connector cursor` through your policy tool")
	}
	state.detail("Cursor applies enterprise hooks.json on plans that support enterprise hooks; confirm with `enterprise policy verify --live` on a real client")
	state.finish()
	return state, nil
}

func (t cursorTarget) Verify(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	if opts.goos() == "windows" {
		return windowsCursorVerify(opts)
	}
	policy := opts.PolicyFor(cursorConnector)
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := newCursorState(policy, paths)
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		return state, nil
	}
	current, exists, err := readPolicyFile(opts, paths[0])
	if err != nil {
		return state, err
	}
	if !exists {
		state.conflict("%s does not exist", paths[0])
		state.finish()
		return state, nil
	}
	if err := inspectCursor(opts, current, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

func (t cursorTarget) RemoveOwned(opts Options) (State, error) {
	if opts.goos() == "windows" {
		return windowsCursorRemove(opts)
	}
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := State{Connector: cursorConnector, Route: RouteMachinePolicy, Paths: paths}
	err = restoreOrStrip(opts, cursorConnector, paths[0], func(current []byte) ([]byte, bool, error) {
		return stripCursorHooks(opts, current)
	}, false, &state)
	return state, err
}

func (cursorTarget) Export(opts Options, format string) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if format != "" && format != "json" {
		return nil, fmt.Errorf("cursor policy export supports format json, not %q", format)
	}
	if opts.goos() == "windows" {
		adapter := joinFor(opts, dirFor(opts, mustPath(CursorEnterpriseHooksPath(opts))), cursorWindowsAdapterName)
		return connector.MergeWindowsCursorEnterpriseHooks(nil, adapter, "closed")
	}
	rendered, _, err := mergeCursorHooks(opts, nil)
	return rendered, err
}

func mustPath(path string, err error) string {
	if err != nil {
		return ""
	}
	return path
}
