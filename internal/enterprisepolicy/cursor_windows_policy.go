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

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Native Windows Cursor may evaluate hooks through PowerShell or Git Bash,
// so the enterprise entry launches a protected PowerShell adapter. The
// standalone profile reuses the adapter renderer and merge/verify/remove
// functions the Secure Client profile certifies, unchanged.
const cursorAdapterRecord = "cursor-adapter"

func windowsCursorPaths(opts Options) (hooks, adapter string, err error) {
	hooks, err = CursorEnterpriseHooksPath(opts)
	if err != nil {
		return "", "", err
	}
	return hooks, joinFor(opts, dirFor(opts, hooks), cursorWindowsAdapterName), nil
}

func windowsCursorReconcile(opts Options) (State, error) {
	policy := opts.PolicyFor(cursorConnector)
	hooksPath, adapterPath, err := windowsCursorPaths(opts)
	if err != nil {
		return State{}, err
	}
	state := newCursorState(policy, []string{hooksPath, adapterPath})
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		return state, nil
	}
	current, exists, err := readPolicyFile(opts, hooksPath)
	if err != nil {
		return state, err
	}
	if policy.Ownership == config.MachinePolicyOwnershipMerge {
		adapter, err := connector.RenderWindowsCursorEnterpriseAdapter(opts.HookBinary, "closed")
		if err != nil {
			return state, err
		}
		adapterCurrent, adapterExists, err := readPolicyFile(opts, adapterPath)
		if err != nil {
			return state, err
		}
		if _, err := publishWithRecord(opts, cursorAdapterRecord, adapterPath, adapterCurrent, adapterExists, adapter, adapterExists && bytes.Equal(adapterCurrent, adapter), windowsCursorAdapterStrip(opts), &state); err != nil {
			return state, err
		}
		merged, err := connector.MergeWindowsCursorEnterpriseHooks(current, adapterPath, "closed")
		if err != nil {
			state.conflict("%v; DefenseClaw cannot merge into this file (use ownership: verify_only)", err)
			state.finish()
			return state, nil
		}
		// Owned entries count as present when they are current or are the
		// previous release's roster with the retired afterAgentThought entry:
		// Merge above already removed that entry, so the publish rewrites the
		// file instead of reporting an outside removal.
		owned := exists && connector.VerifyWindowsCursorEnterpriseHooksRegistered(current, adapterPath, "closed") == nil
		changed, err := publishWithRecord(opts, cursorConnector, hooksPath, current, exists, merged, owned, windowsCursorHooksStrip(adapterPath), &state)
		if err != nil {
			return state, err
		}
		state.Changed = changed
		current = merged
	}
	windowsCursorInspect(opts, current, adapterPath, &state)
	state.finish()
	return state, nil
}

func windowsCursorInspect(opts Options, current []byte, adapterPath string, state *State) {
	if err := connector.VerifyWindowsCursorEnterpriseHooks(current, adapterPath, "closed"); err != nil {
		state.conflict("Cursor enterprise hooks: %v", err)
	} else {
		state.OwnedEntries = len(mustGroups(cursorConnector, opts))
	}
	adapter, err := connector.RenderWindowsCursorEnterpriseAdapter(opts.HookBinary, "closed")
	if err == nil {
		onDisk, exists, readErr := readPolicyFile(opts, adapterPath)
		// The managed runtime writes the per-target render (each enrolled
		// account's fail mode by SID) whenever it enrolls Cursor accounts:
		// that exact canonical render is DefenseClaw's adapter too, so
		// policy verify no longer called it missing while enterprise
		// windows verify was clean (GAP-1857).
		canonical := readErr == nil && exists && bytes.Equal(onDisk, adapter)
		if !canonical && readErr == nil && exists {
			_, mappedErr := connector.WindowsCursorEnterpriseAdapterTargetModes(onDisk, opts.HookBinary)
			canonical = mappedErr == nil
		}
		if !canonical {
			state.conflict("Cursor enterprise adapter %s is missing or differs from the canonical DefenseClaw adapter", adapterPath)
		}
	}
}

func mustGroups(name string, opts Options) []connector.ManagedHookGroup {
	groups, _ := connector.ManagedHookGroupsForOS(name, opts.agentVersion(name), opts.goos())
	return groups
}

func windowsCursorVerify(opts Options) (State, error) {
	policy := opts.PolicyFor(cursorConnector)
	hooksPath, adapterPath, err := windowsCursorPaths(opts)
	if err != nil {
		return State{}, err
	}
	state := newCursorState(policy, []string{hooksPath, adapterPath})
	current, exists, err := readPolicyFile(opts, hooksPath)
	if err != nil {
		return state, err
	}
	if !exists {
		// The configured machine hook must stay published with zero enrolled
		// users; its absence is a protection failure that needs repair.
		state.conflict("%s does not exist: %s", hooksPath, windowsMissingMachineHookDiagnostic("Cursor"))
	} else {
		windowsCursorInspect(opts, current, adapterPath, &state)
	}
	verifyWindowsHookExecutable(opts, "Cursor", &state)
	state.finish()
	return state, nil
}

func windowsCursorRemove(opts Options) (State, error) {
	hooksPath, adapterPath, err := windowsCursorPaths(opts)
	if err != nil {
		return State{}, err
	}
	state := State{Connector: cursorConnector, Route: RouteMachinePolicy, Paths: []string{hooksPath, adapterPath}}
	if err := restoreOrStrip(opts, cursorConnector, hooksPath, windowsCursorHooksStrip(adapterPath), false, &state); err != nil {
		return state, err
	}
	err = restoreOrStrip(opts, cursorAdapterRecord, adapterPath, windowsCursorAdapterStrip(opts), true, &state)
	return state, err
}

// windowsCursorHooksStrip removes the adapter entries DefenseClaw merged
// into the enterprise hooks.json; a file without them is left untouched.
func windowsCursorHooksStrip(adapterPath string) stripFunc {
	return func(current []byte) ([]byte, bool, error) {
		cleaned, err := connector.RemoveWindowsCursorEnterpriseHooks(current, adapterPath)
		if err != nil {
			return nil, false, err
		}
		if bytes.Equal(cleaned, current) {
			return current, false, nil
		}
		if connector.WindowsCursorEnterpriseHooksEmpty(cleaned) {
			return nil, true, nil
		}
		return cleaned, true, nil
	}
}

// windowsCursorAdapterStrip treats an adapter that launches DefenseClaw's
// hook binary as DefenseClaw's whole file.
func windowsCursorAdapterStrip(opts Options) stripFunc {
	needle := bytes.ToLower([]byte(opts.HookBinary))
	return wholeFileStrip(func(current []byte) bool {
		return len(needle) > 0 && bytes.Contains(bytes.ToLower(current), needle)
	})
}
