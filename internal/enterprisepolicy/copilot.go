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

func inspectCopilot(opts Options, state *State) error {
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
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".json") && !strings.HasPrefix(entry.Name(), ".") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	ownedPerEvent := map[string]int{}
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
			list, _ := value.([]any)
			for _, handler := range list {
				if copilotHandlerIsOwned(opts, handler) {
					state.OwnedEntries++
					ownedPerEvent[event]++
					if !copilotHandlerIsIntact(opts, event, handler) {
						state.entryConflict("%s: the DefenseClaw policy hook for Copilot event %s is not the command DefenseClaw publishes, so it may not enforce; the next lifecycle run that applies changes (ensure, repair or reconcile) rewrites it", file, event)
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
		rendered, err := renderCopilotDropIn(opts)
		if err != nil {
			return state, err
		}
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
			current, exists, err = nil, true, nil
		}
		if err != nil {
			return state, err
		}
		changed, err := publishWithRecord(opts, copilotConnector, paths[0], current, exists, rendered, exists && bytes.Equal(current, rendered), copilotStrip(opts), &state, created...)
		if err != nil {
			return state, err
		}
		state.Changed = changed
	}
	if err := vscodeDevicePolicy(opts, &state, policy.Ownership == config.MachinePolicyOwnershipMerge); err != nil {
		return state, err
	}
	if err := copilotManagedSettings(opts, &state, policy.Ownership == config.MachinePolicyOwnershipMerge); err != nil {
		return state, err
	}
	copilotVSCodeStatus(opts, &state)
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
	if err := vscodeDevicePolicy(opts, &state, false); err != nil {
		return state, err
	}
	if err := copilotManagedSettings(opts, &state, false); err != nil {
		return state, err
	}
	copilotVSCodeStatus(opts, &state)
	if err := inspectCopilot(opts, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

func (t copilotTarget) RemoveOwned(opts Options) (State, error) {
	paths, err := t.Paths(opts)
	if err != nil {
		return State{}, err
	}
	state := State{Connector: copilotConnector, Route: RouteMachinePolicy, Paths: paths}
	err = restoreOrStrip(opts, copilotConnector, paths[0], copilotStrip(opts), true, &state)
	return state, errors.Join(err, removeVSCodeDevicePolicy(opts, &state), removeCopilotManagedSettings(opts, &state))
}

// copilotStrip treats a drop-in carrying a DefenseClaw policy hook as
// DefenseClaw's whole file; any other content under the drop-in name is
// left alone.
func copilotStrip(opts Options) stripFunc {
	return wholeFileStrip(func(current []byte) bool {
		doc, err := decodeOrderedObject(current)
		if err != nil {
			return false
		}
		hooksValue, _ := doc.get("hooks")
		hooks, _ := hooksValue.(*object)
		if hooks == nil {
			return false
		}
		for _, event := range hooks.keys {
			value, _ := hooks.get(event)
			list, _ := value.([]any)
			for _, handler := range list {
				if copilotHandlerIsOwned(opts, handler) {
					return true
				}
			}
		}
		return false
	})
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
