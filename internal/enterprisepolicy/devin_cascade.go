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
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// The Cascade bridge. Devin Desktop removed its Cascade agent in 3.9.19;
// earlier builds still run it, under a hook contract DefenseClaw does not
// inspect. Cascade reads a machine-level hooks.json that standard users
// cannot change, runs every hook in it through bash -c (Unix) or
// powershell -Command (Windows), and blocks a pre-event when a hook exits 2
// (https://docs.devin.ai/desktop/cascade/hooks). The bridge puts one
// self-contained entry on each blocking pre-event that prints why and
// exits 2, so an old build's Cascade refuses every prompt, read, write,
// command and MCP call while Devin Local stays protected by the devin
// connector. The entry does not run DefenseClaw, so the block needs no
// runtime, enrollment row or gateway.
//
// The bridge is a companion of the devin connector: it is published while
// devin is a standalone connector, unless
// enterprise.machine_policy.connectors.devincascade.ownership is off. It is
// not a connector of its own: it enrolls nobody, is not recorded in the
// runtime descriptor and is not in the foreign-hook guard summary.
const (
	ConnectorDevinCascade    = "devincascade"
	devinCascadeLegacyRecord = ConnectorDevinCascade + "-legacy"
	devinCascadeParent       = "devin"
	devinCascadeMessage      = "DefenseClaw: the Cascade agent is turned off on this managed device. Update Devin Desktop to 3.9.19 or later and use Devin Local."
)

// devinCascadeEvents are Cascade's blocking pre-events. Post-events cannot
// block and are not registered.
var devinCascadeEvents = []string{"pre_user_prompt", "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"}

// DevinSystemHooksPath is Devin Desktop's machine-level Cascade hooks file.
func DevinSystemHooksPath(opts Options) (string, error) {
	return machinePath(opts,
		"/etc/devin/hooks.json",
		"/Library/Application Support/Devin/hooks.json",
		func(_, programData string) string { return programData + `\Devin\hooks.json` })
}

// devinCascadeLegacyHooksPath is the pre-rename machine-level hooks file
// Devin Desktop reads when the Devin one is absent; pre-rename apps read
// only it.
func devinCascadeLegacyHooksPath(opts Options) (string, error) {
	return machinePath(opts,
		"/etc/"+legacyconnector.CascadeMachineFolderUnix+"/hooks.json",
		"/Library/Application Support/"+legacyconnector.CascadeMachineFolder+"/hooks.json",
		func(_, programData string) string {
			return programData + `\` + legacyconnector.CascadeMachineFolder + `\hooks.json`
		})
}

type devinCascadeTarget struct{}

func (devinCascadeTarget) Name() string { return ConnectorDevinCascade }

func (devinCascadeTarget) Paths(opts Options) ([]string, error) {
	devin, err := DevinSystemHooksPath(opts)
	if err != nil {
		return nil, err
	}
	legacy, err := devinCascadeLegacyHooksPath(opts)
	if err != nil {
		return nil, err
	}
	return []string{devin, legacy}, nil
}

// devinCascadeScript is the entry's command (Unix) or powershell (Windows)
// string. It drains the event payload so Cascade's write never fails, then
// refuses. Under PowerShell's Constrained Language Mode the try blocks
// swallow errors and exit 2 still runs.
func devinCascadeScript(opts Options) (field, script string) {
	if opts.goos() == "windows" {
		return "powershell", "try { $null = [Console]::In.ReadToEnd() } catch { }; try { [Console]::Error.WriteLine('" + devinCascadeMessage + "') } catch { }; exit 2"
	}
	return "command", "IFS= read -r -d '' -t 2 _ || true; printf '%s\\n' '" + devinCascadeMessage + "' >&2; exit 2"
}

// devinCascadeEntry is the entry for the hooks file at path. Its working
// directory is that file's folder, which only administrators can write, so
// a current-directory-first command lookup finds nothing a user planted.
func devinCascadeEntry(opts Options, path string) *object {
	field, script := devinCascadeScript(opts)
	entry := newObject()
	entry.set(field, script)
	entry.set("show_output", true)
	entry.set("working_directory", dirFor(opts, path))
	return entry
}

func devinCascadeEntryIsOwned(opts Options, raw any) bool {
	field, script := devinCascadeScript(opts)
	return stringField(raw, field) == script
}

// mergeDevinCascadeHooks returns the file with exactly one DefenseClaw
// entry per event, every other key, event and entry kept in order, and
// whether it was already exact.
func mergeDevinCascadeHooks(opts Options, path string, current []byte) ([]byte, bool, error) {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	hooksValue, _ := doc.get("hooks")
	hooks, ok := hooksValue.(*object)
	if hooksValue != nil && !ok {
		return nil, false, fmt.Errorf("%s: hooks has unsupported type %T", path, hooksValue)
	}
	if hooks == nil {
		hooks = newObject()
	}
	want := devinCascadeEntry(opts, path)
	exact := true
	for _, event := range devinCascadeEvents {
		existing, _ := hooks.get(event)
		list, _ := existing.([]any)
		if existing != nil && list == nil {
			return nil, false, fmt.Errorf("%s: hooks.%s has unsupported type %T", path, event, existing)
		}
		kept := make([]any, 0, len(list)+1)
		found := false
		for _, item := range list {
			if devinCascadeEntryIsOwned(opts, item) {
				if !found && string(canonicalJSON(item)) == string(canonicalJSON(want)) {
					kept, found = append(kept, item), true
				} else {
					exact = false
				}
				continue
			}
			kept = append(kept, item)
		}
		if !found {
			kept, exact = append(kept, want), false
		}
		hooks.set(event, kept)
	}
	doc.set("hooks", hooks)
	rendered, err := encodeOrdered(doc)
	return rendered, exact, err
}

// stripDevinCascadeHooks removes DefenseClaw's entries; a file without
// them is returned untouched.
func stripDevinCascadeHooks(opts Options) stripFunc {
	return func(current []byte) ([]byte, bool, error) {
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
					if !devinCascadeEntryIsOwned(opts, item) {
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
		if hooks.len() == 0 && doc.len() == 1 {
			return nil, true, nil
		}
		rendered, err := encodeOrdered(doc)
		return rendered, true, err
	}
}

// devinCascadeFile is one hooks file and the ownership record it is
// published under.
type devinCascadeFile struct {
	path, record string
	current      []byte
	exists       bool
	created      []string
}

func devinCascadeFiles(opts Options) ([]devinCascadeFile, error) {
	paths, err := devinCascadeTarget{}.Paths(opts)
	if err != nil {
		return nil, err
	}
	return []devinCascadeFile{{path: paths[0], record: ConnectorDevinCascade}, {path: paths[1], record: devinCascadeLegacyRecord}}, nil
}

// load reads the file. When write is set the file's vendor folders are
// taken back first (Windows ProgramData), and a file there that an
// unprivileged principal controls is neither DefenseClaw's nor the
// administrator's, so it is replaced.
func (f *devinCascadeFile) load(opts Options, write bool, state *State) error {
	if write {
		created, err := takeBackPolicyPath(opts, f.path, state)
		f.created = created
		if err != nil {
			return err
		}
	}
	current, exists, err := readPolicyFile(opts, f.path)
	var untrusted *untrustedPolicyFileError
	if errors.As(err, &untrusted) {
		if !write || validateTrustedAncestors(opts, platformPath(opts, f.path)) != nil {
			state.conflict("%s is not administrator-controlled, so a standard user can change the Cascade hooks every user's Devin Desktop runs: %v", f.path, untrusted.err)
			return nil
		}
		state.detail("replacing %s: %v", f.path, untrusted.err)
		current, exists, err = nil, true, nil
	}
	f.current, f.exists = current, exists
	return err
}

func newDevinCascadeState(policy config.ResolvedConnectorPolicy, paths []string) State {
	return State{Connector: ConnectorDevinCascade, Route: RouteMachinePolicy, Ownership: policy.Ownership, Paths: paths}
}

func (t devinCascadeTarget) Reconcile(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(ConnectorDevinCascade)
	files, err := devinCascadeFiles(opts)
	if err != nil {
		return State{}, err
	}
	state := newDevinCascadeState(policy, []string{files[0].path, files[1].path})
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		return state, nil
	}
	merge := policy.Ownership == config.MachinePolicyOwnershipMerge
	for index := range files {
		if err := files[index].load(opts, merge, &state); err != nil {
			return state, err
		}
	}
	if merge {
		devin, legacy := &files[0], &files[1]
		// Devin Desktop reads the legacy file only when the Devin one is
		// absent, and pre-rename apps read only the legacy one: publish
		// into every file that exists, and create the Devin file when
		// neither does.
		write := map[*devinCascadeFile]bool{devin: devin.exists || !legacy.exists, legacy: legacy.exists}
		for _, file := range []*devinCascadeFile{devin, legacy} {
			strip := stripDevinCascadeHooks(opts)
			if !write[file] {
				// A record left from an earlier pass whose file is gone.
				if err := restoreOrStrip(opts, file.record, file.path, strip, false, &state); err != nil {
					return state, err
				}
				continue
			}
			rendered, exact, err := mergeDevinCascadeHooks(opts, file.path, file.current)
			if err != nil {
				state.conflict("%v; DefenseClaw cannot merge into this file (use ownership: verify_only)", err)
				continue
			}
			changed, err := publishWithRecord(opts, file.record, file.path, file.current, file.exists, rendered, exact, strip, &state, file.created...)
			if err != nil {
				return state, err
			}
			state.Changed = state.Changed || changed
			file.current, file.exists = rendered, true
		}
	}
	inspectDevinCascade(opts, files, &state)
	if policy.Ownership == config.MachinePolicyOwnershipVerifyOnly && state.OwnedEntries == 0 {
		state.detail("missing_defenseclaw_hooks: deploy the output of `defenseclaw-gateway enterprise policy export --connector devincascade` through your policy tool")
	}
	state.finish()
	return state, nil
}

// inspectDevinCascade checks that every hooks file present carries exactly
// one DefenseClaw entry per event.
func inspectDevinCascade(opts Options, files []devinCascadeFile, state *State) {
	present := 0
	for _, file := range files {
		if !file.exists {
			continue
		}
		present++
		doc, err := decodeOrderedObject(file.current)
		if err != nil {
			state.conflict("%s is not valid JSON: %v", file.path, err)
			continue
		}
		hooksValue, _ := doc.get("hooks")
		hooks, _ := hooksValue.(*object)
		for _, event := range devinCascadeEvents {
			count := 0
			if hooks != nil {
				value, _ := hooks.get(event)
				list, _ := value.([]any)
				for _, item := range list {
					if devinCascadeEntryIsOwned(opts, item) {
						count++
					}
				}
			}
			if count != 1 {
				state.conflict("%s: Cascade event %s has %d DefenseClaw entries, want exactly one", file.path, event, count)
			}
		}
		if hooks != nil {
			for _, event := range hooks.keys {
				value, _ := hooks.get(event)
				list, _ := value.([]any)
				for _, item := range list {
					if devinCascadeEntryIsOwned(opts, item) {
						state.OwnedEntries++
					} else {
						state.ForeignEntries++
					}
				}
			}
		}
	}
	if present == 0 {
		state.conflict("%s does not exist", files[0].path)
	}
	state.EffectiveLock = ""
	state.detail("Cascade has no managed-only lock and needs none: other Cascade hooks (cloud, user, workspace) run too, but a hook can only block, never approve or rewrite, so none undoes DefenseClaw's refusal; turn Cascade off in the team settings as well")
	state.detail("applies to Devin Desktop builds before 3.9.19, which still have Cascade; later builds removed it and ignore these entries")
	state.detail("residual: on Linux and macOS Cascade runs hooks through bash -c, so a user who controls the app's environment (BASH_ENV, a bash earlier on PATH) can skip the refusal")
}

func (t devinCascadeTarget) Verify(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(ConnectorDevinCascade)
	files, err := devinCascadeFiles(opts)
	if err != nil {
		return State{}, err
	}
	state := newDevinCascadeState(policy, []string{files[0].path, files[1].path})
	if policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RouteUnsupported
		return state, nil
	}
	for index := range files {
		if err := files[index].load(opts, false, &state); err != nil {
			return state, err
		}
	}
	inspectDevinCascade(opts, files, &state)
	state.finish()
	return state, nil
}

func (t devinCascadeTarget) RemoveOwned(opts Options) (State, error) {
	files, err := devinCascadeFiles(opts)
	if err != nil {
		return State{}, err
	}
	state := State{Connector: ConnectorDevinCascade, Route: RouteMachinePolicy, Paths: []string{files[0].path, files[1].path}}
	var errs []error
	for _, file := range files {
		errs = append(errs, restoreOrStrip(opts, file.record, file.path, stripDevinCascadeHooks(opts), false, &state))
	}
	return state, errors.Join(errs...)
}

func (devinCascadeTarget) Export(opts Options, format string) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	if format != "" && format != "json" {
		return nil, fmt.Errorf("devincascade policy export supports format json, not %q", format)
	}
	path, err := DevinSystemHooksPath(opts)
	if err != nil {
		return nil, err
	}
	rendered, _, err := mergeDevinCascadeHooks(opts, path, nil)
	return rendered, err
}

// companionTargets are machine-policy targets published beside a connector
// on another route, keyed by name, with that connector.
var companionTargets = map[string]struct {
	parent string
	target Target
}{
	ConnectorDevinCascade: {devinCascadeParent, devinCascadeTarget{}},
}

func isCompanion(name string) bool {
	_, ok := companionTargets[name]
	return ok
}

// withCompanions adds to connectors the companions of the connectors it
// names.
func withCompanions(connectors []string) []string {
	out := append([]string(nil), connectors...)
	for name, companion := range companionTargets {
		for _, connector := range connectors {
			if connector == companion.parent {
				out = append(out, name)
				break
			}
		}
	}
	return normalizeConnectors(out)
}

func companionNames() []string {
	return normalizeConnectors(func() []string {
		names := []string{}
		for name := range companionTargets {
			names = append(names, name)
		}
		return names
	}())
}

// withoutCompanions drops companion names (an administrator's
// enterprise.machine_policy.connectors.devincascade key) from a connector
// list.
func withoutCompanions(connectors []string) []string {
	out := []string{}
	for _, name := range connectors {
		if !isCompanion(strings.ToLower(strings.TrimSpace(name))) {
			out = append(out, name)
		}
	}
	return out
}
