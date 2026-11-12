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

// The Cascade companion. Devin Desktop removed its Cascade agent in 3.9.19;
// earlier builds still run it, under a hook contract DefenseClaw does not
// inspect. Releases 1.0.5 to 1.0.8 published one self-contained entry per
// blocking Cascade pre-event (print why, exit 2) into a machine-level hooks
// file, so an old build's Cascade refused every prompt, read, write, command
// and MCP call (https://docs.devin.ai/desktop/cascade/hooks).
//
// DefenseClaw no longer publishes it, because no file it could go into is
// proved to be read only by builds that run Cascade:
//   - the pre-rename hooks file is imported as Devin Local hooks by
//     the Devin CLI and the engine inside Devin Desktop, so an exit-2 entry
//     there refuses current Devin Local too;
//   - the Devin hooks file is opened by no current CLI, and Desktop 3.12.17
//     reads it only for post_setup_worktree; no evidence shows a build that
//     runs Cascade pre-events reads it, so an entry there is inert.
//
// The companion is kept only to withdraw what those releases wrote, from
// both files, and to say that builds before 3.9.19 are not covered. The
// withdrawal can go in 1.1, when no upgrade from 1.0.5 to 1.0.8 remains
// supported. It is not a connector of its own: it enrolls nobody, is not
// recorded in the runtime descriptor and is not in the foreign-hook guard
// summary.
const (
	ConnectorDevinCascade    = "devincascade"
	devinCascadeLegacyRecord = ConnectorDevinCascade + "-legacy"
	devinCascadeParent       = "devin"
	// devinCascadeMessage is the text of the refusal those releases wrote.
	// It must not change: it identifies their entries.
	devinCascadeMessage = "DefenseClaw: the Cascade agent is turned off on this managed device. Update Devin Desktop to 3.9.19 or later and use Devin Local."
)

// DevinSystemHooksPath is the machine-level Devin hooks file an earlier
// release wrote the refusal into.
func DevinSystemHooksPath(opts Options) (string, error) {
	return machinePath(opts,
		"/etc/devin/hooks.json",
		"/Library/Application Support/Devin/hooks.json",
		func(_, programData string) string { return programData + `\Devin\hooks.json` })
}

// devinCascadeLegacyHooksPath is the pre-rename machine-level hooks file an
// earlier release wrote the refusal into when it existed.
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

// devinCascadeScript is the command (Unix) or powershell (Windows) string of
// an entry an earlier release wrote. Only its field and value identify an
// entry as DefenseClaw's.
func devinCascadeScript(opts Options) (field, script string) {
	if opts.goos() == "windows" {
		return "powershell", "try { $null = [Console]::In.ReadToEnd() } catch { }; try { [Console]::Error.WriteLine('" + devinCascadeMessage + "') } catch { }; exit 2"
	}
	return "command", "IFS= read -r -d '' -t 2 _ || true; printf '%s\\n' '" + devinCascadeMessage + "' >&2; exit 2"
}

func devinCascadeEntryIsOwned(opts Options, raw any) bool {
	field, script := devinCascadeScript(opts)
	return stringField(raw, field) == script
}

// stripDevinCascadeHooks removes DefenseClaw's entries; a file without
// them is returned untouched.
func stripDevinCascadeHooks(opts Options) stripFunc {
	return func(current []byte) ([]byte, bool, error) {
		doc, err := decodeOrderedObject(current)
		if err != nil {
			return nil, false, err
		}
		hooks := devinCascadeHooks(doc)
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

// devinCascadeFile is one hooks file and the ownership record an earlier
// release published it under.
type devinCascadeFile struct {
	path, record string
	current      []byte
	exists       bool
	// untrusted is why an unprivileged principal controls the file; current
	// and exists then hold the file as it is, read without the trust rules.
	untrusted error
	// unreadable is why an untrusted file could not be read at all (size,
	// access, change during the read); current and exists are then empty and
	// say nothing about the file.
	unreadable error
}

func devinCascadeFiles(opts Options) ([]devinCascadeFile, error) {
	paths, err := devinCascadeTarget{}.Paths(opts)
	if err != nil {
		return nil, err
	}
	return []devinCascadeFile{{path: paths[0], record: ConnectorDevinCascade}, {path: paths[1], record: devinCascadeLegacyRecord}}, nil
}

// read loads the file. A file an unprivileged principal controls is neither
// DefenseClaw's nor the administrator's, so DefenseClaw does not edit it. Its
// content is read as it is, only to report whether it still carries the
// refusal an earlier release wrote.
func (f *devinCascadeFile) read(opts Options, state *State) error {
	f.unreadable = nil
	current, exists, err := readPolicyFile(opts, f.path)
	var untrusted *untrustedPolicyFileError
	if errors.As(err, &untrusted) {
		f.untrusted = untrusted.err
		current, exists, err = readPolicyFileWith(opts, f.path, func(Options, string) error { return nil })
		if err != nil {
			// The file cannot be inspected at all; inspect reports it as a
			// conflict, never as an empty file.
			f.unreadable = err
			current, exists, err = nil, false, nil
		}
	} else {
		f.untrusted = nil
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
	for index := range files {
		if err := files[index].read(opts, &state); err != nil {
			return state, err
		}
	}
	if policy.Ownership == config.MachinePolicyOwnershipMerge {
		if err := withdrawDevinCascade(opts, files, &state); err != nil {
			return state, err
		}
	}
	inspectDevinCascade(opts, files, &state)
	state.finish()
	return state, nil
}

// withdrawDevinCascade removes the refusal an earlier release wrote, from
// the Devin hooks file and from the pre-rename one, and keeps every
// administrator entry. Records that name a file DefenseClaw created restore
// the file's earlier state.
func withdrawDevinCascade(opts Options, files []devinCascadeFile, state *State) error {
	strip := stripDevinCascadeHooks(opts)
	for index := range files {
		file := &files[index]
		if file.untrusted != nil {
			continue
		}
		if err := restoreOrStrip(opts, file.record, file.path, strip, false, state); err != nil {
			return err
		}
		if err := file.read(opts, state); err != nil {
			return err
		}
	}
	return nil
}

// devinCascadeHooks is the hooks object of a parsed hooks file, or nil.
func devinCascadeHooks(doc *object) *object {
	value, _ := doc.get("hooks")
	hooks, _ := value.(*object)
	return hooks
}

// countDevinCascadeEntries counts the DefenseClaw entries of a hooks object.
func countDevinCascadeEntries(opts Options, hooks *object) int {
	owned := 0
	if hooks == nil {
		return owned
	}
	for _, event := range hooks.keys {
		value, _ := hooks.get(event)
		list, _ := value.([]any)
		for _, item := range list {
			if devinCascadeEntryIsOwned(opts, item) {
				owned++
			}
		}
	}
	return owned
}

// inspectDevinCascade reports the refusals an earlier release left in either
// file and the coverage limit. The state is Unsupported (nothing to cover)
// unless an entry is left: a leftover in the pre-rename file refuses current
// Devin Local, and one in the Devin file is inert.
func inspectDevinCascade(opts Options, files []devinCascadeFile, state *State) {
	for _, file := range files {
		if file.unreadable != nil {
			state.conflict("%s is not administrator-controlled (%v) and DefenseClaw cannot read it (%v), so it cannot tell whether a Cascade refusal from an earlier release is still in it; an administrator must restore its owner and mode and keep it readable, or remove it", file.path, file.untrusted, file.unreadable)
			continue
		}
		if !file.exists && file.untrusted == nil {
			continue
		}
		doc, err := decodeOrderedObject(file.current)
		if err != nil {
			if file.untrusted != nil {
				state.conflict("%s is not administrator-controlled (%v) and DefenseClaw cannot read it, so it cannot tell whether a Cascade refusal from an earlier release is still in it; an administrator must restore its owner and mode, or remove it", file.path, file.untrusted)
				continue
			}
			state.detail("%s is not valid JSON: %v", file.path, err)
			continue
		}
		owned := countDevinCascadeEntries(opts, devinCascadeHooks(doc))
		if file.untrusted != nil {
			if owned > 0 {
				state.OwnedEntries += owned
				state.conflict("%s still carries DefenseClaw Cascade refusals an earlier release wrote and is not administrator-controlled (%v), so DefenseClaw will not edit it; the Devin CLI and Devin Desktop engine can import it, so they can refuse current Devin; an administrator must restore its owner and mode and run ensure, or remove the file", file.path, file.untrusted)
			} else {
				state.detail("%s is not administrator-controlled (%v); it carries no Cascade refusal from an earlier release, and DefenseClaw publishes nothing to it", file.path, file.untrusted)
			}
			continue
		}
		if owned == 0 {
			continue
		}
		state.OwnedEntries += owned
		fix := "run ensure to withdraw them"
		if state.Ownership == config.MachinePolicyOwnershipVerifyOnly {
			fix = "remove them from the file your policy tool manages (ownership: verify_only keeps DefenseClaw from editing it)"
		}
		if file.record == devinCascadeLegacyRecord {
			state.conflict("%s still carries DefenseClaw Cascade refusals an earlier release wrote; the Devin CLI and Devin Desktop engine import this file as Devin Local hooks, so they refuse current Devin; %s", file.path, fix)
		} else {
			state.conflict("%s still carries DefenseClaw Cascade refusals an earlier release wrote; no current Devin client runs them; %s", file.path, fix)
		}
	}
	if len(state.Conflicts) == 0 {
		state.Route = RouteUnsupported
	}
	state.detail("not published: the pre-rename hooks file is imported as Devin Local hooks by current Devin clients, so a refusal there would block current Devin, and no evidence shows that a build which runs Cascade pre-events reads the Devin hooks file")
	state.detail("not covered: Devin Desktop builds before 3.9.19 still run Cascade, which DefenseClaw does not inspect; keep Desktop at 3.9.19 or later and turn Cascade off in your Devin team settings; Devin Local stays protected by the devin connector")
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
		if err := files[index].read(opts, &state); err != nil {
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
		if opts.linkKept(file.path) {
			// A link sits on this file's folder (GAP-0758): nothing is read
			// through it. The other folder's entry is removed as usual.
			continue
		}
		errs = append(errs, restoreOrStrip(opts, file.record, file.path, stripDevinCascadeHooks(opts), false, &state))
	}
	return state, errors.Join(errs...)
}

// Export has nothing to render: DefenseClaw publishes no Cascade entry.
func (devinCascadeTarget) Export(opts Options, _ string) ([]byte, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%w: devincascade publishes nothing (no file is proved to reach only Devin Desktop builds that run Cascade); keep Devin Desktop at 3.9.19 or later", ErrUnsupported)
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

// WithCompanions returns connectors with the companion targets that come
// with them (sorted, without duplicates).
func WithCompanions(connectors []string) []string {
	return withCompanions(connectors)
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
