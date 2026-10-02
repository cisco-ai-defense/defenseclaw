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
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// VS Code device policies for GitHub Copilot in VS Code. Copilot policy.d
// hooks (copilot.go) govern only the Copilot SDK harness; VS Code's default
// Local harness never reads them. DefenseClaw therefore asks VS Code to keep
// hooks on (ChatHooks, which a user can otherwise turn off with
// chat.useHooks) and to open new editor chats on the SDK harness
// (ChatEditorPreferCopilotHarness, VS Code 1.134 and later). A chat a user
// moves back to Local is governed only by a user-level hook file bound with
// `--hook-surface vscode-local` (see the Copilot connector docs).
//
// Delivery (https://code.visualstudio.com/docs/enterprise/policies):
//   - Windows: REG_DWORD values under HKLM\Software\Policies\Microsoft\VSCode.
//   - Linux: /etc/vscode/policy.json, which Devin Desktop also reads.
//   - macOS: a configuration profile; DefenseClaw does not write one and
//     reports the values to deploy through MDM.
//
// Each value is added only when the administrator has not set it. The
// ownership record lists the values DefenseClaw added, and removal deletes
// only those, and only while they still hold DefenseClaw's value. A value
// the administrator set, including a different one, is kept and reported.
// Setting names: https://code.visualstudio.com/docs/enterprise/ai-settings

// vscodeDevicePolicyNames are the boolean policies DefenseClaw may enable.
// harness_preference unmanaged leaves ChatEditorPreferCopilotHarness to the
// administrator, and ChatPluginsEnabled is wanted only while the per-user
// DefenseClaw plugin is deployed (copilotPluginRoute).
var vscodeDevicePolicyNames = []string{"ChatHooks", "ChatEditorPreferCopilotHarness", "ChatPluginsEnabled"}

// vscodeWantedPolicies are the policies opts asks DefenseClaw to hold.
func vscodeWantedPolicies(opts Options) []string {
	wanted := []string{"ChatHooks"}
	if opts.copilotHarnessPreference() == config.CopilotHarnessPreferenceSDK {
		wanted = append(wanted, "ChatEditorPreferCopilotHarness")
	}
	if copilotPluginRoute(opts) {
		wanted = append(wanted, "ChatPluginsEnabled")
	}
	return wanted
}

// vscodePolicyRecord names the ownership record of the VS Code policies.
const vscodePolicyRecord = "copilot-vscode-policy"

// vscodePolicyStore reads and writes the VS Code policy values of one OS.
// Values are reported as enabled (true), set to anything else (false) or
// absent.
type vscodePolicyStore interface {
	where() string
	load() (map[string]bool, error)
	apply(add, remove []string) error
}

// vscodePolicyStoreFor returns the policy store of opts' platform: the
// Linux policy file, or the HKLM key on Windows. Tests (SkipTrustChecks)
// never reach the machine registry.
func vscodePolicyStoreFor(opts Options) (vscodePolicyStore, error) {
	switch opts.goos() {
	case "linux":
		return vscodePolicyFile{opts: opts, path: rooted(opts, "/etc/vscode/policy.json"), created: new([]string)}, nil
	case "windows":
		if opts.SkipTrustChecks {
			return nil, ErrUnsupported
		}
		return windowsVSCodePolicyStore()
	}
	return nil, ErrUnsupported
}

// vscodeDevicePolicy reconciles (write) or inspects the VS Code device
// policies and reports them in state's details. VS Code findings never mark
// the Copilot CLI route uncovered; they describe a different harness.
func vscodeDevicePolicy(opts Options, state *State, write bool) error {
	store, err := vscodePolicyStoreFor(opts)
	if errors.Is(err, ErrUnsupported) {
		if opts.goos() == "darwin" {
			state.detail("vscode: deploy the VS Code policies %s = true in a configuration profile through MDM; DefenseClaw does not write macOS profiles", strings.Join(vscodeWantedPolicies(opts), ", "))
		}
		return nil
	}
	if err != nil {
		return err
	}
	current, err := store.load()
	if err != nil {
		state.detail("vscode: cannot read the VS Code policies at %s: %v", store.where(), err)
		return nil
	}
	record, err := loadRecord(opts, vscodePolicyRecord)
	if err != nil {
		return err
	}
	owned := map[string]bool{}
	if record != nil {
		for _, name := range record.OwnedKeys {
			owned[name] = true
		}
	}
	wanted := vscodeWantedPolicies(opts)
	var add, keep, drop []string
	for _, name := range vscodeDevicePolicyNames {
		enabled, present := current[name]
		if !containsString(wanted, name) {
			// No longer wanted (harness_preference unmanaged, or the plugin
			// route is off): drop only a value DefenseClaw added that still
			// holds its value.
			if owned[name] && present && enabled {
				drop = append(drop, name)
			}
			continue
		}
		switch {
		case !present:
			add = append(add, name)
		case owned[name] && enabled:
			keep = append(keep, name)
		case enabled:
			// The administrator's own value; it is left to them.
		default:
			state.detail("vscode: kept the administrator's value of %s at %s; DefenseClaw needs it enabled", name, store.where())
		}
	}
	if !write {
		for _, name := range add {
			state.detail("vscode: policy %s is not set at %s", name, store.where())
		}
		for _, name := range drop {
			state.detail("vscode: policy %s is no longer wanted at %s; reconcile removes DefenseClaw's value", name, store.where())
		}
		return nil
	}
	if len(add) > 0 || len(drop) > 0 {
		if err := store.apply(add, drop); err != nil {
			return fmt.Errorf("vscode policies at %s: %w", store.where(), err)
		}
		state.Changed = true
		if len(add) > 0 {
			state.detail("vscode: enabled %s at %s", strings.Join(add, ", "), store.where())
		}
		if len(drop) > 0 {
			state.detail("vscode: removed %s from %s", strings.Join(drop, ", "), store.where())
		}
	}
	ownedNow := append(keep, add...)
	if len(ownedNow) == 0 {
		if record != nil {
			removeVSCodePolicyDirs(opts, state, record)
			return deleteRecord(opts, vscodePolicyRecord)
		}
		return nil
	}
	if record == nil {
		record = &ownershipRecord{Connector: vscodePolicyRecord}
	}
	record.Path = store.where()
	record.OwnedKeys = ownedNow
	record.CreatedDirs = appendUnique(record.CreatedDirs, vscodePolicyCreatedDirs(store)...)
	return saveRecord(opts, record)
}

// removeVSCodeDevicePolicy deletes the VS Code policy values DefenseClaw
// added that still hold its value.
func removeVSCodeDevicePolicy(opts Options, state *State) error {
	record, err := loadRecord(opts, vscodePolicyRecord)
	if err != nil || record == nil {
		return err
	}
	store, err := vscodePolicyStoreFor(opts)
	if errors.Is(err, ErrUnsupported) {
		return deleteRecord(opts, vscodePolicyRecord)
	}
	if err != nil {
		return err
	}
	current, err := store.load()
	if err != nil {
		return err
	}
	var remove []string
	for _, name := range record.OwnedKeys {
		if enabled, present := current[name]; present && enabled {
			remove = append(remove, name)
		}
	}
	if len(remove) > 0 {
		if err := store.apply(nil, remove); err != nil {
			return err
		}
		state.Changed = true
		state.detail("vscode: removed %s from %s", strings.Join(remove, ", "), store.where())
	}
	removeVSCodePolicyDirs(opts, state, record)
	return deleteRecord(opts, vscodePolicyRecord)
}

// vscodePolicyFile is the Linux policy.json store. created collects the
// folders a write made (/etc/vscode), which go again with the last value.
type vscodePolicyFile struct {
	opts    Options
	path    string
	created *[]string
}

// vscodePolicyCreatedDirs returns the folders store's writes created.
func vscodePolicyCreatedDirs(store vscodePolicyStore) []string {
	if file, ok := store.(vscodePolicyFile); ok && file.created != nil {
		return *file.created
	}
	return nil
}

// removeVSCodePolicyDirs removes the folders the record says DefenseClaw
// created, deepest first, while they are empty.
func removeVSCodePolicyDirs(opts Options, state *State, record *ownershipRecord) {
	if record == nil {
		return
	}
	dirs := append([]string(nil), record.CreatedDirs...)
	sort.SliceStable(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		if err := removeDirIfEmpty(opts, dir); err != nil {
			state.detail("vscode: left %s in place: %v", dir, err)
		}
	}
}

func (f vscodePolicyFile) where() string { return f.path }

func (f vscodePolicyFile) read() (*object, error) {
	data, exists, err := readPolicyFile(f.opts, f.path)
	if err != nil {
		return nil, err
	}
	if !exists || blank(data) {
		return newObject(), nil
	}
	return decodeOrderedObject(data)
}

func (f vscodePolicyFile) load() (map[string]bool, error) {
	doc, err := f.read()
	if err != nil {
		return nil, err
	}
	values := map[string]bool{}
	for _, name := range vscodeDevicePolicyNames {
		if value, ok := doc.get(name); ok {
			enabled, _ := value.(bool)
			values[name] = enabled
		}
	}
	return values, nil
}

func (f vscodePolicyFile) apply(add, remove []string) error {
	doc, err := f.read()
	if err != nil {
		return err
	}
	for _, name := range add {
		doc.set(name, true)
	}
	for _, name := range remove {
		doc.delete(name)
	}
	if doc.len() == 0 && len(remove) > 0 {
		return removePolicyFile(f.opts, f.path)
	}
	rendered, err := encodeOrdered(doc)
	if err != nil {
		return err
	}
	created, err := writePolicyFile(f.opts, f.path, rendered)
	if f.created != nil {
		*f.created = append(*f.created, created...)
	}
	return err
}
