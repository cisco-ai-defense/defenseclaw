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

package enterprisepolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GitHub Copilot's managed settings file (VS Code Local harness and the
// Copilot CLI read it):
//   - Linux:   /etc/github-copilot/managed-settings.json
//   - Windows: %ProgramFiles%\GitHubCopilot\managed-settings.json
//   - macOS:   /Library/Application Support/GitHubCopilot/managed-settings.json
//     (user-writable parents on stock macOS, so DefenseClaw reports the
//     values to deploy and never writes it)
//
// DefenseClaw adds, only where the administrator has not set them:
//   - enabledPlugins["defenseclaw@defenseclaw"] = true while its per-user
//     plugin is deployed (managed_hooks_only enforce, local_harness govern)
//     and every VS Code found is a version whose plugin store DefenseClaw
//     writes (copilotVSCodePluginStoreGate). The Copilot CLI reads this file
//     too and, from 1.0.92, waits forever on a plugin whose marketplace it
//     does not know, so the key is never written for a host without a VS Code
//     that reads it (GAP-0192);
//   - allowManagedHooksOnly = true (VS Code Local only) once every enrolled
//     user holds the plugin and every VS Code found is a version whose
//     plugin store DefenseClaw writes (copilotLocalLockGate);
//   - sandbox.enabled = true for local_harness retire.
//
// The ownership record lists the keys DefenseClaw added and the folders it
// created for the file; removal deletes only the keys that still hold
// DefenseClaw's value, then the file and those folders once empty. An
// administrator's value, including a different one, is kept and reported.
// The plugin key names DefenseClaw's own plugin, so it is DefenseClaw's
// whenever it holds true, recorded or not: a build before 1.0.0 wrote it
// without a record, and that key outlived every later reconcile and
// uninstall, leaving the Copilot CLI to warn at every start that the
// marketplace "defenseclaw" is not found (GAP-1245).

const copilotManagedSettingsRecord = "copilot-managed-settings"

// Copilot managed-settings keys DefenseClaw may own (dotted paths).
const (
	copilotSettingPlugin    = "enabledPlugins." + CopilotPluginKey
	copilotSettingHooksOnly = "allowManagedHooksOnly"
	copilotSettingSandbox   = "sandbox.enabled"
)

var copilotManagedSettingKeys = []string{copilotSettingPlugin, copilotSettingHooksOnly, copilotSettingSandbox}

// VS Code versions whose plugin store DefenseClaw writes: 1.139 reads
// ~/.copilot/installed-plugins; later builds also need records in
// ~/.copilot/config.json, which DefenseClaw does not write yet.
const (
	copilotLockMinVSCode   = "1.139"
	copilotLockBelowVSCode = "1.140"
)

// CopilotManagedSettingsPath is Copilot's managed settings file.
func CopilotManagedSettingsPath(opts Options) (string, error) {
	return machinePath(opts,
		"/etc/github-copilot/managed-settings.json",
		"/Library/Application Support/GitHubCopilot/managed-settings.json",
		func(programFiles, _ string) string { return programFiles + `\GitHubCopilot\managed-settings.json` })
}

func (o Options) copilotHarnessPreference() string {
	if value := strings.ToLower(strings.TrimSpace(o.CopilotHarnessPreference)); value != "" {
		return value
	}
	return config.CopilotHarnessPreferenceSDK
}

func (o Options) copilotLocalHarness() string {
	if value := strings.ToLower(strings.TrimSpace(o.CopilotLocalHarness)); value != "" {
		return value
	}
	return config.CopilotLocalHarnessGovern
}

// copilotPluginRoute reports whether DefenseClaw deploys its per-user
// Copilot plugin: the Local harness is governed and the managed-only lock
// is wanted (the plugin keeps DefenseClaw's hooks running under it).
func copilotPluginRoute(opts Options) bool {
	policy := opts.PolicyFor(copilotConnector)
	return policy.Ownership != config.MachinePolicyOwnershipOff &&
		opts.copilotLocalHarness() == config.CopilotLocalHarnessGovern &&
		policy.ManagedHooksOnly == config.ManagedHooksOnlyEnforce
}

// CopilotVSCodeUserWant is what each enrolled user's home should hold for
// opts: the Local hook file while Copilot is governed and the Local
// harness is not retired, and the plugin on the plugin route where a VS
// Code that reads it is installed. The plugin follows the same gate as
// its enabledPlugins key (copilotVSCodePluginStoreGate): without that key
// nothing loads it, so on a host without such a VS Code it would only be a
// stray folder in every enrolled home (GAP-1245).
func CopilotVSCodeUserWant(opts Options) (hookFile, plugin bool) {
	policy := opts.PolicyFor(copilotConnector)
	if policy.Ownership == config.MachinePolicyOwnershipOff || opts.copilotLocalHarness() != config.CopilotLocalHarnessGovern {
		return false, false
	}
	if !copilotPluginRoute(opts) {
		return true, false
	}
	gate, _ := copilotVSCodePluginStoreGate(opts)
	return true, gate
}

// VSCodeInstall is one VS Code installation DefenseClaw found.
type VSCodeInstall struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// DiscoverVSCode finds VS Code (stable) installations: the machine-wide
// locations and, on Windows, the per-user installs under the enrolled
// homes. It reads each product's resources/app/package.json.
func DiscoverVSCode(opts Options) []VSCodeInstall {
	var candidates []string
	switch opts.goos() {
	case "windows":
		if pf := strings.TrimRight(opts.WindowsProgramFiles, `\`); pf != "" {
			candidates = append(candidates, pf+`\Microsoft VS Code\resources\app\package.json`)
		}
		for _, home := range opts.CopilotUserHomes {
			candidates = append(candidates, strings.TrimRight(home, `\`)+`\AppData\Local\Programs\Microsoft VS Code\resources\app\package.json`)
		}
	case "darwin":
		candidates = append(candidates, rooted(opts, "/Applications/Visual Studio Code.app/Contents/Resources/app/package.json"))
		for _, home := range opts.CopilotUserHomes {
			candidates = append(candidates, filepath.Join(home, "Applications", "Visual Studio Code.app", "Contents", "Resources", "app", "package.json"))
		}
	default:
		candidates = append(candidates,
			rooted(opts, "/usr/share/code/resources/app/package.json"),
			rooted(opts, "/snap/code/current/usr/share/code/resources/app/package.json"),
			rooted(opts, "/opt/visual-studio-code/resources/app/package.json"))
	}
	var out []VSCodeInstall
	for _, path := range candidates {
		data, err := readSmallFile(platformPath(opts, path), 1<<20)
		if err != nil {
			continue
		}
		var manifest struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &manifest) != nil || strings.TrimSpace(manifest.Version) == "" {
			continue
		}
		out = append(out, VSCodeInstall{Path: path, Version: strings.TrimSpace(manifest.Version)})
	}
	return out
}

func readSmallFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return readBounded(file, limit)
}

// copilotLocalLockGate decides whether DefenseClaw may set
// allowManagedHooksOnly: it drops every user hook file in the Local
// harness, including DefenseClaw's own, so it is written only when every
// enrolled user already runs DefenseClaw's hooks from the plugin.
func copilotLocalLockGate(opts Options) (bool, string) {
	if !copilotPluginRoute(opts) {
		return false, "managed_hooks_only is not enforce or local_harness is not govern"
	}
	if opts.goos() == "windows" {
		return false, "not written on Windows until the Local harness is confirmed to read the managed settings under the trusted Program Files root"
	}
	if len(opts.CopilotUserHomes) == 0 {
		return false, "no enrolled users are recorded yet"
	}
	for _, home := range opts.CopilotUserHomes {
		if _, plugin := CopilotVSCodeUserState(home, opts.goos(), opts.HookBinary); !plugin {
			return false, fmt.Sprintf("DefenseClaw's Copilot plugin is not yet in place under %s", home)
		}
	}
	return copilotVSCodePluginStoreGate(opts)
}

// copilotVSCodePluginStoreGate reports whether VS Code is on this host and
// every installation found is a version whose plugin store DefenseClaw
// writes. The enabledPlugins key is read by VS Code and by the Copilot CLI
// (the same file); without such a VS Code nothing needs it.
func copilotVSCodePluginStoreGate(opts Options) (bool, string) {
	installs := DiscoverVSCode(opts)
	if len(installs) == 0 {
		return false, "no VS Code installation was found to check its plugin store version"
	}
	for _, install := range installs {
		if compareVersions(install.Version, copilotLockMinVSCode) < 0 || compareVersions(install.Version, copilotLockBelowVSCode) >= 0 {
			return false, fmt.Sprintf("VS Code %s at %s is outside %s.x, whose plugin store DefenseClaw writes", install.Version, install.Path, copilotLockMinVSCode)
		}
	}
	return true, ""
}

// copilotWantedSettings are the managed-settings keys opts asks for.
func copilotWantedSettings(opts Options, state *State) []string {
	var wanted []string
	if opts.PolicyFor(copilotConnector).Ownership == config.MachinePolicyOwnershipOff {
		return nil
	}
	if opts.copilotLocalHarness() == config.CopilotLocalHarnessRetire {
		return []string{copilotSettingSandbox}
	}
	if copilotPluginRoute(opts) {
		if ok, reason := copilotVSCodePluginStoreGate(opts); !ok {
			if state != nil {
				state.detail("vscode: %s not set: %s; the Copilot CLI reads the same file and would wait on a plugin marketplace DefenseClaw does not write", copilotSettingPlugin, reason)
			}
			return wanted
		}
		wanted = append(wanted, copilotSettingPlugin)
		if ok, reason := copilotLocalLockGate(opts); ok {
			wanted = append(wanted, copilotSettingHooksOnly)
		} else if state != nil {
			state.detail("vscode: allowManagedHooksOnly not set: %s; the foreign-hook guard still applies in the Local harness", reason)
		}
	}
	return wanted
}

// copilotSettingGet and copilotSettingSet address a dotted key; the
// plugin key's own name holds "@" but no ".".
func copilotSettingParts(key string) []string {
	if rest, ok := strings.CutPrefix(key, "enabledPlugins."); ok {
		return []string{"enabledPlugins", rest}
	}
	return strings.Split(key, ".")
}

func copilotSettingGet(doc *object, key string) (any, bool) {
	parts := copilotSettingParts(key)
	current := doc
	for i, part := range parts {
		value, ok := current.get(part)
		if !ok {
			return nil, false
		}
		if i == len(parts)-1 {
			return value, true
		}
		if current, ok = value.(*object); !ok {
			return value, true
		}
	}
	return nil, false
}

func copilotSettingSet(doc *object, key string) error {
	parts := copilotSettingParts(key)
	current := doc
	for _, part := range parts[:len(parts)-1] {
		value, ok := current.get(part)
		if !ok {
			child := newObject()
			current.set(part, child)
			current = child
			continue
		}
		child, ok := value.(*object)
		if !ok {
			return fmt.Errorf("%s is not an object", part)
		}
		current = child
	}
	current.set(parts[len(parts)-1], true)
	return nil
}

func copilotSettingDelete(doc *object, key string) {
	parts := copilotSettingParts(key)
	parents := []*object{doc}
	current := doc
	for _, part := range parts[:len(parts)-1] {
		value, _ := current.get(part)
		child, ok := value.(*object)
		if !ok {
			return
		}
		parents = append(parents, child)
		current = child
	}
	current.delete(parts[len(parts)-1])
	for i := len(parents) - 1; i > 0; i-- {
		if parents[i].len() != 0 {
			break
		}
		parents[i-1].delete(parts[i-1])
	}
}

// copilotManagedSettings reconciles (write) or inspects Copilot's managed
// settings and reports them in state's details. Like the VS Code device
// policies, these findings never mark the Copilot CLI route uncovered.
func copilotManagedSettings(opts Options, state *State, write bool) error {
	wanted := copilotWantedSettings(opts, state)
	path, err := CopilotManagedSettingsPath(opts)
	if err != nil {
		return nil
	}
	if opts.goos() == "darwin" {
		if len(wanted) > 0 {
			state.detail("vscode: deploy %s = true in %s through your device management; DefenseClaw does not write it on macOS, and a user can override it there", strings.Join(wanted, ", "), path)
		}
		return nil
	}
	data, exists, err := readPolicyFile(opts, path)
	if err != nil {
		state.detail("vscode: cannot read Copilot managed settings %s: %v", path, err)
		return nil
	}
	doc := newObject()
	if exists && !blank(data) {
		if doc, err = decodeOrderedObject(data); err != nil {
			state.detail("vscode: Copilot managed settings %s is not valid JSON; left unchanged: %v", path, err)
			return nil
		}
	}
	record, err := loadRecord(opts, copilotManagedSettingsRecord)
	if err != nil {
		return err
	}
	owned := map[string]bool{copilotSettingPlugin: true}
	if record != nil {
		for _, key := range record.OwnedKeys {
			owned[key] = true
		}
	}
	var add, keep, drop []string
	for _, key := range copilotManagedSettingKeys {
		value, present := copilotSettingGet(doc, key)
		ours := present && value == true
		if !containsString(wanted, key) {
			if owned[key] && ours {
				drop = append(drop, key)
			}
			continue
		}
		switch {
		case !present:
			add = append(add, key)
		case owned[key] && ours:
			keep = append(keep, key)
		case ours:
		default:
			state.detail("vscode: kept the administrator's value of %s in %s; DefenseClaw wants true", key, path)
		}
	}
	if !write {
		for _, key := range add {
			state.detail("vscode: %s is not set in %s", key, path)
		}
		for _, key := range keep {
			state.detail("vscode: %s is set in %s", key, path)
		}
		return nil
	}
	if len(add) > 0 || len(drop) > 0 {
		for _, key := range add {
			if err := copilotSettingSet(doc, key); err != nil {
				return fmt.Errorf("copilot managed settings %s: %w", path, err)
			}
		}
		for _, key := range drop {
			copilotSettingDelete(doc, key)
		}
		created, err := writeCopilotManagedSettings(opts, path, doc)
		if len(created) > 0 {
			if record == nil {
				record = &ownershipRecord{Connector: copilotManagedSettingsRecord}
			}
			record.CreatedDirs = appendUnique(record.CreatedDirs, created...)
		}
		if err != nil {
			return err
		}
		state.Changed = true
		if len(add) > 0 {
			state.detail("vscode: set %s in %s", strings.Join(add, ", "), path)
		}
		if len(drop) > 0 {
			state.detail("vscode: removed %s from %s", strings.Join(drop, ", "), path)
		}
	}
	ownedNow := append(keep, add...)
	if len(ownedNow) == 0 {
		removeCopilotManagedSettingsDirs(opts, path, record, record == nil && len(drop) > 0)
		if record != nil {
			return deleteRecord(opts, copilotManagedSettingsRecord)
		}
		return nil
	}
	if record == nil {
		record = &ownershipRecord{Connector: copilotManagedSettingsRecord}
	}
	record.Path = path
	record.OwnedKeys = ownedNow
	return saveRecord(opts, record)
}

// writeCopilotManagedSettings writes doc to path, or removes the file once
// doc is empty. It returns the folders it created for the file.
func writeCopilotManagedSettings(opts Options, path string, doc *object) ([]string, error) {
	if doc.len() == 0 {
		return nil, removePolicyFile(opts, path)
	}
	rendered, err := encodeOrdered(doc)
	if err != nil {
		return nil, err
	}
	return writePolicyFile(opts, path, rendered)
}

// removeCopilotManagedSettingsDirs removes, once the managed settings file
// is gone, the folders DefenseClaw recorded creating for it, deepest first,
// and with recordless (an older build's file DefenseClaw just emptied) the
// file's own folder. Only an empty folder goes.
func removeCopilotManagedSettingsDirs(opts Options, path string, record *ownershipRecord, recordless bool) {
	if _, err := os.Lstat(platformPath(opts, path)); !errors.Is(err, os.ErrNotExist) {
		return
	}
	var dirs []string
	if record != nil {
		dirs = append(dirs, record.CreatedDirs...)
	}
	if recordless {
		dirs = appendUnique(dirs, dirFor(opts, path))
	}
	sort.SliceStable(dirs, func(i, j int) bool { return len(dirs[i]) > len(dirs[j]) })
	for _, dir := range dirs {
		_ = removeDirIfEmpty(opts, dir)
	}
}

// removeCopilotManagedSettings deletes the keys DefenseClaw added that
// still hold its value, and the plugin key whether recorded or not
// (GAP-1245), then the file and the folders DefenseClaw created for it once
// they are empty.
func removeCopilotManagedSettings(opts Options, state *State) error {
	record, err := loadRecord(opts, copilotManagedSettingsRecord)
	if err != nil {
		return err
	}
	path, err := CopilotManagedSettingsPath(opts)
	if err != nil || opts.goos() == "darwin" {
		if record == nil {
			return nil
		}
		return deleteRecord(opts, copilotManagedSettingsRecord)
	}
	keys := []string{copilotSettingPlugin}
	if record != nil {
		keys = appendUnique(append([]string(nil), record.OwnedKeys...), copilotSettingPlugin)
	}
	data, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return err
	}
	var removed []string
	if exists && !blank(data) {
		doc, err := decodeOrderedObject(data)
		if err != nil {
			if record == nil {
				// Nothing recorded: DefenseClaw left nothing it knows of in
				// a file it cannot read.
				state.detail("vscode: Copilot managed settings %s is not valid JSON; left unchanged: %v", path, err)
				return nil
			}
			return fmt.Errorf("copilot managed settings %s: %w", path, err)
		}
		for _, key := range keys {
			if value, present := copilotSettingGet(doc, key); present && value == true {
				copilotSettingDelete(doc, key)
				removed = append(removed, key)
			}
		}
		if len(removed) > 0 {
			if _, err := writeCopilotManagedSettings(opts, path, doc); err != nil {
				return err
			}
			state.Changed = true
			state.detail("vscode: removed %s from %s", strings.Join(removed, ", "), path)
		}
	}
	removeCopilotManagedSettingsDirs(opts, path, record, record == nil && len(removed) > 0)
	if record == nil {
		return nil
	}
	return deleteRecord(opts, copilotManagedSettingsRecord)
}

// copilotVSCodeStatus reports the VS Code side of the Copilot row: the
// harness settings, the VS Code installations found, and how many enrolled
// users hold DefenseClaw's Local hook file and plugin.
func copilotVSCodeStatus(opts Options, state *State) {
	state.detail("vscode: harness_preference %s, local_harness %s", opts.copilotHarnessPreference(), opts.copilotLocalHarness())
	for _, install := range DiscoverVSCode(opts) {
		state.detail("vscode: found VS Code %s at %s", install.Version, install.Path)
	}
	if len(opts.CopilotUserHomes) == 0 {
		return
	}
	wantFile, wantPlugin := CopilotVSCodeUserWant(opts)
	files, plugins := 0, 0
	for _, home := range opts.CopilotUserHomes {
		file, plugin := CopilotVSCodeUserState(home, opts.goos(), opts.HookBinary)
		if file {
			files++
		} else if wantFile {
			state.UserFileDrift = append(state.UserFileDrift, CopilotVSCodeLocalHookFilePath(home))
		}
		if plugin {
			plugins++
		} else if wantPlugin {
			// The plugin is DefenseClaw's as well: a missing or earlier copy
			// is rewritten on the guardian's next pass, while one holding
			// hooks DefenseClaw did not write stays, and the foreign-hook
			// guard denies that user's calls (GAP-1232).
			if kept := copilotVSCodeUserKept(home, opts.goos(), opts.HookBinary); len(kept) > 0 {
				state.UserFileForeign = append(state.UserFileForeign, kept...)
			} else {
				state.UserFileDrift = append(state.UserFileDrift, CopilotPluginHooksPath(home))
			}
		}
	}
	state.detail("vscode: Local hook file in place for %d of %d enrolled users (wanted: %t); plugin for %d (wanted: %t)",
		files, len(opts.CopilotUserHomes), wantFile, plugins, wantPlugin)
}
