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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const claudeCodeSettingsReadLimit int64 = 4 << 20

type claudeCodeSettingsSource struct {
	name     string
	path     string
	settings map[string]interface{}
}

func (s *claudeCodeSettingsSource) active() bool {
	return s != nil && len(s.settings) > 0
}

func (s *claudeCodeSettingsSource) label() string {
	if s == nil {
		return ""
	}
	if strings.TrimSpace(s.path) == "" {
		return s.name
	}
	return fmt.Sprintf("%s (%s)", s.name, s.path)
}

type claudeCodeOSManagedSources struct {
	admin        *claudeCodeSettingsSource
	userFallback *claudeCodeSettingsSource
}

// Platform implementations return the locally inspectable MDM/OS managed
// source and (on Windows) the lower-priority HKCU policy fallback.
var claudeCodeOSManagedSettingsLoader = loadClaudeCodeOSManagedSettings

// ClaudeCodeManagedSettingsRootOverride isolates managed-policy fixtures. It
// must remain empty in production; Claude's managed file locations are fixed by
// the host OS. Setting it also isolates remote/registry sources so tests never
// consume administrator policy from the machine running the suite.
var ClaudeCodeManagedSettingsRootOverride string

// claudeCodeEffectiveHookContract is deliberately passive. policyHelper is an
// arbitrary administrator program and remote settings can change on the next
// client refresh; Doctor/guardian must identify those boundaries rather than
// execute policy code or silently assume the DefenseClaw drop-in wins.
func claudeCodeEffectiveHookContract(opts SetupOpts) (bool, error) {
	managed, err := inspectClaudeCodeManagedSources()
	if err != nil {
		return false, err
	}
	if helper := claudeCodePolicyHelperSource(managed); helper != nil {
		return false, fmt.Errorf(
			"Claude Code policyHelper from %s is dynamic and cannot be passively verified; include the DefenseClaw managed hook matrix in the helper output",
			helper.label(),
		)
	}

	activeManaged := managed.active()
	// Unix guardian installs harden per-user hook scripts. Only the native
	// enterprise path pins an administrator-owned executable in managed policy.
	managedPolicy := opts.ManagedEnterprise && strings.TrimSpace(opts.HookExecutable) != ""
	if err := validateClaudeCodeManagedHookControls(activeManaged, managedPolicy); err != nil {
		return false, err
	}
	if managedPolicy {
		if activeManaged == nil {
			// The managed file/drop-in may have been removed. Report ordinary
			// absence so the guardian can re-run Setup; Doctor independently
			// emits the source-specific unhealthy diagnostic.
			return false, nil
		}
		// Remote and OS-admin tiers supersede the file destination owned by
		// Setup, so absence/replacement there is not repairable locally and
		// must carry an exact diagnostic. File policy and the lower HKCU
		// fallback can be repaired by restoring our higher file drop-in.
		diagnoseMissing := activeManaged == managed.remote || activeManaged == managed.osAdmin
		return claudeCodeSourceHasHookContract(activeManaged, opts, diagnoseMissing)
	}

	sources, err := inspectClaudeCodeUserSources(opts)
	if err != nil {
		return false, err
	}
	if disabled, source, err := effectiveClaudeCodeUserHooksDisabled(sources); err != nil {
		return false, err
	} else if disabled {
		return false, fmt.Errorf("Claude Code %s sets disableAllHooks=true, so the user-scoped DefenseClaw hooks are inactive", source.label())
	}
	user := sources.user
	if user == nil {
		return false, nil
	}
	return claudeCodeSourceHasHookContract(user, opts, false)
}

type claudeCodeManagedSourceSet struct {
	remote       *claudeCodeSettingsSource
	osAdmin      *claudeCodeSettingsSource
	file         *claudeCodeSettingsSource
	userFallback *claudeCodeSettingsSource
}

func (s claudeCodeManagedSourceSet) active() *claudeCodeSettingsSource {
	for _, candidate := range []*claudeCodeSettingsSource{s.remote, s.osAdmin, s.file, s.userFallback} {
		// Claude selects the first managed source that delivers a non-empty
		// configuration. An empty remote/registry/file object falls through to
		// the next endpoint-managed tier.
		if candidate.active() {
			return candidate
		}
	}
	return nil
}

func inspectClaudeCodeManagedSources() (claudeCodeManagedSourceSet, error) {
	var result claudeCodeManagedSourceSet
	remotePath := claudeCodeRemoteSettingsPath()
	remote, err := readOptionalClaudeCodeSettings("remote/server-managed settings", remotePath)
	if err != nil {
		return result, err
	}
	result.remote = remote

	if ClaudeCodeSettingsPathOverride == "" && ClaudeCodeManagedSettingsRootOverride == "" {
		osSources, err := claudeCodeOSManagedSettingsLoader()
		if err != nil {
			return result, err
		}
		result.osAdmin = osSources.admin
		result.userFallback = osSources.userFallback
	}

	fileSource, err := readClaudeCodeManagedFileSettings()
	if err != nil {
		return result, err
	}
	result.file = fileSource
	return result, nil
}

// validateClaudeCodeManagedFileDestination prevents an enterprise installer
// from writing a perfectly valid drop-in that Claude will never load because a
// higher managed tier wins. The installer owns only the file-based tier; remote
// and MDM policy must carry the hook matrix through their native admin channel.
func validateClaudeCodeManagedFileDestination() error {
	managed, err := inspectClaudeCodeManagedSources()
	if err != nil {
		return err
	}
	if helper := claudeCodePolicyHelperSource(managed); helper != nil {
		return fmt.Errorf(
			"Claude Code policyHelper from %s supersedes file-based managed hooks; add the DefenseClaw hook matrix to the helper output",
			helper.label(),
		)
	}
	if managed.remote.active() {
		return fmt.Errorf(
			"Claude Code %s has higher precedence than file-based managed hooks; deploy the DefenseClaw hook matrix through that source",
			managed.remote.label(),
		)
	}
	if managed.osAdmin.active() {
		return fmt.Errorf(
			"Claude Code %s has higher precedence than file-based managed hooks; deploy the DefenseClaw hook matrix through that source",
			managed.osAdmin.label(),
		)
	}
	if err := validateClaudeCodeManagedHookControls(managed.file, true); err != nil {
		return err
	}
	return nil
}

// Claude documents policyHelper as an admin-only source. A helper configured
// by the OS-managed tier takes precedence over one in file policy; HKCU and
// remote/user/project occurrences are ignored by Claude and therefore do not
// affect this decision.
func claudeCodePolicyHelperSource(s claudeCodeManagedSourceSet) *claudeCodeSettingsSource {
	active := s.active()
	// Claude honors policyHelper only from the active OS-admin or file tier.
	// A non-empty remote source supersedes both, and a file helper is ignored
	// when an OS-admin policy wins.
	if active == nil || (active != s.osAdmin && active != s.file) {
		return nil
	}
	if raw, exists := active.settings["policyHelper"]; exists && raw != nil {
		return active
	}
	return nil
}

func validateClaudeCodeManagedHookControls(source *claudeCodeSettingsSource, managedHook bool) error {
	if source == nil {
		return nil
	}
	if raw, exists := source.settings["disableAllHooks"]; exists {
		disabled, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("Claude Code disableAllHooks from %s has unsupported type %T", source.label(), raw)
		}
		if disabled {
			return fmt.Errorf("Claude Code %s sets disableAllHooks=true", source.label())
		}
	}
	allowManagedOnly := false
	if raw, exists := source.settings["allowManagedHooksOnly"]; exists {
		value, ok := raw.(bool)
		if !ok {
			return fmt.Errorf("Claude Code allowManagedHooksOnly from %s has unsupported type %T", source.label(), raw)
		}
		allowManagedOnly = value
	}
	strictHooks := false
	if raw, exists := source.settings["strictPluginOnlyCustomization"]; exists {
		switch value := raw.(type) {
		case bool:
			strictHooks = value
		case []interface{}:
			for _, item := range value {
				name, ok := item.(string)
				if !ok {
					return fmt.Errorf("Claude Code strictPluginOnlyCustomization from %s contains unsupported value %T", source.label(), item)
				}
				if name == "hooks" {
					strictHooks = true
				}
			}
		default:
			return fmt.Errorf("Claude Code strictPluginOnlyCustomization from %s has unsupported type %T", source.label(), raw)
		}
	}
	if !managedHook && allowManagedOnly {
		return fmt.Errorf("Claude Code %s sets allowManagedHooksOnly=true, so the user-scoped DefenseClaw hooks are ignored", source.label())
	}
	if !managedHook && strictHooks {
		return fmt.Errorf("Claude Code %s restricts hooks to plugins or managed settings, so the user-scoped DefenseClaw hooks are ignored", source.label())
	}
	return nil
}

func claudeCodeSourceHasHookContract(source *claudeCodeSettingsSource, opts SetupOpts, diagnoseMissing bool) (bool, error) {
	if source == nil {
		return false, nil
	}
	rawHooks, exists := source.settings["hooks"]
	if !exists {
		if diagnoseMissing {
			return false, fmt.Errorf("Claude Code %s has no hooks table containing the DefenseClaw contract", source.label())
		}
		return false, nil
	}
	hooks, ok := rawHooks.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("Claude Code hooks from %s have unsupported type %T", source.label(), rawHooks)
	}
	for _, group := range hookGroups {
		entries, ok := hooks[group.eventType].([]interface{})
		if !ok || !claudeCodeEventHasEnforcingHook(entries, group.eventType, group.matcher, group.async, opts) {
			if diagnoseMissing {
				return false, fmt.Errorf("Claude Code %s does not contain the enforcing DefenseClaw %s hook", source.label(), group.eventType)
			}
			return false, nil
		}
	}
	return true, nil
}

type claudeCodeUserSourceSet struct {
	cli     *claudeCodeSettingsSource
	local   *claudeCodeSettingsSource
	project *claudeCodeSettingsSource
	user    *claudeCodeSettingsSource
}

func (s claudeCodeUserSourceSet) highToLow() []*claudeCodeSettingsSource {
	return []*claudeCodeSettingsSource{s.cli, s.local, s.project, s.user}
}

func inspectClaudeCodeUserSources(opts SetupOpts) (claudeCodeUserSourceSet, error) {
	var result claudeCodeUserSourceSet
	user, err := readOptionalClaudeCodeSettings("user settings", claudeCodeSettingsPath())
	if err != nil {
		return result, err
	}
	result.user = user

	workspace := strings.TrimSpace(opts.WorkspaceDir)
	if workspace != "" {
		workspace, err = filepath.Abs(workspace)
		if err != nil {
			return result, fmt.Errorf("resolve Claude Code workspace settings root %s: %w", opts.WorkspaceDir, err)
		}
		projectRoot := filepath.Join(filepath.Clean(workspace), ".claude")
		project, err := readOptionalClaudeCodeSettings("project settings", filepath.Join(projectRoot, "settings.json"))
		if err != nil {
			return result, err
		}
		local, err := readOptionalClaudeCodeSettings("local project settings", filepath.Join(projectRoot, "settings.local.json"))
		if err != nil {
			return result, err
		}
		result.project = project
		result.local = local
	}

	if raw := strings.TrimSpace(opts.ClaudeSettingsOverride); raw != "" {
		cli, err := readClaudeCodeCLISettings(raw, workspace)
		if err != nil {
			return result, err
		}
		result.cli = cli
	}
	return result, nil
}

func effectiveClaudeCodeUserHooksDisabled(sources claudeCodeUserSourceSet) (bool, *claudeCodeSettingsSource, error) {
	for _, source := range sources.highToLow() {
		if source == nil {
			continue
		}
		if rawHooks, exists := source.settings["hooks"]; exists {
			if _, ok := rawHooks.(map[string]interface{}); !ok {
				return false, source, fmt.Errorf("Claude Code hooks from %s have unsupported type %T", source.label(), rawHooks)
			}
		}
		if raw, exists := source.settings["disableAllHooks"]; exists {
			disabled, ok := raw.(bool)
			if !ok {
				return false, source, fmt.Errorf("Claude Code disableAllHooks from %s has unsupported type %T", source.label(), raw)
			}
			return disabled, source, nil
		}
	}
	return false, nil, nil
}

func readClaudeCodeCLISettings(raw, workspace string) (*claudeCodeSettingsSource, error) {
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		settings, err := decodeClaudeCodeSettings([]byte(raw), "CLI --settings inline JSON")
		if err != nil {
			return nil, err
		}
		return &claudeCodeSettingsSource{name: "CLI --settings", path: "inline JSON", settings: settings}, nil
	}
	path := os.ExpandEnv(raw)
	if strings.HasPrefix(path, "~"+string(filepath.Separator)) || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		path = filepath.Join(userHomeDir(), path[2:])
	}
	if !filepath.IsAbs(path) {
		base := workspace
		if base == "" {
			var err error
			base, err = os.Getwd()
			if err != nil {
				return nil, fmt.Errorf("resolve Claude Code CLI --settings working directory: %w", err)
			}
		}
		path = filepath.Join(base, path)
	}
	settings, err := readRequiredClaudeCodeSettings("CLI --settings", filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func claudeCodeRemoteSettingsPath() string {
	if root := strings.TrimSpace(ClaudeCodeManagedSettingsRootOverride); root != "" {
		return filepath.Join(root, ".remote-settings.json")
	}
	// ClaudeCodeSettingsPathOverride is a package test seam. Keep every
	// effective-settings source inside the same fixture root so connector tests
	// never consume a developer machine's cached remote enterprise policy.
	if override := strings.TrimSpace(ClaudeCodeSettingsPathOverride); override != "" {
		return filepath.Join(filepath.Dir(override), ".remote-settings.json")
	}
	return filepath.Join(claudeCodeConfigDir(), "remote-settings.json")
}

func claudeCodeManagedSettingsRoot() string {
	if override := strings.TrimSpace(ClaudeCodeManagedSettingsRootOverride); override != "" {
		return filepath.Clean(override)
	}
	if ClaudeCodeSettingsPathOverride != "" {
		return filepath.Join(filepath.Dir(ClaudeCodeSettingsPathOverride), ".managed-settings")
	}
	switch runtime.GOOS {
	case "windows":
		programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
		if programFiles == "" {
			programFiles = `C:\Program Files`
		}
		return filepath.Join(programFiles, "ClaudeCode")
	case "darwin":
		return "/Library/Application Support/ClaudeCode"
	default:
		return "/etc/claude-code"
	}
}

func readClaudeCodeManagedFileSettings() (*claudeCodeSettingsSource, error) {
	root := claudeCodeManagedSettingsRoot()
	paths := []string{filepath.Join(root, "managed-settings.json")}
	dropin := filepath.Join(root, "managed-settings.d")
	entries, err := os.ReadDir(dropin)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Claude Code managed settings drop-ins %s: %w", dropin, err)
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(strings.ToLower(name), ".json") {
			continue
		}
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	for _, name := range names {
		paths = append(paths, filepath.Join(dropin, name))
	}

	merged := map[string]interface{}{}
	var loaded []string
	for _, path := range paths {
		source, err := readOptionalClaudeCodeSettings("file-based managed settings", path)
		if err != nil {
			return nil, err
		}
		if source == nil {
			continue
		}
		merged = mergeClaudeCodeSettings(merged, source.settings)
		loaded = append(loaded, path)
	}
	if len(loaded) == 0 {
		return nil, nil
	}
	return &claudeCodeSettingsSource{
		name:     "file-based managed settings",
		path:     strings.Join(loaded, ", "),
		settings: merged,
	}, nil
}

func mergeClaudeCodeSettings(lower, higher map[string]interface{}) map[string]interface{} {
	result := cloneClaudeCodeSettingsMap(lower)
	for key, value := range higher {
		if higherMap, ok := value.(map[string]interface{}); ok {
			if lowerMap, ok := result[key].(map[string]interface{}); ok {
				result[key] = mergeClaudeCodeSettings(lowerMap, higherMap)
				continue
			}
			result[key] = cloneClaudeCodeSettingsMap(higherMap)
			continue
		}
		if higherList, ok := value.([]interface{}); ok {
			if lowerList, ok := result[key].([]interface{}); ok {
				combined := append([]interface{}{}, lowerList...)
				for _, item := range higherList {
					duplicate := false
					for _, existing := range combined {
						if jsonValuesEqual(existing, item) {
							duplicate = true
							break
						}
					}
					if !duplicate {
						combined = append(combined, item)
					}
				}
				result[key] = combined
				continue
			}
			result[key] = append([]interface{}{}, higherList...)
			continue
		}
		result[key] = value
	}
	return result
}

func cloneClaudeCodeSettingsMap(source map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func jsonValuesEqual(left, right interface{}) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func readOptionalClaudeCodeSettings(name, path string) (*claudeCodeSettingsSource, error) {
	data, exists, err := readStableClaudeCodeSettingsFile(path)
	if err != nil {
		return nil, fmt.Errorf("inspect Claude Code %s %s: %w", name, path, err)
	}
	if !exists {
		return nil, nil
	}
	settings, err := decodeClaudeCodeSettings(data, fmt.Sprintf("%s (%s)", name, path))
	if err != nil {
		return nil, err
	}
	return &claudeCodeSettingsSource{name: name, path: path, settings: settings}, nil
}

func readRequiredClaudeCodeSettings(name, path string) (*claudeCodeSettingsSource, error) {
	source, err := readOptionalClaudeCodeSettings(name, path)
	if err != nil {
		return nil, err
	}
	if source == nil {
		return nil, fmt.Errorf("Claude Code %s file is missing: %s", name, path)
	}
	return source, nil
}

func decodeClaudeCodeSettings(data []byte, source string) (map[string]interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	settings := map[string]interface{}{}
	if err := decoder.Decode(&settings); err != nil {
		return nil, fmt.Errorf("parse Claude Code %s: %w", source, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return nil, fmt.Errorf("parse Claude Code %s: %w", source, err)
	}
	return settings, nil
}

func readStableClaudeCodeSettingsFile(path string) ([]byte, bool, error) {
	before, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, true, fmt.Errorf("settings source is not a regular file")
	}
	if before.Size() > claudeCodeSettingsReadLimit {
		return nil, true, fmt.Errorf("settings source exceeds %d bytes", claudeCodeSettingsReadLimit)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, true, err
	}
	opened, statErr := file.Stat()
	data, readErr := io.ReadAll(io.LimitReader(file, claudeCodeSettingsReadLimit+1))
	closeErr := file.Close()
	if statErr != nil {
		return nil, true, statErr
	}
	if readErr != nil {
		return nil, true, readErr
	}
	if closeErr != nil {
		return nil, true, closeErr
	}
	if int64(len(data)) > claudeCodeSettingsReadLimit {
		return nil, true, fmt.Errorf("settings source exceeds %d bytes", claudeCodeSettingsReadLimit)
	}
	after, err := os.Lstat(path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() ||
		!os.SameFile(before, opened) || !os.SameFile(opened, after) ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, true, fmt.Errorf("settings source changed during inspection")
	}
	return data, true, nil
}
