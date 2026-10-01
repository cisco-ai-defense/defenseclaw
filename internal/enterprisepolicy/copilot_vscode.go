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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GitHub Copilot in VS Code runs agent-mode hooks in its Local harness. That
// harness does not read Copilot's machine policy.d directory, so DefenseClaw
// governs it with a per-user hook file and, where the lock is wanted, a
// per-user plugin that managed settings enable:
//
//   - ~/.copilot/hooks/defenseclaw-vscode.json: PascalCase events, each
//     running the administrator's hook binary with --hook-surface
//     vscode-local. The Copilot CLI also reads this directory and runs the
//     command field, so the gateway collapses the CLI's second delivery of
//     one tool call (see the gateway's Copilot dedupe).
//   - ~/.copilot/installed-plugins/defenseclaw/defenseclaw/: the same hooks
//     as a plugin, which VS Code keeps running when allowManagedHooksOnly
//     drops user hook files.
//
// Both are rendered from the administrator's hook binary only, so the guard
// recognizes every handler as DefenseClaw's by exact command equality.

// CopilotVSCodeLocalHookFileName is the per-user Local harness hook file.
const CopilotVSCodeLocalHookFileName = "defenseclaw-vscode.json"

// CopilotPluginMarketplace and CopilotPluginName name DefenseClaw's
// per-user Copilot plugin (enabledPlugins key "defenseclaw@defenseclaw").
const (
	CopilotPluginMarketplace = "defenseclaw"
	CopilotPluginName        = "defenseclaw"
	CopilotPluginKey         = CopilotPluginName + "@" + CopilotPluginMarketplace
)

// copilotVSCodeLocalHookTimeout is the handler timeout VS Code honors
// (seconds); the hook's gateway request finishes inside it.
const copilotVSCodeLocalHookTimeout = 30

// CopilotVSCodeLocalHookFilePath is the Local hook file under home.
func CopilotVSCodeLocalHookFilePath(home string) string {
	return filepath.Join(home, ".copilot", "hooks", CopilotVSCodeLocalHookFileName)
}

// CopilotPluginDir is DefenseClaw's plugin directory under home.
func CopilotPluginDir(home string) string {
	return filepath.Join(home, ".copilot", "installed-plugins", CopilotPluginMarketplace, CopilotPluginName)
}

// RenderCopilotVSCodeLocalHooks renders the Local harness hook document for
// the administrator's hook binary on goos.
func RenderCopilotVSCodeLocalHooks(goos, hookBinary string) ([]byte, error) {
	if strings.TrimSpace(hookBinary) == "" {
		return nil, errors.New("copilot vscode local hooks: hook binary is empty")
	}
	hooks := newObject()
	for _, event := range connector.CopilotVSCodeLocalHookEvents {
		handler := newObject()
		handler.set("type", "command")
		handler.set("command", connector.CopilotVSCodeLocalManagedHookCommand(goos, hookBinary, event))
		handler.set("timeout", copilotVSCodeLocalHookTimeout)
		hooks.set(event, []any{handler})
	}
	doc := newObject()
	doc.set("hooks", hooks)
	return encodeOrdered(doc)
}

// renderCopilotPluginManifest is the plugin's manifest; hooks load from the
// plugin's hooks/hooks.json.
func renderCopilotPluginManifest() ([]byte, error) {
	doc := newObject()
	doc.set("name", CopilotPluginName)
	doc.set("description", "DefenseClaw guardrail hooks")
	doc.set("version", "1.0.0")
	doc.set("hooks", "hooks/hooks.json")
	return encodeOrdered(doc)
}

// copilotVSCodeLocalCommandOwned reports whether command is exactly the
// Local harness command DefenseClaw renders for one of its events.
func copilotVSCodeLocalCommandOwned(goos, hookBinary, command string) bool {
	if strings.TrimSpace(hookBinary) == "" || command == "" {
		return false
	}
	for _, event := range connector.CopilotVSCodeLocalHookEvents {
		if command == strings.TrimSpace(connector.CopilotVSCodeLocalManagedHookCommand(goos, hookBinary, event)) {
			return true
		}
	}
	return false
}

// CopilotVSCodeUserResult reports one user's Local hook file and plugin.
type CopilotVSCodeUserResult struct {
	HookFile   string   `json:"hook_file,omitempty"`
	PluginDir  string   `json:"plugin_dir,omitempty"`
	Changed    []string `json:"changed,omitempty"`
	Removed    []string `json:"removed,omitempty"`
	Kept       []string `json:"kept,omitempty"`
	PluginOK   bool     `json:"plugin_ok,omitempty"`
	HookFileOK bool     `json:"hook_file_ok,omitempty"`
}

// CopilotVSCodeUserRequest selects what the user's home should hold. It runs
// as the user (the Unix per-user worker, or the Windows target-user
// impersonation), never as the administrator in a user's home.
type CopilotVSCodeUserRequest struct {
	Home       string
	GOOS       string
	HookBinary string
	// HookFile keeps the Local hook file; false removes DefenseClaw's copy.
	HookFile bool
	// Plugin keeps the plugin; false removes DefenseClaw's copy.
	Plugin bool
	// DryRun reports in Changed and Removed what would change, touching
	// nothing (verify).
	DryRun bool
}

// EnsureCopilotVSCodeUser writes or removes DefenseClaw's Local hook file
// and plugin under Home. A file that holds anything DefenseClaw did not
// render is left alone and reported in Kept: it is the user's, and the
// foreign-hook guard judges it.
func EnsureCopilotVSCodeUser(req CopilotVSCodeUserRequest) (CopilotVSCodeUserResult, error) {
	var result CopilotVSCodeUserResult
	home := strings.TrimSpace(req.Home)
	if home == "" || !filepath.IsAbs(home) {
		return result, fmt.Errorf("copilot vscode: home %q is not absolute", req.Home)
	}
	goos := req.GOOS
	if goos == "" {
		goos = runtimeGOOS()
	}
	hooks, err := RenderCopilotVSCodeLocalHooks(goos, req.HookBinary)
	if err != nil {
		return result, err
	}
	owned := GuardRequest{GOOS: goos, HookBinary: req.HookBinary}
	var errs []error
	result.HookFile = CopilotVSCodeLocalHookFilePath(home)
	if ok, err := ensureOwnedUserFile(&result, owned, result.HookFile, hooks, req.HookFile, true, req.DryRun); err != nil {
		errs = append(errs, err)
	} else {
		result.HookFileOK = ok
	}
	result.PluginDir = CopilotPluginDir(home)
	manifest, err := renderCopilotPluginManifest()
	if err != nil {
		return result, err
	}
	pluginHooks := filepath.Join(result.PluginDir, "hooks", "hooks.json")
	pluginManifest := filepath.Join(result.PluginDir, "plugin.json")
	hooksOK, err := ensureOwnedUserFile(&result, owned, pluginHooks, hooks, req.Plugin, true, req.DryRun)
	if err != nil {
		errs = append(errs, err)
	}
	manifestOK, err := ensureOwnedUserFile(&result, owned, pluginManifest, manifest, req.Plugin, false, req.DryRun)
	if err != nil {
		errs = append(errs, err)
	}
	result.PluginOK = req.Plugin && hooksOK && manifestOK
	if !req.Plugin && !req.DryRun {
		// Remove the now-empty plugin directories we created.
		for _, dir := range []string{filepath.Join(result.PluginDir, "hooks"), result.PluginDir, filepath.Dir(result.PluginDir)} {
			_ = os.Remove(dir)
		}
	}
	return result, errors.Join(errs...)
}

// ensureOwnedUserFile makes path hold want (keep) or not exist (!keep),
// touching it only when it is absent or DefenseClaw's own. It reports
// whether path now holds want.
func ensureOwnedUserFile(result *CopilotVSCodeUserResult, owned GuardRequest, path string, want []byte, keep, hooksDoc, dryRun bool) (bool, error) {
	info, err := os.Lstat(path)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	var current []byte
	if exists {
		if !info.Mode().IsRegular() {
			result.Kept = append(result.Kept, path)
			return false, fmt.Errorf("%s is not a regular file", path)
		}
		if current, err = os.ReadFile(path); err != nil {
			return false, err
		}
		if !bytes.Equal(current, want) && !(hooksDoc && owned.ownedHooksDocument(current)) {
			result.Kept = append(result.Kept, path)
			return false, nil
		}
	}
	if !keep {
		if exists {
			if !dryRun {
				if err := os.Remove(path); err != nil {
					return false, err
				}
			}
			result.Removed = append(result.Removed, path)
		}
		return false, nil
	}
	if exists && bytes.Equal(current, want) {
		return true, nil
	}
	if dryRun {
		result.Changed = append(result.Changed, path)
		return false, nil
	}
	if err := writePrivateUserFile(path, want); err != nil {
		return false, err
	}
	result.Changed = append(result.Changed, path)
	return true, nil
}

// ownedHooksDocument reports a flat hook document whose every handler is
// DefenseClaw's own (an earlier render for another binary path is not).
func (r GuardRequest) ownedHooksDocument(data []byte) bool {
	doc, _, err := decodeGuardDocument(data)
	if err != nil {
		return false
	}
	for _, key := range doc.keys {
		if key != "hooks" && key != "version" {
			return false
		}
	}
	value, _ := doc.get("hooks")
	hooks, ok := value.(*object)
	if !ok {
		return false
	}
	handlers := 0
	for _, event := range hooks.keys {
		value, _ := hooks.get(event)
		list, ok := value.([]any)
		if !ok {
			return false
		}
		for _, handler := range list {
			if !r.ownedHandler(handler) {
				return false
			}
			handlers++
		}
	}
	return handlers > 0
}

// CopilotVSCodeUserState reports, read-only, whether home holds
// DefenseClaw's current Local hook file and plugin (verify and status).
func CopilotVSCodeUserState(home, goos, hookBinary string) (hookFile, plugin bool) {
	hooks, err := RenderCopilotVSCodeLocalHooks(goos, hookBinary)
	if err != nil {
		return false, false
	}
	manifest, _ := renderCopilotPluginManifest()
	same := func(path string, want []byte) bool {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return false
		}
		data, err := os.ReadFile(path)
		return err == nil && bytes.Equal(data, want)
	}
	dir := CopilotPluginDir(home)
	return same(CopilotVSCodeLocalHookFilePath(home), hooks),
		same(filepath.Join(dir, "hooks", "hooks.json"), hooks) && same(filepath.Join(dir, "plugin.json"), manifest)
}
