// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// An enterprise install renders a VS Code Local hook file
// (~/.copilot/hooks/defenseclaw-vscode.json) and a Copilot plugin
// (~/.copilot/installed-plugins/defenseclaw/defenseclaw) that run the
// administrator's hook binary. An enterprise uninstall from before MAC-U2-06
// left both behind with the binary gone. The Copilot CLI reads that hooks
// folder, its hook command fails, and it denies every tool call.
const (
	orphanCopilotVSCodeHookFile  = "defenseclaw-vscode.json"
	orphanCopilotPluginMarket    = "defenseclaw"
	orphanCopilotPluginName      = "defenseclaw"
	orphanCopilotVSCodeCmdMiddle = "' hook --connector copilot --enterprise-managed --event '"
)

// RemoveOrphanedCopilotVSCodeLocalRenders removes those leftovers under
// home: only a hook document whose every handler is the enterprise
// vscode-local command for one absolute hook binary that no longer exists.
// A file with anything else (the user's own hooks, or a live enterprise
// render) is left alone. It returns the paths it removed. On Windows the
// enterprise uninstall owns these files, so it does nothing there.
func RemoveOrphanedCopilotVSCodeLocalRenders(home string) ([]string, error) {
	if runtime.GOOS == "windows" || strings.TrimSpace(home) == "" || !filepath.IsAbs(home) {
		return nil, nil
	}
	var removed []string
	var errs []error
	hookFile := filepath.Join(home, ".copilot", "hooks", orphanCopilotVSCodeHookFile)
	if orphanedCopilotVSCodeLocalDocument(hookFile) {
		if err := os.Remove(hookFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		} else {
			removed = append(removed, hookFile)
		}
	}
	market := filepath.Join(home, ".copilot", "installed-plugins", orphanCopilotPluginMarket)
	plugin := filepath.Join(market, orphanCopilotPluginName)
	pluginHooks := filepath.Join(plugin, "hooks", "hooks.json")
	if orphanedCopilotVSCodeLocalDocument(pluginHooks) && orphanCopilotPluginHoldsOnlyRenders(plugin) {
		for _, path := range []string{pluginHooks, filepath.Join(plugin, "plugin.json")} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}
		}
		for _, dir := range []string{filepath.Join(plugin, "hooks"), plugin, market} {
			_ = os.Remove(dir)
		}
		removed = append(removed, plugin)
	}
	return removed, errors.Join(errs...)
}

// orphanCopilotPluginHoldsOnlyRenders reports a plugin folder holding only
// what the enterprise install rendered there (plugin.json, hooks/hooks.json).
func orphanCopilotPluginHoldsOnlyRenders(plugin string) bool {
	entries, err := os.ReadDir(plugin)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		switch {
		case entry.Name() == "plugin.json" && entry.Type().IsRegular():
		case entry.Name() == "hooks" && entry.IsDir():
			hooks, err := os.ReadDir(filepath.Join(plugin, "hooks"))
			if err != nil || len(hooks) != 1 || hooks[0].Name() != "hooks.json" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// orphanedCopilotVSCodeLocalDocument reports a regular file holding a hook
// document whose every handler is the enterprise vscode-local command (the
// current render or the one 1.0.0 wrote) for one absolute hook binary that
// no longer exists.
func orphanedCopilotVSCodeLocalDocument(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return false
	}
	for key := range doc {
		if key != "hooks" && key != "version" {
			return false
		}
	}
	var hooks map[string][]map[string]any
	if err := json.Unmarshal(doc["hooks"], &hooks); err != nil {
		return false
	}
	binary := ""
	handlers := 0
	for event, list := range hooks {
		for _, handler := range list {
			command, _ := handler["command"].(string)
			bin, ok := orphanCopilotVSCodeCommandBinary(command)
			if !ok || (binary != "" && bin != binary) ||
				(command != CopilotVSCodeLocalManagedHookCommand(runtime.GOOS, bin, event) &&
					command != CopilotVSCodeLocalPriorReleaseHookCommand(runtime.GOOS, bin, event)) {
				return false
			}
			binary = bin
			handlers++
		}
	}
	if handlers == 0 || !filepath.IsAbs(binary) {
		return false
	}
	_, err = os.Lstat(binary)
	return errors.Is(err, os.ErrNotExist)
}

// orphanCopilotVSCodeCommandBinary returns the hook binary a POSIX
// vscode-local command runs (the single-quoted word before " hook", after
// the removed-deployment guard's exec).
func orphanCopilotVSCodeCommandBinary(command string) (string, bool) {
	if _, rest, ok := strings.Cut(command, "|| exit 0; exec "); ok {
		command = rest
	}
	idx := strings.Index(command, orphanCopilotVSCodeCmdMiddle)
	if !strings.HasPrefix(command, "'") || idx < 1 {
		return "", false
	}
	return strings.ReplaceAll(command[1:idx], `'"'"'`, "'"), true
}

// removeOrphanedCopilotVSCodeLocalRendersForPerUser runs the cleanup for a
// per-user Copilot setup or teardown, best effort: a leftover that stays is
// the uninstall's to report, not a reason to fail the user's own setup.
func removeOrphanedCopilotVSCodeLocalRendersForPerUser(opts SetupOpts) {
	if opts.ManagedEnterprise {
		return
	}
	_, _ = RemoveOrphanedCopilotVSCodeLocalRenders(userHomeDir())
	if !copilotManagedHost() {
		removeLeftoverCopilotManagedPluginKey(copilotMachineManagedSettingsPath(), os.Stderr)
	}
}

// A managed install adds enabledPlugins["defenseclaw@defenseclaw"] = true to
// Copilot's machine managed-settings file while it deploys its per-user
// plugin, and its uninstall removes it (GAP-1245). An uninstall before that
// fix left the key behind. On a computer without a managed install the key
// only names a plugin no marketplace has, so the Copilot CLI warns at every
// start that its organization admin requires defenseclaw@defenseclaw and
// that the marketplace "defenseclaw" is not found (GAP-1254). A per-user
// Copilot setup or teardown therefore removes that one key when it holds
// true (the file itself when nothing else is left in it), and leaves every
// other setting, the key with any other value, and the file of a managed
// computer alone. Only an administrator can write the file: a setup that
// cannot says which file and key to remove.
const copilotManagedPluginKey = "defenseclaw@defenseclaw"

// copilotMachineManagedSettingsPath is Copilot's machine managed-settings
// file ("" on macOS, where DefenseClaw never writes it). Tests replace it.
var copilotMachineManagedSettingsPath = func() string {
	switch runtime.GOOS {
	case "windows":
		programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
		if programFiles == "" || !filepath.IsAbs(programFiles) {
			programFiles = `C:\Program Files`
		}
		return filepath.Join(programFiles, "GitHubCopilot", "managed-settings.json")
	case "linux":
		return "/etc/github-copilot/managed-settings.json"
	}
	return ""
}

// copilotManagedHost reports a computer with a managed DefenseClaw install,
// whose lifecycle owns the key. Tests replace it.
var copilotManagedHost = managed.IsStandaloneManagedHost

// removeLeftoverCopilotManagedPluginKey removes the leftover key from the
// managed-settings file at path, best effort. It reports whether it did.
func removeLeftoverCopilotManagedPluginKey(path string, warn io.Writer) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	data, ok := ReadStableInventoryFile(path, copilotSettingsMaxBytes)
	if !ok {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil || doc == nil {
		return false
	}
	var plugins map[string]json.RawMessage
	if json.Unmarshal(doc["enabledPlugins"], &plugins) != nil {
		return false
	}
	var enabled bool
	if json.Unmarshal(plugins[copilotManagedPluginKey], &enabled) != nil || !enabled {
		return false
	}
	delete(plugins, copilotManagedPluginKey)
	if len(plugins) == 0 {
		delete(doc, "enabledPlugins")
	} else {
		doc["enabledPlugins"], _ = json.Marshal(plugins)
	}
	if len(doc) == 0 {
		err = os.Remove(path)
	} else {
		var out []byte
		if out, err = json.MarshalIndent(doc, "", "  "); err == nil {
			err = atomicWriteFile(path, append(out, '\n'), info.Mode().Perm())
		}
	}
	if err != nil {
		if warn != nil {
			fmt.Fprintf(warn, "defenseclaw: %s still sets enabledPlugins %q to true, left by an earlier managed DefenseClaw install; "+
				"the Copilot CLI warns at every start that the marketplace \"defenseclaw\" is not found. "+
				"An administrator can delete that entry from the file (this account cannot: %v).\n", path, copilotManagedPluginKey, err)
		}
		return false
	}
	return true
}
