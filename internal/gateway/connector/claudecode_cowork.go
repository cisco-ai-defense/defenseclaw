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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// Claude Cowork (the agent mode of Claude Desktop) does not read
// ~/.claude/settings.json. It loads hooks from the plugins of the user's Claude
// account and runs them on the device, as the user, as children of Claude
// Desktop's bundled Claude Code (the Cowork host loop). The per-user route
// (`defenseclaw setup cowork`) therefore builds an account plugin whose
// hooks/hooks.json runs the handler Setup writes for Claude Code behind an
// account-removal check, with the same matchers and timeouts. Cowork events reach
// the gateway's Claude Code hook route with the Claude Code connector's
// credential. Managed hosts get Cowork coverage from the Claude Code machine
// policy (ManagedHookPolicy), which Cowork's host loop also runs.

// CoworkPluginHookEvents are the Claude Code hook events Cowork's host loop
// runs, measured on Claude Desktop 4.4212.0 (engine 2.1.309). An event name
// Claude does not know can make it refuse a plugin, so the plugin registers
// only these.
var CoworkPluginHookEvents = []string{
	"SessionStart",
	"UserPromptSubmit",
	"PreToolUse",
	"PermissionRequest",
	"PostToolUse",
	"PostToolUseFailure",
	"SubagentStart",
	"SubagentStop",
	"Stop",
	"SessionEnd",
}

// coworkMissingHookGuardMessage is what the plugin returns when the Unix hook script
// cannot start (claudeCodeMissingHookGuardWith). Like the Claude Code
// sentence it names no script file, and its repair works after the data
// folder is gone: the plugin lives in the Claude account, not in a file.
const coworkMissingHookGuardMessage = "DefenseClaw blocked this: its Claude Code hook script is missing " +
	"or cannot be run. Run the DefenseClaw installer, then defenseclaw setup cowork, to repair it, " +
	"or remove the DefenseClaw plugin in Claude (Customize, Plugins)."

const coworkRemovalMarkerSuffix = hookguard.CoworkRemovalMarkerSuffix

// ErrCoworkClaudeCodeNotSetUp means the Claude Code connector, whose hook and
// credential the Cowork plugin runs, has not been set up in the data
// directory.
var ErrCoworkClaudeCodeNotSetUp = errors.New("the Claude Code connector is not set up")

// CoworkPluginHooks renders the hooks/hooks.json document of the DefenseClaw
// Cowork plugin for this account: {"hooks": {<event>: [<group>]}}. It refuses
// a managed install, and a data directory where the Claude Code connector's
// Setup has not run (no hook contract lock entry, or no hook runner).
func CoworkPluginHooks(opts SetupOpts) ([]byte, error) {
	if opts.ManagedEnterprise {
		return nil, fmt.Errorf("this DefenseClaw is managed by your organization; " +
			"Cowork is covered by the Claude Code machine policy, not by an account plugin")
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return nil, fmt.Errorf("no DefenseClaw data directory")
	}
	if LoadHookContractLockEntry(opts.DataDir, "claudecode").ContractID == "" {
		return nil, fmt.Errorf("%w: its hooks were never installed in %s", ErrCoworkClaudeCodeNotSetUp, opts.DataDir)
	}
	var command, launcher string
	var args []string
	if runtime.GOOS == "windows" {
		executable := strings.TrimSpace(opts.HookExecutable)
		if executable == "" {
			executable = defenseclawHookBinary()
		}
		if !filepath.IsAbs(executable) || !coworkRegularFile(executable) {
			return nil, fmt.Errorf("%w: the hook launcher %s is missing", ErrCoworkClaudeCodeNotSetUp, executable)
		}
		if coworkWindowsGuardExecutable(executable) == "" {
			return nil, fmt.Errorf("%w: the hook guard for %s is missing", ErrCoworkClaudeCodeNotSetUp, executable)
		}
		launcher = executable
	} else {
		script := filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh")
		if !coworkRegularFile(script) {
			return nil, fmt.Errorf("%w: its hook script %s is missing", ErrCoworkClaudeCodeNotSetUp, script)
		}
	}
	registry := make(map[string]claudeCodeHookGroup, len(hookGroups))
	for _, group := range hookGroups {
		registry[group.eventType] = group
	}
	groups := make([]claudeCodeHookGroup, 0, len(CoworkPluginHookEvents))
	for _, event := range CoworkPluginHookEvents {
		group, ok := registry[event]
		if !ok {
			return nil, fmt.Errorf("Claude Code has no hook group for the Cowork event %s", event) //nolint:staticcheck // Keep the product name first.
		}
		groups = append(groups, group)
	}
	hooks := map[string]interface{}{}
	for _, group := range groups {
		if runtime.GOOS == "windows" {
			command, args = coworkWindowsHookInvocation(opts.DataDir, launcher, group.eventType)
		} else {
			command = coworkUnixHookCommand(opts.DataDir, filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"), group.eventType)
		}
		appendClaudeCodeHookGroups(hooks, command, args, []claudeCodeHookGroup{group})
	}
	return json.MarshalIndent(map[string]interface{}{"hooks": hooks}, "", "  ")
}

// The marker is written only after per-user removal completes. The local
// installation records must also be absent, so a retained marker cannot turn
// a later installation or an incomplete removal into an unguarded hook.
func coworkRemovalPaths(dataDir string) (marker string, installed []string) {
	return hookguard.CoworkRemovalPaths(dataDir)
}

func coworkUninstalledJSON(event string, notice bool) string {
	return hookguard.CoworkUninstalledJSON(event, notice)
}

func coworkUnixHookCommand(dataDir, script, event string) string {
	marker, installed := coworkRemovalPaths(dataDir)
	missing := func(path string) string {
		quoted := shellSingleQuote(path)
		return "[ ! -e " + quoted + " ] && [ ! -L " + quoted + " ]"
	}
	condition := "[ -f " + shellSingleQuote(marker) + " ]"
	for _, path := range append(installed, script) {
		condition += " && " + missing(path)
	}
	noticeDir := shellSingleQuote(marker + ".notice")
	var notice string
	if event == "UserPromptSubmit" {
		contextDir := shellSingleQuote(marker + ".context")
		notice = "if mkdir " + contextDir + " 2>/dev/null; then if mkdir " + noticeDir +
			" 2>/dev/null; then printf '%s\\n' " + shellSingleQuote(coworkUninstalledJSON(event, true)) +
			"; else printf '%s\\n' " + shellSingleQuote(coworkUninstalledJSON(event, false)) + "; fi; fi; "
	} else {
		notice = "if mkdir " + noticeDir + " 2>/dev/null; then printf '%s\\n' " +
			shellSingleQuote(coworkUninstalledJSON(event, true)) + "; fi; "
	}
	word := posixHookCommandWord(hookInvocationCommand("claudecode", filepath.ToSlash(script)))
	return "if " + condition + "; then " + notice + "exit 0; fi; " +
		claudeCodeMissingHookGuardWith(word, coworkMissingHookGuardMessage)
}

func coworkWindowsHookInvocation(dataDir, launcher, event string) (string, []string) {
	return coworkWindowsGuardExecutable(launcher), []string{hookguard.CoworkSubcommand, dataDir, launcher, event}
}

// Setup copies this small installed guard into the Cowork plugin. The plugin
// keeps running it after installed binaries are removed, while it continues
// to run the live launcher for installed accounts.
func coworkWindowsGuardExecutable(launcher string) string {
	return coworkWindowsGuardFor(launcher, canonicalNativeWindowsHookBinary(), canonicalNativeWindowsInstalledHookBinary())
}

func coworkWindowsGuardFor(launcher, stable, installed string) string {
	if stable != "" && installed != "" && pathidentity.Same(launcher, stable) &&
		!pathidentity.Same(installed, stable) && hookguard.AbsoluteHookExecutable(installed) {
		guard := filepath.Join(filepath.Dir(installed), windowsHookGuardBinaryName)
		if info, err := os.Lstat(guard); err == nil && info.Mode().IsRegular() {
			return guard
		}
	}
	guard := filepath.Join(filepath.Dir(launcher), windowsHookGuardBinaryName)
	if info, err := os.Lstat(guard); err == nil && info.Mode().IsRegular() &&
		filepath.IsAbs(guard) && !pathidentity.Same(guard, launcher) {
		return guard
	}
	return ""
}

func coworkRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
