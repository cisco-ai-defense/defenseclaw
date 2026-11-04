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
)

// Claude Cowork (the agent mode of Claude Desktop) does not read
// ~/.claude/settings.json. It loads hooks from the plugins of the user's Claude
// account and runs them on the device, as the user, as children of Claude
// Desktop's bundled Claude Code (the Cowork host loop). The per-user route
// (`defenseclaw setup cowork`) therefore builds an account plugin whose
// hooks/hooks.json runs the handler Setup writes for Claude Code: the same
// command and arguments, matchers and timeouts, so every Cowork event reaches
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

// coworkMissingHookGuardMessage is what Cowork shows when the Unix hook script
// exists but cannot be run (DefenseClaw is installed and broken). Like the
// Claude Code sentence it names no script file, and its repair works after
// the data folder is gone: the plugin lives in the Claude account, not in a
// file.
const coworkMissingHookGuardMessage = "DefenseClaw blocked this: its Claude Code hook script is missing " +
	"or cannot be run. Run the DefenseClaw installer, then defenseclaw setup cowork, to repair it, " +
	"or remove the DefenseClaw plugin in Claude (Customize, Plugins)."

// coworkUninstalledMessage is what the plugin says when DefenseClaw is no
// longer on this computer: the per-user uninstall deletes the hook (script or
// launcher), but it cannot remove an account plugin, which stays installed in
// Claude (cowork-1-0-8 GAP-0051). The plugin then lets the call go ahead (the
// per-user install fails open) and says how to remove it. The sentence holds
// no quote, apostrophe or cmd.exe metacharacter (ampersand, pipe, angle
// brackets, parentheses, caret, percent): the Unix guard prints it inside
// single quotes and inside a JSON string, and the Windows guard passes it to
// cmd.exe echo one word per argument.
const coworkUninstalledMessage = "DefenseClaw is no longer installed on this computer, so its Cowork plugin " +
	"checks nothing. Remove the plugin in Claude: Customize, Plugins, the ... menu of the DefenseClaw plugin, Remove."

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
	var command string
	var args []string
	if runtime.GOOS == "windows" {
		executable := strings.TrimSpace(opts.HookExecutable)
		if executable == "" {
			executable = defenseclawHookBinary()
		}
		if !filepath.IsAbs(executable) || !coworkRegularFile(executable) {
			return nil, fmt.Errorf("%w: the hook launcher %s is missing", ErrCoworkClaudeCodeNotSetUp, executable)
		}
		command, args = coworkWindowsHookInvocation(executable)
	} else {
		script := filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh")
		if !coworkRegularFile(script) {
			return nil, fmt.Errorf("%w: its hook script %s is missing", ErrCoworkClaudeCodeNotSetUp, script)
		}
		word := posixHookCommandWord(hookInvocationCommand("claudecode", filepath.ToSlash(script)))
		command = coworkUnixHookCommand(word)
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
		handler := map[string]interface{}{"type": "command", "command": command, "timeout": group.timeout}
		if group.async {
			handler["async"] = true
		}
		if args != nil {
			handler["args"] = args
			// Exec form (Windows): a launcher that is gone or cannot start, or
			// the guard exit 1, is a hook failure, and the call goes ahead
			// with the first stderr line in a "hook error" notice. That is
			// already the default for an exec-form hook; the field says so
			// explicitly (Claude Code 2.1.295 and later; Cowork measured on
			// 2.1.309 and 2.1.317), so a missing DefenseClaw never blocks. It
			// has no effect on Stop, SubagentStop and async hooks.
			if !group.async && group.eventType != "Stop" && group.eventType != "SubagentStop" {
				handler["onFailure"] = "continue"
			}
		}
		entry := map[string]interface{}{"hooks": []interface{}{handler}}
		if group.matcher != "" {
			entry["matcher"] = group.matcher
		}
		existing, _ := hooks[group.eventType].([]interface{})
		hooks[group.eventType] = append(existing, entry)
	}
	return json.MarshalIndent(map[string]interface{}{"hooks": hooks}, "", "  ")
}

// coworkUnixHookCommand is the shell form of every plugin handler on macOS
// and Linux. The hook script runs as the Claude Code handler does and its
// exits pass through unchanged, so verdicts, fail mode and cost are those of
// Claude Code. Only the shell 126 and 127 ("cannot run", "not found") are
// changed: when the script no longer exists, DefenseClaw was uninstalled
// (the per-user uninstall deletes the hooks folder), and the plugin answers
// exit 0 with a systemMessage, which Claude shows to the user, so Cowork
// keeps working until the plugin is removed (GAP-0051). A script that exists
// and cannot be run still blocks with exit 2, as the Claude Code handler
// does. The script stays the first shell word.
func coworkUnixHookCommand(word string) string {
	return word + claudeCodeMissingHookGuardSeparator +
		`[ "$rc" -eq 126 ] || [ "$rc" -eq 127 ] || exit "$rc"; ` +
		"if [ ! -e " + word + " ]; then " +
		`printf '%s\n' '{"systemMessage":"` + coworkUninstalledMessage + `"}'; ` +
		"echo '" + coworkUninstalledMessage + "' >&2; exit 0; fi; " +
		"echo '" + coworkMissingHookGuardMessage + "' >&2; exit 2; }"
}

// coworkWindowsHookInvocation is the exec form of every plugin handler on
// Windows, without Git Bash or PowerShell (cmd.exe is always present and
// starts in milliseconds):
//
//	cmd.exe /d /c if exist "<launcher>" ( "<launcher>" hook --connector claudecode )
//	        else ( echo <uninstalled sentence> 1>&2 & exit /b 1 )
//
// cmd.exe passes the launcher stdin, stdout, stderr and exit code through,
// so verdicts and fail mode are those of the Claude Code handler. When the
// launcher is gone (the per-user uninstall removes it) the guard exits 1, a
// non-blocking hook failure (onFailure "continue"): the call goes ahead and
// Claude shows the sentence in its hook error notice. Exit 0 would hide it
// (Claude never shows the stderr of an exit 0), and cmd.exe cannot print the
// JSON systemMessage: the spawn escapes the quotes of an argument. Unlike the
// Claude Code settings, PreToolUse runs the same guard, not launcher-guard:
// Cursor does not read Cowork plugins (GAP-1011 does not apply), and
// launcher-guard blocks when the launcher is missing and is removed with it.
// A launcher path cmd.exe cannot quote keeps the bare exec form; a missing
// launcher is then a non-blocking "cannot start" failure.
func coworkWindowsHookInvocation(launcher string) (string, []string) {
	hookArgs := []string{"hook", "--connector", "claudecode"}
	if !claudeCodeLauncherGuardable(launcher) {
		return launcher, hookArgs
	}
	args := []string{"/d", "/c", "if", "exist", launcher, "(", launcher}
	args = append(args, hookArgs...)
	args = append(args, ")", "else", "(", "echo")
	args = append(args, strings.Fields(coworkUninstalledMessage)...)
	args = append(args, "1>&2", "&", "exit", "/b", "1", ")")
	return claudeCodeWindowsCommandProcessor(), args
}

func coworkRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}
