// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"runtime"
	"sort"
	"strings"
)

// Agent settings that stop a shell-form hook command from running
// (rel-1-0-6:GAP-0322).
//
// Claude Code starts a hook command without "args" through /bin/sh -c, with
// its own environment plus the env block of every settings file it reads
// (user, project, local, --settings). On RHEL and macOS /bin/sh is bash, and
// bash reads SHELLOPTS from its environment: with SHELLOPTS=noexec it parsed
// the registered command and ran none of it, so no hook ran, the guard clause
// after the script did not run either, and the call went ahead. A repository
// can commit that env block in .claude/settings.json. CLAUDE_CODE_SHELL_PREFIX
// names a program Claude Code runs every shell-form hook command through, in
// place of the command. The hook scripts start with bash -p and ignore the
// other names themselves, but the shell that starts them is Claude Code's.
//
// The per-user registration keeps the shell form. Claude Code's exec form
// (command plus args, spawned with no shell) reports a hook it cannot spawn
// as a non-blocking error, so a script missing after a home move or an
// account rename would let every call run uninspected again (GAP-0542). An
// exec form that starts /bin/bash -p -c with the guard keeps that guard, but
// Cursor imports these hooks from ~/.claude/settings.json and runs only a
// handler's command, without its args (GAP-1011): bash would read Cursor's
// event JSON on stdin as a script. So the settings are checked instead, as
// disableAllHooks is: the strict tier refuses them (Setup and the effective
// policy check), and the default and permissive tiers keep running and warn
// (status, doctor and one gateway alert). The managed Claude Code drop-in
// pins the same names to "" in its env block, which outranks every user,
// project and process value (enterprisepolicy).

// hookShellEnvNames are the env names a settings file must not set for a
// shell-form hook command. A BASH_FUNC_ name (an exported function) counts too.
var hookShellEnvNames = []string{
	"BASHOPTS",
	"BASH_ENV",
	"CLAUDE_CODE_SHELL_PREFIX",
	"ENV",
	"FUNCNEST",
	"SHELLOPTS",
}

const hookShellEnvFunctionPrefix = "BASH_FUNC_"

// HookShellEnvPins returns hookShellEnvNames: the names a managed settings
// document pins to "" for its shell-form hook commands.
func HookShellEnvPins() []string {
	return append([]string(nil), hookShellEnvNames...)
}

func isHookShellEnvName(name string) bool {
	if strings.HasPrefix(name, hookShellEnvFunctionPrefix) {
		return true
	}
	for _, known := range hookShellEnvNames {
		if name == known {
			return true
		}
	}
	return false
}

// hookShellEnvTakesEffect reports whether a settings env value for name
// changes the shell: any value that is not empty. Claude Code passes "" as an
// empty variable, which none of these names reads as an option, a file or a
// prefix (the managed drop-in pins them that way). An exported function
// counts with any value.
func hookShellEnvTakesEffect(name string, value interface{}) bool {
	if strings.HasPrefix(name, hookShellEnvFunctionPrefix) {
		return true
	}
	text, ok := value.(string)
	if !ok {
		return value != nil
	}
	return strings.TrimSpace(text) != ""
}

// claudeCodeSettingsHookShellEnv returns the names the effective Claude Code
// env sets (sorted) and the sources that set them. Claude Code merges the env
// blocks name by name; the highest source that sets a name decides it, so an
// empty value in a higher source clears a lower one.
func claudeCodeSettingsHookShellEnv(sources claudeCodeUserSourceSet) ([]string, []*claudeCodeSettingsSource) {
	decided := map[string]bool{}
	var names []string
	var from []*claudeCodeSettingsSource
	for _, source := range sources.highToLow() {
		if source == nil {
			continue
		}
		env, _ := source.settings["env"].(map[string]interface{})
		keys := make([]string, 0, len(env))
		for key := range env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		setHere := false
		for _, key := range keys {
			if !isHookShellEnvName(key) || decided[key] {
				continue
			}
			decided[key] = true
			if hookShellEnvTakesEffect(key, env[key]) {
				names = append(names, key)
				setHere = true
			}
		}
		if setHere {
			from = append(from, source)
		}
	}
	sort.Strings(names)
	return names, from
}

// claudeCodeHookShellEnvProblem is the sentence for names set by from.
func claudeCodeHookShellEnvProblem(names []string, from []*claudeCodeSettingsSource) string {
	labels := make([]string, 0, len(from))
	for _, source := range from {
		labels = append(labels, source.label())
	}
	verb := "sets"
	if len(from) > 1 {
		verb = "set"
	}
	return fmt.Sprintf(
		"Claude Code %s %s %s in the env block, and Claude Code starts its hook commands through /bin/sh with that environment: a value such as SHELLOPTS=noexec stops every DefenseClaw hook from running",
		strings.Join(labels, " and "), verb, strings.Join(names, ", "),
	)
}

// claudeCodeHookShellEnvApplies reports whether opts registers shell-form
// Claude Code hooks this check covers: a per-user install outside Windows
// (Windows runs the native launcher without /bin/sh; a managed install pins
// the names in its drop-in).
func claudeCodeHookShellEnvApplies(opts SetupOpts) bool {
	return !opts.ManagedEnterprise && runtime.GOOS != "windows"
}

func strictPolicyTier(opts SetupOpts) bool {
	return strings.EqualFold(strings.TrimSpace(opts.PolicyTier), "strict")
}

// claudeCodeHookShellEnvRefusal is the strict-tier refusal, or nil.
func claudeCodeHookShellEnvRefusal(opts SetupOpts, sources claudeCodeUserSourceSet) error {
	if !claudeCodeHookShellEnvApplies(opts) || !strictPolicyTier(opts) {
		return nil
	}
	names, from := claudeCodeSettingsHookShellEnv(sources)
	if len(names) == 0 {
		return nil
	}
	return fmt.Errorf( //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		"%s; the strict policy tier refuses it: remove %s from that env block, then run: defenseclaw-gateway restart",
		claudeCodeHookShellEnvProblem(names, from), strings.Join(names, ", "),
	)
}

// HookShellEnvWarning returns the warning status, doctor and the gateway's
// alert carry when conn's agent settings set a name in hookShellEnvNames
// outside the strict tier, or "". The strict tier refuses the same settings
// instead (checkAgentSettings, the effective hook contract).
func HookShellEnvWarning(conn Connector, opts SetupOpts) string {
	if conn == nil || conn.Name() != "claudecode" || !claudeCodeHookShellEnvApplies(opts) || strictPolicyTier(opts) {
		return ""
	}
	sources, err := inspectClaudeCodeUserSources(opts)
	if err != nil {
		return ""
	}
	names, from := claudeCodeSettingsHookShellEnv(sources)
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf("%s; remove %s from that env block, then restart Claude Code",
		claudeCodeHookShellEnvProblem(names, from), strings.Join(names, ", "))
}
