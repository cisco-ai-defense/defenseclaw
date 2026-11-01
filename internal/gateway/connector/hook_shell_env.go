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

// Agent settings that stop or subvert a shell-form hook command
// (rel-1-0-6:GAP-0322).
//
// Claude Code starts a hook command without "args" through /bin/sh -c with
// process.env after it applied the env block of each settings source, lowest
// first: ~/.claude.json, user, project, local, --settings, managed. On RHEL
// and macOS /bin/sh is bash. What a source's env can do there:
//
//   - SHELLOPTS=noexec: bash as /bin/sh parses the registered command and runs
//     none of it, so no hook and no guard clause run and the call goes ahead.
//   - CLAUDE_CODE_SHELL_PREFIX: Claude Code runs that program in place of each
//     shell-form hook command.
//   - BASH_ENV, BASH_FUNC_<name>%%, BASHOPTS: read by the bash that runs the
//     hook script. A per-user host hook starts with #!/bin/bash on rel/1.0.7,
//     so BASH_ENV runs a file of the project's choosing before the hook (it
//     can exit 0 first) and an exported function replaces a command the
//     script calls (curl, jq, ...). A hook started with #!/bin/bash -p ignores
//     all three. They stay on this list either way: a hook script rendered by
//     an earlier build keeps its #!/bin/bash until the gateway renders it
//     again, a rollback brings it back, and no hook needs a startup file or an
//     exported function from a project's settings to run.
//   - FUNCNEST: bash -p still reads it; a low value makes the hook script's
//     nested helper calls fail.
//
// ENV is not on the list: /bin/sh -c and a #!/bin/bash script are
// non-interactive and never read it.
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
// policy check), the default and permissive tiers keep running and warn
// (status, doctor and one gateway alert).
//
// Coverage: the gateway reads ~/.claude.json, the user settings, the
// managed settings and the project and local settings of the pinned
// workspace (claw.workspace_dir) only. It does not see a repository opened
// anywhere else (the main vector: a cloned repository's committed
// .claude/settings.json), parent-directory settings or the local settings
// Claude Code reads at the git root of a worktree. doctor and status also
// check the folder they run in. That part stays a documented limit
// (docs-site reference/fail-modes.mdx). The managed Claude Code drop-in pins
// the launch-stopping names (ManagedHookShellEnvPins), which closes it on a
// managed host (enterprisepolicy).

// hookShellEnvNames are the env names a settings file must not set for a
// shell-form hook command; a BASH_FUNC_ name (an exported function) counts too.
var hookShellEnvNames = []string{
	"BASHOPTS",
	"BASH_ENV",
	"CLAUDE_CODE_SHELL_PREFIX",
	"FUNCNEST",
	"SHELLOPTS",
}

// managedHookShellEnvNames stop the managed Unix hook command, the absolute
// path of the native defenseclaw-hook binary started by /bin/sh -c: a
// non-interactive POSIX sh ignores BASH_ENV and ENV, a command word with a
// slash is never looked up as a function, and BASHOPTS and FUNCNEST do not
// stop it.
var managedHookShellEnvNames = []string{"CLAUDE_CODE_SHELL_PREFIX", "SHELLOPTS"}

const hookShellEnvFunctionPrefix = "BASH_FUNC_"

// HookShellEnvPins returns hookShellEnvNames, the names a settings document
// that governs per-user style shell hook scripts pins to "" (the OpenShell
// sandbox run drop-in pins those its image drop-in does not).
func HookShellEnvPins() []string {
	return append([]string(nil), hookShellEnvNames...)
}

// ManagedHookShellEnvPins returns the names the managed Claude Code drop-in
// pins to "" on Linux and macOS: only what can stop its native hook command.
// Managed env is process-wide, so pinning more would strip a developer's
// BASH_ENV from every Bash tool command for nothing.
func ManagedHookShellEnvPins() []string {
	return append([]string(nil), managedHookShellEnvNames...)
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

// claudeCodeKeepsEnvValue reports whether Claude Code applies value from a
// settings env block. It keeps a string, number or boolean (stringified) and
// drops anything else (null, an object, an array) and a value holding NUL,
// so a dropped value in a higher source leaves a lower one in force.
func claudeCodeKeepsEnvValue(value interface{}) bool {
	switch v := value.(type) {
	case string:
		return !strings.ContainsRune(v, 0)
	case bool, float64, int, int64:
		return true
	default:
		return false
	}
}

// hookShellEnvTakesEffect reports whether a kept value for name changes the
// shell: an exported function with any value, a number or boolean (never
// empty once stringified), a string that is not blank. "" is unset to each
// name (the managed and sandbox drop-ins pin them that way).
func hookShellEnvTakesEffect(name string, value interface{}) bool {
	if strings.HasPrefix(name, hookShellEnvFunctionPrefix) {
		return true
	}
	if text, ok := value.(string); ok {
		return strings.TrimSpace(text) != ""
	}
	return true
}

// claudeCodeHookShellEnvSources are the settings sources whose env reaches a
// hook command, highest first: managed (the active managed source, when it
// can be read), --settings (a test seam, see SetupOpts.ClaudeSettingsOverride),
// local, project, user, ~/.claude.json. A source that cannot be read is left
// out, as the disableAllHooks check leaves it to the other refusals.
func claudeCodeHookShellEnvSources(sources claudeCodeUserSourceSet) []*claudeCodeSettingsSource {
	var out []*claudeCodeSettingsSource
	if managed, err := inspectClaudeCodeManagedSources(); err == nil {
		if active := managed.active(); active != nil {
			out = append(out, active)
		}
	}
	out = append(out, sources.highToLow()...)
	if global, err := readOptionalClaudeCodeSettings("global config", claudeCodeMCPStatePath()); err == nil && global != nil {
		out = append(out, global)
	}
	return out
}

// claudeCodeSettingsHookShellEnv returns the names the effective Claude Code
// env sets (sorted) and the sources that set them. Claude Code applies the
// env blocks name by name, lowest first, so the highest source with a kept
// value decides a name: "" clears a lower value, a dropped value does not.
func claudeCodeSettingsHookShellEnv(sources []*claudeCodeSettingsSource) ([]string, []*claudeCodeSettingsSource) {
	decided := map[string]bool{}
	var names []string
	var from []*claudeCodeSettingsSource
	for _, source := range sources {
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
			if !isHookShellEnvName(key) || decided[key] || !claudeCodeKeepsEnvValue(env[key]) {
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

// hookShellEnvRisk is what name does to a hook command, for the messages.
func hookShellEnvRisk(name string) string {
	switch {
	case name == "SHELLOPTS":
		return "SHELLOPTS (with noexec, /bin/sh runs none of the hook command)"
	case name == "CLAUDE_CODE_SHELL_PREFIX":
		return "CLAUDE_CODE_SHELL_PREFIX (Claude Code runs that program in place of each hook command)"
	case name == "BASH_ENV":
		return "BASH_ENV (a #!/bin/bash hook script runs that file first, and it can exit before the hook)"
	case name == "BASHOPTS":
		return "BASHOPTS (sets options of a #!/bin/bash hook script)"
	case name == "FUNCNEST":
		return "FUNCNEST (makes the hook script's nested helper calls fail)"
	default:
		command := strings.TrimSuffix(strings.TrimPrefix(name, hookShellEnvFunctionPrefix), "%%")
		return fmt.Sprintf("%s (an exported function that replaces the %s command in a #!/bin/bash hook script)", name, command)
	}
}

// claudeCodeHookShellEnvProblem is the sentence for names set by from.
func claudeCodeHookShellEnvProblem(names []string, from []*claudeCodeSettingsSource) string {
	labels := make([]string, 0, len(from))
	for _, source := range from {
		labels = append(labels, source.label())
	}
	risks := make([]string, 0, len(names))
	for _, name := range names {
		risks = append(risks, hookShellEnvRisk(name))
	}
	verb := "sets"
	if len(from) > 1 {
		verb = "set"
	}
	return fmt.Sprintf(
		"Claude Code %s %s in the env block Claude Code applies to the hook commands it starts through /bin/sh: %s",
		strings.Join(labels, " and "), verb, strings.Join(risks, "; "),
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
	names, from := claudeCodeSettingsHookShellEnv(claudeCodeHookShellEnvSources(sources))
	if len(names) == 0 {
		return nil
	}
	return fmt.Errorf( //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		"%s. The strict policy tier refuses it: the gateway does not set up Claude Code, so every Claude Code session of this account fails closed until it is removed (a session that applies the value may still start no hook). Remove %s from that env block, or use the default policy tier, which only warns; then run: defenseclaw-gateway restart",
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
	names, from := claudeCodeSettingsHookShellEnv(claudeCodeHookShellEnvSources(sources))
	if len(names) == 0 {
		return ""
	}
	return fmt.Sprintf("%s; remove %s from that env block, then restart Claude Code",
		claudeCodeHookShellEnvProblem(names, from), strings.Join(names, ", "))
}
