// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
)

// A per-user Windows hook command starts DefenseClaw's launcher from one
// first stage: the direct cmd.exe line, the encoded system PowerShell bridge
// or a PowerShell adapter. When that stage could not start the launcher it
// ended with its own host's error (cmd.exe 9009 or 1, PowerShell 1), which
// every agent reads as a failed hook, so the call ran uninspected whatever the
// fail mode (rel-1-0-6 GAP-0676). The answer "the launcher cannot run" lived
// only in processes that were not running then: the stable launcher's
// unavailable answer and the Claude Code guard (internal/hookguard).
//
// The stage that starts the launcher now answers its start failure itself,
// with what the agent reads as a block of the bound event (the stable
// launcher's unavailable answer) and the guard's sentence for that agent:
//
//   - The PowerShell bridge (Kiro, Antigravity, Codex for a launcher path the
//     direct form cannot carry) wraps its Process.Start (CreateProcess) and
//     answers a start that throws, a Constrained Language start that never
//     ran, and a launcher that ended with a Windows exception status (a
//     corrupt image; the guard's siblingExceptionStatus).
//   - The direct Codex line starts the one-line install's guard program,
//     which does the same for Codex (hookguard.RunCodex); cmd.exe cannot see a
//     start failure and hangs on an empty or truncated image.
//
// Only the start is judged: a launcher that starts keeps its own answer, so
// an outage keeps its fail mode. Stop, SubagentStop and SessionEnd keep the
// form they had, so a stop never gets a blocking answer. Managed renders are
// unchanged; their guardian restores the launcher.

// launcherStartAnswer is the answer of a hook command whose launcher cannot
// start: the guard sentence on stderr, the agent's block on stdout (empty for
// an agent that reads the exit status) and the exit status.
type launcherStartAnswer struct {
	agent  string
	stdout string
	exit   int
}

// sentence is the guard sentence for the answer's agent.
func (a *launcherStartAnswer) sentence() string {
	return hookguard.LauncherMessage(a.agent, false)
}

// powershell renders the answer as PowerShell statements that also run in
// Constrained Language mode, which refuses the [Console] call: there the
// sentence goes to stderr through Write-Error. The block is written as
// pipeline output, which reaches stdout in both modes.
func (a *launcherStartAnswer) powershell() string {
	sentence := powershellQuoteLiteral(a.sentence())
	statements := "try { [Console]::Error.WriteLine(" + sentence + ") } catch { Microsoft.PowerShell.Utility\\Write-Error -Message " +
		sentence + " -ErrorAction Continue }; "
	if a.stdout != "" {
		statements += powershellQuoteLiteral(a.stdout) + "; "
	}
	return statements + "exit " + strconv.Itoa(a.exit)
}

// kiroLauncherStartAnswer blocks with exit 2, the only non-zero status Kiro
// treats as a block (preToolUse); on every other Kiro event exit 2 is a
// warning, as the stable launcher's unavailable answer is.
func kiroLauncherStartAnswer() *launcherStartAnswer {
	return &launcherStartAnswer{agent: "Kiro", exit: 2}
}

// antigravityLauncherStartAnswer is Antigravity's deny of PreToolUse, the
// only event it blocks, on stdout with exit 0; nil for every other event,
// whose command keeps its form.
func antigravityLauncherStartAnswer(event string) *launcherStartAnswer {
	if event != "PreToolUse" {
		return nil
	}
	answer := &launcherStartAnswer{agent: "Antigravity"}
	body, _ := json.Marshal(map[string]any{"decision": "deny", "reason": answer.sentence()})
	answer.stdout = string(body)
	return answer
}

// codexLauncherStartAnswer is Codex's block of event under contract
// (hookguard.CodexBlock) on stdout with exit 0; nil for an event that gets no
// blocking answer, whose command keeps its form.
func codexLauncherStartAnswer(event, contract string) *launcherStartAnswer {
	answer := &launcherStartAnswer{agent: "Codex"}
	block := hookguard.CodexBlock(event, contract, answer.sentence())
	if block == nil {
		return nil
	}
	body, _ := json.Marshal(block)
	answer.stdout = string(body)
	return answer
}

// windowsAnsweringPowerShellHookCommand is
// windowsNativePowerShellHookCommandForBoundEvent whose bridge answers a
// launcher that cannot start with answer; a nil answer renders that command.
func windowsAnsweringPowerShellHookCommand(connector, event, contractID, hookBinary string, answer *launcherStartAnswer, extra ...string) string {
	script := strings.Join(append([]string{
		"$ErrorActionPreference='Stop'",
		"$env:NoDefaultCurrentDirectoryInExePath='1'",
	}, windowsAwaitedHookStatementsAnswering(hookBinary, nativeHookBridgeArguments(connector, event, contractID, extra), answer)...), "; ")
	return windowsSystemPowerShellExe() + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + powershellEncodedCommand(script)
}

// windowsSiblingLauncherGuard returns the guard program the per-user Codex
// and Devin commands start for launcher: defenseclaw-hook-guard.exe beside it
// (the one-line install) when that is a regular file, else "". The installed
// full hook and the gateway are never used as the guard: as the first program
// the agent starts, their damage would let the call run (REVIEW-g089 M1).
// Tests replace it.
var windowsSiblingLauncherGuard = func(launcher string) string {
	guard := windowsSiblingGuardPath(launcher)
	if guard == "" {
		return ""
	}
	if info, err := os.Lstat(guard); err == nil && info.Mode().IsRegular() {
		return guard
	}
	return ""
}

// windowsSiblingGuardPath is defenseclaw-hook-guard.exe in the folder of
// an absolute defenseclaw-hook.exe launcher, the program the guard argv
// (hookguard.SiblingArgv) starts its launcher beside; otherwise "".
func windowsSiblingGuardPath(launcher string) string {
	if !hookguard.AbsoluteHookExecutable(launcher) {
		return ""
	}
	return launcher[:strings.LastIndexAny(launcher, `\/`)+1] + windowsHookGuardBinaryName
}

// windowsCodexGuardedHookCommand is the direct system cmd.exe start
// (windowsCmdDirectHookCommand) of guard with the bound Codex guard argv:
//
//	<system>\cmd.exe /d /v:off /c "<guard>" launcher-guard-sibling hook --connector codex --event <E> --hook-contract <C>
//
// The launcher is the defenseclaw-hook.exe beside guard. ok is false for a
// guard path or argument the direct form cannot carry.
func windowsCodexGuardedHookCommand(guard, event, contractID string) (string, bool) {
	return windowsCmdDirectHookCommand(guard,
		append([]string{hookguard.SiblingSubcommand}, nativeHookBridgeArguments("codex", event, contractID, nil)...))
}

// windowsCodexAnsweringBridgeHookCommand is the per-user Codex bridge for a
// launcher path the direct form cannot carry: the encoded system PowerShell
// bridge, answering a launcher that cannot start on the events Codex can
// block.
func windowsCodexAnsweringBridgeHookCommand(event, contractID, hookBinary string) string {
	return windowsAnsweringPowerShellHookCommand("codex", event, contractID, hookBinary, codexLauncherStartAnswer(event, contractID))
}

// windowsCodexPerUserHookCommands are the per-user Codex commands of launcher
// for event and contract that this release and its upgrade sources write:
// the bridge of 1.0.1 to 1.0.4 (windowsNativePowerShellHookCommandForCodexEvent),
// the direct start of 1.0.5 to 1.0.8 (GAP-1908), and this release's guarded
// start and answering bridge. Setup rewrites them and teardown removes them;
// the guarded form is listed whether or not the guard program is still there.
func windowsCodexPerUserHookCommands(event, contractID, launcher string) []string {
	commands := []string{
		windowsNativePowerShellHookCommandForCodexEvent(event, contractID, launcher),
		windowsCodexAnsweringBridgeHookCommand(event, contractID, launcher),
	}
	if direct, ok := windowsCmdDirectHookCommand(launcher, nativeHookBridgeArguments("codex", event, contractID, nil)); ok {
		commands = append(commands, direct)
	}
	if guard := windowsSiblingGuardPath(launcher); guard != "" {
		if guarded, ok := windowsCodexGuardedHookCommand(guard, event, contractID); ok {
			commands = append(commands, guarded)
		}
	}
	return uniqueNonEmptyStrings(commands)
}

// launcherStartAnswerHookForms are the per-user Windows hook commands of
// launcher, by connector, that this release writes to answer a launcher that
// cannot start (rel-1-0-6 GAP-0676) and that no release before 1.0.9 owns:
// the Antigravity PreToolUse answering bridge, the Kiro answering bridge of
// each surface, the Codex guarded start and answering bridge of each event
// Codex can block, and the Devin guarded start of each block event. It is the
// one place a connector-wide rollback stash or restore (GAP-0697, lane g697)
// takes them from. Each connector's ownership list holds them too, the Codex,
// Kiro and Devin rollback converters turn them into the earlier forms, and
// Antigravity's entries are owned by their defenseclaw-antigravity-* key
// (TestLauncherStartAnswerHookFormsAreOwnedAndConverted).
func launcherStartAnswerHookForms(launcher string) map[string][]string {
	forms := map[string][]string{
		"antigravity": {windowsAnsweringPowerShellHookCommand("antigravity", "PreToolUse", "", launcher, antigravityLauncherStartAnswer("PreToolUse"))},
		"kiro": {
			windowsKiroHookCommandForBinary(launcher, "", false),
			windowsKiroHookCommandForBinary(launcher, KiroHookSurfaceV3, false),
		},
	}
	guard := windowsSiblingGuardPath(launcher)
	for _, contract := range builtinHookContracts["codex"] {
		for _, event := range contract.Events {
			if codexLauncherStartAnswer(event, contract.ContractID) == nil {
				continue
			}
			forms["codex"] = append(forms["codex"], windowsCodexAnsweringBridgeHookCommand(event, contract.ContractID, launcher))
			if guard == "" {
				continue
			}
			if guarded, ok := windowsCodexGuardedHookCommand(guard, event, contract.ContractID); ok {
				forms["codex"] = append(forms["codex"], guarded)
			}
		}
	}
	for _, event := range devinHookEvents {
		if guard != "" {
			forms["devin"] = append(forms["devin"], windowsDevinGuardedHookCommand(guard, event))
		}
	}
	for name, commands := range forms {
		forms[name] = uniqueNonEmptyStrings(commands)
	}
	return forms
}
