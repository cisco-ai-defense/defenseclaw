// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Codex on Windows runs a hook command through the account's shell
// (PowerShell -Command, or cmd.exe /C in earlier releases), and per-user
// Setup registers the direct system cmd.exe start of the launcher
// (GAP-1908). cmd.exe cannot report a launcher that does not start: it exits
// 9009 or 1, which Codex reads as a failed hook, and it hangs on an empty or
// truncated image. So a launcher that was missing or damaged let every Codex
// call run uninspected (rel-1-0-6 GAP-0676). On the events Codex can block,
// Setup starts this guard program instead, through the same cmd.exe line:
//
//	<system>\cmd.exe /d /v:off /c "<bin>\defenseclaw-hook-guard.exe" launcher-guard-sibling hook --connector codex --event <E> --hook-contract <C>
//
// The guard starts defenseclaw-hook.exe beside it (the one-line install's
// launcher) with the hook argv, as Run does. The launcher is not an argument:
// cmd.exe /c keeps the quotes of a line with exactly two of them, and a
// second quoted path made it strip the first and the last (a profile path
// with a space). A started launcher's stdin, stdout, stderr and exit code
// pass through. When the launcher cannot start, or ends with a Windows
// exception status, the guard answers Codex's block for the event: JSON on
// stdout and exit 0, because Codex 0.130 and later read a non-zero
// UserPromptSubmit status as a failed hook and submit the prompt (GAP-0949).

// SiblingSubcommand is the first argument of the guard argv that starts the
// launcher beside the guard program.
const SiblingSubcommand = "launcher-guard-sibling"

// LauncherMessage is the sentence a guard prints when it blocks because the
// launcher of agent is missing or cannot start. MissingMessage and
// CannotStartMessage are its Claude Code forms.
func LauncherMessage(agent string, missing bool) string {
	state := "cannot start"
	if missing {
		state = "is missing"
	}
	return "DefenseClaw blocked this: its " + agent + " hook launcher " + state +
		". Run the DefenseClaw installer again to repair it."
}

// SiblingArgv returns the hook argv, event and hook contract of the sibling
// guard argv, its arguments after the program name:
//
//	launcher-guard-sibling hook --connector codex --event <E> --hook-contract <C>
//
// The event and contract are bare tokens (letters, digits, '.', '_', '-') and
// the contract is a codex-hooks-* id.
func SiblingArgv(args []string) (hookArgs []string, event, contract string, ok bool) {
	want := []string{SiblingSubcommand, "hook", "--connector", "codex", "--event", "", "--hook-contract", ""}
	if len(args) != len(want) {
		return nil, "", "", false
	}
	for i, arg := range want {
		if arg != "" && args[i] != arg {
			return nil, "", "", false
		}
	}
	event, contract = args[5], args[7]
	if !bareToken(event) || !bareToken(contract) || !strings.HasPrefix(contract, "codex-hooks-") {
		return nil, "", "", false
	}
	return append([]string(nil), args[1:]...), event, contract, true
}

// SiblingLauncher is defenseclaw-hook.exe in the folder of guard, the path
// of the running guard program.
func SiblingLauncher(guard string) string {
	if strings.TrimSpace(guard) == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(guard), hookBinaryName)
}

// CodexBlock is the answer Codex reads as a block of event under contract,
// with message as the reason, the answer the stable launcher gives when its
// installed hook is unavailable (hookruntime answerUnavailableDelegation).
// It is nil for an event Codex gives no control, and for Stop, SubagentStop
// and SessionEnd: a block there only keeps Codex running, and a launcher
// that cannot start never gets a blocking answer on a stop.
func CodexBlock(event, contract, message string) map[string]any {
	switch event {
	case "PreToolUse":
		return map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": message,
		}}
	case "PermissionRequest":
		return map[string]any{"hookSpecificOutput": map[string]any{
			"hookEventName": "PermissionRequest", "decision": map[string]any{"behavior": "deny", "message": message},
		}}
	case "UserPromptSubmit", "PostToolUse":
		return map[string]any{"decision": "block", "reason": message}
	case "SessionStart", "PreCompact", "PostCompact":
		switch contract {
		case "codex-hooks-v3", "codex-hooks-v3-generic", "codex-hooks-v4":
			return map[string]any{"continue": false, "stopReason": message}
		}
	}
	return nil
}

// RunCodex runs launcher with hookArgs and passes its stdin, stdout, stderr
// and exit code through. When the launcher cannot start, or ends with a
// Windows exception status (siblingExceptionStatus), it prints the Codex
// sentence and answers CodexBlock for event, exit 0; an event without a
// block gets the sentence and exit 0.
func RunCodex(launcher string, hookArgs []string, event, contract string, stdin io.Reader, stdout, stderr io.Writer) int {
	code, started, missing := runSiblingLauncher(launcher, hookArgs, stdin, stdout, stderr)
	if started {
		return code
	}
	message := LauncherMessage("Codex", missing)
	fmt.Fprintln(stderr, message)
	if body := CodexBlock(event, contract, message); body != nil {
		if err := json.NewEncoder(stdout).Encode(body); err != nil {
			fmt.Fprintf(stderr, "defenseclaw-hook-guard: write the block: %v\n", err)
			return 2
		}
	}
	return 0
}

// runSiblingLauncher runs launcher with hookArgs and passes its stdin,
// stdout, stderr and exit code through. started is false when the launcher
// did not run normally: it could not start, or it ended with a Windows
// exception status; missing then says nothing is at the launcher path.
func runSiblingLauncher(launcher string, hookArgs []string, stdin io.Reader, stdout, stderr io.Writer) (code int, started, missing bool) {
	command := exec.Command(launcher, hookArgs...)
	command.Stdin, command.Stdout, command.Stderr = stdin, stdout, stderr
	err := command.Run()
	if err == nil {
		return 0, true, false
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() >= 0 {
		if !siblingExceptionStatus(exitErr.ExitCode()) {
			return exitErr.ExitCode(), true, false
		}
		return 0, false, false
	}
	_, statErr := os.Lstat(launcher)
	return 0, false, errors.Is(statErr, fs.ErrNotExist)
}

// siblingExceptionStatus reports a Windows process exit code of 0x80000000
// or above: the process ended on an exception (a corrupt code section, a
// loader failure, an access violation), not with a status it chose. No
// DefenseClaw launcher exits with such a code itself; a Go panic exits 2.
// It is private to the sibling guards (Codex, Devin) so it cannot collide
// with the Claude Code guard's exported ExceptionStatus (fix/r109-g089c).
func siblingExceptionStatus(code int) bool {
	return uint32(code) >= 0x80000000 //nolint:gosec // the Windows exit code is a DWORD; the conversion keeps its bits.
}

func bareToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("._-", r) {
			return false
		}
	}
	return true
}
