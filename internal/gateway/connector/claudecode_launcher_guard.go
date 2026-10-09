// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"strings"
)

// Claude Code on Windows spawns a hook's command directly. When the per-user
// defenseclaw-hook.exe is gone (an antivirus quarantine, a cleanup tool) that
// spawn fails with ENOENT, which Claude Code treats as a non-blocking error:
// the prompt and every tool call ran unguarded even in action mode with fail
// mode closed (GAP-1091). Per-user Setup therefore registers the launcher
// through the system command processor, which is always present:
//
//	cmd.exe /d /c if exist "<launcher>" ( "<launcher>" hook --connector claudecode )
//	        else ( echo <guard sentence> 1>&2 & exit /b 2 )
//
// cmd.exe waits for the launcher, passes its stdin, stdout, stderr and exit
// code through, and blocks with exit 2 and one sentence when the launcher is
// missing, as the Unix hook command does. Managed installs keep the exec form
// their guardian restores.

// claudeCodeLauncherGuardWords is the guard sentence, one argument per word
// so no argument needs quoting; it holds no cmd.exe metacharacter.
var claudeCodeLauncherGuardWords = strings.Fields(
	"DefenseClaw blocked this: its Claude Code hook launcher is missing. " +
		"Run the DefenseClaw installer again to repair it.",
)

// claudeCodeWindowsCommandProcessor is the system cmd.exe the guard runs.
func claudeCodeWindowsCommandProcessor() string {
	root := strings.TrimSpace(os.Getenv("SystemRoot"))
	if root == "" || !filepath.IsAbs(root) {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "cmd.exe")
}

// claudeCodeLauncherGuardable reports whether cmd.exe reads the launcher path
// literally inside double quotes: it must not contain a quote, a variable
// sign or a line break. Other paths keep the exec form.
func claudeCodeLauncherGuardable(launcher string) bool {
	return strings.TrimSpace(launcher) == launcher && launcher != "" &&
		!strings.ContainsAny(launcher, "\"%!\r\n")
}

// claudeCodeLauncherGuardArgs is the cmd.exe argv that runs launcher with
// hookArgs when it exists and blocks otherwise.
func claudeCodeLauncherGuardArgs(launcher string, hookArgs []string) []string {
	args := []string{"/d", "/c", "if", "exist", launcher, "(", launcher}
	args = append(args, hookArgs...)
	args = append(args, ")", "else", "(", "echo")
	args = append(args, claudeCodeLauncherGuardWords...)
	return append(args, "1>&2", "&", "exit", "/b", "2", ")")
}

// claudeCodeLauncherGuardParts returns the launcher and hook argv of an exact
// generated guard; any other handler, including an edited guard, is not one.
func claudeCodeLauncherGuardParts(hook map[string]interface{}) (string, []string, bool) {
	command, _ := hook["command"].(string)
	if command == "" || normalizeWindowsHookExecutable(command) !=
		normalizeWindowsHookExecutable(claudeCodeWindowsCommandProcessor()) {
		return "", nil, false
	}
	args, ok := claudeCodeNativeExecArguments(hook)
	if !ok || len(args) < 8 || args[0] != "/d" || args[1] != "/c" || args[2] != "if" ||
		args[3] != "exist" || args[5] != "(" || args[6] != args[4] {
		return "", nil, false
	}
	end := -1
	for i := 7; i+1 < len(args); i++ {
		if args[i] == ")" && args[i+1] == "else" {
			end = i
			break
		}
	}
	if end < 0 {
		return "", nil, false
	}
	launcher, hookArgs := args[4], append([]string(nil), args[7:end]...)
	want := claudeCodeLauncherGuardArgs(launcher, hookArgs)
	if len(want) != len(args) {
		return "", nil, false
	}
	for i := range want {
		if want[i] != args[i] {
			return "", nil, false
		}
	}
	return launcher, hookArgs, true
}

// claudeCodeExecView returns a guarded handler as the exec-form handler it
// runs (command = launcher, args = hook argv), so the ownership and contract
// checks written for the exec form apply to both. Any other value is returned
// unchanged.
func claudeCodeExecView(rawHook interface{}) interface{} {
	hook, ok := rawHook.(map[string]interface{})
	if !ok {
		return rawHook
	}
	launcher, hookArgs, ok := claudeCodeLauncherGuardParts(hook)
	if !ok {
		return rawHook
	}
	view := make(map[string]interface{}, len(hook))
	for key, value := range hook {
		view[key] = value
	}
	args := make([]interface{}, len(hookArgs))
	for i, arg := range hookArgs {
		args[i] = arg
	}
	view["command"] = launcher
	view["args"] = args
	return view
}

// claudeCodeRecordedHookCommand is the command a Setup records as its own:
// the launcher, not cmd.exe, which other hooks may use too.
func claudeCodeRecordedHookCommand(command string, args []string) string {
	hook := map[string]interface{}{"command": command, "args": args}
	if launcher, _, ok := claudeCodeLauncherGuardParts(hook); ok {
		return launcher
	}
	return command
}

// claudeCodeWindowsHookInvocation is the per-user or managed Windows argv.
func claudeCodeWindowsHookInvocation(opts SetupOpts, executable string) (string, []string) {
	args := []string{"hook", "--connector", "claudecode"}
	if !opts.ManagedEnterprise && claudeCodeLauncherGuardable(executable) {
		return claudeCodeWindowsCommandProcessor(), claudeCodeLauncherGuardArgs(executable, args)
	}
	return executable, args
}
