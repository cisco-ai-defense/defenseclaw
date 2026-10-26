// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
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
//
// PreToolUse is the exception. Cursor imports the hooks in
// ~/.claude/settings.json and runs a handler's command without its args, and
// an argument-free cmd.exe made Cursor block every tool call (GAP-1011). The
// PreToolUse handler of a packaged per-user install therefore starts the
// installed full hook, a separate file from the stable launcher:
//
//	<install>\bin\defenseclaw-hook.exe launcher-guard <launcher> hook --connector claudecode
//
// It runs the launcher as cmd.exe does and blocks with exit 2 and the same
// sentence when the launcher is missing or cannot start, so a tool call of a
// turn that began before the launcher went missing is not let through. Started
// by Cursor without arguments it gives no answer. The launcher delegates every
// call to that same installed hook, so its absence already leaves no hook to
// run; the guard adds no file a call depends on.
//
// The one-line install has no separate installed hook: its launcher is
// ~/.local/bin\defenseclaw-hook.exe. Its PreToolUse handler starts the
// defenseclaw-gateway.exe beside that launcher as the same guard, with the
// same argv:
//
//	<bin>\defenseclaw-gateway.exe launcher-guard <launcher> hook --connector claudecode
//
// so a launcher removed in the middle of a turn still blocks the next tool
// call; a direct start of the missing launcher was a non-blocking error that
// let the call run uninspected. Started by Cursor without arguments and a
// Cursor event on stdin, the gateway gives no answer either. Only a launcher
// with neither guard program (a repository build) keeps the exec form
// (command = launcher, args = hook --connector claudecode) on PreToolUse. The
// cmd.exe guard is never the PreToolUse command: Cursor starts cmd.exe with no
// arguments and the tool call event on stdin, so cmd.exe printed its banner
// instead of JSON and read that event as commands; every Cursor tool call was
// blocked (GAP-1011).
//
// Hook-shape compatibility rule (GAP-1284): a hook entry that release N
// writes must keep a shape that every earlier 1.x teardown recognises, or
// release N's rollback must convert it before the older release starts. The
// older release cannot be patched. 1.0.0 and 0.8.x own a Windows Claude Code
// handler only in the exec form (command = launcher, args = hook --connector
// claudecode), so after `defenseclaw rollback` their uninstall kept every
// guard and still reported the teardown verified. ConvertHooksForRollback is
// the converter, and the installers run it with this release's gateway before
// they restore the older install. A future change to a hook shape needs its
// own converter and a fixture in
// TestClaudeCodeRollbackLeavesHooksEarlierReleasesRemove.

// claudeCodeLauncherGuardWords is the guard sentence, one argument per word
// so no argument needs quoting; it holds no cmd.exe metacharacter.
var claudeCodeLauncherGuardWords = strings.Fields(
	"DefenseClaw blocked this: its Claude Code hook launcher is missing. " +
		"Run the DefenseClaw installer again to repair it.",
)

// ClaudeCodeLauncherMissingMessage is the guard sentence on one line, which
// the PreToolUse guard (defenseclaw-hook launcher-guard) prints.
var ClaudeCodeLauncherMissingMessage = strings.Join(claudeCodeLauncherGuardWords, " ")

// ClaudeCodeLauncherGuardSubcommand is the first argument of the PreToolUse
// guard handler.
const ClaudeCodeLauncherGuardSubcommand = "launcher-guard"

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
// generated guard, the cmd.exe guard or the PreToolUse guard; any other
// handler, including an edited guard, is not one.
func claudeCodeLauncherGuardParts(hook map[string]interface{}) (string, []string, bool) {
	if launcher, hookArgs, ok := claudeCodeCmdGuardParts(hook); ok {
		return launcher, hookArgs, true
	}
	return claudeCodePreToolGuardParts(hook)
}

// claudeCodeCmdGuardParts returns the launcher and hook argv of an exact
// generated cmd.exe guard. cmd.exe is the one in the system directory the
// Windows API reports, never one named by SystemRoot in the environment of
// the agent or hook that asks.
func claudeCodeCmdGuardParts(hook map[string]interface{}) (string, []string, bool) {
	command, _ := hook["command"].(string)
	if command == "" || normalizeWindowsHookExecutable(command) !=
		normalizeWindowsHookExecutable(windowsSystemCmdExe()) {
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

// claudeCodePreToolGuardArgs is the argv of the PreToolUse guard handler.
func claudeCodePreToolGuardArgs(launcher string, hookArgs []string) []string {
	return append([]string{ClaudeCodeLauncherGuardSubcommand, launcher}, hookArgs...)
}

// ClaudeCodeLauncherGuardArgv returns the launcher and hook argv that the
// PreToolUse guard runs for args, its arguments after the program name. Only
// an absolute defenseclaw-hook.exe launcher with the per-user Claude Code hook
// argv is accepted, so the guard starts nothing but DefenseClaw's launcher.
func ClaudeCodeLauncherGuardArgv(args []string) (launcher string, hookArgs []string, ok bool) {
	want := []string{"hook", "--connector", "claudecode"}
	if len(args) != 2+len(want) || args[0] != ClaudeCodeLauncherGuardSubcommand ||
		!claudeCodeLauncherGuardable(args[1]) || !claudeCodeAbsoluteHookExecutable(args[1]) {
		return "", nil, false
	}
	for i, arg := range want {
		if args[2+i] != arg {
			return "", nil, false
		}
	}
	return args[1], append([]string(nil), want...), true
}

// claudeCodeAbsoluteHookExecutable reports an absolute path whose file name is
// defenseclaw-hook.exe.
func claudeCodeAbsoluteHookExecutable(path string) bool {
	if !isWindowsAbsolutePath(path) && !filepath.IsAbs(path) {
		return false
	}
	return strings.EqualFold(path[strings.LastIndexAny(path, `\/`)+1:], windowsHookBinaryName)
}

// claudeCodePreToolGuardProgram reports a program that can run as the
// PreToolUse guard: an absolute defenseclaw-hook.exe (the installed full hook
// of a packaged install) or defenseclaw-gateway.exe (the one-line install's
// gateway beside its launcher), both of which answer the launcher-guard argv.
func claudeCodePreToolGuardProgram(path string) bool {
	if !claudeCodeLauncherGuardable(path) || (!isWindowsAbsolutePath(path) && !filepath.IsAbs(path)) {
		return false
	}
	name := path[strings.LastIndexAny(path, `\/`)+1:]
	return strings.EqualFold(name, windowsHookBinaryName) || strings.EqualFold(name, windowsGatewayBinaryName)
}

// claudeCodePreToolGuardParts returns the launcher and hook argv of an exact
// generated PreToolUse guard handler.
func claudeCodePreToolGuardParts(hook map[string]interface{}) (string, []string, bool) {
	command, _ := hook["command"].(string)
	if !claudeCodePreToolGuardProgram(command) {
		return "", nil, false
	}
	args, ok := claudeCodeNativeExecArguments(hook)
	if !ok {
		return "", nil, false
	}
	launcher, hookArgs, ok := ClaudeCodeLauncherGuardArgv(args)
	if !ok || normalizeWindowsHookExecutable(launcher) == normalizeWindowsHookExecutable(command) {
		return "", nil, false
	}
	return launcher, hookArgs, true
}

// claudeCodePreToolGuardExecutable returns the program the PreToolUse
// handler starts for launcher, or "" when there is none and PreToolUse runs
// the launcher in the exec form. Tests replace it.
var claudeCodePreToolGuardExecutable = func(launcher string) string {
	if guard := claudeCodePreToolGuardFor(launcher, canonicalNativeWindowsHookBinary(), canonicalNativeWindowsInstalledHookBinary()); guard != "" {
		return guard
	}
	return claudeCodeGatewayPreToolGuardFor(launcher)
}

// claudeCodeGatewayPreToolGuardFor returns the defenseclaw-gateway.exe beside
// launcher, the one-line install's ~/.local/bin layout, when it is a regular
// file; otherwise "".
func claudeCodeGatewayPreToolGuardFor(launcher string) string {
	if !claudeCodeAbsoluteHookExecutable(launcher) || !claudeCodeLauncherGuardable(launcher) {
		return ""
	}
	gateway := launcher[:strings.LastIndexAny(launcher, `\/`)+1] + windowsGatewayBinaryName
	if !claudeCodePreToolGuardProgram(gateway) {
		return ""
	}
	info, err := os.Lstat(gateway)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return gateway
}

// claudeCodePreToolGuardFor returns installed, the installed full hook, when
// launcher is the stable launcher of a packaged install and installed is a
// separate regular file; otherwise "".
func claudeCodePreToolGuardFor(launcher, stable, installed string) string {
	if strings.TrimSpace(stable) == "" || strings.TrimSpace(installed) == "" ||
		!pathidentity.Same(launcher, stable) || pathidentity.Same(installed, stable) ||
		!claudeCodeAbsoluteHookExecutable(installed) || !claudeCodeLauncherGuardable(installed) {
		return ""
	}
	info, err := os.Lstat(installed)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	return installed
}

// ClaudeCodeLauncherGuardTarget returns the launcher and hook argv of a
// handler in the exact launcher-guard form per-user Setup has written since
// 1.0.0; ok is false for any other handler, an edited guard included.
func ClaudeCodeLauncherGuardTarget(hook map[string]interface{}) (launcher string, hookArgs []string, ok bool) {
	return claudeCodeLauncherGuardParts(hook)
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

// claudeCodeHandlerInvocation is the argv of the handler Setup writes for
// eventType. Cursor imports the hooks in ~/.claude/settings.json (its
// third-party hooks, on by default) and runs only a handler's command,
// without its args. For the cmd.exe guard that started an interactive
// cmd.exe, which printed its banner instead of JSON, and Cursor blocks a
// tool call whose pre-tool hook answers with something other than JSON: every
// Cursor tool call was blocked, also with no Cursor hooks set up (GAP-1011).
// PreToolUse is the only Claude Code event Cursor runs as a pre-tool check,
// so that handler runs the PreToolUse guard instead (see the top of this
// file): started by Cursor with no arguments it gives no answer, and started
// by Claude Code it blocks when the launcher is missing, also in a turn that
// began before the launcher went missing. The one-line install runs its
// gateway as that guard; only a launcher with neither guard program runs in
// the exec form on PreToolUse (see the top of this file). Every other event
// keeps the cmd.exe guard (GAP-1091).
func claudeCodeHandlerInvocation(eventType, command string, args []string) (string, []string) {
	if eventType != "PreToolUse" {
		return command, args
	}
	hook := map[string]interface{}{"command": command, "args": args}
	launcher, hookArgs, ok := claudeCodeCmdGuardParts(hook)
	if !ok {
		return command, args
	}
	guardArgs := claudeCodePreToolGuardArgs(launcher, hookArgs)
	if guard := claudeCodePreToolGuardExecutable(launcher); guard != "" {
		if _, _, valid := ClaudeCodeLauncherGuardArgv(guardArgs); valid {
			return guard, guardArgs
		}
	}
	return launcher, hookArgs
}

// claudeCodeRollbackBackupName is the copy of settings.json taken before
// ConvertHooksForRollback rewrites it, under <data dir>/backups.
const claudeCodeRollbackBackupName = "claudecode-settings.before-rollback.json"

// ConvertHooksForRollback rewrites the per-user Claude Code handlers this
// release writes in a shape earlier releases do not own into the shape they
// do: the Windows launcher guard becomes its exec form, and a Unix script path
// quoted for a home with a space (GAP-0382) becomes the unquoted command 1.0.0
// wrote. The installers run it just before a rollback restores an older
// install; rolling forward again runs Setup, which writes the current form.
// It leaves edited and foreign handlers as they are, keeps a copy of the file
// it changes, and returns how many handlers it rewrote.
func (c *ClaudeCodeConnector) ConvertHooksForRollback(opts SetupOpts) (int, error) {
	if opts.ManagedEnterprise {
		return 0, nil // managed installs write the exec form
	}
	settingsPath := claudeCodeSettingsPath()
	readPath, err := claudeCodeUserSettingsReadPath(settingsPath)
	if err != nil {
		return 0, fmt.Errorf("Claude Code user settings %s: %w", settingsPath, err) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	data, err := os.ReadFile(readPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read Claude Code settings %s: %w", settingsPath, err)
	}
	convert := claudeCodeRollbackConversion(opts, settingsPath)
	if _, changed, err := convert(data); err != nil || changed == 0 {
		return 0, err
	}
	converted := 0
	err = withFileLock(settingsPath, func() error {
		return transformClaudeCodeRollback(settingsPath, opts,
			func(current []byte, exists bool) (atomicTransformResult, error) {
				if !exists {
					return atomicTransformResult{Remove: true}, nil
				}
				out, changed, err := convert(current)
				if err != nil || changed == 0 {
					return atomicTransformResult{Data: current}, err
				}
				if err := writeClaudeCodeRollbackBackup(opts.DataDir, current); err != nil {
					return atomicTransformResult{}, fmt.Errorf("keep a copy of the settings: %w", err)
				}
				converted = changed
				return atomicTransformResult{Data: out}, nil
			})
	})
	if err != nil {
		return 0, fmt.Errorf("rewrite Claude Code hooks in %s: %w", settingsPath, err)
	}
	return converted, nil
}

func claudeCodeRollbackConversion(opts SetupOpts, settingsPath string) func([]byte) ([]byte, int, error) {
	launcher := strings.TrimSpace(opts.HookExecutable)
	if launcher == "" {
		launcher = defenseclawHookBinary()
	}
	owned := func(path string) bool {
		return pathidentity.Same(path, launcher) || isDefenseClawHookExecutable(path)
	}
	script := filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"))
	return func(data []byte) ([]byte, int, error) {
		if len(bytes.TrimSpace(data)) == 0 {
			return nil, 0, nil
		}
		settings := map[string]interface{}{}
		if err := json.Unmarshal(data, &settings); err != nil {
			return nil, 0, fmt.Errorf("parse Claude Code settings %s: %w", settingsPath, err)
		}
		changed := claudeCodeHooksInEarlierReleaseForm(settings, runtime.GOOS, script, owned)
		if changed == 0 {
			return nil, 0, nil
		}
		out, err := json.MarshalIndent(settings, "", "  ")
		return out, changed, err
	}
}

// claudeCodeHooksInEarlierReleaseForm rewrites in place every handler under
// settings["hooks"] that ConvertHooksForRollback converts and returns how
// many it changed. goos selects the form, script is the Unix hook script
// path, and owned reports whether a Windows launcher is DefenseClaw's.
func claudeCodeHooksInEarlierReleaseForm(
	settings map[string]interface{},
	goos, script string,
	owned func(string) bool,
) int {
	hooks, _ := settings["hooks"].(map[string]interface{})
	changed := 0
	for _, event := range hooks {
		groups, _ := event.([]interface{})
		for _, rawGroup := range groups {
			group, _ := rawGroup.(map[string]interface{})
			handlers, _ := group["hooks"].([]interface{})
			for _, rawHandler := range handlers {
				handler, ok := rawHandler.(map[string]interface{})
				if ok && claudeCodeHandlerInEarlierReleaseForm(handler, goos, script, owned) {
					changed++
				}
			}
		}
	}
	return changed
}

func claudeCodeHandlerInEarlierReleaseForm(
	handler map[string]interface{},
	goos, script string,
	owned func(string) bool,
) bool {
	if goos == "windows" {
		launcher, hookArgs, ok := claudeCodeLauncherGuardParts(handler)
		if !ok || !owned(launcher) || strings.Join(hookArgs, " ") != "hook --connector claudecode" {
			return false
		}
		args := make([]interface{}, len(hookArgs))
		for i, arg := range hookArgs {
			args[i] = arg
		}
		handler["command"] = launcher
		handler["args"] = args
		return true
	}
	// 1.0.0 matched its handlers by the unquoted script path prefix.
	command, _ := handler["command"].(string)
	quoted := posixHookCommandWord(script)
	if quoted == script || claudeCodeUnguardedHookCommand(command) != quoted {
		return false
	}
	handler["command"] = script
	return true
}
