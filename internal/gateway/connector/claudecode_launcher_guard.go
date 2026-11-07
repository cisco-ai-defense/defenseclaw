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

	"github.com/defenseclaw/defenseclaw/internal/hookguard"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
)

// Per-user Windows Claude Code registers a stable hook chain. The system
// cmd.exe starts each event except PreToolUse: it compares the small guard
// with Setup's approved copy, starts that guard, and maps its answer to the
// native hook status. The guard starts the launcher with CreateProcess, so a
// path that exists but cannot start gets the same documented answer as a
// missing launcher. Neutral lifecycle events get a warning and a nonblocking
// status. A launcher that runs keeps its ordinary fail-mode decision.
//
// PreToolUse starts the installed full hook on a packaged install, or the
// small guard on a one-line install, directly. Cursor imports Claude Code's
// settings but starts this handler without arguments; a cmd.exe command there
// interrupted ordinary Cursor tool calls. The guard gives that argument-free
// start no answer. The small guard copy is kept outside the replaceable install
// tree and the gateway repairs the current copy during its hook audit. Managed
// and Secure Client hook registrations retain their exec form.
//
// An older cmd.exe guard and a direct launcher guard remain recognizable for
// supported upgrade, teardown and rollback. Setup requires a working small
// guard for every Windows launcher layout.
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
var claudeCodeLauncherGuardWords = strings.Fields(hookguard.MissingMessage)

// ClaudeCodeLauncherMissingMessage is the guard sentence on one line, which
// the PreToolUse guard (internal/hookguard) prints.
const ClaudeCodeLauncherMissingMessage = hookguard.MissingMessage

// ClaudeCodeLauncherGuardSubcommand is the first argument of the PreToolUse
// guard handler.
const ClaudeCodeLauncherGuardSubcommand = hookguard.Subcommand

// claudeCodeWindowsCommandProcessor is the system cmd.exe the guard runs: the
// one in the system directory the Windows API reports (windowsSystemCmdExe),
// never one named by SystemRoot in the environment of whoever runs Setup. The
// writer and the recognizer (claudeCodeCmdGuardParts) use the same one, so a
// Setup run with SystemRoot unset or changed still recognizes the guard it
// wrote (GAP-1851).
func claudeCodeWindowsCommandProcessor() string {
	return windowsSystemCmdExe()
}

// claudeCodeLauncherGuardable reports whether cmd.exe reads the launcher path
// literally inside double quotes: it must not contain a quote, a variable
// sign or a line break. Other paths keep the exec form.
func claudeCodeLauncherGuardable(launcher string) bool {
	return hookguard.Guardable(launcher)
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
	if launcher, hookArgs, ok := claudeGuardWrapperParts(hook); ok {
		return launcher, hookArgs, true
	}
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

// claudeCodePreToolGuardArgs is the argv of the PreToolUse guard handler.
func claudeCodePreToolGuardArgs(launcher string, hookArgs []string) []string {
	return append([]string{ClaudeCodeLauncherGuardSubcommand, launcher}, hookArgs...)
}

// claudeCodeAbsoluteHookExecutable reports an absolute path whose file name is
// defenseclaw-hook.exe.
func claudeCodeAbsoluteHookExecutable(path string) bool {
	return hookguard.AbsoluteHookExecutable(path)
}

// claudeCodePreToolGuardProgram reports a program that can run as the
// PreToolUse guard: an absolute defenseclaw-hook.exe (the installed full hook
// of a packaged install), defenseclaw-hook-guard.exe (the one-line install's
// guard beside its launcher) or defenseclaw-gateway.exe (the one-line guard
// of a repository build and of 1.0.5 release candidates), all of which answer
// the launcher-guard argv.
func claudeCodePreToolGuardProgram(path string) bool {
	if !claudeCodeLauncherGuardable(path) || (!isWindowsAbsolutePath(path) && !filepath.IsAbs(path)) {
		return false
	}
	name := path[strings.LastIndexAny(path, `\/`)+1:]
	return strings.EqualFold(name, windowsHookBinaryName) || strings.EqualFold(name, windowsHookGuardBinaryName) ||
		strings.EqualFold(name, windowsGatewayBinaryName)
}

// claudeCodePreToolGuardParts returns the launcher and hook argv of an exact
// generated PreToolUse guard handler.
func claudeCodePreToolGuardParts(hook map[string]interface{}) (string, []string, bool) {
	command, _ := hook["command"].(string)
	if !claudeCodePreToolGuardProgram(command) {
		return "", nil, false
	}
	args, ok := claudeCodeNativeExecArguments(hook)
	if !ok || len(args) == 0 || args[0] != hookguard.Subcommand {
		return "", nil, false
	}
	launcher, hookArgs, _, wrapped, _, ok := hookguard.ParseInvocationMode(args)
	if !ok || wrapped || normalizeWindowsHookExecutable(launcher) == normalizeWindowsHookExecutable(command) {
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
	return claudeCodeOneLinePreToolGuardFor(launcher)
}

// claudeCodeOneLinePreToolGuardFor returns the guard program beside launcher
// in the one-line install's ~/.local/bin layout: defenseclaw-hook-guard.exe
// when it is a regular file, else defenseclaw-gateway.exe when that is one (a
// repository build ships no guard file); otherwise "". The guard file comes
// first because it has the GUI subsystem: the console gateway got a console
// window of its own when Claude Code started it without one (GAP-2467).
func claudeCodeOneLinePreToolGuardFor(launcher string) string {
	if !claudeCodeAbsoluteHookExecutable(launcher) || !claudeCodeLauncherGuardable(launcher) {
		return ""
	}
	dir := launcher[:strings.LastIndexAny(launcher, `\/`)+1]
	for _, name := range []string{windowsHookGuardBinaryName, windowsGatewayBinaryName} {
		guard := dir + name
		if !claudeCodePreToolGuardProgram(guard) {
			continue
		}
		if info, err := os.Lstat(guard); err == nil && info.Mode().IsRegular() {
			return guard
		}
	}
	return ""
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
func claudeCodeUnavailableOpen(opts SetupOpts) bool {
	return !opts.ManagedEnterprise && !opts.SecureClientHookDelivery &&
		!strings.EqualFold(strings.TrimSpace(opts.PolicyTier), "strict")
}

func claudeCodeChainAdmission(opts SetupOpts, command string, args []string, goos string) error {
	if goos != "windows" || opts.ManagedEnterprise || opts.SecureClientHookDelivery {
		return nil
	}
	launcher, _, guarded := claudeCodeCmdGuardParts(map[string]interface{}{"command": command, "args": args})
	if !guarded {
		launcher = command
		if !hookguard.AbsoluteHookExecutable(launcher) {
			return nil
		}
	}
	if !claudeWrapperSafe(launcher) {
		return fmt.Errorf("the Claude Code hook launcher path cannot be rendered by cmd.exe")
	}
	if guard, _ := claudeChainFor(launcher); guard == "" {
		return fmt.Errorf("the Claude Code hook guard is unavailable; run the DefenseClaw installer again")
	}
	return nil
}

func claudeCodeWindowsHookInvocation(opts SetupOpts, executable string) (string, []string) {
	args := []string{"hook", "--connector", "claudecode"}
	if !opts.ManagedEnterprise && claudeCodeLauncherGuardable(executable) {
		return claudeCodeWindowsCommandProcessor(), claudeCodeLauncherGuardArgs(executable, args)
	}
	return executable, args
}

// claudeCodeHandlerInvocation binds each event to the per-user Windows
// chain when Setup installed one. Exact older forms remain readable for
// upgrade and teardown, but are not published again.
func claudeCodeHandlerInvocation(eventType, command string, args []string, unavailableOpen ...bool) (string, []string) {
	open := len(unavailableOpen) > 0 && unavailableOpen[0]
	hook := map[string]interface{}{"command": command, "args": args}
	launcher, hookArgs, ok := claudeCodeCmdGuardParts(hook)
	if !ok {
		return command, args
	}
	if guard, approved := claudeChainFor(launcher); guard != "" {
		if eventType == "PreToolUse" {
			// The installed full hook remains an independent start path on
			// packaged installs. A lost chain copy must not weaken it.
			if direct := claudeCodePreToolGuardExecutable(launcher); direct != "" {
				return direct, claudeGuardEventArgs(launcher, hookArgs, eventType, false, open)
			}
			return guard, claudeGuardEventArgs(launcher, hookArgs, eventType, false, open)
		}
		return claudeCodeWindowsCommandProcessor(), claudeGuardWrapperArgs(guard, approved, launcher, eventType, hookArgs, open)
	}
	guard := claudeCodePreToolGuardExecutable(launcher)
	if guard != "" {
		guardArgs := claudeCodePreToolGuardArgs(launcher, hookArgs)
		if eventType != "PreToolUse" || open {
			guardArgs = claudeGuardEventArgs(launcher, hookArgs, eventType, false, open)
		}
		return guard, guardArgs
	}
	if eventType != "PreToolUse" {
		// Setup refuses to publish an incomplete chain. An empty command is
		// the error value for callers that render before that preflight.
		return "", nil
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
	_, wanted, err := convert(data)
	if err != nil || wanted == 0 {
		return 0, err
	}
	converted := 0
	err = withFileLock(settingsPath, func() error {
		// A file nobody edited since setup gets its saved bytes back and needs
		// no conversion (restoreUneditedForRollback).
		if done, err := restoreUneditedForRollback(opts.DataDir, c.Name(), settingsPath, nil); err != nil || done {
			if err == nil {
				converted = wanted
			}
			return err
		}
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
		if runtime.GOOS != "windows" {
			for _, root := range []string{userHomeDir(), opts.DataDir} {
				if pathidentity.Same(path, filepath.Join(root, ".local", "bin", "defenseclaw-hook-user")) {
					return true
				}
			}
		}
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
			kept := handlers[:0]
			for _, rawHandler := range handlers {
				handler, ok := rawHandler.(map[string]interface{})
				if ok && goos != "windows" &&
					claudeCodePerUserFallbackTarget(handler, filepath.Dir(script)) {
					command, _ := handler["command"].(string)
					if owned(command) {
						changed++
						continue
					}
				}
				if ok && claudeCodeHandlerInEarlierReleaseForm(handler, goos, script, owned) {
					changed++
				}
				kept = append(kept, rawHandler)
			}
			group["hooks"] = kept
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
	if claudeCodePerUserGuardTarget(handler, filepath.Dir(script)) {
		native := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(script))), ".local", "bin", "defenseclaw-hook-user")
		if owned(native) {
			handler["command"] = script
			delete(handler, "args")
			return true
		}
	}
	command, _ := handler["command"].(string)
	if word, rest, ok := posixHookCommandSplit(claudeCodeUnguardedHookCommand(command)); ok &&
		filepath.IsAbs(word) && filepath.Base(word) == "defenseclaw-hook-user" && owned(word) {
		homeArg := " hook --connector claudecode --hook-home " +
			posixHookCommandWord(filepath.Dir(filepath.Dir(script)))
		if rest == homeArg ||
			(strings.HasPrefix(rest, homeArg+" --api-addr ") &&
				claudeCodeRollbackAPIAddr(strings.TrimPrefix(rest, homeArg+" --api-addr "))) {
			handler["command"] = script
			return true
		}
	}
	quoted := posixHookCommandWord(script)
	if quoted == script || claudeCodeUnguardedHookCommand(command) != quoted {
		return false
	}
	handler["command"] = script
	return true
}

// claudeCodeRollbackAPIAddr accepts only the exact shell word this release
// renders for a local gateway address, including a quoted bracketed IPv6 word.
func claudeCodeRollbackAPIAddr(rendered string) bool {
	addr, rest, ok := posixHookCommandSplit(rendered)
	return ok && rest == "" && posixHookCommandWord(addr) == rendered &&
		claudeCodeLoopbackGatewayEndpoint("http://"+addr)
}
