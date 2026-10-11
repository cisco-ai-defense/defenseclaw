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
		return 0, fmt.Errorf("Claude Code user settings %s: %w", settingsPath, err)
	}
	data, err := os.ReadFile(readPath)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read Claude Code settings %s: %w", settingsPath, err)
	}
	launcher := strings.TrimSpace(opts.HookExecutable)
	if launcher == "" {
		launcher = defenseclawHookBinary()
	}
	owned := func(path string) bool {
		return pathidentity.Same(path, launcher) || isDefenseClawHookExecutable(path)
	}
	script := filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"))
	convert := func(data []byte) ([]byte, int, error) {
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
	if _, changed, err := convert(data); err != nil || changed == 0 {
		return 0, err
	}
	converted := 0
	err = withFileLock(settingsPath, func() error {
		return atomicTransformFileWithStateDir(settingsPath, opts.DataDir, 0o600,
			func(current []byte, exists bool) (atomicTransformResult, error) {
				if !exists {
					return atomicTransformResult{Remove: true}, nil
				}
				out, changed, err := convert(current)
				if err != nil || changed == 0 {
					return atomicTransformResult{Data: current}, err
				}
				backupDir := filepath.Join(opts.DataDir, "backups")
				if err := os.MkdirAll(backupDir, 0o700); err != nil {
					return atomicTransformResult{}, fmt.Errorf("keep a copy of the settings: %w", err)
				}
				if err := atomicWriteFile(filepath.Join(backupDir, claudeCodeRollbackBackupName), current, 0o600); err != nil {
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
