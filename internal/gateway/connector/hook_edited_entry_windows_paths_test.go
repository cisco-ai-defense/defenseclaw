// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// GAP-1923: a hook config copied from another Windows account or from
// dotfiles names DefenseClaw's hook script by a Windows path. Claude Code's
// Setup and Teardown claim such a copy since GAP-1909; Codex, Kiro, Copilot
// and Hermes kept it next to the working set. Each connector's removal pass
// now reads a Windows-path script word with the same POSIX script rules, on
// every OS. A user's hook, and a word the shape rule does not accept, stay.

// gap1923Claimed are copies of DefenseClaw's script scriptName, each followed
// by binding, that a removal pass must claim. Every command names the
// account fx1923peer (in any case).
func gap1923Claimed(t *testing.T, scriptName, binding string) map[string]string {
	t.Helper()
	stem := strings.TrimSuffix(scriptName, ".sh")
	dataDir := `D:\fx1923peer\.defenseclaw`
	if runtime.GOOS == "windows" {
		// A real Windows data directory of another account.
		dataDir = filepath.Join(testenv.PrivateTempDir(t), "fx1923peer", ".defenseclaw")
	}
	if !isWindowsDriveAbsolutePath(filepath.ToSlash(dataDir)) {
		t.Fatalf("fixture: %q is not a drive path", dataDir)
	}
	return map[string]string{
		"drive, forward slashes":   `C:/Users/fx1923peer/.defenseclaw/hooks/` + scriptName + binding,
		"drive, backslashes":       `C:\Users\fx1923peer\.defenseclaw\hooks\` + scriptName + binding,
		`\\?\ drive`:               `\\?\C:\Users\fx1923peer\.defenseclaw\hooks\` + scriptName + binding,
		"UNC":                      `\\fs01\home\fx1923peer\.defenseclaw\hooks\` + scriptName + binding,
		"case folded":              `C:\USERS\FX1923PEER\.DefenseClaw\HOOKS\` + strings.ToUpper(scriptName) + binding,
		"single-quoted with space": `'C:\Users\fx1923peer one\.defenseclaw\hooks\` + scriptName + `'` + binding,
		"double-quoted with space": `"C:\Users\fx1923peer two\.defenseclaw\hooks\` + scriptName + `"` + binding,
		"edited script name":       `C:\Users\fx1923peer\.defenseclaw\hooks\` + stem + `X.sh` + binding,
		"edited data dir":          `C:\Users\fx1923peer\.defenseclaw-old\hooks\` + scriptName + binding,
		"real drive data dir":      dataDir + `\hooks\` + scriptName + binding,
	}
}

// gap1923Kept are hooks a removal pass must keep. Every command names the
// account fx1923keep once.
func gap1923Kept(scriptName, binding string) map[string]string {
	return map[string]string{
		"script outside .defenseclaw": `C:\Users\fx1923keep\hooks\` + scriptName,
		"other script name":           `C:\Users\fx1923keep\.defenseclaw\hooks\review-hook.sh` + binding,
		"drive-relative":              `C:Users\fx1923keep\.defenseclaw\hooks\` + scriptName + binding,
		"rooted without a volume":     `\Users\fx1923keep\.defenseclaw\hooks\` + scriptName + binding,
		"unclean":                     `C:\Users\fx1923keep\.defenseclaw\hooks\..\hooks\` + scriptName + binding,
		"with an argument":            `C:\Users\fx1923keep\.defenseclaw\hooks\` + scriptName + ` --flag`,
		"with a second command":       `C:\Users\fx1923keep\.defenseclaw\hooks\` + scriptName + `; echo done`,
		"double-quoted expansion":     `"C:\Users\fx1923keep$HOME\.defenseclaw\hooks\` + scriptName + `"` + binding,
		"user hook":                   `C:\Users\fx1923keep\bin\my-review-hook.exe`,
	}
}

func gap1923Names(commands map[string]string) []string {
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// gap1923Check fails when text still names a claimed copy or lost a kept hook.
func gap1923Check(t *testing.T, step, text string, kept int) {
	t.Helper()
	if strings.Contains(strings.ToLower(text), "fx1923peer") {
		t.Errorf("%s kept a copied DefenseClaw hook entry named by a Windows path:\n%s", step, text)
	}
	if got := strings.Count(text, "fx1923keep"); got != kept {
		t.Errorf("%s kept %d of the user's %d hooks:\n%s", step, got, kept, text)
	}
}

// gap1942Launcher is the native launcher a Windows Setup registers.
const gap1942Launcher = `C:\Program Files\DefenseClaw\defenseclaw-hook.exe`

// gap1942HookCommands are the hook commands a connector's Setup passes to its
// removal passes: the Unix script path, and on Windows the native launcher,
// adapter or bridge command, which names no script. The Windows-path claim
// was a no-op on a Windows host for Hermes, Kiro's agent files and Copilot's
// unexpected events, which took the script name from that command (GAP-1942);
// each removal pass runs with both on every OS.
func gap1942HookCommands(unix, windows string) map[string]string {
	return map[string]string{"unix script": unix, "windows command": windows}
}

func gap1923SetupOpts(root string) SetupOpts {
	return SetupOpts{
		DataDir:       filepath.Join(root, ".defenseclaw"),
		ProxyAddr:     "127.0.0.1:4000",
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "api-token",
		OTLPPathToken: strings.Repeat("a", 64),
	}
}

func gap1923WriteFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func gap1923JSON(t *testing.T, value interface{}) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestGAP1923CodexSetupAndTeardownClaimWindowsPathCopies(t *testing.T) {
	const binding = " --event PreToolUse --hook-contract c1"
	claimed := gap1923Claimed(t, "codex-hook.sh", binding)
	kept := gap1923Kept("codex-hook.sh", binding)
	hooksDir := filepath.Join(t.TempDir(), ".defenseclaw", "hooks")
	for _, name := range gap1923Names(claimed) {
		if !isOwnedCodexHookHandler(map[string]interface{}{"type": "command", "command": claimed[name]}, hooksDir) {
			t.Errorf("%s: the Codex removal pass kept the copied DefenseClaw handler %q", name, claimed[name])
		}
	}
	for _, name := range gap1923Names(kept) {
		if isOwnedCodexHookHandler(map[string]interface{}{"type": "command", "command": kept[name]}, hooksDir) {
			t.Errorf("%s: the Codex removal pass claimed %q as a DefenseClaw handler", name, kept[name])
		}
	}

	root := testenv.PrivateTempDir(t)
	path := filepath.Join(root, "agent", "config.toml")
	previous := CodexConfigPathOverride
	CodexConfigPathOverride = path
	t.Cleanup(func() { CodexConfigPathOverride = previous })
	// Codex asks for a manual repair when one group holds several
	// DefenseClaw handlers, so each copy gets its own run, in its own group
	// before a group of the user's hooks.
	seed := func(copied string) string {
		var b strings.Builder
		b.WriteString("[[hooks.PreToolUse]]\nmatcher = '*'\n\n[[hooks.PreToolUse.hooks]]\ncommand = " +
			gap1923JSON(t, copied) + "\ntype = 'command'\n\n[[hooks.PreToolUse]]\nmatcher = '*'\n")
		for _, name := range gap1923Names(kept) {
			b.WriteString("\n[[hooks.PreToolUse.hooks]]\ncommand = " + gap1923JSON(t, kept[name]) + "\ntype = 'command'\n")
		}
		return b.String()
	}
	opts := gap1923SetupOpts(root)
	codex := NewCodexConnector()
	for _, name := range gap1923Names(claimed) {
		gap1923WriteFile(t, path, seed(claimed[name]))
		if err := codex.Setup(context.Background(), opts); err != nil {
			t.Fatalf("%s: Setup: %v", name, err)
		}
		gap1923Check(t, name+": Codex Setup", readHookFileForTest(t, path), len(kept))
		gap1923WriteFile(t, path, seed(claimed[name]))
		if err := codex.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("%s: Teardown: %v", name, err)
		}
		gap1923Check(t, name+": Codex Teardown", readHookFileForTest(t, path), len(kept))
	}
}

func TestGAP1923KiroSetupAndTeardownClaimWindowsPathCopies(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	unixScript := filepath.Join(root, ".defenseclaw", "hooks", kiroHookScriptName)
	agentCommands := gap1942HookCommands(unixScript, windowsKiroHookCommandForBinary(gap1942Launcher, "", false))
	v3Commands := gap1942HookCommands(unixScript, windowsKiroHookCommandForBinary(gap1942Launcher, KiroHookSurfaceV3, false))
	for surface, binding := range map[string]string{"agent": "", "v3": " --hook-surface v3"} {
		claimed := gap1923Claimed(t, kiroHookScriptName, binding)
		kept := gap1923Kept(kiroHookScriptName, binding)
		for _, form := range gap1923Names(agentCommands) {
			agentCommand, v3Command := agentCommands[form], v3Commands[form]
			for _, name := range gap1923Names(claimed) {
				command := claimed[name]
				if len(removeKiroOwnedV2Hooks([]interface{}{map[string]interface{}{"command": command}}, agentCommand)) != 0 {
					t.Errorf("%s %s, %s: the Kiro agent removal pass kept the copied DefenseClaw entry %q", surface, name, form, command)
				}
				v3 := map[string]interface{}{"name": "copied", "action": map[string]interface{}{"type": "command", "command": command}}
				if !kiroOwnedV3Hook(v3, v3Command) {
					t.Errorf("%s %s, %s: the Kiro v3 removal pass kept the copied DefenseClaw entry %q", surface, name, form, command)
				}
			}
			for _, name := range gap1923Names(kept) {
				command := kept[name]
				if len(removeKiroOwnedV2Hooks([]interface{}{map[string]interface{}{"command": command}}, agentCommand)) != 1 {
					t.Errorf("%s %s, %s: the Kiro agent removal pass claimed %q", surface, name, form, command)
				}
				// A user's v3 hook that names kiro-hook.sh is the user's too
				// (GAP-1932): v3 claims only DefenseClaw's names, commands and
				// script shape.
				v3 := map[string]interface{}{"name": "user", "action": map[string]interface{}{"type": "command", "command": command}}
				if kiroOwnedV3Hook(v3, v3Command) {
					t.Errorf("%s %s, %s: the Kiro v3 removal pass claimed %q", surface, name, form, command)
				}
			}
		}
	}

	// The universal agent file: Setup's repair and Teardown.
	claimed := gap1923Claimed(t, kiroHookScriptName, "")
	kept := gap1923Kept(kiroHookScriptName, "")
	path := filepath.Join(root, "agent", "universal.json")
	seed := func() string {
		hooks := []interface{}{}
		for i, set := range []map[string]string{claimed, kept} {
			for _, name := range gap1923Names(set) {
				hooks = append(hooks, map[string]interface{}{
					"name": []string{"copied", "user"}[i] + "-" + name, "trigger": "preToolUse", "matcher": "*",
					"action": map[string]interface{}{"type": "command", "command": set[name]},
				})
			}
		}
		return gap1923JSON(t, map[string]interface{}{"hooks": hooks})
	}
	for _, form := range gap1923Names(agentCommands) {
		gap1923WriteFile(t, path, seed())
		if err := patchKiroV2AgentHooks(path, agentCommands[form]); err != nil {
			t.Fatalf("%s: repair: %v", form, err)
		}
		gap1923Check(t, form+": Kiro repair", readHookFileForTest(t, path), len(kept))
		gap1923WriteFile(t, path, seed())
		if err := removeKiroV2AgentHooksKeeping(path, agentCommands[form], false, nil); err != nil {
			t.Fatalf("%s: uninstall: %v", form, err)
		}
		gap1923Check(t, form+": Kiro uninstall", readHookFileForTest(t, path), len(kept))
	}
}

func TestGAP1923CopilotSetupAndTeardownClaimWindowsPathCopies(t *testing.T) {
	const binding = " --event 'preToolUse'"
	root := testenv.PrivateTempDir(t)
	hookScript := filepath.Join(root, ".defenseclaw", "hooks", "copilot-hook.sh")
	path := filepath.Join(root, "agent", "defenseclaw.json")
	document := func(commands ...string) string {
		entries := make([]interface{}, 0, len(commands))
		for _, command := range commands {
			entries = append(entries, map[string]interface{}{"type": "command", "bash": command})
		}
		return gap1923JSON(t, map[string]interface{}{"version": 1, "hooks": map[string]interface{}{"preToolUse": entries}})
	}

	// DefenseClaw owns this file: a copy is claimed and replaced. Copilot
	// refuses an event with several DefenseClaw entries, so each copy gets
	// its own run.
	claimed := gap1923Claimed(t, "copilot-hook.sh", binding)
	for _, name := range gap1923Names(claimed) {
		gap1923WriteFile(t, path, document(claimed[name]))
		if err := patchCopilotHooks(path, hookScript); err != nil {
			t.Errorf("%s: repair refused a file that holds only a DefenseClaw copy: %v", name, err)
			continue
		}
		gap1923Check(t, name+": Copilot repair", readHookFileForTest(t, path), 0)
		gap1923WriteFile(t, path, document(claimed[name]))
		if err := removeCopilotHookReferences(path, hookScript); err != nil {
			t.Fatalf("%s: uninstall: %v", name, err)
		}
		gap1923Check(t, name+": Copilot uninstall", readHookFileForTest(t, path), 0)
	}

	// A user's command in it is not DefenseClaw's: the repair still refuses
	// the file and uninstall keeps the command.
	kept := gap1923Kept("copilot-hook.sh", binding)
	for _, name := range gap1923Names(kept) {
		gap1923WriteFile(t, path, document(kept[name]))
		if err := patchCopilotHooks(path, hookScript); err == nil || !strings.Contains(err.Error(), "another hook file") {
			t.Errorf("%s: repair must refuse the user's command %q: %v", name, kept[name], err)
		}
		gap1923WriteFile(t, path, document(kept[name]))
		if err := removeCopilotHookReferences(path, hookScript); err != nil {
			t.Fatalf("%s: uninstall: %v", name, err)
		}
		if got := strings.Count(readHookFileForTest(t, path), "fx1923keep"); got != 1 {
			t.Errorf("%s: uninstall removed the user's command %q", name, kept[name])
		}
	}

	// An event Setup does not bind: the copy is claimed by its script shape,
	// with or without the event binding, whatever command Setup registers.
	commands := gap1942HookCommands(hookScript, hookInvocationCommandFor("windows", "copilot", hookScript))
	for _, form := range gap1923Names(commands) {
		for _, binding := range []string{binding, ""} {
			for _, name := range gap1923Names(gap1923Claimed(t, "copilot-hook.sh", binding)) {
				command := gap1923Claimed(t, "copilot-hook.sh", binding)[name]
				for _, entry := range []interface{}{
					map[string]interface{}{"type": "command", "bash": command},
					map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": command}}},
				} {
					if !copilotUnexpectedEventOwnsHook(entry, commands[form]) {
						t.Errorf("%s, %s: an unexpected event kept the copied DefenseClaw entry %v", form, name, entry)
					}
				}
			}
			for _, name := range gap1923Names(gap1923Kept("copilot-hook.sh", binding)) {
				command := gap1923Kept("copilot-hook.sh", binding)[name]
				if copilotUnexpectedEventOwnsHook(map[string]interface{}{"type": "command", "bash": command}, commands[form]) {
					t.Errorf("%s, %s: an unexpected event claimed the user's command %q", form, name, command)
				}
			}
		}
	}
}

func TestGAP1923HermesSetupAndTeardownClaimWindowsPathCopies(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	hookScript := filepath.Join(root, ".defenseclaw", "hooks", "hermes-hook.sh")
	path := filepath.Join(root, "agent", "config.yaml")
	claimed := gap1923Claimed(t, "hermes-hook.sh", "")
	kept := gap1923Kept("hermes-hook.sh", "")
	seed := func() string {
		var b strings.Builder
		b.WriteString("hooks:\n  pre_tool_call:\n")
		for _, set := range []map[string]string{claimed, kept} {
			for _, name := range gap1923Names(set) {
				b.WriteString("  - command: '" + strings.ReplaceAll(set[name], "'", "''") + "'\n    matcher: .*\n")
			}
		}
		return b.String()
	}
	// The command each OS's Setup passes (hookCommandForOS), with the
	// launcher a Windows Setup records (opts.HookExecutable).
	opts := gap1923SetupOpts(root)
	opts.HookExecutable = gap1942Launcher
	hermes := NewHermesConnector()
	commands := gap1942HookCommands(hookScript, hermes.hookCommandForOS("windows", opts))
	executables := map[string]string{"unix script": "", "windows command": gap1942Launcher}
	if commands["windows command"] == "" {
		t.Fatal("fixture: no Windows Hermes command")
	}
	for _, form := range gap1923Names(commands) {
		gap1923WriteFile(t, path, seed())
		if err := patchHermesHooks(path, commands[form], executables[form]); err != nil {
			t.Fatalf("%s: repair: %v", form, err)
		}
		gap1923Check(t, form+": Hermes repair", readHookFileForTest(t, path), len(kept))
		gap1923WriteFile(t, path, seed())
		if err := removeHermesHooks(path, commands[form], nil); err != nil {
			t.Fatalf("%s: uninstall: %v", form, err)
		}
		gap1923Check(t, form+": Hermes uninstall", readHookFileForTest(t, path), len(kept))
	}
}
