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
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func gap1909Handler(command string, args ...string) map[string]interface{} {
	handler := map[string]interface{}{"type": "command", "command": command}
	if args != nil {
		values := make([]interface{}, len(args))
		for i, arg := range args {
			values[i] = arg
		}
		handler["args"] = values
	}
	return handler
}

// gap1909Removed reports whether Setup's and Teardown's removal pass takes the
// handler out of its event.
func gap1909Removed(t *testing.T, handler map[string]interface{}, hooksDir string) bool {
	t.Helper()
	event := []interface{}{map[string]interface{}{"matcher": "*", "hooks": []interface{}{handler}}}
	remaining, err := removeOwnedClaudeCodeHooks(event, hooksDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return len(remaining) == 0
}

// GAP-1909: a settings.json copied from another account can name that
// account's DefenseClaw hook by a Windows path: the generated script by drive
// letter, UNC or \\?\ path, or the native launcher in one of the exact forms
// Windows Setup writes. Setup and Teardown claim those on every OS, as they
// claim the POSIX-path copies, and never a user's own hook.
func TestGAP1909ForeignWindowsPathHookEntriesAreClaimed(t *testing.T) {
	savedSystem := windowsSystemDirectory
	windowsSystemDirectory = func() string { return `C:\Windows\System32` }
	t.Cleanup(func() { windowsSystemDirectory = savedSystem })
	hooksDir := filepath.Join(t.TempDir(), ".defenseclaw", "hooks")

	hookArgs := []string{"hook", "--connector", "claudecode"}
	oneLine := `C:\Users\peer\.local\bin\defenseclaw-hook.exe`
	runtimeDir := `C:\Users\peer\AppData\Local\DefenseClaw\HookRuntime`
	launcher := runtimeDir + `\defenseclaw-hook.exe`
	guard := runtimeDir + `\claude-code-chain\defenseclaw-hook-guard.exe`
	approved := runtimeDir + `\claude-code-chain\defenseclaw-hook-guard.approved`
	cmdCommand, cmdArgs := claudeCodeWindowsHookInvocation(SetupOpts{}, oneLine)
	if cmdCommand != claudeCodeWindowsCommandProcessor() {
		t.Fatalf("fixture: per-user command = %q, want the cmd.exe guard", cmdCommand)
	}
	managedArgs := append(slices.Clone(hookArgs), "--enterprise-managed")

	claimed := map[string]map[string]interface{}{
		"drive, forward slashes":   gap1909Handler(`C:/Users/peer/.defenseclaw/hooks/claude-code-hook.sh`),
		"drive, backslashes":       gap1909Handler(`C:\Users\peer\.defenseclaw\hooks\claude-code-hook.sh`),
		"drive, mixed separators":  gap1909Handler(`c:\Users/peer\.defenseclaw/hooks\claude-code-hook.sh`),
		`\\?\ drive`:               gap1909Handler(`\\?\C:\Users\peer\.defenseclaw\hooks\claude-code-hook.sh`),
		`\\.\ drive`:               gap1909Handler(`\\.\C:\Users\peer\.defenseclaw\hooks\claude-code-hook.sh`),
		"UNC":                      gap1909Handler(`\\fs01\home\peer\.defenseclaw\hooks\claude-code-hook.sh`),
		"UNC, forward slashes":     gap1909Handler(`//fs01/home/peer/.defenseclaw/hooks/claude-code-hook.sh`),
		`\\?\UNC`:                  gap1909Handler(`\\?\UNC\fs01\home\peer\.defenseclaw\hooks\claude-code-hook.sh`),
		"case folded":              gap1909Handler(`C:\USERS\PEER\.DefenseClaw\HOOKS\Claude-Code-Hook.SH`),
		"single-quoted with space": gap1909Handler(`'C:\Users\Ana Lima\.defenseclaw\hooks\claude-code-hook.sh'`),
		"double-quoted with space": gap1909Handler(`"C:\Users\Ana Lima\.defenseclaw\hooks\claude-code-hook.sh"`),
		"edited script name":       gap1909Handler(`C:\Users\peer\.defenseclaw\hooks\claude-code-hook.sh.off`),
		"edited data dir":          gap1909Handler(`C:\Users\peer\.defenseclaw-old\hooks\claude-code-hook.sh`),
		"cmd.exe launcher guard":   gap1909Handler(cmdCommand, cmdArgs...),
		"chain wrapper":            gap1909Handler(claudeCodeWindowsCommandProcessor(), claudeGuardWrapperArgs(guard, approved, launcher, "Stop", hookArgs)...),
		"chain PreToolUse guard":   gap1909Handler(guard, claudeGuardEventArgs(launcher, hookArgs, "PreToolUse", false)...),
		"managed wrapper": gap1909Handler(claudeCodeWindowsCommandProcessor(), claudeManagedGuardWrapperArgs(
			`D:\Apps\DefenseClaw\bin\defenseclaw-hook-guard.exe`, `D:\Apps\DefenseClaw\bin\defenseclaw-hook.exe`, "Stop", managedArgs)...),
		"one-line exec form": gap1909Handler(oneLine, hookArgs...),
	}
	// A real Windows data directory on Windows, a fixed one elsewhere.
	driveDir := `C:\Users\u\.defenseclaw`
	if runtime.GOOS == "windows" {
		driveDir = filepath.Join(testenv.PrivateTempDir(t), ".defenseclaw")
	}
	driveScript := driveDir + `\hooks\claude-code-hook.sh`
	claimed["drive data dir, backslashes"] = gap1909Handler(driveScript)
	claimed["drive data dir, forward slashes"] = gap1909Handler(strings.ReplaceAll(driveScript, `\`, "/"))
	claimed["drive data dir, edited script name"] = gap1909Handler(driveScript + ".bak")
	for name, handler := range claimed {
		if !gap1909Removed(t, handler, hooksDir) {
			t.Errorf("%s: the removal pass kept the foreign DefenseClaw entry %v", name, handler)
		}
	}

	editedGuard := slices.Clone(cmdArgs)
	editedGuard[len(editedGuard)-2] = "0"
	otherConnector := []string{"hook", "--connector", "codex"}
	otherCommand, otherArgs := claudeCodeWindowsHookInvocation(SetupOpts{}, `C:\Tools\review-hook.exe`)
	kept := map[string]map[string]interface{}{
		"exec form in another product's folder": gap1909Handler(`C:\OtherProduct\defenseclaw-hook.exe`, hookArgs...),
		"one-line exec form, other connector":   gap1909Handler(oneLine, otherConnector...),
		"one-line exec form, extra argument":    gap1909Handler(oneLine, append(slices.Clone(hookArgs), "--x")...),
		"edited cmd.exe guard":                  gap1909Handler(cmdCommand, editedGuard...),
		"cmd.exe guard of another program":      gap1909Handler(otherCommand, otherArgs...),
		"chain wrapper, other connector":        gap1909Handler(claudeCodeWindowsCommandProcessor(), claudeGuardWrapperArgs(guard, approved, launcher, "Stop", otherConnector)...),
		"script outside .defenseclaw":           gap1909Handler(`C:\Users\me\hooks\claude-code-hook.sh`),
		"other script name":                     gap1909Handler(`C:\Users\peer\.defenseclaw\hooks\review-hook.sh`),
		"drive-relative":                        gap1909Handler(`C:Users\peer\.defenseclaw\hooks\claude-code-hook.sh`),
		"rooted without a volume":               gap1909Handler(`\Users\peer\.defenseclaw\hooks\claude-code-hook.sh`),
		"with an argument":                      gap1909Handler(`C:\Users\peer\.defenseclaw\hooks\claude-code-hook.sh --flag`),
		"with a second command":                 gap1909Handler(`C:\Users\peer\.defenseclaw\hooks\claude-code-hook.sh; echo done`),
		"unclean":                               gap1909Handler(`C:\Users\peer\.defenseclaw\hooks\..\hooks\claude-code-hook.sh`),
		"doubled separator":                     gap1909Handler(`C:\Users\peer\\.defenseclaw\hooks\claude-code-hook.sh`),
		`\\?\ with a forward slash`:             gap1909Handler(`\\?\C:/Users/peer/.defenseclaw/hooks/claude-code-hook.sh`),
		"double-quoted expansion":               gap1909Handler(`"C:\Users\$USERNAME\.defenseclaw\hooks\claude-code-hook.sh"`),
		"unterminated quote":                    gap1909Handler(`"C:\Users\peer\.defenseclaw\hooks\claude-code-hook.sh`),
		"quote glued to text":                   gap1909Handler(`"C:\Users\peer\.defenseclaw\hooks\claude-code-hook.sh"x`),
		"UNC share named .defenseclaw":          gap1909Handler(`\\fs01\.defenseclaw\claude-code-hook.sh`),
		"user hook":                             gap1909Handler(`C:\Users\me\bin\my-review-hook.exe`),
	}
	for name, handler := range kept {
		if gap1909Removed(t, handler, hooksDir) {
			t.Errorf("%s: the removal pass claimed %v as a DefenseClaw entry", name, handler)
		}
	}
}

// GAP-1909: Setup replaces and Teardown removes the copied entries of another
// account on every OS, and keeps the user's own hooks.
func TestGAP1909SetupAndTeardownReplaceForeignWindowsPathEntries(t *testing.T) {
	dir := t.TempDir()
	settingsPath := filepath.Join(dir, "settings.json")
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = settingsPath
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	hookArgs := []string{"hook", "--connector", "claudecode"}
	cmdCommand, cmdArgs := claudeCodeWindowsHookInvocation(SetupOpts{}, `C:\Users\fx1909peer\.local\bin\defenseclaw-hook.exe`)
	foreign := []interface{}{
		gap1909Handler(`C:/Users/fx1909peer/.defenseclaw/hooks/claude-code-hook.sh`),
		gap1909Handler(`C:\Users\fx1909peer\.defenseclaw\hooks\claude-code-hook.sh`),
		gap1909Handler(`\\?\C:\Users\fx1909peer\.defenseclaw\hooks\claude-code-hook.sh`),
		gap1909Handler(cmdCommand, cmdArgs...),
	}
	own := []interface{}{
		gap1909Handler("/usr/local/bin/my-review-hook.sh"),
		gap1909Handler(`C:\OtherProduct\defenseclaw-hook.exe`, hookArgs...),
	}
	write := func(hooks map[string]interface{}) {
		t.Helper()
		data, err := json.Marshal(map[string]interface{}{"hooks": hooks})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(settingsPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(map[string]interface{}{
		"PreToolUse": []interface{}{map[string]interface{}{"matcher": "*", "hooks": append(slices.Clone(foreign), own...)}},
		"Stop":       []interface{}{map[string]interface{}{"hooks": slices.Clone(foreign)}},
	})
	opts := SetupOpts{
		DataDir:       filepath.Join(dir, "self"),
		ProxyAddr:     "127.0.0.1:4000",
		APIAddr:       "127.0.0.1:18970",
		APIToken:      "api-token",
		OTLPPathToken: strings.Repeat("a", 64),
	}
	if err := os.MkdirAll(opts.DataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	check := func(step string) {
		t.Helper()
		after := mustReadClaudeSettingsForTest(t, settingsPath)
		if strings.Contains(after, "fx1909peer") {
			t.Fatalf("%s kept a foreign DefenseClaw hook entry: %s", step, after)
		}
		if !strings.Contains(after, "/usr/local/bin/my-review-hook.sh") || !strings.Contains(after, `OtherProduct`) {
			t.Fatalf("%s lost a hook of the user: %s", step, after)
		}
	}
	c := NewClaudeCodeConnector()
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	check("Setup")

	// A copied entry can also arrive after Setup; Teardown must remove it.
	var settings map[string]interface{}
	if err := json.Unmarshal([]byte(mustReadClaudeSettingsForTest(t, settingsPath)), &settings); err != nil {
		t.Fatal(err)
	}
	hooks := settings["hooks"].(map[string]interface{})
	group := hooks["PreToolUse"].([]interface{})[0].(map[string]interface{})
	group["hooks"] = append(group["hooks"].([]interface{}), foreign...)
	write(hooks)
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	check("Teardown")
}
