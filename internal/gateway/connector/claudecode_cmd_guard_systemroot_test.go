// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"slices"
	"testing"
)

// GAP-1851 (review R2-1): per-user Setup writes the cmd.exe launcher guard
// with the cmd.exe its own recognizer accepts, the one in the system
// directory the Windows API reports, whatever SystemRoot says in the
// environment Setup runs in. Before, the writer read SystemRoot and the
// recognizer the system directory, so a Setup with SystemRoot unset, or run
// from an agent that changed it, wrote a guard that its own teardown,
// migration and ownership checks no longer read as DefenseClaw's.
func TestClaudeCodeCmdGuardWriterAndRecognizerAgreeWhateverSystemRootSays(t *testing.T) {
	saved := windowsSystemDirectory
	windowsSystemDirectory = func() string { return `D:\WINNT\System32\` }
	t.Cleanup(func() { windowsSystemDirectory = saved })
	launcher := `C:\Users\dcuser\.local\bin\defenseclaw-hook.exe`
	for _, systemRoot := range []string{"", `C:\Windows`, `E:\agent-root`} {
		t.Setenv("SystemRoot", systemRoot)
		command, args := claudeCodeWindowsHookInvocation(SetupOpts{HookExecutable: launcher}, launcher)
		if normalizeWindowsHookExecutable(command) != normalizeWindowsHookExecutable(`D:\WINNT\System32\cmd.exe`) {
			t.Fatalf("SystemRoot %q: Setup writes the guard for %q, not the system cmd.exe", systemRoot, command)
		}
		hook := map[string]interface{}{"type": "command", "command": command, "args": stringsToInterfaces(args)}
		guarded, hookArgs, ok := claudeCodeCmdGuardParts(hook)
		if !ok || guarded != launcher || !slices.Equal(hookArgs, []string{"hook", "--connector", "claudecode"}) {
			t.Fatalf("SystemRoot %q: the guard Setup wrote is not read as its own: %v %q %q", systemRoot, ok, guarded, hookArgs)
		}
	}
}
