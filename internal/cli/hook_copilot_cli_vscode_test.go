// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

// GAP-1075: the Copilot CLI ran the VS Code Local hook file next to its
// machine policy hooks, so each CLI event was evaluated twice.
func TestCopilotCLIRunsVSCodeLocalHookOnlyForTheCLIUnderMachinePolicy(t *testing.T) {
	oldExe, oldPolicy := hookAgentExecutable, hookCopilotCLIMachinePolicyInForce
	t.Cleanup(func() { hookAgentExecutable, hookCopilotCLIMachinePolicyInForce = oldExe, oldPolicy })
	exe, policy := "/opt/agents/lib/node_modules/@github/copilot/node_modules/@github/copilot-darwin-arm64/copilot", true
	hookAgentExecutable = func() string { return exe }
	hookCopilotCLIMachinePolicyInForce = func() bool { return policy }

	if !copilotCLIRunsVSCodeLocalHook("copilot", "vscode-local", true) {
		t.Fatal("the CLI's delivery of the VS Code Local hook file must be answered without a second evaluation")
	}
	cases := []struct {
		name, connector, surface, exe string
		managed, policy               bool
	}{
		{"camelCase machine policy hook", "copilot", "", exe, true, true},
		{"not managed", "copilot", "vscode-local", exe, false, true},
		{"machine policy not in force", "copilot", "vscode-local", exe, true, false},
		{"VS Code extension host", "copilot", "vscode-local", "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)", true, true},
		{"VS Code server node", "copilot", "vscode-local", "/home/u/.vscode-server/bin/abc/node", true, true},
		{"unknown engine", "copilot", "vscode-local", "", true, true},
		{"other connector", "claudecode", "vscode-local", exe, true, true},
	}
	for _, tc := range cases {
		exe, policy = tc.exe, tc.policy
		if copilotCLIRunsVSCodeLocalHook(tc.connector, tc.surface, tc.managed) {
			t.Errorf("%s: must be evaluated", tc.name)
		}
	}
	exe, policy = `C:\Users\u\AppData\Local\copilot\copilot.exe`, true
	if !copilotCLIRunsVSCodeLocalHook("copilot", "vscode-local", true) {
		t.Error("copilot.exe is the CLI too")
	}
	// GAP-1779: VS Code's Copilot CLI agent host runs the same engine.
	exe = `c:\Program Files\Microsoft VS Code\07f806f999\resources\app\node_modules.asar.unpacked\@github\copilot-sdk-win32-x64\prebuilds\win32-x64\copilot-runtime.exe`
	if !copilotCLIRunsVSCodeLocalHook("copilot", "vscode-local", true) {
		t.Error("the VS Code agent host's copilot-runtime.exe is the CLI engine too")
	}
	exe = `C:\Users\u\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	if copilotCLIRunsVSCodeLocalHook("copilot", "vscode-local", true) {
		t.Error("VS Code itself must be evaluated")
	}
}
