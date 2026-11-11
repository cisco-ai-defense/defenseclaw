// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A .NET write through a variable bound to a path under a junction onto the
// state directory writes the state file, as Set-Content of the same path
// does: observe mode blocks it at top level and in pwsh -Command. The same
// write to a sibling folder whose name starts with the junction name stays
// allowed.
func TestPowerShellBoundWriteThroughAJunctionToStateIsProven(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	sibling := filepath.Join(project, "lnkDx")
	for _, dir := range []string{project, state, sibling} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(state, "config.yaml"), filepath.Join(sibling, "config.yaml")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(project, "lnkD"), state).CombinedOutput(); err != nil {
		t.Fatalf("junction: %v %s", err, out)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	const connectorName = "ps-bound-junction"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	linked := filepath.Join(project, "lnkD", "config.yaml")
	other := filepath.Join(sibling, "config.yaml")
	write := func(path string) string { return `$p='` + path + `'; [System.IO.File]::WriteAllText($p,'x')` }
	api := &APIServer{}
	for _, tc := range []struct {
		name, command string
		block         bool
	}{
		{"bound write through the junction", write(linked), true},
		{"bound write through the junction in pwsh", `pwsh -NoProfile -Command "` + write(linked) + `"`, true},
		{"bound write to the sibling folder", write(other), false},
		{"bound write to the sibling folder in pwsh", `pwsh -NoProfile -Command "` + write(other) + `"`, false},
	} {
		for _, managed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/managed=%t", tc.name, managed), func(t *testing.T) {
				args, _ := json.Marshal(map[string]string{"command": tc.command})
				input := actionfacts.Input{Tool: "shell_command", Args: args, CWD: project, ActiveHome: home}
				input.DialectHint = agentHookWindowsShellDialect(input)
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: input, LegacyText: string(args), Connector: connectorName,
					EnforcementCapable: true, ProtectedHomeHook: managed,
				})
				verdict := buildVerdict(findings, "tool_call")
				if got := verdict.Action == "block" && api.provenActiveStateMutation(t.Context(), verdict); got != tc.block {
					t.Fatalf("observe-mode hard block=%t, want %t (action %q, findings %v)", got, tc.block, verdict.Action, findingIDs(findings))
				}
			})
		}
	}
}
