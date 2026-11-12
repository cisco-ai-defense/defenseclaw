// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A managed gateway cannot walk the user's links: it places a path only from
// the hook client's map. A .NET write through a variable bound to a path the
// client lists in the state tree (a junction in the project onto
// ~/.defenseclaw) is the state write, at top level and in pwsh -Command,
// as the Set-Content of that path is. The same write when the client lists
// the path as itself, and a read of the listed path, stay allowed.
func TestManagedPowerShellBoundWriteThroughAClientPlacedLinkIsProven(t *testing.T) {
	const home = `C:\Users\r109mgd`
	project := home + `\project`
	linked := project + `\lnkD\config.yaml`
	state := home + `\.defenseclaw\config.yaml`
	const connectorName = "ps-managed-client-link"
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	write := `$p='` + linked + `'; [System.IO.File]::WriteAllText($p,'x')`
	placed := map[string]string{hookpaths.CWDKey: project, linked: state}
	itself := map[string]string{hookpaths.CWDKey: project, linked: linked}
	api := &APIServer{}
	for _, tc := range []struct {
		name, command string
		targets       map[string]string
		block         bool
	}{
		{"bound write the client places in state", write, placed, true},
		{"bound write the client places in state in pwsh", `pwsh -NoProfile -Command "` + write + `"`, placed, true},
		{"bound write the client places as itself", write, itself, false},
		{"bound read the client places in state", `$p='` + linked + `'; Get-Content $p`, placed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := json.Marshal(map[string]string{"command": tc.command})
			input := actionfacts.Input{Tool: "shell_command", Args: args, CWD: project, ActiveHome: home,
				DialectHint: actionfacts.DialectPowerShell}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName,
				EnforcementCapable: true, ProtectedHomeHook: true, ResolvedWriteTargets: tc.targets,
			})
			verdict := buildVerdict(findings, "tool_call")
			if got := verdict.Action == "block" && api.provenActiveStateMutation(t.Context(), verdict); got != tc.block {
				t.Fatalf("observe-mode hard block=%t, want %t (action %q, findings %v)", got, tc.block, verdict.Action, findingIDs(findings))
			}
		})
	}
}
