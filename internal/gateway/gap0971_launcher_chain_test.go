// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap0971Wrappers are chains of the GAP-0857 wrapper operands spelled as
// launcher names (gap0857Wrappers without the start rows), 1 to 8 long and
// past the launcher reading bound, and start prefixes whose switches take an
// operand (/d <dir>, /D <launcher name>, /d<dir>, /node, /affinity, /machine).
func gap0971Wrappers() []gap0805Wrapper {
	var operands []gap0805Wrapper
	for _, w := range gap0857Wrappers {
		if w.argv[0] != "start" {
			operands = append(operands, w)
		}
	}
	var out []gap0805Wrapper
	for _, n := range []int{1, 2, 3, 4, 5, 6, 7, 8, 12, 20} {
		chain := gap0805Wrapper{name: fmt.Sprintf("decoy chain n=%d", n)}
		for i := 0; i < n; i++ {
			w := operands[i%len(operands)]
			chain.argv = append(chain.argv, w.argv...)
			chain.text += w.text
		}
		out = append(out, chain)
	}
	return append(out,
		gap0805Wrapper{"start /d <dir> <title>", []string{"start", "/d", `C:\work`, "T"}, `start /d C:\work "T" `},
		gap0805Wrapper{"start /d <launcher name> <title>", []string{"start", "/d", "cmd", "T"}, `start /d cmd "T" `},
		gap0805Wrapper{`start "" /d <launcher name>`, []string{"start", "", "/d", "pwsh"}, `start "" /d pwsh `},
		gap0805Wrapper{"start /b <title> /d <launcher name>", []string{"start", "/b", "T", "/d", "cmd"}, `start /b "T" /d cmd `},
		gap0805Wrapper{"start <title> /D <launcher name>", []string{"start", "T", "/D", "pwsh.exe"}, `start "T" /D pwsh.exe `},
		gap0805Wrapper{"start /d<dir> <title>", []string{"start", `/dC:\work`, "T"}, `start /dC:\work "T" `},
		gap0805Wrapper{"start /node <n> <title>", []string{"start", "/node", "1", "T"}, `start /node 1 "T" `},
		gap0805Wrapper{"start /affinity <mask> <title>", []string{"start", "/AFFINITY", "3", "T"}, `start /AFFINITY 3 "T" `},
		gap0805Wrapper{"start /machine <arch> <title>", []string{"start", "/machine", "amd64", "T"}, `start /machine amd64 "T" `},
	)
}

// A launcher behind any number of wrapper operands spelled as launcher names,
// or behind a start switch that takes an operand, is read: the authorized_keys
// redirect fixture blocks behind each, argv and string alike. An ordinary
// script behind them is allowed, or, where the chain holds more launcher
// readings than the reader judges, TRUNCATED: at least the unknown tier with
// the evaluation-limit rule, never above it (the one bound rule). 5 tiers, a
// PowerShell and a CMD launcher (rel-1-0-10:GAP-0971).
func TestGAP0971LauncherChainsDefault(t *testing.T)       { gap0971LauncherChains(t, 0) }
func TestGAP0971LauncherChainsPermissive(t *testing.T)    { gap0971LauncherChains(t, 1) }
func TestGAP0971LauncherChainsStrict(t *testing.T)        { gap0971LauncherChains(t, 2) }
func TestGAP0971LauncherChainsManaged(t *testing.T)       { gap0971LauncherChains(t, 3) }
func TestGAP0971LauncherChainsManagedStrict(t *testing.T) { gap0971LauncherChains(t, 4) }

func gap0971LauncherChains(t *testing.T, tierIndex int) {
	gap0589WindowsHost(t)
	cwd := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	tier := boundedTestTiers[tierIndex]
	floor := bounded.Unknown(tier.tier)
	api := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
	decide := func(command interface{}) codexHookResponse {
		return api.evaluateCodexHook(t.Context(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
			ToolInput: map[string]interface{}{"command": command},
		})
	}
	launchers := []gap0711Launcher{gap0805Launchers[1], gap0805Launchers[3]}
	for _, w := range gap0971Wrappers() {
		for _, l := range launchers {
			forms := func(body string) map[string]codexHookResponse {
				return map[string]codexHookResponse{
					"argv": decide(gap0805Argv(w, l, body)), "string": decide(gap0805Text(w, l, body)),
				}
			}
			for form, got := range forms(overLimitWindowsRedirect) {
				if boundedParse(got.Action) != bounded.Block {
					t.Errorf("%s/%s/%s redirect %s: action %s %v, want block", tier.name, w.name, l.name, form, got.Action, got.RuleIDs)
				}
			}
			for form, got := range forms(`git log --oneline -5`) {
				action := boundedParse(got.Action)
				limited := containsString(got.RuleIDs, evaluationLimitRuleID)
				if action != bounded.Allow && (!limited || action != floor) {
					t.Errorf("%s/%s/%s benign %s: action %s %v, want allow or the unknown tier %s with %s",
						tier.name, w.name, l.name, form, got.Action, got.RuleIDs, floor, evaluationLimitRuleID)
				}
				if strings.HasPrefix(w.name, "start") && action != bounded.Allow {
					t.Errorf("%s/%s/%s benign %s: action %s %v, want allow", tier.name, w.name, l.name, form, got.Action, got.RuleIDs)
				}
			}
		}
	}
}
