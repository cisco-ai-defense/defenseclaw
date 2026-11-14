// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The one bound rule for a PowerShell reading that stops at its command cap
// under the statement budget (rel-1-0-10:GAP-0589, GAP-0590). The attack
// units are the existing PowerShell atomic parity fixtures, loaded by index
// and placed beside ordinary lines in code; no new command text is added.
//
// In every tier (default, permissive, strict, managed, managed strict) and on
// both hooks that run PowerShell (the Claude Code PowerShell tool and the
// Codex shell tool on a Windows host, which selects the PowerShell dialect):
//   - a capped call is TRUNCATED: it carries the evaluation-limit finding
//     naming cap=items and is at least the unknown tier of its pack;
//   - a fixture placed first, last, or last after an unreadable statement,
//     with 100 ordinary lines, keeps its own finding and verdict: the answer is
//     the fixture's answer alone or the unknown tier, whichever is stricter,
//     and never more;
//   - an ordinary script of 70 or 127 lines (over the command cap, under the
//     statement budget) is exactly the unknown tier: an alert in default and
//     permissive, a block in strict; one of 30 lines is read to its end and
//     allowed;
//   - a call over the statement budget keeps its refusal (GAP-0426 rows), and
//     a POSIX call past
//     the command cap (the control, TestGAP0589POSIXOverCapControl) is at
//     least the unknown tier as on rel, with a state write after the cap
//     still blocking.

// gap0589Filler is n ordinary PowerShell lines: an assigned & call is two
// commands, so about 64 lines fill the command cap.
func gap0589Filler(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("$o%d = & git rev-parse HEAD", i)
	}
	return out
}

func gap0589Join(parts ...[]string) string {
	var all []string
	for _, part := range parts {
		all = append(all, part...)
	}
	return strings.Join(all, "\n")
}

// gap0589Route sends one PowerShell call through a hook as on a Windows host.
type gap0589Route struct {
	name, connector string
	decide          func(t *testing.T, api *APIServer, cwd, command string) (string, []string)
}

var gap0589Routes = []gap0589Route{
	{"claudecode PowerShell", "claudecode", func(t *testing.T, api *APIServer, cwd, command string) (string, []string) {
		resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "gap0589", CWD: cwd, ToolName: "PowerShell",
			ToolInput: map[string]interface{}{"command": command},
		})
		return resp.Action, resp.Findings
	}},
	{"codex shell", "codex", func(t *testing.T, api *APIServer, _, command string) (string, []string) {
		resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "shell", CWD: `C:\repo`,
			ToolInput: map[string]interface{}{"command": command},
		})
		return resp.Action, resp.Findings
	}},
}

// gap0589TierAPI is the test API of one tier for connector, its tier
// asserted at the route (boundedTierAPI, with the connector's own profile).
func gap0589TierAPI(t *testing.T, connector, posture string, managedInstall bool, want bounded.Tier) *APIServer {
	t.Helper()
	api := instructionProtectionTestAPIWithPack(t, connector, "action", "", posture)
	if managedInstall {
		api.scannerCfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		api.scannerCfg.Enterprise.Profile = managed.ProfileStandalone
	}
	if got := api.boundedTier(context.Background(), connector); got != want {
		t.Fatalf("pack %s managed=%t: the %s route judges in tier %d, want %d", posture, managedInstall, connector, got, want)
	}
	return api
}

func gap0589WindowsHost(t *testing.T) {
	t.Helper()
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
}

// withoutBoundedTruncation is findings without the evaluation-limit finding
// that only the floor of a TRUNCATED reading added (withBoundedTruncation),
// and whether the call is TRUNCATED (an evaluation-limit finding names a
// bounded cap): a test of what the reading itself proves judges the rest. A
// limit finding the call had already (a statement budget) is kept.
func withoutBoundedTruncation(findings []RuleFinding) ([]RuleFinding, bool) {
	truncated := slices.ContainsFunc(findings, func(f RuleFinding) bool {
		return canonicalTrustedRuleID(f.RuleID) == evaluationLimitRuleID && strings.Contains(f.Evidence, bounded.ReasonCode)
	})
	kept := slices.DeleteFunc(slices.Clone(findings), func(f RuleFinding) bool {
		return canonicalTrustedRuleID(f.RuleID) == evaluationLimitRuleID && strings.HasPrefix(f.Title, boundedTruncatedTitle)
	})
	return kept, truncated
}

func gap0589HasRule(findings []string, ruleID string) bool {
	for _, finding := range findings {
		if strings.HasPrefix(finding, ruleID+":") || finding == ruleID {
			return true
		}
	}
	return false
}

func TestGAP0589PowerShellCappedReadingFiveTiers(t *testing.T) {
	gap0589WindowsHost(t)
	cwd := filepath.Join(t.TempDir(), "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	fixtures := windowsAtomicParityPositives[2:4] // the PowerShell fixtures
	for _, tier := range boundedTestTiers {
		floor := bounded.Unknown(tier.tier)
		for _, route := range gap0589Routes {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, fixture := range fixtures {
				aloneAction, aloneFindings := route.decide(t, api, cwd, fixture.command)
				alone := boundedParse(aloneAction)
				t.Logf("ROW %s | %s | %s | alone | %s", tier.name, route.name, fixture.name, aloneAction)
				ruled := gap0589HasRule(aloneFindings, fixture.ruleID)
				if !ruled {
					t.Fatalf("%s/%s/%s alone: action %s findings %v, want the fixture's rule", tier.name, route.name, fixture.name, aloneAction, aloneFindings)
				}
				for _, layout := range []struct {
					name    string
					command string
				}{
					{"first+100", gap0589Join([]string{fixture.command}, gap0589Filler(100))},
					{"100+last", gap0589Join(gap0589Filler(100), []string{fixture.command})},
					{"unreadable+100+last", gap0589Join([]string{windowsUnreadableStatement}, gap0589Filler(100), []string{fixture.command})},
				} {
					action, findings := route.decide(t, api, cwd, layout.command)
					t.Logf("ROW %s | %s | %s | %s | %s", tier.name, route.name, fixture.name, layout.name, action)
					want := bounded.Stricter(alone, floor)
					if got := boundedParse(action); got != want {
						t.Errorf("%s/%s/%s %s: action %s, want %s (the fixture alone %s, the unknown tier %s); findings %v",
							tier.name, route.name, fixture.name, layout.name, action, want, aloneAction, floor, findings)
					}
					if ruled && !gap0589HasRule(findings, fixture.ruleID) {
						t.Errorf("%s/%s/%s %s: the fixture's %s is missing: %v", tier.name, route.name, fixture.name, layout.name, fixture.ruleID, findings)
					}
					if !boundedHasLimit(findings, bounded.Items, true) {
						t.Errorf("%s/%s/%s %s: not TRUNCATED (no %s naming cap=items): %v", tier.name, route.name, fixture.name, layout.name, evaluationLimitRuleID, findings)
					}
				}
			}
			for _, benign := range []struct {
				lines     int
				truncated bool
			}{{30, false}, {70, true}, {127, true}} {
				action, findings := route.decide(t, api, cwd, gap0589Join(gap0589Filler(benign.lines)))
				t.Logf("ROW %s | %s | benign | %d lines | %s", tier.name, route.name, benign.lines, action)
				want := bounded.Allow
				if benign.truncated {
					want = floor
				}
				if got := boundedParse(action); got != want {
					t.Errorf("%s/%s benign %d lines: action %s, want %s; findings %v", tier.name, route.name, benign.lines, action, want, findings)
				}
				if got := boundedHasLimit(findings, bounded.Items, true); got != benign.truncated {
					t.Errorf("%s/%s benign %d lines: TRUNCATED=%t, want %t: %v", tier.name, route.name, benign.lines, got, benign.truncated, findings)
				}
			}
		}
		// CMD and the statement budget (rel-1-0-10:GAP-0426): 64 copies of
		// a two-statement fixture and an unreadable statement. The Codex
		// hook reads the call as PowerShell, where it is one statement over
		// the budget, which refuses it whole: still at least the unknown tier
		// with the evaluation-limit finding.
		unit := windowsAtomicParityPositives[2]
		parts := make([]string, 0, 65)
		for range 64 {
			parts = append(parts, unit.command)
		}
		cmdCall := strings.Join(append(parts, windowsUnreadableStatement), "\n")
		api := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
		action, findings := gap0589Routes[1].decide(t, api, cwd, cmdCall)
		t.Logf("ROW %s | codex shell | over budget | 64 units + unreadable | %s", tier.name, action)
		if got := boundedParse(action); got < floor || !boundedHasLimit(findings, bounded.Items, false) {
			t.Errorf("%s over budget: action %s, want at least %s with %s: %v", tier.name, action, floor, evaluationLimitRuleID, findings)
		}
	}
}

// TestGAP0589POSIXOverCapControl is the POSIX control, unchanged from rel: a
// Bash call past the command cap under the statement budget is at least the
// unknown tier, and a state write after the cap still blocks in every tier.
func TestGAP0589POSIXOverCapControl(t *testing.T) {
	env := boundedLaneEnv(t)
	lines := make([]string, 50)
	for i := range lines {
		lines[i] = "echo $(date) $(date)" // three commands a statement
	}
	benign := strings.Join(lines, "\n")
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(benign))
		t.Logf("ROW %s | claudecode Bash | posix over-cap | 50 lines | %s | %v", tier.name, action, findings)
		if boundedParse(action) < bounded.Unknown(tier.tier) {
			t.Errorf("%s POSIX over-cap: action %s, want at least the unknown tier: %v", tier.name, action, findings)
		}
		action, findings = boundedDecideClaudeCode(t, api, env, boundedShellCommand(benign+"\n"+boundedShellSeen))
		t.Logf("ROW %s | claudecode Bash | posix over-cap | 50 lines + state write | %s", tier.name, action)
		if boundedParse(action) != bounded.Block {
			t.Errorf("%s POSIX over-cap + state write: action %s, want block: %v", tier.name, action, findings)
		}
	}
}
