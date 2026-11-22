// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestGAP0693PowerShellPaddingNextToAProtectedWriteKeepsTheBlock: a protected
// PowerShell write placed beside the padding of a reading cap (513 nested
// parentheses or subexpressions, 131073 words, 2100 statements) keeps its own
// verdict in every tier, on both hooks that run PowerShell. Without it the call
// was the unknown tier of its pack (an alert in four of the five tiers) with
// the write lost behind the cap, which the same call without the padding was
// not (rel-1-0-10:GAP-0693). A call with no write beside the padding is
// exactly the unknown tier.
//
// The attack units are existing fixtures: the PowerShell atomic parity
// fixtures and the Windows redirect of the GAP-0611 tests; the padding is
// generated.
func TestGAP0693PowerShellPaddingNextToAProtectedWriteKeepsTheBlock(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The matrix is 300 hook calls, most of them over 100 KB: about 40 s
		// here and 25 minutes on a busy Windows host, which would hold a
		// native CI shard (GAP-0766). The logic does not depend on the host
		// (windowsHookHost is forced); the smoke test below runs natively,
		// and the matrix ran once natively on dc-ent-win for this change.
		t.Skip("the full matrix runs on POSIX hosts; TestGAP0693PowerShellPaddingSmoke runs everywhere")
	}
	gap0693PaddingMatrix(t, gap0693Fillers(true), boundedTestTiers, gap0589Routes)
}

// TestGAP0693PowerShellPaddingSmoke is the small, host-independent cut of the
// matrix above: the Claude Code PowerShell tool in the default and strict
// packs, the two cheap fillers, so a native Windows run stays under a minute.
func TestGAP0693PowerShellPaddingSmoke(t *testing.T) {
	var tiers []struct {
		name    string
		posture string
		managed bool
		tier    bounded.Tier
	}
	for _, tier := range boundedTestTiers {
		if tier.name == "default" || tier.name == "strict" {
			tiers = append(tiers, tier)
		}
	}
	gap0693PaddingMatrix(t, gap0693Fillers(false), tiers, gap0589Routes[:1])
}

func gap0693Fillers(all bool) []struct{ name, text string } {
	r := strings.Repeat
	fillers := []struct{ name, text string }{
		{"paren513", r("(", 513) + "1" + r(")", 513)},
		{"stmts2100", r("a;", 2100)},
	}
	if all {
		fillers = append(fillers,
			struct{ name, text string }{"subexpr513", r("$(", 513) + "1" + r(")", 513)},
			struct{ name, text string }{"words131073", "Write-Output " + r("a ", 131073)})
	}
	return fillers
}

func gap0693PaddingMatrix(t *testing.T, fillers []struct{ name, text string }, tiers []struct {
	name    string
	posture string
	managed bool
	tier    bounded.Tier
}, routes []gap0589Route) {
	t.Helper()
	gap0589WindowsHost(t)
	cwd := `C:\Users\alice`
	type unit struct{ name, command, ruleID string }
	units := []unit{{"redirect", overLimitWindowsRedirect, ""}}
	for _, fixture := range windowsAtomicParityPositives[2:4] {
		units = append(units, unit{fixture.name, fixture.command, fixture.ruleID})
	}
	benign := `Get-ChildItem C:\Users\alice\project`
	for _, tier := range tiers {
		floor := bounded.Unknown(tier.tier)
		for _, route := range routes {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, filler := range fillers {
				for _, layout := range []string{"before", "after"} {
					place := func(command string) string {
						if layout == "before" {
							return command + "\n" + filler.text
						}
						return filler.text + "\n" + command
					}
					for _, u := range units {
						aloneAction, _ := route.decide(t, api, cwd, u.command)
						action, findings := route.decide(t, api, cwd, place(u.command))
						t.Logf("ROW %s | %s | %s | %s %s | %s", tier.name, route.name, u.name, filler.name, layout, action)
						// The call keeps the verdict of the unit alone, or is
						// the unknown tier when that is stricter (the same
						// as the command-cap rows, GAP-0589).
						want := bounded.Stricter(boundedParse(aloneAction), floor)
						if u.name == "redirect" {
							want = bounded.Block
						}
						if got := boundedParse(action); got != want {
							t.Errorf("%s/%s %s %s %s: action %s, want %s (alone %s, unknown tier %s); findings %v", tier.name, route.name, u.name, filler.name, layout, action, want, aloneAction, floor, findings)
						}
						// A fixture of more than one statement is a chain: its
						// statements judged one by one prove less than the chain
						// does, so only the verdict above is held for it.
						if u.ruleID != "" && len(powerShellCapPieces(u.command)) == 1 && !gap0589HasRule(findings, u.ruleID) {
							t.Errorf("%s/%s %s %s %s: the fixture's %s is missing: %v", tier.name, route.name, u.name, filler.name, layout, u.ruleID, findings)
						}
					}
					action, findings := route.decide(t, api, cwd, place(benign))
					t.Logf("ROW %s | %s | benign | %s %s | %s", tier.name, route.name, filler.name, layout, action)
					if got := boundedParse(action); got != floor {
						t.Errorf("%s/%s benign %s %s: action %s, want the unknown tier %s; findings %v", tier.name, route.name, filler.name, layout, action, floor, findings)
					}
					if !gap0589HasRule(findings, evaluationLimitRuleID) {
						t.Errorf("%s/%s benign %s %s: not TRUNCATED, no %s: %v", tier.name, route.name, filler.name, layout, evaluationLimitRuleID, findings)
					}
				}
			}
		}
	}
}

// TestPowerShellCapPiecesCutTheEndsOfACall pins the cut: the first and the
// last statements of a call, at a line end or a ; outside a string, a
// here-string, a comment and a bracket; a statement over the piece bound is
// padding and is not judged alone.
func TestPowerShellCapPiecesCutTheEndsOfACall(t *testing.T) {
	for _, row := range []struct {
		name, command string
		want          []string
	}{
		{"line ends and semicolons", "a\nb; c\r\nd", []string{"a", "b", "c", "d"}},
		{"a pipeline stays one piece", "a | b\nc", []string{"a | b", "c"}},
		{"a string keeps its ;", "echo 'a;b'\nc", []string{"echo 'a;b'", "c"}},
		{"a bracket keeps its line end", "f (1,\n2)\nc", []string{"f (1,\n2)", "c"}},
		{"a here-string is one piece", "x = @\"\na\nb\n\"@\nc", []string{"x = @\"\na\nb\n\"@", "c"}},
		{"a comment is not a statement end", "a # b; c\nd", []string{"a # b; c", "d"}},
		{"padding is no piece", "a\n" + strings.Repeat("x", psCapPieceBytes+1) + "\nb", []string{"a", "b"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := powerShellCapPieces(row.command); fmt.Sprint(got) != fmt.Sprint(row.want) {
				t.Fatalf("pieces %q, want %q", got, row.want)
			}
		})
	}
	var lines []string
	for i := range 40 {
		lines = append(lines, fmt.Sprintf("s%d", i))
	}
	got := powerShellCapPieces(strings.Join(lines, "\n"))
	if len(got) != 2*psCapPiecesPerEnd || got[0] != "s0" || got[len(got)-1] != "s39" {
		t.Fatalf("a long call gives the first and the last %d statements, got %q", psCapPiecesPerEnd, got)
	}
}
