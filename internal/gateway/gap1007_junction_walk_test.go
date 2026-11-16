// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// gap1007Tier is one of the five hook tiers: the pack posture, and a
// managed hook peer whose gateway reads the hook client's map.
type gap1007Tier struct {
	name, posture string
	managed       bool
}

var gap1007Tiers = []gap1007Tier{
	{"default", "default", false}, {"permissive", "permissive", false}, {"strict", "strict", false},
	{"managed", "default", true}, {"managed-strict", "strict", true},
}

// gap1007Decide judges one Claude Code PreToolUse call in tier: a per-user
// gateway walks the call itself; a managed one gets the peer home and the
// hook client's map (gap1006ManagedDecide).
func gap1007Decide(t *testing.T, home, cwd string, tier gap1007Tier, tool, command string) string {
	t.Helper()
	if tier.managed {
		return gap1006ManagedDecide(t, home, cwd, tier.posture, tool, command)
	}
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
		"tool_name": tool, "tool_input": map[string]any{"command": command}})
	if err != nil {
		t.Fatal(err)
	}
	installToolCallCorpusProfileConnector(t, "claudecode", tier.posture)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), tier.posture)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	rt := claudeCodeHookProfileRuntime(connector.HookProfile{Name: "claudecode"})
	return rt.Evaluate(api, context.Background(), agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse"}, body, payload).Action
}

// gap1007Spellings are the GAP-1007 spellings of the DefenseClaw config
// through project/jx (a junction on Windows, a symlink elsewhere) followed
// by .., and the forms that write them (the TestZZG982LK rows). The
// backslash spellings are Windows paths only.
func gap1007Spellings(home string) (targets, forms []struct{ id, text string }) {
	nat, fwd := home, filepath.ToSlash(home)
	q := func(p string) string { return "'" + p + "'" }
	targets = []struct{ id, text string }{
		{"lkDots", q(fwd + "/project/jx/../.defenseclaw/config.yaml")},
		{"lkDotsRel", "jx/../.defenseclaw/config.yaml"},
	}
	if runtime.GOOS == "windows" {
		targets = append(targets,
			struct{ id, text string }{"lkDotsN", q(nat + `\project\jx\..\.defenseclaw\config.yaml`)},
			struct{ id, text string }{"lkDotsMix", q(fwd + `/project/jx\..\.defenseclaw/config.yaml`)})
	}
	forms = []struct{ id, text string }{
		{"gt", "echo x > %s"}, {"gtgt", "echo x >> %s"}, {"tee", "echo x | tee %s"},
		{"c24", "/opt/tools/add-key notes.txt > %s"},
	}
	return targets, forms
}

// TestGAP1007JunctionDotDotWriteIsStateWriteInEveryTier: a write to the
// DefenseClaw config through a junction (a symlink on POSIX) followed by ..
// gets the verdict of the config named directly, a block, in all five tiers
// and for both shell tools: the walk spelling is judged before the lexical
// one on the same path in every tier (rel-1-0-10:GAP-1007). The ordinary
// project file the operand cleans to lexically stays allowed.
func TestGAP1007JunctionDotDotWriteIsStateWriteInEveryTier(t *testing.T) {
	home, cwd := gap1006Fixture(t)
	targets, forms := gap1007Spellings(home)
	direct := "echo x > '" + filepath.ToSlash(home) + "/project/jx/config.yaml'"
	cells := 0
	for _, tier := range gap1007Tiers {
		for _, tool := range []string{"Bash", "PowerShell"} {
			if got := gap1007Decide(t, home, cwd, tier, tool, direct); got != "block" {
				t.Fatalf("%s/%s: the config named through the junction directly: %s, want block", tier.name, tool, got)
			}
			for _, target := range targets {
				for _, form := range forms {
					cells++
					command := fmt.Sprintf(form.text, target.text)
					if got := gap1007Decide(t, home, cwd, tier, tool, command); got != "block" {
						t.Errorf("%s/%s/%s|%s: action %s, want block (the config through the junction)", tier.name, tool, form.id, target.id, got)
					}
				}
			}
			decoy := "echo x > '" + filepath.ToSlash(home) + "/project/.defenseclaw/config.yaml'"
			if got := gap1007Decide(t, home, cwd, tier, tool, decoy); got == "block" {
				t.Errorf("%s/%s: the ordinary project file write alone blocked", tier.name, tool)
			}
		}
	}
	t.Logf("GAP1007 junction state-write cells checked: %d", cells)
}

// TestGAP1007UnwalkableDotDotWriteIsUnknownTier: a write operand whose ..
// follows a link the walk cannot resolve (a link loop) has an unknown target:
// an alert in the default, permissive and managed default tiers and a block
// in strict and managed strict, never an allow (rel-1-0-10:GAP-1007). A ..
// after a folder that does not exist yet is not unknown
// (TestDotDotWalkUnresolvedReadings); its own rule judges it.
func TestGAP1007UnwalkableDotDotWriteIsUnknownTier(t *testing.T) {
	home, cwd := gap1006Fixture(t)
	loop := filepath.Join(cwd, "lp")
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", loop, loop).CombinedOutput(); err != nil {
			t.Fatalf("mklink: %v %s", err, out)
		}
	} else if err := os.Symlink("lp", loop); err != nil {
		t.Fatal(err)
	}
	if _, ok := hookpaths.ResolveWriteTarget(filepath.Join(loop, "x")); ok {
		t.Fatal("fixture: the loop resolved")
	}
	for _, tier := range gap1007Tiers {
		for _, tool := range []string{"Bash", "PowerShell"} {
			got := gap1007Decide(t, home, cwd, tier, tool, "echo x > lp/../out.txt")
			if tier.posture == "strict" {
				if got != "block" {
					t.Errorf("%s/%s: unwalkable .. operand: %s, want block", tier.name, tool, got)
				}
			} else if got == "allow" || got == "block" {
				t.Errorf("%s/%s: unwalkable .. operand: %s, want the unknown tier (alert)", tier.name, tool, got)
			}
		}
	}
}
