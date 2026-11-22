// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Raise-only across layers (1.0.10 lead ruling on rel-1-0-10:GAP-0867):
// turning on a later layer never lowers the verdict an earlier layer gives on
// its own. Checked for every layer pair, in all 5 packs, on Claude Code and
// Codex, for every System One answer, over the benign fixture call and the
// first shell cases of the tool-call corpus (loaded by case id, unchanged):
//   - rules (cascade 1) vs rules + System One (cascade 2);
//   - rules + System One vs rules + System One + judge (cascade 3), the judge
//     answering clean;
//   - cascade 3 with the judge unreachable, and timed out, vs cascade 2.
// Two rules (1.0.10 lead, rel-1-0-10:GAP-0868):
//  1. a judge that does not answer (unreachable, timed out) never lowers
//     anything: cascade 3 then gives exactly cascade 2's verdict, an unsure
//     System One ask or alert included;
//  2. an unsure System One answer (a confirm, or a block on a call the rules
//     flagged, which System One never confidently blocks) has no verdict of
//     its own, so a clean judge answer may resolve it, never below the rules
//     (cascade 1); a confident System One block is never lowered (GAP-0867).

// stalledLLMProvider never answers before the call's deadline.
type stalledLLMProvider struct{}

func (stalledLLMProvider) ChatCompletion(ctx context.Context, _ *ChatRequest) (*ChatResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (stalledLLMProvider) ChatCompletionStream(ctx context.Context, _ *ChatRequest, _ func(StreamChunk)) (*ChatUsage, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func raiseOnlyActionRank(action string) int {
	switch normalizedGuardrailAction(action) {
	case guardrailActionBlock:
		return 3
	case guardrailActionConfirm:
		return 2
	case guardrailActionAlert:
		return 1
	}
	return 0
}

// raiseOnlyCalls are the calls the layer pairs are compared on: the benign
// fixture call and the first shell cases of the tool-call corpus.
func raiseOnlyCalls(t *testing.T) []string {
	t.Helper()
	calls := []string{"make -C ./fixtures/reports"}
	file, err := os.Open(filepath.Join("testdata", "security_suite", "toolcall", "corpus.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1<<20), 16<<20)
	for scanner.Scan() && len(calls) < 9 {
		var row toolCallCorpusCase
		if json.Unmarshal(scanner.Bytes(), &row) == nil && row.Command != "" && (row.Tool == "" || row.Tool == "Bash") && row.Dialect == "" {
			calls = append(calls, row.Command)
		}
	}
	if len(calls) < 9 {
		t.Fatalf("only %d calls", len(calls))
	}
	return calls
}

func raiseOnlyAPI(t *testing.T, posture string, managedInstall bool, connector string, cascade int, dmURL string, judge LLMProvider) *APIServer {
	t.Helper()
	api := instructionProtectionTestAPIWithPack(t, connector, "action", "", posture)
	cfg := api.scannerCfg
	if managedInstall {
		cfg.DeploymentMode = managed.DeploymentModeManagedEnterprise
		cfg.Enterprise.Profile = managed.ProfileStandalone
	}
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.DetectionStrategy = "regex_judge"
	cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: dmURL, Timeout: 1}
	switch cascade {
	case 2:
		cfg.DecisionModel.HookConnectors = []string{connector}
		api.SetHookDecisionJudge(newDecisionOnlyJudge(cfg))
	case 3:
		cfg.Guardrail.Judge = config.JudgeConfig{Enabled: true, ToolInjection: true, HookConnectors: []string{connector}, HookTimeout: 0.2}
		j := &LLMJudge{cfg: &cfg.Guardrail.Judge, model: "test-model", provider: judge, rp: &guardrail.RulePack{}}
		j.decision = newDecisionModel(cfg, "")
		api.SetHookJudge(j)
	}
	return api
}

func TestRaiseOnlyAcrossLayers(t *testing.T) {
	calls := raiseOnlyCalls(t)
	answers := map[string]struct {
		choice string
		pAllow float64
	}{
		"allow": {"allow", 0.97}, "block": {"block", 0.02}, "confirm": {"confirm", 0.30}, "down": {"", 0},
	}
	judges := map[string]LLMProvider{
		"clean":       cleanToolJudgeProvider(),
		"unreachable": &mockLLMProvider{err: errors.New("judge unreachable")},
		"timed out":   stalledLLMProvider{},
	}
	blocks := 0
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			for name, ans := range answers {
				url := "http://127.0.0.1:1/v1/systemone" // nothing listens
				if ans.choice != "" {
					srv := fakeDecisionModel(t, ans.choice, ans.pAllow, nil)
					t.Cleanup(srv.Close)
					url = srv.URL
				}
				verdicts := func(cascade int, judge LLMProvider) []*ToolInspectVerdict {
					api := raiseOnlyAPI(t, tier.posture, tier.managed, connector, cascade, url, judge)
					out := make([]*ToolInspectVerdict, len(calls))
					for i, command := range calls {
						args, _ := json.Marshal(map[string]string{"command": command})
						out[i] = api.inspectToolPolicy(&ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: connector})
					}
					return out
				}
				c1, c2 := verdicts(1, nil), verdicts(2, nil)
				for i := range calls {
					if raiseOnlyActionRank(c2[i].Action) < raiseOnlyActionRank(c1[i].Action) {
						t.Errorf("%s/%s/S1 %s call %d: rules+S1 %s lowered rules %s", tier.name, connector, name, i, c2[i].Action, c1[i].Action)
					}
					if name == "block" && c2[i].Action == guardrailActionBlock {
						blocks++
					}
				}
				for jname, judge := range judges {
					c3 := verdicts(3, judge)
					for i := range calls {
						// A clean judge may resolve anything but a confident
						// System One block; it never goes below the rules.
						floor, layer := c2[i], "rules+S1"
						confident := c2[i].Action == guardrailActionBlock && c2[i].Severity == "CRITICAL" && slices.Contains(c2[i].Findings, decisionModelFindingID)
						if jname == "clean" && !confident {
							floor, layer = c1[i], "rules"
						}
						if raiseOnlyActionRank(c3[i].Action) < raiseOnlyActionRank(floor.Action) {
							t.Errorf("%s/%s/S1 %s/judge %s call %d: rules+S1+judge %s lowered %s %s (%s)",
								tier.name, connector, name, jname, i, c3[i].Action, layer, floor.Action, c3[i].Reason)
						}
						// Rule 1: no judge answer, exactly cascade 2. The only
						// raises a missing judge makes are refusals: the hook
						// fail mode's refusal of an escalated CRITICAL finding,
						// and under the strict policy the refusal of any judged
						// call (GAP-0559, option b).
						refused := slices.Contains(c3[i].Findings, escalatedJudgeUnavailableFinding) ||
							(tier.posture == "strict" && slices.ContainsFunc(c3[i].Findings, func(f string) bool { return strings.Contains(f, judgeUnavailableFinding) }))
						if jname != "clean" && !refused && (c3[i].Action != c2[i].Action || c3[i].Severity != c2[i].Severity) {
							t.Errorf("%s/%s/S1 %s/judge %s call %d: no judge answer gave %s %s, want cascade 2's %s %s",
								tier.name, connector, name, jname, i, c3[i].Action, c3[i].Severity, c2[i].Action, c2[i].Severity)
						}
					}
				}
			}
		}
	}
	if blocks == 0 {
		t.Fatal("no confident System One block in cascade 2: the block pairs were not exercised")
	}
}
