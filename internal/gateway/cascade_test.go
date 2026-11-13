// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

var cascadeActions = []string{"allow", "log", "alert", "confirm", "block"}

func defaultCascade() config.EffectiveCascade { return (&config.Config{}).ResolveCascade("") }

// The final step's table: what the policy may do within the limits.
func TestCascadeFinalActionTable(t *testing.T) {
	e := defaultCascade()
	dec := func(action, id string) []policy.CascadeDecision {
		return []policy.CascadeDecision{{Action: action, ID: id, Reason: id}}
	}
	tests := []struct {
		name                        string
		before                      string
		flagged, critical           bool
		decisions                   []policy.CascadeDecision
		err                         error
		lowest, highest, floor      string
		want, decidedBy, policyRule string
	}{
		{"no decision keeps the cascade", "alert", true, false, nil, nil, "", "", "", "alert", "", ""},
		{"raise an allow", "allow", false, false, dec("block", "r1"), nil, "", "", "", "block", "policy", "r1"},
		{"raise capped by highest", "allow", false, false, dec("block", "r1"), nil, "", "confirm", "", "confirm", "policy", "r1"},
		{"highest never lowers the cascade", "block", true, false, dec("block", "r1"), nil, "", "alert", "", "block", "", ""},
		{"lower a block to the lowest", "block", true, false, dec("allow", "r2"), nil, "", "", "", "alert", "policy", "r2"},
		{"lower within an explicit lowest", "block", true, false, dec("allow", "r2"), nil, "allow", "", "", "allow", "policy", "r2"},
		{"lower never raises", "confirm", true, false, dec("log", "r2"), nil, "confirm", "", "", "confirm", "", ""},
		{"critical floor binds the lowering", "block", true, true, dec("allow", "r3"), nil, "allow", "", "", "alert", "policy", "r3"},
		{"critical floor block", "block", true, true, dec("allow", "r3"), nil, "allow", "", "block", "block", "", ""},
		{"opt-out lets a critical go to log", "block", true, true, dec("log", "r3"), nil, "log", "", "log", "log", "policy", "r3"},
		{"strictest decision wins", "allow", false, false, []policy.CascadeDecision{{Action: "alert", ID: "a"}, {Action: "block", ID: "b"}}, nil, "", "", "", "block", "policy", "b"},
		{"error raises to the unknown tier", "allow", false, false, nil, errors.New("boom"), "", "", "", "alert", "policy_error", ""},
		{"error never lowers", "block", true, false, nil, errors.New("boom"), "", "", "", "block", "", ""},
		{"floor without a policy", "alert", true, true, nil, nil, "", "", "block", "block", "critical_floor", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eff := e
			if tt.lowest != "" {
				eff.PolicyLowest = tt.lowest
			}
			if tt.highest != "" {
				eff.PolicyHighest = tt.highest
			}
			if tt.floor != "" {
				eff.CriticalFloor = tt.floor
			}
			out := cascadeFinalAction(tt.before, tt.flagged, tt.critical, tt.decisions, tt.err, "alert", eff)
			if out.Final != tt.want || out.DecidedBy != tt.decidedBy || out.PolicyRule != tt.policyRule {
				t.Fatalf("got final=%s decided_by=%q rule=%q, want %s %q %q", out.Final, out.DecidedBy, out.PolicyRule, tt.want, tt.decidedBy, tt.policyRule)
			}
		})
	}
}

// I2-I4: every combination of the cascade's action, the policy's answer
// and the administrator's limits keeps a proven CRITICAL at or above the
// floor (unless the floor is the explicit log opt-out), never lowers a
// flagged call below the lowest limit (or the cascade's own action, if
// lower), never raises above max(cascade, highest), and an error is at
// least the unknown tier.
func TestCascadeFinalInvariantGrid(t *testing.T) {
	base := defaultCascade()
	rank := cascadeRank
	answers := append([]string{"", "error"}, cascadeActions...)
	n := 0
	for _, before := range cascadeActions {
		for _, answer := range answers {
			for _, flagged := range []bool{false, true} {
				for _, critical := range []bool{false, true} {
					if critical && !flagged {
						continue // a proven finding flags the call
					}
					for _, lowest := range []string{"allow", "log", "alert", "confirm"} {
						for _, highest := range []string{"alert", "confirm", "block"} {
							if rank(lowest) > rank(highest) {
								continue
							}
							for _, floor := range []string{"log", "alert", "confirm", "block"} {
								for _, unknown := range []string{"alert", "confirm", "block"} {
									e := base
									e.PolicyLowest, e.PolicyHighest, e.CriticalFloor = lowest, highest, floor
									var decisions []policy.CascadeDecision
									var err error
									switch answer {
									case "":
									case "error":
										err = errors.New("eval failed")
									default:
										decisions = []policy.CascadeDecision{{Action: answer, ID: "x"}}
									}
									out := cascadeFinalAction(before, flagged, critical, decisions, err, unknown, e)
									got := rank(out.Final)
									n++
									if critical && got < rank(floor) {
										t.Fatalf("critical below floor: before=%s answer=%s floor=%s -> %s", before, answer, floor, out.Final)
									}
									if critical && floor != "log" && got < rank("alert") {
										t.Fatalf("critical silenced without the opt-out: %+v", out)
									}
									if flagged && got < min(rank(lowest), rank(before)) {
										t.Fatalf("flagged call below lowest: before=%s answer=%s lowest=%s -> %s", before, answer, lowest, out.Final)
									}
									if got > max(rank(before), rank(highest), rank(floor)*boolInt(critical), rank(unknown)*boolInt(err != nil)) {
										t.Fatalf("raised above the limits: before=%s answer=%s highest=%s -> %s", before, answer, highest, out.Final)
									}
									if err != nil && got < max(rank(before), rank(unknown)) {
										t.Fatalf("error below the unknown tier: before=%s unknown=%s -> %s", before, unknown, out.Final)
									}
									if answer == "" && err == nil && !critical && got != rank(before) {
										t.Fatalf("no decision changed the action: %s -> %s", before, out.Final)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if n < 5000 {
		t.Fatalf("grid ran %d cases", n)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func cascadeConfig(t *testing.T, posture string, cascade func(*config.CascadeConfig)) *config.Config {
	t.Helper()
	api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", posture)
	if cascade != nil {
		cascade(&api.scannerCfg.Guardrail.Cascade)
	}
	return api.scannerCfg
}

func TestCascadeJudgeRole(t *testing.T) {
	yes := true
	block := &ScanVerdict{Action: "block", Severity: "CRITICAL", Findings: []string{"llm-judge:x"}}
	agreed := &ScanVerdict{Action: "block", Severity: "CRITICAL", systemOneBlocked: true}
	tests := []struct {
		name         string
		set          func(*config.CascadeConfig)
		v            *ScanVerdict
		decisionOnly bool
		want         string
	}{
		{"default keeps the block", nil, block, false, "block"},
		{"max alert", func(c *config.CascadeConfig) { c.Judge.MaxAction = "alert" }, block, false, "alert"},
		{"max log is an allow", func(c *config.CascadeConfig) { c.Judge.MaxAction = "log" }, block, false, "allow"},
		{"needs System One: asks", func(c *config.CascadeConfig) { c.Judge.BlockNeedsSystemOne = &yes }, block, false, "confirm"},
		{"needs System One: agreed", func(c *config.CascadeConfig) { c.Judge.BlockNeedsSystemOne = &yes }, agreed, false, "block"},
		{"cascade 2 is not the judge", func(c *config.CascadeConfig) { c.Judge.MaxAction = "alert" }, block, true, "block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := cascadeConfig(t, "default", tt.set)
			got := applyCascadeJudgeRole(cfg, "claudecode", tt.decisionOnly, tt.v)
			if got.Action != tt.want {
				t.Fatalf("action = %s, want %s (%s)", got.Action, tt.want, got.Reason)
			}
			if len(got.Findings) != len(tt.v.Findings) {
				t.Fatalf("findings changed: %v", got.Findings)
			}
		})
	}
}

func TestCascadeUnsureVerdicts(t *testing.T) {
	if cascadeUnsureVerdict(config.CascadeConfirm, "r", 0.5) != nil {
		t.Fatal("confirm (the default) must keep today's confirm verdict")
	}
	alert := cascadeUnsureVerdict(config.CascadeAlert, "r", 0.5)
	if alert.Action != "alert" || !alert.cascadeFixed || alert.decisionConfirm {
		t.Fatalf("alert = %+v", alert)
	}
	rules := cascadeUnsureVerdict(config.CascadeFromRules, "r", 0.5)
	if rules.Action != "allow" || !rules.cascadeFixed {
		t.Fatalf("rules = %+v", rules)
	}
	// A fixed action is not mapped again by severity, even in the strict
	// pack, where a HIGH would block.
	cfg := cascadeConfig(t, "strict", nil)
	if got := hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", alert); got.Action != "alert" {
		t.Fatalf("strict pack remapped on_unsure alert to %s", got.Action)
	}
	dm := &decisionModel{allowAt: 0.3, blockAt: 0.75, blockRiskScore: 1.5, escalateRuleFlagged: true}
	if r := dm.routingFor(t.Context()); r.allowAt != 0.3 || r.onUnsure != config.CascadeConfirm || !r.escalateRuleFlagged {
		t.Fatalf("routing without a scope = %+v", r)
	}
}

// D6: decide is retired (s7/sysone 1eb8bf9277); a cascade-3 confident block
// with a silent judge ends at the decision model's HIGH floor: an alert in
// the default pack (block_at CRITICAL), a block in strict (block_at MEDIUM).
func TestCascadeThreeConfidentBlockSilentJudge(t *testing.T) {
	floor := &ScanVerdict{Action: "block", Severity: "HIGH", Findings: []string{decisionModelFindingID}, Scanner: decisionModelScanner, systemOneBlocked: true}
	for posture, want := range map[string]string{"default": "alert", "permissive": "alert", "strict": "block"} {
		cfg := cascadeConfig(t, posture, nil)
		got := hookJudgeLaneVerdict(cfg, "claudecode", "tool_call", strongerDecisionVerdict(nil, floor))
		if got.Action != want {
			t.Fatalf("%s pack: %s, want %s", posture, got.Action, want)
		}
		if !strongerDecisionVerdict(&ScanVerdict{Action: "allow", Severity: "NONE"}, floor).systemOneBlocked {
			t.Fatal("System One's block mark lost in the merge")
		}
	}
}

// I6: the unknown tier follows the pack by default and guardrail.cascade.unknown
// when set; never below alert.
func TestCascadeUnknownTier(t *testing.T) {
	request := trustedActionRequest{EnforcementCapable: true}
	truncatedOnly := withBoundedTruncation(nil, bounded.Of(bounded.Paths), request)
	tests := []struct {
		posture, unknown, want string
		tier                   bounded.Tier
	}{
		{"default", "", "alert", bounded.TierDefault},
		{"permissive", "", "alert", bounded.TierPermissive},
		{"strict", "", "block", bounded.TierStrict},
		{"default", "block", "block", bounded.TierStrict},
		{"default", "confirm", "confirm", bounded.TierConfirm},
		{"strict", "alert", "alert", bounded.TierDefault},
		{"strict", "pack", "block", bounded.TierStrict},
	}
	for _, tt := range tests {
		t.Run(tt.posture+"/"+tt.unknown, func(t *testing.T) {
			cfg := cascadeConfig(t, tt.posture, func(c *config.CascadeConfig) { c.Unknown = tt.unknown })
			got := guardrailActionForProfileUnknown(truncatedOnly, false,
				func() string { return cascadeUnknownForConfig(cfg, "claudecode") }, boundedTestActionFor)
			if got != tt.want {
				t.Fatalf("truncated-only call: %s, want %s", got, tt.want)
			}
			packTier := bounded.TierOf(tt.posture)
			if tier := cascadeBoundedTier(cfg, "claudecode", packTier); tier != tt.tier {
				t.Fatalf("bound tier %d, want %d", tier, tt.tier)
			}
			v := &ToolInspectVerdict{Action: "allow", Severity: "NONE"}
			v.floorBoundedTruncated(bounded.Of(bounded.Items), cascadeBoundedTier(cfg, "claudecode", packTier))
			if v.Action != tt.want {
				t.Fatalf("floored verdict: %s, want %s", v.Action, tt.want)
			}
		})
	}
	// A proven block beside the cap still decides.
	if got := guardrailActionForProfileUnknown(append(truncatedOnly, RuleFinding{RuleID: "X", Severity: "CRITICAL"}), false,
		func() string { return config.CascadeAlert }, boundedTestActionFor); got != "block" {
		t.Fatalf("proven finding beside the cap: %s", got)
	}
}

func cascadeModuleConfig(t *testing.T, posture, module, extra string) *APIServer {
	t.Helper()
	api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "HIGH", posture)
	dir := t.TempDir()
	path := filepath.Join(dir, "cascade.rego")
	if err := os.WriteFile(path, []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(module))
	raw := []byte("config_version: 9\ndata_dir: " + filepath.Join(dir, "state") + "\nguardrail:\n  cascade:\n" + extra +
		"    policy:\n      module: {path: " + path + ", digest: \"sha256:" + hex.EncodeToString(sum[:]) + "\"}\n")
	loaded, err := config.LoadRuntimeV8FromBytes("config.yaml", raw)
	if err != nil {
		t.Fatal(err)
	}
	if inv := loaded.Guardrail.Cascade.Invalid(); inv != nil {
		t.Fatalf("cascade refused: %s", inv.Error)
	}
	api.scannerCfg.Guardrail.Cascade = loaded.Guardrail.Cascade
	return api
}

const cascadeTestModule = `package defenseclaw.cascade
import rego.v1

decisions contains {"action": "block", "id": "bash-blocked", "reason": "Bash is not allowed here"} if {
	input.tool == "Bash"
	input.surface == "tool_call"
	not input.flagged
}

decisions contains {"action": "allow", "id": "instruction-writes-ok", "reason": "the team edits its own instructions"} if {
	some f in input.findings
	f.rule_id == "COG-CLAUDE-MD"
}
`

// The policy on the real hook path: it raises an unflagged call, it lowers
// a flagged one only to policy.lowest, and the audit finding and reason
// name the rule that set the action.
func TestCascadeHookPathPolicy(t *testing.T) {
	root := t.TempDir()
	writeActiveAgentTestFile(t, root, "CLAUDE.md")
	write := map[string]interface{}{"command": "printf changed >> CLAUDE.md"}
	ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, root, "Bash", write), "claudecode")
	baseline := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	run := func(api *APIServer, input map[string]interface{}) claudeCodeHookResponse {
		ctx := ctx
		if input["command"] != write["command"] {
			ctx = withAuthenticatedHookConnector(t.Context(), "claudecode")
		}
		api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "InstructionsLoaded", SessionID: "s", CWD: root})
		return api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "s", CWD: root, ToolName: "Bash", ToolInput: input,
		})
	}
	if got := run(baseline, write); got.Action != "block" || !findingStringHasRuleID(got.Findings, "COG-CLAUDE-MD") {
		t.Fatalf("baseline: %+v", got)
	}
	api := cascadeModuleConfig(t, "default", cascadeTestModule, "")
	lowered := run(api, write)
	if lowered.Action != "alert" || !findingStringHasRuleID(lowered.Findings, "COG-CLAUDE-MD") ||
		!strings.Contains(strings.Join(lowered.Findings, " "), "CASCADE-POLICY:instruction-writes-ok") {
		t.Fatalf("lowered (policy.lowest alert): action=%s findings=%v reason=%q", lowered.Action, lowered.Findings, lowered.Reason)
	}
	raised := run(cascadeModuleConfig(t, "default", cascadeTestModule, ""), map[string]interface{}{"command": "ls"})
	if raised.Action != "block" || !strings.Contains(strings.Join(raised.Findings, " "), "CASCADE-POLICY:bash-blocked") {
		t.Fatalf("raised: action=%s findings=%v reason=%q", raised.Action, raised.Findings, raised.Reason)
	}
	// A lowest of allow lets the policy clear the finding's block unless the
	// finding is a proven CRITICAL (the floor keeps it an alert).
	allow := cascadeModuleConfig(t, "default", cascadeTestModule, "")
	allow.scannerCfg.Guardrail.Cascade.Policy.Lowest = "allow"
	if got := run(allow, write); got.Action != "allow" && got.Action != "alert" {
		t.Fatalf("lowest allow: %s", got.Action)
	}
}

// A policy that errors (a runtime conflict here) raises the call to the
// unknown tier and records it.
func TestCascadePolicyErrorIsUnknown(t *testing.T) {
	module := "package defenseclaw.cascade\nimport rego.v1\n\ndecisions contains {\"action\": x} if { x := input.tool }\n"
	api := cascadeModuleConfig(t, "default", module, "")
	v := api.applyCascadeFinal(t.Context(), "claudecode", "tool_call", "PreToolUse", "Bash",
		&ToolInspectVerdict{Action: "allow", Severity: "NONE"})
	if v.Action != "alert" || !strings.Contains(strings.Join(v.Findings, " "), cascadePolicyErrorID) {
		t.Fatalf("error verdict: %+v", v)
	}
	strict := cascadeModuleConfig(t, "strict", module, "")
	if v := strict.applyCascadeFinal(t.Context(), "claudecode", "tool_call", "PreToolUse", "Bash",
		&ToolInspectVerdict{Action: "allow", Severity: "NONE"}); v.Action != "block" {
		t.Fatalf("strict error verdict: %s", v.Action)
	}
}

// I8: without a policy module no input is built, no evaluation runs and the
// final step allocates nothing on a clean call.
func TestCascadeOffCostsNothing(t *testing.T) {
	api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", "default")
	ctx := t.Context()
	if got := withCascadeTrace(ctx, api.scannerCfg, "claudecode"); got != ctx {
		t.Fatal("a trace was started without a policy")
	}
	v := &ToolInspectVerdict{Action: "alert", Severity: "HIGH", Findings: []string{"X"}}
	allocs := testing.AllocsPerRun(200, func() {
		api.applyCascadeFinal(ctx, "claudecode", "tool_call", "PreToolUse", "Bash", v)
	})
	if allocs > 0 {
		t.Fatalf("applyCascadeFinal allocates %.0f times per call without a policy", allocs)
	}
	if v.Action != "alert" || v.cascadeOutcome != nil {
		t.Fatalf("verdict changed: %+v", v)
	}
}

// I10: the policy input carries no evidence, argument or content.
func TestCascadePolicyInputHasNoContent(t *testing.T) {
	api := cascadeModuleConfig(t, "default", "package defenseclaw.cascade\n", "")
	const marker = "MARKER-VALUE-0123456789"
	v := &ToolInspectVerdict{Action: "alert", Severity: "HIGH", Reason: marker,
		Findings:         []string{"R1"},
		DetailedFindings: []RuleFinding{{RuleID: "R1", Title: marker, Severity: "HIGH", Evidence: marker}},
	}
	input := api.cascadePolicyInput(t.Context(), api.scannerCfg, api.scannerCfg.ResolveCascade("claudecode"),
		"claudecode", "tool_call", "PreToolUse", "Bash", v, true, "alert")
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), marker) {
		t.Fatalf("policy input carries content: %s", raw)
	}
	if !strings.Contains(string(raw), `"rule_id":"R1"`) {
		t.Fatalf("policy input lacks the finding: %s", raw)
	}
}

// I11: a 1.0.9 config with every released cascade knob loads unchanged, its
// cascade is the defaults, and explain names what runs where.
func TestCascadeUpgradeFrom109Unchanged(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "cascade", "oss-1.0.9-guardrail.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(dir, ".defenseclaw"))
	doc := strings.ReplaceAll(string(raw), "DATA_DIR", filepath.Join(dir, "state"))
	cfg, err := config.LoadRuntimeV8FromBytes("config.yaml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if inv := cfg.Guardrail.Cascade.Invalid(); inv != nil {
		t.Fatalf("1.0.9 config made the cascade invalid: %s", inv.Error)
	}
	for _, connector := range []string{"", "claudecode", "codex"} {
		if e := cfg.ResolveCascade(connector); !e.IsDefault() {
			t.Fatalf("%s: a 1.0.9 config resolves a non-default cascade: %+v", connector, e)
		}
	}
	claude, err := ExplainCascade(cfg, "claudecode", "")
	if err != nil {
		t.Fatal(err)
	}
	if claude.Judge.Runs != "escalation" || claude.SystemOne.Runs != "with_judge" || claude.Unknown.Action != "alert" ||
		!claude.Rules.HILT || claude.CriticalFloor != "alert" || claude.Policy.Active || len(claude.Sources) != 2 {
		t.Fatalf("claudecode = %+v", claude)
	}
	codex, err := ExplainCascade(cfg, "codex", "")
	if err != nil {
		t.Fatal(err)
	}
	if codex.Judge.Runs != "off" || codex.SystemOne.Runs != "alone" || codex.Rules.BlockAt != "HIGH" || codex.SystemOne.OnUnsure != "confirm" {
		t.Fatalf("codex = %+v", codex)
	}
}
