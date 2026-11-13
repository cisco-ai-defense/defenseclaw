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
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// CascadeExplanation is the effective cascade of one connector and profile
// (`defenseclaw guardrail cascade explain`): what runs, what each outcome
// does, and the key that set each value.
type CascadeExplanation struct {
	Connector string                 `json:"connector"`
	Profile   string                 `json:"profile,omitempty"`
	Valid     bool                   `json:"valid"`
	Invalid   *config.CascadeInvalid `json:"invalid,omitempty"`
	Rules     CascadeRulesLayer      `json:"rules"`
	SystemOne CascadeSystemOneLayer  `json:"system_one"`
	Judge     CascadeJudgeLayer      `json:"judge"`
	Unknown   CascadeUnknownView     `json:"unknown"`
	Lanes     []CascadeLaneView      `json:"lanes"`
	Policy    CascadePolicyView      `json:"policy"`
	// CriticalFloor is the lowest action a proven CRITICAL ends at.
	CriticalFloor string   `json:"critical_floor"`
	Locked        []string `json:"locked,omitempty"`
	// HookFailMode is what a hook does while the gateway is down.
	HookFailMode string `json:"hook_fail_mode"`
	// Sources maps each cascade value to the key that set it; a value not
	// listed is the default.
	Sources map[string]string `json:"sources"`
}

// CascadeRulesLayer is the rules layer (always on).
type CascadeRulesLayer struct {
	Mode        string `json:"mode"`
	Pack        string `json:"pack"`
	Tier        string `json:"tier"`
	BlockAt     string `json:"block_at"`
	AlertAt     string `json:"alert_at"`
	Source      string `json:"source"`
	HILT        bool   `json:"hilt"`
	HILTMinimum string `json:"hilt_min_severity,omitempty"`
}

// CascadeSystemOneLayer is System One: off, with_judge (cascade 3) or alone
// (cascade 2).
type CascadeSystemOneLayer struct {
	Runs                string  `json:"runs"`
	Protocol            string  `json:"protocol,omitempty"`
	AllowThreshold      float64 `json:"allow_threshold"`
	BlockThreshold      float64 `json:"block_threshold"`
	BlockRiskScore      float64 `json:"block_risk_score"`
	EscalateRuleFlagged bool    `json:"escalate_rule_flagged"`
	OnConfidentBlock    string  `json:"on_confident_block"`
	OnUnsure            string  `json:"on_unsure"`
}

// CascadeJudgeLayer is the LLM judge: off, escalation (regex_judge) or always
// (judge_first) on tool calls.
type CascadeJudgeLayer struct {
	Runs                string `json:"runs"`
	MaxAction           string `json:"max_action"`
	BlockNeedsSystemOne bool   `json:"block_needs_system_one"`
	NoVerdict           string `json:"no_verdict"`
}

// CascadeUnknownView is the unknown and TRUNCATED tier.
type CascadeUnknownView struct {
	Setting string `json:"setting"`
	Action  string `json:"action"`
}

// CascadeLaneView is one lane switch.
type CascadeLaneView struct {
	Name       string `json:"name"`
	Mode       string `json:"mode"`
	Default    string `json:"default"`
	ShadowOnly string `json:"shadow_only,omitempty"`
}

// CascadePolicyView is the Rego policy.
type CascadePolicyView struct {
	Active    bool   `json:"active"`
	Module    string `json:"module,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Lowest    string `json:"lowest"`
	Highest   string `json:"highest"`
	TimeoutMs int64  `json:"timeout_ms"`
}

// ExplainCascade resolves the cascade of connector ("" for the global
// scope) for profile ("" for none) from cfg as the gateway would. It reads
// the pack manifest posture itself, like ConfigThresholds.
func ExplainCascade(cfg *config.Config, connector, profile string) (CascadeExplanation, error) {
	if cfg == nil {
		return CascadeExplanation{}, errors.New("configuration is unavailable")
	}
	if cfg.SecureClientIntegration() {
		return CascadeExplanation{}, errors.New("guardrail.cascade is not available under the Secure Client integration")
	}
	connector = config.NormalizeConnectorName(connector)
	scoped := cfg
	if profile = strings.TrimSpace(profile); profile != "" {
		derived, err := cfg.DerivedForProfile(profile)
		if err != nil {
			return CascadeExplanation{}, err
		}
		scoped = derived
	}
	e := scoped.ResolveCascadeExplained(connector)
	levels := ConfigThresholds(scoped, connector)
	ref := scoped.EffectiveRulePackRefForConnector(connector)
	dir := scoped.ResolveRulePackDir(ref)
	tier := postureFromManifest(dir, guardrail.ReadPackPosture(dir))
	hilt := scoped.EffectiveHILTForConnector(connector)
	out := CascadeExplanation{
		Connector: connector, Profile: profile, Valid: e.Invalid == nil, Invalid: e.Invalid,
		Rules: CascadeRulesLayer{
			Mode: scoped.HookModeForConnector(connector), Pack: packLabel(ref, tier), Tier: tier,
			BlockAt: levels.Block, AlertAt: levels.Alert, Source: levels.Source, HILT: hilt.Enabled,
		},
		Unknown:       CascadeUnknownView{Setting: e.Unknown, Action: e.UnknownAction(tier)},
		CriticalFloor: e.CriticalFloor,
		Locked:        e.Locked,
		HookFailMode:  scoped.EffectiveHookOutageFailModeForConnector(connector),
		Sources:       e.Sources,
	}
	if hilt.Enabled {
		out.Rules.HILTMinimum = strings.ToUpper(cascadeOrDefault(hilt.MinSeverity, "HIGH"))
	}
	judgeRuns := "off"
	strategy := scoped.Guardrail.EffectiveStrategy("tool_call")
	if scoped.Guardrail.Judge.Enabled && scoped.Guardrail.Judge.HookConnectorEnabled(connector) {
		switch strategy {
		case "regex_judge":
			judgeRuns = "escalation"
		case "judge_first":
			judgeRuns = "always"
		}
	}
	out.Judge = CascadeJudgeLayer{Runs: judgeRuns, MaxAction: e.JudgeMaxAction, BlockNeedsSystemOne: e.JudgeBlockNeedsSystemOne, NoVerdict: e.JudgeNoVerdict}
	dm := scoped.DecisionModel
	s1 := "off"
	switch {
	case dm.Active() && judgeRuns != "off":
		s1 = "with_judge"
	case dm.AnswersAlone(connector):
		s1 = "alone"
	}
	out.SystemOne = CascadeSystemOneLayer{
		Runs: s1, AllowThreshold: e.SystemOneAllowThreshold, BlockThreshold: e.SystemOneBlockThreshold,
		BlockRiskScore: e.SystemOneBlockRiskScore, EscalateRuleFlagged: e.SystemOneEscalateFlagged,
		OnConfidentBlock: config.DecisionModelEscalate, OnUnsure: e.SystemOneOnUnsure,
	}
	if dm.Active() {
		out.SystemOne.Protocol = dm.EffectiveProtocol()
	}
	for _, lane := range config.CascadeLanes() {
		out.Lanes = append(out.Lanes, CascadeLaneView{Name: lane.Name, Mode: e.LaneMode(lane.Name), Default: lane.Default, ShadowOnly: lane.ShadowOnly})
	}
	out.Policy = CascadePolicyView{Active: e.PolicyActive, Lowest: e.PolicyLowest, Highest: e.PolicyHighest, TimeoutMs: e.PolicyTimeout.Milliseconds()}
	if e.PolicyActive {
		out.Policy.Module, out.Policy.Digest = e.PolicyModule.Path, e.PolicyModule.Digest
	}
	return out, nil
}

func cascadeOrDefault(v, def string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return def
}

// CascadeSimulation is one decision replayed through the final step: the
// layers' verdicts from a policy input (the JSON explain --input reads), the
// policy's decisions on it, and which layer or policy rule set the final
// action.
type CascadeSimulation struct {
	Layers  map[string]string `json:"layers"`
	Outcome CascadeOutcome    `json:"outcome"`
}

// SimulateCascade runs cfg's policy module (if any) on input, a policy input
// v1 (see docs: guardrail/configure-cascade), and applies the limits and the
// CRITICAL floor of connector's cascade. It names the layer that set the
// action before the policy (rules, system_one, judge) and the final one.
func SimulateCascade(ctx context.Context, cfg *config.Config, connector string, input map[string]any) (CascadeSimulation, error) {
	if cfg == nil || cfg.SecureClientIntegration() {
		return CascadeSimulation{}, errors.New("guardrail.cascade is not available")
	}
	e := cfg.ResolveCascade(config.NormalizeConnectorName(connector))
	before, _ := input["cascade_action"].(string)
	unknown, _ := input["unknown_action"].(string)
	if unknown == "" {
		unknown = config.CascadeAlert
	}
	flagged, _ := input["flagged"].(bool)
	critical := false
	if findings, ok := input["findings"].([]any); ok {
		for _, f := range findings {
			if m, ok := f.(map[string]any); ok {
				enforceable, _ := m["enforceable"].(bool)
				severity, _ := m["severity"].(string)
				if enforceable && strings.EqualFold(severity, "CRITICAL") {
					critical = true
				}
			}
		}
	}
	sim := CascadeSimulation{Layers: map[string]string{}}
	decidedBefore := "rules"
	bestRank := -1
	if layers, ok := input["layers"].(map[string]any); ok {
		for _, name := range []string{"rules", "system_one", "judge"} {
			layer, _ := layers[name].(map[string]any)
			action, _ := layer["action"].(string)
			if action == "" {
				continue
			}
			sim.Layers[name] = action
			if r := cascadeRank(action); r > bestRank {
				bestRank, decidedBefore = r, name
			}
		}
	}
	if before == "" {
		before = config.CascadeActionName(max(bestRank, 0))
	}
	var decisions []policy.CascadeDecision
	var evalErr error
	if src := cfg.Guardrail.Cascade.PolicySource(); len(src) > 0 {
		p, err := policy.PrepareCascade(ctx, src)
		if err != nil {
			return CascadeSimulation{}, fmt.Errorf("guardrail.cascade.policy.module: %w", err)
		}
		evalCtx, cancel := context.WithTimeout(ctx, e.PolicyTimeout)
		decisions, evalErr = p.Evaluate(evalCtx, input)
		cancel()
	}
	sim.Outcome = cascadeFinalAction(before, flagged, critical, decisions, evalErr, unknown, e)
	if sim.Outcome.DecidedBy == "" {
		sim.Outcome.DecidedBy = decidedBefore
	}
	return sim, nil
}
