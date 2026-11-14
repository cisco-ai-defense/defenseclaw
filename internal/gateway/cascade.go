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
	"os"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// The guardrail cascade's runtime (guardrail.cascade, config/cascade.go):
//
//  1. Rules decide with block_at / alert_at / hilt as before; the unknown
//     tier of a truncated input follows cascade.unknown (cascadeUnknown).
//  2. System One (decision_model) routes with decision_model and the scope's
//     cascade.system_one overrides; cascade 2's unsure answer follows
//     cascade.system_one.on_unsure.
//  3. The judge lane's verdict is capped by cascade.judge (max_action,
//     block_needs_system_one); no verdict follows cascade.judge.no_verdict.
//  4. The Rego policy (cascade.policy) may raise or lower the merged action
//     within policy.lowest / policy.highest, and a proven CRITICAL finding
//     never ends below admin.critical_floor (applyCascadeFinal).
//
// Models only raise the rule verdict; the policy is the only point that can
// lower it. An empty cascade decides exactly as before, and without a policy
// module no input is built and no evaluation runs.

// Finding IDs the cascade adds to a verdict (audit rows and responses).
const (
	cascadePolicyFindingID   = "CASCADE-POLICY"
	cascadePolicyErrorID     = "CASCADE-POLICY-ERROR"
	cascadeCriticalFloorID   = "CASCADE-CRITICAL-FLOOR"
	cascadeNoVerdictID       = "CASCADE-NO-VERDICT"
	cascadeScanner           = "cascade"
	maxCascadeInputFindings  = 64
	maxCascadeInputFindTags  = 8
	maxCascadeInputProfiles  = 16
	cascadePolicyLatencyNote = "guardrail.cascade.policy.timeout_ms"
)

// cascadeUnknownForConfig is the unknown-tier action a truncated input of
// connector maps to under cfg: "" when the pack decides as it always did
// (a strict pack maps the limit finding by its levels), else the action.
func cascadeUnknownForConfig(cfg *config.Config, connector string) string {
	if cfg == nil || cfg.SecureClientIntegration() {
		return ""
	}
	if u := cfg.ResolveCascade(connector).Unknown; u != "" && u != config.CascadeUnknownPack {
		return u
	}
	if strictPackPosture(cfg, connector) {
		return ""
	}
	return guardrailActionAlert
}

// cascadeUnknownForGuardrail is cascadeUnknownForConfig for a caller that
// holds only the guardrail block (the proxy).
func cascadeUnknownForGuardrail(gc *config.GuardrailConfig, connector string, strict func() bool) string {
	if u := gc.CascadeUnknown(connector); u != config.CascadeUnknownPack {
		return u
	}
	if strict() {
		return ""
	}
	return guardrailActionAlert
}

// cascadeBoundedTier maps the cascade's unknown tier onto the bound rule's
// tier: pack keeps the pack's own (packTier).
func cascadeBoundedTier(cfg *config.Config, connector string, packTier bounded.Tier) bounded.Tier {
	if cfg == nil || cfg.SecureClientIntegration() {
		return packTier
	}
	switch cfg.ResolveCascade(connector).Unknown {
	case config.CascadeAlert:
		return bounded.TierDefault
	case config.CascadeConfirm:
		return bounded.TierConfirm
	case config.CascadeBlock:
		return bounded.TierStrict
	}
	return packTier
}

// cascadeSystemOneRouting is the System One routing of one call: the
// decision_model values with the call's scope overrides.
type cascadeSystemOneRouting struct {
	allowAt, blockAt, blockRiskScore float64
	escalateRuleFlagged              bool
	onUnsure                         string
}

type cascadeSystemOneKey struct{}

// withCascadeSystemOne carries the routing of cfg's scope for connector to
// the decision model.
func withCascadeSystemOne(ctx context.Context, cfg *config.Config, connector string) context.Context {
	if cfg == nil || cfg.SecureClientIntegration() || !cfg.DecisionModel.Active() {
		return ctx
	}
	e := cfg.ResolveCascade(connector)
	return context.WithValue(ctx, cascadeSystemOneKey{}, cascadeSystemOneRouting{
		allowAt: e.SystemOneAllowThreshold, blockAt: e.SystemOneBlockThreshold, blockRiskScore: e.SystemOneBlockRiskScore,
		escalateRuleFlagged: e.SystemOneEscalateFlagged, onUnsure: e.SystemOneOnUnsure,
	})
}

// routingFor is d's routing, with the call's scope overrides when the caller
// set them.
func (d *decisionModel) routingFor(ctx context.Context) cascadeSystemOneRouting {
	if r, ok := ctx.Value(cascadeSystemOneKey{}).(cascadeSystemOneRouting); ok {
		return r
	}
	return cascadeSystemOneRouting{allowAt: d.allowAt, blockAt: d.blockAt, blockRiskScore: d.blockRiskScore,
		escalateRuleFlagged: d.escalateRuleFlagged, onUnsure: config.CascadeConfirm}
}

// cascadeUnsureVerdict is cascade 2's unsure answer under on_unsure alert or
// rules (nil keeps today's confirm). Its action is final: the lane does not
// map it by severity again.
func cascadeUnsureVerdict(onUnsure, reason string, risk float64) *ScanVerdict {
	switch onUnsure {
	case config.CascadeAlert:
		return &ScanVerdict{
			Action: guardrailActionAlert, Severity: "HIGH", Reason: reason + " (guardrail.cascade.system_one.on_unsure: alert)",
			Findings: []string{decisionModelFindingID}, Scanner: decisionModelScanner, Confidence: risk, cascadeFixed: true,
		}
	case config.CascadeFromRules:
		v := allowVerdict(decisionModelScanner)
		v.Reason = reason + "; the rule verdict stands (guardrail.cascade.system_one.on_unsure: rules)"
		v.cascadeFixed = true
		return v
	}
	return nil
}

// applyCascadeJudgeRole caps the judge lane's verdict v by the scope's
// cascade.judge: block_needs_system_one turns a block System One did not
// confidently make into a confirm, and max_action caps the action (log is
// an allow that keeps the findings). The decision model alone (cascade 2)
// is not the judge and keeps its verdict.
func applyCascadeJudgeRole(cfg *config.Config, connector string, decisionOnly bool, v *ScanVerdict) *ScanVerdict {
	if v == nil || decisionOnly || cfg == nil || cfg.SecureClientIntegration() || v.JudgeFailed {
		return v
	}
	e := cfg.ResolveCascade(connector)
	action := normalizedGuardrailAction(v.Action)
	out := *v
	changed := false
	if e.JudgeBlockNeedsSystemOne && action == guardrailActionBlock && !v.systemOneBlocked {
		out.Action, action, changed = guardrailActionConfirm, guardrailActionConfirm, true
		out.Reason = strings.TrimSpace(out.Reason + " (a judge block needs System One to agree: guardrail.cascade.judge.block_needs_system_one; asked instead)")
	}
	if limit := config.CascadeActionRank(e.JudgeMaxAction); limit >= 0 && config.CascadeActionRank(action) > limit {
		capped := config.CascadeActionName(limit)
		out.Reason = strings.TrimSpace(out.Reason + " (judge capped at " + capped + " by guardrail.cascade.judge.max_action)")
		if capped == config.CascadeLog {
			capped = guardrailActionAllow
		}
		out.Action, changed = capped, true
	}
	if !changed {
		return v
	}
	out.decisionConfirm = false
	return &out
}

// cascadeNoVerdict is the verdict of a call whose judge lane gave none
// under cascade.judge.no_verdict unknown: at least the unknown tier. nil
// keeps the rule verdict (rules, the default).
func cascadeNoVerdict(cfg *config.Config, connector string, tier bounded.Tier) *ScanVerdict {
	if cfg == nil || cfg.SecureClientIntegration() || cfg.ResolveCascade(connector).JudgeNoVerdict != config.CascadeNoVerdictUnknown {
		return nil
	}
	action := bounded.Unknown(cascadeBoundedTier(cfg, connector, tier)).String()
	severity := "MEDIUM"
	if action != guardrailActionAlert {
		severity = "HIGH"
	}
	return &ScanVerdict{
		Action: action, Severity: severity, Scanner: cascadeScanner,
		Reason:   "the model layers gave no verdict; judged as unknown (guardrail.cascade.judge.no_verdict: unknown)",
		Findings: []string{cascadeNoVerdictID}, cascadeFixed: true,
	}
}

// cascadeTrace records what the model layers of one call decided, for the
// policy input. It exists only when a policy module is loaded.
type cascadeTrace struct {
	mu        sync.Mutex
	systemOne map[string]any
	judge     map[string]any
}

type cascadeTraceKey struct{}

// withCascadeTrace starts the trace of one hook call when cfg runs a
// cascade policy for connector; otherwise ctx is returned as is.
func withCascadeTrace(ctx context.Context, cfg *config.Config, connector string) context.Context {
	if cfg == nil || cfg.SecureClientIntegration() || len(cfg.Guardrail.Cascade.PolicySource()) == 0 {
		return ctx
	}
	if _, ok := ctx.Value(cascadeTraceKey{}).(*cascadeTrace); ok {
		return ctx
	}
	return context.WithValue(ctx, cascadeTraceKey{}, &cascadeTrace{})
}

func cascadeTraceFrom(ctx context.Context) *cascadeTrace {
	t, _ := ctx.Value(cascadeTraceKey{}).(*cascadeTrace)
	return t
}

func recordCascadeSystemOne(ctx context.Context, res decisionResult, v *ScanVerdict) {
	t := cascadeTraceFrom(ctx)
	if t == nil {
		return
	}
	route := "unsure"
	switch {
	case res.skipped:
		route = "skipped"
	case res.failure != "" && res.refusal == "":
		route = "failed"
	case res.route == decisionAllow:
		route = "allow"
	case res.route == decisionBlock:
		route = "block"
	}
	entry := map[string]any{"ran": !res.skipped, "route": route, "risk": res.risk, "risk_score": res.riskScore}
	if v != nil {
		entry["action"] = normalizedGuardrailAction(v.Action)
	}
	t.mu.Lock()
	t.systemOne = entry
	t.mu.Unlock()
}

func recordCascadeJudge(ctx context.Context, v *ScanVerdict) {
	t := cascadeTraceFrom(ctx)
	if t == nil {
		return
	}
	entry := map[string]any{"ran": true, "failed": v == nil || v.JudgeFailed}
	if v != nil && !v.JudgeFailed {
		entry["action"] = normalizedGuardrailAction(v.Action)
		entry["severity"] = strings.ToUpper(strings.TrimSpace(v.Severity))
		entry["confidence"] = v.Confidence
	}
	t.mu.Lock()
	t.judge = entry
	t.mu.Unlock()
}

// cascadeProvenCritical reports an enforceable CRITICAL rule finding.
func cascadeProvenCritical(v *ToolInspectVerdict) bool {
	for _, finding := range enforceableRuleFindings(v.DetailedFindings) {
		if strings.EqualFold(strings.TrimSpace(finding.Severity), "CRITICAL") {
			return true
		}
	}
	return false
}

// cascadeRank is the cascade rank of a gateway action ("" and unknown
// spellings rank as allow and block).
func cascadeRank(action string) int {
	if strings.TrimSpace(action) == "" {
		return 0
	}
	if r := config.CascadeActionRank(action); r >= 0 {
		return r
	}
	return config.CascadeActionRank(config.CascadeBlock)
}

// CascadeOutcome is what the final step of the cascade did with one call.
type CascadeOutcome struct {
	// Before and Final are the cascade's action before the policy and the
	// call's final action (allow, log, alert, confirm, block).
	Before string `json:"before"`
	Final  string `json:"final"`
	// DecidedBy is the layer that set Final: rules, system_one, judge,
	// unknown, policy, policy_error or critical_floor.
	DecidedBy string `json:"decided_by"`
	// PolicyRule is the id of the policy decision that set Final.
	PolicyRule string `json:"policy_rule,omitempty"`
	// Decisions are the policy's decisions, Clamped says the limits moved
	// the policy's action.
	Decisions []policy.CascadeDecision `json:"decisions,omitempty"`
	Clamped   bool                     `json:"clamped,omitempty"`
	Error     string                   `json:"error,omitempty"`
}

// cascadeFinalAction is the pure final step: the policy's decisions (or
// its error) applied to before within the limits, then the CRITICAL floor.
func cascadeFinalAction(before string, flagged, provenCritical bool, decisions []policy.CascadeDecision, evalErr error,
	unknownAction string, e config.EffectiveCascade,
) CascadeOutcome {
	out := CascadeOutcome{Before: config.CascadeActionName(cascadeRank(before)), Decisions: decisions}
	cur := cascadeRank(before)
	final := cur
	out.DecidedBy = ""
	switch {
	case evalErr != nil:
		out.Error = evalErr.Error()
		if u := cascadeRank(unknownAction); u > final {
			final = u
			out.DecidedBy = "policy_error"
		}
	case len(decisions) > 0:
		best := decisions[0]
		for _, d := range decisions[1:] {
			if cascadeRank(d.Action) > cascadeRank(best.Action) {
				best = d
			}
		}
		target := cascadeRank(best.Action)
		lo, hi := cascadeRank(e.PolicyLowest), cascadeRank(e.PolicyHighest)
		if !flagged {
			lo = 0
		}
		if provenCritical {
			lo = max(lo, cascadeRank(e.CriticalFloor))
		}
		if target >= cur {
			final = max(cur, min(target, hi))
		} else {
			final = max(target, min(lo, cur))
		}
		out.Clamped = final != target
		if final != cur {
			out.DecidedBy = "policy"
			out.PolicyRule = best.ID
		}
	}
	if provenCritical && final < cascadeRank(e.CriticalFloor) {
		final = cascadeRank(e.CriticalFloor)
		out.DecidedBy = "critical_floor"
	}
	out.Final = config.CascadeActionName(final)
	return out
}

// applyCascadeFinal is step 4 of the cascade for one hook call: the policy
// (when loaded) and the CRITICAL floor on v, the verdict the call's layers
// merged, before the hook mode and the connector's mapping. surface is the
// call's surface (tool_call, prompt, tool_result, response, message).
func (a *APIServer) applyCascadeFinal(ctx context.Context, connector, surface, event, tool string, v *ToolInspectVerdict) *ToolInspectVerdict {
	cfg := a.decisionConfig(ctx)
	if v == nil || cfg == nil || cfg.SecureClientIntegration() {
		return v
	}
	e := cfg.ResolveCascade(connector)
	critical := cascadeProvenCritical(v)
	var prepared *policy.CascadePolicy
	if e.PolicyActive {
		prepared = a.cascadePolicyFor(ctx, cfg)
	}
	if prepared == nil {
		if critical && cascadeRank(v.Action) < cascadeRank(e.CriticalFloor) {
			out := cascadeFinalAction(v.Action, true, true, nil, nil, "", e)
			v.applyCascadeOutcome(out, nil)
		}
		return v
	}
	flagged := rulesFlagged(v)
	unknownAction := bounded.Unknown(a.boundedTier(ctx, connector)).String()
	input := a.cascadePolicyInput(ctx, cfg, e, connector, surface, event, tool, v, flagged, unknownAction)
	evalCtx, cancel := context.WithTimeout(ctx, e.PolicyTimeout)
	decisions, err := prepared.Evaluate(evalCtx, input)
	cancel()
	if err != nil {
		if errors.Is(evalCtx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("evaluation exceeded %s (%s)", e.PolicyTimeout, cascadePolicyLatencyNote)
		}
		fmt.Fprintf(os.Stderr, "[guardrail] cascade policy error connector=%s surface=%s: %v; judged as unknown\n", connector, surface, err)
	}
	out := cascadeFinalAction(v.Action, flagged, critical, decisions, err, unknownAction, e)
	v.applyCascadeOutcome(out, err)
	return v
}

// applyCascadeOutcome writes the final step's outcome onto v.
func (v *ToolInspectVerdict) applyCascadeOutcome(out CascadeOutcome, err error) {
	if out.DecidedBy == "" && err == nil {
		return
	}
	finalAction := out.Final
	if finalAction == config.CascadeLog {
		finalAction = guardrailActionAllow
	}
	note := ""
	finding := ""
	switch out.DecidedBy {
	case "policy":
		note = fmt.Sprintf("cascade policy %s set %s (was %s)", out.PolicyRule, out.Final, out.Before)
		finding = cascadePolicyFindingID + ":" + out.PolicyRule
		for _, d := range out.Decisions {
			if d.ID == out.PolicyRule && d.Reason != "" {
				note += ": " + d.Reason
				break
			}
		}
	case "policy_error":
		note = "cascade policy failed (" + out.Error + "); judged as unknown"
		finding = cascadePolicyErrorID
	case "critical_floor":
		note = "a proven CRITICAL finding is at least " + out.Final + " (guardrail.cascade.admin.critical_floor)"
		finding = cascadeCriticalFloorID
	default:
		if err != nil {
			finding = cascadePolicyErrorID
			note = "cascade policy failed (" + out.Error + "); the cascade's action stands"
		}
	}
	if cascadeRank(finalAction) != cascadeRank(v.Action) {
		v.Action = finalAction
		v.decisionConfirm = false
	}
	switch v.Action {
	case guardrailActionBlock, guardrailActionConfirm:
		if guardrailSeverityRank(v.Severity) < severityHigh {
			v.Severity = "HIGH"
		}
	case guardrailActionAlert:
		if guardrailSeverityRank(v.Severity) < severityMedium {
			v.Severity = "MEDIUM"
		}
	}
	if finding != "" {
		v.Findings = append(v.Findings, finding)
	}
	if note != "" {
		if v.Reason == "" {
			v.Reason = note
		} else {
			v.Reason = note + "; " + v.Reason
		}
	}
	v.cascadeOutcome = &out
}

// cascadePolicyInput is input v1 of the cascade policy: no prompt, argument,
// evidence or file content, bounded lists.
func (a *APIServer) cascadePolicyInput(ctx context.Context, cfg *config.Config, e config.EffectiveCascade, connector, surface, event, tool string,
	v *ToolInspectVerdict, flagged bool, unknownAction string,
) map[string]any {
	ref := cfg.EffectiveRulePackRefForConnector(connector)
	tier := packPostureFor(cfg, ref, cfg.ResolveRulePackDir(ref))
	findings := make([]any, 0, min(len(v.DetailedFindings), maxCascadeInputFindings))
	truncated := false
	for i, f := range v.DetailedFindings {
		if i >= maxCascadeInputFindings {
			truncated = true
			break
		}
		tags := f.Tags
		if len(tags) > maxCascadeInputFindTags {
			tags = tags[:maxCascadeInputFindTags]
		}
		findings = append(findings, map[string]any{
			"rule_id": f.RuleID, "severity": strings.ToUpper(strings.TrimSpace(f.Severity)), "layer": "rules",
			"enforceable": f.contributesToEnforcement(), "alert_only": f.contributesToAlertOnly(),
			"confidence": f.Confidence, "tags": stringsAny(tags),
		})
	}
	layerFindings := []any{}
	for _, f := range v.Findings {
		if strings.HasPrefix(f, "llm-judge:") || strings.HasPrefix(f, decisionModelFindingID) || strings.HasPrefix(f, "ai-defense:") {
			layerFindings = append(layerFindings, f)
		}
		if len(layerFindings) >= maxCascadeInputFindings {
			break
		}
	}
	subject := map[string]any{"profile": "", "profiles": []any{}, "matched_group": "", "source": ""}
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil {
		d := resolved.decision
		profiles := d.provenMembers
		if len(profiles) == 0 && d.Name != "" {
			profiles = []string{d.Name}
		}
		if len(profiles) > maxCascadeInputProfiles {
			profiles = profiles[:maxCascadeInputProfiles]
		}
		subject = map[string]any{"profile": d.Name, "profiles": stringsAny(profiles), "matched_group": d.MatchedGroup, "source": d.SubjectSource}
	}
	layers := map[string]any{
		"rules":      map[string]any{"action": normalizedGuardrailAction(v.Action), "severity": strings.ToUpper(strings.TrimSpace(v.Severity))},
		"system_one": map[string]any{"ran": false},
		"judge":      map[string]any{"ran": false},
		"findings":   layerFindings,
	}
	if t := cascadeTraceFrom(ctx); t != nil {
		t.mu.Lock()
		if t.systemOne != nil {
			layers["system_one"] = t.systemOne
		}
		if t.judge != nil {
			layers["judge"] = t.judge
		}
		t.mu.Unlock()
	}
	limitHit := boundedLimitIndex(v.DetailedFindings) >= 0
	return map[string]any{
		"version":        1,
		"surface":        surface,
		"connector":      config.NormalizeConnectorName(connector),
		"event":          event,
		"tool":           tool,
		"mode":           cfg.HookModeForConnector(connector),
		"pack":           map[string]any{"name": packLabel(ref, tier), "tier": tier},
		"subject":        subject,
		"findings":       findings,
		"flagged":        flagged,
		"truncated":      map[string]any{"any": limitHit || truncated, "input_findings_capped": truncated},
		"layers":         layers,
		"cascade_action": normalizedGuardrailAction(v.Action),
		"unknown_action": unknownAction,
		"limits":         map[string]any{"lowest": e.PolicyLowest, "highest": e.PolicyHighest, "critical_floor": e.CriticalFloor},
	}
}

func stringsAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// buildCascadePolicy prepares the verified policy module cfg carries.
func buildCascadePolicy(ctx context.Context, cfg *config.Config) (*policy.CascadePolicy, error) {
	if cfg == nil || cfg.SecureClientIntegration() {
		return nil, nil
	}
	src := cfg.Guardrail.Cascade.PolicySource()
	if len(src) == 0 {
		return nil, nil
	}
	return policy.PrepareCascade(ctx, src)
}

// cascadeInvalidReported keeps the last invalid-cascade message the sidecar
// recorded, so a reload that keeps it does not add another audit row.
var cascadeInvalidReported sync.Map // config path -> message

// noteCascade runs after a generation is published: an invalid cascade is
// reported (stderr, an audit row, status), a valid one becomes the
// last-known-good fallback.
func noteCascade(logger *audit.Logger, g *Generation) {
	if g == nil || g.Config == nil || g.Config.SecureClientIntegration() {
		return
	}
	cfg := g.Config
	key := cfg.ConfigFilePath
	if inv := cfg.Guardrail.Cascade.Invalid(); inv != nil {
		msg := inv.Message()
		if prev, ok := cascadeInvalidReported.Load(key); ok && prev == msg {
			return
		}
		cascadeInvalidReported.Store(key, msg)
		fmt.Fprintf(os.Stderr, "[sidecar] %s\n", msg)
		if logger != nil {
			_ = logger.LogActionSeverityConnector(string(audit.ActionGuardrailDegraded), "guardrail.cascade", msg, "HIGH", "")
		}
		return
	}
	cascadeInvalidReported.Delete(key)
	if err := config.WriteCascadeLastGood(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] could not save the last-known-good guardrail.cascade: %v\n", err)
	}
}

// finishHookJudge is the hook-lane verdict of one judge-lane answer v: the
// severity mapping, the default pack's audit-only review finding, then the
// judge's role (guardrail.cascade.judge), recorded for the cascade policy.
func (a *APIServer) finishHookJudge(ctx context.Context, cfg *config.Config, connector, strategyDirection string,
	judge *LLMJudge, ruleFloor bool, v *ScanVerdict,
) *ScanVerdict {
	decisionOnly := judge != nil && judge.decisionOnly
	out := judgeReviewOnlyAudit(cfg, connector, ruleFloor, hookJudgeLaneVerdict(cfg, connector, strategyDirection, v))
	out = applyCascadeJudgeRole(cfg, connector, decisionOnly, out)
	if !decisionOnly {
		recordCascadeJudge(ctx, out)
	}
	return out
}

// hookCascadeSurface names the surface of a hook event for the cascade
// policy input.
func hookCascadeSurface(event string) string {
	switch {
	case isPromptLikeEvent(event):
		return "prompt"
	case isResultLikeEvent(event):
		return "tool_result"
	}
	switch canonicalEvent(event) {
	case "pretooluse", "permissionrequest", "beforeshellexecution", "beforemcpexecution", "beforereadfile",
		"pretoolcall", "beforetool", "preinvocation":
		return "tool_call"
	case "stop", "subagentstop", "afteragentresponse":
		return "response"
	}
	return "event"
}

// startCascadePolicies holds the policy compiled for a start-time
// configuration that no generation carries (an API server before its first
// generation, tests).
var startCascadePolicies sync.Map // *config.Config -> *policy.CascadePolicy

// cascadePolicyFor is the prepared policy a request decides with: its
// generation's, else the one compiled once for the start-time configuration.
func (a *APIServer) cascadePolicyFor(ctx context.Context, cfg *config.Config) *policy.CascadePolicy {
	if g := a.decisionGeneration(ctx); g != nil {
		return g.CascadePolicy
	}
	if p, ok := startCascadePolicies.Load(cfg); ok {
		return p.(*policy.CascadePolicy)
	}
	p, err := buildCascadePolicy(ctx, cfg)
	if err != nil || p == nil {
		return nil
	}
	startCascadePolicies.Store(cfg, p)
	return p
}
