// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func meetVerdictFixture(t *testing.T, a, b config.GuardrailProfile, aRule, bRule *PatternRule) (*APIServer, context.Context) {
	t.Helper()
	stubProfileSources(t)
	root := t.TempDir()
	a.RulePackDir = meetRulePackDir(t, root, "VERDICT-A")
	b.RulePackDir = meetRulePackDir(t, root, "VERDICT-B")
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"a": a, "b": b}
	p := identityTestPlatforms[0]
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "b", Match: config.ProfileMatch{Users: []string{p.id}}},
		{Profile: "a", Match: config.ProfileMatch{Groups: []string{p.group}}},
	}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	for name, rule := range map[string]*PatternRule{"a": aRule, "b": bRule} {
		if rule == nil {
			continue
		}
		generation, err := compileRulePackGeneration([]ruleCategory{{Name: "secret", Rules: []PatternRule{*rule}}})
		if err != nil {
			t.Fatal(err)
		}
		set.rules[effectiveRulePackKey(set.profiles[name].Config, "codex")] = generation
	}
	set.missing = nil
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	api.guardrailProfiles.set.Store(set)
	subject := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
	ctx := api.withGuardrailProfileDecision(withProfilePath(subject, profilePathHook), "codex")
	if got := resolvedGuardrailProfileFrom(ctx).decision; got.Name != config.ProfileMeetName([]string{"a", "b"}) || got.Refused != "" {
		t.Fatalf("meet fixture: %+v", got)
	}
	return api, ctx
}

func meetVerdictRule(id, marker, severity string) *PatternRule {
	return &PatternRule{ID: id, Title: id, Pattern: regexp.MustCompile(regexp.QuoteMeta(marker)), Severity: severity, Confidence: 0.99}
}

func strongestMeetFinding(findings []RuleFinding, id string) *RuleFinding {
	var strongest *RuleFinding
	for i := range findings {
		finding := &findings[i]
		if finding.RuleID == id && (strongest == nil || strongerRuleFinding(*finding, *strongest)) {
			strongest = finding
		}
	}
	return strongest
}

func TestProfileMeetDecidesEachMembersOwnThresholdAndHILT(t *testing.T) {
	for _, tc := range []struct {
		name, severity, blockA, blockB, want string
		hiltA, hiltB                         bool
	}{
		{name: "other member has low block threshold", severity: "MEDIUM", blockA: "LOW", blockB: "CRITICAL", want: "alert"},
		{name: "other member has high block threshold", severity: "HIGH", blockA: "CRITICAL", blockB: "HIGH", hiltA: true, want: "confirm"},
		{name: "matching member really blocks", severity: "CRITICAL", blockA: "LOW", blockB: "CRITICAL", want: "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := config.GuardrailProfile{Mode: "action", BlockAt: tc.blockA, AlertAt: "LOW"}
			b := config.GuardrailProfile{Mode: "action", BlockAt: tc.blockB, AlertAt: "LOW"}
			if tc.hiltA {
				a.HILT = &config.HILTConfig{Enabled: true, MinSeverity: "HIGH"}
				b, a = a, b // the matching first assignment is b
			}
			api, ctx := meetVerdictFixture(t, a, b, meetVerdictRule("A-UNMATCHED", "absent-marker", "HIGH"),
				meetVerdictRule("B-MATCH", "sample-marker", tc.severity))
			verdict := api.inspectMessageContent(ctx, &ToolInspectRequest{Connector: "codex", Content: "sample-marker", Direction: "outbound"})
			if verdict.Action != tc.want {
				t.Fatalf("action=%s, want %s; verdict=%+v", verdict.Action, tc.want, verdict)
			}
			if !tc.hiltA {
				set := resolvedGuardrailProfileFrom(ctx).set
				proxyCtx := withPinnedGeneration(withProfilePath(ctx, profilePathInspect),
					&Generation{N: 1, Config: set.base, Profiles: set})
				proxyCtx = withThresholdConnector(withGuardrailProfile(proxyCtx, set, "codex"), "codex")
				proxyVerdict := NewGuardrailInspector("local", nil, nil).Inspect(proxyCtx, "completion", "sample-marker", nil, "", "action")
				if proxyVerdict == nil || proxyVerdict.Action != tc.want {
					t.Fatalf("proxy verdict=%+v, want %s from b's own pack and threshold", proxyVerdict, tc.want)
				}
			}
		})
	}
}

func TestProfileMeetAuditsObserveAndSameIDFindingsFromEveryMember(t *testing.T) {
	for _, tc := range []struct {
		name               string
		observeA, observeB bool
		sameID             bool
	}{
		{name: "observe member", observeB: true},
		{name: "both observe", observeA: true, observeB: true},
		{name: "same rule ID", sameID: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := config.GuardrailProfile{Mode: "action", BlockAt: "CRITICAL", AlertAt: "LOW"}
			b := config.GuardrailProfile{Mode: "action", BlockAt: "CRITICAL", AlertAt: "LOW"}
			idA, idB := "A-FINDING", "B-FINDING"
			if tc.observeA {
				a.Mode = "observe"
				a.Sandbox = &config.OpenShellAdminConfig{EgressBlock: []string{"a.example"}}
			}
			if tc.observeB {
				b.Mode = "observe"
				b.Sandbox = &config.OpenShellAdminConfig{EgressBlock: []string{"observe.example"}}
			}
			if tc.sameID {
				idA, idB = "SHARED-ID", "SHARED-ID"
			}
			api, ctx := meetVerdictFixture(t, a, b, meetVerdictRule(idA, "sample-marker", "LOW"),
				meetVerdictRule(idB, "sample-marker", "HIGH"))
			verdict := api.inspectMessageContent(ctx, &ToolInspectRequest{Connector: "codex", Content: "sample-marker", Direction: "outbound"})
			if len(verdict.DetailedFindings) != 2 {
				t.Fatalf("findings=%+v; want both member findings", verdict.DetailedFindings)
			}
			seen := map[string]bool{}
			for _, finding := range ruleFindingsToInspect(verdict.DetailedFindings, "message") {
				for _, member := range []string{"a", "b"} {
					if slices.Contains(finding.Tags, "profile:"+member) {
						seen[member] = true
					}
				}
			}
			if !seen["a"] || !seen["b"] {
				t.Fatalf("audit findings lack member provenance: %+v", ruleFindingsToInspect(verdict.DetailedFindings, "message"))
			}
			if (tc.observeA || tc.observeB) && verdict.Action == "block" {
				t.Fatalf("observe finding blocked: %+v", verdict)
			}
		})
	}
}

func TestProfileMeetHookJudgeKeepsEachMembersFinding(t *testing.T) {
	a := config.GuardrailProfile{Mode: "action", BlockAt: "CRITICAL", AlertAt: "LOW"}
	b := config.GuardrailProfile{Mode: "observe", BlockAt: "HIGH", AlertAt: "LOW",
		Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"observe.example"}}}
	api, ctx := meetVerdictFixture(t, a, b, nil, nil)
	judgeConfig := config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"codex"}}
	api.scannerCfg.Guardrail.Judge = judgeConfig
	api.scannerCfg.Guardrail.DetectionStrategy = "judge_first"
	resolved := resolvedGuardrailProfileFrom(ctx)
	resolved.derived.Guardrail.Judge = judgeConfig
	resolved.derived.Guardrail.DetectionStrategy = "judge_first"
	for _, member := range []string{"a", "b"} {
		cfg := resolved.set.profileConfig(member)
		cfg.Guardrail.Judge = judgeConfig
		cfg.Guardrail.DetectionStrategy = "judge_first"
	}
	mock := injectionHitProvider()
	api.SetHookJudge(&LLMJudge{cfg: &api.scannerCfg.Guardrail.Judge, model: "test-model", provider: mock, rp: &guardrail.RulePack{}})
	verdict := api.runHookJudge(ctx, "prompt", "prompt", "codex", "hello there, lovely weather today", "", nil)
	if verdict == nil || len(mock.captured) != 2 || len(verdict.Findings) != 2 {
		t.Fatalf("judge calls=%d, verdict=%+v; want a finding from each member", len(mock.captured), verdict)
	}
	if verdict.Action == guardrailActionBlock {
		t.Fatalf("observe member blocked a hook: %+v", verdict)
	}
	audit := ruleFindingsToInspect(mergeWithJudgeVerdict(nil, verdict).DetailedFindings, "message")
	seen := map[string]bool{}
	for _, finding := range audit {
		for _, member := range []string{"a", "b"} {
			seen[member] = seen[member] || slices.Contains(finding.Tags, "profile:"+member)
		}
	}
	if !seen["a"] || !seen["b"] {
		t.Fatalf("judge audit findings lack member provenance: %+v", audit)
	}
}

type delayedMemberJudgeProvider struct {
	mu      sync.Mutex
	members []string
}

func (p *delayedMemberJudgeProvider) ChatCompletion(ctx context.Context, _ *ChatRequest) (*ChatResponse, error) {
	member := ""
	if resolved := resolvedGuardrailProfileFrom(ctx); resolved != nil {
		member = resolved.decision.Name
	}
	p.mu.Lock()
	p.members = append(p.members, member)
	p.mu.Unlock()
	if member == "a" {
		select {
		case <-time.After(1500 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return &ChatResponse{Model: "test-model", Choices: []ChatChoice{{Message: &ChatMessage{Content: hookInjectionHitJSON}}}}, nil
}

func (*delayedMemberJudgeProvider) ChatCompletionStream(context.Context, *ChatRequest, func(StreamChunk)) (*ChatUsage, error) {
	return nil, errors.New("stream not supported")
}

func TestProfileMeetHookJudgePreservesLaterActionMemberUnderSharedDeadline(t *testing.T) {
	a := config.GuardrailProfile{Mode: "observe", Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"observer.example"}}}
	b := config.GuardrailProfile{Mode: "action", BlockAt: "HIGH", AlertAt: "LOW"}
	api, ctx := meetVerdictFixture(t, a, b, nil, nil)
	judgeConfig := config.JudgeConfig{Enabled: true, Injection: true, HookConnectors: []string{"codex"}, HookTimeout: 2}
	api.scannerCfg.Guardrail.Judge = judgeConfig
	api.scannerCfg.Guardrail.DetectionStrategy = "judge_first"
	resolved := resolvedGuardrailProfileFrom(ctx)
	resolved.derived.Guardrail.Judge = judgeConfig
	resolved.derived.Guardrail.DetectionStrategy = "judge_first"
	for _, member := range []string{"a", "b"} {
		cfg := resolved.set.profileConfig(member)
		cfg.Guardrail.Judge = judgeConfig
		cfg.Guardrail.DetectionStrategy = "judge_first"
	}
	provider := &delayedMemberJudgeProvider{}
	api.SetHookJudge(&LLMJudge{cfg: &api.scannerCfg.Guardrail.Judge, model: "test-model", provider: provider, rp: &guardrail.RulePack{}})
	verdict := api.runHookJudge(ctx, "prompt", "prompt", "codex", "hello there, lovely weather today", "", nil)
	provider.mu.Lock()
	members := slices.Clone(provider.members)
	provider.mu.Unlock()
	if !slices.Contains(members, "b") || verdict == nil || verdict.Action != guardrailActionBlock ||
		!slices.Contains(verdict.findingProfiles, "b") {
		t.Fatalf("judge calls=%v verdict=%+v; want b's blocking finding under the shared deadline", members, verdict)
	}
}

func TestProfileMeetSensitiveToolUsesOneMembersPackAtATime(t *testing.T) {
	a := config.GuardrailProfile{Mode: "action", BlockAt: "CRITICAL", AlertAt: "LOW"}
	b := config.GuardrailProfile{Mode: "action", BlockAt: "CRITICAL", AlertAt: "LOW"}
	api, ctx := meetVerdictFixture(t, a, b, nil, nil)
	set := resolvedGuardrailProfileFrom(ctx).set
	ctx = withPinnedGeneration(ctx, &Generation{N: 1, Config: set.base, Profiles: set})
	packA := &guardrail.RulePack{SensitiveTools: &guardrail.SensitiveToolsConfig{Tools: []guardrail.SensitiveTool{
		{Name: "read_db", ResultInspection: false, MinEntitiesAlert: 2},
	}}}
	packB := &guardrail.RulePack{SensitiveTools: &guardrail.SensitiveToolsConfig{Tools: []guardrail.SensitiveTool{
		{Name: "read_db", ResultInspection: true, MinEntitiesAlert: 5},
	}}}
	set.packs[effectiveRulePackKey(set.profileConfig("a"), "codex")] = packA
	set.packs[effectiveRulePackKey(set.profileConfig("b"), "codex")] = packB
	piiFindings := []string{"JUDGE-PII-EMAIL", "JUDGE-PII-EMAIL"}
	if reason, alert := api.sensitiveToolResultAlert(ctx, "codex", "read_db", "HIGH", piiFindings, "some output"); alert {
		t.Fatalf("cross-member sensitive-tool settings caused alert: %s", reason)
	}
	packB.SensitiveTools.Tools[0].MinEntitiesAlert = 2
	if reason, alert := api.sensitiveToolResultAlert(ctx, "codex", "read_db", "HIGH", piiFindings, "some output"); !alert {
		t.Fatalf("matching member did not alert: %s", reason)
	}
}
