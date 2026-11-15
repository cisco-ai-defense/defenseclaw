// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func meetVerdictFixture(t *testing.T, a, b config.GuardrailProfile, aRule, bRule *PatternRule) (*APIServer, context.Context) {
	t.Helper()
	return meetVerdictFixtureSelected(t, a, b, aRule, bRule, config.ProfileMeetName([]string{"a", "b"}))
}

func meetVerdictFixtureSelected(t *testing.T, a, b config.GuardrailProfile, aRule, bRule *PatternRule, wantSelection string) (*APIServer, context.Context) {
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
	// Publish the fixture's set as a gateway does and put the process-wide
	// set back after: a set another test's API server had left there was
	// resolved instead on later -count runs (rel-1-0-6 GAP-0335).
	previous := liveGuardrailProfiles.Load()
	t.Cleanup(func() { liveGuardrailProfiles.Store(previous) })
	api.setGuardrailProfiles(set)
	subject := context.WithValue(t.Context(), testVerifiedSubjectKey{}, identityTestSubject(p, p.providers[0], stateProven, true))
	ctx := api.withGuardrailProfileDecision(withProfilePath(subject, profilePathHook), "codex")
	if got := resolvedGuardrailProfileFrom(ctx).decision; got.Name != wantSelection || got.Refused != "" {
		t.Fatalf("fixture: selection %+v, want %q", got, wantSelection)
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

func TestProfileMeetObserverMainHookFindingCannotEnterEnforcingToolChain(t *testing.T) {
	const keyPath = "/home/alice/.ssh/id_rsa"
	const command = "cat " + keyPath
	for _, tc := range []struct {
		name                                         string
		observer, connectorObserver, covered, sameID bool
		wantStep                                     bool
	}{
		{name: "observer in meet", observer: true},
		{name: "observer on this connector", connectorObserver: true},
		{name: "action member control", wantStep: true},
		{name: "observer and action share ID", observer: true, sameID: true, wantStep: true},
		{name: "covered observer", observer: true, covered: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := config.GuardrailProfile{Mode: "action", BlockAt: "CRITICAL", AlertAt: "LOW"}
			b := config.GuardrailProfile{Mode: "action", BlockAt: "HIGH", AlertAt: "LOW"}
			if tc.observer {
				b.Mode = "observe"
			}
			if tc.connectorObserver {
				b.Connectors = map[string]config.PerConnectorGuardrailConfig{
					"codex": {Mode: "observe"},
				}
			}
			if !tc.covered {
				b.Sandbox = &config.OpenShellAdminConfig{EgressBlock: []string{"observer.example"}}
			}
			aRule := meetVerdictRule("A-OTHER", "absent-marker", "HIGH")
			if tc.sameID {
				aRule = meetVerdictRule("PATH-SSH-KEY", keyPath, "HIGH")
			}
			wantSelection := config.ProfileMeetName([]string{"a", "b"})
			if tc.covered {
				wantSelection = "a"
			}
			_, ctx := meetVerdictFixtureSelected(t, a, b, aRule,
				meetVerdictRule("PATH-SSH-KEY", keyPath, "HIGH"), wantSelection)
			generation := resolvedGuardrailProfileFrom(ctx).ruleGenerationFor(ctx, "codex")
			if generation == nil || len(generation.members) != 2 {
				t.Fatalf("fixture: meet generation=%+v", generation)
			}
			for _, entry := range []string{"context recorder", "generic recorder"} {
				t.Run(entry, func(t *testing.T) {
					capture := &toolChainHookCapture{}
					captureCtx := withToolChainHookCapture(ctx, capture)
					record := toolChainRecorderFromContext(captureCtx)
					if entry == "generic recorder" {
						record = toolChainRecorder(captureCtx, "codex", capture)
					}
					findings := dispatchTrustedAction(captureCtx, trustedActionRequest{
						Input:      actionfacts.Input{Tool: "shell", Command: command, ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX},
						LegacyText: command, Connector: "codex", EnforcementCapable: true,
						generation: generation, record: record,
					})
					if !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == "PATH-SSH-KEY" && f.profile == "b" }) {
						t.Fatalf("observer finding missing from hook audit: %+v", findings)
					}
					if tc.sameID && !slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == "PATH-SSH-KEY" && f.profile == "a" }) {
						t.Fatalf("action member's same-ID finding missing from hook audit: %+v", findings)
					}
					projection, _ := projectAgentHookToolChains(agentHookRequest{toolChain: capture}, connector.ToolCallLifecycleContract{})
					step, _ := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, 1)
					// The read of a credentials file arms the chain from the
					// call's ActionFacts on its own (substrate-1:GAP-0210), so
					// the step is present in every case. What an observer must
					// never do is add to it: without an enforcing member's
					// finding, the chain is exactly the facts-only projection.
					if projection.DetectionStepMask&step == 0 {
						t.Fatalf("secret-read chain detection step missing; projection=%+v", projection)
					}
					if !tc.wantStep {
						factsOnly := guardrail.ToolChainProjection{ParseStatus: capture.facts.Parse.Status}
						projectTrustedActionChainSteps(&factsOnly, capture.facts, nil)
						if projection.DetectionStepMask != factsOnly.DetectionStepMask ||
							projection.EnforcementStepMask != factsOnly.EnforcementStepMask ||
							projection.EnforcementJoinDigests != factsOnly.EnforcementJoinDigests {
							t.Fatalf("observer finding changed the chain: %+v, facts only %+v", projection, factsOnly)
						}
					}
				})
			}
		})
	}
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

// Under identity profiles a cascade-2 confirm keeps its HIGH alert mapping on
// an agent that cannot ask: the meet of the members keeps decisionConfirm.
func TestProfileMeetKeepsTheDecisionModelConfirm(t *testing.T) {
	var calls atomic.Int32
	srv := countingDecisionModel(t, "confirm", 0.30, &calls)
	a := config.GuardrailProfile{Mode: "action", BlockAt: "CRITICAL", AlertAt: "LOW"}
	b := config.GuardrailProfile{Mode: "action", BlockAt: "CRITICAL", AlertAt: "MEDIUM"}
	api, ctx := meetVerdictFixture(t, a, b, nil, nil)
	dm := config.DecisionModelConfig{Enabled: true, Model: "fake", BaseURL: srv.URL, Timeout: 1, HookConnectors: []string{"codex"}}
	api.scannerCfg.DecisionModel = dm
	api.scannerCfg.DataDir = t.TempDir()
	resolved := resolvedGuardrailProfileFrom(ctx)
	resolved.derived.DecisionModel = dm
	for _, member := range []string{"a", "b"} {
		resolved.set.profileConfig(member).DecisionModel = dm
	}
	api.SetHookDecisionJudge(newDecisionOnlyJudge(api.scannerCfg))
	verdict := api.runHookJudge(ctx, "tool_call", "prompt", "codex", `{"command":"make -C ./fixtures/reports"}`, "Bash", nil)
	if verdict == nil || calls.Load() == 0 || verdict.Action != guardrailActionConfirm || !verdict.decisionConfirm {
		t.Fatalf("meet verdict = %+v (decision model calls %d), want the decision model's confirm", verdict, calls.Load())
	}
}

// When another member confirms the same call for another reason, the meet's
// confirm is not the decision model's alone: the flag is cleared.
func TestProfileMeetClearsTheDecisionModelConfirmBesideAnotherConfirm(t *testing.T) {
	dm := &ScanVerdict{Action: guardrailActionConfirm, Severity: "HIGH", decisionConfirm: true}
	other := &ScanVerdict{Action: guardrailActionConfirm, Severity: "HIGH"}
	alert := &ScanVerdict{Action: guardrailActionAlert, Severity: "HIGH"}
	flag := meetDecisionConfirm(false, guardrailActionAllow, dm, true)
	if !flag {
		t.Fatal("a member that raises the meet to the decision model's confirm must set the flag")
	}
	if !meetDecisionConfirm(flag, guardrailActionConfirm, alert, false) {
		t.Fatal("a weaker member must leave the flag")
	}
	if !meetDecisionConfirm(flag, guardrailActionConfirm, dm, false) {
		t.Fatal("a second decision-model confirm must leave the flag")
	}
	if meetDecisionConfirm(flag, guardrailActionConfirm, other, false) {
		t.Fatal("another member's confirm at the same action must clear the flag")
	}
	if meetDecisionConfirm(false, guardrailActionAlert, other, true) {
		t.Fatal("a non-model confirm that raises the meet must not set the flag")
	}
}
