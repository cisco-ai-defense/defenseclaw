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

// Verdict cache metrics + LLM judge spans are implemented in llm_judge.go and
// internal/guardrail/verdict_cache.go (Track 3).

import (
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// defaultLogWriter is the destination for guardrail diagnostic messages.
var defaultLogWriter io.Writer = os.Stderr

// ScanVerdict is the result of a guardrail inspection.
type ScanVerdict struct {
	Action         string   `json:"action"`
	Severity       string   `json:"severity"`
	Reason         string   `json:"reason"`
	Findings       []string `json:"findings"`
	EntityCount    int      `json:"entity_count,omitempty"`
	Scanner        string   `json:"scanner,omitempty"`
	ScannerSources []string `json:"scanner_sources,omitempty"`
	CiscoElapsedMs float64  `json:"cisco_elapsed_ms,omitempty"`
	JudgeFailed    bool     `json:"-"`
}

func allowVerdict(scanner string) *ScanVerdict {
	return &ScanVerdict{
		Action:   "allow",
		Severity: "NONE",
		Scanner:  scanner,
	}
}

func errorVerdict(scanner string) *ScanVerdict {
	return &ScanVerdict{
		Action:      "allow",
		Severity:    "NONE",
		Scanner:     scanner,
		JudgeFailed: true,
	}
}

// TriageSignal is a finding from the regex triage layer. Unlike ScanVerdict,
// signals carry a classification level that determines whether the finding
// should block immediately, be adjudicated by the LLM judge, or just logged.
type TriageSignal struct {
	Level      string // "HIGH_SIGNAL", "NEEDS_REVIEW", "LOW_SIGNAL"
	FindingID  string
	Category   string // "injection", "pii", "secret", "exfil"
	Pattern    string // what matched
	Evidence   string // ~200-char context window around match
	Confidence float64
}

// guardrailSpanEmitter is the callback surface the inspector
// uses to open and close OTel spans for each stage. Kept as a
// pair of function fields instead of an interface so the
// sidecar wiring can populate it from internal/telemetry
// without the inspector package importing telemetry directly.
//
// A nil emitter (or either nil field) is valid — every call
// site guards before invoking, so tests and non-otel consumers
// opt out by just not calling SetTracer.
//
// `start` opens the root "stage" span (regex_only / regex_judge /
// judge_first). `startPhase` opens child spans for each sub-stage
// (regex, cisco_ai_defense, judge.prompt_injection, judge.pii,
// opa, finalize) so operators can drill past stage-level latency
// into the exact phase that dominated the budget.
type guardrailSpanEmitter struct {
	start      func(ctx context.Context, stage, direction, model string) (context.Context, func(action, severity, reason string, latencyMs int64))
	startPhase func(ctx context.Context, phase string) (context.Context, func(action, severity string, latencyMs int64))
}

// GuardrailInspector orchestrates local pattern scanning, Cisco AI Defense,
// the LLM judge, and OPA policy evaluation.
type GuardrailInspector struct {
	scannerMode       string
	ciscoClient       *CiscoInspectClient
	judge             *LLMJudge
	policyDir         string
	detectionStrategy string
	strategyPrompt    string
	strategyComplete  string
	strategyToolCall  string
	judgeSweep        bool

	// Rego policy engine — lazily constructed on first finalize() call and
	// cached for the lifetime of the inspector. Previously policy.New() ran
	// on every inspection (parsing every .rego file and compiling the
	// module set from scratch), which dominated guardrail latency under
	// load. Reload is caller-driven via ReloadPolicies().
	engineMu        sync.RWMutex
	engine          *policy.Engine
	engineLoadErr   error
	engineInitOnce  sync.Once
	engineErrLogged sync.Once

	// tracer is set via SetTracer() from the sidecar wiring layer
	// once an OTel provider is available. Kept as an interface so
	// the inspector doesn't need to import internal/telemetry.
	tracer *guardrailSpanEmitter
}

// NewGuardrailInspector creates an inspector from config parameters.
func NewGuardrailInspector(scannerMode string, cisco *CiscoInspectClient, judge *LLMJudge, policyDir string) *GuardrailInspector {
	return &GuardrailInspector{
		scannerMode: scannerMode,
		ciscoClient: cisco,
		judge:       judge,
		policyDir:   policyDir,
	}
}

// SetTracerFunc installs the OTel span emitter. Pass nil to
// disable span emission entirely (tests typically never call
// this). The sidecar wires this to telemetry.Provider once
// OTel is initialized.
func (g *GuardrailInspector) SetTracerFunc(
	start func(ctx context.Context, stage, direction, model string) (context.Context, func(action, severity, reason string, latencyMs int64)),
) {
	if start == nil {
		// Preserve any phase tracer already installed — SetTracerFunc
		// may be called with nil during proxy teardown while the
		// phase tracer is still live.
		if g.tracer != nil {
			g.tracer.start = nil
			if g.tracer.startPhase == nil {
				g.tracer = nil
			}
		}
		return
	}
	if g.tracer == nil {
		g.tracer = &guardrailSpanEmitter{}
	}
	g.tracer.start = start
}

// SetPhaseTracerFunc installs the child-span emitter used to track
// individual phases (regex, cisco_ai_defense, judge.*, opa, finalize)
// within a guardrail inspection. Separate setter from SetTracerFunc
// so the two tiers can be wired independently — e.g. stage-only for
// legacy dashboards, or phase-only for latency debugging without
// doubling span cost in production.
func (g *GuardrailInspector) SetPhaseTracerFunc(
	start func(ctx context.Context, phase string) (context.Context, func(action, severity string, latencyMs int64)),
) {
	if start == nil {
		if g.tracer != nil {
			g.tracer.startPhase = nil
			if g.tracer.start == nil {
				g.tracer = nil
			}
		}
		return
	}
	if g.tracer == nil {
		g.tracer = &guardrailSpanEmitter{}
	}
	g.tracer.startPhase = start
}

// startPhaseSpan is the internal helper every phase call site uses.
// Returns (ctx, endFn). endFn is always non-nil so callers can
// unconditionally `defer end(...)` without a nil guard.
func (g *GuardrailInspector) startPhaseSpan(ctx context.Context, phase string) (context.Context, func(action, severity string, latencyMs int64)) {
	if g.tracer == nil || g.tracer.startPhase == nil {
		return ctx, func(string, string, int64) {}
	}
	return g.tracer.startPhase(ctx, phase)
}

// SetDetectionStrategy configures the multi-strategy dispatch fields.
func (g *GuardrailInspector) SetDetectionStrategy(global, prompt, completion, toolCall string, sweep bool) {
	g.detectionStrategy = global
	g.strategyPrompt = prompt
	g.strategyComplete = completion
	g.strategyToolCall = toolCall
	g.judgeSweep = sweep
}

// effectiveStrategy resolves the detection strategy for a given direction.
func (g *GuardrailInspector) effectiveStrategy(direction string) string {
	var override string
	switch direction {
	case "prompt":
		override = g.strategyPrompt
	case "completion":
		override = g.strategyComplete
	case "tool_call":
		override = g.strategyToolCall
	}
	if override != "" {
		return override
	}
	if g.detectionStrategy != "" {
		return g.detectionStrategy
	}
	return "regex_only"
}

// SetScannerMode updates the scanner mode at runtime.
func (g *GuardrailInspector) SetScannerMode(mode string) {
	g.scannerMode = mode
}

// Inspect runs scanners according to detection_strategy and scanner_mode,
// then returns a merged verdict. The detection strategy controls whether
// regex runs alone, triages for LLM adjudication, or the LLM runs first.
func (g *GuardrailInspector) Inspect(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	strategy := g.effectiveStrategy(direction)

	// Open a span for the whole inspection — stage naming follows
	// the strategy so dashboards can compare regex-only vs
	// regex+judge latency distributions side-by-side.
	var endSpan func(action, severity, reason string, latencyMs int64)
	if g.tracer != nil && g.tracer.start != nil {
		var newCtx context.Context
		newCtx, endSpan = g.tracer.start(ctx, strategy, direction, model)
		ctx = newCtx
	}

	start := time.Now()
	var verdict *ScanVerdict
	switch strategy {
	case "regex_judge":
		verdict = g.inspectRegexJudge(ctx, direction, content, messages, model, mode)
	case "judge_first":
		verdict = g.inspectJudgeFirst(ctx, direction, content, messages, model, mode)
	default:
		verdict = g.inspectRegexOnly(ctx, direction, content, messages, model, mode)
	}

	latencyMs := time.Since(start).Milliseconds()

	if endSpan != nil {
		var action, sev, reason string
		if verdict != nil {
			action, sev, reason = verdict.Action, verdict.Severity, verdict.Reason
		}
		endSpan(action, sev, reason, latencyMs)
	}

	// Structured verdict emission — one record per top-level Inspect
	// call, regardless of strategy. Skipping NONE/empty verdicts keeps
	// the JSONL focused on real decisions; lifecycle events already
	// cover the "nothing happened" case.
	if verdict != nil && verdict.Severity != "" && verdict.Severity != "NONE" {
		emitVerdict(
			ctx,
			gatewaylog.StageFinal,
			gatewaylog.Direction(direction),
			model,
			verdict.Action,
			verdict.Reason,
			deriveSeverity(verdict.Severity),
			categoriesOf(verdict.Findings),
			latencyMs,
		)
	}
	return verdict
}

// categoriesOf returns deduped finding identifiers in insertion
// order. ScanVerdict.Findings is a flat []string (e.g. "pii:email",
// "injection:ignore-previous"), so we just preserve distinct entries
// without trying to parse them — parsing happens downstream in the
// TUI/sink consumers that know their own schema.
func categoriesOf(findings []string) []string {
	if len(findings) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(findings))
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		if f == "" {
			continue
		}
		if _, ok := seen[f]; ok {
			continue
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	return out
}

// InspectMidStream runs regex-only inspection for mid-stream SSE chunks.
// The LLM judge is too slow for per-chunk scanning; it runs on PRE-CALL
// and POST-CALL only. Mid-stream uses fast regex to catch high-severity
// content (sensitive paths, dangerous commands, critical injection patterns)
// and block the stream immediately without waiting for an LLM round-trip.
func (g *GuardrailInspector) InspectMidStream(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	return g.inspectRegexOnly(ctx, direction, content, messages, model, mode)
}

// inspectRegexOnly is the original flow: regex patterns produce verdicts,
// no LLM involvement. Backward-compatible with pre-strategy behavior.
func (g *GuardrailInspector) inspectRegexOnly(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	var localResult *ScanVerdict
	var ciscoResult *ScanVerdict
	var ciscoElapsedMs float64

	sm := g.scannerMode

	regexStart := time.Now()
	_, endRegex := g.startPhaseSpan(ctx, "regex")
	localResult = scanLocalPatterns(direction, content)
	endRegex(phaseAction(localResult), phaseSeverity(localResult), time.Since(regexStart).Milliseconds())

	if sm == "local" || (localResult != nil && localResult.Severity == "HIGH") {
		if localResult != nil {
			localResult.ScannerSources = []string{"local-pattern"}
		}
		return g.finalize(ctx, direction, model, mode, content, localResult, nil)
	}

	if (sm == "remote" || sm == "both") && g.ciscoClient != nil && len(messages) > 0 {
		t0 := time.Now()
		_, endCisco := g.startPhaseSpan(ctx, "cisco_ai_defense")
		ciscoResult = g.ciscoClient.Inspect(messages)
		ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
		endCisco(phaseAction(ciscoResult), phaseSeverity(ciscoResult), int64(ciscoElapsedMs))
	}

	merged := mergeVerdicts(localResult, ciscoResult)
	merged.CiscoElapsedMs = ciscoElapsedMs

	return g.finalize(ctx, direction, model, mode, content, merged, ciscoResult)
}

// inspectRegexJudge uses triage patterns to route ambiguous findings to the
// LLM judge, while running the full rule engine (ScanAllRules) as a safety net
// for patterns triage doesn't cover (sensitive paths, commands, C2, etc.).
func (g *GuardrailInspector) inspectRegexJudge(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	regexStart := time.Now()
	_, endRegex := g.startPhaseSpan(ctx, "regex")
	signals := triagePatterns(direction, content)
	high, review, _ := partitionSignals(signals)

	// Run the full rule engine for categories triage doesn't cover.
	ruleFindings := ScanAllRules(content, "")
	var ruleVerdict *ScanVerdict
	if len(ruleFindings) > 0 {
		maxSev := HighestSeverity(ruleFindings)
		action := "alert"
		if severityRank[maxSev] >= severityRank["HIGH"] {
			action = "block"
		}
		var ids []string
		for _, f := range ruleFindings {
			ids = append(ids, f.RuleID+":"+f.Title)
		}
		top := ids
		if len(top) > 5 {
			top = top[:5]
		}
		ruleVerdict = &ScanVerdict{
			Action:         action,
			Severity:       maxSev,
			Reason:         "matched: " + strings.Join(top, ", "),
			Findings:       ids,
			Scanner:        "local-pattern",
			ScannerSources: []string{"local-pattern"},
		}
	}
	// Regex phase outcome is the stronger of triage/rule so the span
	// attributes reflect what actually influenced the decision.
	regexVerdictForSpan := ruleVerdict
	if len(high) > 0 && (regexVerdictForSpan == nil || severityRank["HIGH"] > severityRank[regexVerdictForSpan.Severity]) {
		regexVerdictForSpan = &ScanVerdict{Action: "block", Severity: "HIGH"}
	}
	endRegex(phaseAction(regexVerdictForSpan), phaseSeverity(regexVerdictForSpan), time.Since(regexStart).Milliseconds())

	var ciscoResult *ScanVerdict
	var ciscoElapsedMs float64

	runCisco := func() {
		t0 := time.Now()
		_, endCisco := g.startPhaseSpan(ctx, "cisco_ai_defense")
		ciscoResult = g.ciscoClient.Inspect(messages)
		ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
		endCisco(phaseAction(ciscoResult), phaseSeverity(ciscoResult), int64(ciscoElapsedMs))
	}

	// HIGH_SIGNAL triage findings produce an immediate verdict.
	if len(high) > 0 {
		verdict := signalsToVerdict(high, "local-triage")
		verdict.ScannerSources = []string{"local-triage"}
		if ruleVerdict != nil {
			verdict = mergeVerdicts(verdict, ruleVerdict)
		}

		if (g.scannerMode == "remote" || g.scannerMode == "both") && g.ciscoClient != nil && len(messages) > 0 {
			runCisco()
			verdict = mergeVerdicts(verdict, ciscoResult)
			verdict.CiscoElapsedMs = ciscoElapsedMs
		}
		return g.finalize(ctx, direction, model, mode, content, verdict, ciscoResult)
	}

	// If the rule engine found HIGH+ severity, block immediately (covers
	// sensitive paths, dangerous commands, C2, etc. that triage doesn't have).
	if ruleVerdict != nil && severityRank[ruleVerdict.Severity] >= severityRank["HIGH"] {
		if (g.scannerMode == "remote" || g.scannerMode == "both") && g.ciscoClient != nil && len(messages) > 0 {
			runCisco()
			ruleVerdict = mergeVerdicts(ruleVerdict, ciscoResult)
			ruleVerdict.CiscoElapsedMs = ciscoElapsedMs
		}
		return g.finalize(ctx, direction, model, mode, content, ruleVerdict, ciscoResult)
	}

	// NEEDS_REVIEW: send to judge for adjudication with evidence.
	// If the judge is unavailable or fails, fall back to treating NEEDS_REVIEW
	// signals as MEDIUM alerts so they appear in the audit log rather than
	// being silently dropped.
	var judgeVerdict *ScanVerdict
	if len(review) > 0 {
		if g.judge != nil {
			judgeStart := time.Now()
			judgeCtx, endJudge := g.startPhaseSpan(ctx, "judge.adjudicate")
			judgeVerdict = g.judge.AdjudicateFindings(judgeCtx, direction, content, review)
			endJudge(phaseAction(judgeVerdict), phaseSeverity(judgeVerdict), time.Since(judgeStart).Milliseconds())
		}
		if judgeVerdict == nil || judgeVerdict.JudgeFailed {
			judgeVerdict = signalsToVerdict(review, "local-triage-fallback")
			judgeVerdict.Severity = "MEDIUM"
			judgeVerdict.Action = "alert"
		}
	}

	// NO_SIGNAL + judge_sweep: run full classification.
	if len(signals) == 0 && g.judgeSweep && g.judge != nil {
		sweepStart := time.Now()
		sweepCtx, endSweep := g.startPhaseSpan(ctx, "judge.sweep")
		judgeVerdict = g.judge.RunJudges(sweepCtx, direction, content, "")
		endSweep(phaseAction(judgeVerdict), phaseSeverity(judgeVerdict), time.Since(sweepStart).Milliseconds())
	}

	// Cisco AI Defense (if configured).
	if (g.scannerMode == "remote" || g.scannerMode == "both") && g.ciscoClient != nil && len(messages) > 0 {
		runCisco()
	}

	merged := allowVerdict("local-triage")
	if ruleVerdict != nil && ruleVerdict.Severity != "NONE" {
		merged = ruleVerdict
	}
	if judgeVerdict != nil && judgeVerdict.Severity != "NONE" {
		if merged.Action == "allow" {
			merged = judgeVerdict
		} else {
			merged = mergeVerdicts(merged, judgeVerdict)
		}
	}
	if ciscoResult != nil {
		merged = mergeVerdicts(merged, ciscoResult)
		merged.CiscoElapsedMs = ciscoElapsedMs
	}

	return g.finalize(ctx, direction, model, mode, content, merged, ciscoResult)
}

// inspectJudgeFirst runs the LLM judge as the primary scanner with regex as
// a parallel safety net. If the judge fails or times out, falls back to regex.
func (g *GuardrailInspector) inspectJudgeFirst(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	var ciscoResult *ScanVerdict
	var ciscoElapsedMs float64

	type result struct {
		verdict *ScanVerdict
		err     bool
	}

	judgeCh := make(chan result, 1)
	triageCh := make(chan []TriageSignal, 1)

	// Run judge and triage in parallel.
	//
	// A panic in either goroutine would leave its channel unwritten and
	// deadlock the parent on `<-judgeCh` / `<-triageCh`, stalling the
	// request and permanently pinning the http handler goroutine.
	// Both producers therefore wrap their body in defer/recover() and
	// fall back to an error sentinel so the parent always proceeds
	// (judge → regex fallback, triage → empty signal set) even under
	// a pathological policy / scanner bug.
	if g.judge != nil {
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					fmt.Fprintf(defaultLogWriter, "[guardrail] judge_first: judge goroutine panic recovered: %v\n", rec)
					judgeCh <- result{verdict: nil, err: true}
				}
			}()
			judgeStart := time.Now()
			judgeCtx, endJudge := g.startPhaseSpan(ctx, "judge.sweep")
			v := g.judge.RunJudges(judgeCtx, direction, content, "")
			endJudge(phaseAction(v), phaseSeverity(v), time.Since(judgeStart).Milliseconds())
			judgeCh <- result{verdict: v}
		}()
	} else {
		judgeCh <- result{verdict: nil, err: true}
	}

	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				fmt.Fprintf(defaultLogWriter, "[guardrail] judge_first: triage goroutine panic recovered: %v\n", rec)
				triageCh <- nil
			}
		}()
		regexStart := time.Now()
		_, endRegex := g.startPhaseSpan(ctx, "regex")
		sigs := triagePatterns(direction, content)
		// Regex phase without a verdict still records latency — timing
		// alone is a useful signal when comparing judge_first budgets.
		endRegex("", "", time.Since(regexStart).Milliseconds())
		triageCh <- sigs
	}()

	judgeRes := <-judgeCh
	signals := <-triageCh

	// If the judge failed completely (nil, explicit error, or all sub-judges
	// errored), fall back to full regex scanning. If the judge partially
	// succeeded (some sub-judges failed), merge the regex safety net for
	// the failed categories so detection doesn't silently degrade.
	if judgeRes.err || judgeRes.verdict == nil || judgeRes.verdict.JudgeFailed {
		reason := "unknown"
		if judgeRes.err {
			reason = "goroutine-err"
		} else if judgeRes.verdict == nil {
			reason = "nil-verdict"
		} else if judgeRes.verdict.JudgeFailed {
			reason = "judge-failed (scanner=" + judgeRes.verdict.Scanner + ")"
		}
		fmt.Fprintf(defaultLogWriter, "  [guardrail] judge_first: judge unavailable (%s dir=%s), falling back to regex_only\n", reason, direction)
		fallbackStart := time.Now()
		_, endFallback := g.startPhaseSpan(ctx, "regex.fallback")
		localResult := scanLocalPatterns(direction, content)
		endFallback(phaseAction(localResult), phaseSeverity(localResult), time.Since(fallbackStart).Milliseconds())
		if localResult != nil {
			localResult.ScannerSources = []string{"local-pattern", "judge-fallback"}
		}
		// Also run Cisco remote on fallback for full parity with regex_only path.
		if (g.scannerMode == "remote" || g.scannerMode == "both") && g.ciscoClient != nil && len(messages) > 0 {
			t0 := time.Now()
			_, endCisco := g.startPhaseSpan(ctx, "cisco_ai_defense")
			ciscoResult = g.ciscoClient.Inspect(messages)
			ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
			endCisco(phaseAction(ciscoResult), phaseSeverity(ciscoResult), int64(ciscoElapsedMs))
			localResult = mergeVerdicts(localResult, ciscoResult)
			if localResult != nil {
				localResult.CiscoElapsedMs = ciscoElapsedMs
			}
		}
		return g.finalize(ctx, direction, model, mode, content, localResult, ciscoResult)
	}

	merged := judgeRes.verdict

	// Always merge the regex safety net — even when the judge succeeded,
	// it may have missed categories that only regex covers. HIGH_SIGNAL
	// regex findings and full rule engine results are both applied.
	high, _, _ := partitionSignals(signals)
	if len(high) > 0 {
		regexVerdict := signalsToVerdict(high, "local-triage")
		merged = mergeWithJudge(merged, regexVerdict)
	}

	// Run the full rule engine as a safety net for categories the judge and
	// triage don't cover (sensitive paths, dangerous commands, C2, etc.).
	ruleFindings := ScanAllRules(content, "")
	if len(ruleFindings) > 0 {
		maxSev := HighestSeverity(ruleFindings)
		if severityRank[maxSev] >= severityRank["HIGH"] {
			var ids []string
			for _, f := range ruleFindings {
				ids = append(ids, f.RuleID+":"+f.Title)
			}
			top := ids
			if len(top) > 5 {
				top = top[:5]
			}
			rv := &ScanVerdict{
				Action:   "block",
				Severity: maxSev,
				Reason:   "matched: " + strings.Join(top, ", "),
				Findings: ids,
				Scanner:  "local-pattern",
			}
			merged = mergeVerdicts(merged, rv)
		}
	}

	// Cisco AI Defense (if configured).
	if (g.scannerMode == "remote" || g.scannerMode == "both") && g.ciscoClient != nil && len(messages) > 0 {
		t0 := time.Now()
		_, endCisco := g.startPhaseSpan(ctx, "cisco_ai_defense")
		ciscoResult = g.ciscoClient.Inspect(messages)
		ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
		endCisco(phaseAction(ciscoResult), phaseSeverity(ciscoResult), int64(ciscoElapsedMs))
		merged = mergeVerdicts(merged, ciscoResult)
		merged.CiscoElapsedMs = ciscoElapsedMs
	}

	return g.finalize(ctx, direction, model, mode, content, merged, ciscoResult)
}

// phaseAction safely extracts the action from a potentially-nil verdict
// for span attribute tagging. Empty string is returned for nil/NONE so
// the OTel attribute is omitted cleanly.
func phaseAction(v *ScanVerdict) string {
	if v == nil {
		return ""
	}
	if v.Severity == "NONE" || v.Severity == "" {
		return ""
	}
	return v.Action
}

// phaseSeverity mirrors phaseAction for the severity attribute.
func phaseSeverity(v *ScanVerdict) string {
	if v == nil {
		return ""
	}
	if v.Severity == "NONE" {
		return ""
	}
	return v.Severity
}

// policyEngine returns the cached Rego engine, initializing it on first call.
// Returns nil if construction failed; the error is logged exactly once so
// OPA misconfiguration surfaces in logs without flooding them on every
// request. Callers fall back to the merged scanner verdict when nil.
func (g *GuardrailInspector) policyEngine() *policy.Engine {
	g.engineInitOnce.Do(func() {
		eng, err := policy.New(g.policyDir)
		g.engineMu.Lock()
		g.engine = eng
		g.engineLoadErr = err
		g.engineMu.Unlock()
	})
	g.engineMu.RLock()
	eng, err := g.engine, g.engineLoadErr
	g.engineMu.RUnlock()
	if err != nil {
		g.engineErrLogged.Do(func() {
			fmt.Fprintf(defaultLogWriter,
				"  [guardrail] policy engine unavailable, falling back to scanner verdict: %v\n", err)
		})
		return nil
	}
	return eng
}

// ReloadPolicies rebuilds the policy engine from disk. Call this when the
// policy directory has changed (e.g. config reload). If the new bundle
// fails to compile, the previous engine is retained and an error is
// returned.
func (g *GuardrailInspector) ReloadPolicies() error {
	if g.policyDir == "" {
		return nil
	}
	eng, err := policy.New(g.policyDir)
	if err != nil {
		return err
	}
	g.engineMu.Lock()
	g.engine = eng
	g.engineLoadErr = nil
	g.engineMu.Unlock()
	return nil
}

// finalize runs OPA policy evaluation if available, otherwise returns the
// merged verdict directly.
func (g *GuardrailInspector) finalize(ctx context.Context, direction, model, mode, content string, merged *ScanVerdict, ciscoResult *ScanVerdict) *ScanVerdict {
	if g.policyDir == "" {
		return merged
	}

	engine := g.policyEngine()
	if engine == nil {
		return merged
	}

	input := policy.GuardrailInput{
		Direction:     direction,
		Model:         model,
		Mode:          mode,
		ScannerMode:   g.scannerMode,
		ContentLength: len(content),
	}

	if merged != nil && merged.Severity != "NONE" {
		input.LocalResult = &policy.GuardrailScanResult{
			Action:   merged.Action,
			Severity: merged.Severity,
			Reason:   merged.Reason,
			Findings: merged.Findings,
		}
	}
	if ciscoResult != nil && ciscoResult.Severity != "NONE" {
		input.CiscoResult = &policy.GuardrailScanResult{
			Action:   ciscoResult.Action,
			Severity: ciscoResult.Severity,
			Reason:   ciscoResult.Reason,
			Findings: ciscoResult.Findings,
		}
	}

	opaStart := time.Now()
	opaCtx, endOPA := g.startPhaseSpan(ctx, "opa")
	out, err := engine.EvaluateGuardrail(opaCtx, input)
	opaLatency := time.Since(opaStart).Milliseconds()
	if err != nil || out == nil {
		// Record the latency even on failure so the phase span
		// makes the OPA fallback visible in trace waterfalls.
		endOPA("", "", opaLatency)
		return merged
	}
	endOPA(out.Action, out.Severity, opaLatency)

	return &ScanVerdict{
		Action:         out.Action,
		Severity:       out.Severity,
		Reason:         out.Reason,
		Findings:       merged.Findings,
		ScannerSources: out.ScannerSources,
	}
}

// ---------------------------------------------------------------------------
// Local pattern scanning
// ---------------------------------------------------------------------------

var injectionPatterns = []string{
	"ignore previous", "ignore all instructions", "ignore above",
	"ignore all previous", "ignore your instructions", "ignore prior",
	"disregard previous", "disregard all", "disregard your",
	"forget your instructions", "forget all previous",
	"override your instructions", "override all instructions",
	"you are now", "pretend you are",
	"jailbreak", "do anything now", "dan mode",
	"developer mode enabled",
}

var injectionRegexes = []*regexp.Regexp{
	regexp.MustCompile(`ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|directives|guidelines)`),
	regexp.MustCompile(`disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|directives|guidelines)`),
	regexp.MustCompile(`(?:share|reveal|show|print|output|dump|repeat|give\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)`),
	regexp.MustCompile(`(?:what\s+(?:is|are)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules))`),
	regexp.MustCompile(`act\s+as\b`),
	regexp.MustCompile(`bypass\s+(?:your|the|my|all|any)\s+(?:filter|guard|safe|restrict|rule|instruction)`),
}

var piiRequestPatterns = []string{
	"find their ssn", "find my ssn", "look up their ssn",
	"retrieve their ssn", "get their ssn", "get my ssn",
	"social security number", "mother's maiden name",
	"mothers maiden name", "credit card number",
	"find their password", "look up their password",
	"find their email", "look up their email",
	"date of birth", "bank account number",
	"passport number", "driver's license",
	"drivers license",
}

var piiDataRegexes = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	regexp.MustCompile(`\b\d{9}\b`),
	regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),
}

var secretPatterns = []string{
	"sk-", "sk-ant-", "sk-proj-", "api_key=", "apikey=",
	"-----begin rsa", "-----begin private", "-----begin openssh",
	"aws_access_key", "aws_secret_access", "password=",
	"bearer ", "ghp_", "gho_", "github_pat_",
}

// secretPatternRegexes tighten patterns that cause false positives as bare
// substrings. Requires assignment-like context with a long alphanumeric value
// (20+ chars) to avoid matching conversational "reply with this token: XYZ".
var secretPatternRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\btoken\s*[:=]\s*["']?[A-Za-z0-9_\-/.]{20,}`),
}

var exfilPatterns = []string{
	"/etc/passwd", "/etc/shadow", "base64 -d", "base64 --decode",
	"exfiltrate", "exfil", "send to my server", "curl http",
}

// exfilRegexes is the deterministic regex FLOOR for credential-file
// reads. It runs against the normalized triage view (lowercased,
// zero-width stripped, whitespace-around-slashes collapsed) so it
// catches typo evasions and odd separators that the literal
// substring list above would silently miss:
//
//   - "etccc passwd", "etc passsswd", "etc/  passwd"
//     → matches via `etc.{0,3}pas{1,8}wd`
//   - "etc shaaadow", "etc shadow"
//     → matches via `etc.{0,3}sha{1,8}dow`
//   - "id_rsa", "id_ed25519", any sibling SSH private key file
//     → matches via `\bid_(?:rsa|ed25519|ecdsa|dsa)\b`
//   - ".ssh/config", "~/.ssh/authorized_keys"
//     → matches via `(?:^|[/\s'"\x60])\.ssh/`
//   - ".aws/credentials", ".aws/config"
//     → matches via `(?:^|[/\s'"\x60])\.aws/(?:credentials|config)\b`
//
// The `.{0,3}` separator is intentionally permissive: it admits both
// extra alphanumerics ("etccc passwd" = 3 trailing c's plus space)
// AND non-alphanumerics ("etc / passwd"). A stricter `[^a-z0-9]{0,3}`
// alternative would silently miss the most common attacker typo
// shape — appending or duplicating letters in the directory name.
// The pattern is still anchored to the exact target words ("etc" +
// "pas...wd" / "sha...dow") so false positives from prose
// containing both fragments separately are rare.
//
// Treat this as a floor under the LLM-judge layer: even if the exfil
// judge is offline, mis-routed, or returns "false" on a polite typo
// prompt, these patterns alone are enough to raise a HIGH_SIGNAL
// triage finding. They are intentionally narrow (no `\.env`,
// `kubeconfig`, etc. — those live under the rules engine and the
// exfil-context probe) so the FLOOR stays opinionated and hard to
// false-positive.
var exfilRegexes = []*regexp.Regexp{
	regexp.MustCompile(`etc.{0,3}pas{1,8}wd\b`),
	regexp.MustCompile(`etc.{0,3}sha{1,8}dow\b`),
	regexp.MustCompile(`\bid_(?:rsa|ed25519|ecdsa|dsa)\b`),
	regexp.MustCompile(`(?:^|[/\s'"` + "`" + `])\.ssh/`),
	regexp.MustCompile(`(?:^|[/\s'"` + "`" + `])\.aws/(?:credentials|config)\b`),
}

// bulkAccessRegex detects prompts requesting bulk extraction from sensitive tools
// (e.g. "users_list with top 10", "contacts_list top 50").
var bulkAccessRegex = regexp.MustCompile(
	`(?i)\b(?:users_list|contacts_list|mail_search|delegated_email_list_principals)\b.*\btop\s+\d{2,}\b`)

func scanLocalPatterns(direction, content string) *ScanVerdict {
	// normalized defeats whitespace/slash-run evasions (Phase 7 of the
	// multi-provider-adapters PR). Substring and regex matches use the
	// normalized string so "/ etc / passwd" and "/etc//passwd" still
	// flag; the judge still receives `content` (the unmodified original)
	// to avoid false-positive leakage from normalization.
	lower := normalizeForTriage(content)
	var flags []string
	isHigh := false

	if direction == "prompt" {
		for _, p := range injectionPatterns {
			if strings.Contains(lower, p) {
				flags = append(flags, p)
				isHigh = true
			}
		}
		for _, re := range injectionRegexes {
			if re.MatchString(lower) {
				match := re.FindString(lower)
				flags = append(flags, match)
				isHigh = true
			}
		}
		for _, p := range piiRequestPatterns {
			if strings.Contains(lower, p) {
				flags = append(flags, "pii-request:"+p)
				isHigh = true
			}
		}
		for _, p := range exfilPatterns {
			if strings.Contains(lower, p) {
				flags = append(flags, p)
				isHigh = true
			}
		}
		// Regex floor: catches typo evasions like "etccc passwd",
		// "etc shaadow", and direct ~/.ssh/.aws/ credential paths
		// that the literal substring list above misses.
		for _, re := range exfilRegexes {
			if match, norm, ok := findRegexMatch(content, lower, re); ok {
				flag := "exfil-regex:" + match
				if norm {
					flag = "exfil-regex:[normalized] " + match
				}
				flags = append(flags, flag)
				isHigh = true
			}
		}
		if bulkAccessRegex.MatchString(lower) {
			flags = append(flags, "bulk-access:sensitive-tool")
		}
	}

	// PII and secret regexes run against BOTH `content` (byte-aligned,
	// case-preserved) AND `lower` (the normalizeForTriage output) via
	// findRegexMatch so zero-width / Unicode-whitespace evasions
	// ("1234\u200B5678\u200B9012\u200B3456" for credit card,
	// "token\u00A0=\u00A0<secret>" for the token regex) still surface
	// here. Without the normalized fallback the docstring above would
	// be a lie: PII/secret regexes are exactly the surfaces an attacker
	// would target with invisible-character splicing.
	for _, re := range piiDataRegexes {
		if match, norm, ok := findRegexMatch(content, lower, re); ok {
			flag := "pii-data:" + match
			if norm {
				flag = "pii-data:[normalized] " + match
			}
			flags = append(flags, flag)
			isHigh = true
		}
	}

	for _, p := range secretPatterns {
		if strings.Contains(lower, p) {
			flags = append(flags, p)
		}
	}
	for _, re := range secretPatternRegexes {
		if match, norm, ok := findRegexMatch(content, lower, re); ok {
			flag := match
			if norm {
				flag = "[normalized] " + match
			}
			flags = append(flags, flag)
		}
	}

	// Run the full rule engine (sensitive paths, dangerous commands, C2, etc.)
	// so that scanLocalPatterns covers every category regardless of strategy.
	maxRuleSev := "NONE"
	ruleFindings := ScanAllRules(content, "")
	for _, rf := range ruleFindings {
		flags = append(flags, rf.RuleID+":"+rf.Title)
		if severityRank[rf.Severity] >= severityRank["HIGH"] {
			isHigh = true
		}
		if severityRank[rf.Severity] > severityRank[maxRuleSev] {
			maxRuleSev = rf.Severity
		}
	}

	if len(flags) == 0 {
		return allowVerdict("local-pattern")
	}

	severity := "MEDIUM"
	if isHigh {
		severity = "HIGH"
	}
	if severityRank[maxRuleSev] > severityRank[severity] {
		severity = maxRuleSev
	}

	action := "alert"
	if severity == "HIGH" || severity == "CRITICAL" {
		action = "block"
	}

	top := flags
	if len(top) > 5 {
		top = top[:5]
	}

	return &ScanVerdict{
		Action:         action,
		Severity:       severity,
		Reason:         "matched: " + strings.Join(top, ", "),
		Findings:       flags,
		Scanner:        "local-pattern",
		ScannerSources: []string{"local-pattern"},
	}
}

// ---------------------------------------------------------------------------
// Triage pattern scanning (for regex_judge and judge_first strategies)
// ---------------------------------------------------------------------------

// Multi-word injection phrases that are unambiguously adversarial.
var highSignalInjectionPatterns = []string{
	"ignore all previous instructions", "ignore all instructions",
	"ignore your instructions", "ignore previous instructions",
	"disregard all instructions", "disregard previous instructions",
	"disregard your instructions",
	"forget your instructions", "forget all previous",
	"override your instructions", "override all instructions",
	"developer mode enabled", "do anything now", "dan mode",
}

// Short injection keywords that need LLM adjudication — many are benign.
var reviewInjectionPatterns = []string{
	"ignore previous", "ignore above", "ignore prior",
	"disregard previous", "disregard all",
	"you are now", "pretend you are",
	"jailbreak",
}

var reviewInjectionRegexes = []*regexp.Regexp{
	regexp.MustCompile(`act\s+as\b`),
	regexp.MustCompile(`bypass\s+(?:your|the|my|all|any)\s+(?:filter|guard|safe|restrict|rule|instruction)`),
}

var highSignalInjectionRegexes = []*regexp.Regexp{
	regexp.MustCompile(`ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|directives|guidelines)`),
	regexp.MustCompile(`disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|directives|guidelines)`),
	regexp.MustCompile(`(?:share|reveal|show|print|output|dump|repeat|give\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions|rules)`),
	regexp.MustCompile(`(?:what\s+(?:is|are)\s+your\s+(?:system\s+)?(?:prompt|instructions|rules))`),
}

// SSN format \d{3}-\d{2}-\d{4} is HIGH_SIGNAL (unambiguous).
var ssnDashRegex = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

// Bare 9-digit numbers are NEEDS_REVIEW (could be Telegram IDs, timestamps, etc).
var bare9DigitRegex = regexp.MustCompile(`\b\d{9}\b`)

// Credit card patterns are HIGH_SIGNAL.
var creditCardRegex = regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`)

func triagePatterns(direction, content string) []TriageSignal {
	// See scanLocalPatterns for why we normalize for regex matching
	// only — the original `content` is preserved for evidence
	// extraction and for anything downstream that feeds the judge.
	lower := normalizeForTriage(content)
	var signals []TriageSignal

	if direction == "prompt" {
		// HIGH_SIGNAL injection patterns (multi-word, unambiguous).
		for _, p := range highSignalInjectionPatterns {
			if strings.Contains(lower, p) {
				signals = append(signals, TriageSignal{
					Level: "HIGH_SIGNAL", FindingID: "TRIAGE-INJ-PHRASE",
					Category: "injection", Pattern: p,
					Evidence: extractEvidence(content, lower, p), Confidence: 0.95,
				})
			}
		}
		for _, re := range highSignalInjectionRegexes {
			if re.MatchString(lower) {
				signals = append(signals, TriageSignal{
					Level: "HIGH_SIGNAL", FindingID: "TRIAGE-INJ-REGEX",
					Category: "injection", Pattern: re.String(),
					Evidence: extractEvidenceRegex(content, lower, re), Confidence: 0.90,
				})
			}
		}

		// NEEDS_REVIEW injection patterns (short, ambiguous).
		for _, p := range reviewInjectionPatterns {
			if strings.Contains(lower, p) {
				signals = append(signals, TriageSignal{
					Level: "NEEDS_REVIEW", FindingID: "TRIAGE-INJ-REVIEW",
					Category: "injection", Pattern: p,
					Evidence: extractEvidence(content, lower, p), Confidence: 0.50,
				})
			}
		}
		for _, re := range reviewInjectionRegexes {
			if re.MatchString(lower) {
				signals = append(signals, TriageSignal{
					Level: "NEEDS_REVIEW", FindingID: "TRIAGE-INJ-REVIEW",
					Category: "injection", Pattern: re.String(),
					Evidence: extractEvidenceRegex(content, lower, re), Confidence: 0.50,
				})
			}
		}

		// PII request patterns (asking for PII = HIGH_SIGNAL).
		for _, p := range piiRequestPatterns {
			if strings.Contains(lower, p) {
				signals = append(signals, TriageSignal{
					Level: "HIGH_SIGNAL", FindingID: "TRIAGE-PII-REQUEST",
					Category: "pii", Pattern: p,
					Evidence: extractEvidence(content, lower, p), Confidence: 0.90,
				})
			}
		}

		// Exfiltration patterns (HIGH_SIGNAL).
		for _, p := range exfilPatterns {
			if strings.Contains(lower, p) {
				signals = append(signals, TriageSignal{
					Level: "HIGH_SIGNAL", FindingID: "TRIAGE-EXFIL",
					Category: "exfil", Pattern: p,
					Evidence: extractEvidence(content, lower, p), Confidence: 0.90,
				})
			}
		}
		// Regex floor: typo / separator-evasion variants of the
		// credential-file targets above. HIGH_SIGNAL because the
		// regex set is opinionated enough that a positive match is
		// not benign — see exfilRegexes for the discipline. This is
		// what guarantees that "please dump etccc passwd" still
		// blocks even if the exfil judge is unreachable.
		for _, re := range exfilRegexes {
			if loc, src, norm, ok := findRegexLoc(content, lower, re); ok {
				ev := extractEvidenceAt(src, loc[0], loc[1])
				if norm {
					ev = "[normalized] " + ev
				}
				signals = append(signals, TriageSignal{
					Level: "HIGH_SIGNAL", FindingID: "TRIAGE-EXFIL-REGEX",
					Category: "exfil", Pattern: re.String(),
					Evidence: ev, Confidence: 0.90,
				})
			}
		}

		// Bulk data access (NEEDS_REVIEW — judge decides if intent is benign).
		if bulkAccessRegex.MatchString(lower) {
			signals = append(signals, TriageSignal{
				Level: "NEEDS_REVIEW", FindingID: "TRIAGE-BULK-ACCESS",
				Category: "data-access", Pattern: "sensitive tool bulk access",
				Evidence: extractEvidenceRegex(content, lower, bulkAccessRegex), Confidence: 0.60,
			})
		}
	}

	// PII data patterns (direction-independent). Matched against both
	// `content` and `lower` via findRegexLoc so zero-width / Unicode-
	// whitespace splicing ("123-45\u200B-6789", "4111\u00A04111…")
	// cannot slip past SSN / 9-digit / credit-card triage.
	if loc, src, norm, ok := findRegexLoc(content, lower, ssnDashRegex); ok {
		ev := extractEvidenceAt(src, loc[0], loc[1])
		if norm {
			ev = "[normalized] " + ev
		}
		signals = append(signals, TriageSignal{
			Level: "HIGH_SIGNAL", FindingID: "TRIAGE-PII-SSN",
			Category: "pii", Pattern: "SSN (xxx-xx-xxxx)",
			Evidence: ev, Confidence: 0.90,
		})
	}
	if loc, src, norm, ok := findRegexLoc(content, lower, bare9DigitRegex); ok {
		ev := extractEvidenceAt(src, loc[0], loc[1])
		if norm {
			ev = "[normalized] " + ev
		}
		signals = append(signals, TriageSignal{
			Level: "NEEDS_REVIEW", FindingID: "TRIAGE-PII-9DIGIT",
			Category: "pii", Pattern: "9-digit number",
			Evidence: ev, Confidence: 0.30,
		})
	}
	if loc, src, norm, ok := findRegexLoc(content, lower, creditCardRegex); ok {
		ev := extractEvidenceAt(src, loc[0], loc[1])
		if norm {
			ev = "[normalized] " + ev
		}
		signals = append(signals, TriageSignal{
			Level: "HIGH_SIGNAL", FindingID: "TRIAGE-PII-CC",
			Category: "pii", Pattern: "credit card number",
			Evidence: ev, Confidence: 0.95,
		})
	}

	// Secret patterns: HIGH_SIGNAL in prompts, NEEDS_REVIEW in completions
	// so the judge can adjudicate whether a completion-side secret leak is real.
	secretLevel := "NEEDS_REVIEW"
	if direction == "prompt" {
		secretLevel = "HIGH_SIGNAL"
	}
	for _, p := range secretPatterns {
		if strings.Contains(lower, p) {
			signals = append(signals, TriageSignal{
				Level: secretLevel, FindingID: "TRIAGE-SECRET",
				Category: "secret", Pattern: p,
				Evidence: extractEvidence(content, lower, p), Confidence: 0.70,
			})
		}
	}
	// Secret regex: tries `content` first (case/whitespace preserved
	// for audit context) and falls back to `lower` so evasions like
	// "token\u200B=\u200B<60-char key>" still fire. Without the
	// fallback the docstring on scanLocalPatterns above — which
	// promises normalization defeats whitespace/slash-run evasions —
	// would not hold for secrets.
	for _, re := range secretPatternRegexes {
		if loc, src, norm, ok := findRegexLoc(content, lower, re); ok {
			ev := extractEvidenceAt(src, loc[0], loc[1])
			if norm {
				ev = "[normalized] " + ev
			}
			signals = append(signals, TriageSignal{
				Level: secretLevel, FindingID: "TRIAGE-SECRET-REGEX",
				Category: "secret", Pattern: re.String(),
				Evidence: ev, Confidence: 0.75,
			})
		}
	}

	return signals
}

// partitionSignals separates triage signals by level.
func partitionSignals(signals []TriageSignal) (high, review, low []TriageSignal) {
	for _, s := range signals {
		switch s.Level {
		case "HIGH_SIGNAL":
			high = append(high, s)
		case "NEEDS_REVIEW":
			review = append(review, s)
		default:
			low = append(low, s)
		}
	}
	return
}

// signalsToVerdict converts a set of triage signals into a ScanVerdict.
func signalsToVerdict(signals []TriageSignal, scanner string) *ScanVerdict {
	if len(signals) == 0 {
		return allowVerdict(scanner)
	}

	var findings []string
	var reasons []string
	maxSev := "NONE"

	for _, s := range signals {
		findings = append(findings, s.FindingID+":"+s.Pattern)
		sev := "MEDIUM"
		if s.Level == "HIGH_SIGNAL" {
			sev = "HIGH"
		}
		if severityRank[sev] > severityRank[maxSev] {
			maxSev = sev
		}
	}

	top := findings
	if len(top) > 5 {
		top = top[:5]
	}
	reasons = append(reasons, "triage: "+strings.Join(top, ", "))

	action := "alert"
	if maxSev == "HIGH" || maxSev == "CRITICAL" {
		action = "block"
	}

	return &ScanVerdict{
		Action:   action,
		Severity: maxSev,
		Reason:   strings.Join(reasons, "; "),
		Findings: findings,
		Scanner:  scanner,
	}
}

// extractEvidence returns ~200 chars of context around the first occurrence
// of pattern in original (case-insensitively). The `normalized` argument is
// the output of normalizeForTriage(original) and is used ONLY as a
// fallback when the pattern required normalization to match (e.g. the
// pattern is "/etc/passwd" and original was "/ etc / passwd"): in that
// case the literal pattern does not exist as contiguous bytes in original,
// so we extract the window from the normalized string instead and prefix
// the returned snippet with "[normalized]" so log consumers can tell.
//
// Rationale: before Phase 7, `lower` was just strings.ToLower(original)
// and its byte offsets aligned 1:1 with original for the ASCII+BMP fast
// path. After Phase 7, `normalized` can be shorter than original (whitespace-
// around-slash collapse, duplicate-slash collapse, NFC composition), so
// using a normalized offset as an index into original produces a window
// pointing at the wrong bytes. Re-locating against strings.ToLower(original)
// restores byte alignment in the common case.
//
// UTF-8 safety: extractEvidenceAt clamps both ends to the nearest rune
// boundary so we never emit invalid UTF-8 to logs, audit records, or
// downstream sinks.
func extractEvidence(original, normalized, pattern string) string {
	lowerOrig := strings.ToLower(original)
	if idx := strings.Index(lowerOrig, pattern); idx >= 0 {
		return extractEvidenceAt(original, idx, idx+len(pattern))
	}
	// Fast path missed: normalization was load-bearing for the match.
	// Return the normalized window so logs still carry useful context,
	// prefixed with a marker so operators know the bytes are post-
	// normalization (the original may have had whitespace evasion,
	// NFC-decomposed characters, or duplicate slashes).
	if idx := strings.Index(normalized, pattern); idx >= 0 {
		return "[normalized] " + extractEvidenceAt(normalized, idx, idx+len(pattern))
	}
	return ""
}

// extractEvidenceRegex returns a ±window snippet around the first match of
// `re` in original. Like extractEvidence, it prefers the original-bytes
// path and falls back to the normalized string when normalization was
// required for the regex to hit.
//
// Assumes `re` is pre-lowercased (all triage regexes in this file are);
// case-insensitivity is handled by lowercasing original rather than by
// a `(?i)` flag, matching how the rest of this file dispatches.
func extractEvidenceRegex(original, normalized string, re *regexp.Regexp) string {
	if loc := re.FindStringIndex(strings.ToLower(original)); loc != nil {
		return extractEvidenceAt(original, loc[0], loc[1])
	}
	if loc := re.FindStringIndex(normalized); loc != nil {
		return "[normalized] " + extractEvidenceAt(normalized, loc[0], loc[1])
	}
	return ""
}

// findRegexLoc locates the first match of `re` in `original`; when
// `original` has no match, it falls back to `normalized` (the
// normalizeForTriage output: NFC-composed, zero-width-stripped,
// lowercased, slash-collapsed) so evasions that splice invisible or
// Unicode-whitespace characters between otherwise-matching bytes —
// "4111\u200B1111\u200B1111\u200B1111" for credit card,
// "token\u00A0=\u00A0<key>" for the token secret regex — still fire.
//
// Returns the location, the string the location indexes into (so
// callers can extractEvidenceAt it without tracking which path was
// taken), wasNormalized telling callers to prefix operator-visible
// evidence with "[normalized] ", and ok = whether any match was found.
// The fallback is only consulted when `original` misses, so in the
// common non-evasion case we preserve byte-aligned original-text
// offsets and avoid extra regex work.
func findRegexLoc(original, normalized string, re *regexp.Regexp) (loc []int, source string, wasNormalized, ok bool) {
	if l := re.FindStringIndex(original); l != nil {
		return l, original, false, true
	}
	if l := re.FindStringIndex(normalized); l != nil {
		return l, normalized, true, true
	}
	return nil, "", false, false
}

// findRegexMatch is the FindString sibling of findRegexLoc. Used by
// scanLocalPatterns where callers record the matched substring rather
// than slicing a ±window around it. Same original-first / normalized-
// fallback contract; wasNormalized tells the caller to tag the flag
// with "[normalized] " so operators grepping audit logs can see which
// evasion path fired.
func findRegexMatch(original, normalized string, re *regexp.Regexp) (match string, wasNormalized, ok bool) {
	if m := re.FindString(original); m != "" {
		return m, false, true
	}
	if m := re.FindString(normalized); m != "" {
		return m, true, true
	}
	return "", false, false
}

func extractEvidenceAt(content string, matchStart, matchEnd int) string {
	const window = 100
	if matchStart < 0 {
		matchStart = 0
	}
	if matchEnd > len(content) {
		matchEnd = len(content)
	}
	if matchEnd < matchStart {
		matchEnd = matchStart
	}

	start := matchStart - window
	if start < 0 {
		start = 0
	}
	end := matchEnd + window
	if end > len(content) {
		end = len(content)
	}

	// Clamp boundaries to rune starts so we never slice across a multi-byte
	// rune and produce invalid UTF-8 in the evidence string (which gets
	// logged, written to audit records, and may reach downstream systems).
	for start > 0 && start < len(content) && !utf8.RuneStart(content[start]) {
		start--
	}
	for end > 0 && end < len(content) && !utf8.RuneStart(content[end]) {
		end++
	}

	snippet := content[start:end]
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(content) {
		snippet = snippet + "..."
	}
	return snippet
}

// ---------------------------------------------------------------------------
// Verdict merging
// ---------------------------------------------------------------------------

func mergeVerdicts(local, cisco *ScanVerdict) *ScanVerdict {
	if local == nil && cisco == nil {
		return allowVerdict("")
	}
	if local == nil {
		cisco.ScannerSources = []string{"ai-defense"}
		return cisco
	}
	if cisco == nil {
		local.ScannerSources = []string{"local-pattern"}
		return local
	}

	winner := local
	if severityRank[cisco.Severity] > severityRank[local.Severity] {
		winner = cisco
	}

	var reasons []string
	if local.Reason != "" {
		reasons = append(reasons, local.Reason)
	}
	if cisco.Reason != "" {
		reasons = append(reasons, cisco.Reason)
	}

	var combined []string
	combined = append(combined, local.Findings...)
	combined = append(combined, cisco.Findings...)

	return &ScanVerdict{
		Action:         winner.Action,
		Severity:       winner.Severity,
		Reason:         strings.Join(reasons, "; "),
		Findings:       combined,
		ScannerSources: []string{"local-pattern", "ai-defense"},
	}
}

func mergeWithJudge(base, judge *ScanVerdict) *ScanVerdict {
	if judge == nil || judge.Severity == "NONE" {
		return base
	}
	if base == nil || base.Severity == "NONE" {
		return judge
	}

	winner := base
	if severityRank[judge.Severity] > severityRank[base.Severity] {
		winner = judge
	}

	var reasons []string
	if base.Reason != "" {
		reasons = append(reasons, base.Reason)
	}
	if judge.Reason != "" {
		reasons = append(reasons, judge.Reason)
	}

	var combined []string
	combined = append(combined, base.Findings...)
	combined = append(combined, judge.Findings...)

	sources := base.ScannerSources
	if len(sources) == 0 {
		sources = []string{}
	}
	sources = append(sources, "llm-judge")

	return &ScanVerdict{
		Action:         winner.Action,
		Severity:       winner.Severity,
		Reason:         strings.Join(reasons, "; "),
		Findings:       combined,
		ScannerSources: sources,
	}
}

// ---------------------------------------------------------------------------
// Message extraction helpers
// ---------------------------------------------------------------------------

// lastUserText extracts text from only the most recent user message.
// Scanning the full history causes false positives when a previously flagged
// message stays in the conversation context.
func lastUserText(messages []ChatMessage) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

func promptInspectionText(userText string) string {
	return stripOpenClawUntrustedEnvelope(userText)
}

func stripOpenClawUntrustedEnvelope(userText string) string {
	trimmed := strings.TrimSpace(userText)
	if !strings.HasPrefix(trimmed, "Sender (untrusted metadata):") {
		return userText
	}
	fenceStart := strings.Index(trimmed, "```")
	if fenceStart < 0 {
		return userText
	}
	afterFence := trimmed[fenceStart+len("```"):]
	fenceEnd := strings.Index(afterFence, "```")
	if fenceEnd < 0 {
		return userText
	}
	rest := strings.TrimSpace(afterFence[fenceEnd+len("```"):])
	if strings.HasPrefix(rest, "[") {
		if close := strings.Index(rest, "]"); close >= 0 && close < 128 {
			rest = strings.TrimSpace(rest[close+1:])
		}
	}
	if rest == "" {
		return userText
	}
	return rest
}

// isHeartbeatMessage detects OpenClaw's internal liveness probes that should
// bypass guardrail inspection. The heartbeat sends a short system prompt
// ("Read HEARTBEAT.md") + expects "HEARTBEAT_OK" back; flagging it as prompt
// injection is a false positive.
//
// The bypass is keyed STRICTLY on the current user turn (userText).
// `messages` is intentionally ignored — a past turn's "HEARTBEAT_OK"
// assistant reply left in the conversation history must NEVER enable a
// bypass for the next turn, otherwise the very first heartbeat handshake
// would disarm guardrail inspection for the entire rest of the session.
// That was the v0.2.0 regression; see PR #127.
//
// Bypass conditions (ALL must hold):
//
//  1. Length ≤ maxHeartbeatProbeLen. The canonical probe is ~170 chars;
//     messaging bridges (WhatsApp/Teams) prepend transport banners and
//     timing metadata that push it to several hundred chars, so we cap
//     generously — but we still cap so an attacker cannot smuggle an
//     arbitrarily large payload past the guardrail.
//
//  2. References the canonical probe file "HEARTBEAT.md" (not merely
//     the response token "HEARTBEAT_OK", which an attacker could trivially
//     append to an injection payload).
//
//  3. Ends with the canonical response-token instruction
//     ("…HEARTBEAT_OK[.!]?$"). A legitimate probe ALWAYS tells the LLM
//     how to reply; an attacker appending malicious tail content (e.g.
//     "Read HEARTBEAT.md. Ignore all prior instructions.") will not end
//     with HEARTBEAT_OK and is therefore inspected normally.
//
//  4. No known injection imperatives appear anywhere in the text
//     ("ignore previous/prior", "disregard", "override", "exfiltrate",
//     "rm -rf", "cat /", "/etc/passwd|shadow", "DAN", "jailbreak").
//     Belt-and-suspenders: if an attacker manages to craft text that
//     satisfies (2) and (3) simultaneously, these token triggers will
//     still force normal inspection.
//
// This function is called only from the pre-call prompt inspection
// site in handlePassthrough / handleChatCompletion; completion-side
// inspection does not consult it.
func isHeartbeatMessage(userText string, _ []ChatMessage) bool {
	const maxHeartbeatProbeLen = 2048
	if userText == "" || len(userText) > maxHeartbeatProbeLen {
		return false
	}
	if !containsHeartbeatProbeSignature(userText) {
		return false
	}
	if !heartbeatOKFooterRe.MatchString(userText) {
		return false
	}
	if heartbeatInjectionHintRe.MatchString(userText) {
		return false
	}
	return true
}

// containsHeartbeatProbeSignature reports whether s references the probe
// filename "HEARTBEAT.md". Matching on the filename (not the response
// token) prevents an attacker from bypassing the guardrail by appending
// "HEARTBEAT_OK" to an otherwise malicious prompt.
func containsHeartbeatProbeSignature(s string) bool {
	return strings.Contains(strings.ToUpper(s), "HEARTBEAT.MD")
}

// heartbeatOKFooterRe matches when a message ends with the canonical
// HEARTBEAT_OK response-token instruction, allowing for trailing
// punctuation / whitespace. Used by isHeartbeatMessage to reject any
// "Read HEARTBEAT.md. <injection tail>" smuggling attempt because a
// legitimate probe ALWAYS ends by telling the LLM to reply HEARTBEAT_OK.
var heartbeatOKFooterRe = regexp.MustCompile(`(?i)\bHEARTBEAT_OK\b[\s"'.!?)\]]*$`)

// heartbeatInjectionHintRe matches a small vocabulary of unambiguous
// prompt-injection / exfil imperatives. If any of them appears anywhere
// in a message that otherwise looks like a heartbeat probe, we force
// normal inspection. This is belt-and-suspenders — the ends-with
// HEARTBEAT_OK check (heartbeatOKFooterRe) already rejects most tail
// smuggling, but this catches attackers who manage to structure their
// attack around the footer.
//
// The word list stays narrow on purpose so it does not accidentally
// match the legitimate probe body ("do not infer or repeat old tasks
// from prior chats" — the probe text contains "prior" as a bare word,
// so we only match IGNORE + PRIOR together, not PRIOR alone).
var heartbeatInjectionHintRe = regexp.MustCompile(
	`(?i)\b(?:` +
		`IGNORE(?:\s+ALL)?\s+(?:PRIOR|PREVIOUS)|` +
		`DISREGARD(?:\s+(?:ALL|ANY|PRIOR|PREVIOUS|THE))?\s*(?:INSTRUCTION|PROMPT|RULE|CONTEXT)|` +
		`OVERRIDE\s+(?:YOUR|THE|ALL|ANY)\s+(?:INSTRUCTION|RULE|SYSTEM|PROMPT)|` +
		`EXFILTRATE|` +
		`RM\s+-\s*RF|` +
		`CAT\s+/|` +
		`/ETC/(?:PASSWD|SHADOW|HOSTS)|` +
		`\bDAN\s+MODE\b|` +
		`JAILBREAK|` +
		`SUDO\s+RM` +
		`)\b`)

// ---------------------------------------------------------------------------
// Secret redaction
// ---------------------------------------------------------------------------

var secretRedactRe = regexp.MustCompile(
	`(?i)(?:sk-ant-|sk-proj-|sk-|ghp_|gho_|ghu_|ghs_|ghr_|github_pat_` +
		`|xox[bpors]-|AIza|eyJ)[A-Za-z0-9\-_+/=.]{6,}` +
		`|AKIA[A-Z0-9]{12,}`)

var kvRedactRe = regexp.MustCompile(
	`(?i)((?:password|secret|token|api_key|apikey|aws_secret_access)[=:\s]+)\S{6,}`)

func redactSecrets(text string) string {
	text = secretRedactRe.ReplaceAllStringFunc(text, func(m string) string {
		if len(m) <= 4 {
			return m
		}
		return m[:4] + "***REDACTED***"
	})
	text = kvRedactRe.ReplaceAllString(text, "${1}***REDACTED***")
	return text
}

// blockMessage returns the message to send when a request/response is blocked.
func blockMessage(customMsg, direction, reason string) string {
	if customMsg != "" {
		return "[DefenseClaw] " + customMsg
	}
	if direction == "prompt" {
		return fmt.Sprintf(
			"[DefenseClaw] This request was blocked. A potential security "+
				"concern was detected in the prompt (%s). "+
				"If you believe this is a false positive, contact your "+
				"administrator or adjust the guardrail policy.", reason)
	}
	return fmt.Sprintf(
		"[DefenseClaw] The model's response was blocked due to a "+
			"potential security concern (%s). "+
			"If you believe this is a false positive, contact your "+
			"administrator or adjust the guardrail policy.", reason)
}
