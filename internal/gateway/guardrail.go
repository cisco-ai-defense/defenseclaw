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
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

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
	Level      string  // "HIGH_SIGNAL", "NEEDS_REVIEW", "LOW_SIGNAL"
	FindingID  string
	Category   string  // "injection", "pii", "secret", "exfil"
	Pattern    string  // what matched
	Evidence   string  // ~200-char context window around match
	Confidence float64
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

	switch strategy {
	case "regex_judge":
		return g.inspectRegexJudge(ctx, direction, content, messages, model, mode)
	case "judge_first":
		return g.inspectJudgeFirst(ctx, direction, content, messages, model, mode)
	default:
		return g.inspectRegexOnly(ctx, direction, content, messages, model, mode)
	}
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

	localResult = scanLocalPatterns(direction, content)

	if sm == "local" || (localResult != nil && localResult.Severity == "HIGH") {
		if localResult != nil {
			localResult.ScannerSources = []string{"local-pattern"}
		}
		return g.finalize(ctx, direction, model, mode, content, localResult, nil)
	}

	if (sm == "remote" || sm == "both") && g.ciscoClient != nil && len(messages) > 0 {
		t0 := time.Now()
		ciscoResult = g.ciscoClient.Inspect(messages)
		ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
	}

	merged := mergeVerdicts(localResult, ciscoResult)
	merged.CiscoElapsedMs = ciscoElapsedMs

	if g.judge != nil {
		judgeVerdict := g.judge.RunJudges(ctx, direction, content)
		if judgeVerdict != nil && judgeVerdict.Severity != "NONE" {
			merged = mergeWithJudge(merged, judgeVerdict)
		}
	}

	return g.finalize(ctx, direction, model, mode, content, merged, ciscoResult)
}

// inspectRegexJudge uses triage patterns to route ambiguous findings to the
// LLM judge, while running the full rule engine (ScanAllRules) as a safety net
// for patterns triage doesn't cover (sensitive paths, commands, C2, etc.).
func (g *GuardrailInspector) inspectRegexJudge(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
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

	var ciscoResult *ScanVerdict
	var ciscoElapsedMs float64

	// HIGH_SIGNAL triage findings produce an immediate verdict.
	if len(high) > 0 {
		verdict := signalsToVerdict(high, "local-triage")
		verdict.ScannerSources = []string{"local-triage"}
		if ruleVerdict != nil {
			verdict = mergeVerdicts(verdict, ruleVerdict)
		}

		if (g.scannerMode == "remote" || g.scannerMode == "both") && g.ciscoClient != nil && len(messages) > 0 {
			t0 := time.Now()
			ciscoResult = g.ciscoClient.Inspect(messages)
			ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
			verdict = mergeVerdicts(verdict, ciscoResult)
			verdict.CiscoElapsedMs = ciscoElapsedMs
		}
		return g.finalize(ctx, direction, model, mode, content, verdict, ciscoResult)
	}

	// If the rule engine found HIGH+ severity, block immediately (covers
	// sensitive paths, dangerous commands, C2, etc. that triage doesn't have).
	if ruleVerdict != nil && severityRank[ruleVerdict.Severity] >= severityRank["HIGH"] {
		if (g.scannerMode == "remote" || g.scannerMode == "both") && g.ciscoClient != nil && len(messages) > 0 {
			t0 := time.Now()
			ciscoResult = g.ciscoClient.Inspect(messages)
			ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
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
			judgeVerdict = g.judge.AdjudicateFindings(ctx, direction, content, review)
		}
		if judgeVerdict == nil || judgeVerdict.JudgeFailed {
			judgeVerdict = signalsToVerdict(review, "local-triage-fallback")
			judgeVerdict.Severity = "MEDIUM"
			judgeVerdict.Action = "alert"
		}
	}

	// NO_SIGNAL + judge_sweep: run full classification.
	if len(signals) == 0 && g.judgeSweep && g.judge != nil {
		judgeVerdict = g.judge.RunJudges(ctx, direction, content)
	}

	// Cisco AI Defense (if configured).
	if (g.scannerMode == "remote" || g.scannerMode == "both") && g.ciscoClient != nil && len(messages) > 0 {
		t0 := time.Now()
		ciscoResult = g.ciscoClient.Inspect(messages)
		ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
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
	if g.judge != nil {
		go func() {
			v := g.judge.RunJudges(ctx, direction, content)
			judgeCh <- result{verdict: v}
		}()
	} else {
		judgeCh <- result{verdict: nil, err: true}
	}

	go func() {
		triageCh <- triagePatterns(direction, content)
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
		localResult := scanLocalPatterns(direction, content)
		if localResult != nil {
			localResult.ScannerSources = []string{"local-pattern", "judge-fallback"}
		}
		return g.finalize(ctx, direction, model, mode, content, localResult, nil)
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
		ciscoResult = g.ciscoClient.Inspect(messages)
		ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
		merged = mergeVerdicts(merged, ciscoResult)
		merged.CiscoElapsedMs = ciscoElapsedMs
	}

	return g.finalize(ctx, direction, model, mode, content, merged, ciscoResult)
}

// finalize runs OPA policy evaluation if available, otherwise returns the
// merged verdict directly.
func (g *GuardrailInspector) finalize(ctx context.Context, direction, model, mode, content string, merged *ScanVerdict, ciscoResult *ScanVerdict) *ScanVerdict {
	if g.policyDir == "" {
		return merged
	}

	engine, err := policy.New(g.policyDir)
	if err != nil {
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

	out, err := engine.EvaluateGuardrail(ctx, input)
	if err != nil || out == nil {
		return merged
	}

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
// substrings. "token:" alone matches any YAML key; the regex requires an
// assignment with a value of 8+ non-whitespace characters.
var secretPatternRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\btoken\s*[:=]\s*["']?\S{8,}`),
}

var exfilPatterns = []string{
	"/etc/passwd", "/etc/shadow", "base64 -d", "base64 --decode",
	"exfiltrate", "exfil", "send to my server", "curl http",
}

func scanLocalPatterns(direction, content string) *ScanVerdict {
	lower := strings.ToLower(content)
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
	}

	for _, re := range piiDataRegexes {
		if re.MatchString(content) {
			flags = append(flags, "pii-data:"+re.FindString(content))
			isHigh = true
		}
	}

	for _, p := range secretPatterns {
		if strings.Contains(lower, p) {
			flags = append(flags, p)
		}
	}
	for _, re := range secretPatternRegexes {
		if re.MatchString(content) {
			flags = append(flags, re.FindString(content))
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
	lower := strings.ToLower(content)
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
			if loc := re.FindStringIndex(lower); loc != nil {
				signals = append(signals, TriageSignal{
					Level: "HIGH_SIGNAL", FindingID: "TRIAGE-INJ-REGEX",
					Category: "injection", Pattern: re.String(),
					Evidence: extractEvidenceAt(content, loc[0], loc[1]), Confidence: 0.90,
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
			if loc := re.FindStringIndex(lower); loc != nil {
				signals = append(signals, TriageSignal{
					Level: "NEEDS_REVIEW", FindingID: "TRIAGE-INJ-REVIEW",
					Category: "injection", Pattern: re.String(),
					Evidence: extractEvidenceAt(content, loc[0], loc[1]), Confidence: 0.50,
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
	}

	// PII data patterns (direction-independent).
	if loc := ssnDashRegex.FindStringIndex(content); loc != nil {
		signals = append(signals, TriageSignal{
			Level: "HIGH_SIGNAL", FindingID: "TRIAGE-PII-SSN",
			Category: "pii", Pattern: "SSN (xxx-xx-xxxx)",
			Evidence: extractEvidenceAt(content, loc[0], loc[1]), Confidence: 0.90,
		})
	}
	if loc := bare9DigitRegex.FindStringIndex(content); loc != nil {
		signals = append(signals, TriageSignal{
			Level: "NEEDS_REVIEW", FindingID: "TRIAGE-PII-9DIGIT",
			Category: "pii", Pattern: "9-digit number",
			Evidence: extractEvidenceAt(content, loc[0], loc[1]), Confidence: 0.30,
		})
	}
	if loc := creditCardRegex.FindStringIndex(content); loc != nil {
		signals = append(signals, TriageSignal{
			Level: "HIGH_SIGNAL", FindingID: "TRIAGE-PII-CC",
			Category: "pii", Pattern: "credit card number",
			Evidence: extractEvidenceAt(content, loc[0], loc[1]), Confidence: 0.95,
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
	for _, re := range secretPatternRegexes {
		if loc := re.FindStringIndex(content); loc != nil {
			signals = append(signals, TriageSignal{
				Level: secretLevel, FindingID: "TRIAGE-SECRET-REGEX",
				Category: "secret", Pattern: re.String(),
				Evidence: extractEvidenceAt(content, loc[0], loc[1]), Confidence: 0.75,
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
// of pattern in the lowercase content, but returns the original-case text.
func extractEvidence(original, lower, pattern string) string {
	idx := strings.Index(lower, pattern)
	if idx < 0 {
		return ""
	}
	return extractEvidenceAt(original, idx, idx+len(pattern))
}

func extractEvidenceAt(content string, matchStart, matchEnd int) string {
	const window = 100
	start := matchStart - window
	if start < 0 {
		start = 0
	}
	end := matchEnd + window
	if end > len(content) {
		end = len(content)
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
