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
	Scanner        string   `json:"scanner,omitempty"`
	ScannerSources []string `json:"scanner_sources,omitempty"`
	CiscoElapsedMs float64  `json:"cisco_elapsed_ms,omitempty"`
}

func allowVerdict(scanner string) *ScanVerdict {
	return &ScanVerdict{
		Action:   "allow",
		Severity: "NONE",
		Scanner:  scanner,
	}
}

// GuardrailInspector orchestrates local pattern scanning, Cisco AI Defense,
// the LLM judge, and OPA policy evaluation.
type GuardrailInspector struct {
	scannerMode string
	ciscoClient *CiscoInspectClient
	judge       *LLMJudge
	policyDir   string
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

// SetScannerMode updates the scanner mode at runtime.
func (g *GuardrailInspector) SetScannerMode(mode string) {
	g.scannerMode = mode
}

// Inspect runs scanners according to scanner_mode and returns a merged verdict.
func (g *GuardrailInspector) Inspect(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	var localResult *ScanVerdict
	var ciscoResult *ScanVerdict
	var ciscoElapsedMs float64

	sm := g.scannerMode

	if sm == "local" || sm == "both" {
		localResult = scanLocalPatterns(direction, content)
	}

	// In "both" mode, skip remote if local already flags something.
	if sm == "both" && localResult != nil && localResult.Severity != "NONE" {
		localResult.ScannerSources = []string{"local-pattern"}
		return g.finalize(ctx, direction, model, mode, content, localResult, nil)
	}

	if (sm == "remote" || sm == "both") && g.ciscoClient != nil && len(messages) > 0 {
		t0 := time.Now()
		ciscoResult = g.ciscoClient.Inspect(messages)
		ciscoElapsedMs = float64(time.Since(t0).Milliseconds())
	}

	merged := mergeVerdicts(localResult, ciscoResult)
	merged.CiscoElapsedMs = ciscoElapsedMs

	// Run LLM judge if configured.
	if g.judge != nil {
		judgeVerdict := g.judge.RunJudges(ctx, direction, content)
		if judgeVerdict != nil && judgeVerdict.Severity != "NONE" {
			merged = mergeWithJudge(merged, judgeVerdict)
		}
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

// injectionRule pairs a compiled regexp with a short finding name.
// All rules fire only on direction=="prompt".
type injectionRule struct {
	re   *regexp.Regexp
	name string
}

// injectionRules uses context-aware regexps rather than bare substrings.
// A pattern must match both the injection verb AND its malicious target or
// explicit restriction-removal qualifier before firing. This eliminates
// false positives on normal operational phrasing ("act as a helpful
// assistant", "you are now connected", "bypass this error").
var injectionRules = []injectionRule{
	// Explicit instruction override — clearest injection signal.
	// Matches "ignore all instructions" (bare) and "ignore all previous instructions" (qualified).
	{
		regexp.MustCompile(`(?i)(?:ignore|disregard|forget|override)\s+(?:all\s+(?:previous\s+|prior\s+|above\s+|your\s+)?|(?:previous|prior|above|your)\s+)(?:instructions?|rules?|guidelines?|directives?|constraints?)`),
		"instruction-override",
	},
	// Role-play as a malicious entity (named role).
	{
		regexp.MustCompile(`(?i)(?:act\s+as|pretend\s+(?:you\s+are|to\s+be)|simulate|roleplay\s+as)\s+(?:a\s+|an\s+)?(?:hacker|attacker|malicious|uncensored|unfiltered|unrestricted|jailbroken|evil|dangerous)`),
		"malicious-role",
	},
	// Role-play combined with explicit restriction removal ("a system with no rules").
	{
		regexp.MustCompile(`(?i)(?:act\s+as|pretend\s+(?:you\s+are|to\s+be)|you\s+are(?:\s+now)?|roleplay).{0,50}?(?:no|without)\s+(?:any\s+)?(?:rules|restrictions|constraints|limits|guidelines|filters)`),
		"no-restrictions-roleplay",
	},
	// "You are now" + explicit restriction-removal qualifier.
	{
		regexp.MustCompile(`(?i)you\s+are\s+now\s+(?:a\s+|an\s+)?(?:jailbroken|unrestricted|uncensored|unfiltered|dangerous|malicious|evil|hacked|different\s+ai|new\s+ai)`),
		"you-are-now-unrestricted",
	},
	// Jailbreak vocabulary.
	{regexp.MustCompile(`(?i)\bjailbreak\b`), "jailbreak"},
	{regexp.MustCompile(`(?i)\bdan\s+mode\b`), "dan-mode"},
	{regexp.MustCompile(`(?i)\bdo\s+anything\s+now\b`), "do-anything-now"},
	// Prompt injection meta-vocabulary.
	{regexp.MustCompile(`(?i)prompt\s+(?:injection|hacking|hijack)`), "prompt-injection-meta"},
	{regexp.MustCompile(`(?i)hidden\s+instruction`), "hidden-instruction"},
	{regexp.MustCompile(`(?i)system\s+prompt\s+(?:override|bypass|leak|extract)`), "system-prompt-attack"},
}

// secretPatterns matches credentials that are structurally identifiable —
// patterns that require a specific prefix or key material format.
// "token:" and "bearer " are omitted: without an accompanying value they
// match routine CLI metadata and auth discussion, causing false positives.
var secretPatterns = []string{
	"sk-ant-", "sk-proj-", "sk-live_", "api_key=", "apikey=",
	"-----begin rsa", "-----begin private", "-----begin openssh",
	"aws_access_key", "aws_secret_access", "password=",
	"ghp_", "gho_", "github_pat_",
}

var exfilPatterns = []string{
	"/etc/passwd", "/etc/shadow", "base64 -d", "base64 --decode",
	"exfiltrate", "send to my server", "curl http",
}

func scanLocalPatterns(direction, content string) *ScanVerdict {
	lower := strings.ToLower(content)
	var flags []string
	severity := "MEDIUM" // secrets default; injection/exfil upgrade to HIGH

	if direction == "prompt" {
		for _, rule := range injectionRules {
			if rule.re.MatchString(lower) {
				flags = append(flags, rule.name)
				severity = "HIGH"
			}
		}
		for _, p := range exfilPatterns {
			if strings.Contains(lower, p) {
				flags = append(flags, p)
				severity = "HIGH"
			}
		}
	}
	for _, p := range secretPatterns {
		if strings.Contains(lower, p) {
			flags = append(flags, p)
		}
	}

	if len(flags) == 0 {
		return allowVerdict("local-pattern")
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
		return customMsg
	}
	if direction == "prompt" {
		return fmt.Sprintf(
			"I'm unable to process this request. DefenseClaw detected a "+
				"potential security concern in the prompt (%s). "+
				"If you believe this is a false positive, contact your "+
				"administrator or adjust the guardrail policy.", reason)
	}
	return fmt.Sprintf(
		"The model's response was blocked by DefenseClaw due to a "+
			"potential security concern (%s). "+
			"If you believe this is a false positive, contact your "+
			"administrator or adjust the guardrail policy.", reason)
}
