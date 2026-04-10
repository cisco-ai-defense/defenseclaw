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
// Local pattern scanning always runs as a baseline, regardless of scanner_mode,
// to ensure prompt injection and PII patterns are caught even when the remote
// scanner returns safe or is unreachable.
func (g *GuardrailInspector) Inspect(ctx context.Context, direction, content string, messages []ChatMessage, model, mode string) *ScanVerdict {
	var localResult *ScanVerdict
	var ciscoResult *ScanVerdict
	var ciscoElapsedMs float64

	sm := g.scannerMode

	localResult = scanLocalPatterns(direction, content)

	// In local-only mode or if local already flagged HIGH+, skip the remote call.
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
	"token:", "bearer ", "ghp_", "gho_", "github_pat_",
}

var exfilPatterns = []string{
	"/etc/passwd", "/etc/shadow", "base64 -d", "base64 --decode",
	"exfiltrate", "send to my server", "curl http",
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

	if len(flags) == 0 {
		return allowVerdict("local-pattern")
	}

	severity := "MEDIUM"
	if isHigh {
		severity = "HIGH"
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
