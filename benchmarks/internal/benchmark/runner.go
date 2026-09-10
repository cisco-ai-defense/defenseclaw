// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type Runner struct {
	RepoRoot     string
	PolicyRoot   string
	DataDir      string
	RunID        string
	Profiles     []string
	SkillBinary  string
	PluginBinary string
	MCPBinary    string
	// MCPYARARulesDir selects a benchmark-owned YARA pack. MCP Scanner treats
	// this directory as a replacement for its bundled rules, so callers should
	// benchmark custom and upstream packs as separate, attributable lanes.
	MCPYARARulesDir string
	Timeout         time.Duration
	// EvaluateOutOfScope emits detector diagnostics for candidate corpora while
	// keeping Applicable=false so those rows never enter publication scores.
	EvaluateOutOfScope bool
}

func (r Runner) Run(ctx context.Context, cases []Case) ([]Prediction, map[string]string, error) {
	if r.RepoRoot == "" {
		return nil, nil, fmt.Errorf("repo root is required")
	}
	if r.RunID == "" {
		return nil, nil, fmt.Errorf("run ID is required")
	}
	if len(r.Profiles) == 0 {
		r.Profiles = []string{"default"}
	}
	if r.Timeout <= 0 {
		r.Timeout = 30 * time.Second
	}
	for _, profile := range r.Profiles {
		if err := ValidateProfile(profile); err != nil {
			return nil, nil, err
		}
	}

	embedded, err := guardrail.LoadRulePack("")
	if err != nil {
		return nil, nil, fmt.Errorf("load embedded rule pack: %w", err)
	}
	defer func() {
		_ = gateway.ApplyRulePackOverrides(embedded)
		_ = gateway.ApplyLocalPatternsOverride(embedded.LocalPatterns)
	}()

	var predictions []Prediction
	policyDigests := make(map[string]string, len(r.Profiles))
	for _, profile := range r.Profiles {
		profileDir := filepath.Join(r.policyRoot(), profile)
		pack, err := guardrail.LoadRulePack(profileDir)
		if err != nil {
			return nil, nil, fmt.Errorf("load %s profile: %w", profile, err)
		}
		if err := gateway.ApplyRulePackOverrides(pack); err != nil {
			return nil, nil, fmt.Errorf("activate %s profile rules: %w", profile, err)
		}
		if err := gateway.ApplyLocalPatternsOverride(pack.LocalPatterns); err != nil {
			return nil, nil, fmt.Errorf("activate %s local patterns: %w", profile, err)
		}
		connector := "benchmark-" + profile
		if err := gateway.ApplyConnectorRulePackOverrides(connector, pack); err != nil {
			return nil, nil, fmt.Errorf("activate %s connector rules: %w", profile, err)
		}
		policyDigests[profile] = pack.Summary().Digest
		allowedRuleIDs := make(map[string]struct{})
		for _, ruleFile := range pack.RuleFiles {
			for _, definition := range ruleFile.Rules {
				allowedRuleIDs[definition.ID] = struct{}{}
			}
		}
		textInspector := gateway.NewGuardrailInspector("local", nil, nil, "")
		textInspector.SetDetectionStrategy("regex_only", "", "", "", false)
		textInspector.SetFallbackProfile(profile)

		for _, benchmarkCase := range cases {
			// Code and external artifact scanners own separate policies. Until a
			// profile-specific scanner policy is selected by an adapter, run their
			// public detector result exactly once instead of tripling the sample.
			if profile != "default" && benchmarkCase.Surface != "text" && benchmarkCase.Surface != "action" && benchmarkCase.Surface != "stateful" && benchmarkCase.Surface != "e2e" {
				continue
			}
			prediction := r.runCase(ctx, profile, connector, textInspector, allowedRuleIDs, benchmarkCase)
			predictions = append(predictions, prediction)
		}
		gateway.RemoveConnectorRulePackOverrides(connector)
	}
	return predictions, policyDigests, nil
}

func (r Runner) runCase(
	ctx context.Context,
	profile, connector string,
	textInspector *gateway.GuardrailInspector,
	allowedRuleIDs map[string]struct{},
	benchmarkCase Case,
) Prediction {
	prediction := Prediction{
		SchemaVersion: SchemaVersion,
		RunID:         r.RunID,
		CaseID:        benchmarkCase.ID,
		Profile:       profile,
		Applicable:    benchmarkCase.Truth.Applicability == InScope,
		Action:        "not_applicable",
		Severity:      "NONE",
		Route:         "none",
	}
	if !prediction.Applicable && !r.EvaluateOutOfScope {
		prediction.Engine = engineForSurface(benchmarkCase.Surface)
		return prediction
	}

	caseCtx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	start := time.Now()
	switch benchmarkCase.Surface {
	case "text":
		prediction = r.runText(caseCtx, textInspector, allowedRuleIDs, benchmarkCase, prediction)
	case "action":
		prediction = r.runAction(caseCtx, profile, connector, benchmarkCase, prediction)
	case "code":
		prediction = r.runCode(caseCtx, benchmarkCase, prediction)
	case "skill", "plugin", "mcp":
		prediction = r.runArtifact(caseCtx, profile, benchmarkCase, prediction)
	case "stateful":
		prediction = r.runStateful(caseCtx, profile, connector, benchmarkCase, prediction)
	case "e2e":
		prediction = r.runE2E(caseCtx, profile, connector, benchmarkCase, prediction)
	default:
		prediction.Engine = engineForSurface(benchmarkCase.Surface)
		prediction.Action = "error"
		prediction.ErrorCode = "unsupported_surface"
	}
	prediction.DurationMicros = time.Since(start).Microseconds()
	if prediction.DurationMicros < 0 {
		prediction.DurationMicros = 0
	}
	sort.Strings(prediction.RuleIDs)
	prediction.RuleIDs = compactStrings(prediction.RuleIDs)
	sort.Strings(prediction.IssueCodes)
	prediction.IssueCodes = compactStrings(prediction.IssueCodes)
	prediction = applyConservativeAlertProjection(prediction)
	return prediction
}

func (r Runner) runStateful(ctx context.Context, profile, connector string, benchmarkCase Case, prediction Prediction) Prediction {
	prediction.Engine = "gateway-tool-chain"
	baseTime := time.Unix(1700000000, 0).UTC()
	prior := make([]guardrail.ToolChainWindowEvent, 0, len(benchmarkCase.Payload.Events))
	var detectedMask, enforcementMask uint32
	allAuthoritative := true
	routes := make(map[string]struct{})
	for index, event := range benchmarkCase.Payload.Events {
		input := actionfacts.Input{
			Tool:             firstNonEmpty(event.ToolName, "shell"),
			Args:             benchmarkRuntimeArgs(event.Args, event.Command != "" || len(event.Argv) != 0),
			Command:          event.Command,
			Argv:             append([]string(nil), event.Argv...),
			CWD:              firstNonEmpty(event.CWD, "/repo"),
			ActiveHome:       firstNonEmpty(event.ActiveHome, "/home/alice"),
			ActiveAgentFiles: append([]string(nil), event.ActiveAgentFiles...),
			DialectHint:      benchmarkDialect(event.Dialect),
		}
		result := gateway.EvaluateDeterministicAction(ctx, input, firstNonEmpty(event.Command, string(event.Args)), connector, profile)
		prediction.IssueCodes = append(prediction.IssueCodes, result.IssueCodes...)
		prediction.EvaluationStatus = mergeEvaluationStatus(prediction.EvaluationStatus, result.CELEvaluationStatus)
		allAuthoritative = allAuthoritative && result.Authoritative
		if result.Route != "" && result.Route != "none" {
			routes[result.Route] = struct{}{}
		}
		windowEvent := guardrail.ToolChainWindowEvent{
			SemanticEventID: fmt.Sprintf("%s/%d", benchmarkCase.ID, index+1),
			Sequence:        uint64(index + 1),
			ReceivedAt:      baseTime.Add(time.Duration(event.OffsetSeconds) * time.Second),
			Projection: guardrail.ToolChainProjection{
				ParseStatus:                  actionfacts.ParseStatus(result.ParseStatus),
				DetectionStepMask:            result.DetectionStepMask,
				EnforcementStepMask:          result.EnforcementStepMask,
				EnforcementJoinDigests:       result.EnforcementJoinDigests,
				EnforcementOutputJoinDigests: result.EnforcementOutputJoinDigests,
			},
		}
		if event.Outcome != "" && event.Outcome != "succeeded" {
			// A failed, denied, cancelled, or unresolved action cannot become a
			// successful predecessor or sink in a deterministic sequence proof.
			windowEvent.Projection.DetectionStepMask = 0
			windowEvent.Projection.EnforcementStepMask = 0
			windowEvent.Projection.EnforcementJoinDigests = [guardrail.ToolChainCount]string{}
			windowEvent.Projection.EnforcementOutputJoinDigests = [guardrail.ToolChainCount]string{}
		}
		if index > 0 {
			matches, err := guardrail.MatchToolChains(prior, windowEvent)
			if err != nil {
				prediction.Action = "error"
				prediction.ErrorCode = "chain_match_failure"
				return prediction
			}
			detectedMask |= matches.DetectedMask
			enforcementMask |= matches.EnforcementSafeMask
		}
		prior = append(prior, windowEvent)
	}
	ids, err := guardrail.ToolChainIDs(detectedMask)
	if err != nil {
		prediction.Action = "error"
		prediction.ErrorCode = "chain_id_failure"
		return prediction
	}
	prediction.RuleIDs = append(prediction.RuleIDs, ids...)
	prediction.FindingCount = len(ids)
	prediction.Detected = detectedMask != 0
	prediction.Alerted = prediction.Detected
	prediction.AlertFindingCount = len(ids)
	prediction.DetectOnlyFindingCount = len(ids)
	prediction.Authoritative = allAuthoritative
	prediction.EnforcementEligible = enforcementMask != 0
	prediction.Action = "allow"
	prediction.Severity = "NONE"
	if prediction.Detected {
		prediction.Severity = gateway.DeterministicToolChainSeverity(ids)
		prediction.Action = "alert"
	}
	if enforcementMask != 0 {
		enforcementIDs, idErr := guardrail.ToolChainIDs(enforcementMask)
		if idErr != nil {
			prediction.Action = "error"
			prediction.ErrorCode = "chain_id_failure"
			return prediction
		}
		prediction.EnforceableFindingCount = len(enforcementIDs)
		prediction.DetectOnlyFindingCount -= len(enforcementIDs)
		prediction.Action = normalizeAction(gateway.ActionForDeterministicSeverity(
			gateway.DeterministicToolChainSeverity(enforcementIDs), profile,
		))
	}
	switch len(routes) {
	case 0:
		prediction.Route = "none"
	case 1:
		for route := range routes {
			prediction.Route = route
		}
	default:
		prediction.Route = "mixed"
	}
	return prediction
}

func (r Runner) runE2E(ctx context.Context, profile, connector string, benchmarkCase Case, prediction Prediction) Prediction {
	prediction.Engine = "gateway-http-inspect"
	profileDir := filepath.Join(r.policyRoot(), profile)
	result, err := gateway.EvaluateDeterministicHTTPMessage(
		ctx,
		benchmarkCase.Payload.Content,
		benchmarkCase.Payload.Direction,
		connector,
		profileDir,
	)
	if err != nil {
		prediction.Action = "error"
		prediction.ErrorCode = "http_inspect_failure"
		return prediction
	}
	prediction.Detected = result.Detected
	prediction.Action = normalizeAction(result.Action)
	prediction.Severity = normalizeSeverity(result.Severity)
	prediction.RuleIDs = append(prediction.RuleIDs, result.RuleIDs...)
	prediction.FindingCount = result.FindingCount
	return applyConservativeAlertProjection(prediction)
}

func (r Runner) policyRoot() string {
	if r.PolicyRoot == "" {
		return filepath.Join(r.RepoRoot, "policies", "guardrail")
	}
	if filepath.IsAbs(r.PolicyRoot) {
		return filepath.Clean(r.PolicyRoot)
	}
	return filepath.Join(r.RepoRoot, r.PolicyRoot)
}

func (r Runner) runText(
	ctx context.Context,
	inspector *gateway.GuardrailInspector,
	allowedRuleIDs map[string]struct{},
	benchmarkCase Case,
	prediction Prediction,
) Prediction {
	prediction.Engine = "gateway-local-text"
	verdict := inspector.Inspect(
		ctx,
		benchmarkCase.Payload.Direction,
		benchmarkCase.Payload.Content,
		nil,
		"benchmark-local",
		"observe",
	)
	if verdict == nil {
		prediction.Action = "error"
		prediction.ErrorCode = "nil_verdict"
		return prediction
	}
	prediction.Detected = verdict.Severity != "" && verdict.Severity != "NONE"
	prediction.Action = normalizeAction(verdict.Action)
	prediction.Severity = normalizeSeverity(verdict.Severity)
	for _, ruleID := range verdict.RuleIDs {
		if _, allowed := allowedRuleIDs[ruleID]; allowed {
			prediction.RuleIDs = append(prediction.RuleIDs, ruleID)
		}
	}
	prediction.RuleIDs = append(prediction.RuleIDs, ruleIDsFromFindingStrings(verdict.Findings, allowedRuleIDs)...)
	prediction.FindingCount = len(verdict.Findings)
	for _, span := range gateway.EvaluateDeterministicTextSpans(benchmarkCase.Payload.Content) {
		prediction.Spans = append(prediction.Spans, Span{
			Start: span.Start, End: span.End, Label: "pii", RuleID: span.RuleID,
		})
		prediction.RuleIDs = append(prediction.RuleIDs, span.RuleID)
	}
	return applyConservativeAlertProjection(prediction)
}

func (r Runner) runAction(ctx context.Context, profile, connector string, benchmarkCase Case, prediction Prediction) Prediction {
	prediction.Engine = "gateway-trusted-action"
	input := actionfacts.Input{
		Tool:             firstNonEmpty(benchmarkCase.Payload.ToolName, "shell"),
		Args:             benchmarkRuntimeArgs(benchmarkCase.Payload.Args, benchmarkCase.Payload.Command != "" || len(benchmarkCase.Payload.Argv) != 0),
		Command:          benchmarkCase.Payload.Command,
		Argv:             append([]string(nil), benchmarkCase.Payload.Argv...),
		CWD:              firstNonEmpty(benchmarkCase.Payload.CWD, "/repo"),
		ActiveHome:       firstNonEmpty(benchmarkCase.Payload.ActiveHome, "/home/alice"),
		ActiveAgentFiles: append([]string(nil), benchmarkCase.Payload.ActiveAgentFiles...),
		DialectHint:      benchmarkDialect(benchmarkCase.Payload.Dialect),
	}
	result := gateway.EvaluateDeterministicAction(
		ctx,
		input,
		firstNonEmpty(benchmarkCase.Payload.Command, string(benchmarkCase.Payload.Args)),
		connector,
		profile,
	)
	prediction.Detected = len(result.Findings) > 0
	prediction.Action = normalizeAction(result.Action)
	prediction.Severity = normalizeSeverity(result.Severity)
	prediction.Route = result.Route
	prediction.ParseStatus = result.ParseStatus
	prediction.EvaluationStatus = result.CELEvaluationStatus
	prediction.Authoritative = result.Authoritative
	prediction.EnforcementEligible = result.EnforcementEligible
	prediction.DetectionStepMask = result.DetectionStepMask
	prediction.EnforcementStepMask = result.EnforcementStepMask
	prediction.IssueCodes = append(prediction.IssueCodes, result.IssueCodes...)
	prediction.RuleIDs = append(prediction.RuleIDs, result.RuleIDs...)
	prediction.FindingCount = len(result.Findings)
	if err := applyActionFindingDispositions(&prediction, result.Findings); err != nil {
		prediction.Action = "error"
		prediction.ErrorCode = "unsupported_finding_disposition"
	}
	return applyConservativeAlertProjection(prediction)
}

func applyActionFindingDispositions(
	prediction *Prediction,
	findings []gateway.DeterministicActionFinding,
) error {
	var audit, advisory, detectOnly, enforceable int
	for _, finding := range findings {
		switch strings.ToLower(strings.TrimSpace(finding.Disposition)) {
		case "audit":
			audit++
		case "advisory":
			advisory++
		case "detect_only":
			detectOnly++
		case "enforceable":
			enforceable++
		default:
			return fmt.Errorf("unsupported finding disposition %q", finding.Disposition)
		}
	}
	prediction.AuditFindingCount = audit
	prediction.AdvisoryFindingCount = advisory
	prediction.DetectOnlyFindingCount = detectOnly
	prediction.EnforceableFindingCount = enforceable
	prediction.AlertFindingCount = advisory + detectOnly + enforceable
	prediction.Alerted = prediction.AlertFindingCount > 0
	return nil
}

// applyConservativeAlertProjection preserves legacy behavior for surfaces
// whose engines do not expose per-finding dispositions. Those findings remain
// user-visible alerts rather than being silently reclassified as audit-only.
func applyConservativeAlertProjection(prediction Prediction) Prediction {
	classified := prediction.AuditFindingCount + prediction.AdvisoryFindingCount +
		prediction.DetectOnlyFindingCount + prediction.EnforceableFindingCount
	if prediction.FindingCount > 0 && classified == 0 {
		prediction.DetectOnlyFindingCount = prediction.FindingCount
		prediction.AlertFindingCount = prediction.FindingCount
		prediction.Alerted = prediction.Detected
	}
	return prediction
}

func benchmarkRuntimeArgs(raw json.RawMessage, hasExplicitCommand bool) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return append(json.RawMessage(nil), raw...)
	}
	if _, annotated := object["_actionfacts"]; !annotated {
		return append(json.RawMessage(nil), raw...)
	}
	if hasExplicitCommand {
		return nil
	}
	// _actionfacts is a synthetic expectation envelope, not connector input.
	// Remove only that annotation and retain ordinary sibling fields: those are
	// the fixture's real tool arguments and must pass through the same closed
	// ActionFacts schemas as production input.
	delete(object, "_actionfacts")
	if len(object) == 0 {
		return nil
	}
	clean, err := json.Marshal(object)
	if err != nil {
		return nil
	}
	return clean
}

func mergeEvaluationStatus(current, next string) string {
	if current == "" || current == next {
		return next
	}
	return "mixed"
}

func (r Runner) runCode(ctx context.Context, benchmarkCase Case, prediction Prediction) Prediction {
	prediction.Engine = "code-scan-local"
	target, cleanup, err := r.materializeTarget(benchmarkCase)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		prediction.Action = "error"
		prediction.ErrorCode = "invalid_target"
		return prediction
	}
	result, err := scanner.ScanCode(ctx, target, "")
	if err != nil {
		prediction.Action = "error"
		prediction.ErrorCode = "scanner_failure"
		return prediction
	}
	return predictionFromScanResult(prediction, result, false, "default")
}

func (r Runner) runArtifact(ctx context.Context, profile string, benchmarkCase Case, prediction Prediction) Prediction {
	target, cleanup, err := r.materializeTarget(benchmarkCase)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		prediction.Engine = engineForSurface(benchmarkCase.Surface)
		prediction.Action = "error"
		prediction.ErrorCode = "invalid_target"
		return prediction
	}
	var implementation scanner.Scanner
	switch benchmarkCase.Surface {
	case "skill":
		prediction.Engine = "skill-scanner-static"
		implementation = scanner.NewSkillScannerFromLLM(
			config.SkillScannerConfig{Binary: r.SkillBinary, UseLLM: false, UseBehavioral: false},
			config.LLMConfig{},
			config.CiscoAIDefenseConfig{},
		)
	case "plugin":
		prediction.Engine = "plugin-scanner-static"
		implementation = scanner.NewPluginScanner(r.PluginBinary)
	case "mcp":
		prediction.Engine = "mcp-scanner-yara-static"
		result, err := r.runMCPYARA(ctx, target)
		if err != nil {
			prediction.Action = "error"
			prediction.ErrorCode = "scanner_failure"
			return prediction
		}
		return predictionFromScanResult(prediction, result, true, profile)
	}
	result, err := implementation.Scan(ctx, target)
	if err != nil {
		prediction.Action = "error"
		prediction.ErrorCode = "scanner_failure"
		return prediction
	}
	return predictionFromScanResult(prediction, result, true, profile)
}

type mcpYARAOutput struct {
	ScanResults        []mcpYARAToolResult `json:"scan_results"`
	RequestedAnalyzers []string            `json:"requested_analyzers"`
}

type mcpYARAToolResult struct {
	Status   string                    `json:"status"`
	ToolName string                    `json:"tool_name"`
	Findings map[string]mcpYARAFinding `json:"findings"`
}

type mcpYARAFinding struct {
	Severity      string   `json:"severity"`
	ThreatNames   []string `json:"threat_names"`
	ThreatSummary string   `json:"threat_summary"`
	TotalFindings int      `json:"total_findings"`
}

// runMCPYARA uses the standalone scanner's static-file contract. Retained MCP
// benchmark payloads are tool-definition JSON, not live MCP server targets, so
// routing them through "defenseclaw mcp scan" changes the input semantics.
func (r Runner) runMCPYARA(ctx context.Context, target string) (*scanner.ScanResult, error) {
	start := time.Now()
	binary := firstNonEmpty(r.MCPBinary, "mcp-scanner")
	args := []string{"--analyzers", "yara", "--format", "raw"}
	if rulesDir := strings.TrimSpace(r.MCPYARARulesDir); rulesDir != "" {
		if !filepath.IsAbs(rulesDir) {
			rulesDir = filepath.Join(r.RepoRoot, rulesDir)
		}
		args = append(args, "--rules-path", filepath.Clean(rulesDir))
	}
	args = append(args, "static", "--tools", target)
	cmd := processutil.CommandContext(ctx, binary, args...)
	output, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("mcp YARA scanner exited %d: %s", exitErr.ExitCode(), strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, fmt.Errorf("run mcp YARA scanner: %w", err)
	}
	findings, err := parseMCPYARAOutput(output)
	if err != nil {
		return nil, fmt.Errorf("parse mcp YARA scanner output: %w", err)
	}
	return &scanner.ScanResult{
		Scanner:    "mcp-scanner",
		Target:     target,
		Timestamp:  start,
		Duration:   time.Since(start),
		TargetType: "mcp",
		Findings:   findings,
	}, nil
}

func parseMCPYARAOutput(data []byte) ([]scanner.Finding, error) {
	start := strings.IndexByte(string(data), '{')
	end := strings.LastIndexByte(string(data), '}')
	if start < 0 || end < start {
		return nil, errors.New("missing JSON object")
	}
	var output mcpYARAOutput
	if err := json.Unmarshal(data[start:end+1], &output); err != nil {
		return nil, err
	}
	if len(output.RequestedAnalyzers) != 1 || strings.ToLower(strings.TrimSpace(output.RequestedAnalyzers[0])) != "yara" {
		return nil, fmt.Errorf("scanner did not confirm YARA-only execution: %v", output.RequestedAnalyzers)
	}

	var findings []scanner.Finding
	for _, tool := range output.ScanResults {
		if !strings.EqualFold(strings.TrimSpace(tool.Status), "completed") {
			return nil, fmt.Errorf("tool %q scan status is %q", tool.ToolName, tool.Status)
		}
		for analyzer, finding := range tool.Findings {
			if analyzer != "yara_analyzer" {
				return nil, fmt.Errorf("unexpected analyzer %q in YARA-only output", analyzer)
			}
			if finding.TotalFindings <= 0 {
				continue
			}
			rules := mcpYARARules(finding.ThreatSummary)
			if len(rules) == 0 {
				rules = []string{"unclassified_match"}
			}
			for index := 0; index < finding.TotalFindings; index++ {
				rule := rules[index%len(rules)]
				id := "mcp_yara." + rule
				findings = append(findings, scanner.Finding{
					ID:       id,
					RuleID:   id,
					Severity: mcpYARASeverity(finding.Severity),
					Title:    finding.ThreatSummary,
					Location: "mcp-tool:" + tool.ToolName,
					Scanner:  "mcp-scanner/yara",
					Category: strings.Join(finding.ThreatNames, ","),
				})
			}
		}
	}
	return findings, nil
}

func mcpYARARules(summary string) []string {
	_, names, ok := strings.Cut(summary, ":")
	if !ok {
		return nil
	}
	var rules []string
	for _, name := range strings.Split(names, ",") {
		if normalized := normalizeMCPYARARule(name); normalized != "" {
			rules = append(rules, normalized)
		}
	}
	return compactStrings(rules)
}

func normalizeMCPYARARule(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	separator := false
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') {
			if separator && builder.Len() > 0 {
				builder.WriteByte('_')
			}
			builder.WriteRune(char)
			separator = false
		} else {
			separator = true
		}
	}
	return builder.String()
}

func mcpYARASeverity(value string) scanner.Severity {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return scanner.SeverityCritical
	case "HIGH":
		return scanner.SeverityHigh
	case "MEDIUM":
		return scanner.SeverityMedium
	case "LOW":
		return scanner.SeverityLow
	case "INFO", "UNKNOWN", "":
		// Benchmark predictions intentionally use the closed LOW..CRITICAL
		// severity scale. Preserve an unknown scanner finding as a low-severity
		// detection instead of emitting an invalid INFO prediction.
		return scanner.SeverityLow
	default:
		return scanner.SeverityLow
	}
}

func predictionFromScanResult(prediction Prediction, result *scanner.ScanResult, admission bool, profile string) Prediction {
	if result == nil {
		prediction.Action = "error"
		prediction.ErrorCode = "nil_scan_result"
		return prediction
	}
	prediction.FindingCount = len(result.Findings)
	prediction.Detected = len(result.Findings) > 0
	prediction.Severity = string(result.MaxSeverity())
	if !prediction.Detected {
		prediction.Severity = "NONE"
	}
	for _, finding := range result.Findings {
		prediction.RuleIDs = append(prediction.RuleIDs, firstNonEmpty(finding.RuleID, finding.ID))
	}
	prediction.Action = "allow"
	if prediction.Detected {
		prediction.Action = "alert"
	}
	if admission {
		verdict := strings.ToLower(strings.TrimSpace(result.Verdict))
		if verdict == "malicious" || verdict == "block" || verdict == "blocked" {
			prediction.Action = "block"
		}
	}
	return applyConservativeAlertProjection(prediction)
}

func (r Runner) materializeTarget(benchmarkCase Case) (string, func(), error) {
	if benchmarkCase.Payload.Target != "" {
		if r.DataDir == "" {
			return "", nil, fmt.Errorf("data dir is required for external target")
		}
		clean := filepath.Clean(benchmarkCase.Payload.Target)
		if filepath.IsAbs(clean) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", nil, fmt.Errorf("target must be a relative path below data dir")
		}
		root, err := filepath.Abs(r.DataDir)
		if err != nil {
			return "", nil, err
		}
		target, err := filepath.Abs(filepath.Join(root, clean))
		if err != nil || (target != root && !strings.HasPrefix(target, root+string(filepath.Separator))) {
			return "", nil, fmt.Errorf("target escapes data dir")
		}
		return target, nil, nil
	}

	dir, err := os.MkdirTemp("", "defenseclaw-benchmark-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	name := filepath.Base(benchmarkCase.Payload.Filename)
	if name == "." || name == string(filepath.Separator) || name == "" {
		cleanup()
		return "", nil, fmt.Errorf("invalid filename")
	}
	target := filepath.Join(dir, name)
	if err := os.WriteFile(target, []byte(benchmarkCase.Payload.Content), 0o600); err != nil {
		cleanup()
		return "", nil, err
	}
	return target, cleanup, nil
}

func benchmarkDialect(value string) actionfacts.Dialect {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "argv":
		return actionfacts.DialectArgv
	case "powershell":
		return actionfacts.DialectPowerShell
	case "cmd":
		return actionfacts.DialectCMD
	case "mixed":
		return actionfacts.DialectMixed
	case "none":
		return actionfacts.DialectNone
	default:
		return actionfacts.DialectPOSIX
	}
}

func engineForSurface(surface string) string {
	switch surface {
	case "text":
		return "gateway-local-text"
	case "action":
		return "gateway-trusted-action"
	case "code":
		return "code-scan-local"
	case "skill":
		return "skill-scanner-static"
	case "plugin":
		return "plugin-scanner-static"
	case "mcp":
		return "mcp-scanner-yara-static"
	case "stateful":
		return "gateway-tool-chain"
	case "e2e":
		return "gateway-http-inspect"
	default:
		return surface
	}
}

func normalizeAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "block", "deny", "denied":
		return "block"
	case "confirm", "ask":
		return "confirm"
	case "alert", "warn", "warning":
		return "alert"
	case "allow", "allowed", "":
		return "allow"
	default:
		return "error"
	}
}

func normalizeSeverity(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "LOW":
		return "LOW"
	case "MEDIUM":
		return "MEDIUM"
	case "HIGH":
		return "HIGH"
	case "CRITICAL":
		return "CRITICAL"
	default:
		return "NONE"
	}
}

func ruleIDsFromFindingStrings(findings []string, allowedRuleIDs map[string]struct{}) []string {
	var ids []string
	for _, finding := range findings {
		index := strings.IndexByte(finding, ':')
		if index <= 0 {
			continue
		}
		id := strings.TrimSpace(finding[:index])
		if _, allowed := allowedRuleIDs[id]; allowed {
			ids = append(ids, id)
		}
	}
	return ids
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	sort.Strings(values)
	out := values[:0]
	for _, value := range values {
		if value == "" || (len(out) > 0 && out[len(out)-1] == value) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
