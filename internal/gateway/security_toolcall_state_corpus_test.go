// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

type toolCallStateExpectedDisposition string

const (
	toolCallStateDispositionBlock  toolCallStateExpectedDisposition = "block"
	toolCallStateDispositionDetect toolCallStateExpectedDisposition = "detect"
	toolCallStateDispositionNone   toolCallStateExpectedDisposition = "none"
)

type toolCallStateCorpusCase struct {
	ID                  string                           `json:"id"`
	Pair                string                           `json:"pair"`
	Platforms           []string                         `json:"platforms"`
	ExpectedDisposition toolCallStateExpectedDisposition `json:"expected_disposition"`
	ExpectedRule        string                           `json:"expected_rule"`
	Steps               []toolCallStateCorpusStep        `json:"steps"`
}

type toolCallStateCorpusStep struct {
	Event               string `json:"event"`
	Session             string `json:"session,omitempty"`
	Invocation          string `json:"invocation,omitempty"`
	Command             string `json:"command,omitempty"`
	ArtifactNamePOSIX   string `json:"artifact_name_posix,omitempty"`
	ArtifactNameWindows string `json:"artifact_name_windows,omitempty"`
	ArtifactBodyPOSIX   string `json:"artifact_body_posix,omitempty"`
	ArtifactBodyWindows string `json:"artifact_body_windows,omitempty"`
}

type toolCallStateConfusionMatrix struct {
	truePositive  int
	trueNegative  int
	falsePositive int
	falseNegative int
}

func (matrix *toolCallStateConfusionMatrix) observe(expected, actual bool) {
	switch {
	case expected && actual:
		matrix.truePositive++
	case expected:
		matrix.falseNegative++
	case actual:
		matrix.falsePositive++
	default:
		matrix.trueNegative++
	}
}

func (matrix toolCallStateConfusionMatrix) metrics() (precision, recall, f1 float64) {
	precision = corpusRatio(matrix.truePositive, matrix.truePositive+matrix.falsePositive)
	recall = corpusRatio(matrix.truePositive, matrix.truePositive+matrix.falseNegative)
	if precision+recall > 0 {
		f1 = 2 * precision * recall / (precision + recall)
	}
	return precision, recall, f1
}

// TestSecuritySuiteToolCallState is a deliberately small paired benchmark for
// every active experimental chain plus final-artifact inspection. Detection is
// measured across all applicable pairs; blocking is measured only where both
// chain steps carry exact enforcement evidence. Its metrics describe only this
// checked-in corpus, not production prevalence or generalization.
func TestSecuritySuiteToolCallState(t *testing.T) {
	const connectorName = "claudecode"
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, connectorName)
	cases := readJSONL[toolCallStateCorpusCase](t, "toolcall", "stateful.jsonl")
	if len(cases) == 0 || len(cases) > 12 {
		t.Fatalf("stateful corpus size=%d, want 1..12", len(cases))
	}
	validateToolCallStateCorpus(t, cases)

	fixture := newSidecarRuntimeFixture(t, true)
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime})
	queryDB, err := sql.Open("sqlite", fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queryDB.Close() })
	newHandler := func(mode string) http.Handler {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = mode
		cfg.Guardrail.Connector = connectorName
		cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "strict")
		api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
		return http.HandlerFunc(api.handleAgentHook(connectorName))
	}
	actionHandler := newHandler("action")
	observeHandler := newHandler("observe")

	blockEligiblePairs := make(map[string]bool)
	for _, corpusCase := range cases {
		if corpusCase.ExpectedDisposition == toolCallStateDispositionBlock {
			blockEligiblePairs[corpusCase.Pair] = true
		}
	}
	var detection, blocking toolCallStateConfusionMatrix
	applicableCases := 0
	applicablePairs := make(map[string]struct{})
	for _, corpusCase := range cases {
		corpusCase := corpusCase
		t.Run(corpusCase.ID, func(t *testing.T) {
			if !toolCallStateCorpusApplies(corpusCase, runtime.GOOS) {
				t.Skipf("not applicable to %s", runtime.GOOS)
			}
			applicableCases++
			applicablePairs[corpusCase.Pair] = struct{}{}
			targetRule := corpusCase.ExpectedRule
			handler := observeHandler
			if blockEligiblePairs[corpusCase.Pair] {
				handler = actionHandler
			}
			targetSeen, targetBlocked := runToolCallStateCorpusCase(t, handler, queryDB, corpusCase, targetRule)
			expectedDetection := corpusCase.ExpectedDisposition != toolCallStateDispositionNone
			detection.observe(expectedDetection, targetSeen)
			if blockEligiblePairs[corpusCase.Pair] {
				blocking.observe(
					corpusCase.ExpectedDisposition == toolCallStateDispositionBlock,
					targetBlocked,
				)
			}
			switch corpusCase.ExpectedDisposition {
			case toolCallStateDispositionBlock:
				if !targetSeen || !targetBlocked {
					t.Errorf("target=%q want=block seen=%t blocked=%t", targetRule, targetSeen, targetBlocked)
				}
			case toolCallStateDispositionDetect:
				if !targetSeen || targetBlocked {
					t.Errorf("target=%q want=detect seen=%t blocked=%t", targetRule, targetSeen, targetBlocked)
				}
			case toolCallStateDispositionNone:
				if targetSeen || targetBlocked {
					t.Errorf("target=%q want=none seen=%t blocked=%t", targetRule, targetSeen, targetBlocked)
				}
			}
		})
	}

	detectionPrecision, detectionRecall, detectionF1 := detection.metrics()
	blockPrecision, blockRecall, blockF1 := blocking.metrics()
	t.Logf(
		"experimental target-detection corpus: TP=%d TN=%d FP=%d FN=%d precision=%.3f recall=%.3f F1=%.3f",
		detection.truePositive, detection.trueNegative,
		detection.falsePositive, detection.falseNegative,
		detectionPrecision, detectionRecall, detectionF1,
	)
	t.Logf(
		"experimental target-blocking corpus (block-eligible pairs only): TP=%d TN=%d FP=%d FN=%d precision=%.3f recall=%.3f F1=%.3f",
		blocking.truePositive, blocking.trueNegative,
		blocking.falsePositive, blocking.falseNegative,
		blockPrecision, blockRecall, blockF1,
	)
	t.Logf(
		"scope: %d/%d applicable cases across %d/%d pairs on %s; paired curated regression, not a production-rate estimate",
		applicableCases, len(cases), len(applicablePairs), len(cases)/2, runtime.GOOS,
	)
	if detection.falsePositive != 0 || detection.falseNegative != 0 ||
		blocking.falsePositive != 0 || blocking.falseNegative != 0 {
		t.Fatalf(
			"stateful corpus regression: detection FP=%d FN=%d; blocking FP=%d FN=%d",
			detection.falsePositive, detection.falseNegative,
			blocking.falsePositive, blocking.falseNegative,
		)
	}
}

func validateToolCallStateCorpus(t *testing.T, cases []toolCallStateCorpusCase) {
	t.Helper()
	seen := make(map[string]struct{}, len(cases))
	type pairSummary struct {
		positiveDisposition toolCallStateExpectedDisposition
		positiveCount       int
		negativeCount       int
		rule                string
		platforms           []string
	}
	pairs := make(map[string]pairSummary)
	for _, corpusCase := range cases {
		if strings.TrimSpace(corpusCase.ID) == "" ||
			strings.TrimSpace(corpusCase.Pair) == "" ||
			strings.TrimSpace(corpusCase.ExpectedRule) == "" ||
			len(corpusCase.Platforms) == 0 || len(corpusCase.Steps) == 0 {
			t.Fatalf("invalid stateful corpus case: %+v", corpusCase)
		}
		switch corpusCase.ExpectedDisposition {
		case toolCallStateDispositionBlock, toolCallStateDispositionDetect, toolCallStateDispositionNone:
		default:
			t.Fatalf("case %q has invalid expected disposition %q", corpusCase.ID, corpusCase.ExpectedDisposition)
		}
		platformSet := make(map[string]struct{}, len(corpusCase.Platforms))
		for _, platform := range corpusCase.Platforms {
			if platform != "posix" && platform != "windows" {
				t.Fatalf("case %q has invalid platform %q", corpusCase.ID, platform)
			}
			if _, duplicate := platformSet[platform]; duplicate {
				t.Fatalf("case %q repeats platform %q", corpusCase.ID, platform)
			}
			platformSet[platform] = struct{}{}
		}
		if _, duplicate := seen[corpusCase.ID]; duplicate {
			t.Fatalf("duplicate stateful corpus id %q", corpusCase.ID)
		}
		seen[corpusCase.ID] = struct{}{}
		summary := pairs[corpusCase.Pair]
		if summary.rule == "" {
			summary.rule = corpusCase.ExpectedRule
			summary.platforms = slices.Clone(corpusCase.Platforms)
		} else if summary.rule != corpusCase.ExpectedRule ||
			!slices.Equal(summary.platforms, corpusCase.Platforms) {
			t.Fatalf("pair %q must use one target rule and platform set", corpusCase.Pair)
		}
		if corpusCase.ExpectedDisposition == toolCallStateDispositionNone {
			summary.negativeCount++
		} else {
			summary.positiveCount++
			summary.positiveDisposition = corpusCase.ExpectedDisposition
		}
		pairs[corpusCase.Pair] = summary
	}
	if len(pairs)*2 != len(cases) {
		t.Fatalf("stateful corpus has %d cases across %d pairs", len(cases), len(pairs))
	}
	for pair, summary := range pairs {
		if summary.positiveCount != 1 || summary.negativeCount != 1 {
			t.Fatalf(
				"pair %q has positive=%d negative=%d, want one of each",
				pair, summary.positiveCount, summary.negativeCount,
			)
		}
	}
	type expectedPair struct {
		rule        string
		disposition toolCallStateExpectedDisposition
		platforms   []string
	}
	expectedPairs := map[string]expectedPair{
		"permission-turn-session-artifact": {
			rule: guardrail.ToolChainPermissionDeniedThenBypass, disposition: toolCallStateDispositionBlock,
			platforms: []string{"posix", "windows"},
		},
		"final-artifact-bytes": {
			rule: "CMD-RM-RF", disposition: toolCallStateDispositionBlock,
			platforms: []string{"posix", "windows"},
		},
		"privilege-discovery-elevation": {
			rule: guardrail.ToolChainPrivilegeDiscoveryThenElevation, disposition: toolCallStateDispositionBlock,
			platforms: []string{"posix"},
		},
		"secret-manager-egress": {
			rule: guardrail.ToolChainSecretManagerReadThenEgress, disposition: toolCallStateDispositionDetect,
			platforms: []string{"posix"},
		},
		"secret-read-egress": {
			rule: guardrail.ToolChainSecretReadThenEgress, disposition: toolCallStateDispositionDetect,
			platforms: []string{"posix"},
		},
		"workload-identity-lateral": {
			rule: guardrail.ToolChainWorkloadIdentityThenLateralExec, disposition: toolCallStateDispositionDetect,
			platforms: []string{"posix"},
		},
	}
	if len(pairs) != len(expectedPairs) {
		t.Fatalf("stateful corpus has %d pairs, want %d active pairs", len(pairs), len(expectedPairs))
	}
	for pair, expected := range expectedPairs {
		summary, ok := pairs[pair]
		if !ok || summary.rule != expected.rule ||
			summary.positiveDisposition != expected.disposition ||
			!slices.Equal(summary.platforms, expected.platforms) {
			t.Fatalf(
				"pair %q got rule=%q disposition=%q platforms=%v present=%t; want rule=%q disposition=%q platforms=%v",
				pair, summary.rule, summary.positiveDisposition, summary.platforms, ok,
				expected.rule, expected.disposition, expected.platforms,
			)
		}
	}
}

func toolCallStateCorpusApplies(corpusCase toolCallStateCorpusCase, goos string) bool {
	platform := "posix"
	if goos == "windows" {
		platform = "windows"
	}
	return slices.Contains(corpusCase.Platforms, platform)
}

func runToolCallStateCorpusCase(t *testing.T, handler http.Handler, queryDB *sql.DB, corpusCase toolCallStateCorpusCase, targetRule string) (targetSeen, targetBlocked bool) {
	t.Helper()
	dir := t.TempDir()
	chainTarget := strings.HasPrefix(targetRule, "chain.")
	receiptsBefore := 0
	if chainTarget {
		receiptsBefore = toolCallStateReceiptCount(t, queryDB, targetRule)
	}
	invocationTools := make(map[string]string)
	for index, step := range corpusCase.Steps {
		session := corpusCase.ID + "-" + firstNonEmpty(step.Session, "main")
		invocation := corpusCase.ID + "-" + step.Invocation
		key := session + "\x00" + invocation
		payload := map[string]interface{}{
			"hook_event_name": step.Event,
			"session_id":      session,
		}
		switch step.Event {
		case "PreToolUse":
			command, tool := stateCorpusCommand(t, dir, corpusCase.ID, index, step)
			payload["tool_use_id"] = invocation
			payload["tool_name"] = tool
			payload["tool_input"] = map[string]interface{}{"command": command}
			payload["cwd"] = dir
			invocationTools[key] = tool
		case "PostToolUse", "PostToolUseFailure", "PermissionDenied":
			payload["tool_use_id"] = invocation
			payload["tool_name"] = firstNonEmpty(invocationTools[key], "Bash")
			if step.Event == "PermissionDenied" {
				payload["tool_input"] = map[string]interface{}{"command": "echo harmless"}
			} else {
				payload["tool_response"] = map[string]interface{}{
					"status": map[bool]string{true: "success", false: "failure"}[step.Event == "PostToolUse"],
				}
			}
		case "Stop", "SessionEnd":
		default:
			t.Fatalf("unsupported stateful corpus event %q", step.Event)
		}
		response := callAgentHookForTest(t, handler, payload)
		if slices.Contains(response.RuleIDs, targetRule) {
			targetSeen = true
			targetBlocked = targetBlocked || !chainTarget && response.Action == guardrailActionBlock
		}
	}
	if chainTarget {
		targetBlocked = toolCallStateReceiptCount(t, queryDB, targetRule) > receiptsBefore
	}
	return targetSeen, targetBlocked
}

func toolCallStateReceiptCount(t *testing.T, db *sql.DB, rule string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_deny_receipts WHERE chain_id=?`, rule).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func stateCorpusCommand(t *testing.T, dir, caseID string, stepIndex int, step toolCallStateCorpusStep) (command, tool string) {
	t.Helper()
	if step.ArtifactBodyPOSIX == "" && step.ArtifactBodyWindows == "" {
		if strings.TrimSpace(step.Command) == "" {
			t.Fatal("PreToolUse step requires command or artifact body")
		}
		if runtime.GOOS == "windows" {
			return step.Command, "PowerShell"
		}
		return step.Command, "Bash"
	}
	name := step.ArtifactNamePOSIX
	body := step.ArtifactBodyPOSIX
	tool = "Bash"
	if runtime.GOOS == "windows" {
		name = step.ArtifactNameWindows
		body = step.ArtifactBodyWindows
		tool = "PowerShell"
	}
	if name == "" || body == "" || filepath.Base(name) != name {
		t.Fatalf("invalid platform artifact fixture name=%q body_bytes=%d", name, len(body))
	}
	path := filepath.Join(dir, fmt.Sprintf("%02d-%s-%s", stepIndex, caseID, name))
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		quoted := "'" + strings.ReplaceAll(path, "'", "''") + "'"
		return "powershell -NoProfile -File " + quoted, tool
	}
	return fmt.Sprintf("bash %q", path), tool
}

func corpusRatio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
