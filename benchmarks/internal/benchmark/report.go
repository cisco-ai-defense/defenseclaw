// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"encoding/csv"
	"fmt"
	"io"
	"sort"
	"strconv"
)

func WriteMarkdown(w io.Writer, summary Summary, environment Environment) error {
	if _, err := fmt.Fprintf(w, "# DefenseClaw deterministic benchmark\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Run `%s` on DefenseClaw `%s` (%s/%s). Classification results exclude timing fields and source payloads.\n\n", environment.RunID, environment.DefenseClawCommit, environment.GOOS, environment.GOARCH); err != nil {
		return err
	}
	if environment.TruthCorpusSHA256 != "" {
		if _, err := fmt.Fprintf(
			w,
			"Evaluated corpus SHA-256: `%s`. Scoring truth corpus SHA-256: `%s`.\n\n",
			environment.CorpusSHA256,
			environment.TruthCorpusSHA256,
		); err != nil {
			return err
		}
	}
	if environment.Dirty {
		if _, err := fmt.Fprint(w, "> Warning: the source worktree was dirty. This run is not publication eligible.\n\n"); err != nil {
			return err
		}
	}
	if hasScoreDimension(summary, "deterministic_truth") {
		if _, err := fmt.Fprint(w, "> Adjudicated-label warning: primary detection metrics use `deterministic_truth` where present and exclude contextual/dual-use rows from binary F1 and FPR. `source_truth` remains available for attack-source diagnostics. Model-assisted labels require a resolved review queue before publication. Detection FPR counts every finding, including audit telemetry; alert FPR counts user-visible advisory, detect-only, and enforceable findings; use benign block rate to describe blocking.\n\n"); err != nil {
			return err
		}
	} else if _, err := fmt.Fprint(w, "> Source-label warning: detection metrics score the public dataset's broad `source_truth`. For command corpora, attack provenance or scenario context does not prove that each standalone command is deterministically malicious. Do not present detection F1 as enforcement coverage. Detection FPR counts every finding, including audit telemetry; alert FPR counts user-visible advisory, detect-only, and enforceable findings; use benign block rate to describe blocking.\n\n"); err != nil {
		return err
	}
	if hasScoreDimension(summary, "enforcement_lens") {
		if _, err := fmt.Fprint(w, "> Enforcement-lens warning: expected dispositions were transformed under an explicitly declared policy lens while source truth and predictions remained unchanged. Compare enforcement metrics only between artifacts using the same lens.\n\n"); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, "## Results\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| Profile | Dimension | Group | Applicable | Errors | Detection F1 | Detection FPR | Alert F1 | Alert FPR | Audit telemetry | Enforcement F1 | Span F1 | Benign block rate | p95 | Support |\n| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |"); err != nil {
		return err
	}
	for _, group := range summary.Groups {
		if group.Dimension != "overall" && group.Dimension != "surface" && group.Dimension != "dataset" {
			continue
		}
		support := "ok"
		if group.LowSupport {
			support = "low"
		}
		if _, err := fmt.Fprintf(
			w,
			"| %s | %s | %s | %d | %d | %.2f%% | %.2f%% | %.2f%% | %.2f%% | %.2f%% (%d/%d) | %.2f%% | %.2f%% | %.2f%% (%d/%d) | %s | %s |\n",
			group.Profile,
			group.Dimension,
			group.Group,
			group.Applicable,
			group.Errors,
			100*group.Detection.F1,
			100*group.Detection.FPR,
			100*group.Alert.F1,
			100*group.Alert.FPR,
			100*group.AuditTelemetryRate.Value,
			group.AuditTelemetryRate.Numerator,
			group.AuditTelemetryRate.Denominator,
			100*group.Enforcement.F1,
			100*group.Spans.F1,
			100*group.BenignBlockRate.Value,
			group.BenignBlockRate.Numerator,
			group.BenignBlockRate.Denominator,
			formatMicros(group.Latency.P95Micros),
			support,
		); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprint(w, "\n## Overall confusion counts\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| Profile | Detection TP | FP | FN | TN | Alert TP | FP | FN | TN | Enforcement TP | FP | FN | TN |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"); err != nil {
		return err
	}
	for _, group := range summary.Groups {
		if group.Dimension != "overall" {
			continue
		}
		detection := group.Detection.Confusion
		alert := group.Alert.Confusion
		enforcement := group.Enforcement.Confusion
		if _, err := fmt.Fprintf(
			w,
			"| %s | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d |\n",
			group.Profile,
			detection.TruePositive,
			detection.FalsePositive,
			detection.FalseNegative,
			detection.TrueNegative,
			alert.TruePositive,
			alert.FalsePositive,
			alert.FalseNegative,
			alert.TrueNegative,
			enforcement.TruePositive,
			enforcement.FalsePositive,
			enforcement.FalseNegative,
			enforcement.TrueNegative,
		); err != nil {
			return err
		}
	}
	if len(summary.ProfileComparisons) > 0 {
		if _, err := fmt.Fprint(w, "\n## Paired profile changes\n\n"); err != nil {
			return err
		}
		if _, err := fmt.Fprintln(w, "| Profiles | Comparable | Positive detections +/− | Benign findings +/resolved | Expected blocks +/− | Benign blocks +/resolved | Actions stricter/looser |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: |"); err != nil {
			return err
		}
		for _, comparison := range summary.ProfileComparisons {
			if _, err := fmt.Fprintf(
				w,
				"| %s → %s | %d | %d/%d | %d/%d | %d/%d | %d/%d | %d/%d |\n",
				comparison.BaselineProfile,
				comparison.ComparisonProfile,
				comparison.ComparablePredictions,
				comparison.PositiveDetectionGains,
				comparison.PositiveDetectionLosses,
				comparison.BenignFindingIntroduced,
				comparison.BenignFindingResolved,
				comparison.ExpectedBlockGains,
				comparison.ExpectedBlockLosses,
				comparison.BenignBlockIntroduced,
				comparison.BenignBlockResolved,
				comparison.MoreRestrictiveActions,
				comparison.LessRestrictiveActions,
			); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprint(w, "\n## Macro averages\n\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "| Profile | Surfaces | Detection F1 | Alert F1 | Enforcement F1 |\n| --- | ---: | ---: | ---: | ---: |"); err != nil {
		return err
	}
	for _, macro := range summary.Macro {
		if _, err := fmt.Fprintf(w, "| %s | %d | %.2f%% | %.2f%% | %.2f%% |\n", macro.Profile, macro.SurfaceCount, 100*macro.DetectionF1, 100*macro.AlertF1, 100*macro.EnforcementF1); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(w, "\n## Interpretation\n\nDetection and enforcement use different truth labels. A malicious or sensitive `detect_only` case is positive for broad detection but negative for blocking. Detection includes internal audit telemetry; Alert includes only user-visible advisory, detect-only, and enforceable findings. A detection false positive may therefore be audit-only, while an alert false positive reaches the user; neither is necessarily a blocked benign action. Span scores use one-to-one byte-range overlap and do not require detector labels to match. Confidence intervals and the complete machine-readable scorecard are available in `results.json`. Groups whose benign denominator does not meet the protocol's claim floor have `fpr_claim_eligible=false` in that file. A smoke report is a harness check, not a production-rate claim.")
	return err
}

func hasScoreDimension(summary Summary, dimension string) bool {
	for _, group := range summary.Groups {
		if group.Dimension == dimension {
			return true
		}
	}
	return false
}

func formatMicros(value int64) string {
	if value >= 1000 {
		return fmt.Sprintf("%.2f ms", float64(value)/1000)
	}
	return fmt.Sprintf("%d µs", value)
}

func WriteSummaryCSV(w io.Writer, summary Summary) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()
	if err := writer.Write([]string{
		"profile", "dimension", "group", "cases", "applicable", "out_of_scope", "errors",
		"detection_tp", "detection_tn", "detection_fp", "detection_fn",
		"detection_precision", "detection_recall", "detection_f1", "detection_fpr",
		"alert_tp", "alert_tn", "alert_fp", "alert_fn",
		"alert_precision", "alert_recall", "alert_f1", "alert_fpr",
		"block_tp", "block_tn", "block_fp", "block_fn", "block_precision", "block_recall", "block_f1",
		"span_tp", "span_fp", "span_fn", "span_precision", "span_recall", "span_f1",
		"benign_block_numerator", "benign_block_denominator", "benign_block_rate",
		"audit_telemetry_numerator", "audit_telemetry_denominator", "audit_telemetry_rate",
		"applicability_rate", "error_rate", "safe_abstention_rate", "authoritative_rate", "enforcement_eligible_rate",
		"semantic_match_route_rate", "fallback_match_route_rate", "mixed_match_route_rate",
		"p50_micros", "p95_micros", "p99_micros", "low_support", "fpr_claim_minimum", "fpr_claim_eligible",
	}); err != nil {
		return err
	}
	for _, group := range summary.Groups {
		d := group.Detection
		a := group.Alert
		e := group.Enforcement
		s := group.Spans
		row := []string{
			group.Profile, group.Dimension, group.Group,
			strconv.Itoa(group.Cases), strconv.Itoa(group.Applicable), strconv.Itoa(group.OutOfScope), strconv.Itoa(group.Errors),
			strconv.Itoa(d.Confusion.TruePositive), strconv.Itoa(d.Confusion.TrueNegative), strconv.Itoa(d.Confusion.FalsePositive), strconv.Itoa(d.Confusion.FalseNegative),
			formatFloat(d.Precision), formatFloat(d.Recall), formatFloat(d.F1), formatFloat(d.FPR),
			strconv.Itoa(a.Confusion.TruePositive), strconv.Itoa(a.Confusion.TrueNegative), strconv.Itoa(a.Confusion.FalsePositive), strconv.Itoa(a.Confusion.FalseNegative),
			formatFloat(a.Precision), formatFloat(a.Recall), formatFloat(a.F1), formatFloat(a.FPR),
			strconv.Itoa(e.Confusion.TruePositive), strconv.Itoa(e.Confusion.TrueNegative), strconv.Itoa(e.Confusion.FalsePositive), strconv.Itoa(e.Confusion.FalseNegative),
			formatFloat(e.Precision), formatFloat(e.Recall), formatFloat(e.F1),
			strconv.Itoa(s.TruePositive), strconv.Itoa(s.FalsePositive), strconv.Itoa(s.FalseNegative),
			formatFloat(s.Precision), formatFloat(s.Recall), formatFloat(s.F1),
			strconv.Itoa(group.BenignBlockRate.Numerator), strconv.Itoa(group.BenignBlockRate.Denominator), formatFloat(group.BenignBlockRate.Value),
			strconv.Itoa(group.AuditTelemetryRate.Numerator), strconv.Itoa(group.AuditTelemetryRate.Denominator), formatFloat(group.AuditTelemetryRate.Value),
			formatFloat(group.ApplicabilityRate.Value), formatFloat(group.ErrorRate.Value), formatFloat(group.SafeAbstentionRate.Value),
			formatFloat(group.AuthoritativeRate.Value), formatFloat(group.EnforcementEligibleRate.Value),
			formatFloat(group.SemanticMatchRouteRate.Value), formatFloat(group.FallbackMatchRouteRate.Value), formatFloat(group.MixedMatchRouteRate.Value),
			strconv.FormatInt(group.Latency.P50Micros, 10), strconv.FormatInt(group.Latency.P95Micros, 10), strconv.FormatInt(group.Latency.P99Micros, 10),
			strconv.FormatBool(group.LowSupport), strconv.Itoa(group.FPRClaimMinimum), strconv.FormatBool(group.FPRClaimEligible),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}
	return writer.Error()
}

func WriteCoverageCSV(w io.Writer, cases []Case, predictions []Prediction) error {
	type key struct {
		profile string
		ruleID  string
	}
	type coverage struct {
		support int
		matched int
	}
	caseByID := make(map[string]Case, len(cases))
	for _, benchmarkCase := range cases {
		caseByID[benchmarkCase.ID] = benchmarkCase
	}
	entries := make(map[key]*coverage)
	for _, prediction := range predictions {
		benchmarkCase, ok := caseByID[prediction.CaseID]
		if !ok || !prediction.Applicable || prediction.ErrorCode != "" {
			continue
		}
		actual := make(map[string]struct{}, len(prediction.RuleIDs))
		for _, ruleID := range prediction.RuleIDs {
			actual[ruleID] = struct{}{}
		}
		for _, expectedRuleID := range benchmarkCase.Truth.RuleIDs {
			entryKey := key{profile: prediction.Profile, ruleID: expectedRuleID}
			entry := entries[entryKey]
			if entry == nil {
				entry = &coverage{}
				entries[entryKey] = entry
			}
			entry.support++
			if _, found := actual[expectedRuleID]; found {
				entry.matched++
			}
		}
	}
	keys := make([]key, 0, len(entries))
	for entryKey := range entries {
		keys = append(keys, entryKey)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].profile != keys[j].profile {
			return keys[i].profile < keys[j].profile
		}
		return keys[i].ruleID < keys[j].ruleID
	})
	writer := csv.NewWriter(w)
	defer writer.Flush()
	if err := writer.Write([]string{"profile", "rule_id", "support", "matched", "match_rate", "low_support"}); err != nil {
		return err
	}
	for _, entryKey := range keys {
		entry := entries[entryKey]
		if err := writer.Write([]string{
			entryKey.profile,
			entryKey.ruleID,
			strconv.Itoa(entry.support),
			strconv.Itoa(entry.matched),
			formatFloat(ratio(entry.matched, entry.support)),
			strconv.FormatBool(entry.support < 30),
		}); err != nil {
			return err
		}
	}
	return writer.Error()
}

func formatFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', 8, 64)
}
