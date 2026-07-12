// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type scanTraceCapturingRuntime struct {
	*testRuntimeV8Emitter
	traces []observability.SpanAssetScanInput
	err    error
}

func (runtime *scanTraceCapturingRuntime) EmitRuntimeV8AssetScanTrace(
	_ context.Context,
	input observability.SpanAssetScanInput,
) error {
	runtime.traces = append(runtime.traces, input)
	return runtime.err
}

func TestScanV8EmitsOccurrenceFindingsBeforeSummaryAndPreservesMetricParity(t *testing.T) {
	logger := newTestLogger(t)
	runtime := &scanTraceCapturingRuntime{
		testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary),
	}
	logger.SetRuntimeV8Emitter(runtime)
	line := 17
	result := &scanner.ScanResult{
		Scanner: "codeguard", Target: "asset/code/example", TargetType: "code",
		Timestamp: time.Date(2026, 7, 6, 14, 0, 0, 0, time.UTC), Duration: 1250 * time.Millisecond,
		Findings: []scanner.Finding{
			{ID: "CG-SECRET", RuleID: "CG-SECRET", Severity: scanner.SeverityHigh,
				Title: "Credential found", Description: "source evidence", Location: "main.go",
				LineNumber: &line, Remediation: "remove the credential", Scanner: "codeguard",
				Tags: []string{"credential"}, Confidence: 0.9},
			{ID: "CG-PATH", RuleID: "CG-PATH", Severity: scanner.SeverityLow,
				Title: "Unsafe path", Scanner: "codeguard", DataAxis: []string{"sensitive_access"}},
		},
	}
	corr := ScanCorrelation{
		RunID: "run-scan", RequestID: "request-scan", SessionID: "session-scan",
		TraceID: "0123456789abcdef0123456789abcdef", AgentID: "agent-scan",
		AgentName: "scanner-agent", AgentInstanceID: "agent-instance-scan", Connector: "codex",
	}
	if err := logger.LogScanWithCorrelation(context.Background(), result, "blocked", corr); err != nil {
		_, partial := runtime.snapshot()
		t.Fatalf("LogScanWithCorrelation: %v (persisted generated prefix=%d)", err, len(partial))
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 3 || len(records) != 3 {
		t.Fatalf("generated metadata/records=%d/%d, want 3/3", len(metadata), len(records))
	}
	for index := 0; index < 2; index++ {
		if records[index].EventName() != observability.EventName(observability.TelemetryEventFindingObserved) ||
			records[index].Bucket() != observability.BucketSecurityFinding {
			t.Fatalf("finding record[%d]=%s/%s", index, records[index].Bucket(), records[index].EventName())
		}
		body := securityActionBody(t, records[index])
		if body["defenseclaw.finding.id"] != result.Findings[index].FindingOccurrenceID ||
			body["defenseclaw.finding.rule_id"] != result.Findings[index].RuleID {
			t.Fatalf("finding record[%d] identity body=%#v", index, body)
		}
	}
	if records[2].EventName() != observability.EventName(observability.TelemetryEventScanCompleted) ||
		records[2].Bucket() != observability.BucketAssetScan || records[2].Outcome() != observability.OutcomeCompleted {
		t.Fatalf("scan summary=%s/%s outcome=%s", records[2].Bucket(), records[2].EventName(), records[2].Outcome())
	}
	summaryBody := securityActionBody(t, records[2])
	scanID, ok := summaryBody["defenseclaw.scan.id"].(string)
	if !ok || scanID == "" || fmt.Sprint(summaryBody["defenseclaw.scan.finding_count"]) != "2" ||
		fmt.Sprint(summaryBody["defenseclaw.scan.high_count"]) != "1" ||
		fmt.Sprint(summaryBody["defenseclaw.scan.low_count"]) != "1" ||
		summaryBody["defenseclaw.scan.verdict"] != "block" {
		t.Fatalf("scan summary body=%#v", summaryBody)
	}
	findings, err := logger.store.ListScanFindings(scanID)
	if err != nil || len(findings) != 2 {
		t.Fatalf("forensic findings=%d err=%v", len(findings), err)
	}
	for index := range findings {
		if findings[index].ID != result.Findings[index].FindingOccurrenceID ||
			records[index].RecordID() != findings[index].ID {
			t.Fatalf("finding occurrence[%d] forensic=%q source=%q record=%q", index,
				findings[index].ID, result.Findings[index].FindingOccurrenceID, records[index].RecordID())
		}
	}
	events, err := logger.store.ListEvents(10)
	if err != nil || len(events) != 3 {
		t.Fatalf("canonical event history=%d err=%v", len(events), err)
	}
	metrics := runtime.metricSnapshot()
	wantFamilies := map[observability.EventName]int{
		observability.EventName(observability.TelemetryInstrumentDefenseClawAuditEventsTotal):   1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawScanCount):          1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawScanDuration):       2,
		observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindings):       2,
		observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsGauge):  2,
		observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsByRule): 2,
	}
	gotFamilies := make(map[observability.EventName]int)
	for _, metric := range metrics {
		gotFamilies[metric.EventName()]++
	}
	if !reflect.DeepEqual(gotFamilies, wantFamilies) {
		t.Fatalf("generated scan metric families=%v, want %v", gotFamilies, wantFamilies)
	}
	if len(runtime.traces) != 1 {
		t.Fatalf("generated scan traces=%d, want 1", len(runtime.traces))
	}
	traceInput := runtime.traces[0]
	traceScanID, traceScanIDPresent := traceInput.DefenseClawScanID.Get()
	traceScanner, traceScannerPresent := traceInput.DefenseClawScanScanner.Get()
	if !traceScanIDPresent || traceScanID != scanID || !traceScannerPresent || traceScanner != "codeguard" ||
		traceInput.Outcome != observability.OutcomeCompleted || traceInput.Kind != "INTERNAL" ||
		traceInput.Envelope.Correlation.TraceID != corr.TraceID ||
		traceInput.EndTimeUnixNano-traceInput.StartTimeUnixNano != uint64(result.Duration) {
		t.Fatalf("generated scan trace input=%#v", traceInput)
	}
}

func TestScanV8FailureUsesFailedFamilyWithoutInventingFindingStatus(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	result := &scanner.ScanResult{
		Scanner: "skill-scanner", Target: "skill/example", TargetType: "skill",
		Timestamp: time.Now().UTC(), Duration: time.Millisecond,
		ExitCode: 2, ScanError: "scanner process failed",
	}
	if err := logger.LogScan(result); err != nil {
		t.Fatal(err)
	}
	_, records := runtime.snapshot()
	if len(records) != 1 || records[0].EventName() != observability.EventName(observability.TelemetryEventScanFailed) ||
		records[0].Outcome() != observability.OutcomeFailed {
		t.Fatalf("failed scan records=%#v", records)
	}
	body := securityActionBody(t, records[0])
	if _, exists := body["defenseclaw.finding.status"]; exists {
		t.Fatalf("failed scan invented finding status: %#v", body)
	}
}

func TestScanV8DerivedEvidenceMatchesForensicAndCanonicalRecords(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	result := &scanner.ScanResult{
		Scanner: "codeguard", Target: "asset/example", TargetType: "code",
		Timestamp: time.Date(2026, 7, 7, 10, 0, 0, 0, time.UTC),
		Findings: []scanner.Finding{
			{RuleID: "CG-DESCRIPTION", Severity: scanner.SeverityHigh, Description: "matched source excerpt"},
			{RuleID: "CG-FALLBACK", Severity: scanner.SeverityLow, Title: "Fallback title", Location: "main.go:17"},
		},
	}
	if err := logger.LogScan(result); err != nil {
		t.Fatal(err)
	}
	_, records := runtime.snapshot()
	if len(records) != 3 {
		t.Fatalf("canonical records=%d, want two findings plus summary", len(records))
	}
	scanID := records[0].Correlation().ScanID
	rows, err := logger.store.ListScanFindings(scanID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("forensic findings=%d err=%v", len(rows), err)
	}
	want := []string{
		"matched source excerpt",
		"rule=CG-FALLBACK; title=Fallback title; target_type=code; location=main.go:17",
	}
	for index := range want {
		body := securityActionBody(t, records[index])
		if got := body["defenseclaw.guardrail.evidence_summary"]; got != want[index] {
			t.Fatalf("canonical evidence[%d]=%#v want %q", index, got, want[index])
		}
		if !rows[index].EvidenceSummary.Valid || rows[index].EvidenceSummary.String != want[index] ||
			result.Findings[index].EvidenceSummary != want[index] {
			t.Fatalf("forensic/source evidence[%d]=%#v/%q want %q",
				index, rows[index].EvidenceSummary, result.Findings[index].EvidenceSummary, want[index])
		}
		if _, exists := body["defenseclaw.finding.status"]; exists {
			t.Fatalf("finding[%d] invented status: %#v", index, body)
		}
	}
}

func TestLogInspectFindingsWithCorrelationUsesOneGeneratedV8Pipeline(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	const evaluationID = "evaluation-runtime-inspect"
	source := scanner.InspectFindingSource{
		Scanner: "hook-rules", Target: "codex:PreToolUse", TargetType: "tool_call",
		Verdict: "block", DurationMs: 7, EvaluationID: evaluationID,
		Findings: []scanner.InspectFinding{{
			RuleID: "SECRET-AWS-AKIA", Title: "AWS access key", Severity: scanner.SeverityHigh,
			Confidence: 0.95, Evidence: "source-evidence-excerpt", Tags: []string{"secret"},
		}},
	}
	corr := ScanCorrelation{
		RequestID: "request-runtime", SessionID: "session-runtime",
		TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef",
		AgentID: "agent-runtime", AgentInstanceID: "instance-runtime", Connector: "codex",
	}

	gotEvaluationID, scanID, err := logger.LogInspectFindingsWithCorrelation(t.Context(), source, corr)
	if err != nil {
		t.Fatal(err)
	}
	if gotEvaluationID != evaluationID || scanID == "" {
		t.Fatalf("runtime inspection identifiers evaluation=%q scan=%q", gotEvaluationID, scanID)
	}

	_, records := runtime.snapshot()
	if len(records) != 2 {
		t.Fatalf("generated runtime inspection records=%d, want finding + summary", len(records))
	}
	for index, record := range records {
		correlation := record.Correlation()
		if correlation.EvaluationID != evaluationID || correlation.ScanID != scanID ||
			correlation.TraceID != corr.TraceID || correlation.SpanID != corr.SpanID ||
			correlation.RequestID != corr.RequestID || correlation.SessionID != corr.SessionID ||
			correlation.AgentID != corr.AgentID || correlation.AgentInstanceID != corr.AgentInstanceID ||
			correlation.ConnectorID != corr.Connector {
			t.Fatalf("record[%d] correlation=%+v", index, correlation)
		}
		body := securityActionBody(t, record)
		if body["defenseclaw.evaluation.id"] != evaluationID || body["defenseclaw.scan.id"] != scanID {
			t.Fatalf("record[%d] identifiers=%#v", index, body)
		}
		if index == 0 && body["defenseclaw.guardrail.evidence_summary"] != "source-evidence-excerpt" {
			t.Fatalf("finding evidence summary=%#v", body)
		}
	}

	findings, err := logger.store.ListScanFindings(scanID)
	if err != nil || len(findings) != 1 || findings[0].EvaluationID != evaluationID ||
		findings[0].EvidenceSummary.String != "source-evidence-excerpt" ||
		findings[0].ID != records[0].RecordID() {
		t.Fatalf("forensic runtime findings=%#v err=%v", findings, err)
	}
	metrics := runtime.metricSnapshot()
	if len(metrics) == 0 {
		t.Fatal("runtime inspection emitted no generated dashboard metrics")
	}
	foundByRuleMetric := false
	for index, metric := range metrics {
		correlation := metric.Correlation()
		if correlation.EvaluationID != evaluationID || correlation.ScanID != scanID ||
			correlation.TraceID != corr.TraceID || correlation.SpanID != corr.SpanID {
			t.Fatalf("metric[%d] %s correlation=%+v", index, metric.EventName(), correlation)
		}
		if metric.EventName() == observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsByRule) {
			foundByRuleMetric = true
			instrument, present := metric.InstrumentData()
			if !present {
				t.Fatal("dashboard by-rule metric has no instrument data")
			}
			data, dataErr := instrument.Object()
			if dataErr != nil {
				t.Fatal(dataErr)
			}
			attributes, ok := data["attributes"].(map[string]any)
			if !ok || attributes["defenseclaw.scan.scanner"] != "hook-rules" ||
				attributes["defenseclaw.connector.source"] != "codex" ||
				attributes["defenseclaw.security.severity"] != "HIGH" ||
				attributes["defenseclaw.finding.rule_id"] != "SECRET-AWS-AKIA" {
				t.Fatalf("dashboard by-rule dimensions=%#v", data)
			}
		}
	}
	if !foundByRuleMetric {
		t.Fatal("runtime inspection omitted the dashboard by-rule metric")
	}
}
