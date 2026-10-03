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

// GAP-2000: a judge or AI Defense finding merged into the hook-rules scan is
// exported under its own lane, like `defenseclaw alerts` shows it.
func TestScanV8HookLaneFindingsNameTheirScanner(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	result := &scanner.ScanResult{
		Scanner: "hook-rules", Target: "claudecode/PreToolUse", TargetType: "tool_call",
		Timestamp: time.Now().UTC(), Duration: time.Millisecond,
		Findings: []scanner.Finding{
			{ID: "JUDGE-EXFIL-FILE", RuleID: "JUDGE-EXFIL-FILE", Severity: scanner.SeverityHigh,
				Title: "Sensitive File Access", Scanner: "hook-rules", Tags: []string{"llm-judge"}},
			{ID: "JUDGE-PII-SSN", RuleID: "JUDGE-PII-SSN", Severity: scanner.SeverityHigh,
				Title: "SSN", Scanner: "hook-rules", Tags: []string{"pii", "redacted"}},
			{ID: "AID-PII", RuleID: "AID-PII", Severity: scanner.SeverityMedium,
				Title: "PII", Scanner: "hook-rules", Tags: []string{"ai-defense"}},
			{ID: "CMD-MARKER", RuleID: "CMD-MARKER", Severity: scanner.SeverityHigh,
				Title: "Marker rule", Scanner: "hook-rules", Tags: []string{"command"}},
		},
	}
	if err := logger.LogScanWithVerdict(result, "block"); err != nil {
		t.Fatal(err)
	}
	_, records := runtime.snapshot()
	want := map[string]string{
		"JUDGE-EXFIL-FILE": "llm-judge", "JUDGE-PII-SSN": "llm-judge",
		"AID-PII": "ai-defense", "CMD-MARKER": "hook-rules",
	}
	seen := 0
	for _, record := range records {
		if record.EventName() != observability.EventName(observability.TelemetryEventFindingObserved) {
			continue
		}
		body := securityActionBody(t, record)
		rule, _ := body["defenseclaw.finding.rule_id"].(string)
		if got := body["defenseclaw.scan.scanner"]; got != want[rule] {
			t.Errorf("%s scanner=%v, want %s", rule, got, want[rule])
		}
		seen++
	}
	if seen != len(want) {
		t.Fatalf("finding records=%d, want %d", seen, len(want))
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
	// GAP-1987: a scan that never ran is not clean on any signal.
	if verdict, exists := body["defenseclaw.scan.verdict"]; exists {
		t.Fatalf("failed scan log verdict=%v, want absent", verdict)
	}
	counted := false
	for _, metric := range runtime.metricSnapshot() {
		if metric.EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawScanCount) {
			continue
		}
		counted = true
		if got := metricAttributes(t, metric)["defenseclaw.metric.verdict"]; got != "error" {
			t.Fatalf("failed scan count verdict=%v, want error (attributes %v)", got, metricAttributes(t, metric))
		}
	}
	if !counted {
		t.Fatal("failed scan emitted no scan.count metric")
	}
	if got := scanV8Verdict(result, "clean"); got != "error" {
		t.Fatalf("explicit clean on a failed scan = %q, want error", got)
	}
	if _, present := scanV8VerdictEnum("error").Get(); present {
		t.Fatal("error verdict reached the clean/warn/block enum")
	}
}

func TestScanV8RepeatedAssetFindingOnlyEmitsLifecycleChanges(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	base := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	newResult := func(at time.Time, findings ...scanner.Finding) *scanner.ScanResult {
		return &scanner.ScanResult{
			Scanner: "codeguard", Target: "asset/distinct", TargetType: "code",
			Timestamp: at, Duration: time.Millisecond, Findings: findings,
		}
	}
	newFinding := func() scanner.Finding {
		return scanner.Finding{
			Scanner: "codeguard", RuleID: "CG-DISTINCT", Severity: scanner.SeverityHigh,
			Title: "Distinct finding", Description: "same matched source", Location: "main.go:7",
		}
	}

	first := newResult(base, newFinding())
	if err := logger.LogScan(first); err != nil {
		t.Fatal(err)
	}
	_, firstRecords := runtime.snapshot()
	firstMetrics := runtime.metricSnapshot()
	if len(firstRecords) != 2 || firstRecords[0].EventName() != observability.EventName(observability.TelemetryEventFindingObserved) {
		t.Fatalf("first records=%#v", firstRecords)
	}

	second := newResult(base.Add(time.Minute), newFinding())
	if err := logger.LogScan(second); err != nil {
		t.Fatal(err)
	}
	_, records := runtime.snapshot()
	if len(records) != len(firstRecords)+1 ||
		records[len(records)-1].EventName() != observability.EventName(observability.TelemetryEventScanCompleted) {
		t.Fatalf("repeat emitted finding instead of summary only: before=%d after=%d", len(firstRecords), len(records))
	}
	repeatMetrics := runtime.metricSnapshot()[len(firstMetrics):]
	for _, metric := range repeatMetrics {
		switch metric.EventName() {
		case observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindings),
			observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsGauge),
			observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsByRule):
			t.Fatalf("repeat emitted finding metric %s value=%v", metric.EventName(), metricValue(t, metric))
		}
	}
	events, err := logger.store.ListEvents(100)
	if err != nil {
		t.Fatal(err)
	}
	findingEvents := 0
	for _, event := range events {
		if event.Action == string(ActionScanFinding) {
			findingEvents++
		}
	}
	if findingEvents != 1 {
		t.Fatalf("default event history has %d repeated finding events, want 1", findingEvents)
	}
	firstRows, listErr := logger.store.ListScanFindings(first.ScanID)
	if listErr != nil || len(firstRows) != 1 {
		t.Fatalf("first static transition %s=%+v err=%v", first.ScanID, firstRows, listErr)
	}
	repeatRows, listErr := logger.store.ListScanFindings(second.ScanID)
	if listErr != nil || len(repeatRows) != 0 {
		t.Fatalf("repeated static detail storage %s=%+v err=%v", second.ScanID, repeatRows, listErr)
	}

	beforeResolutionMetrics := len(runtime.metricSnapshot())
	empty := newResult(base.Add(2 * time.Minute))
	if err := logger.LogScan(empty); err != nil {
		t.Fatal(err)
	}
	resolutionMetrics := runtime.metricSnapshot()[beforeResolutionMetrics:]
	resolvedGauge := false
	for _, metric := range resolutionMetrics {
		switch metric.EventName() {
		case observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindings),
			observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsByRule):
			t.Fatalf("resolution invented a finding counter %s", metric.EventName())
		case observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsGauge):
			if fmt.Sprint(metricValue(t, metric)) != "-1" {
				t.Fatalf("resolution gauge=%v, want -1", metricValue(t, metric))
			}
			resolvedGauge = true
		}
	}
	if !resolvedGauge {
		t.Fatal("empty successful scan omitted current-state resolution gauge")
	}
}

func TestScanV8RebuildsCurrentFindingGaugeAfterRuntimeRebind(t *testing.T) {
	logger := newTestLogger(t)
	firstRuntime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(firstRuntime)
	base := time.Date(2026, 8, 7, 11, 0, 0, 0, time.UTC)
	newResult := func(at time.Time) *scanner.ScanResult {
		return &scanner.ScanResult{
			Scanner: "codeguard", Target: "asset/rebind", TargetType: "code",
			Timestamp: at, Duration: time.Millisecond,
			Findings: []scanner.Finding{{
				Scanner: "codeguard", RuleID: "CG-REBIND", Severity: scanner.SeverityHigh,
				Description: "same matched source", Location: "main.go:9",
			}},
		}
	}
	if err := logger.LogScan(newResult(base)); err != nil {
		t.Fatal(err)
	}

	secondRuntime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(secondRuntime)
	if err := logger.LogScan(newResult(base.Add(time.Minute))); err != nil {
		t.Fatal(err)
	}
	_, records := secondRuntime.snapshot()
	if len(records) != 1 || records[0].EventName() != observability.EventName(observability.TelemetryEventScanCompleted) {
		t.Fatalf("runtime rebind replayed repeated finding logs: %#v", records)
	}
	foundBaseline := false
	for _, metric := range secondRuntime.metricSnapshot() {
		switch metric.EventName() {
		case observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindings),
			observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsByRule):
			t.Fatalf("runtime rebind replayed finding counter %s", metric.EventName())
		case observability.EventName(observability.TelemetryInstrumentDefenseClawScanFindingsGauge):
			if fmt.Sprint(metricValue(t, metric)) != "1" {
				t.Fatalf("rebuilt finding gauge=%v, want 1", metricValue(t, metric))
			}
			foundBaseline = true
		}
	}
	if !foundBaseline {
		t.Fatal("runtime rebind did not rebuild the current distinct finding gauge")
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
	const sourceEvidence = "source-evidence-excerpt"
	const wantEvidence = "<redacted-sensitive len=23>"
	source := scanner.InspectFindingSource{
		Scanner: "hook-rules", Target: "codex:PreToolUse", TargetType: "tool_call",
		Verdict: "block", DurationMs: 7, EvaluationID: evaluationID,
		Findings: []scanner.InspectFinding{{
			RuleID: "SECRET-AWS-AKIA", Title: "AWS access key", Severity: scanner.SeverityHigh,
			Confidence: 0.95, Evidence: sourceEvidence, Tags: []string{"secret"},
		}},
	}
	corr := ScanCorrelation{
		RequestID: "request-runtime", SessionID: "session-runtime",
		TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef",
		AgentID: "agent-runtime", AgentInstanceID: "instance-runtime", Connector: "codex",
		UserID: "1002", UserIDKind: "posix_uid", UserName: "bob",
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
		// Finding and scan-verdict rows name the caller, as hook decisions do.
		if body["user.id"] != "1002" || body["defenseclaw.user.id_kind"] != "posix_uid" ||
			body["defenseclaw.user.name"] != "bob" {
			t.Fatalf("record[%d] caller=%#v", index, body)
		}
		if index == 0 && body["defenseclaw.guardrail.evidence_summary"] != wantEvidence {
			t.Fatalf("finding evidence summary=%#v", body)
		}
	}

	findings, err := logger.store.ListScanFindings(scanID)
	if err != nil || len(findings) != 1 || findings[0].EvaluationID != evaluationID ||
		findings[0].EvidenceSummary.String != wantEvidence ||
		findings[0].ID != records[0].RecordID() || !findings[0].RuleID.Valid {
		t.Fatalf("forensic runtime findings=%#v err=%v", findings, err)
	}
	persistedRuleID := findings[0].RuleID.String
	if persistedRuleID == source.Findings[0].RuleID ||
		!authenticatedSensitiveOpaqueRuleID(
			persistedRuleID, sensitiveFindingKindSecret, source.Scanner, runtime,
		) {
		t.Fatalf("custom producer RuleID was not keyed: source=%q persisted=%q",
			source.Findings[0].RuleID, persistedRuleID)
	}
	if body := securityActionBody(t, records[0]); body["defenseclaw.finding.rule_id"] != persistedRuleID {
		t.Fatalf("generated finding RuleID=%#v, want persisted %q", body, persistedRuleID)
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
				attributes["defenseclaw.finding.rule_id"] != persistedRuleID {
				t.Fatalf("dashboard by-rule dimensions=%#v", data)
			}
		}
	}
	if !foundByRuleMetric {
		t.Fatal("runtime inspection omitted the dashboard by-rule metric")
	}
}

// GAP-1381: a path-targeted scan names the asset by its last path element,
// and a scan with findings but no admission verdict is not "clean".
func TestScanV8NamesPathTargetsAndKeepsFindingsOutOfClean(t *testing.T) {
	for target, want := range map[string]string{
		"/home/u/.claude/skills/ws1-notes/":   "ws1-notes",
		`C:\Users\u\.claude\skills\ws1-notes`: "ws1-notes",
		"skill://demo":                        "skill://demo",
		"http://127.0.0.1:8000/mcp":           "http://127.0.0.1:8000/mcp",
		// GAP-2338: names the identifier grammar rejects still name the target.
		"/home/u/.hermes/hermes-agent/plugins/__pycache__": "plugins/__pycache__",
		`C:\Users\u\plugins\My Plugin`:                     "plugins/My_Plugin",
	} {
		if got, ok := scanV8TargetRef(target).Get(); !ok || got != want {
			t.Errorf("scanV8TargetRef(%q) = %q, %v; want %q", target, got, ok, want)
		}
	}
	withFinding := &scanner.ScanResult{Findings: []scanner.Finding{{Severity: scanner.SeverityInfo}}}
	if got := scanV8Verdict(withFinding, ""); got != "warn" {
		t.Errorf("verdict with findings = %q, want warn", got)
	}
	if got := scanV8Verdict(&scanner.ScanResult{}, ""); got != "clean" {
		t.Errorf("verdict without findings = %q, want clean", got)
	}
	if got := scanV8Verdict(withFinding, "block"); got != "block" {
		t.Errorf("explicit verdict = %q, want block", got)
	}
}

// GAP-2440: plugins nested in a category folder under a plugins root keep
// that category, so same-named plugins stay distinct in audit.
func TestScanV8PluginTargetRefKeepsCategoryFolder(t *testing.T) {
	for _, tc := range []struct{ target, targetType, want string }{
		{"/opt/hermes/plugins/browser/firecrawl", "plugin", "browser/firecrawl"},
		{"/opt/hermes/plugins/web/firecrawl", "plugin", "web/firecrawl"},
		{`C:\Users\u\hermes\plugins\image_gen\openrouter`, "plugin", "image_gen/openrouter"},
		{"/home/u/.hermes/plugins/notes", "plugin", "notes"},
		{"/home/u/.claude/skills/review/notes", "skill", "notes"},
	} {
		result := &scanner.ScanResult{Target: tc.target, TargetType: tc.targetType}
		if got, ok := scanV8ResultTargetRef(result).Get(); !ok || got != tc.want {
			t.Errorf("scanV8ResultTargetRef(%q, %s) = %q, %v; want %q", tc.target, tc.targetType, got, ok, tc.want)
		}
	}
}
