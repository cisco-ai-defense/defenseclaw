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

package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// metricsSet holds all registered OTel instruments.
type metricsSet struct {
	// Scan metrics
	scanCount         metric.Int64Counter
	scanDuration      metric.Float64Histogram
	scanFindings      metric.Int64Counter
	scanFindingsGauge metric.Int64UpDownCounter
	scanErrors        metric.Int64Counter

	// Runtime metrics
	toolCalls     metric.Int64Counter
	toolDuration  metric.Float64Histogram
	toolErrors    metric.Int64Counter
	approvalCount metric.Int64Counter

	// GenAI semconv metrics
	genAITokenUsage       metric.Float64Histogram // gen_ai.client.token.usage
	genAIOperationDuration metric.Float64Histogram // gen_ai.client.operation.duration

	// Alert metrics
	alertCount           metric.Int64Counter
	guardrailEvaluations metric.Int64Counter
	guardrailLatency     metric.Float64Histogram

	// HTTP API metrics
	httpRequestCount    metric.Int64Counter
	httpRequestDuration metric.Float64Histogram

	// Admission gate metrics
	admissionDecisions metric.Int64Counter

	// Watcher metrics
	watcherEvents   metric.Int64Counter
	watcherErrors   metric.Int64Counter
	watcherRestarts metric.Int64Counter

	// Inspect metrics
	inspectEvaluations metric.Int64Counter
	inspectLatency     metric.Float64Histogram

	// Audit store metrics
	auditDBErrors metric.Int64Counter
	auditEvents   metric.Int64Counter

	// Config metrics
	configLoadErrors metric.Int64Counter

	// Policy evaluation metrics
	policyEvaluations metric.Int64Counter
	policyLatency     metric.Float64Histogram
	policyReloads     metric.Int64Counter
}

func newMetricsSet(m metric.Meter) (*metricsSet, error) {
	var ms metricsSet
	var err error

	ms.scanCount, err = m.Int64Counter("defenseclaw.scan.count",
		metric.WithUnit("{scan}"),
		metric.WithDescription("Total number of scans completed"))
	if err != nil {
		return nil, err
	}

	ms.scanDuration, err = m.Float64Histogram("defenseclaw.scan.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Scan duration distribution"))
	if err != nil {
		return nil, err
	}

	ms.scanFindings, err = m.Int64Counter("defenseclaw.scan.findings",
		metric.WithUnit("{finding}"),
		metric.WithDescription("Total findings across all scans"))
	if err != nil {
		return nil, err
	}

	ms.scanFindingsGauge, err = m.Int64UpDownCounter("defenseclaw.scan.findings.gauge",
		metric.WithUnit("{finding}"),
		metric.WithDescription("Current open finding count"))
	if err != nil {
		return nil, err
	}

	ms.toolCalls, err = m.Int64Counter("defenseclaw.tool.calls",
		metric.WithUnit("{call}"),
		metric.WithDescription("Total tool calls observed"))
	if err != nil {
		return nil, err
	}

	ms.toolDuration, err = m.Float64Histogram("defenseclaw.tool.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Tool call duration distribution"))
	if err != nil {
		return nil, err
	}

	ms.toolErrors, err = m.Int64Counter("defenseclaw.tool.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Tool calls that returned non-zero exit codes"))
	if err != nil {
		return nil, err
	}

	ms.approvalCount, err = m.Int64Counter("defenseclaw.approval.count",
		metric.WithUnit("{request}"),
		metric.WithDescription("Exec approval requests processed"))
	if err != nil {
		return nil, err
	}

	ms.genAITokenUsage, err = m.Float64Histogram("gen_ai.client.token.usage",
		metric.WithUnit("{token}"),
		metric.WithDescription("Number of input and output tokens used."),
		metric.WithExplicitBucketBoundaries(1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864),
	)
	if err != nil {
		return nil, err
	}

	ms.genAIOperationDuration, err = m.Float64Histogram("gen_ai.client.operation.duration",
		metric.WithUnit("s"),
		metric.WithDescription("GenAI operation duration."),
		metric.WithExplicitBucketBoundaries(0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92),
	)
	if err != nil {
		return nil, err
	}

	ms.alertCount, err = m.Int64Counter("defenseclaw.alert.count",
		metric.WithUnit("{alert}"),
		metric.WithDescription("Total runtime alerts emitted"))
	if err != nil {
		return nil, err
	}

	ms.guardrailEvaluations, err = m.Int64Counter("defenseclaw.guardrail.evaluations",
		metric.WithUnit("{evaluation}"),
		metric.WithDescription("Total guardrail evaluations performed"))
	if err != nil {
		return nil, err
	}

	ms.guardrailLatency, err = m.Float64Histogram("defenseclaw.guardrail.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("Guardrail evaluation latency distribution"))
	if err != nil {
		return nil, err
	}

	ms.scanErrors, err = m.Int64Counter("defenseclaw.scan.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Scanner invocations that failed (crash, timeout, not found)"))
	if err != nil {
		return nil, err
	}

	ms.httpRequestCount, err = m.Int64Counter("defenseclaw.http.request.count",
		metric.WithUnit("{request}"),
		metric.WithDescription("Total HTTP requests to the sidecar API"))
	if err != nil {
		return nil, err
	}

	ms.httpRequestDuration, err = m.Float64Histogram("defenseclaw.http.request.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("HTTP request duration distribution"))
	if err != nil {
		return nil, err
	}

	ms.admissionDecisions, err = m.Int64Counter("defenseclaw.admission.decisions",
		metric.WithUnit("{decision}"),
		metric.WithDescription("Admission gate decisions"))
	if err != nil {
		return nil, err
	}

	ms.watcherEvents, err = m.Int64Counter("defenseclaw.watcher.events",
		metric.WithUnit("{event}"),
		metric.WithDescription("Filesystem watcher events observed"))
	if err != nil {
		return nil, err
	}

	ms.watcherErrors, err = m.Int64Counter("defenseclaw.watcher.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Filesystem watcher errors"))
	if err != nil {
		return nil, err
	}

	ms.watcherRestarts, err = m.Int64Counter("defenseclaw.watcher.restarts",
		metric.WithUnit("{restart}"),
		metric.WithDescription("Watcher or gateway reconnection events"))
	if err != nil {
		return nil, err
	}

	ms.inspectEvaluations, err = m.Int64Counter("defenseclaw.inspect.evaluations",
		metric.WithUnit("{evaluation}"),
		metric.WithDescription("Tool/message inspect evaluations"))
	if err != nil {
		return nil, err
	}

	ms.policyEvaluations, err = m.Int64Counter("defenseclaw.policy.evaluations",
		metric.WithUnit("{evaluation}"),
		metric.WithDescription("Total OPA policy evaluations per domain"))
	if err != nil {
		return nil, err
	}

	ms.inspectLatency, err = m.Float64Histogram("defenseclaw.inspect.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("Tool/message inspect latency distribution"))
	if err != nil {
		return nil, err
	}

	ms.policyLatency, err = m.Float64Histogram("defenseclaw.policy.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("OPA policy evaluation latency distribution"))
	if err != nil {
		return nil, err
	}

	ms.auditDBErrors, err = m.Int64Counter("defenseclaw.audit.db.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("SQLite audit store operation failures"))
	if err != nil {
		return nil, err
	}

	ms.auditEvents, err = m.Int64Counter("defenseclaw.audit.events.total",
		metric.WithUnit("{event}"),
		metric.WithDescription("Total audit events persisted"))
	if err != nil {
		return nil, err
	}

	ms.configLoadErrors, err = m.Int64Counter("defenseclaw.config.load.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Configuration load or validation errors"))
	if err != nil {
		return nil, err
	}

	ms.policyReloads, err = m.Int64Counter("defenseclaw.policy.reloads",
		metric.WithUnit("{reload}"),
		metric.WithDescription("Total OPA policy reload events"))
	if err != nil {
		return nil, err
	}

	return &ms, nil
}

// RecordScan records scan-related metrics.
func (p *Provider) RecordScan(ctx context.Context, scanner, targetType, verdict string, durationMs float64, findings map[string]int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}

	baseAttrs := metric.WithAttributes(
		attribute.String("scanner", scanner),
		attribute.String("target_type", targetType),
	)

	p.metrics.scanCount.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scanner", scanner),
		attribute.String("target_type", targetType),
		attribute.String("verdict", verdict),
	))
	p.metrics.scanDuration.Record(ctx, durationMs, baseAttrs)

	for severity, count := range findings {
		if count > 0 {
			p.metrics.scanFindings.Add(ctx, int64(count), metric.WithAttributes(
				attribute.String("scanner", scanner),
				attribute.String("target_type", targetType),
				attribute.String("severity", severity),
			))
			p.metrics.scanFindingsGauge.Add(ctx, int64(count), metric.WithAttributes(
				attribute.String("target_type", targetType),
				attribute.String("severity", severity),
			))
		}
	}
}

// RecordToolCall records a tool call metric.
func (p *Provider) RecordToolCall(ctx context.Context, tool, provider string, dangerous bool) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.toolCalls.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tool.name", tool),
		attribute.String("tool.provider", provider),
		attribute.Bool("dangerous", dangerous),
	))
}

// RecordToolDuration records a tool call duration metric.
func (p *Provider) RecordToolDuration(ctx context.Context, tool, provider string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.toolDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("tool.name", tool),
		attribute.String("tool.provider", provider),
	))
}

// RecordToolError records a tool error metric.
func (p *Provider) RecordToolError(ctx context.Context, tool string, exitCode int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.toolErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tool.name", tool),
		attribute.Int("exit_code", exitCode),
	))
}

// RecordApproval records an approval request metric.
func (p *Provider) RecordApproval(ctx context.Context, result string, auto, dangerous bool) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.approvalCount.Add(ctx, 1, metric.WithAttributes(
		attribute.String("result", result),
		attribute.Bool("auto", auto),
		attribute.Bool("dangerous", dangerous),
	))
}

// RecordLLMTokens records token consumption metrics per OTel GenAI semconv.
// gen_ai.client.token.usage histogram with gen_ai.token.type = "input"/"output".
func (p *Provider) RecordLLMTokens(ctx context.Context, operationName, providerName, model string, prompt, completion int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	commonAttrs := []attribute.KeyValue{
		attribute.String("gen_ai.operation.name", operationName),
		attribute.String("gen_ai.provider.name", providerName),
		attribute.String("gen_ai.request.model", model),
	}
	if prompt > 0 {
		attrs := append([]attribute.KeyValue{attribute.String("gen_ai.token.type", "input")}, commonAttrs...)
		p.metrics.genAITokenUsage.Record(ctx, float64(prompt), metric.WithAttributes(attrs...))
	}
	if completion > 0 {
		attrs := append([]attribute.KeyValue{attribute.String("gen_ai.token.type", "output")}, commonAttrs...)
		p.metrics.genAITokenUsage.Record(ctx, float64(completion), metric.WithAttributes(attrs...))
	}
}

// RecordLLMDuration records LLM call duration per OTel GenAI semconv.
// gen_ai.client.operation.duration histogram, unit=seconds.
func (p *Provider) RecordLLMDuration(ctx context.Context, operationName, providerName, model string, durationSeconds float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.genAIOperationDuration.Record(ctx, durationSeconds, metric.WithAttributes(
		attribute.String("gen_ai.operation.name", operationName),
		attribute.String("gen_ai.provider.name", providerName),
		attribute.String("gen_ai.request.model", model),
	))
}

// RecordAlert records a runtime alert metric.
func (p *Provider) RecordAlert(ctx context.Context, alertType, severity, source string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.alertCount.Add(ctx, 1, metric.WithAttributes(
		attribute.String("alert.type", alertType),
		attribute.String("alert.severity", severity),
		attribute.String("alert.source", source),
	))
}

// RecordGuardrailEvaluation records a guardrail evaluation metric.
func (p *Provider) RecordGuardrailEvaluation(ctx context.Context, scanner, actionTaken string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.guardrailEvaluations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("guardrail.scanner", scanner),
		attribute.String("guardrail.action_taken", actionTaken),
	))
}

// RecordGuardrailLatency records guardrail evaluation latency.
func (p *Provider) RecordGuardrailLatency(ctx context.Context, scanner string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.guardrailLatency.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("guardrail.scanner", scanner),
	))
}

// RecordScanError records a scanner invocation failure.
func (p *Provider) RecordScanError(ctx context.Context, scanner, targetType, errorType string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.scanErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scanner", scanner),
		attribute.String("target_type", targetType),
		attribute.String("error_type", errorType),
	))
}

// RecordHTTPRequest records an HTTP API request metric.
func (p *Provider) RecordHTTPRequest(ctx context.Context, method, route string, statusCode int, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("http.method", method),
		attribute.String("http.route", route),
		attribute.Int("http.status_code", statusCode),
	)
	p.metrics.httpRequestCount.Add(ctx, 1, attrs)
	p.metrics.httpRequestDuration.Record(ctx, durationMs, attrs)
}

// RecordAdmissionDecision records an admission gate decision.
func (p *Provider) RecordAdmissionDecision(ctx context.Context, decision, targetType, source string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.admissionDecisions.Add(ctx, 1, metric.WithAttributes(
		attribute.String("decision", decision),
		attribute.String("target_type", targetType),
		attribute.String("source", source),
	))
}

// RecordWatcherEvent records a filesystem watcher event.
func (p *Provider) RecordWatcherEvent(ctx context.Context, eventType, targetType string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.watcherEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("event_type", eventType),
		attribute.String("target_type", targetType),
	))
}

// RecordWatcherError records a filesystem watcher error.
func (p *Provider) RecordWatcherError(ctx context.Context) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.watcherErrors.Add(ctx, 1)
}

// RecordWatcherRestart records a watcher or gateway reconnection.
func (p *Provider) RecordWatcherRestart(ctx context.Context) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.watcherRestarts.Add(ctx, 1)
}

// RecordInspectEvaluation records a tool/message inspect evaluation.
func (p *Provider) RecordInspectEvaluation(ctx context.Context, tool, action, severity string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.inspectEvaluations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("tool", tool),
		attribute.String("action", action),
		attribute.String("severity", severity),
	))
}

// RecordInspectLatency records tool/message inspect latency.
func (p *Provider) RecordInspectLatency(ctx context.Context, tool string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.inspectLatency.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("tool", tool),
	))
}

// RecordAuditDBError records an SQLite audit store operation failure.
func (p *Provider) RecordAuditDBError(ctx context.Context, operation string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.auditDBErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("operation", operation),
	))
}

// RecordAuditEvent records that an audit event was persisted.
func (p *Provider) RecordAuditEvent(ctx context.Context, action, severity string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.auditEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("action", action),
		attribute.String("severity", severity),
	))
}

// RecordConfigLoadError records a config load or validation error.
func (p *Provider) RecordConfigLoadError(ctx context.Context, errorType string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.configLoadErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("error_type", errorType),
	))
}

// RecordPolicyEvaluation records a policy evaluation metric for the given domain.
func (p *Provider) RecordPolicyEvaluation(ctx context.Context, domain, verdict string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.policyEvaluations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("policy.domain", domain),
		attribute.String("policy.verdict", verdict),
	))
}

// RecordPolicyLatency records policy evaluation latency for the given domain.
func (p *Provider) RecordPolicyLatency(ctx context.Context, domain string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.policyLatency.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("policy.domain", domain),
	))
}

// RecordPolicyReload records a policy reload event.
func (p *Provider) RecordPolicyReload(ctx context.Context, status string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.policyReloads.Add(ctx, 1, metric.WithAttributes(
		attribute.String("policy.status", status),
	))
}
