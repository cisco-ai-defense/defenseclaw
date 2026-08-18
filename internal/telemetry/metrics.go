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

import "go.opentelemetry.io/otel/metric"

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
	genAITokenUsage        metric.Float64Histogram // gen_ai.client.token.usage
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
	hookInvocations    metric.Int64Counter
	hookLatency        metric.Float64Histogram

	// Connector hook parity with codex notify.
	// hookTokens: split by kind=prompt|completion|total so dashboards
	// can sum any subset; bounded by connector × model cardinality.
	// hookOutcome: split by action × severity × would_block so the
	// alerting rules can group on "alerts that became blocks".
	hookTokens  metric.Int64Counter
	hookOutcome metric.Int64Counter

	// unifiedHookDispatch bumps on every invocation of
	// handleUnifiedConnectorHook. Operators graph it to confirm
	// every connector's hook traffic is flowing through the unified
	// dispatcher (vs. an out-of-tree handler registration that
	// bypasses audit/metrics emission). Cardinality is bounded by
	// connector (7 today); no event dimension to keep the series
	// cheap — operators join with hookOutcome for richer breakdowns.
	unifiedHookDispatch metric.Int64Counter

	// Audit store metrics
	auditDBErrors metric.Int64Counter
	auditEvents   metric.Int64Counter

	// Config metrics
	configLoadErrors metric.Int64Counter

	// Gatewaylog runtime schema validator metrics. Counts events
	// dropped by the strict JSON-schema gate (v7). Labelled by
	// event_type + error_code so operators can filter "which
	// subsystem is emitting broken scan_finding payloads" directly
	// from PromQL without trawling JSONL lines.
	schemaViolations metric.Int64Counter

	// Policy evaluation metrics
	policyEvaluations metric.Int64Counter
	policyLatency     metric.Float64Histogram
	policyReloads     metric.Int64Counter

	// Gateway compatibility metric instruments retained for the generated
	// local-observability projection.
	verdictsTotal    metric.Int64Counter
	judgeInvocations metric.Int64Counter
	judgeLatency     metric.Float64Histogram
	judgeErrors      metric.Int64Counter
	gatewayErrors    metric.Int64Counter
	sinkSendFailures metric.Int64Counter

	// Local-observability compatibility instruments. Canonical generated v8
	// records are their only input; the legacy direct Record* surface is gone.
	//
	// Scanner observability
	scanFindingsByRule metric.Int64Counter // per-scanner/rule_id
	scannerQueueDepth  metric.Int64UpDownCounter
	quarantineActions  metric.Int64Counter // quarantine op + result
	// Activity tracking
	activityTotal       metric.Int64Counter
	activityDiffEntries metric.Int64Histogram

	// Egress (Layer 3 silent-bypass observability).
	// Labels: branch (known|shape|passthrough), decision (allow|block),
	// source (go|ts). Kept low-cardinality so Prometheus recording
	// rules can roll this up per-branch without blowing up TSDB.
	egressEvents metric.Int64Counter

	// Guardrail per-request agent-to-upstream header forwarding
	// (llm.forward_custom_headers). Labels: path
	// (chat-completions|passthrough), result (ok|rejected_invalid|
	// rejected_overflow). The counter is incremented once per
	// request: ok records the number of forwarded headers; rejected_*
	// records 1 so operators can alert on validation-failure rates.
	forwardedHeaders metric.Int64Counter
	// External integrations — sink health
	sinkBatchesDelivered metric.Int64Counter
	sinkBatchesDropped   metric.Int64Counter
	sinkQueueDepth       metric.Int64UpDownCounter
	sinkDeliveryLatency  metric.Float64Histogram
	sinkCircuitState     metric.Int64UpDownCounter
	// HTTP / security events (beyond RecordHTTPRequest)
	httpAuthFailures      metric.Int64Counter
	httpRateLimitBreaches metric.Int64Counter
	webhookDispatches     metric.Int64Counter
	webhookFailures       metric.Int64Counter
	webhookLatency        metric.Float64Histogram
	// Capacity / SLO — gauges record absolute snapshots on each tick.
	goroutines          metric.Int64Gauge
	heapAlloc           metric.Int64Gauge
	heapObjects         metric.Int64Gauge
	gcPauseNs           metric.Int64Histogram
	fdInUse             metric.Int64Gauge
	uptimeSeconds       metric.Float64Gauge
	sqliteDBBytes       metric.Int64Gauge
	sqliteWALBytes      metric.Int64Gauge
	sqlitePageCount     metric.Int64Gauge
	sqliteFreelistCount metric.Int64Gauge
	sqliteCheckpointMs  metric.Float64Histogram
	sqliteBusyRetries   metric.Int64Counter
	sloBlockLatency     metric.Float64Histogram
	sloTUIRefresh       metric.Float64Histogram
	// Queue backpressure (generic; sink/scanner paths call RecordQueueDepth).
	queueDepthGauge metric.Int64Gauge
	queueDrops      metric.Int64Counter
	// Process health
	panicsTotal           metric.Int64Counter
	destinationSpans      metric.Int64Counter
	destinationExports    metric.Int64Counter
	telemetryExporterErrs metric.Int64Counter
	exporterLastExportSec metric.Float64Gauge
	tuiFilterApplied      metric.Int64Counter
	judgeSemDepth         metric.Int64UpDownCounter
	judgeSemDrops         metric.Int64Counter
	// Judge-body persistence (Phase 3 of the SQLite write-lock fix):
	// the authoritative async queue replaces the removed synchronous
	// callback that used to fire two sequential SQLite writes on the
	// proxy hot path. Drops are the canary signal — a healthy
	// sidecar should hold this at zero; a non-zero rate means the
	// queue depth or batch size are mis-tuned for the offered load.
	judgePersistDrops      metric.Int64Counter
	judgePersistQueueDepth metric.Int64Gauge
	judgePersistBatchSize  metric.Int64Histogram
	// Track 10 (OTel log records + provenance fanout)
	gatewayEventsEmitted metric.Int64Counter
	provenanceBumps      metric.Int64Counter

	// SSE streaming lifecycle telemetry
	streamLifecycle   metric.Int64Counter
	streamBytesSent   metric.Int64Histogram
	streamDurationMs  metric.Float64Histogram
	redactionsApplied metric.Int64Counter

	// Guardrail LLM judge + verdict cache
	guardrailJudgeLatency metric.Float64Histogram
	guardrailCacheHits    metric.Int64Counter
	guardrailCacheMisses  metric.Int64Counter

	// Connector OTLP ingest receivers (native connector telemetry
	// posted to /v1/logs, /v1/metrics, /v1/traces). Kept
	// low-cardinality on purpose — labels are signal (logs|metrics|
	// traces) and source (registered connector name|unknown). Records counts
	// the per-batch leaf records (logRecords / dataPoints / spans)
	// the summarizer extracted; used by the connector dashboard to
	// show "telemetry volume per connector".
	otelIngestRequests  metric.Int64Counter
	otelIngestRecords   metric.Int64Counter
	otelIngestBytes     metric.Int64Counter
	otelIngestMalformed metric.Int64Counter
	otelIngestLastSeen  metric.Float64Gauge

	// On-demand local agent discovery. Emitted by the CLI via
	// POST /api/v1/agents/discovery after it has stripped raw local paths.
	agentLastSeen             metric.Float64Gauge
	agentLifecycleTransitions metric.Int64Counter
	agentPhaseCurrent         metric.Int64Gauge
	agentPhaseTransitions     metric.Int64Counter
	agentReportedCost         metric.Float64Gauge
	agentTokenUsage           metric.Int64Counter
	agentDiscoveryRuns        metric.Int64Counter
	agentDiscoveryDuration    metric.Float64Histogram
	agentDiscoverySignals     metric.Int64Counter
	agentDiscoveryInstalled   metric.Int64Gauge
	agentDiscoveryErrors      metric.Int64Counter

	// Continuous AI discovery / shadow AI visibility.
	aiDiscoveryRuns             metric.Int64Counter
	aiDiscoveryDuration         metric.Float64Histogram
	aiDiscoverySignals          metric.Int64Counter
	aiDiscoveryNewSignals       metric.Int64Counter
	aiDiscoveryActiveSignals    metric.Int64Gauge
	aiDiscoveryGoneSignals      metric.Int64Counter
	aiDiscoveryErrors           metric.Int64Counter
	aiDiscoveryFilesScanned     metric.Int64Counter
	aiDiscoveryDedupeSuppressed metric.Int64Counter

	// Component-level confidence emissions, derived from the
	// two-axis Bayesian engine. These are scoped per (ecosystem,
	// name) and are deliberately separate from the per-signal
	// counters above so dashboards can show "what does the
	// gateway think it observed?" alongside "how raw signals
	// fanned in?". Cardinality is bounded by the discovered
	// component set (typically tens to low hundreds per host),
	// not by signal volume.
	aiComponentObservations metric.Int64Counter
	aiComponentInstalls     metric.Int64Gauge
	aiComponentWorkspaces   metric.Int64Gauge
	aiConfidenceIdentity    metric.Float64Histogram
	aiConfidencePresence    metric.Float64Histogram

	// Codex notify webhook (agent-turn-complete et al.). type is
	// the sanitized notify type ("agent-turn-complete", "unknown",
	// "malformed"); status is the codex-supplied status string when
	// present (empty otherwise). Both labels run through the same
	// allow-list as the audit action key so cardinality stays bounded.
	codexNotifyTotal     metric.Int64Counter
	codexNotifyMalformed metric.Int64Counter

	// External integrations — LLM bridge, OpenShell, Cisco, webhook circuit / cooldown
	llmBridgeLatency          metric.Float64Histogram
	openShellExit             metric.Int64Counter
	ciscoErrors               metric.Int64Counter
	ciscoInspectLatency       metric.Float64Histogram
	webhookCooldownSuppressed metric.Int64Counter
	webhookCircuitEvents      metric.Int64Counter
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

	ms.hookInvocations, err = m.Int64Counter("defenseclaw.connector.hook.invocations",
		metric.WithUnit("{hook}"),
		metric.WithDescription("Connector hook invocations observed by the gateway."),
	)
	if err != nil {
		return nil, err
	}

	ms.hookLatency, err = m.Float64Histogram("defenseclaw.connector.hook.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("Connector hook handler latency."),
		// Connector hooks run on the agent's critical path (every
		// pre-tool / pre-prompt callback). Buckets bias hard towards
		// sub-100ms so dashboards can spot regressions long before
		// they're user-visible; the long tail still captures stalls.
		metric.WithExplicitBucketBoundaries(1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000),
	)
	if err != nil {
		return nil, err
	}

	// Hook token usage + outcome counters.
	// Token-usage counters are additive across kind={prompt,completion,total}
	// so a sum-by-connector PromQL gives the full token throughput per
	// connector without joining three series. The metric name uses the
	// same defenseclaw.connector.hook.* prefix as the existing
	// invocations + latency counters so dashboards can build one
	// per-connector panel that surfaces all four signals.
	ms.hookTokens, err = m.Int64Counter("defenseclaw.connector.hook.tokens",
		metric.WithUnit("{token}"),
		metric.WithDescription("Token usage attributable to connector hook invocations. Split by kind=prompt|completion|total."),
	)
	if err != nil {
		return nil, err
	}

	ms.hookOutcome, err = m.Int64Counter("defenseclaw.connector.hook.outcome",
		metric.WithUnit("{decision}"),
		metric.WithDescription("Connector hook outcomes labelled by action, severity, and would_block."),
	)
	if err != nil {
		return nil, err
	}

	// unifiedHookDispatch is a single-dimension counter (connector)
	// to keep cardinality minimal; richer breakdowns can be derived
	// from hookOutcome which is filtered to the same request set.
	ms.unifiedHookDispatch, err = m.Int64Counter("defenseclaw.connector.hook.unified_dispatch",
		metric.WithUnit("{invocation}"),
		metric.WithDescription("Count of hook invocations routed through the unified hook collector, by connector."),
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

	ms.schemaViolations, err = m.Int64Counter("defenseclaw.schema.violations",
		metric.WithUnit("{event}"),
		metric.WithDescription("Gateway events dropped by the runtime JSON-schema gate (v7)"))
	if err != nil {
		return nil, err
	}

	ms.policyReloads, err = m.Int64Counter("defenseclaw.policy.reloads",
		metric.WithUnit("{reload}"),
		metric.WithDescription("Total OPA policy reload events"))
	if err != nil {
		return nil, err
	}

	ms.verdictsTotal, err = m.Int64Counter("defenseclaw.gateway.verdicts",
		metric.WithUnit("{verdict}"),
		metric.WithDescription("Guardrail verdicts emitted per stage/action/severity"))
	if err != nil {
		return nil, err
	}
	ms.judgeInvocations, err = m.Int64Counter("defenseclaw.gateway.judge.invocations",
		metric.WithUnit("{invocation}"),
		metric.WithDescription("LLM judge invocations by kind/action"))
	if err != nil {
		return nil, err
	}
	ms.judgeLatency, err = m.Float64Histogram("defenseclaw.gateway.judge.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("LLM judge invocation latency"))
	if err != nil {
		return nil, err
	}
	ms.judgeErrors, err = m.Int64Counter("defenseclaw.gateway.judge.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("LLM judge errors (provider, parse, or empty response)"))
	if err != nil {
		return nil, err
	}
	ms.gatewayErrors, err = m.Int64Counter("defenseclaw.gateway.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Structured gateway errors by subsystem/code"))
	if err != nil {
		return nil, err
	}
	ms.sinkSendFailures, err = m.Int64Counter("defenseclaw.audit.sink.failures",
		metric.WithUnit("{failure}"),
		metric.WithDescription("Audit sink send failures by sink kind"))
	if err != nil {
		return nil, err
	}

	// v7 instruments — scanner observability
	ms.scanFindingsByRule, err = m.Int64Counter("defenseclaw.scan.findings.by_rule",
		metric.WithUnit("{finding}"),
		metric.WithDescription("Findings grouped by scanner + rule_id + severity"))
	if err != nil {
		return nil, err
	}
	ms.scannerQueueDepth, err = m.Int64UpDownCounter("defenseclaw.scanner.queue.depth",
		metric.WithUnit("{scan}"),
		metric.WithDescription("Pending scanner jobs queued ahead of execution"))
	if err != nil {
		return nil, err
	}
	ms.quarantineActions, err = m.Int64Counter("defenseclaw.quarantine.actions",
		metric.WithUnit("{action}"),
		metric.WithDescription("Filesystem quarantine and restore operations"))
	if err != nil {
		return nil, err
	}

	// v7 instruments — activity tracking
	ms.activityTotal, err = m.Int64Counter("defenseclaw.activity.total",
		metric.WithUnit("{activity}"),
		metric.WithDescription("Operator mutations recorded (EventActivity)"))
	if err != nil {
		return nil, err
	}
	ms.activityDiffEntries, err = m.Int64Histogram("defenseclaw.activity.diff_entries",
		metric.WithUnit("{entry}"),
		metric.WithDescription("Number of diff entries per EventActivity"))
	if err != nil {
		return nil, err
	}

	// v7.1 — egress silent-bypass telemetry
	ms.egressEvents, err = m.Int64Counter("defenseclaw.egress.events",
		metric.WithUnit("{event}"),
		metric.WithDescription("Egress requests classified by Layer 1 shape detection (branch=known|shape|passthrough)"))
	if err != nil {
		return nil, err
	}

	// Per-request header forwarding from agent to upstream LLM
	// provider. Counts forwarded headers on the ok path; counts 1 per
	// failed request on rejected_* so operators can alert on
	// validation-failure rates without inflating ok totals.
	ms.forwardedHeaders, err = m.Int64Counter("defenseclaw.gateway.forwarded_headers",
		metric.WithUnit("{header}"),
		metric.WithDescription("Inbound HTTP headers forwarded from the agent to the upstream LLM provider (path=chat-completions|passthrough, result=ok|rejected_invalid|rejected_overflow)"))
	if err != nil {
		return nil, err
	}

	// External integrations — sink health
	ms.sinkBatchesDelivered, err = m.Int64Counter("defenseclaw.audit.sink.batches.delivered",
		metric.WithUnit("{batch}"),
		metric.WithDescription("Audit sink batches acknowledged by remote"))
	if err != nil {
		return nil, err
	}
	ms.sinkBatchesDropped, err = m.Int64Counter("defenseclaw.audit.sink.batches.dropped",
		metric.WithUnit("{batch}"),
		metric.WithDescription("Audit sink batches dropped due to queue or circuit breaker"))
	if err != nil {
		return nil, err
	}
	ms.sinkQueueDepth, err = m.Int64UpDownCounter("defenseclaw.audit.sink.queue.depth",
		metric.WithUnit("{event}"),
		metric.WithDescription("Audit sink in-memory queue depth"))
	if err != nil {
		return nil, err
	}
	ms.sinkDeliveryLatency, err = m.Float64Histogram("defenseclaw.audit.sink.delivery.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("Audit sink per-batch delivery latency"))
	if err != nil {
		return nil, err
	}
	ms.sinkCircuitState, err = m.Int64UpDownCounter("defenseclaw.audit.sink.circuit.state",
		metric.WithUnit("1"),
		metric.WithDescription("Audit sink circuit breaker state (0=closed, 1=open, 2=half-open)"))
	if err != nil {
		return nil, err
	}

	// v7 instruments — HTTP / security events
	ms.httpAuthFailures, err = m.Int64Counter("defenseclaw.http.auth.failures",
		metric.WithUnit("{failure}"),
		metric.WithDescription("HTTP authentication failures by route + reason"))
	if err != nil {
		return nil, err
	}
	ms.httpRateLimitBreaches, err = m.Int64Counter("defenseclaw.http.rate_limit.breaches",
		metric.WithUnit("{breach}"),
		metric.WithDescription("HTTP rate limit breaches by route"))
	if err != nil {
		return nil, err
	}
	ms.webhookDispatches, err = m.Int64Counter("defenseclaw.webhook.dispatches",
		metric.WithUnit("{dispatch}"),
		metric.WithDescription("Webhook dispatches attempted by webhook kind"))
	if err != nil {
		return nil, err
	}
	ms.webhookFailures, err = m.Int64Counter("defenseclaw.webhook.failures",
		metric.WithUnit("{failure}"),
		metric.WithDescription("Webhook dispatch failures by webhook kind + reason"))
	if err != nil {
		return nil, err
	}
	ms.webhookLatency, err = m.Float64Histogram("defenseclaw.webhook.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("Webhook dispatch latency distribution"))
	if err != nil {
		return nil, err
	}

	sloMsBuckets := []float64{50, 100, 250, 500, 1000, 2000, 5000, 10000}

	// genericMsBuckets covers the broad latency range used by most
	// histograms in this package (handler latency, scan duration,
	// discovery scan duration, etc.). It biases towards sub-second
	// but extends out to a minute so a hung scanner is still visible
	// on dashboards before falling off the right edge.
	genericMsBuckets := []float64{
		1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, 60000,
	}

	// v7 instruments — capacity / SLO + process-health gauges (absolute snapshots).
	ms.goroutines, err = m.Int64Gauge("defenseclaw.runtime.goroutines",
		metric.WithUnit("{goroutine}"),
		metric.WithDescription("Current goroutine count"))
	if err != nil {
		return nil, err
	}
	ms.heapAlloc, err = m.Int64Gauge("defenseclaw.runtime.heap.alloc",
		metric.WithUnit("By"),
		metric.WithDescription("Current heap allocation in bytes"))
	if err != nil {
		return nil, err
	}
	ms.heapObjects, err = m.Int64Gauge("defenseclaw.runtime.heap.objects",
		metric.WithUnit("{object}"),
		metric.WithDescription("Live heap objects (runtime.MemStats.HeapObjects)"))
	if err != nil {
		return nil, err
	}
	ms.gcPauseNs, err = m.Int64Histogram("defenseclaw.runtime.gc.pause",
		metric.WithUnit("ns"),
		metric.WithDescription("Go GC pause sample (P99 of recent pauses per tick)"))
	if err != nil {
		return nil, err
	}
	ms.fdInUse, err = m.Int64Gauge("defenseclaw.runtime.fd.in_use",
		metric.WithUnit("{fd}"),
		metric.WithDescription("File descriptors currently held by the sidecar"))
	if err != nil {
		return nil, err
	}
	ms.uptimeSeconds, err = m.Float64Gauge("defenseclaw.process.uptime_seconds",
		metric.WithUnit("s"),
		metric.WithDescription("Sidecar process uptime"))
	if err != nil {
		return nil, err
	}
	ms.sqliteDBBytes, err = m.Int64Gauge("defenseclaw.sqlite.db.bytes",
		metric.WithUnit("By"),
		metric.WithDescription("SQLite main database file size"))
	if err != nil {
		return nil, err
	}
	ms.sqliteWALBytes, err = m.Int64Gauge("defenseclaw.sqlite.wal.bytes",
		metric.WithUnit("By"),
		metric.WithDescription("SQLite WAL file size"))
	if err != nil {
		return nil, err
	}
	ms.sqlitePageCount, err = m.Int64Gauge("defenseclaw.sqlite.page_count",
		metric.WithUnit("{page}"),
		metric.WithDescription("SQLite PRAGMA page_count"))
	if err != nil {
		return nil, err
	}
	ms.sqliteFreelistCount, err = m.Int64Gauge("defenseclaw.sqlite.freelist_count",
		metric.WithUnit("{page}"),
		metric.WithDescription("SQLite PRAGMA freelist_count"))
	if err != nil {
		return nil, err
	}
	ms.sqliteCheckpointMs, err = m.Float64Histogram("defenseclaw.sqlite.checkpoint.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("SQLite PRAGMA wal_checkpoint(PASSIVE) duration"))
	if err != nil {
		return nil, err
	}
	ms.sqliteBusyRetries, err = m.Int64Counter("defenseclaw.sqlite.busy_retries",
		metric.WithUnit("{event}"),
		metric.WithDescription("SQLite SQLITE_BUSY events by operation"))
	if err != nil {
		return nil, err
	}
	ms.sloBlockLatency, err = m.Float64Histogram("defenseclaw.slo.block.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("Admission-block enforcement latency (SLO target: < 2000ms)"),
		metric.WithExplicitBucketBoundaries(sloMsBuckets...))
	if err != nil {
		return nil, err
	}
	ms.sloTUIRefresh, err = m.Float64Histogram("defenseclaw.slo.tui.refresh",
		metric.WithUnit("ms"),
		metric.WithDescription("TUI panel refresh latency (SLO target: < 5000ms)"),
		metric.WithExplicitBucketBoundaries(sloMsBuckets...))
	if err != nil {
		return nil, err
	}
	ms.queueDepthGauge, err = m.Int64Gauge("defenseclaw.queue.depth",
		metric.WithUnit("{item}"),
		metric.WithDescription("Current depth of a buffered queue"))
	if err != nil {
		return nil, err
	}
	ms.queueDrops, err = m.Int64Counter("defenseclaw.queue.drops",
		metric.WithUnit("{drop}"),
		metric.WithDescription("Events dropped due to full queue or backpressure"))
	if err != nil {
		return nil, err
	}
	ms.panicsTotal, err = m.Int64Counter("defenseclaw.panics.total",
		metric.WithUnit("{panic}"),
		metric.WithDescription("Recovered panics by subsystem"))
	if err != nil {
		return nil, err
	}
	ms.destinationSpans, err = m.Int64Counter("defenseclaw.telemetry.destination.spans",
		metric.WithUnit("{span}"),
		metric.WithDescription("Spans accepted or dropped by a named telemetry destination profile"))
	if err != nil {
		return nil, err
	}
	ms.destinationExports, err = m.Int64Counter("defenseclaw.telemetry.destination.exports",
		metric.WithUnit("{span}"),
		metric.WithDescription("Spans attempted, delivered, rejected, or failed by a named OTLP destination"))
	if err != nil {
		return nil, err
	}
	ms.telemetryExporterErrs, err = m.Int64Counter("defenseclaw.telemetry.exporter.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("OTel exporter or SDK errors by signal"))
	if err != nil {
		return nil, err
	}
	ms.exporterLastExportSec, err = m.Float64Gauge("defenseclaw.telemetry.exporter.last_export_ts",
		metric.WithUnit("s"),
		metric.WithDescription("Unix seconds of last successful metric export"))
	if err != nil {
		return nil, err
	}
	ms.tuiFilterApplied, err = m.Int64Counter("defenseclaw.tui.filter.applied",
		metric.WithUnit("{filter}"),
		metric.WithDescription("TUI panel filter applications (operator changed a filter chip or search)"))
	if err != nil {
		return nil, err
	}
	ms.judgeSemDepth, err = m.Int64UpDownCounter("defenseclaw.judge.semaphore.depth",
		metric.WithUnit("{slot}"),
		metric.WithDescription("Judge concurrency semaphore: slots currently held"))
	if err != nil {
		return nil, err
	}
	ms.judgeSemDrops, err = m.Int64Counter("defenseclaw.judge.semaphore.drops",
		metric.WithUnit("{drop}"),
		metric.WithDescription("Judge semaphore drops (queue full)"))
	if err != nil {
		return nil, err
	}

	ms.judgePersistDrops, err = m.Int64Counter("defenseclaw.judge.persist.drops",
		metric.WithUnit("{drop}"),
		metric.WithDescription("Judge bodies dropped before persistence (queue full)"))
	if err != nil {
		return nil, err
	}
	ms.judgePersistQueueDepth, err = m.Int64Gauge("defenseclaw.judge.persist.queue_depth",
		metric.WithUnit("{item}"),
		metric.WithDescription("Current depth of the async judge-persistence queue"))
	if err != nil {
		return nil, err
	}
	// Histogram buckets aligned with the 32-row max-batch policy in
	// JudgeStore.run(): they capture both bursty single-row commits
	// (latency-dominated) and full-batch commits (fsync-amortized)
	// so dashboards can distinguish the two regimes.
	ms.judgePersistBatchSize, err = m.Int64Histogram("defenseclaw.judge.persist.batch_size",
		metric.WithUnit("{row}"),
		metric.WithDescription("Rows committed per judge-persistence transaction"),
		metric.WithExplicitBucketBoundaries(1, 2, 4, 8, 16, 24, 32, 48, 64))
	if err != nil {
		return nil, err
	}

	// v7 instruments — Track 10 OTel logs + provenance
	ms.gatewayEventsEmitted, err = m.Int64Counter("defenseclaw.gateway.events.emitted",
		metric.WithUnit("{event}"),
		metric.WithDescription("Gateway events written through the writer choke point"))
	if err != nil {
		return nil, err
	}
	ms.provenanceBumps, err = m.Int64Counter("defenseclaw.provenance.bumps",
		metric.WithUnit("{bump}"),
		metric.WithDescription("Monotonic provenance generation bumps"))
	if err != nil {
		return nil, err
	}

	// Phase K4 — SSE streaming surface
	ms.streamLifecycle, err = m.Int64Counter("defenseclaw.stream.lifecycle",
		metric.WithUnit("{transition}"),
		metric.WithDescription("SSE/stream lifecycle transitions (open/close) per route/outcome"))
	if err != nil {
		return nil, err
	}
	ms.streamBytesSent, err = m.Int64Histogram("defenseclaw.stream.bytes_sent",
		metric.WithUnit("By"),
		metric.WithDescription("Bytes sent on an SSE/stream before close"))
	if err != nil {
		return nil, err
	}
	ms.streamDurationMs, err = m.Float64Histogram("defenseclaw.stream.duration_ms",
		metric.WithUnit("ms"),
		metric.WithDescription("Wall-clock duration of an SSE/stream from open to close"))
	if err != nil {
		return nil, err
	}
	ms.redactionsApplied, err = m.Int64Counter("defenseclaw.redaction.applied",
		metric.WithUnit("{redaction}"),
		metric.WithDescription("Guardrail/egress redactions applied by detector/field"))
	if err != nil {
		return nil, err
	}

	// External integrations — LLM bridge, OpenShell, Cisco, webhook
	ms.llmBridgeLatency, err = m.Float64Histogram("defenseclaw.llm_bridge.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("LiteLLM bridge call latency (Python subprocess)"))
	if err != nil {
		return nil, err
	}
	ms.openShellExit, err = m.Int64Counter("defenseclaw.openshell.exit",
		metric.WithUnit("{exit}"),
		metric.WithDescription("OpenShell subprocess exits by command and exit code"))
	if err != nil {
		return nil, err
	}
	ms.ciscoErrors, err = m.Int64Counter("defenseclaw.cisco.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Cisco AI Defense inspect errors by code"))
	if err != nil {
		return nil, err
	}
	ms.ciscoInspectLatency, err = m.Float64Histogram("defenseclaw.cisco_inspect.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("Cisco AI Defense HTTP inspect round-trip latency"))
	if err != nil {
		return nil, err
	}
	ms.webhookCooldownSuppressed, err = m.Int64Counter("defenseclaw.webhook.cooldown.suppressed",
		metric.WithUnit("{event}"),
		metric.WithDescription("Webhook dispatches suppressed by per-endpoint cooldown"))
	if err != nil {
		return nil, err
	}
	ms.webhookCircuitEvents, err = m.Int64Counter("defenseclaw.webhook.circuit_breaker",
		metric.WithUnit("{transition}"),
		metric.WithDescription("Webhook circuit breaker open/close transitions"))
	if err != nil {
		return nil, err
	}

	// Guardrail LLM judge + verdict cache
	ms.guardrailJudgeLatency, err = m.Float64Histogram("defenseclaw.guardrail.judge.latency",
		metric.WithUnit("ms"),
		metric.WithDescription("LLM judge invocation latency (cache miss path includes model round-trip)"),
	)
	if err != nil {
		return nil, err
	}
	ms.guardrailCacheHits, err = m.Int64Counter("defenseclaw.guardrail.cache.hits",
		metric.WithUnit("{hit}"),
		metric.WithDescription("Verdict cache hits by scanner/verdict/TTL bucket"),
	)
	if err != nil {
		return nil, err
	}
	ms.guardrailCacheMisses, err = m.Int64Counter("defenseclaw.guardrail.cache.misses",
		metric.WithUnit("{miss}"),
		metric.WithDescription("Verdict cache misses by scanner/verdict/TTL bucket"),
	)
	if err != nil {
		return nil, err
	}

	// Connector OTLP ingest receivers.
	ms.otelIngestRequests, err = m.Int64Counter("defenseclaw.otel.ingest.requests",
		metric.WithUnit("{request}"),
		metric.WithDescription("OTLP-HTTP requests accepted by the connector ingest receiver, by signal/source/result"),
	)
	if err != nil {
		return nil, err
	}
	ms.otelIngestRecords, err = m.Int64Counter("defenseclaw.otel.ingest.records",
		metric.WithUnit("{record}"),
		metric.WithDescription("Leaf records (logRecords|dataPoints|spans) extracted from inbound OTLP-JSON batches by signal/source"),
	)
	if err != nil {
		return nil, err
	}
	ms.otelIngestBytes, err = m.Int64Counter("defenseclaw.otel.ingest.bytes",
		metric.WithUnit("By"),
		metric.WithDescription("Total OTLP body bytes received by the connector ingest receiver, by signal/source"),
	)
	if err != nil {
		return nil, err
	}
	ms.otelIngestMalformed, err = m.Int64Counter("defenseclaw.otel.ingest.malformed",
		metric.WithUnit("{request}"),
		metric.WithDescription("OTLP-JSON bodies that failed to parse, by signal/source"),
	)
	if err != nil {
		return nil, err
	}
	ms.otelIngestLastSeen, err = m.Float64Gauge("defenseclaw.otel.ingest.last_seen_ts",
		metric.WithUnit("s"),
		metric.WithDescription("Unix-seconds timestamp of the most recent OTLP-HTTP batch accepted from a given source/signal. Used by the ConnectorTelemetrySilent alert."),
	)
	if err != nil {
		return nil, err
	}

	// Agent360 inventory and lifecycle metrics. The identity labels are
	// intentionally stable correlation IDs rather than request/trace IDs so a
	// newly observed agent appears in Grafana immediately and remains
	// selectable across executions and gateway restarts.
	ms.agentLastSeen, err = m.Float64Gauge("defenseclaw.agent.last_seen",
		metric.WithUnit("s"),
		metric.WithDescription("Unix seconds when an agent lifecycle transition was last observed."),
	)
	if err != nil {
		return nil, err
	}
	ms.agentLifecycleTransitions, err = m.Int64Counter("defenseclaw.agent.lifecycle.transitions",
		metric.WithUnit("{transition}"),
		metric.WithDescription("Agent lifecycle transitions by stable identity, execution, event, and state."),
	)
	if err != nil {
		return nil, err
	}
	ms.agentPhaseCurrent, err = m.Int64Gauge("defenseclaw.agent.phase.current",
		metric.WithUnit("1"),
		metric.WithDescription("Current execution phase encoded as a stable integer for state timelines."),
	)
	if err != nil {
		return nil, err
	}
	ms.agentPhaseTransitions, err = m.Int64Counter("defenseclaw.agent.phase.transitions",
		metric.WithUnit("{transition}"),
		metric.WithDescription("Directed execution phase transitions by stable agent identity and execution."),
	)
	if err != nil {
		return nil, err
	}
	ms.agentReportedCost, err = m.Float64Gauge("defenseclaw.agent.reported_cost",
		metric.WithUnit("USD"),
		metric.WithDescription("Latest upstream-reported cumulative agent cost in USD; absent when the connector does not report cost."),
	)
	if err != nil {
		return nil, err
	}
	ms.agentTokenUsage, err = m.Int64Counter("defenseclaw.agent.token.usage",
		metric.WithUnit("{token}"),
		metric.WithDescription("Connector-reported input and output tokens attributed to an agent tree."),
	)
	if err != nil {
		return nil, err
	}

	ms.agentDiscoveryRuns, err = m.Int64Counter("defenseclaw.agent.discovery.runs",
		metric.WithUnit("{run}"),
		metric.WithDescription("On-demand local agent discovery reports accepted by the sidecar, by source/cache/result."),
	)
	if err != nil {
		return nil, err
	}
	ms.agentDiscoveryDuration, err = m.Float64Histogram("defenseclaw.agent.discovery.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Wall-clock duration of the CLI local agent discovery scan."),
		metric.WithExplicitBucketBoundaries(genericMsBuckets...),
	)
	if err != nil {
		return nil, err
	}
	ms.agentDiscoverySignals, err = m.Int64Counter("defenseclaw.agent.discovery.signals",
		metric.WithUnit("{signal}"),
		metric.WithDescription("Per-connector install signals reported by agent discovery."),
	)
	if err != nil {
		return nil, err
	}
	ms.agentDiscoveryInstalled, err = m.Int64Gauge("defenseclaw.agent.discovery.installed",
		metric.WithUnit("1"),
		metric.WithDescription("Latest discovered installed state for each connector (1 installed, 0 not installed)."),
	)
	if err != nil {
		return nil, err
	}
	ms.agentDiscoveryErrors, err = m.Int64Counter("defenseclaw.agent.discovery.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Version probe or discovery errors by connector and bounded reason."),
	)
	if err != nil {
		return nil, err
	}

	ms.aiDiscoveryRuns, err = m.Int64Counter("defenseclaw.ai.discovery.runs",
		metric.WithUnit("{run}"),
		metric.WithDescription("Continuous AI discovery scans completed by the sidecar."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiDiscoveryDuration, err = m.Float64Histogram("defenseclaw.ai.discovery.duration",
		metric.WithUnit("ms"),
		metric.WithDescription("Wall-clock duration of continuous AI discovery scans."),
		metric.WithExplicitBucketBoundaries(genericMsBuckets...),
	)
	if err != nil {
		return nil, err
	}
	ms.aiDiscoverySignals, err = m.Int64Counter("defenseclaw.ai.discovery.signals",
		metric.WithUnit("{signal}"),
		metric.WithDescription("AI usage signals observed by category/vendor/product/state."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiDiscoveryNewSignals, err = m.Int64Counter("defenseclaw.ai.discovery.new_signals",
		metric.WithUnit("{signal}"),
		metric.WithDescription("New or changed AI usage signals discovered."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiDiscoveryActiveSignals, err = m.Int64Gauge("defenseclaw.ai.discovery.active_signals",
		metric.WithUnit("{signal}"),
		metric.WithDescription("Latest active AI usage signal count."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiDiscoveryGoneSignals, err = m.Int64Counter("defenseclaw.ai.discovery.gone_signals",
		metric.WithUnit("{signal}"),
		metric.WithDescription("AI usage signals that disappeared from a full scan."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiDiscoveryErrors, err = m.Int64Counter("defenseclaw.ai.discovery.errors",
		metric.WithUnit("{error}"),
		metric.WithDescription("Continuous AI discovery detector errors by bounded detector/reason."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiDiscoveryFilesScanned, err = m.Int64Counter("defenseclaw.ai.discovery.files_scanned",
		metric.WithUnit("{file}"),
		metric.WithDescription("Package manifest and shell history files inspected by continuous AI discovery."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiDiscoveryDedupeSuppressed, err = m.Int64Counter("defenseclaw.ai.discovery.dedupe_suppressed",
		metric.WithUnit("{signal}"),
		metric.WithDescription("Duplicate AI discovery signals suppressed within a scan."),
	)
	if err != nil {
		return nil, err
	}

	// Component-level instruments. We use bounded labels
	// (ecosystem, name, identity_band, presence_band) so the
	// cardinality stays proportional to the discovered component
	// set, not to scan or signal volume. Score histograms expose
	// the calibrated confidence so operators can alert on drift
	// (e.g. "presence_band==very_low for >24h means the SDK was
	// removed without a redeploy").
	ms.aiComponentObservations, err = m.Int64Counter("defenseclaw.ai.components.observations",
		metric.WithUnit("{observation}"),
		metric.WithDescription("Per-(ecosystem,name) confidence emissions; one increment per scan that produced a component rollup."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiComponentInstalls, err = m.Int64Gauge("defenseclaw.ai.components.installs",
		metric.WithUnit("{install}"),
		metric.WithDescription("Distinct install evidences per component as of the last scan."),
	)
	if err != nil {
		return nil, err
	}
	ms.aiComponentWorkspaces, err = m.Int64Gauge("defenseclaw.ai.components.workspaces",
		metric.WithUnit("{workspace}"),
		metric.WithDescription("Distinct workspaces a component appears in as of the last scan."),
	)
	if err != nil {
		return nil, err
	}
	// Bucket boundaries explicitly tuned for [0,1] confidence scores.
	// Without this override, the OTel SDK falls back to the default
	// latency-shaped boundaries (0, 5, 10, 25, …, 10000, +Inf), which
	// puts every confidence sample in the le=5.0 bucket and makes
	// `histogram_quantile(...)` flat-line at zero on dashboards. The
	// granularity below mirrors the bands the engine itself surfaces
	// (very_low / low / medium / high / very_high) so band thresholds
	// stay queryable directly off the bucket counts.
	confidenceBuckets := []float64{0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0}
	ms.aiConfidenceIdentity, err = m.Float64Histogram("defenseclaw.ai.confidence.identity_score",
		metric.WithUnit("1"),
		metric.WithDescription("Two-axis Bayesian engine identity score in [0,1] per component, per scan."),
		metric.WithExplicitBucketBoundaries(confidenceBuckets...),
	)
	if err != nil {
		return nil, err
	}
	ms.aiConfidencePresence, err = m.Float64Histogram("defenseclaw.ai.confidence.presence_score",
		metric.WithUnit("1"),
		metric.WithDescription("Two-axis Bayesian engine presence score in [0,1] per component, per scan."),
		metric.WithExplicitBucketBoundaries(confidenceBuckets...),
	)
	if err != nil {
		return nil, err
	}

	// Codex notify (agent-turn-complete et al.). Avoid `.total` in
	// the meter name because the OTel→Prom exporter appends `_total`
	// to counter metric names automatically; "defenseclaw.codex.notify"
	// becomes the canonical "defenseclaw_codex_notify_total" in the
	// scraped exposition format.
	ms.codexNotifyTotal, err = m.Int64Counter("defenseclaw.codex.notify",
		metric.WithUnit("{event}"),
		metric.WithDescription("Codex notify events received via the notify-bridge shim, labelled by type/status"),
	)
	if err != nil {
		return nil, err
	}
	ms.codexNotifyMalformed, err = m.Int64Counter("defenseclaw.codex.notify.malformed",
		metric.WithUnit("{event}"),
		metric.WithDescription("Codex notify payloads that failed to parse"),
	)
	if err != nil {
		return nil, err
	}

	return &ms, nil
}

// RecordScan records scan-related metrics. connector is the originating
// connector when the scan ran in a connector-scoped context; "" records
// connector="unknown" on the scan-findings total so the label stays present.
