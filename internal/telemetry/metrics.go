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
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
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

	// Structured gateway event metrics (Phase 2.4). These derive
	// entirely from gatewaylog.Event envelopes so the writer's
	// fanout drives the whole pipeline — callers never touch the
	// meter directly.
	verdictsTotal    metric.Int64Counter
	judgeInvocations metric.Int64Counter
	judgeLatency     metric.Float64Histogram
	judgeErrors      metric.Int64Counter
	gatewayErrors    metric.Int64Counter
	sinkSendFailures metric.Int64Counter

	// v7 observability (Track 0 pre-allocation). Declared here so
	// parallel tracks (1-10) do not touch metricsSet; each track's
	// writers call the corresponding Record* method below.
	//
	// Track 1/2/3 (scanner observability)
	scanFindingsByRule metric.Int64Counter // per-scanner/rule_id
	scannerQueueDepth  metric.Int64UpDownCounter
	quarantineActions  metric.Int64Counter // op + result (Track 2)
	// Track 6 (activity tracking)
	activityTotal       metric.Int64Counter
	activityDiffEntries metric.Int64Histogram

	// v7.1 — egress (Layer 3 silent-bypass observability).
	// Labels: branch (known|shape|passthrough), decision (allow|block),
	// source (go|ts). Kept low-cardinality so Prometheus recording
	// rules can roll this up per-branch without blowing up TSDB.
	egressEvents metric.Int64Counter
	// Track 7 (external integrations — sink health)
	sinkBatchesDelivered metric.Int64Counter
	sinkBatchesDropped   metric.Int64Counter
	sinkQueueDepth       metric.Int64UpDownCounter
	sinkDeliveryLatency  metric.Float64Histogram
	sinkCircuitState     metric.Int64UpDownCounter
	// Track 8 (HTTP/security events beyond RecordHTTPRequest)
	httpAuthFailures      metric.Int64Counter
	httpRateLimitBreaches metric.Int64Counter
	webhookDispatches     metric.Int64Counter
	webhookFailures       metric.Int64Counter
	webhookLatency        metric.Float64Histogram
	// Track 9 (capacity/SLO) — gauges record absolute snapshots on each tick.
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
	// Track 7 — queue backpressure (generic; sink/scanner paths call RecordQueueDepth).
	queueDepthGauge metric.Int64Gauge
	queueDrops      metric.Int64Counter
	// Track 7 — process health
	panicsTotal           metric.Int64Counter
	telemetryExporterErrs metric.Int64Counter
	exporterLastExportSec metric.Float64Gauge
	tuiFilterApplied      metric.Int64Counter
	judgeSemDepth         metric.Int64UpDownCounter
	judgeSemDrops         metric.Int64Counter
	// Track 10 (OTel log records + provenance fanout)
	gatewayEventsEmitted metric.Int64Counter
	provenanceBumps      metric.Int64Counter

	// Track 1 / K4 — SSE streaming lifecycle telemetry
	streamLifecycle   metric.Int64Counter
	streamBytesSent   metric.Int64Histogram
	streamDurationMs  metric.Float64Histogram
	redactionsApplied metric.Int64Counter

	// Track 3 (guardrail LLM judge + verdict cache)
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
	agentDiscoveryRuns      metric.Int64Counter
	agentDiscoveryDuration  metric.Float64Histogram
	agentDiscoverySignals   metric.Int64Counter
	agentDiscoveryInstalled metric.Int64Gauge
	agentDiscoveryErrors    metric.Int64Counter

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

	// Track 6 (LLM bridge, OpenShell, Cisco, webhook circuit / cooldown)
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

	// v7 instruments — Track 1/2/3 scanner observability
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

	// v7 instruments — Track 6 activity tracking
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

	// v7 instruments — Track 7 external integrations
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

	// v7 instruments — Track 8 HTTP/security
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

	// v7 instruments — Track 9 capacity/SLO + Track 7 (gauges = absolute snapshots).
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

	// Track 6 — external integrations
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

	// Track 3 — guardrail judge + verdict cache
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
		attribute.String("gen_ai.tool.name", tool),
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
		attribute.String("gen_ai.tool.name", tool),
		attribute.String("tool.provider", provider),
	))
}

// RecordToolError records a tool error metric.
func (p *Provider) RecordToolError(ctx context.Context, tool string, exitCode int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.toolErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("gen_ai.tool.name", tool),
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
//
// agentName is the human-readable logical agent name ("openclaw",
// "sample-agent", …). agentID is the bounded deployment-scoped agent
// identifier (e.g. the claw-mode agent key). Both are omitted from
// metric attributes when empty so pre-v7 callers do not inflate the
// series count — see docs/OTEL-IMPLEMENTATION-STATUS.md for the
// cardinality contract.
func (p *Provider) RecordLLMTokens(ctx context.Context, operationName, providerName, model, agentName, agentID string, prompt, completion int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	if prompt > 0 {
		p.RecordLLMTokenUsage(ctx, operationName, providerName, model, agentName, agentID, "input", prompt)
	}
	if completion > 0 {
		p.RecordLLMTokenUsage(ctx, operationName, providerName, model, agentName, agentID, "output", completion)
	}
}

// RecordLLMTokenUsage records one token-usage data point with an explicit
// token type. It is used for connector-native counters such as Claude Code's
// cacheRead/cacheCreation token categories, while RecordLLMTokens preserves
// the common input/output call-site contract.
func (p *Provider) RecordLLMTokenUsage(ctx context.Context, operationName, providerName, model, agentName, agentID, tokenType string, tokens int64) {
	if !p.Enabled() || p.metrics == nil || tokens <= 0 {
		return
	}
	tokenType = strings.TrimSpace(tokenType)
	if tokenType == "" {
		tokenType = "unknown"
	}
	commonAttrs := []attribute.KeyValue{
		attribute.String("gen_ai.operation.name", operationName),
		attribute.String("gen_ai.provider.name", providerName),
		attribute.String("gen_ai.request.model", model),
	}
	if agentName != "" {
		commonAttrs = append(commonAttrs, attribute.String("gen_ai.agent.name", agentName))
	}
	if agentID != "" {
		commonAttrs = append(commonAttrs, attribute.String("gen_ai.agent.id", agentID))
	}
	attrs := append([]attribute.KeyValue{attribute.String("gen_ai.token.type", tokenType)}, commonAttrs...)
	p.metrics.genAITokenUsage.Record(ctx, float64(tokens), metric.WithAttributes(attrs...))
}

// RecordLLMDuration records LLM call duration per OTel GenAI semconv.
// gen_ai.client.operation.duration histogram, unit=seconds. See
// RecordLLMTokens for the agentName / agentID cardinality contract.
func (p *Provider) RecordLLMDuration(ctx context.Context, operationName, providerName, model, agentName, agentID string, durationSeconds float64) {
	if !p.Enabled() || p.metrics == nil || durationSeconds <= 0 {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.operation.name", operationName),
		attribute.String("gen_ai.provider.name", providerName),
		attribute.String("gen_ai.request.model", model),
	}
	if agentName != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.name", agentName))
	}
	if agentID != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.id", agentID))
	}
	p.metrics.genAIOperationDuration.Record(ctx, durationSeconds, metric.WithAttributes(attrs...))
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

// RecordConnectorHookInvocation records a hook request that reached the
// gateway. Client-side spawn failures happen before this point, but this metric
// gives dashboards a durable count of handled hooks, gateway rejections, and
// handler latency.
func (p *Provider) RecordConnectorHookInvocation(ctx context.Context, connector, eventType, result, reason string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	connector = strings.TrimSpace(connector)
	if connector == "" {
		connector = "unknown"
	}
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		eventType = "unknown"
	}
	result = strings.TrimSpace(result)
	if result == "" {
		result = "unknown"
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "none"
	}
	attrs := []attribute.KeyValue{
		attribute.String("connector", connector),
		attribute.String("event_type", eventType),
		attribute.String("result", result),
		attribute.String("reason", reason),
	}
	p.metrics.hookInvocations.Add(ctx, 1, metric.WithAttributes(attrs...))
	p.metrics.hookLatency.Record(ctx, durationMs, metric.WithAttributes(attrs...))
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

// RecordConfigLoadError records a config load or validation error and emits
// a structured gateway EventError when logs export is enabled.
func (p *Provider) RecordConfigLoadError(ctx context.Context, errorType string) {
	if p == nil || !p.Enabled() {
		return
	}
	if p.metrics != nil {
		p.metrics.configLoadErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("error_type", errorType),
		))
	}
	p.emitConfigLoadFailure(ctx, errorType)
}

// RecordSchemaViolation increments the runtime JSON-schema violation
// counter. Called from gatewaylog.Writer every time the strict-mode
// gate drops an event. eventType is the event_type of the dropped
// event (may be empty for truly malformed envelopes); code is the
// short identifier from gatewaylog.ErrorCode. The OTel counter is
// labelled with both so operators can pinpoint "which subsystem is
// producing bad scan_finding rows" directly from PromQL.
func (p *Provider) RecordSchemaViolation(ctx context.Context, eventType, code string) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	if eventType == "" {
		eventType = "unknown"
	}
	if code == "" {
		code = "UNKNOWN"
	}
	p.metrics.schemaViolations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("event_type", eventType),
		attribute.String("code", code),
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

// RecordSinkFailure is called by audit-sink implementations when a
// send attempt fails permanently (after retries). Kept on Provider
// so sinks can reuse the shared meter without each sink building
// its own.
func (p *Provider) RecordSinkFailure(sinkKind, sinkName, reason string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.sinkSendFailures.Add(context.Background(), 1,
		metric.WithAttributes(
			attribute.String("sink.kind", sinkKind),
			attribute.String("sink.name", sinkName),
			attribute.String("sink.reason", reason),
		))
}

// ==========================================================================
// v7 observability Record* methods (Track 0 pre-allocation).
//
// Each method is implemented here with a safe no-op fast path so
// parallel tracks (1-10) can call them immediately without waiting
// for Track 0 to merge. If p or p.metrics is nil (OTel disabled)
// the call is free.
//
// Parallel tracks MUST NOT add new fields to metricsSet; add your
// new calls here by editing this block only.
// ==========================================================================

// RecordScanFindingByRule is called once per finding so dashboards
// can rank hot rules per scanner/severity. The body is small
// enough that Track 1/2/3 can call this from within their emit
// loops without worrying about hot-path cost.
func (p *Provider) RecordScanFindingByRule(ctx context.Context, scanner, ruleID, severity string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.scanFindingsByRule.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scanner", scanner),
		attribute.String("rule_id", ruleID),
		attribute.String("severity", severity),
	))
}

// RecordScannerLatency records defenseclaw.scan.duration with scanner only.
func (p *Provider) RecordScannerLatency(ctx context.Context, scanner string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.scanDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("scanner", scanner),
	))
}

// RecordQuarantineAction records a quarantine or restore filesystem operation.
// op is one of move_in, move_out, restore; result is ok or error.
func (p *Provider) RecordQuarantineAction(ctx context.Context, op, result string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.quarantineActions.Add(ctx, 1, metric.WithAttributes(
		attribute.String("quarantine.op", op),
		attribute.String("quarantine.result", result),
	))
}

// RecordScannerQueueDepth updates the pending-scanner-jobs gauge.
// Positive delta on enqueue, negative on dequeue. Used by the
// skill/plugin/mcp scanner supervisors.
func (p *Provider) RecordScannerQueueDepth(ctx context.Context, scanner string, delta int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.scannerQueueDepth.Add(ctx, delta, metric.WithAttributes(
		attribute.String("scanner", scanner),
	))
}

// RecordActivity records an operator mutation metric. Counterpart
// for EventActivity emitted by Track 6.
func (p *Provider) RecordActivity(ctx context.Context, action, targetType, actor string, diffEntries int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("action", action),
		attribute.String("target_type", targetType),
		attribute.String("actor", actor),
	)
	p.metrics.activityTotal.Add(ctx, 1, attrs)
	p.metrics.activityDiffEntries.Record(ctx, int64(diffEntries), attrs)
}

// RecordEgress increments the v7.1 egress counter with a small,
// bounded label set so downstream Prometheus/OTLP pipelines can
// alert on "shape-branch block surge" without TSDB cardinality
// explosions. Callers MUST pass the enum values defined in
// gatewaylog.EgressPayload (branch=known|shape|passthrough,
// decision=allow|block, source=go|ts); malformed labels are
// accepted but should fail the shape_test.go validator.
func (p *Provider) RecordEgress(ctx context.Context, branch, decision, source string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.egressEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("branch", branch),
		attribute.String("decision", decision),
		attribute.String("source", source),
	))
}

// RecordSinkBatch is DEPRECATED and intentionally a no-op.
//
// It used to emit defenseclaw.audit.sink.batches.{delivered,dropped}
// with attributes sink.kind / sink.name / outcome, while the
// currently-wired code path (RecordSinkBatchDelivered /
// RecordSinkBatchFailed, called from internal/audit/logger_sink.go)
// emits the same counters with attributes sink / kind / status_code /
// retry_count. If both coexisted the metrics backend would split into
// two incompatible label shapes for a single counter, which breaks
// recording rules in bundles/local_observability_stack/prometheus/rules/recording.yml
// (sink:defenseclaw_audit_sink_drop_ratio:5m groups by `sink`, not
// `sink_kind` / `sink_name`).
//
// Keeping the symbol so external callers compile, but explicitly
// dropping the write so we can never reintroduce the split-series bug
// by accident. Callers should migrate to RecordSinkBatchDelivered or
// RecordSinkBatchFailed.
func (p *Provider) RecordSinkBatch(ctx context.Context, sinkKind, sinkName, outcome string, latencyMs float64) {
	_ = ctx
	_ = sinkKind
	_ = sinkName
	_ = outcome
	_ = latencyMs
}

// RecordSinkBatchDelivered records a successful audit-sink delivery with
// HTTP status_code and retry_count dimensions (v7 Track 5).
func (p *Provider) RecordSinkBatchDelivered(ctx context.Context, sinkName, sinkKind string, statusCode, retryCount int, latencyMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("sink", sinkName),
		attribute.String("kind", sinkKind),
		attribute.Int("status_code", statusCode),
		attribute.Int("retry_count", retryCount),
	)
	p.metrics.sinkBatchesDelivered.Add(ctx, 1, attrs)
	p.metrics.sinkDeliveryLatency.Record(ctx, latencyMs, attrs)
}

// RecordSinkBatchFailed records a failed audit-sink delivery (v7 Track 5).
func (p *Provider) RecordSinkBatchFailed(ctx context.Context, sinkName, sinkKind string, statusCode, retryCount int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.sinkBatchesDropped.Add(ctx, 1, metric.WithAttributes(
		attribute.String("sink", sinkName),
		attribute.String("kind", sinkKind),
		attribute.Int("status_code", statusCode),
		attribute.Int("retry_count", retryCount),
	))
}

// RecordActivityTotal is an alias for RecordActivity (Track 0 instrument name).
func (p *Provider) RecordActivityTotal(ctx context.Context, action, targetType, actor string, diffEntries int) {
	p.RecordActivity(ctx, action, targetType, actor, diffEntries)
}

// RecordSinkQueueDepth updates an audit sink's queue depth gauge.
func (p *Provider) RecordSinkQueueDepth(ctx context.Context, sinkKind, sinkName string, delta int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.sinkQueueDepth.Add(ctx, delta, metric.WithAttributes(
		attribute.String("sink.kind", sinkKind),
		attribute.String("sink.name", sinkName),
	))
}

// RecordSinkCircuitState updates the circuit breaker state for a
// sink. state must be 0 (closed), 1 (open), or 2 (half-open).
func (p *Provider) RecordSinkCircuitState(ctx context.Context, sinkKind, sinkName string, state int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	// UpDownCounter semantics: callers compute delta-from-last
	// internally; here we set via observation attribute.
	p.metrics.sinkCircuitState.Add(ctx, state, metric.WithAttributes(
		attribute.String("sink.kind", sinkKind),
		attribute.String("sink.name", sinkName),
	))
}

// RecordHTTPAuthFailure records a 401/403 response from the sidecar.
// Route is the matched router pattern, reason is a short enum string
// ("missing_token", "bad_signature", "expired", ...).
func (p *Provider) RecordHTTPAuthFailure(ctx context.Context, route, reason string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.httpAuthFailures.Add(ctx, 1, metric.WithAttributes(
		attribute.String("http.route", route),
		attribute.String("reason", reason),
	))
}

// RecordHTTPRateLimitBreach records a rate-limited HTTP request.
func (p *Provider) RecordHTTPRateLimitBreach(ctx context.Context, route, clientKind string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.httpRateLimitBreaches.Add(ctx, 1, metric.WithAttributes(
		attribute.String("http.route", route),
		attribute.String("client.kind", clientKind),
	))
}

// RecordWebhookDispatch records a webhook dispatch attempt (counters only).
// outcome: "delivered", "failed", "cooldown_suppressed", "circuit_open".
func (p *Provider) RecordWebhookDispatch(ctx context.Context, webhookKind, outcome string, latencyMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("webhook.kind", webhookKind),
		attribute.String("outcome", outcome),
	)
	p.metrics.webhookDispatches.Add(ctx, 1, attrs)
	if outcome != "delivered" {
		p.metrics.webhookFailures.Add(ctx, 1, attrs)
	}
	_ = latencyMs // latency recorded via RecordWebhookLatency for rich attributes
}

// RecordWebhookLatency records per-delivery latency on defenseclaw.webhook.latency
// with endpoint kind, target hash, and HTTP status (0 if unset / circuit skip).
func (p *Provider) RecordWebhookLatency(ctx context.Context, webhookKind, targetHash string, httpStatus int, latencyMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.webhookLatency.Record(ctx, latencyMs, metric.WithAttributes(
		attribute.String("webhook.kind", webhookKind),
		attribute.String("webhook.target_hash", targetHash),
		attribute.Int("http.status_code", httpStatus),
	))
}

// RecordWebhookCircuitBreaker records a circuit breaker state transition.
// state is "opened" or "closed".
func (p *Provider) RecordWebhookCircuitBreaker(ctx context.Context, targetHash, state string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.webhookCircuitEvents.Add(ctx, 1, metric.WithAttributes(
		attribute.String("webhook.target_hash", targetHash),
		attribute.String("state", state),
	))
}

// RecordWebhookCooldownSuppressed increments the cooldown suppression counter.
func (p *Provider) RecordWebhookCooldownSuppressed(ctx context.Context, webhookKind string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.webhookCooldownSuppressed.Add(ctx, 1, metric.WithAttributes(
		attribute.String("webhook.kind", webhookKind),
	))
}

// RecordLLMBridgeLatency records LiteLLM bridge duration (Python subprocess).
func (p *Provider) RecordLLMBridgeLatency(ctx context.Context, model, status string, durationMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.llmBridgeLatency.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("gen_ai.request.model", model),
		attribute.String("status", status),
	))
}

// RecordOpenShellExit records an OpenShell subprocess exit (non-zero typically).
//
// `command` is the program (NOT the full argv) that was launched; the
// caller MUST pass only the binary name or a stable identifier — the
// label is bounded here as a defense-in-depth via boundOpenShellCommand
// so a future caller passing the full user-supplied command line can't
// blow up Prometheus cardinality. Anything outside [a-z0-9._-] (case
// folded) is collapsed to "other".
func (p *Provider) RecordOpenShellExit(ctx context.Context, command string, exitCode int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.openShellExit.Add(ctx, 1, metric.WithAttributes(
		attribute.String("command", boundOpenShellCommand(command)),
		attribute.Int("exit_code", exitCode),
	))
}

// boundOpenShellCommand returns a low-cardinality label for a shell
// command. Only the first whitespace-separated token is considered
// (so `rm -rf /tmp/foo` collapses to `rm`), the value is lowercased,
// and any character outside the safe alphabet is replaced with `-`.
// Empty input becomes "unknown"; anything longer than 32 bytes after
// normalisation becomes "other" so a hostile / pathological binary
// name can't introduce thousands of new series.
func boundOpenShellCommand(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	if i := strings.IndexAny(s, " \t\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.ToLower(s)
	if len(s) > 32 {
		return "other"
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-' || c == '_' || c == '.':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "unknown"
	}
	return string(out)
}

// RecordCiscoError increments Cisco inspect errors by stable code.
func (p *Provider) RecordCiscoError(ctx context.Context, code string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.ciscoErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("code", code),
	))
}

// RecordCiscoInspectLatency records Cisco HTTP round-trip latency in
// ms with an operational outcome ("success" | "error" | "timeout" |
// "upstream-error" | ...). Outcome lets dashboards split p95 by
// failure mode — without it, a spike in error-path latency is
// indistinguishable from a genuine upstream slowdown.
func (p *Provider) RecordCiscoInspectLatency(ctx context.Context, durationMs float64, outcome string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	if outcome == "" {
		outcome = "success"
	}
	p.metrics.ciscoInspectLatency.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("outcome", outcome),
	))
}

// RuntimeMetrics is sampled by the capacity collector (15s ticker).
type RuntimeMetrics struct {
	Goroutines     int64
	HeapAllocBytes int64
	HeapObjects    int64
	GCPauseP99Ns   int64
	FDsOpen        int64
	UptimeSeconds  float64
}

// RecordRuntimeMetrics records point-in-time Go runtime gauges plus GC pause P99.
func (p *Provider) RecordRuntimeMetrics(ctx context.Context, m RuntimeMetrics) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.goroutines.Record(ctx, m.Goroutines)
	p.metrics.heapAlloc.Record(ctx, m.HeapAllocBytes)
	p.metrics.heapObjects.Record(ctx, m.HeapObjects)
	p.metrics.fdInUse.Record(ctx, m.FDsOpen)
	p.metrics.uptimeSeconds.Record(ctx, m.UptimeSeconds)
	if m.GCPauseP99Ns > 0 {
		p.metrics.gcPauseNs.Record(ctx, m.GCPauseP99Ns)
	}
}

// RecordRuntimeSnapshot is a compatibility alias for older call sites.
func (p *Provider) RecordRuntimeSnapshot(ctx context.Context, snapshot RuntimeSnapshot) {
	p.RecordRuntimeMetrics(ctx, RuntimeMetrics{
		Goroutines:     snapshot.Goroutines,
		HeapAllocBytes: snapshot.HeapAllocBytes,
		HeapObjects:    snapshot.HeapObjects,
		GCPauseP99Ns:   snapshot.GCPauseNs,
		FDsOpen:        snapshot.FDsInUse,
		UptimeSeconds:  snapshot.UptimeSeconds,
	})
}

// RuntimeSnapshot is the legacy capacity-collector payload (subset of RuntimeMetrics).
type RuntimeSnapshot struct {
	Goroutines     int64
	HeapAllocBytes int64
	HeapObjects    int64
	FDsInUse       int64
	SQLiteDBBytes  int64
	SQLiteWALBytes int64
	GCPauseNs      int64
	UptimeSeconds  float64
}

// SQLiteHealthMetrics carries PRAGMA-derived SQLite observations.
type SQLiteHealthMetrics struct {
	DBSizeBytes   int64
	WALSizeBytes  int64
	PageCount     int64
	FreelistCount int64
	CheckpointMs  float64
}

// RecordSQLiteHealth records SQLite file sizes, page stats, and checkpoint latency.
func (p *Provider) RecordSQLiteHealth(ctx context.Context, h SQLiteHealthMetrics) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.sqliteDBBytes.Record(ctx, h.DBSizeBytes)
	p.metrics.sqliteWALBytes.Record(ctx, h.WALSizeBytes)
	p.metrics.sqlitePageCount.Record(ctx, h.PageCount)
	p.metrics.sqliteFreelistCount.Record(ctx, h.FreelistCount)
	if h.CheckpointMs >= 0 {
		p.metrics.sqliteCheckpointMs.Record(ctx, h.CheckpointMs)
	}
}

// RecordQueueDepth records absolute depth for a named buffered queue.
func (p *Provider) RecordQueueDepth(ctx context.Context, queueName string, depth, capacity int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("queue", queueName),
		attribute.Int64("capacity", capacity),
	)
	p.metrics.queueDepthGauge.Record(ctx, depth, attrs)
}

// RecordQueueDropped increments the drop counter (e.g. queue full).
func (p *Provider) RecordQueueDropped(ctx context.Context, queueName, reason string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	if reason == "" {
		reason = "full"
	}
	p.metrics.queueDrops.Add(ctx, 1, metric.WithAttributes(
		attribute.String("queue", queueName),
		attribute.String("reason", reason),
	))
}

// ExporterHealthStatus is reported by the OTLP metric exporter wrapper.
type ExporterHealthStatus string

const (
	ExporterHealthSuccess ExporterHealthStatus = "success"
	ExporterHealthFailure ExporterHealthStatus = "failure"
)

// RecordExporterHealth records OTLP metric export outcomes and updates last-success timestamp.
func (p *Provider) RecordExporterHealth(ctx context.Context, exporter string, status ExporterHealthStatus) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	if status == ExporterHealthFailure {
		p.metrics.telemetryExporterErrs.Add(ctx, 1, metric.WithAttributes(
			attribute.String("exporter", exporter),
			attribute.String("signal", "metrics"),
		))
		p.emitExporterFailure(ctx, exporter)
		return
	}
	p.metrics.exporterLastExportSec.Record(ctx, float64(time.Now().Unix()), metric.WithAttributes(
		attribute.String("exporter", exporter),
		attribute.String("signal", "metrics"),
	))
}

// RecordPanic increments the panic counter and emits EventError.
func (p *Provider) RecordPanic(ctx context.Context, subsystem gatewaylog.Subsystem) {
	if p != nil && p.Enabled() && p.metrics != nil {
		p.metrics.panicsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("subsystem", string(subsystem)),
		))
	}
	if p != nil {
		p.emitPanicRecovered(ctx, subsystem)
	}
}

// RecordSLOBlockLatency records admission latency toward the <2000ms SLO.
func (p *Provider) RecordSLOBlockLatency(ctx context.Context, latencyMs float64) {
	p.RecordBlockSLO(ctx, "admission", latencyMs)
}

// RecordSLOTUIRefresh records TUI refresh latency toward the <5000ms SLO.
func (p *Provider) RecordSLOTUIRefresh(ctx context.Context, panel string, latencyMs float64) {
	p.RecordTUIRefreshSLO(ctx, panel, latencyMs)
}

// RecordSQLiteBusyRetry records a SQLITE_BUSY event (legacy name).
func (p *Provider) RecordSQLiteBusyRetry(ctx context.Context, operation string) {
	p.RecordSQLiteBusy(ctx, operation)
}

// RecordSQLiteBusy increments the busy counter and emits EventError.
func (p *Provider) RecordSQLiteBusy(ctx context.Context, operation string) {
	if !p.Enabled() || p.metrics == nil {
		p.emitSQLiteBusy(ctx, operation)
		return
	}
	p.metrics.sqliteBusyRetries.Add(ctx, 1, metric.WithAttributes(
		attribute.String("operation", operation),
	))
	p.emitSQLiteBusy(ctx, operation)
}

// RecordBlockSLO records admission-block enforcement latency.
// Histogram buckets are tuned around the 2000ms SLO target.
func (p *Provider) RecordBlockSLO(ctx context.Context, targetType string, latencyMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.sloBlockLatency.Record(ctx, latencyMs, metric.WithAttributes(
		attribute.String("target_type", targetType),
	))
}

// RecordTUIRefreshSLO records TUI panel refresh latency.
func (p *Provider) RecordTUIRefreshSLO(ctx context.Context, panel string, latencyMs float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.sloTUIRefresh.Record(ctx, latencyMs, metric.WithAttributes(
		attribute.String("panel", panel),
	))
}

// RecordTUIFilterApplied increments the filter-change counter used by
// dashboard panels (alerts, logs, skills, …).
func (p *Provider) RecordTUIFilterApplied(ctx context.Context, panel, filterType string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.tuiFilterApplied.Add(ctx, 1, metric.WithAttributes(
		attribute.String("panel", panel),
		attribute.String("filter_type", filterType),
	))
}

// RecordJudgeSemaphore updates the judge concurrency semaphore
// gauge. delta is +1 on acquire, -1 on release. Dropped callers
// also increment the drops counter.
func (p *Provider) RecordJudgeSemaphore(ctx context.Context, delta int64, dropped bool) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.judgeSemDepth.Add(ctx, delta)
	if dropped {
		p.metrics.judgeSemDrops.Add(ctx, 1)
	}
}

// RecordGatewayEventEmitted is called by the gatewaylog.Writer
// choke point exactly once per Emit. Used by Track 10 to compare
// emission rates against sink throughput.
func (p *Provider) RecordGatewayEventEmitted(ctx context.Context, eventType, severity string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.gatewayEventsEmitted.Add(ctx, 1, metric.WithAttributes(
		attribute.String("event_type", eventType),
		attribute.String("severity", severity),
	))
}

// RecordSSELifecycle emits stream lifecycle + duration + byte volume
// metrics when an SSE (or any long-poll) response finishes. `transition`
// should be "open" or "close"; the close transition is when duration
// and byte counters are also populated. Intended to be called from
// `internal/gateway/proxy.go::handleStreamingRequest` so the K4 contract
// is satisfied for every stream terminus.
func (p *Provider) RecordSSELifecycle(ctx context.Context, route, transition, outcome string, durationMs float64, bytesSent int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.streamLifecycle.Add(ctx, 1, metric.WithAttributes(
		attribute.String("http.route", route),
		attribute.String("transition", transition),
		attribute.String("outcome", outcome),
	))
	if transition == "close" {
		attrs := metric.WithAttributes(
			attribute.String("http.route", route),
			attribute.String("outcome", outcome),
		)
		p.metrics.streamDurationMs.Record(ctx, durationMs, attrs)
		if bytesSent >= 0 {
			p.metrics.streamBytesSent.Record(ctx, bytesSent, attrs)
		}
	}
}

// RecordRedactionApplied increments defenseclaw.redaction.applied
// once per redaction pass (Phase K2). Detector identifies which scanner
// or rule redacted; field identifies the JSON path being redacted.
func (p *Provider) RecordRedactionApplied(ctx context.Context, detector, field string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.redactionsApplied.Add(ctx, 1, metric.WithAttributes(
		attribute.String("detector", detector),
		attribute.String("field", field),
	))
}

// RecordProvenanceBump counts monotonic generation bumps. Spikes
// in this counter usually mean operators are thrashing config and
// SIEM dashboards that bucket by content_hash will see many rows.
func (p *Provider) RecordProvenanceBump(ctx context.Context, reason string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.provenanceBumps.Add(ctx, 1, metric.WithAttributes(
		attribute.String("reason", reason),
	))
}

// RecordJudgeLatency records defenseclaw.guardrail.judge.latency with model + kind.
func (p *Provider) RecordJudgeLatency(ctx context.Context, model, kind string, ms float64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.guardrailJudgeLatency.Record(ctx, ms, metric.WithAttributes(
		attribute.String("gen_ai.request.model", model),
		attribute.String("judge.kind", kind),
	))
}

// RecordJudgeTokens records per-direction token usage for judge calls (input vs output).
func (p *Provider) RecordJudgeTokens(ctx context.Context, model, direction string, tokens int64) {
	if !p.Enabled() || p.metrics == nil || tokens <= 0 {
		return
	}
	// direction must be "input" or "output" for the histogram bucket label.
	tokenType := direction
	if tokenType != "input" && tokenType != "output" {
		tokenType = "input"
	}
	p.metrics.genAITokenUsage.Record(ctx, float64(tokens), metric.WithAttributes(
		attribute.String("gen_ai.token.type", tokenType),
		attribute.String("gen_ai.operation.name", "judge"),
		attribute.String("gen_ai.request.model", model),
	))
}

// RecordGuardrailCacheHit records a verdict cache hit.
func (p *Provider) RecordGuardrailCacheHit(ctx context.Context, scanner, verdict, ttlBucket string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.guardrailCacheHits.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scanner", scanner),
		attribute.String("verdict", verdict),
		attribute.String("ttl_bucket", ttlBucket),
		attribute.String("cache", "verdict"),
	))
}

// RecordGuardrailCacheMiss records a verdict cache miss (before invoking the judge).
func (p *Provider) RecordGuardrailCacheMiss(ctx context.Context, scanner, verdictPlaceholder, ttlBucket string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.guardrailCacheMisses.Add(ctx, 1, metric.WithAttributes(
		attribute.String("scanner", scanner),
		attribute.String("verdict", verdictPlaceholder),
		attribute.String("ttl_bucket", ttlBucket),
		attribute.String("cache", "verdict"),
	))
}

// RecordOTelIngest records a single OTLP-HTTP batch the gateway
// accepted from a connector. Emits four
// time series per call:
//
//   - defenseclaw.otel.ingest.requests{signal,source,result} += 1
//   - defenseclaw.otel.ingest.records{signal,source}         += records
//   - defenseclaw.otel.ingest.bytes{signal,source}           += bodyBytes
//   - defenseclaw.otel.ingest.last_seen_ts{signal,source}    = now()
//
// `result` is "ok" on the happy path, "malformed" when the body
// failed to parse (records/bytes are still recorded so volume
// dashboards stay accurate even during schema drift). Cardinality
// is bounded: signal ∈ {logs,metrics,traces}, source is the
// sanitized x-defenseclaw-source header or path-token source, result ∈
// {ok,malformed}.
func (p *Provider) RecordOTelIngest(ctx context.Context, signal, source, result string, records, bodyBytes int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	if signal == "" {
		signal = "unknown"
	}
	if source == "" {
		source = "unknown"
	}
	if result == "" {
		result = "ok"
	}

	requestAttrs := metric.WithAttributes(
		attribute.String("signal", signal),
		attribute.String("source", source),
		attribute.String("result", result),
	)
	p.metrics.otelIngestRequests.Add(ctx, 1, requestAttrs)
	if result == "malformed" {
		p.metrics.otelIngestMalformed.Add(ctx, 1, metric.WithAttributes(
			attribute.String("signal", signal),
			attribute.String("source", source),
		))
	}

	volumeAttrs := metric.WithAttributes(
		attribute.String("signal", signal),
		attribute.String("source", source),
	)
	if records > 0 {
		p.metrics.otelIngestRecords.Add(ctx, records, volumeAttrs)
	}
	if bodyBytes > 0 {
		p.metrics.otelIngestBytes.Add(ctx, bodyBytes, volumeAttrs)
	}

	// last_seen is a Float64Gauge (Unix seconds). Recording a fresh
	// timestamp on every batch lets the ConnectorTelemetrySilent
	// alert page when a connector goes silent for >10m.
	p.metrics.otelIngestLastSeen.Record(ctx, float64(time.Now().Unix()), volumeAttrs)
}

// RecordAgentDiscovery records one on-demand agent discovery report accepted
// by the sidecar. The CLI sends only sanitized path booleans, basenames, and
// hashes; this method keeps labels low-cardinality so the metric can be safely
// enabled on developer workstations and CI.
func (p *Provider) RecordAgentDiscovery(ctx context.Context, source string, cacheHit bool, result string, durationMs float64, agentsTotal, installedTotal int) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	source = normalizeTelemetryLabel(source, "unknown")
	result = normalizeTelemetryLabel(result, "ok")
	attrs := metric.WithAttributes(
		attribute.String("source", source),
		attribute.Bool("cache_hit", cacheHit),
		attribute.String("result", result),
	)
	p.metrics.agentDiscoveryRuns.Add(ctx, 1, attrs)
	if durationMs >= 0 {
		p.metrics.agentDiscoveryDuration.Record(ctx, durationMs, attrs)
	}
}

// RecordAgentDiscoverySignal records a single connector signal within an
// accepted discovery report.
func (p *Provider) RecordAgentDiscoverySignal(ctx context.Context, connector string, installed, hasConfig, hasBinary bool, probeStatus string) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	connector = normalizeTelemetryLabel(connector, "unknown")
	probeStatus = normalizeTelemetryLabel(probeStatus, "unknown")
	attrs := metric.WithAttributes(
		attribute.String("connector", connector),
		attribute.Bool("installed", installed),
		attribute.Bool("has_config", hasConfig),
		attribute.Bool("has_binary", hasBinary),
		attribute.String("probe_status", probeStatus),
	)
	p.metrics.agentDiscoverySignals.Add(ctx, 1, attrs)
	installedValue := int64(0)
	if installed {
		installedValue = 1
	}
	p.metrics.agentDiscoveryInstalled.Record(ctx, installedValue, metric.WithAttributes(
		attribute.String("connector", connector),
	))
}

// RecordAgentDiscoveryError records a bounded version-probe or parse error
// class for a connector. The error reason is a class, not raw stderr.
func (p *Provider) RecordAgentDiscoveryError(ctx context.Context, connector, reason string) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	connector = normalizeTelemetryLabel(connector, "unknown")
	reason = normalizeTelemetryLabel(reason, "other")
	p.metrics.agentDiscoveryErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("connector", connector),
		attribute.String("reason", reason),
	))
}

// EmitAgentDiscoverySummaryLog emits one structured OTel log record per
// on-demand discovery run. It intentionally excludes local filesystem paths.
func (p *Provider) EmitAgentDiscoverySummaryLog(ctx context.Context, source string, cacheHit bool, result string, durationMs float64, agentsTotal, installedTotal int) {
	if !p.LogsEnabled() {
		return
	}
	source = normalizeTelemetryLabel(source, "unknown")
	result = normalizeTelemetryLabel(result, "ok")
	rec := otellog.Record{}
	now := time.Now()
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	if result == "ok" {
		rec.SetSeverity(otellog.SeverityInfo)
		rec.SetSeverityText("INFO")
	} else {
		rec.SetSeverity(otellog.SeverityWarn)
		rec.SetSeverityText("WARN")
	}
	rec.SetBody(otellog.StringValue("agent discovery"))
	rec.AddAttributes(
		otellog.String("event.name", "defenseclaw.agent.discovery"),
		otellog.String("event.domain", "defenseclaw.agent"),
		otellog.String("defenseclaw.agent.discovery.source", source),
		otellog.Bool("defenseclaw.agent.discovery.cache_hit", cacheHit),
		otellog.String("defenseclaw.agent.discovery.result", result),
		otellog.Int64("defenseclaw.agent.discovery.duration_ms", int64(durationMs)),
		otellog.Int64("defenseclaw.agent.discovery.agents_total", int64(agentsTotal)),
		otellog.Int64("defenseclaw.agent.discovery.installed_total", int64(installedTotal)),
	)
	p.logger.Emit(ctx, rec)
}

// EmitAgentDiscoverySignalLog emits one low-cardinality per-connector log
// record. It carries booleans and probe classes only; no raw local paths.
func (p *Provider) EmitAgentDiscoverySignalLog(ctx context.Context, connector string, installed, hasConfig, hasBinary bool, probeStatus string) {
	if !p.LogsEnabled() {
		return
	}
	connector = normalizeTelemetryLabel(connector, "unknown")
	probeStatus = normalizeTelemetryLabel(probeStatus, "unknown")
	rec := otellog.Record{}
	now := time.Now()
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetSeverityText("INFO")
	rec.SetBody(otellog.StringValue("agent discovery signal"))
	rec.AddAttributes(
		otellog.String("event.name", "defenseclaw.agent.discovery.signal"),
		otellog.String("event.domain", "defenseclaw.agent"),
		otellog.String("defenseclaw.agent.discovery.connector", connector),
		otellog.Bool("defenseclaw.agent.discovery.installed", installed),
		otellog.Bool("defenseclaw.agent.discovery.has_config", hasConfig),
		otellog.Bool("defenseclaw.agent.discovery.has_binary", hasBinary),
		otellog.String("defenseclaw.agent.discovery.probe_status", probeStatus),
	)
	p.logger.Emit(ctx, rec)
}

// RecordAIDiscoveryRun records one continuous AI visibility scan. Labels are
// bounded to avoid turning device inventory into a high-cardinality metric.
func (p *Provider) RecordAIDiscoveryRun(ctx context.Context, source, privacyMode, result string, durationMs float64, signalsTotal, activeTotal, newTotal, goneTotal, filesScanned, dedupeSuppressed int) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	source = normalizeTelemetryLabel(source, "sidecar")
	privacyMode = normalizeTelemetryLabel(privacyMode, "enhanced")
	result = normalizeTelemetryLabel(result, "ok")
	attrs := metric.WithAttributes(
		attribute.String("source", source),
		attribute.String("privacy_mode", privacyMode),
		attribute.String("result", result),
	)
	p.metrics.aiDiscoveryRuns.Add(ctx, 1, attrs)
	p.metrics.aiDiscoveryDuration.Record(ctx, durationMs, attrs)
	p.metrics.aiDiscoveryActiveSignals.Record(ctx, int64(activeTotal), metric.WithAttributes(
		attribute.String("source", source),
		attribute.String("privacy_mode", privacyMode),
	))
	if filesScanned > 0 {
		p.metrics.aiDiscoveryFilesScanned.Add(ctx, int64(filesScanned), attrs)
	}
	if dedupeSuppressed > 0 {
		p.metrics.aiDiscoveryDedupeSuppressed.Add(ctx, int64(dedupeSuppressed), attrs)
	}
	if newTotal > 0 {
		p.metrics.aiDiscoveryNewSignals.Add(ctx, int64(newTotal), attrs)
	}
	if goneTotal > 0 {
		p.metrics.aiDiscoveryGoneSignals.Add(ctx, int64(goneTotal), attrs)
	}
	_ = signalsTotal // summary count is carried in logs; signal counter is per-signal below.
}

// RecordAIDiscoverySignal records one sanitized AI usage signal.
func (p *Provider) RecordAIDiscoverySignal(ctx context.Context, category, vendor, product, state, detector string, confidence float64) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	attrs := metric.WithAttributes(
		attribute.String("signal.category", normalizeTelemetryLabel(category, "unknown")),
		attribute.String("ai.vendor", normalizeTelemetryLabel(vendor, "unknown")),
		attribute.String("ai.product", normalizeTelemetryLabel(product, "unknown")),
		attribute.String("state", normalizeTelemetryLabel(state, "seen")),
		attribute.String("detector", normalizeTelemetryLabel(detector, "unknown")),
		attribute.String("confidence", confidenceBucket(confidence)),
	)
	p.metrics.aiDiscoverySignals.Add(ctx, 1, attrs)
	if state == "new" || state == "changed" {
		p.metrics.aiDiscoveryNewSignals.Add(ctx, 1, attrs)
	}
	if state == "gone" {
		p.metrics.aiDiscoveryGoneSignals.Add(ctx, 1, attrs)
	}
}

func (p *Provider) RecordAIDiscoveryError(ctx context.Context, detector, reason string) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.aiDiscoveryErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("detector", normalizeTelemetryLabel(detector, "unknown")),
		attribute.String("reason", normalizeTelemetryLabel(reason, "other")),
	))
}

func (p *Provider) EmitAIDiscoverySummaryLog(ctx context.Context, source, privacyMode, result string, durationMs float64, signalsTotal, activeTotal, newTotal, goneTotal, filesScanned int) {
	if !p.LogsEnabled() {
		return
	}
	source = normalizeTelemetryLabel(source, "sidecar")
	privacyMode = normalizeTelemetryLabel(privacyMode, "enhanced")
	result = normalizeTelemetryLabel(result, "ok")
	rec := otellog.Record{}
	now := time.Now()
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	if result == "ok" {
		rec.SetSeverity(otellog.SeverityInfo)
		rec.SetSeverityText("INFO")
	} else {
		rec.SetSeverity(otellog.SeverityWarn)
		rec.SetSeverityText("WARN")
	}
	rec.SetBody(otellog.StringValue("continuous AI discovery"))
	rec.AddAttributes(
		otellog.String("event.name", "defenseclaw.ai.discovery"),
		otellog.String("event.domain", "defenseclaw.ai_visibility"),
		otellog.String("defenseclaw.ai.discovery.source", source),
		otellog.String("defenseclaw.ai.discovery.privacy_mode", privacyMode),
		otellog.String("defenseclaw.ai.discovery.result", result),
		otellog.Int64("defenseclaw.ai.discovery.duration_ms", int64(durationMs)),
		otellog.Int64("defenseclaw.ai.discovery.signals_total", int64(signalsTotal)),
		otellog.Int64("defenseclaw.ai.discovery.active_total", int64(activeTotal)),
		otellog.Int64("defenseclaw.ai.discovery.new_total", int64(newTotal)),
		otellog.Int64("defenseclaw.ai.discovery.gone_total", int64(goneTotal)),
		otellog.Int64("defenseclaw.ai.discovery.files_scanned", int64(filesScanned)),
	)
	p.logger.Emit(ctx, rec)
}

func (p *Provider) EmitAIDiscoverySignalLog(ctx context.Context, category, vendor, product, state, detector string, confidence float64) {
	if !p.LogsEnabled() {
		return
	}
	rec := otellog.Record{}
	now := time.Now()
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetSeverityText("INFO")
	rec.SetBody(otellog.StringValue("AI usage signal"))
	rec.AddAttributes(
		otellog.String("event.name", "defenseclaw.ai.discovery.signal"),
		otellog.String("event.domain", "defenseclaw.ai_visibility"),
		otellog.String("signal.category", normalizeTelemetryLabel(category, "unknown")),
		otellog.String("ai.vendor", normalizeTelemetryLabel(vendor, "unknown")),
		otellog.String("ai.product", normalizeTelemetryLabel(product, "unknown")),
		otellog.String("state", normalizeTelemetryLabel(state, "seen")),
		otellog.String("detector", normalizeTelemetryLabel(detector, "unknown")),
		otellog.String("confidence", confidenceBucket(confidence)),
	)
	p.logger.Emit(ctx, rec)
}

// AIComponentConfidenceAttrs is the bounded-label payload for one
// component-level confidence emission. We pass it as a struct so
// adding fields (e.g. policy_version) doesn't break call sites or
// silently swap argument order. Identity / presence bands are the
// operator-facing labels (very_high|high|medium|low|very_low) the
// engine produced; ecosystem and name are the dedupe key the
// /components endpoint groups on.
type AIComponentConfidenceAttrs struct {
	Ecosystem      string
	Name           string
	Framework      string
	IdentityScore  float64
	IdentityBand   string
	PresenceScore  float64
	PresenceBand   string
	InstallCount   int
	WorkspaceCount int
	PolicyVersion  int
	DetectorCount  int
}

// RecordAIComponentConfidence emits one bounded metric burst per
// component the gateway scored in the latest scan: a counter so
// "how many scans saw openai?" is queryable, two gauges for
// install / workspace fan-out, and two histograms for the
// identity/presence score distribution. Cardinality is bounded
// by the discovered component set (ecosystem + name only — bands
// are sub-attributes), which is independent of signal volume.
func (p *Provider) RecordAIComponentConfidence(ctx context.Context, attrs AIComponentConfidenceAttrs) {
	if p == nil || !p.Enabled() || p.metrics == nil {
		return
	}
	ecosystem := normalizeTelemetryLabel(attrs.Ecosystem, "unknown")
	name := normalizeTelemetryLabel(attrs.Name, "unknown")
	framework := normalizeTelemetryLabel(attrs.Framework, "unknown")
	identityBand := normalizeTelemetryLabel(attrs.IdentityBand, "unknown")
	presenceBand := normalizeTelemetryLabel(attrs.PresenceBand, "unknown")
	identity := clampUnitInterval(attrs.IdentityScore)
	presence := clampUnitInterval(attrs.PresenceScore)

	// Counter labels carry the bands so an operator can graph
	// "components in very_low presence band over time" without
	// pulling histogram percentiles. The gauge labels deliberately
	// drop the band so the value reflects the latest scan even
	// when the band changes between scans.
	counterAttrs := metric.WithAttributes(
		attribute.String("ecosystem", ecosystem),
		attribute.String("name", name),
		attribute.String("identity_band", identityBand),
		attribute.String("presence_band", presenceBand),
	)
	gaugeAttrs := metric.WithAttributes(
		attribute.String("ecosystem", ecosystem),
		attribute.String("name", name),
	)
	histogramAttrs := metric.WithAttributes(
		attribute.String("ecosystem", ecosystem),
		attribute.String("name", name),
		attribute.String("framework", framework),
	)

	p.metrics.aiComponentObservations.Add(ctx, 1, counterAttrs)
	p.metrics.aiComponentInstalls.Record(ctx, int64(attrs.InstallCount), gaugeAttrs)
	p.metrics.aiComponentWorkspaces.Record(ctx, int64(attrs.WorkspaceCount), gaugeAttrs)
	p.metrics.aiConfidenceIdentity.Record(ctx, identity, histogramAttrs)
	p.metrics.aiConfidencePresence.Record(ctx, presence, histogramAttrs)
}

// EmitAIComponentConfidenceLog records one structured log per
// scored component so SIEMs that only ingest the OTel logs stream
// (no metrics pipeline) still get the full identity/presence
// breakdown. Severity escalates to WARN when identity is high but
// presence dropped to very_low — the signature operators alert on
// for "the SDK was removed but the manifest is still around".
func (p *Provider) EmitAIComponentConfidenceLog(ctx context.Context, attrs AIComponentConfidenceAttrs) {
	if p == nil || !p.LogsEnabled() {
		return
	}
	identity := clampUnitInterval(attrs.IdentityScore)
	presence := clampUnitInterval(attrs.PresenceScore)
	identityBand := normalizeTelemetryLabel(attrs.IdentityBand, "unknown")
	presenceBand := normalizeTelemetryLabel(attrs.PresenceBand, "unknown")
	rec := otellog.Record{}
	now := time.Now()
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	if identity >= 0.7 && presence <= 0.2 {
		rec.SetSeverity(otellog.SeverityWarn)
		rec.SetSeverityText("WARN")
	} else {
		rec.SetSeverity(otellog.SeverityInfo)
		rec.SetSeverityText("INFO")
	}
	rec.SetBody(otellog.StringValue("AI component confidence"))
	rec.AddAttributes(
		otellog.String("event.name", "defenseclaw.ai.confidence.component"),
		otellog.String("event.domain", "defenseclaw.ai_visibility"),
		otellog.String("ai.component.ecosystem", normalizeTelemetryLabel(attrs.Ecosystem, "unknown")),
		otellog.String("ai.component.name", normalizeTelemetryLabel(attrs.Name, "unknown")),
		otellog.String("ai.component.framework", normalizeTelemetryLabel(attrs.Framework, "unknown")),
		otellog.Float64("ai.confidence.identity_score", identity),
		otellog.String("ai.confidence.identity_band", identityBand),
		otellog.Float64("ai.confidence.presence_score", presence),
		otellog.String("ai.confidence.presence_band", presenceBand),
		otellog.Int64("ai.component.install_count", int64(attrs.InstallCount)),
		otellog.Int64("ai.component.workspace_count", int64(attrs.WorkspaceCount)),
		otellog.Int64("ai.component.detector_count", int64(attrs.DetectorCount)),
		otellog.Int64("ai.confidence.policy_version", int64(attrs.PolicyVersion)),
	)
	p.logger.Emit(ctx, rec)
}

// clampUnitInterval normalizes the score histogram inputs so a
// rounding error in the engine (e.g. 1.0000000002) doesn't slip
// past the OTel histogram and skew the +Inf bucket. The engine
// already targets [0,1] but defense in depth here is cheap.
func clampUnitInterval(v float64) float64 {
	if v != v { // NaN — engine never produces this but guard anyway.
		return 0
	}
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func confidenceBucket(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "high"
	case confidence >= 0.7:
		return "medium"
	default:
		return "low"
	}
}

func normalizeTelemetryLabel(value, fallback string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		value = fallback
	}
	if len(value) > 80 {
		value = value[:80]
	}
	return value
}

// RecordCodexNotify records a single codex notify webhook event.
// `kind` is the sanitized notify type the action key uses
// ("agent-turn-complete", "unknown", "malformed"); `status` is
// the codex-supplied status string when present, "" otherwise.
// `result` is "ok" on parse success, "malformed" otherwise — we
// still increment the counter on malformed so dashboards see the
// volume even when the schema drifts.
func (p *Provider) RecordCodexNotify(ctx context.Context, kind, status, result string) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	if kind == "" {
		kind = "unknown"
	}
	if result == "" {
		result = "ok"
	}
	p.metrics.codexNotifyTotal.Add(ctx, 1, metric.WithAttributes(
		attribute.String("type", kind),
		attribute.String("status", status),
		attribute.String("result", result),
	))
	if result == "malformed" {
		p.metrics.codexNotifyMalformed.Add(ctx, 1, metric.WithAttributes(
			attribute.String("type", kind),
		))
	}
}

// EmitConnectorTelemetryLog emits an OTel log record summarizing an
// inbound OTLP-HTTP batch from a connector. The record routes
// through the gateway's own log pipeline (see
// internal/telemetry/provider.go::loggerProvider) and therefore
// lands in whatever OTel collector the operator has configured —
// in the local-observability-stack that's the bundled collector
// → Loki, giving operators direct visibility into connector
// telemetry without configuring an additional audit OTLP sink.
//
// The log body is short ("connector ingest …") because the
// structured fields carry the searchable signal; Loki indexes
// body and labels separately and we don't want to balloon the
// chunk store with verbose summaries.
//
// signal: logs|metrics|traces. source: registered connector name|unknown.
// result: ok|malformed. records is the leaf-record count the
// summarizer produced; bodyBytes is the request size; summary
// is the human-readable summary line the audit row also stores.
func (p *Provider) EmitConnectorTelemetryLog(ctx context.Context, signal, source, result string, records, bodyBytes int64, summary string) {
	if !p.LogsEnabled() {
		return
	}
	rec := otellog.Record{}
	now := time.Now()
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	if result == "malformed" {
		rec.SetSeverity(otellog.SeverityWarn)
		rec.SetSeverityText("WARN")
	} else {
		rec.SetSeverity(otellog.SeverityInfo)
		rec.SetSeverityText("INFO")
	}
	eventName := "defenseclaw.otel.ingest"
	body := "connector telemetry ingest"
	if signal == "hook" {
		eventName = "defenseclaw.hook.invocation"
		body = "connector hook invocation"
	}
	rec.SetBody(otellog.StringValue(body))
	rec.AddAttributes(
		otellog.String("event.name", eventName),
		otellog.String("event.domain", "defenseclaw.connector"),
		otellog.String("defenseclaw.otel.ingest.signal", signal),
		otellog.String("defenseclaw.otel.ingest.source", source),
		otellog.String("defenseclaw.otel.ingest.result", result),
		otellog.Int64("defenseclaw.otel.ingest.records", records),
		otellog.Int64("defenseclaw.otel.ingest.bytes", bodyBytes),
		otellog.String("defenseclaw.otel.ingest.summary", summary),
	)
	p.logger.Emit(ctx, rec)
}

// EmitCodexNotifyLog emits an OTel log record for one codex notify
// event. Routed through the same logger as connector telemetry so
// the local-stack's Loki sees turn-complete events alongside log
// records — no extra sink configuration required.
func (p *Provider) EmitCodexNotifyLog(ctx context.Context, kind, status, result, turnID, model string) {
	if !p.LogsEnabled() {
		return
	}
	rec := otellog.Record{}
	now := time.Now()
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	if result == "malformed" {
		rec.SetSeverity(otellog.SeverityWarn)
		rec.SetSeverityText("WARN")
	} else {
		rec.SetSeverity(otellog.SeverityInfo)
		rec.SetSeverityText("INFO")
	}
	rec.SetBody(otellog.StringValue("codex notify"))
	rec.AddAttributes(
		otellog.String("event.name", "defenseclaw.codex.notify"),
		otellog.String("event.domain", "defenseclaw.connector"),
		otellog.String("defenseclaw.codex.notify.type", kind),
		otellog.String("defenseclaw.codex.notify.status", status),
		otellog.String("defenseclaw.codex.notify.result", result),
		otellog.String("defenseclaw.codex.notify.turn_id", turnID),
		otellog.String("defenseclaw.codex.notify.model", model),
	)
	p.logger.Emit(ctx, rec)
}
