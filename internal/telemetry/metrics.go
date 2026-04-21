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
	"time"

	"go.opentelemetry.io/otel/attribute"
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
func (p *Provider) RecordLLMTokens(ctx context.Context, operationName, providerName, model, agentName string, prompt, completion int64) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	commonAttrs := []attribute.KeyValue{
		attribute.String("gen_ai.operation.name", operationName),
		attribute.String("gen_ai.provider.name", providerName),
		attribute.String("gen_ai.request.model", model),
	}
	if agentName != "" {
		commonAttrs = append(commonAttrs, attribute.String("gen_ai.agent.name", agentName))
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
func (p *Provider) RecordLLMDuration(ctx context.Context, operationName, providerName, model, agentName string, durationSeconds float64) {
	if !p.Enabled() || p.metrics == nil {
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

// RecordSinkBatch is DEPRECATED and intentionally a no-op.
//
// It used to emit defenseclaw.audit.sink.batches.{delivered,dropped}
// with attributes sink.kind / sink.name / outcome, while the
// currently-wired code path (RecordSinkBatchDelivered /
// RecordSinkBatchFailed, called from internal/audit/logger_sink.go)
// emits the same counters with attributes sink / kind / status_code /
// retry_count. If both coexisted the metrics backend would split into
// two incompatible label shapes for a single counter, which breaks
// recording rules in deploy/observability/prometheus/rules/recording.yml
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
func (p *Provider) RecordOpenShellExit(ctx context.Context, command string, exitCode int) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	p.metrics.openShellExit.Add(ctx, 1, metric.WithAttributes(
		attribute.String("command", command),
		attribute.Int("exit_code", exitCode),
	))
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
