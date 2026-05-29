variable "create_detectors" {
  description = "Whether to create Splunk Observability detectors alongside the dashboards."
  type        = bool
  default     = true
}

variable "detectors_disabled" {
  description = "Create detector rules in a disabled state. Useful for dry-run rollout into an existing org."
  type        = bool
  default     = false
}

variable "detector_notifications" {
  description = "Notification targets for every detector rule, for example [\"Email,secops@example.com\"] or [\"Team,teamId\"]. Empty means detectors create O11y alerts/events without external notifications."
  type        = list(string)
  default     = []
}

locals {
  detectors = {
    schema_violations = {
      name             = "DefenseClaw - Schema violations"
      severity         = "Critical"
      detect_label     = "DefenseClawSchemaViolations"
      description      = "gateway.jsonl events are being dropped for schema violations."
      rule_description = "Runtime JSON schema validation is rejecting gateway events. Open Runtime and Reliability -> Schema violations by event type and code."
      tags             = ["correctness", "gateway"]
      program          = <<-EOT
        A = data('defenseclaw.schema.violations', rollup='rate').sum().scale(60).publish(label='Schema violations / min')
        detect(when(A > 0, '2m')).publish('DefenseClawSchemaViolations')
      EOT
    }
    gateway_errors_spike = {
      name             = "DefenseClaw - Gateway errors spike"
      severity         = "Warning"
      detect_label     = "DefenseClawGatewayErrorsSpike"
      description      = "Gateway error rate is above 30/min for 5 minutes."
      rule_description = "Structured gateway errors are sustained. Open Runtime and Reliability -> Gateway errors by subsystem and code."
      tags             = ["correctness", "gateway"]
      program          = <<-EOT
        A = data('defenseclaw.gateway.errors', rollup='rate').sum().scale(60).publish(label='Gateway errors / min')
        detect(when(A > 30, '5m')).publish('DefenseClawGatewayErrorsSpike')
      EOT
    }
    panic = {
      name             = "DefenseClaw - Panic recovered"
      severity         = "Critical"
      detect_label     = "DefenseClawPanic"
      description      = "A DefenseClaw subsystem panic was recovered."
      rule_description = "RecordPanic fired. Inspect Runtime and Reliability plus logs for the panic source."
      tags             = ["correctness", "runtime"]
      program          = <<-EOT
        A = data('defenseclaw.panics.total', rollup='rate').sum().scale(60).publish(label='Panics / min')
        detect(when(A > 0)).publish('DefenseClawPanic')
      EOT
    }
    block_slo_breach = {
      name             = "DefenseClaw - Block SLO p95 breach"
      severity         = "Critical"
      detect_label     = "DefenseClawBlockSLOBreach"
      description      = "Admission/block p95 latency is above 2s for 10 minutes."
      rule_description = "Admission-block decisions are exceeding the 2s latency target. Open Runtime and Reliability -> Block SLO latency p95."
      tags             = ["slo", "runtime"]
      program          = <<-EOT
        A = histogram('defenseclaw.slo.block.latency').percentile(pct=95).publish(label='p95 block SLO ms')
        detect(when(A > 2000, '10m')).publish('DefenseClawBlockSLOBreach')
      EOT
    }
    tui_refresh_slo_breach = {
      name             = "DefenseClaw - TUI refresh SLO p95 breach"
      severity         = "Warning"
      detect_label     = "DefenseClawTUIRefreshSLOBreach"
      description      = "TUI refresh p95 latency is above 5s for 15 minutes."
      rule_description = "TUI dashboards are refreshing slower than the 5s target. Open Runtime and Reliability -> TUI refresh latency p95."
      tags             = ["slo", "runtime"]
      program          = <<-EOT
        A = histogram('defenseclaw.slo.tui.refresh').percentile(pct=95).publish(label='p95 TUI refresh ms')
        detect(when(A > 5000, '15m')).publish('DefenseClawTUIRefreshSLOBreach')
      EOT
    }
    otlp_exporter_silent = {
      name             = "DefenseClaw - OTLP exporter silent"
      severity         = "Critical"
      detect_label     = "DefenseClawOTLPExporterStalled"
      description      = "OTLP exporter health stopped reporting for 5 minutes."
      rule_description = "Observability may be blind because exporter health is no longer reporting. Check OTel Collector and network reachability."
      tags             = ["pipeline", "telemetry"]
      program          = <<-EOT
        A = data('defenseclaw.telemetry.exporter.last_export_ts', rollup='latest').max(by=['exporter']).publish(label='Last export timestamp')
        detect(when(A is None, '5m')).publish('DefenseClawOTLPExporterStalled')
      EOT
    }
    otlp_exporter_errors = {
      name             = "DefenseClaw - OTLP exporter errors"
      severity         = "Warning"
      detect_label     = "DefenseClawOTLPExporterErrors"
      description      = "OTLP exporter errors are above 6/min for 10 minutes."
      rule_description = "Exporter errors are sustained; spans, metrics, or logs may be dropped. Open Runtime and Reliability -> Exporter errors by signal."
      tags             = ["pipeline", "telemetry"]
      program          = <<-EOT
        A = data('defenseclaw.telemetry.exporter.errors', rollup='rate').sum().scale(60).publish(label='Exporter errors / min')
        detect(when(A > 6, '10m')).publish('DefenseClawOTLPExporterErrors')
      EOT
    }
    audit_sink_failures = {
      name             = "DefenseClaw - Audit sink failures"
      severity         = "Critical"
      detect_label     = "DefenseClawAuditSinkFailures"
      description      = "A configured audit sink is failing above 6/min for 10 minutes."
      rule_description = "Compliance downstreams may be missing events. Open Runtime and Reliability -> Sink batches delivered vs dropped."
      tags             = ["pipeline", "audit"]
      program          = <<-EOT
        A = data('defenseclaw.audit.sink.failures', rollup='rate').sum(by=['sink.kind', 'sink.name']).scale(60).publish(label='Sink failures / min')
        detect(when(A > 6, '10m')).publish('DefenseClawAuditSinkFailures')
      EOT
    }
    audit_sink_circuit_open = {
      name             = "DefenseClaw - Audit sink circuit open"
      severity         = "Warning"
      detect_label     = "DefenseClawAuditSinkCircuitOpen"
      description      = "An audit sink circuit breaker is non-closed for 5 minutes."
      rule_description = "A sink circuit is open or half-open. Open Runtime and Reliability -> Sink queue and circuit state."
      tags             = ["pipeline", "audit"]
      program          = <<-EOT
        A = data('defenseclaw.audit.sink.circuit.state', rollup='latest').max(by=['sink.kind', 'sink.name']).publish(label='Circuit state')
        detect(when(A > 0.5, '5m')).publish('DefenseClawAuditSinkCircuitOpen')
      EOT
    }
    audit_sink_drop_ratio = {
      name             = "DefenseClaw - Audit sink drop ratio"
      severity         = "Warning"
      detect_label     = "DefenseClawAuditSinkDropRatio"
      description      = "Audit sink dropped-batch ratio is above 10% for 10 minutes."
      rule_description = "Dropped audit sink batches are high relative to total sink traffic. Open Runtime and Reliability -> Sink batches delivered vs dropped."
      tags             = ["pipeline", "audit"]
      program          = <<-EOT
        D = data('defenseclaw.audit.sink.batches.dropped', rollup='rate').sum(by=['sink']).publish(label='Dropped batches / sec')
        T = (data('defenseclaw.audit.sink.batches.delivered', rollup='rate').sum(by=['sink']) + data('defenseclaw.audit.sink.batches.dropped', rollup='rate').sum(by=['sink'])).publish(label='Total batches / sec')
        R = (D / T).publish(label='Drop ratio')
        detect(when(R > 0.10, '10m')).publish('DefenseClawAuditSinkDropRatio')
      EOT
    }
    block_rate_spike = {
      name             = "DefenseClaw - Block rate spike"
      severity         = "Warning"
      detect_label     = "DefenseClawBlockRateSpike"
      description      = "More than 25% of gateway verdicts are blocks for 10 minutes."
      rule_description = "Either a real attack is in progress or a recent policy/scanner change is producing false positives. Open Security and Policy -> Verdict breakdown."
      tags             = ["security", "guardrail"]
      program          = <<-EOT
        B = data('defenseclaw.gateway.verdicts', filter=filter('verdict.action', 'block'), rollup='rate').sum().publish(label='Blocks / sec')
        T = data('defenseclaw.gateway.verdicts', rollup='rate').sum().publish(label='Verdicts / sec')
        R = (B / T).publish(label='Block ratio')
        detect(when(R > 0.25, '10m')).publish('DefenseClawBlockRateSpike')
      EOT
    }
    judge_error_rate = {
      name             = "DefenseClaw - Judge error rate"
      severity         = "Warning"
      detect_label     = "DefenseClawJudgeErrorRate"
      description      = "LLM judge error rate is above 10% for 10 minutes."
      rule_description = "Guardrail judge quality is degraded and may fall back to heuristics. Open Security and Policy -> Judge errors by reason."
      tags             = ["security", "guardrail"]
      program          = <<-EOT
        E = data('defenseclaw.gateway.judge.errors', rollup='rate').sum().publish(label='Judge errors / sec')
        T = data('defenseclaw.gateway.judge.invocations', rollup='rate').sum().publish(label='Judge invocations / sec')
        R = (E / T).publish(label='Judge error ratio')
        detect(when(R > 0.10, '10m')).publish('DefenseClawJudgeErrorRate')
      EOT
    }
    webhook_failures = {
      name             = "DefenseClaw - Webhook failures sustained"
      severity         = "Warning"
      detect_label     = "DefenseClawWebhookFailuresSustained"
      description      = "Webhook failures are above 3/min for 15 minutes."
      rule_description = "Security or incident notification webhooks may be missing events. Open Runtime and Reliability -> Webhook outcomes."
      tags             = ["security", "webhooks"]
      program          = <<-EOT
        A = data('defenseclaw.webhook.dispatches', filter=filter('outcome', 'failed'), rollup='rate').sum(by=['webhook.kind']).scale(60).publish(label='Webhook failures / min')
        detect(when(A > 3, '15m')).publish('DefenseClawWebhookFailuresSustained')
      EOT
    }
    http_5xx_spike = {
      name             = "DefenseClaw - HTTP 5xx spike"
      severity         = "Warning"
      detect_label     = "DefenseClawHTTP5xxSpike"
      description      = "Gateway 5xx ratio is above 2% for 10 minutes."
      rule_description = "The gateway is returning 5xx on more than 2% of requests. Open Runtime and Reliability -> HTTP requests by route and status."
      tags             = ["traffic", "gateway"]
      program          = <<-EOT
        E = data('defenseclaw.http.request.count', filter=filter('http.status_code', '5*'), rollup='rate').sum().publish(label='5xx / sec')
        T = data('defenseclaw.http.request.count', rollup='rate').sum().publish(label='Requests / sec')
        R = (E / T).publish(label='5xx ratio')
        detect(when(R > 0.02, '10m')).publish('DefenseClawHTTP5xxSpike')
      EOT
    }
    http_auth_failures = {
      name             = "DefenseClaw - HTTP auth failures surge"
      severity         = "Warning"
      detect_label     = "DefenseClawHTTPAuthFailuresSurge"
      description      = "Authentication failures are above 60/min for 10 minutes."
      rule_description = "This could be bad-credential probing or a deployment regression. Open Runtime and Reliability -> Auth failures by route and reason."
      tags             = ["traffic", "security"]
      program          = <<-EOT
        A = data('defenseclaw.http.auth.failures', rollup='rate').sum().scale(60).publish(label='Auth failures / min')
        detect(when(A > 60, '10m')).publish('DefenseClawHTTPAuthFailuresSurge')
      EOT
    }
    rate_limit_surge = {
      name             = "DefenseClaw - Rate-limit surge"
      severity         = "Warning"
      detect_label     = "DefenseClawRateLimitSurge"
      description      = "Rate-limit breaches are above 120/min for 10 minutes."
      rule_description = "A client is being throttled aggressively. Open Runtime and Reliability -> HTTP surface and queue panels."
      tags             = ["traffic", "gateway"]
      program          = <<-EOT
        A = data('defenseclaw.http.rate_limit.breaches', rollup='rate').sum().scale(60).publish(label='Rate-limit breaches / min')
        detect(when(A > 120, '10m')).publish('DefenseClawRateLimitSurge')
      EOT
    }
    goroutine_leak = {
      name             = "DefenseClaw - Goroutine leak"
      severity         = "Warning"
      detect_label     = "DefenseClawGoroutineLeak"
      description      = "Goroutine count is above 10k for 15 minutes."
      rule_description = "Possible goroutine leak. Open Runtime and Reliability -> Runtime goroutines."
      tags             = ["runtime"]
      program          = <<-EOT
        A = data('defenseclaw.runtime.goroutines', rollup='latest').max().publish(label='Goroutines')
        detect(when(A > 10000, '15m')).publish('DefenseClawGoroutineLeak')
      EOT
    }
    sqlite_busy_retries = {
      name             = "DefenseClaw - SQLite busy retries"
      severity         = "Warning"
      detect_label     = "DefenseClawSQLiteBusyRetries"
      description      = "SQLite busy retries are above 60/min for 10 minutes."
      rule_description = "The audit store is contended and may hurt latency. Open Runtime and Reliability -> SQLite busy retries."
      tags             = ["runtime", "audit-db"]
      program          = <<-EOT
        A = data('defenseclaw.sqlite.busy_retries', rollup='rate').sum().scale(60).publish(label='SQLite busy retries / min')
        detect(when(A > 60, '10m')).publish('DefenseClawSQLiteBusyRetries')
      EOT
    }
    config_load_errors = {
      name             = "DefenseClaw - Config load errors"
      severity         = "Warning"
      detect_label     = "DefenseClawConfigLoadErrors"
      description      = "Config reload failures were detected."
      rule_description = "A recent config reload failed. The previous config is still active, but the operator-facing change did not take effect."
      tags             = ["runtime", "config"]
      program          = <<-EOT
        A = data('defenseclaw.config.load.errors', rollup='rate').sum().scale(60).publish(label='Config load errors / min')
        detect(when(A > 0)).publish('DefenseClawConfigLoadErrors')
      EOT
    }
    connector_telemetry_silent = {
      name             = "DefenseClaw - Connector telemetry silent"
      severity         = "Warning"
      detect_label     = "DefenseClawConnectorTelemetrySilent"
      description      = "A previously reporting connector signal stopped reporting for 10 minutes."
      rule_description = "A connector that was emitting OTLP telemetry is now silent. Open Connector and OTel Ingest and inspect source/signal mix."
      tags             = ["connectors", "otel"]
      program          = <<-EOT
        A = data('defenseclaw.otel.ingest.last_seen_ts', rollup='latest').max(by=['source', 'signal']).publish(label='Connector last seen')
        detect(when(A is None, '10m')).publish('DefenseClawConnectorTelemetrySilent')
      EOT
    }
    connector_telemetry_malformed = {
      name             = "DefenseClaw - Connector telemetry malformed"
      severity         = "Warning"
      detect_label     = "DefenseClawConnectorTelemetryMalformed"
      description      = "Malformed connector telemetry ratio is above 10% for 10 minutes."
      rule_description = "More than 10% of connector OTLP requests are malformed. Open Connector and OTel Ingest -> Malformed OTLP by source and signal."
      tags             = ["connectors", "otel"]
      program          = <<-EOT
        M = data('defenseclaw.otel.ingest.malformed', rollup='rate').sum(by=['source', 'signal']).publish(label='Malformed / sec')
        T = data('defenseclaw.otel.ingest.requests', rollup='rate').sum(by=['source', 'signal']).publish(label='Requests / sec')
        R = (M / T).publish(label='Malformed ratio')
        detect(when(R > 0.10, '10m')).publish('DefenseClawConnectorTelemetryMalformed')
      EOT
    }
  }
}

resource "signalfx_detector" "detector" {
  for_each = { for name, detector in local.detectors : name => detector if var.create_detectors }

  name             = "${each.value.name}${local.display_name_suffix}"
  description      = each.value.description
  program_text     = trimspace(each.value.program)
  tags             = concat(["defenseclaw", "otel"], each.value.tags)
  show_event_lines = true
  time_range       = 3600

  rule {
    detect_label          = each.value.detect_label
    description           = each.value.rule_description
    severity              = each.value.severity
    disabled              = var.detectors_disabled
    notifications         = var.detector_notifications
    parameterized_body    = each.value.rule_description
    parameterized_subject = "${each.value.name}${local.display_name_suffix}"
  }
}

output "detector_urls" {
  description = "Created Splunk Observability detector URLs."
  value       = { for name, detector in signalfx_detector.detector : name => detector.url }
}
