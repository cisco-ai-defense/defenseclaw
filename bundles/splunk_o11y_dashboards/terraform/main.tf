terraform {
  required_version = ">= 1.5.0"

  required_providers {
    signalfx = {
      source  = "splunk-terraform/signalfx"
      version = ">= 9.6.0, < 10.0.0"
    }
  }
}

variable "signalfx_auth_token" {
  description = "Splunk Observability Cloud user API access token. Leave null to use SFX_AUTH_TOKEN."
  type        = string
  default     = null
  sensitive   = true
}

variable "signalfx_api_url" {
  description = "Splunk Observability Cloud API URL. Leave null to use SFX_API_URL."
  type        = string
  default     = null
}

variable "name_prefix" {
  description = "Optional label used to distinguish dashboard groups, dashboards, and detectors for disposable smoke tests."
  type        = string
  default     = ""
}

provider "signalfx" {
  auth_token = var.signalfx_auth_token
  api_url    = var.signalfx_api_url
}

locals {
  display_name_prefix = trimspace(var.name_prefix) == "" ? "" : "${trimspace(var.name_prefix)} "
  display_name_suffix = trimspace(var.name_prefix) == "" ? "" : " (${trimspace(var.name_prefix)})"

  common_dashboard_variables = [
    { property = "tenant_id", alias = "tenant" },
    { property = "workspace_id", alias = "workspace" },
    { property = "host.name", alias = "host" },
  ]

  dashboard_variables = {
    executive = concat(local.common_dashboard_variables, [
      { property = "gen_ai.agent.name", alias = "agent" },
    ])
    guardrail_inspection = concat(local.common_dashboard_variables, [
      { property = "sf_service", alias = "service" },
      { property = "gen_ai.agent.name", alias = "agent" },
    ])
    connector_ingest = concat(local.common_dashboard_variables, [
      { property = "source", alias = "connector source" },
      { property = "signal", alias = "otel signal" },
      { property = "connector", alias = "hook connector" },
      { property = "gen_ai.agent.name", alias = "agent" },
    ])
    security_policy = concat(local.common_dashboard_variables, [
      { property = "policy.domain", alias = "policy domain" },
      { property = "verdict.stage", alias = "verdict stage" },
    ])
    token_economics = [
      { property = "deployment.environment", alias = "environment" },
      { property = "service.name", alias = "service" },
      { property = "gen_ai.agent.name", alias = "agent" },
      { property = "gen_ai.request.model", alias = "model" },
    ]
    runtime_reliability = concat(local.common_dashboard_variables, [
      { property = "http.route", alias = "route" },
      { property = "sink", alias = "batch sink" },
      { property = "sink.name", alias = "sink name" },
      { property = "webhook.kind", alias = "webhook kind" },
    ])
    scanners_findings = concat(local.common_dashboard_variables, [
      { property = "scanner", alias = "scanner" },
      { property = "target_type", alias = "target type" },
      { property = "severity", alias = "severity" },
    ])
  }

  single_value_charts = {
    executive_verdicts_31d = {
      name        = "Verdicts"
      description = "All DefenseClaw gateway verdicts in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.gateway.verdicts', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.verdicts', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Verdicts')
      EOT
    }
    executive_blocks_31d = {
      name        = "Blocks"
      description = "Gateway verdicts where verdict.action is block in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.gateway.verdicts', filter=filter('verdict.action', 'block'), extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.verdicts', filter=filter('verdict.action', 'block'), extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Blocks')
      EOT
    }
    executive_guardrail_evaluations_31d = {
      name        = "Guardrail evals"
      description = "Guardrail evaluations in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.guardrail.evaluations', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.guardrail.evaluations', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Guardrail evals')
      EOT
    }
    executive_inspect_evaluations_31d = {
      name        = "Inspections"
      description = "Tool and message inspection evaluations in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.inspect.evaluations', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Inspections')
      EOT
    }
    executive_otel_records_31d = {
      name        = "OTel records"
      description = "Leaf records extracted from inbound OTLP logs, metrics, and traces in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.records', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.otel.ingest.records', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='OTel records')
      EOT
    }
    executive_gateway_errors_31d = {
      name        = "Gateway errors"
      description = "Structured gateway errors in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.gateway.errors', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.errors', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Gateway errors')
      EOT
    }
    guardrail_total_evaluations = {
      name        = "Guardrail evals"
      description = "Guardrail evaluations in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.guardrail.evaluations', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.guardrail.evaluations', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Guardrail evals')
      EOT
    }
    guardrail_total_inspections = {
      name        = "Inspections"
      description = "Tool and message inspection evaluations in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.inspect.evaluations', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Inspections')
      EOT
    }
    guardrail_total_blocked_inspections = {
      name        = "Blocked inspections"
      description = "Inspection evaluations where action is block in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', filter=filter('action', 'block'), extrapolation='zero', rollup='delta')
        B = data('defenseclaw.inspect.evaluations', filter=filter('action', 'block'), extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Blocked inspections')
      EOT
    }
    guardrail_total_alert_inspections = {
      name        = "Alert inspections"
      description = "Inspection evaluations where action is alert in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', filter=filter('action', 'alert'), extrapolation='zero', rollup='delta')
        B = data('defenseclaw.inspect.evaluations', filter=filter('action', 'alert'), extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Alert inspections')
      EOT
    }
    guardrail_total_audit_events = {
      name        = "Audit events"
      description = "Audit events in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.audit.events.total', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.audit.events.total', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Audit events')
      EOT
    }
    guardrail_total_runtime_alerts = {
      name        = "Runtime alerts"
      description = "Runtime alerts in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.alert.count', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.alert.count', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Runtime alerts')
      EOT
    }
    scanner_total_scans = {
      name        = "Scans"
      description = "Completed scans in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.scan.count', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.scan.count', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Scans')
      EOT
    }
    scanner_total_findings = {
      name        = "New findings"
      description = "New scan findings in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.scan.findings', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.scan.findings', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='New findings')
      EOT
    }
    scanner_total_scan_errors = {
      name        = "Scan errors"
      description = "Scanner invocation failures in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.scan.errors', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.scan.errors', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Scan errors')
      EOT
    }
    scanner_open_findings = {
      name        = "Open finding backlog"
      description = "Latest open finding count in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.scan.findings.gauge', rollup='latest').sum().publish(label='Open finding backlog')
      EOT
    }
    connector_total_otel_requests = {
      name        = "OTLP requests"
      description = "Inbound OTLP-HTTP requests in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.requests', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.otel.ingest.requests', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='OTLP requests')
      EOT
    }
    connector_total_otel_records = {
      name        = "OTel records"
      description = "Leaf records extracted from inbound OTLP batches in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.records', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.otel.ingest.records', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='OTel records')
      EOT
    }
    connector_total_otel_bytes = {
      name        = "OTLP bytes"
      description = "Inbound OTLP payload bytes in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.bytes', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.otel.ingest.bytes', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='OTLP bytes')
      EOT
    }
    connector_total_codex_notify = {
      name        = "Codex notify"
      description = "Codex notify-bridge webhook events in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.codex.notify', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.codex.notify', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Codex notify')
      EOT
    }
    connector_total_hook_invocations = {
      name        = "Hook invocations"
      description = "Connector hook invocations in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.connector.hook.invocations', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.connector.hook.invocations', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Hook invocations')
      EOT
    }
    connector_total_llm_events = {
      name        = "LLM events"
      description = "Gateway-normalized prompt, response, and tool events in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.gateway.events.emitted', filter=filter('event_type', 'llm_prompt', 'llm_response', 'tool_invocation'), extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.events.emitted', filter=filter('event_type', 'llm_prompt', 'llm_response', 'tool_invocation'), extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='LLM events')
      EOT
    }
    security_total_policy_denies = {
      name        = "Policy denies"
      description = "Policy evaluations returning deny, block, blocked, or rejected in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.policy.evaluations', filter=filter('policy.verdict', 'deny', 'block', 'blocked', 'rejected'), extrapolation='zero', rollup='delta')
        B = data('defenseclaw.policy.evaluations', filter=filter('policy.verdict', 'deny', 'block', 'blocked', 'rejected'), extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Policy denies')
      EOT
    }
    security_total_findings = {
      name        = "New findings"
      description = "New scan findings in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.scan.findings', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.scan.findings', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='New findings')
      EOT
    }
    security_total_egress_blocks = {
      name        = "Egress blocks"
      description = "Egress events where decision is block in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.egress.events', filter=filter('decision', 'block'), extrapolation='zero', rollup='delta')
        B = data('defenseclaw.egress.events', filter=filter('decision', 'block'), extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Egress blocks')
      EOT
    }
    security_total_runtime_alerts = {
      name        = "Runtime alerts"
      description = "Runtime alerts in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.alert.count', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.alert.count', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Runtime alerts')
      EOT
    }
    security_total_judge_invocations = {
      name        = "Judge invocations"
      description = "Gateway judge invocations in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.gateway.judge.invocations', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.judge.invocations', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Judge invocations')
      EOT
    }
    security_total_judge_errors = {
      name        = "Judge errors"
      description = "Gateway judge provider, parse, or empty-response errors in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.gateway.judge.errors', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.judge.errors', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Judge errors')
      EOT
    }
    token_records = {
      name        = "Token records"
      description = "GenAI token usage observations in the selected time range."
      program     = <<-EOT
        A = histogram('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat')).count().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Token records')
      EOT
    }
    token_errors = {
      name        = "Errors"
      description = "DefenseClaw gateway errors in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.gateway.errors', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.errors', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Errors')
      EOT
    }
    token_active_agents = {
      name        = "Active agents"
      description = "Approximate active agent count from GenAI token metrics in the selected time range."
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat'), rollup='sum').sum(by=['gen_ai.agent.name']).sum(over=Args.get('ui.dashboard_window', '31d'))
        B = A.count().publish(label='Agents')
      EOT
    }
    token_total_tokens = {
      name        = "Tokens"
      description = "Total GenAI tokens from DefenseClaw GenAI OTel metrics in the selected time range."
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Tokens')
      EOT
    }
    token_input_tokens = {
      name        = "Input tokens"
      description = "Input tokens from gen_ai.client.token.usage in the selected time range."
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Input tokens')
      EOT
    }
    token_output_tokens = {
      name        = "Output tokens"
      description = "Output tokens from gen_ai.client.token.usage in the selected time range."
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Output tokens')
      EOT
    }
    token_estimated_cost = {
      name        = "Estimated cost"
      description = "Estimated USD using dashboard-side standard model rates. Cached-input discounts are not applied because token usage is currently split only into input and output."
      program     = <<-EOT
        I4O = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-4o-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000015).fill(0)
        O4O = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-4o-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000060).fill(0)
        I41 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-4.1-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000040).fill(0)
        O41 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-4.1-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000160).fill(0)
        I54M = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.4-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000075).fill(0)
        O54M = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.4-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000450).fill(0)
        I54 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.4'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000250).fill(0)
        O54 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.4'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00001500).fill(0)
        I55 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.5'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000500).fill(0)
        O55 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.5'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00003000).fill(0)
        C = (I4O + O4O + I41 + O41 + I54M + O54M + I54 + O54 + I55 + O55).publish(label='Estimated USD')
      EOT
    }
    token_estimated_input_cost = {
      name        = "Estimated input cost"
      description = "Estimated input USD using dashboard-side standard model rates. Cached-input discounts are not applied."
      program     = <<-EOT
        I4O = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-4o-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000015).fill(0)
        I41 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-4.1-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000040).fill(0)
        I54M = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.4-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000075).fill(0)
        I54 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.4'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000250).fill(0)
        I55 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.5'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000500).fill(0)
        C = (I4O + I41 + I54M + I54 + I55).publish(label='Input USD')
      EOT
    }
    token_estimated_output_cost = {
      name        = "Estimated output cost"
      description = "Estimated output USD using dashboard-side standard model rates."
      program     = <<-EOT
        O4O = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-4o-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000060).fill(0)
        O41 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-4.1-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000160).fill(0)
        O54M = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.4-mini'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00000450).fill(0)
        O54 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.4'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00001500).fill(0)
        O55 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.5'), rollup='sum').sum().sum(over=Args.get('ui.dashboard_window', '31d')).scale(0.00003000).fill(0)
        C = (O4O + O41 + O54M + O54 + O55).publish(label='Output USD')
      EOT
    }
    runtime_total_gateway_errors = {
      name        = "Gateway errors"
      description = "Structured gateway errors in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.gateway.errors', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.errors', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Gateway errors')
      EOT
    }
    runtime_total_schema_violations = {
      name        = "Schema violations"
      description = "Runtime schema validation drops in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.schema.violations', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.schema.violations', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Schema violations')
      EOT
    }
    runtime_total_http_requests = {
      name        = "HTTP requests"
      description = "Sidecar API requests in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.http.request.count', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.http.request.count', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='HTTP requests')
      EOT
    }
    runtime_total_auth_failures = {
      name        = "Auth failures"
      description = "HTTP auth failures in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.http.auth.failures', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.http.auth.failures', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Auth failures')
      EOT
    }
    runtime_total_exporter_errors = {
      name        = "Exporter errors"
      description = "OTLP telemetry exporter errors in the selected time range."
      program     = <<-EOT
        A = data('defenseclaw.telemetry.exporter.errors', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.telemetry.exporter.errors', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum().sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Exporter errors')
      EOT
    }
    verdicts_per_min = {
      name        = "Verdicts / min"
      description = "All DefenseClaw gateway verdicts per minute."
      program     = <<-EOT
        A = data('defenseclaw.gateway.verdicts', rollup='rate').sum().scale(60).publish(label='Verdicts / min')
      EOT
    }
    blocks_per_min = {
      name        = "Blocks / min"
      description = "Gateway verdicts where verdict.action is block."
      program     = <<-EOT
        A = data('defenseclaw.gateway.verdicts', filter=filter('verdict.action', 'block'), rollup='rate').sum().scale(60).publish(label='Blocks / min')
      EOT
    }
    guardrail_evaluations_per_min = {
      name        = "Guardrail evals / min"
      description = "Guardrail evaluations emitted by scanner and action."
      program     = <<-EOT
        A = data('defenseclaw.guardrail.evaluations', rollup='rate').sum().scale(60).publish(label='Guardrail evals / min')
      EOT
    }
    inspect_evaluations_per_min = {
      name        = "Inspections / min"
      description = "Tool and message inspection evaluations per minute."
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', rollup='rate').sum().scale(60).publish(label='Inspections / min')
      EOT
    }
    blocked_inspections_per_min = {
      name        = "Blocked inspections / min"
      description = "Inspection evaluations where action is block."
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', filter=filter('action', 'block'), rollup='rate').sum().scale(60).publish(label='Blocked inspections / min')
      EOT
    }
    alert_inspections_per_min = {
      name        = "Alert inspections / min"
      description = "Inspection evaluations where action is alert."
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', filter=filter('action', 'alert'), rollup='rate').sum().scale(60).publish(label='Alert inspections / min')
      EOT
    }
    audit_events_per_min = {
      name        = "Audit events / min"
      description = "Audit events persisted per minute."
      program     = <<-EOT
        A = data('defenseclaw.audit.events.total', rollup='rate').sum().scale(60).publish(label='Audit events / min')
      EOT
    }
    otel_requests_per_min = {
      name        = "OTLP requests / min"
      description = "Inbound OTLP-HTTP requests received by the connector ingest receiver."
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.requests', rollup='rate').sum().scale(60).publish(label='OTLP requests / min')
      EOT
    }
    otel_records_per_min = {
      name        = "OTel records / min"
      description = "Leaf records extracted from inbound OTLP logs, metrics, and traces."
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.records', rollup='rate').sum().scale(60).publish(label='OTel records / min')
      EOT
    }
    otel_malformed_per_min = {
      name        = "Malformed OTLP / min"
      description = "OTLP-JSON bodies that failed parsing."
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.malformed', rollup='rate').sum().scale(60).publish(label='Malformed OTLP / min')
      EOT
    }
    codex_notify_per_min = {
      name        = "Codex notify / min"
      description = "Codex notify-bridge webhook events per minute."
      program     = <<-EOT
        A = data('defenseclaw.codex.notify', rollup='rate').sum().scale(60).publish(label='Codex notify / min')
      EOT
    }
    hook_invocations_per_min = {
      name        = "Hook invocations / min"
      description = "Connector hook invocations observed by the gateway."
      program     = <<-EOT
        A = data('defenseclaw.connector.hook.invocations', rollup='rate').sum().scale(60).publish(label='Hook invocations / min')
      EOT
    }
    llm_events_per_min = {
      name        = "LLM events / min"
      description = "Gateway-normalized prompt, response, and tool events."
      program     = <<-EOT
        A = data('defenseclaw.gateway.events.emitted', filter=filter('event_type', 'llm_prompt', 'llm_response', 'tool_invocation'), rollup='rate').sum().scale(60).publish(label='LLM events / min')
      EOT
    }
    policy_denies_per_min = {
      name        = "Policy denies / min"
      description = "Policy evaluations returning deny, block, blocked, or rejected."
      program     = <<-EOT
        A = data('defenseclaw.policy.evaluations', filter=filter('policy.verdict', 'deny', 'block', 'blocked', 'rejected'), rollup='rate').sum().scale(60).publish(label='Policy denies / min')
      EOT
    }
    findings_per_min = {
      name        = "Findings / min"
      description = "Scan findings per minute."
      program     = <<-EOT
        A = data('defenseclaw.scan.findings', rollup='rate').sum().scale(60).publish(label='Findings / min')
      EOT
    }
    scan_errors_per_min = {
      name        = "Scan errors / min"
      description = "Scanner invocation failures per minute."
      program     = <<-EOT
        A = data('defenseclaw.scan.errors', rollup='rate').sum().scale(60).publish(label='Scan errors / min')
      EOT
    }
    open_findings = {
      name        = "Open findings"
      description = "Current open findings gauge across target types and severities."
      program     = <<-EOT
        A = data('defenseclaw.scan.findings.gauge', rollup='latest').sum().publish(label='Open findings')
      EOT
    }
    quarantine_actions_per_min = {
      name        = "Quarantine actions / min"
      description = "Quarantine or restore operations per minute."
      program     = <<-EOT
        A = data('defenseclaw.quarantine.actions', rollup='rate').sum().scale(60).publish(label='Quarantine actions / min')
      EOT
    }
    egress_blocks_per_min = {
      name        = "Egress blocks / min"
      description = "Egress events where decision is block."
      program     = <<-EOT
        A = data('defenseclaw.egress.events', filter=filter('decision', 'block'), rollup='rate').sum().scale(60).publish(label='Egress blocks / min')
      EOT
    }
    alerts_per_min = {
      name        = "Alerts / min"
      description = "Runtime alert count per minute."
      program     = <<-EOT
        A = data('defenseclaw.alert.count', rollup='rate').sum().scale(60).publish(label='Alerts / min')
      EOT
    }
    judge_invocations_per_min = {
      name        = "Judge invocations / min"
      description = "Gateway judge invocations per minute."
      program     = <<-EOT
        A = data('defenseclaw.gateway.judge.invocations', rollup='rate').sum().scale(60).publish(label='Judge invocations / min')
      EOT
    }
    judge_errors_per_min = {
      name        = "Judge errors / min"
      description = "Gateway judge provider, parse, or empty-response errors."
      program     = <<-EOT
        A = data('defenseclaw.gateway.judge.errors', rollup='rate').sum().scale(60).publish(label='Judge errors / min')
      EOT
    }
    gateway_errors_per_min = {
      name        = "Gateway errors / min"
      description = "Structured gateway errors per minute."
      program     = <<-EOT
        A = data('defenseclaw.gateway.errors', rollup='rate').sum().scale(60).publish(label='Gateway errors / min')
      EOT
    }
    schema_violations_per_min = {
      name        = "Schema violations / min"
      description = "Gateway events dropped by runtime schema validation."
      program     = <<-EOT
        A = data('defenseclaw.schema.violations', rollup='rate').sum().scale(60).publish(label='Schema violations / min')
      EOT
    }
    sink_drops_per_min = {
      name        = "Sink drops / min"
      description = "Audit sink batches dropped due to queue or circuit breaker."
      program     = <<-EOT
        A = data('defenseclaw.audit.sink.batches.dropped', rollup='rate').sum().scale(60).publish(label='Sink drops / min')
      EOT
    }
    exporter_errors_per_min = {
      name        = "Exporter errors / min"
      description = "OTLP telemetry exporter errors per minute."
      program     = <<-EOT
        A = data('defenseclaw.telemetry.exporter.errors', rollup='rate').sum().scale(60).publish(label='Exporter errors / min')
      EOT
    }
    panics_1h = {
      name        = "Panics / hour"
      description = "Recovered DefenseClaw panics over the current rollup window."
      program     = <<-EOT
        A = data('defenseclaw.panics.total', rollup='rate').sum().scale(3600).publish(label='Panics / hour')
      EOT
    }
    auth_failures_per_min = {
      name        = "Auth failures / min"
      description = "Sidecar 401/403 responses per minute."
      program     = <<-EOT
        A = data('defenseclaw.http.auth.failures', rollup='rate').sum().scale(60).publish(label='Auth failures / min')
      EOT
    }
    rate_limit_breaches_per_min = {
      name        = "Rate limits / min"
      description = "Rate-limited HTTP requests per minute."
      program     = <<-EOT
        A = data('defenseclaw.http.rate_limit.breaches', rollup='rate').sum().scale(60).publish(label='Rate limits / min')
      EOT
    }
    uptime_seconds = {
      name        = "Process uptime"
      description = "DefenseClaw process uptime in seconds."
      program     = <<-EOT
        A = data('defenseclaw.process.uptime_seconds', rollup='latest').max().publish(label='Uptime seconds')
      EOT
    }
  }

  time_charts = {
    verdicts_by_action = {
      name        = "Verdicts by action"
      description = "Gateway verdict counts grouped by action."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "verdicts"
      program     = <<-EOT
        A = data('defenseclaw.gateway.verdicts').sum(by=['verdict.action']).publish(label='Verdicts')
      EOT
    }
    verdicts_by_stage = {
      name        = "Verdicts by stage"
      description = "Gateway verdict rate grouped by enforcement stage."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "events / min"
      program     = <<-EOT
        A = data('defenseclaw.gateway.verdicts', rollup='rate').sum(by=['verdict.stage']).scale(60).publish(label='Verdicts / min')
      EOT
    }
    verdicts_by_severity = {
      name        = "Verdicts by severity"
      description = "Gateway verdict rate grouped by severity."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "events / min"
      program     = <<-EOT
        A = data('defenseclaw.gateway.verdicts', rollup='rate').sum(by=['verdict.severity']).scale(60).publish(label='Verdicts / min')
      EOT
    }
    guardrail_evaluations_by_action = {
      name        = "Guardrail Evaluations by Action"
      description = "All guardrail evaluations grouped by action (block/alert/allow) - auto-discovers new action types."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "evaluations"
      program     = <<-EOT
        A = data('defenseclaw.guardrail.evaluations').sum(by=['guardrail.action_taken']).publish()
      EOT
    }
    guardrail_latency_p95 = {
      name        = "Guardrail latency p95"
      description = "P95 guardrail evaluation latency."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.guardrail.latency').percentile(pct=95).publish(label='p95 guardrail ms')
      EOT
    }
    inspections_by_tool = {
      name        = "Inspections by Tool"
      description = "All tool inspections grouped by tool name - automatically includes any new tools without chart changes."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "inspections"
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations').sum(by=['tool']).publish()
      EOT
    }
    inspections_by_severity = {
      name        = "Inspections by Severity"
      description = "All inspections grouped by severity level - auto-discovers severity values from the data."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "inspections"
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations').sum(by=['severity']).publish()
      EOT
    }
    blocked_inspections_by_tool = {
      name        = "Block Rate by Tool"
      description = "Blocked inspections over time grouped by tool - auto-discovers new tools."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "blocks"
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', filter=filter('action', 'block')).sum(by=['tool']).publish()
      EOT
    }
    alert_inspections_by_tool = {
      name        = "Alert Rate by Tool"
      description = "Flagged (alert) inspections over time grouped by tool - auto-discovers new tools."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "alerts"
      program     = <<-EOT
        A = data('defenseclaw.inspect.evaluations', filter=filter('action', 'alert')).sum(by=['tool']).publish()
      EOT
    }
    inspect_latency_p95 = {
      name        = "Inspection latency p95"
      description = "P95 tool/message inspection latency grouped by tool."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.inspect.latency').percentile(pct=95).publish(label='p95 inspect ms')
      EOT
    }
    audit_events_by_action = {
      name        = "Audit Events by Action"
      description = "All audit events grouped by action type - auto-discovers new event types as they appear."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "events"
      program     = <<-EOT
        A = data('defenseclaw.audit.events.total').sum(by=['action']).publish()
      EOT
    }
    otel_requests_by_source_signal = {
      name        = "OTLP requests by source and signal"
      description = "Inbound OTLP-HTTP request rate grouped by connector source and signal."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "requests / sec"
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.requests', rollup='rate').sum(by=['source', 'signal']).publish(label='OTLP requests / sec')
      EOT
    }
    otel_records_by_source_signal = {
      name        = "OTLP records by source and signal"
      description = "Leaf records extracted from inbound OTLP batches."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "records / sec"
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.records', rollup='rate').sum(by=['source', 'signal']).publish(label='OTLP records / sec')
      EOT
    }
    otel_bytes_by_source_signal = {
      name        = "OTLP bytes by source and signal"
      description = "Inbound OTLP body byte rate grouped by connector source and signal."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "bytes / sec"
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.bytes', rollup='rate').sum(by=['source', 'signal']).publish(label='OTLP bytes / sec')
      EOT
    }
    malformed_by_source_signal = {
      name        = "OTLP requests by result"
      description = "Inbound OTLP request counts grouped by source, signal, and result."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "requests"
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.requests').sum(by=['source', 'signal', 'result']).publish(label='OTLP requests')
      EOT
    }
    codex_notify_by_type_result = {
      name        = "Codex notify by type and result"
      description = "Codex notify-bridge events grouped by type and result."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "events / min"
      program     = <<-EOT
        A = data('defenseclaw.codex.notify', rollup='rate').sum(by=['type', 'result']).scale(60).publish(label='Codex notify / min')
      EOT
    }
    hook_invocations_by_connector = {
      name        = "Hook invocations by connector"
      description = "Gateway connector hook invocations grouped by connector, event type, and result."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "hooks / min"
      program     = <<-EOT
        A = data('defenseclaw.connector.hook.invocations', rollup='rate').sum(by=['connector', 'event_type', 'result']).scale(60).publish(label='Hook invocations / min')
      EOT
    }
    hook_latency_p95 = {
      name        = "Connector hook latency p95"
      description = "P95 connector hook handling latency."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.connector.hook.latency').percentile(pct=95).publish(label='p95 hook ms')
      EOT
    }
    genai_tokens_by_agent_type = {
      name        = "GenAI tokens by agent"
      description = "Token usage from promoted GenAI OTel metrics grouped by agent."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "tokens"
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat'), rollup='sum').sum(by=['gen_ai.agent.name']).publish(label='Tokens')
      EOT
    }
    genai_operation_duration_p95 = {
      name        = "LLM operation duration p95"
      description = "P95 duration for promoted GenAI client operations."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "seconds"
      program     = <<-EOT
        A = histogram('gen_ai.client.operation.duration').percentile(pct=95).publish(label='p95 operation seconds')
      EOT
    }
    llm_events_by_type = {
      name        = "LLM events by type"
      description = "Gateway-normalized prompt, response, and tool event emission rate."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "events / min"
      program     = <<-EOT
        A = data('defenseclaw.gateway.events.emitted', filter=filter('event_type', 'llm_prompt', 'llm_response', 'tool_invocation'), rollup='rate', extrapolation='zero').sum(by=['event_type']).scale(60).publish(label='LLM events / min')
      EOT
    }
    token_tokens_by_agent = {
      name        = "Tokens by agent"
      description = "Token usage grouped by GenAI agent name."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "tokens"
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat'), rollup='sum').sum(by=['gen_ai.agent.name']).publish(label='Tokens')
      EOT
    }
    token_tokens_by_model = {
      name        = "Tokens by model"
      description = "Token usage grouped by requested model."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "tokens"
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat'), rollup='sum').sum(by=['gen_ai.request.model']).publish(label='Tokens')
      EOT
    }
    token_input_vs_output = {
      name        = "Input vs output tokens"
      description = "Token mix by token type."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "tokens"
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat'), rollup='sum').sum(by=['gen_ai.token.type']).publish(label='Tokens')
      EOT
    }
    token_estimated_cost_by_agent = {
      name        = "Estimated cost by agent"
      description = "Estimated USD by agent using dashboard-side standard model rates. Cached-input discounts are not applied."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "USD"
      program     = <<-EOT
        I4O = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-4o-mini'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00000015).fill(0)
        O4O = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-4o-mini'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00000060).fill(0)
        C4O = (I4O + O4O).publish(label='gpt-4o-mini USD')

        I41 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-4.1-mini'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00000040).fill(0)
        O41 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-4.1-mini'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00000160).fill(0)
        C41 = (I41 + O41).publish(label='gpt-4.1-mini USD')

        I54M = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.4-mini'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00000075).fill(0)
        O54M = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.4-mini'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00000450).fill(0)
        C54M = (I54M + O54M).publish(label='gpt-5.4-mini USD')

        I54 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.4'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00000250).fill(0)
        O54 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.4'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00001500).fill(0)
        C54 = (I54 + O54).publish(label='gpt-5.4 USD')

        I55 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'input') and filter('gen_ai.request.model', 'gpt-5.5'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00000500).fill(0)
        O55 = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat') and filter('gen_ai.token.type', 'output') and filter('gen_ai.request.model', 'gpt-5.5'), rollup='sum').sum(by=['gen_ai.agent.name']).scale(0.00003000).fill(0)
        C55 = (I55 + O55).publish(label='gpt-5.5 USD')

        C = (C4O + C41 + C54M + C54 + C55).publish(label='Estimated USD')
      EOT
    }
    policy_evaluations_by_domain = {
      name        = "Policy evaluations by verdict"
      description = "Policy evaluations grouped by verdict."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "evaluations / min"
      program     = <<-EOT
        A = data('defenseclaw.policy.evaluations', rollup='rate').sum(by=['policy.verdict']).scale(60).publish(label='Policy evaluations / min')
      EOT
    }
    policy_latency_p95 = {
      name        = "Policy latency p95"
      description = "P95 policy evaluation latency grouped by domain."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.policy.latency').percentile(pct=95).publish(label='p95 policy ms')
      EOT
    }
    findings_by_severity = {
      name        = "Findings by severity"
      description = "Scan findings grouped by severity."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "findings / min"
      program     = <<-EOT
        A = data('defenseclaw.scan.findings', rollup='rate').sum(by=['severity']).scale(60).publish(label='Findings / min')
      EOT
    }
    findings_by_scanner = {
      name        = "Findings by scanner"
      description = "Scan finding counts grouped by scanner."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "findings"
      program     = <<-EOT
        A = data('defenseclaw.scan.findings').sum(by=['scanner']).publish(label='Findings')
      EOT
    }
    egress_by_decision = {
      name        = "Egress decisions"
      description = "Egress event rate grouped by decision."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "events / min"
      program     = <<-EOT
        A = data('defenseclaw.egress.events', rollup='rate').sum(by=['decision']).scale(60).publish(label='Egress events / min')
      EOT
    }
    alerts_by_type_severity = {
      name        = "Alerts by severity"
      description = "Runtime alerts grouped by severity."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "alerts / min"
      program     = <<-EOT
        A = data('defenseclaw.alert.count', rollup='rate').sum(by=['alert.severity']).scale(60).publish(label='Alerts / min')
      EOT
    }
    judge_latency_p95 = {
      name        = "Judge latency p95"
      description = "P95 gateway judge invocation latency."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.gateway.judge.latency').percentile(pct=95).publish(label='p95 judge ms')
      EOT
    }
    judge_errors_by_reason = {
      name        = "Judge errors by reason"
      description = "Gateway judge errors grouped by reason."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "errors / min"
      program     = <<-EOT
        A = data('defenseclaw.gateway.judge.errors', rollup='rate').sum(by=['judge.reason']).scale(60).publish(label='Judge errors / min')
      EOT
    }
    guardrail_cache = {
      name        = "Guardrail cache hits and misses"
      description = "Verdict cache hit/miss rate by scanner and verdict."
      plot_type   = "AreaChart"
      stacked     = true
      axis_label  = "events / min"
      program     = <<-EOT
        A = data('defenseclaw.guardrail.cache.hits', rollup='rate').sum(by=['scanner', 'verdict']).scale(60).publish(label='Cache hits / min')
        B = data('defenseclaw.guardrail.cache.misses', rollup='rate').sum(by=['scanner', 'verdict']).scale(60).publish(label='Cache misses / min')
      EOT
    }
    llm_bridge_latency_p95 = {
      name        = "LLM bridge latency p95"
      description = "P95 LiteLLM bridge latency grouped by model and status."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.llm_bridge.latency').percentile(pct=95).publish(label='p95 bridge ms')
      EOT
    }
    cisco_inspect_latency_p95 = {
      name        = "Cisco Inspect latency p95"
      description = "P95 Cisco Inspect latency grouped by outcome."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.cisco_inspect.latency').percentile(pct=95).publish(label='p95 Cisco Inspect ms')
      EOT
    }
    gateway_errors_by_code = {
      name        = "Gateway errors by code"
      description = "Structured gateway errors grouped by error code."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "errors"
      program     = <<-EOT
        A = data('defenseclaw.gateway.errors').sum(by=['error.code']).publish(label='Gateway errors')
      EOT
    }
    schema_violations_by_code = {
      name        = "Schema violations by code"
      description = "Runtime schema violations grouped by validation code."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "violations"
      program     = <<-EOT
        A = data('defenseclaw.schema.violations').sum(by=['code']).publish(label='Schema violations')
      EOT
    }
    http_requests_by_route_status = {
      name        = "HTTP requests by status"
      description = "Sidecar API request counts grouped by HTTP status code."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "requests"
      program     = <<-EOT
        A = data('defenseclaw.http.request.count').sum(by=['http.status_code']).publish(label='HTTP requests')
      EOT
    }
    http_duration_p95 = {
      name        = "HTTP duration p95"
      description = "P95 sidecar request duration."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.http.request.duration').percentile(pct=95).publish(label='p95 HTTP ms')
      EOT
    }
    auth_failures_by_reason = {
      name        = "Auth failures by reason"
      description = "HTTP auth failures grouped by reason."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "failures"
      program     = <<-EOT
        A = data('defenseclaw.http.auth.failures').sum(by=['reason']).publish(label='Auth failures')
      EOT
    }
    stream_lifecycle = {
      name        = "Stream lifecycle"
      description = "SSE stream open and close events grouped by outcome."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "events"
      program     = <<-EOT
        A = data('defenseclaw.stream.lifecycle').sum(by=['outcome']).publish(label='Stream events')
      EOT
    }
    stream_duration_p95 = {
      name        = "Stream duration p95"
      description = "P95 SSE stream duration."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.stream.duration_ms').percentile(pct=95).publish(label='p95 stream ms')
      EOT
    }
    tool_calls_by_tool = {
      name        = "Tool calls by tool and provider"
      description = "Runtime tool calls grouped by tool and provider."
      plot_type   = "AreaChart"
      stacked     = true
      axis_label  = "calls / min"
      program     = <<-EOT
        A = data('defenseclaw.tool.calls', rollup='rate').sum(by=['gen_ai.tool.name', 'tool.provider']).scale(60).publish(label='Tool calls / min')
      EOT
    }
    tool_duration_p95 = {
      name        = "Tool duration p95"
      description = "P95 runtime tool call duration."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.tool.duration').percentile(pct=95).publish(label='p95 tool ms')
      EOT
    }
    admission_decisions = {
      name        = "Admission decisions"
      description = "Admission gate decisions grouped by decision."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "decisions"
      program     = <<-EOT
        A = data('defenseclaw.admission.decisions').sum(by=['decision']).publish(label='Admission decisions')
      EOT
    }
    sink_batches = {
      name        = "Sink batches delivered vs dropped"
      description = "Audit sink delivery and drop counts."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "batches"
      program     = <<-EOT
        A = data('defenseclaw.audit.sink.batches.delivered').sum().publish(label='Delivered')
        B = data('defenseclaw.audit.sink.batches.dropped').sum().publish(label='Dropped')
      EOT
    }
    sink_delivery_latency_p95 = {
      name        = "Sink delivery latency p95"
      description = "P95 audit sink delivery latency."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.audit.sink.delivery.latency').percentile(pct=95).publish(label='p95 sink delivery ms')
      EOT
    }
    sink_queue_depth = {
      name        = "Sink queue depth"
      description = "Audit sink queue depth by sink kind and sink name."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "items"
      program     = <<-EOT
        A = data('defenseclaw.audit.sink.queue.depth', rollup='latest').max(by=['sink.kind', 'sink.name']).publish(label='Sink queue depth')
      EOT
    }
    webhook_outcomes = {
      name        = "Webhook outcomes"
      description = "Webhook dispatch outcomes grouped by outcome."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "dispatches"
      program     = <<-EOT
        A = data('defenseclaw.webhook.dispatches').sum(by=['outcome']).publish(label='Webhook dispatches')
      EOT
    }
    webhook_latency_p95 = {
      name        = "Webhook latency p95"
      description = "P95 webhook delivery latency."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.webhook.latency').percentile(pct=95).publish(label='p95 webhook ms')
      EOT
    }
    runtime_goroutines = {
      name        = "Runtime goroutines"
      description = "Go runtime goroutine gauge."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "goroutines"
      program     = <<-EOT
        A = data('defenseclaw.runtime.goroutines', rollup='latest').max().publish(label='Goroutines')
      EOT
    }
    runtime_heap = {
      name        = "Runtime heap"
      description = "Go heap allocation and object count gauges."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "bytes / objects"
      program     = <<-EOT
        A = data('defenseclaw.runtime.heap.alloc', rollup='latest').max().publish(label='Heap alloc bytes')
        B = data('defenseclaw.runtime.heap.objects', rollup='latest').max().publish(label='Heap objects')
      EOT
    }
    runtime_gc_pause_p99 = {
      name        = "Runtime GC pause p99"
      description = "P99 Go runtime GC pause duration."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ns"
      program     = <<-EOT
        A = histogram('defenseclaw.runtime.gc.pause').percentile(pct=99).publish(label='p99 GC pause ns')
      EOT
    }
    runtime_fd_in_use = {
      name        = "Runtime file descriptors"
      description = "Open file descriptor gauge."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "fds"
      program     = <<-EOT
        A = data('defenseclaw.runtime.fd.in_use', rollup='latest').max().publish(label='FDs in use')
      EOT
    }
    block_slo_latency_p95 = {
      name        = "Block SLO latency p95"
      description = "P95 admission/block SLO latency."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.slo.block.latency').percentile(pct=95).publish(label='p95 block SLO ms')
      EOT
    }
    tui_refresh_latency_p95 = {
      name        = "TUI refresh latency p95"
      description = "P95 TUI refresh latency."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.slo.tui.refresh').percentile(pct=95).publish(label='p95 TUI refresh ms')
      EOT
    }
    sqlite_size = {
      name        = "SQLite DB and WAL size"
      description = "SQLite DB and WAL file size gauges."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "bytes"
      program     = <<-EOT
        A = data('defenseclaw.sqlite.db.bytes', rollup='latest').max().publish(label='DB bytes')
        B = data('defenseclaw.sqlite.wal.bytes', rollup='latest').max().publish(label='WAL bytes')
      EOT
    }
    sqlite_checkpoint_p95 = {
      name        = "SQLite checkpoint duration p95"
      description = "P95 SQLite checkpoint duration."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.sqlite.checkpoint.duration').percentile(pct=95).publish(label='p95 checkpoint ms')
      EOT
    }
    sqlite_busy_retries = {
      name        = "SQLite busy retries"
      description = "SQLite busy retries grouped by operation."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "retries"
      program     = <<-EOT
        A = data('defenseclaw.sqlite.busy_retries').sum(by=['operation']).publish(label='Busy retries')
      EOT
    }
    exporter_errors = {
      name        = "Exporter errors by signal"
      description = "Telemetry exporter errors grouped by signal."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "errors"
      program     = <<-EOT
        A = data('defenseclaw.telemetry.exporter.errors').sum(by=['signal']).publish(label='Exporter errors')
      EOT
    }
    queue_depth = {
      name        = "Queue depth"
      description = "Generic buffered queue depth by queue."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "items"
      program     = <<-EOT
        A = data('defenseclaw.queue.depth', rollup='latest').max(by=['queue']).publish(label='Queue depth')
      EOT
    }
    queue_drops = {
      name        = "Queue drops"
      description = "Generic buffered queue drops grouped by queue and reason."
      plot_type   = "AreaChart"
      stacked     = true
      axis_label  = "drops / min"
      program     = <<-EOT
        A = data('defenseclaw.queue.drops', rollup='rate').sum(by=['queue', 'reason']).scale(60).publish(label='Queue drops / min')
      EOT
    }
    scans_by_scanner = {
      name        = "Scans by verdict"
      description = "Scan counts grouped by verdict."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "scans"
      program     = <<-EOT
        A = data('defenseclaw.scan.count').sum(by=['verdict']).publish(label='Scans')
      EOT
    }
    scan_counts_by_scanner = {
      name        = "Scans by scanner"
      description = "Scan counts grouped by scanner."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "scans"
      program     = <<-EOT
        A = data('defenseclaw.scan.count').sum(by=['scanner']).publish(label='Scans')
      EOT
    }
    scan_duration_p95 = {
      name        = "Scan duration p95"
      description = "P95 scanner duration."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "ms"
      program     = <<-EOT
        A = histogram('defenseclaw.scan.duration').percentile(pct=95).publish(label='p95 scan ms')
      EOT
    }
    scan_errors_by_type = {
      name        = "Scan errors by type"
      description = "Scanner error counts grouped by error type."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "errors"
      program     = <<-EOT
        A = data('defenseclaw.scan.errors').sum(by=['error_type']).publish(label='Scan errors')
      EOT
    }
    scanner_findings_by_severity = {
      name        = "Findings by severity"
      description = "Scan finding counts grouped by severity."
      plot_type   = "ColumnChart"
      stacked     = true
      axis_label  = "findings"
      program     = <<-EOT
        A = data('defenseclaw.scan.findings').sum(by=['severity']).publish(label='Findings')
      EOT
    }
    quarantine_actions = {
      name        = "Quarantine actions"
      description = "Quarantine and restore operations by operation and result."
      plot_type   = "AreaChart"
      stacked     = true
      axis_label  = "actions / min"
      program     = <<-EOT
        A = data('defenseclaw.quarantine.actions', rollup='rate').sum(by=['quarantine.op', 'quarantine.result']).scale(60).publish(label='Quarantine actions / min')
      EOT
    }
    scanner_queue_depth = {
      name        = "Scanner queue depth"
      description = "Scanner queue depth grouped by scanner."
      plot_type   = "LineChart"
      stacked     = false
      axis_label  = "items"
      program     = <<-EOT
        A = data('defenseclaw.scanner.queue.depth', rollup='latest').max(by=['scanner']).publish(label='Scanner queue depth')
      EOT
    }
  }

  time_chart_legend_dimensions = {
    verdicts_by_action              = "verdict.action"
    verdicts_by_stage               = "verdict.stage"
    verdicts_by_severity            = "verdict.severity"
    guardrail_evaluations_by_action = "guardrail.action_taken"
    inspections_by_tool             = "tool"
    inspections_by_severity         = "severity"
    blocked_inspections_by_tool     = "tool"
    alert_inspections_by_tool       = "tool"
    audit_events_by_action          = "action"
    otel_requests_by_source_signal  = "signal"
    otel_records_by_source_signal   = "signal"
    otel_bytes_by_source_signal     = "signal"
    malformed_by_source_signal      = "result"
    codex_notify_by_type_result     = "type"
    hook_invocations_by_connector   = "event_type"
    genai_tokens_by_agent_type      = "gen_ai.agent.name"
    llm_events_by_type              = "event_type"
    token_tokens_by_agent           = "gen_ai.agent.name"
    token_tokens_by_model           = "gen_ai.request.model"
    token_input_vs_output           = "gen_ai.token.type"
    token_estimated_cost_by_agent   = "gen_ai.agent.name"
    policy_evaluations_by_domain    = "policy.verdict"
    findings_by_severity            = "severity"
    findings_by_scanner             = "scanner"
    egress_by_decision              = "decision"
    alerts_by_type_severity         = "alert.severity"
    judge_errors_by_reason          = "judge.reason"
    guardrail_cache                 = "plot_label"
    gateway_errors_by_code          = "error.code"
    schema_violations_by_code       = "code"
    http_requests_by_route_status   = "http.status_code"
    auth_failures_by_reason         = "reason"
    stream_lifecycle                = "outcome"
    tool_calls_by_tool              = "gen_ai.tool.name"
    admission_decisions             = "decision"
    sink_batches                    = "plot_label"
    sink_queue_depth                = "sink.name"
    webhook_outcomes                = "outcome"
    runtime_heap                    = "plot_label"
    sqlite_size                     = "plot_label"
    sqlite_busy_retries             = "operation"
    exporter_errors                 = "signal"
    queue_depth                     = "queue"
    queue_drops                     = "queue"
    scans_by_scanner                = "verdict"
    scan_counts_by_scanner          = "scanner"
    scan_errors_by_type             = "error_type"
    scanner_findings_by_severity    = "severity"
    quarantine_actions              = "quarantine.op"
    scanner_queue_depth             = "scanner"
  }

  table_charts = {
    verdict_breakdown = {
      name        = "Verdict breakdown"
      description = "Gateway verdict totals by action in the selected time range."
      group_by    = ["verdict.action"]
      program     = <<-EOT
        A = data('defenseclaw.gateway.verdicts', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.verdicts', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum(by=['verdict.action']).sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Verdicts')
      EOT
    }
    policy_actions = {
      name        = "Policy verdict table"
      description = "Policy evaluation totals by domain and verdict in the selected time range."
      group_by    = ["policy.domain", "policy.verdict"]
      program     = <<-EOT
        A = data('defenseclaw.policy.evaluations', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.policy.evaluations', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum(by=['policy.domain', 'policy.verdict']).sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Policy evaluations')
      EOT
    }
    findings_by_rule = {
      name        = "Findings by rule"
      description = "Per-rule finding totals in the selected time range."
      group_by    = ["scanner", "rule_id", "severity"]
      program     = <<-EOT
        A = data('defenseclaw.scan.findings.by_rule', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.scan.findings.by_rule', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum(by=['scanner', 'rule_id', 'severity']).sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Findings')
      EOT
    }
    otel_ingest_mix = {
      name        = "OTLP ingest mix"
      description = "OTLP request totals by source, signal, and result in the selected time range."
      group_by    = ["source", "signal", "result"]
      program     = <<-EOT
        A = data('defenseclaw.otel.ingest.requests', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.otel.ingest.requests', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum(by=['source', 'signal', 'result']).sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='OTLP requests')
      EOT
    }
    codex_notify_mix = {
      name        = "Codex notify mix"
      description = "Codex notify event totals by type, status, and result in the selected time range."
      group_by    = ["type", "status", "result"]
      program     = <<-EOT
        A = data('defenseclaw.codex.notify', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.codex.notify', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum(by=['type', 'status', 'result']).sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Codex notify')
      EOT
    }
    token_agent_table = {
      name        = "Agent token table"
      description = "Current token rows grouped by agent, service, environment, provider, and model."
      group_by    = ["gen_ai.agent.name", "service.name", "deployment.environment", "gen_ai.provider.name", "gen_ai.request.model"]
      program     = <<-EOT
        A = data('gen_ai.client.token.usage', filter=filter('gen_ai.operation.name', 'chat'), rollup='sum').sum(by=['gen_ai.agent.name', 'service.name', 'deployment.environment', 'gen_ai.provider.name', 'gen_ai.request.model']).sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Tokens')
      EOT
    }
    sink_queue_by_sink = {
      name        = "Sink queue and circuit state"
      description = "Audit sink queue depth and circuit state by sink."
      group_by    = ["sink.kind", "sink.name"]
      program     = <<-EOT
        A = data('defenseclaw.audit.sink.queue.depth', rollup='latest').max(by=['sink.kind', 'sink.name']).publish(label='Queue depth')
        B = data('defenseclaw.audit.sink.circuit.state', rollup='latest').max(by=['sink.kind', 'sink.name']).publish(label='Circuit state')
      EOT
    }
    gateway_error_codes = {
      name        = "Gateway error codes"
      description = "Structured gateway error totals by subsystem and code in the selected time range."
      group_by    = ["error.subsystem", "error.code"]
      program     = <<-EOT
        A = data('defenseclaw.gateway.errors', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.gateway.errors', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum(by=['error.subsystem', 'error.code']).sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Gateway errors')
      EOT
    }
    scan_errors = {
      name        = "Scan error totals"
      description = "Scanner error totals in the selected time range by scanner and error type."
      group_by    = ["scanner", "error_type"]
      program     = <<-EOT
        A = data('defenseclaw.scan.errors', extrapolation='zero', rollup='delta')
        B = data('defenseclaw.scan.errors', extrapolation='zero', rollup='latest')
        C = A.delta()
        D = (A if C is not None else B).sum(by=['scanner', 'error_type']).sum(over=Args.get('ui.dashboard_window', '31d')).publish(label='Scan errors')
      EOT
    }
  }

  dashboard_layouts = {
    executive = [
      { type = "single", key = "executive_verdicts_31d", row = 0, column = 0, width = 2, height = 1 },
      { type = "single", key = "executive_blocks_31d", row = 0, column = 2, width = 2, height = 1 },
      { type = "single", key = "executive_guardrail_evaluations_31d", row = 0, column = 4, width = 2, height = 1 },
      { type = "single", key = "executive_inspect_evaluations_31d", row = 0, column = 6, width = 2, height = 1 },
      { type = "single", key = "executive_otel_records_31d", row = 0, column = 8, width = 2, height = 1 },
      { type = "single", key = "executive_gateway_errors_31d", row = 0, column = 10, width = 2, height = 1 },
      { type = "time", key = "verdicts_by_action", row = 1, column = 0, width = 4, height = 2 },
      { type = "time", key = "inspections_by_tool", row = 1, column = 4, width = 4, height = 2 },
      { type = "time", key = "guardrail_latency_p95", row = 1, column = 8, width = 4, height = 2 },
      { type = "time", key = "genai_tokens_by_agent_type", row = 3, column = 0, width = 4, height = 2 },
      { type = "time", key = "llm_events_by_type", row = 3, column = 4, width = 4, height = 2 },
      { type = "table", key = "verdict_breakdown", row = 3, column = 8, width = 4, height = 2 },
    ]
    guardrail_inspection = [
      { type = "single", key = "guardrail_total_evaluations", row = 0, column = 0, width = 2, height = 1 },
      { type = "single", key = "guardrail_total_inspections", row = 0, column = 2, width = 2, height = 1 },
      { type = "single", key = "guardrail_total_blocked_inspections", row = 0, column = 4, width = 2, height = 1 },
      { type = "single", key = "guardrail_total_alert_inspections", row = 0, column = 6, width = 2, height = 1 },
      { type = "single", key = "guardrail_total_audit_events", row = 0, column = 8, width = 2, height = 1 },
      { type = "single", key = "guardrail_total_runtime_alerts", row = 0, column = 10, width = 2, height = 1 },
      { type = "time", key = "guardrail_evaluations_by_action", row = 1, column = 0, width = 4, height = 2 },
      { type = "time", key = "blocked_inspections_by_tool", row = 1, column = 4, width = 4, height = 2 },
      { type = "time", key = "alert_inspections_by_tool", row = 1, column = 8, width = 4, height = 2 },
      { type = "time", key = "inspections_by_tool", row = 3, column = 0, width = 4, height = 2 },
      { type = "time", key = "inspections_by_severity", row = 3, column = 4, width = 4, height = 2 },
      { type = "time", key = "audit_events_by_action", row = 3, column = 8, width = 4, height = 2 },
      { type = "time", key = "guardrail_latency_p95", row = 5, column = 0, width = 6, height = 2 },
      { type = "time", key = "inspect_latency_p95", row = 5, column = 6, width = 6, height = 2 },
    ]
    connector_ingest = [
      { type = "single", key = "connector_total_otel_requests", row = 0, column = 0, width = 3, height = 1 },
      { type = "single", key = "connector_total_otel_records", row = 0, column = 3, width = 3, height = 1 },
      { type = "single", key = "connector_total_otel_bytes", row = 0, column = 6, width = 3, height = 1 },
      { type = "single", key = "connector_total_hook_invocations", row = 0, column = 9, width = 3, height = 1 },
      { type = "time", key = "otel_requests_by_source_signal", row = 1, column = 0, width = 4, height = 2 },
      { type = "time", key = "otel_records_by_source_signal", row = 1, column = 4, width = 4, height = 2 },
      { type = "time", key = "otel_bytes_by_source_signal", row = 1, column = 8, width = 4, height = 2 },
      { type = "time", key = "malformed_by_source_signal", row = 3, column = 0, width = 4, height = 2 },
      { type = "table", key = "otel_ingest_mix", row = 3, column = 4, width = 4, height = 2 },
      { type = "time", key = "hook_invocations_by_connector", row = 3, column = 8, width = 4, height = 2 },
      { type = "time", key = "hook_latency_p95", row = 5, column = 0, width = 4, height = 2 },
      { type = "time", key = "genai_tokens_by_agent_type", row = 5, column = 4, width = 4, height = 2 },
      { type = "time", key = "genai_operation_duration_p95", row = 5, column = 8, width = 4, height = 2 },
      { type = "time", key = "llm_events_by_type", row = 7, column = 0, width = 4, height = 2 },
    ]
    security_policy = [
      { type = "single", key = "security_total_policy_denies", row = 0, column = 0, width = 2, height = 1 },
      { type = "single", key = "security_total_findings", row = 0, column = 2, width = 2, height = 1 },
      { type = "single", key = "security_total_egress_blocks", row = 0, column = 4, width = 2, height = 1 },
      { type = "single", key = "security_total_runtime_alerts", row = 0, column = 6, width = 2, height = 1 },
      { type = "single", key = "security_total_judge_invocations", row = 0, column = 8, width = 2, height = 1 },
      { type = "single", key = "security_total_judge_errors", row = 0, column = 10, width = 2, height = 1 },
      { type = "time", key = "verdicts_by_stage", row = 1, column = 0, width = 4, height = 2 },
      { type = "time", key = "verdicts_by_severity", row = 1, column = 4, width = 4, height = 2 },
      { type = "table", key = "verdict_breakdown", row = 1, column = 8, width = 4, height = 2 },
      { type = "time", key = "policy_evaluations_by_domain", row = 3, column = 0, width = 4, height = 2 },
      { type = "time", key = "policy_latency_p95", row = 3, column = 4, width = 4, height = 2 },
      { type = "table", key = "policy_actions", row = 3, column = 8, width = 4, height = 2 },
      { type = "time", key = "judge_latency_p95", row = 5, column = 0, width = 4, height = 2 },
      { type = "time", key = "judge_errors_by_reason", row = 5, column = 4, width = 4, height = 2 },
      { type = "time", key = "findings_by_severity", row = 7, column = 0, width = 4, height = 2 },
      { type = "table", key = "findings_by_rule", row = 7, column = 4, width = 4, height = 2 },
      { type = "time", key = "egress_by_decision", row = 7, column = 8, width = 4, height = 2 },
      { type = "time", key = "alerts_by_type_severity", row = 9, column = 0, width = 4, height = 2 },
    ]
    token_economics = [
      { type = "single", key = "token_records", row = 0, column = 0, width = 2, height = 1 },
      { type = "single", key = "token_errors", row = 0, column = 2, width = 2, height = 1 },
      { type = "single", key = "token_active_agents", row = 0, column = 4, width = 2, height = 1 },
      { type = "single", key = "token_total_tokens", row = 0, column = 6, width = 2, height = 1 },
      { type = "single", key = "token_input_tokens", row = 0, column = 8, width = 2, height = 1 },
      { type = "single", key = "token_output_tokens", row = 0, column = 10, width = 2, height = 1 },
      { type = "single", key = "token_estimated_cost", row = 1, column = 0, width = 4, height = 1 },
      { type = "single", key = "token_estimated_input_cost", row = 1, column = 4, width = 4, height = 1 },
      { type = "single", key = "token_estimated_output_cost", row = 1, column = 8, width = 4, height = 1 },
      { type = "time", key = "token_tokens_by_agent", row = 2, column = 0, width = 4, height = 2 },
      { type = "time", key = "token_tokens_by_model", row = 2, column = 4, width = 4, height = 2 },
      { type = "time", key = "token_input_vs_output", row = 2, column = 8, width = 4, height = 2 },
      { type = "time", key = "token_estimated_cost_by_agent", row = 4, column = 0, width = 6, height = 2 },
      { type = "table", key = "token_agent_table", row = 4, column = 6, width = 6, height = 2 },
    ]
    runtime_reliability = [
      { type = "single", key = "runtime_total_gateway_errors", row = 0, column = 0, width = 2, height = 1 },
      { type = "single", key = "runtime_total_schema_violations", row = 0, column = 2, width = 2, height = 1 },
      { type = "single", key = "runtime_total_http_requests", row = 0, column = 4, width = 2, height = 1 },
      { type = "single", key = "runtime_total_auth_failures", row = 0, column = 6, width = 2, height = 1 },
      { type = "single", key = "runtime_total_exporter_errors", row = 0, column = 8, width = 2, height = 1 },
      { type = "single", key = "uptime_seconds", row = 0, column = 10, width = 2, height = 1 },
      { type = "time", key = "gateway_errors_by_code", row = 1, column = 0, width = 4, height = 2 },
      { type = "time", key = "schema_violations_by_code", row = 1, column = 4, width = 4, height = 2 },
      { type = "table", key = "gateway_error_codes", row = 1, column = 8, width = 4, height = 2 },
      { type = "time", key = "http_requests_by_route_status", row = 3, column = 0, width = 4, height = 2 },
      { type = "time", key = "http_duration_p95", row = 3, column = 4, width = 4, height = 2 },
      { type = "time", key = "auth_failures_by_reason", row = 3, column = 8, width = 4, height = 2 },
      { type = "time", key = "stream_lifecycle", row = 5, column = 0, width = 4, height = 2 },
      { type = "time", key = "stream_duration_p95", row = 5, column = 4, width = 4, height = 2 },
      { type = "time", key = "admission_decisions", row = 5, column = 8, width = 4, height = 2 },
      { type = "time", key = "sink_batches", row = 7, column = 0, width = 6, height = 2 },
      { type = "time", key = "webhook_outcomes", row = 7, column = 6, width = 6, height = 2 },
      { type = "time", key = "webhook_latency_p95", row = 9, column = 0, width = 4, height = 2 },
      { type = "time", key = "exporter_errors", row = 9, column = 4, width = 4, height = 2 },
      { type = "time", key = "sqlite_size", row = 9, column = 8, width = 4, height = 2 },
      { type = "time", key = "runtime_goroutines", row = 11, column = 0, width = 3, height = 2 },
      { type = "time", key = "runtime_heap", row = 11, column = 3, width = 3, height = 2 },
      { type = "time", key = "runtime_gc_pause_p99", row = 11, column = 6, width = 3, height = 2 },
      { type = "time", key = "runtime_fd_in_use", row = 11, column = 9, width = 3, height = 2 },
      { type = "time", key = "sqlite_busy_retries", row = 13, column = 0, width = 6, height = 2 },
      { type = "time", key = "sqlite_checkpoint_p95", row = 13, column = 6, width = 6, height = 2 },
    ]
    scanners_findings = [
      { type = "single", key = "scanner_total_scans", row = 0, column = 0, width = 3, height = 1 },
      { type = "single", key = "scanner_total_findings", row = 0, column = 3, width = 3, height = 1 },
      { type = "single", key = "scanner_total_scan_errors", row = 0, column = 6, width = 3, height = 1 },
      { type = "single", key = "scanner_open_findings", row = 0, column = 9, width = 3, height = 1 },
      { type = "time", key = "scans_by_scanner", row = 1, column = 0, width = 4, height = 2 },
      { type = "time", key = "scan_counts_by_scanner", row = 1, column = 4, width = 4, height = 2 },
      { type = "time", key = "scan_duration_p95", row = 1, column = 8, width = 4, height = 2 },
      { type = "time", key = "scanner_findings_by_severity", row = 3, column = 0, width = 4, height = 2 },
      { type = "time", key = "findings_by_scanner", row = 3, column = 4, width = 4, height = 2 },
      { type = "time", key = "scan_errors_by_type", row = 3, column = 8, width = 4, height = 2 },
      { type = "table", key = "scan_errors", row = 5, column = 0, width = 12, height = 2 },
    ]
  }
}

resource "signalfx_dashboard_group" "defenseclaw_o11y" {
  name        = "${local.display_name_prefix}DefenseClaw O11y"
  description = "Splunk Observability Cloud dashboards for DefenseClaw native OTel metrics."
}

resource "signalfx_single_value_chart" "single" {
  for_each = local.single_value_charts

  name                    = each.value.name
  description             = each.value.description
  program_text            = trimspace(each.value.program)
  color_by                = "Metric"
  max_precision           = 2
  is_timestamp_hidden     = true
  secondary_visualization = "None"
  show_spark_line         = false
  timezone                = "UTC"
  unit_prefix             = "Metric"
}

resource "signalfx_time_chart" "time" {
  for_each = local.time_charts

  name              = each.value.name
  description       = each.value.description
  program_text      = trimspace(each.value.program)
  plot_type         = each.value.plot_type
  stacked           = each.value.stacked
  time_range        = 3600
  axes_include_zero = true
  # Shows the color key directly on the chart for grouped series.
  on_chart_legend_dimension = lookup(local.time_chart_legend_dimensions, each.key, null)

  axis_left {
    label = each.value.axis_label
  }
}

resource "signalfx_table_chart" "table" {
  for_each = local.table_charts

  name         = each.value.name
  description  = each.value.description
  program_text = trimspace(each.value.program)
  group_by     = each.value.group_by
}

resource "signalfx_dashboard" "executive" {
  name            = "Executive Agent Watch${local.display_name_suffix}"
  description     = "Landing view for DefenseClaw verdicts, guardrails, inspections, connector ingress, GenAI usage, and error signals."
  dashboard_group = signalfx_dashboard_group.defenseclaw_o11y.id
  time_range      = "-31d"
  tags            = ["defenseclaw", "executive", "agentwatch", "otel"]

  dynamic "variable" {
    for_each = local.dashboard_variables.executive
    iterator = dashboard_var

    content {
      property       = dashboard_var.value.property
      alias          = dashboard_var.value.alias
      apply_if_exist = true
    }
  }

  dynamic "chart" {
    for_each = local.dashboard_layouts.executive
    iterator = dashboard_chart

    content {
      chart_id = (
        dashboard_chart.value.type == "single" ? signalfx_single_value_chart.single[dashboard_chart.value.key].id :
        dashboard_chart.value.type == "time" ? signalfx_time_chart.time[dashboard_chart.value.key].id :
        signalfx_table_chart.table[dashboard_chart.value.key].id
      )
      width  = dashboard_chart.value.width
      height = dashboard_chart.value.height
      row    = dashboard_chart.value.row
      column = dashboard_chart.value.column
    }
  }
}

resource "signalfx_dashboard" "guardrail_inspection" {
  name            = "Guardrail and Inspection${local.display_name_suffix}"
  description     = "Guardrail evaluations, tool inspections, block/alert outcomes, audit events, and guardrail/inspection latency."
  dashboard_group = signalfx_dashboard_group.defenseclaw_o11y.id
  time_range      = "-31d"
  tags            = ["defenseclaw", "guardrail", "inspection", "otel"]

  dynamic "variable" {
    for_each = local.dashboard_variables.guardrail_inspection
    iterator = dashboard_var

    content {
      property       = dashboard_var.value.property
      alias          = dashboard_var.value.alias
      apply_if_exist = true
    }
  }

  dynamic "chart" {
    for_each = local.dashboard_layouts.guardrail_inspection
    iterator = dashboard_chart

    content {
      chart_id = (
        dashboard_chart.value.type == "single" ? signalfx_single_value_chart.single[dashboard_chart.value.key].id :
        dashboard_chart.value.type == "time" ? signalfx_time_chart.time[dashboard_chart.value.key].id :
        signalfx_table_chart.table[dashboard_chart.value.key].id
      )
      width  = dashboard_chart.value.width
      height = dashboard_chart.value.height
      row    = dashboard_chart.value.row
      column = dashboard_chart.value.column
    }
  }
}

resource "signalfx_dashboard" "connector_ingest" {
  name            = "Connector and OTel Ingest${local.display_name_suffix}"
  description     = "OTLP ingest health, connector hooks, Codex notify, normalized LLM events, and GenAI token/duration telemetry."
  dashboard_group = signalfx_dashboard_group.defenseclaw_o11y.id
  time_range      = "-1h"
  tags            = ["defenseclaw", "connectors", "otel", "codex", "claudecode"]

  dynamic "variable" {
    for_each = local.dashboard_variables.connector_ingest
    iterator = dashboard_var

    content {
      property       = dashboard_var.value.property
      alias          = dashboard_var.value.alias
      apply_if_exist = true
    }
  }

  dynamic "chart" {
    for_each = local.dashboard_layouts.connector_ingest
    iterator = dashboard_chart

    content {
      chart_id = (
        dashboard_chart.value.type == "single" ? signalfx_single_value_chart.single[dashboard_chart.value.key].id :
        dashboard_chart.value.type == "time" ? signalfx_time_chart.time[dashboard_chart.value.key].id :
        signalfx_table_chart.table[dashboard_chart.value.key].id
      )
      width  = dashboard_chart.value.width
      height = dashboard_chart.value.height
      row    = dashboard_chart.value.row
      column = dashboard_chart.value.column
    }
  }
}

resource "signalfx_dashboard" "security_policy" {
  name            = "Security and Policy${local.display_name_suffix}"
  description     = "Gateway verdicts, policy decisions, findings, egress decisions, alerts, judge latency/errors, and external security integrations."
  dashboard_group = signalfx_dashboard_group.defenseclaw_o11y.id
  time_range      = "-1h"
  tags            = ["defenseclaw", "security", "policy", "otel"]

  dynamic "variable" {
    for_each = local.dashboard_variables.security_policy
    iterator = dashboard_var

    content {
      property       = dashboard_var.value.property
      alias          = dashboard_var.value.alias
      apply_if_exist = true
    }
  }

  dynamic "chart" {
    for_each = local.dashboard_layouts.security_policy
    iterator = dashboard_chart

    content {
      chart_id = (
        dashboard_chart.value.type == "single" ? signalfx_single_value_chart.single[dashboard_chart.value.key].id :
        dashboard_chart.value.type == "time" ? signalfx_time_chart.time[dashboard_chart.value.key].id :
        signalfx_table_chart.table[dashboard_chart.value.key].id
      )
      width  = dashboard_chart.value.width
      height = dashboard_chart.value.height
      row    = dashboard_chart.value.row
      column = dashboard_chart.value.column
    }
  }
}

resource "signalfx_dashboard" "token_economics" {
  name            = "DefenseClaw AI Agents Token Economics${local.display_name_suffix}"
  description     = "AI agent token usage and dashboard-side cost estimates from DefenseClaw GenAI OTel metrics. Cost cards use hardcoded pricebook rates and should be updated when supported model pricing changes."
  dashboard_group = signalfx_dashboard_group.defenseclaw_o11y.id
  time_range      = "-31d"
  tags            = ["defenseclaw", "genai", "tokenomics", "otel"]

  dynamic "variable" {
    for_each = local.dashboard_variables.token_economics
    iterator = dashboard_var

    content {
      property       = dashboard_var.value.property
      alias          = dashboard_var.value.alias
      apply_if_exist = true
    }
  }

  dynamic "chart" {
    for_each = local.dashboard_layouts.token_economics
    iterator = dashboard_chart

    content {
      chart_id = (
        dashboard_chart.value.type == "single" ? signalfx_single_value_chart.single[dashboard_chart.value.key].id :
        dashboard_chart.value.type == "time" ? signalfx_time_chart.time[dashboard_chart.value.key].id :
        signalfx_table_chart.table[dashboard_chart.value.key].id
      )
      width  = dashboard_chart.value.width
      height = dashboard_chart.value.height
      row    = dashboard_chart.value.row
      column = dashboard_chart.value.column
    }
  }
}

resource "signalfx_dashboard" "runtime_reliability" {
  name            = "Runtime and Reliability${local.display_name_suffix}"
  description     = "Gateway reliability, HTTP traffic, auth failures, streams, audit sinks, webhooks, runtime gauges, exporter errors, and SQLite health."
  dashboard_group = signalfx_dashboard_group.defenseclaw_o11y.id
  time_range      = "-1h"
  tags            = ["defenseclaw", "runtime", "reliability", "slo", "otel"]

  dynamic "variable" {
    for_each = local.dashboard_variables.runtime_reliability
    iterator = dashboard_var

    content {
      property       = dashboard_var.value.property
      alias          = dashboard_var.value.alias
      apply_if_exist = true
    }
  }

  dynamic "chart" {
    for_each = local.dashboard_layouts.runtime_reliability
    iterator = dashboard_chart

    content {
      chart_id = (
        dashboard_chart.value.type == "single" ? signalfx_single_value_chart.single[dashboard_chart.value.key].id :
        dashboard_chart.value.type == "time" ? signalfx_time_chart.time[dashboard_chart.value.key].id :
        signalfx_table_chart.table[dashboard_chart.value.key].id
      )
      width  = dashboard_chart.value.width
      height = dashboard_chart.value.height
      row    = dashboard_chart.value.row
      column = dashboard_chart.value.column
    }
  }
}

resource "signalfx_dashboard" "scanners_findings" {
  name            = "Scanners and Findings${local.display_name_suffix}"
  description     = "Scanner throughput, scanner latency, scan errors, and findings by severity and scanner."
  dashboard_group = signalfx_dashboard_group.defenseclaw_o11y.id
  time_range      = "-1h"
  tags            = ["defenseclaw", "scanners", "findings", "otel"]

  dynamic "variable" {
    for_each = local.dashboard_variables.scanners_findings
    iterator = dashboard_var

    content {
      property       = dashboard_var.value.property
      alias          = dashboard_var.value.alias
      apply_if_exist = true
    }
  }

  dynamic "chart" {
    for_each = local.dashboard_layouts.scanners_findings
    iterator = dashboard_chart

    content {
      chart_id = (
        dashboard_chart.value.type == "single" ? signalfx_single_value_chart.single[dashboard_chart.value.key].id :
        dashboard_chart.value.type == "time" ? signalfx_time_chart.time[dashboard_chart.value.key].id :
        signalfx_table_chart.table[dashboard_chart.value.key].id
      )
      width  = dashboard_chart.value.width
      height = dashboard_chart.value.height
      row    = dashboard_chart.value.row
      column = dashboard_chart.value.column
    }
  }
}

output "dashboard_urls" {
  description = "Created Splunk Observability dashboard URLs."
  value = {
    executive            = signalfx_dashboard.executive.url
    guardrail_inspection = signalfx_dashboard.guardrail_inspection.url
    connector_ingest     = signalfx_dashboard.connector_ingest.url
    security_policy      = signalfx_dashboard.security_policy.url
    token_economics      = signalfx_dashboard.token_economics.url
    runtime_reliability  = signalfx_dashboard.runtime_reliability.url
    scanners_findings    = signalfx_dashboard.scanners_findings.url
  }
}
