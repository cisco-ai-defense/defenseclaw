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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/metric"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// RecordGatewayEvent derives metric observations from a single
// structured gatewaylog.Event. Called by EmitGatewayEvent so the
// writer fanout drives logs + metrics from a single side-effect.
//
// Attribute cardinality is intentionally small (stage/action/
// severity/kind/subsystem) — model/provider dimensions live on
// logs and traces, not counters, to keep metric storage bounded.
func (p *Provider) RecordGatewayEvent(e gatewaylog.Event) {
	if !p.Enabled() || p.metrics == nil {
		return
	}
	ctx := context.Background()

	switch e.EventType {
	case gatewaylog.EventVerdict:
		if e.Verdict == nil {
			return
		}
		p.metrics.verdictsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("verdict.stage", string(e.Verdict.Stage)),
			attribute.String("verdict.action", e.Verdict.Action),
			attribute.String("verdict.severity", strings.ToUpper(string(e.Severity))),
		))
	case gatewaylog.EventJudge:
		if e.Judge == nil {
			return
		}
		p.metrics.judgeInvocations.Add(ctx, 1, metric.WithAttributes(
			attribute.String("judge.kind", e.Judge.Kind),
			attribute.String("judge.action", e.Judge.Action),
			attribute.String("judge.severity", strings.ToUpper(string(e.Severity))),
		))
		p.metrics.judgeLatency.Record(ctx, float64(e.Judge.LatencyMs),
			metric.WithAttributes(attribute.String("judge.kind", e.Judge.Kind)))
		if e.Judge.Action == "error" || e.Judge.ParseError != "" {
			// Label set is intentionally small (kind + reason
			// class) to keep the time series bounded. The raw
			// parse-error string is redacted and may embed a
			// hash prefix, which would otherwise explode the
			// counter's cardinality to one series per unique
			// redacted value. The detailed reason lives in
			// the log record emitted below.
			reason := "provider"
			if e.Judge.ParseError != "" {
				reason = "parse"
			}
			p.metrics.judgeErrors.Add(ctx, 1, metric.WithAttributes(
				attribute.String("judge.kind", e.Judge.Kind),
				attribute.String("judge.reason", reason),
			))
		}
	case gatewaylog.EventError:
		if e.Error == nil {
			return
		}
		p.metrics.gatewayErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("error.subsystem", e.Error.Subsystem),
			attribute.String("error.code", e.Error.Code),
		))
	}
}

// EmitGatewayEvent maps a structured gatewaylog.Event onto an OTel
// LogRecord and, when appropriate, records metric observations.
// Callers should attach this via gatewaylog.Writer.WithFanout so
// every JSONL event also lands on the configured OTLP logs pipeline.
//
// The mapping is intentionally lossless for the top-level envelope
// (timestamp, severity, identifiers) while typed payload fields are
// serialized into the record body as compact JSON. Operators can
// query the flat attributes for filtering and drill into body JSON
// for details.
func (p *Provider) EmitGatewayEvent(e gatewaylog.Event) {
	if !p.Enabled() {
		// Still record metrics even when log export is off — the meter
		// may be a no-op but RecordGatewayEvent short-circuits cleanly.
		p.RecordGatewayEvent(e)
		return
	}

	p.RecordGatewayEvent(e)

	if !p.LogsEnabled() {
		return
	}

	sevText, sevNum := gatewaySeverityToOTel(e.Severity)

	now := e.Timestamp
	if now.IsZero() {
		now = time.Now()
	}

	rec := log.Record{}
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(log.Severity(sevNum))
	rec.SetSeverityText(sevText)
	rec.SetBody(log.StringValue(renderGatewayBody(e)))

	attrs := []log.KeyValue{
		log.String("event.name", "defenseclaw.gateway."+string(e.EventType)),
		log.String("event.domain", "defenseclaw.gateway"),
		log.String("defenseclaw.gateway.event_type", string(e.EventType)),
	}
	if e.RunID != "" {
		attrs = append(attrs, log.String("defenseclaw.run_id", e.RunID))
	}
	if e.RequestID != "" {
		attrs = append(attrs, log.String("defenseclaw.request_id", e.RequestID))
	}
	if e.SessionID != "" {
		attrs = append(attrs, log.String("defenseclaw.session_id", e.SessionID))
	}
	if e.Provider != "" {
		attrs = append(attrs, log.String("defenseclaw.llm.provider", e.Provider))
	}
	if e.Model != "" {
		attrs = append(attrs, log.String("defenseclaw.llm.model", e.Model))
	}
	if e.Direction != "" {
		attrs = append(attrs, log.String("defenseclaw.direction", string(e.Direction)))
	}

	switch e.EventType {
	case gatewaylog.EventVerdict:
		if v := e.Verdict; v != nil {
			attrs = append(attrs,
				log.String("defenseclaw.verdict.stage", string(v.Stage)),
				log.String("defenseclaw.verdict.action", v.Action),
				log.String("defenseclaw.verdict.reason", v.Reason),
				log.Int64("defenseclaw.verdict.latency_ms", v.LatencyMs),
			)
			if len(v.Categories) > 0 {
				attrs = append(attrs,
					log.String("defenseclaw.verdict.categories", strings.Join(v.Categories, ",")))
			}
		}
	case gatewaylog.EventJudge:
		if j := e.Judge; j != nil {
			attrs = append(attrs,
				log.String("defenseclaw.judge.kind", j.Kind),
				log.String("defenseclaw.judge.action", j.Action),
				log.Int64("defenseclaw.judge.latency_ms", j.LatencyMs),
				log.Int("defenseclaw.judge.input_bytes", j.InputBytes),
			)
			if j.ParseError != "" {
				attrs = append(attrs, log.String("defenseclaw.judge.parse_error", j.ParseError))
			}
		}
	case gatewaylog.EventLifecycle:
		if l := e.Lifecycle; l != nil {
			attrs = append(attrs,
				log.String("defenseclaw.lifecycle.subsystem", l.Subsystem),
				log.String("defenseclaw.lifecycle.transition", l.Transition),
			)
		}
	case gatewaylog.EventError:
		if er := e.Error; er != nil {
			attrs = append(attrs,
				log.String("defenseclaw.error.subsystem", er.Subsystem),
				log.String("defenseclaw.error.code", er.Code),
			)
			if er.Cause != "" {
				attrs = append(attrs, log.String("defenseclaw.error.cause", er.Cause))
			}
		}
	case gatewaylog.EventDiagnostic:
		if d := e.Diagnostic; d != nil {
			attrs = append(attrs,
				log.String("defenseclaw.diagnostic.component", d.Component))
		}
	}

	rec.AddAttributes(attrs...)
	p.logger.Emit(context.Background(), rec)
}

// gatewaySeverityToOTel maps the gatewaylog severity enum onto the
// OpenTelemetry severity number/text pair. Unknown values fall back
// to INFO so we never drop a record to an enum mismatch.
func gatewaySeverityToOTel(s gatewaylog.Severity) (string, int) {
	switch strings.ToUpper(string(s)) {
	case "CRITICAL":
		return "CRITICAL", 21
	case "HIGH":
		return "ERROR", 17
	case "MEDIUM":
		return "WARN", 13
	case "LOW":
		return "INFO2", 10
	case "INFO":
		return "INFO", 9
	default:
		return "INFO", 9
	}
}

// renderGatewayBody produces a compact JSON body — OTel logs
// consumers can pretty-print this, and JSON keeps the structure
// addressable via jq/splunk spath without a custom parser.
func renderGatewayBody(e gatewaylog.Event) string {
	buf, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf("event=%s severity=%s (marshal-failed: %v)",
			e.EventType, e.Severity, err)
	}
	return string(buf)
}
