// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"encoding/json"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/trace"
)

// NetworkEgressLogAttrs is the sanitized cross-signal correlation contract
// for website/network activity. Full URLs and bodies are deliberately omitted
// because query strings frequently contain credentials; the audit DB remains
// the forensic source for the complete operator-permitted record.
type NetworkEgressLogAttrs struct {
	SessionID, Connector, AgentID, RootAgentID, ParentAgentID, RootSessionID string
	LifecycleID, ExecutionID, UserID, ToolID                                 string
	Hostname, HTTPMethod, Protocol, PolicyOutcome, DecisionCode, Severity    string
	Blocked                                                                  bool
}

// EmitNetworkEgressLog emits an immediately queryable Loki record for both
// allowed and blocked outbound interactions.
func (p *Provider) EmitNetworkEgressLog(ctx context.Context, attrs NetworkEgressLogAttrs) {
	if p == nil || !p.LogsEnabled() {
		return
	}
	now := time.Now()
	record := otellog.Record{}
	record.SetTimestamp(now)
	record.SetObservedTimestamp(now)
	record.SetSeverityText(attrs.Severity)
	if attrs.Blocked {
		record.SetSeverity(otellog.SeverityWarn)
	} else {
		record.SetSeverity(otellog.SeverityInfo)
	}
	eventType := string(gatewaylog.EventEgress)
	bodyFields := map[string]interface{}{
		"event_type": eventType, "hostname": attrs.Hostname,
		"http_method": attrs.HTTPMethod, "protocol": attrs.Protocol,
		"blocked": attrs.Blocked, "decision_code": attrs.DecisionCode,
	}
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		bodyFields["trace_id"] = spanContext.TraceID().String()
		bodyFields["span_id"] = spanContext.SpanID().String()
	}
	body, _ := json.Marshal(bodyFields)
	record.SetBody(otellog.StringValue(string(body)))
	logAttrs := []otellog.KeyValue{
		otellog.String("defenseclaw.gateway.event_type", eventType),
		otellog.String("connector", attrs.Connector),
		otellog.String("gen_ai.agent.id", attrs.AgentID),
		otellog.String("defenseclaw.agent.root.id", attrs.RootAgentID),
		otellog.String("defenseclaw.agent.parent.id", attrs.ParentAgentID),
		otellog.String("gen_ai.conversation.id", attrs.SessionID),
		otellog.String("defenseclaw.session.root.id", attrs.RootSessionID),
		otellog.String("defenseclaw.agent.lifecycle.id", attrs.LifecycleID),
		otellog.String("defenseclaw.agent.execution.id", attrs.ExecutionID),
		otellog.String("user.id", attrs.UserID),
		otellog.String("gen_ai.tool.call.id", attrs.ToolID),
		otellog.String("server.address", attrs.Hostname),
		otellog.String("http.request.method", attrs.HTTPMethod),
		otellog.String("url.scheme", attrs.Protocol),
		otellog.String("defenseclaw.policy.outcome", attrs.PolicyOutcome),
		otellog.String("defenseclaw.policy.decision_code", attrs.DecisionCode),
		otellog.Bool("defenseclaw.network.blocked", attrs.Blocked),
	}
	if spanContext.IsValid() {
		logAttrs = append(logAttrs,
			otellog.String("trace_id", spanContext.TraceID().String()),
			otellog.String("span_id", spanContext.SpanID().String()),
		)
	}
	record.AddAttributes(logAttrs...)
	p.logger.Emit(ctx, record)
}
