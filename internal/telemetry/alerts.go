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

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/log"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// AlertType constants for defenseclaw.alert.type.
const (
	AlertDangerousCommand = "dangerous-command"
	AlertGuardrailFlag    = "guardrail-flag"
	AlertGuardrailBlock   = "guardrail-block"
	AlertPromptInjection  = "prompt-injection"
	AlertDataExfiltration = "data-exfiltration"
	AlertContentViolation = "content-violation"
	AlertCodeGuardFinding = "codeguard-finding"
	AlertToolCallFlagged  = "tool-call-flagged"
)

// AlertSource constants for defenseclaw.alert.source.
const (
	SourceLocalPattern   = "local-pattern"
	SourceLocalGuardrail = "local-guardrail"
	SourceAIDefense      = "ai-defense"
	SourceOPAPolicy      = "opa-policy"
	SourceCodeGuard      = "codeguard"
	SourceToolInspect    = "tool-inspect"
)

// EmitRuntimeAlert emits a high-priority OTel LogRecord for a runtime alert.
func (p *Provider) EmitRuntimeAlert(
	alertType, severity, source, body string,
	trigger map[string]string,
	guardrail map[string]string,
	traceID, spanID string,
) {
	if !p.Enabled() {
		return
	}

	ctx := context.Background()

	p.RecordAlert(ctx, alertType, severity, source)

	if guardrailScanner, ok := guardrail["scanner"]; ok {
		actionTaken := guardrail["action_taken"]
		p.RecordGuardrailEvaluation(ctx, guardrailScanner, actionTaken, MetricEnvelope{
			Result: actionTaken,
		})
	}

	if !p.LogsEnabled() {
		return
	}

	sevText, sevNum := alertSeverityToOTel(severity)
	alertID := uuid.New().String()

	// Alert bodies are built from reason strings that
	// commonly embed the matched literal (e.g. the full
	// prompt that triggered a prompt-injection block, or
	// the scanned secret). OTel is a persistent sink, so
	// always redact via ForSinkReason (preserves rule IDs
	// while scrubbing PII/secret content).
	safeBody := redaction.ForSinkReason(body)

	now := time.Now()
	rec := log.Record{}
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(log.Severity(sevNum))
	rec.SetSeverityText(sevText)
	rec.SetBody(log.StringValue(safeBody))

	attrs := []log.KeyValue{
		log.String("event.name", "runtime.alert"),
		log.String("event.domain", "defenseclaw.runtime"),
		log.String("defenseclaw.alert.id", alertID),
		log.String("defenseclaw.alert.type", alertType),
		log.String("defenseclaw.alert.severity", severity),
		log.String("defenseclaw.alert.source", source),
	}

	if v, ok := trigger["tool"]; ok && v != "" {
		attrs = append(attrs, log.String("defenseclaw.alert.trigger.tool", v))
	}
	if v, ok := trigger["command"]; ok && v != "" {
		attrs = append(attrs, log.String("defenseclaw.alert.trigger.command", baseCommand(v)))
	}
	if v, ok := trigger["model"]; ok && v != "" {
		attrs = append(attrs, log.String("defenseclaw.alert.trigger.model", v))
	}
	if v, ok := trigger["direction"]; ok && v != "" {
		attrs = append(attrs, log.String("defenseclaw.alert.trigger.direction", v))
	}

	if v, ok := guardrail["scanner"]; ok && v != "" {
		attrs = append(attrs, log.String("defenseclaw.guardrail.scanner", v))
	}
	if v, ok := guardrail["policy"]; ok && v != "" {
		attrs = append(attrs, log.String("defenseclaw.guardrail.policy", v))
	}
	if v, ok := guardrail["action_taken"]; ok && v != "" {
		attrs = append(attrs, log.String("defenseclaw.guardrail.action_taken", v))
	}

	if traceID != "" {
		attrs = append(attrs, log.String("defenseclaw.alert.trace_id", traceID))
	}
	if spanID != "" {
		attrs = append(attrs, log.String("defenseclaw.alert.span_id", spanID))
	}

	rec.AddAttributes(attrs...)
	p.logger.Emit(ctx, rec)
}

func alertSeverityToOTel(sev string) (string, int) {
	switch sev {
	case "CRITICAL":
		return "CRITICAL", 21
	case "HIGH":
		return "HIGH", 17
	case "MEDIUM":
		return "MEDIUM", 13
	default:
		return "LOW", 9
	}
}
