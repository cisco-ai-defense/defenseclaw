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

	"go.opentelemetry.io/otel/log"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// EmitPolicyDecision emits an OTel LogRecord for a security-relevant policy
// evaluation decision such as firewall deny, admission block, or sandbox
// restrict. Routine "allow" decisions should generally not be emitted to
// avoid log noise; callers decide when a decision is noteworthy.
func (p *Provider) EmitPolicyDecision(
	domain, verdict, target, targetType, reason string,
	extra map[string]string,
) {
	if !p.LogsEnabled() {
		return
	}

	sevText, sevNum := policyVerdictSeverity(verdict)
	// OTel is a persistent sink. Reasons are the most
	// frequent leak vector because they routinely embed the
	// matched literal ("blocked secret sk-ant-api03-...").
	// Run reason + any extra attributes through the sink
	// redactor before export. Verdict/target/type are
	// short enums, safe as-is.
	safeReason := redaction.ForSinkReason(reason)
	body := domain + " policy: " + verdict + " " + targetType + " " + target

	now := time.Now()
	rec := log.Record{}
	rec.SetTimestamp(now)
	rec.SetObservedTimestamp(now)
	rec.SetSeverity(log.Severity(sevNum))
	rec.SetSeverityText(sevText)
	rec.SetBody(log.StringValue(body))

	attrs := []log.KeyValue{
		log.String("event.name", "policy.decision"),
		log.String("event.domain", "defenseclaw.policy"),
		log.String("defenseclaw.policy.domain", domain),
		log.String("defenseclaw.policy.verdict", verdict),
		log.String("defenseclaw.policy.target", target),
		log.String("defenseclaw.policy.target_type", targetType),
		log.String("defenseclaw.policy.reason", safeReason),
	}

	for k, v := range extra {
		if v != "" {
			attrs = append(attrs, log.String("defenseclaw.policy."+k, redaction.ForSinkString(v)))
		}
	}

	rec.AddAttributes(attrs...)
	p.logger.Emit(context.Background(), rec)
}

func policyVerdictSeverity(verdict string) (string, int) {
	switch verdict {
	case "blocked", "rejected", "deny", "block":
		return "WARN", 13
	case "failed":
		return "ERROR", 17
	default:
		return "INFO", 9
	}
}
