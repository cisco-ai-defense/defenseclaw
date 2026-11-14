// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// hookDecisionConnectorHookID is the export id of the v7 connector-hook line
// an export derives from a hook_decision row that is its decision's only
// local row: the row's id with a fixed suffix, so a re-export gives the same
// id and it never collides with a stored row.
const hookDecisionConnectorHookIDSuffix = "-connector-hook"

// hookDecisionConnectorHook is the v7 connector-hook row of a benign
// per-user allow whose connector-hook record was exported but not written
// locally (#1384): an audit export still has one connector-hook line per
// decision, built from the facts its hook_decision row keeps (the
// defenseclaw.hook.v1 envelope fields; the hook compatibility extras are
// not kept). ok is false for a body that is not a hook decision.
func hookDecisionConnectorHook(connector, body string) (target, details, structured string, ok bool) {
	var fields map[string]any
	if err := json.Unmarshal([]byte(body), &fields); err != nil || fields == nil {
		return "", "", "", false
	}
	text := func(key string) string {
		value, _ := fields[key].(string)
		return strings.TrimSpace(value)
	}
	event, action := text("defenseclaw.hook.event"), text("defenseclaw.guardrail.effective_action")
	if event == "" || action == "" {
		return "", "", "", false
	}
	result := hookExportFirstNonEmpty(text("defenseclaw.hook.result"), "ok")
	rawAction := hookExportFirstNonEmpty(text("defenseclaw.guardrail.raw_action"), action)
	severity := hookExportFirstNonEmpty(text("defenseclaw.security.severity"), "NONE")
	// hook_decision names the mode observe or enforce; the hook envelope
	// says action for an enforcing mode.
	mode := text("defenseclaw.guardrail.mode")
	if mode == "enforce" {
		mode = "action"
	}
	wouldBlock, _ := fields["defenseclaw.guardrail.would_block"].(bool)
	elapsed := int64(0)
	if latency, isNumber := fields["defenseclaw.guardrail.latency_ms"].(float64); isNumber && latency >= 0 && latency < math.MaxInt64 {
		elapsed = int64(latency)
	}
	envelope := map[string]any{
		"schema": "defenseclaw.hook.v1", "connector": connector, "event": event, "result": result,
		"action": action, "raw_action": rawAction, "severity": severity, "mode": mode,
		"would_block": wouldBlock, "elapsed_ms": elapsed,
	}
	copyField := func(from, to string) {
		if value, present := fields[from]; present && value != nil {
			envelope[to] = value
		}
	}
	copyField("defenseclaw.hook.body_bytes", "body_bytes")
	copyField("defenseclaw.hook.raw_origin", "raw_origin")
	copyField("defenseclaw.hook.raw_event_ids", "raw_event_ids")
	copyField("defenseclaw.guardrail.reason", "reason")
	copyField("defenseclaw.guardrail.rule_ids", "rule_ids")
	copyField("defenseclaw.evaluation.id", "evaluation_id")
	copyField("defenseclaw.connector.step_idx", "step_idx")
	copyField("defenseclaw.agent.phase", "agent_phase")
	copyField("defenseclaw.agent.sequence", "agent_sequence")
	copyField("defenseclaw.agent.lifecycle.id", "agent_lifecycle_id")
	copyField("defenseclaw.agent.execution.id", "agent_execution_id")
	copyField("defenseclaw.operation.id", "agent_operation_id")
	copyField("user.id", "user.id")
	copyField("defenseclaw.user.name", "defenseclaw.user.name")
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return "", "", "", false
	}
	var tail strings.Builder
	fmt.Fprintf(&tail, "connector=%s result=%s action=%s raw_action=%s severity=%s mode=%s would_block=%t elapsed_ms=%d",
		connector, result, action, rawAction, severity, mode, wouldBlock, elapsed)
	if bytes, isNumber := fields["defenseclaw.hook.body_bytes"].(float64); isNumber {
		fmt.Fprintf(&tail, " body_bytes=%d", int64(bytes))
	}
	if origin := text("defenseclaw.hook.raw_origin"); origin != "" {
		fmt.Fprintf(&tail, " raw_origin=%s", origin)
	}
	fmt.Fprintf(&tail, " details_json=%s", strconv.Quote(string(encoded)))
	return event, tail.String(), string(encoded), true
}

func hookExportFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// loneHookDecisionBodySQL selects the body of a hook_decision row that is
// its decision's only local hook row (audit.LoneHookDecisionSQL), NULL for
// every other row.
func loneHookDecisionBodySQL() string {
	return `CASE WHEN ` + audit.LoneHookDecisionSQL("") + ` THEN ` + audit.HookDecisionBodySQL("") + ` END`
}
