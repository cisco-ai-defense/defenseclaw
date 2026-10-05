// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// hookGuardrailOutcome is the guardrail action a hook decision imposed on
// one operation (block, ask or alert). It rides llmEventMeta onto the tool
// span of the call, so every trace destination sees the decision on the
// span itself: an ERROR status for a block, a defenseclaw.guardrail.<action>
// event and flat defenseclaw.guardrail.action/rule_id/severity attributes.
type hookGuardrailOutcome struct {
	Action   string
	RuleID   string
	Severity string
	// Reason is the decision reason with matched literals redacted.
	Reason string
	At     time.Time
}

// hookGuardrailOutcomeFor maps a connector-facing hook decision onto the
// outcome vocabulary. Allow, including an observe-mode would-block, has none.
func hookGuardrailOutcomeFor(action, severity, reason string, ruleIDs []string) (hookGuardrailOutcome, bool) {
	outcome := hookGuardrailOutcome{Reason: guardrailSpanReason(strings.TrimSpace(reason)), At: time.Now().UTC()}
	switch normalizeHookActionLabel(action) {
	case "block":
		outcome.Action = "block"
	case "confirm":
		outcome.Action = "ask"
	case "alert":
		outcome.Action = "alert"
	default:
		return hookGuardrailOutcome{}, false
	}
	for _, id := range ruleIDs {
		if hookV8OptionalIdentifier(id).IsPresent() {
			outcome.RuleID = strings.TrimSpace(id)
			break
		}
	}
	if normalized := observability.NormalizeSeverity(severity); normalized.Valid && normalized.Present {
		outcome.Severity = string(normalized.Severity)
	}
	return outcome, true
}

// guardrailSpanReason is the reason a guardrail span carries. A reason made
// only of shipped rule IDs and their exact catalog titles
// (trustedBuiltInMatchReason) is DefenseClaw-authored and stays readable, as
// on agent and notification surfaces; the sink scrub turned "matched:
// <RULE-ID>:SSH authorized keys mutation" into a redacted token. Any other
// reason, and every reason under a managed (Secure Client) redaction policy,
// keeps the scrub.
func guardrailSpanReason(reason string) string {
	if !managedEnterpriseActive.Load() && trustedBuiltInMatchReason(reason) {
		return reason
	}
	return redaction.ForSinkReason(reason)
}

// hookToolCallCapture records the tool call a hook request remembered for
// its tool span, so the decision reached after evaluation lands on the same
// pending invocation.
type hookToolCallCapture struct {
	meta      llmEventMeta
	tool      string
	arguments string
	// invocationID names the pending call this request remembered.
	invocationID string
	ok           bool
	// promptMeta is the prompt this request remembered for its turn.
	promptMeta llmEventMeta
	promptOK   bool
}

type hookToolCallCaptureKey struct{}

func withHookToolCallCapture(ctx context.Context, capture *hookToolCallCapture) context.Context {
	return context.WithValue(ctx, hookToolCallCaptureKey{}, capture)
}

func captureHookToolCall(ctx context.Context, meta llmEventMeta, tool, arguments, invocationID string) {
	if ctx == nil {
		return
	}
	if capture, _ := ctx.Value(hookToolCallCaptureKey{}).(*hookToolCallCapture); capture != nil {
		*capture = hookToolCallCapture{meta: meta, tool: tool, arguments: arguments, invocationID: invocationID, ok: true}
	}
}

// captureHookPrompt records the prompt a hook request remembered for its
// turn, so a block of that prompt can end the turn.
func captureHookPrompt(ctx context.Context, meta llmEventMeta) {
	if ctx == nil {
		return
	}
	if capture, _ := ctx.Value(hookToolCallCaptureKey{}).(*hookToolCallCapture); capture != nil {
		capture.promptMeta, capture.promptOK = meta, true
	}
}

// emitHookGuardrailOutcomeV8 puts a block, ask or alert decision on a span.
// A tool call this request remembered carries it on its tool span: a blocked
// call never runs, so its span ends now with an ERROR status and the reason
// as the result the agent saw; an asked or alerted call keeps it until the
// connector reports the result. Any other decision (a prompt, a tool result)
// gets an apply_guardrail span.
func (a *APIServer) emitHookGuardrailOutcomeV8(
	ctx context.Context,
	req agentHookRequest,
	resp agentHookResponse,
	elapsed time.Duration,
) {
	if a == nil || ctx == nil {
		return
	}
	outcome, ok := hookGuardrailOutcomeFor(resp.Action, resp.Severity, hookSourceReason(resp), resp.RuleIDs)
	if !ok {
		return
	}
	capture, _ := ctx.Value(hookToolCallCaptureKey{}).(*hookToolCallCapture)
	if capture != nil && capture.ok {
		meta := capture.meta
		meta.Guardrail = outcome
		if outcome.Action == "block" {
			meta.LifecycleOutcome = "blocked"
			a.emitHookToolSpanFor(ctx, meta, capture.tool, capture.invocationID, capture.arguments, redaction.ForSinkReason(resp.Reason), nil)
			return
		}
		a.annotateHookToolInvocation(meta, capture.tool, capture.invocationID, outcome)
		return
	}
	verdict := &ToolInspectVerdict{
		Action: resp.Action, RawAction: resp.RawAction, Severity: resp.Severity,
		Reason: hookSourceReason(resp), Mode: resp.Mode, WouldBlock: resp.WouldBlock,
	}
	evaluation := hookEvaluationContext{EvaluationID: resp.EvaluationID, RuleIDs: resp.RuleIDs}
	a.emitGuardrailApplyTraceV8(ctx, req.ConnectorName, req.ToolName,
		hookTargetTypeForEvent(req.HookEventName), verdict, elapsed, evaluation)
	if capture != nil && capture.promptOK && outcome.Action == "block" {
		// A blocked prompt never reaches the model, so no Stop ends its turn
		// and Galileo, which has no span type for apply_guardrail, showed
		// nothing (GAP-2485). The turn ends now with the block on its agent
		// and chat spans and the block message as the reply the user saw.
		meta := capture.promptMeta
		meta.Guardrail = outcome
		meta.LifecycleOutcome = "blocked"
		reply := strings.TrimSpace(hookPromptBlockReply(resp.Reason))
		if reply == "" {
			reply = "DefenseClaw blocked this prompt"
		}
		a.emitHookLLMSpan(ctx, meta, reply)
	}
}

// hookPromptBlockReply is the reply a blocked prompt's turn carries: the
// block message the agent showed its user. That message is already worded
// and scrubbed for the agent (agentDisplayReason, agentVerdictReason), so the
// sink scrub on top turned it into a "<redacted len=N sha=...>" token even
// for an unredacted destination (GAP-2510). A managed (Secure Client)
// deployment keeps the scrub.
func hookPromptBlockReply(reason string) string {
	if managedEnterpriseActive.Load() {
		return redaction.ForSinkReason(reason)
	}
	return reason
}

// annotateHookToolInvocation attaches an ask or alert decision to the tool
// call this request remembered; the tool span emitted with the result
// carries it.
func (a *APIServer) annotateHookToolInvocation(meta llmEventMeta, tool, invocationID string, outcome hookGuardrailOutcome) {
	key := hookToolInvocationKey(meta, tool)
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	queue := a.hookToolInvocations[key]
	for i := range queue {
		if queue[i].id == invocationID {
			queue[i].meta.Guardrail = outcome
			return
		}
	}
	if invocationID == "" && len(queue) > 0 {
		queue[len(queue)-1].meta.Guardrail = outcome
	}
}

// guardrailOutcomeAttributes are the flat defenseclaw.guardrail.action,
// rule_id and severity attributes of an outcome, all absent without one.
// The agent and chat spans of a blocked prompt or turn carry them as a tool
// span does, so Galileo shows the rule of a prompt block on the turn
// (GAP-2332).
func guardrailOutcomeAttributes(
	outcome hookGuardrailOutcome,
) (action, ruleID, severity observability.Optional[string]) {
	if outcome.Action == "" {
		return observability.Absent[string](), observability.Absent[string](), observability.Absent[string]()
	}
	return observability.Present(outcome.Action), hookV8OptionalIdentifier(outcome.RuleID),
		hookV8OptionalText(outcome.Severity, 16)
}

// guardrailOutcomeBlocked reports whether a span already carries a block,
// which a later alert on the same span must not replace.
func guardrailOutcomeBlocked(action observability.Optional[string]) bool {
	value, ok := action.Get()
	return ok && value == "block"
}

// guardrailOutcomeEvent is the one field set every
// defenseclaw.guardrail.<action> span event carries. The generated event
// inputs of each family and action share it, so each converts from it.
type guardrailOutcomeEvent = observability.SpanToolExecuteDefenseClawGuardrailBlockEventInput

func newGuardrailOutcomeEvent(
	outcome hookGuardrailOutcome, at time.Time, connector, userID, userName string,
) guardrailOutcomeEvent {
	return guardrailOutcomeEvent{
		TimeUnixNano:                 uint64(at.UnixNano()),
		DefenseClawGuardrailRuleID:   hookV8OptionalIdentifier(outcome.RuleID),
		DefenseClawGuardrailSeverity: hookV8OptionalText(outcome.Severity, 16),
		DefenseClawConnectorSource:   hookV8OptionalIdentifier(connector),
		UserID:                       hookV8OptionalIdentifier(userID),
		DefenseClawUserName:          hookV8OptionalIdentifier(userName),
		DefenseClawGuardrailReason:   hookV8OptionalText(outcome.Reason, 65536),
	}
}

// applyToolGuardrailOutcome stamps a hook decision on a tool span: the flat
// outcome attributes, the matching span event and, for a block, an ERROR
// status whose description is the redacted reason.
func applyToolGuardrailOutcome(input *observability.SpanToolExecuteInput, observation generatedToolV8Observation) {
	outcome := observation.meta.Guardrail
	if input == nil || outcome.Action == "" {
		return
	}
	at := outcome.At
	if at.Before(observation.startedAt) || at.After(observation.finishedAt) {
		at = observation.finishedAt
	}
	fields := newGuardrailOutcomeEvent(outcome, at, observation.meta.Source, observation.meta.UserID, observation.meta.UserName)
	input.DefenseClawGuardrailAction = observability.Present(outcome.Action)
	input.DefenseClawGuardrailRuleID = fields.DefenseClawGuardrailRuleID
	input.DefenseClawGuardrailSeverity = fields.DefenseClawGuardrailSeverity
	var event observability.TraceEventInput
	var err error
	switch outcome.Action {
	case "block":
		input.Status = observability.NewTraceStatusError(fields.DefenseClawGuardrailReason)
		event, err = observability.NewSpanToolExecuteDefenseClawGuardrailBlockEvent(fields)
	case "ask":
		event, err = observability.NewSpanToolExecuteDefenseClawGuardrailAskEvent(
			observability.SpanToolExecuteDefenseClawGuardrailAskEventInput(fields))
	default:
		event, err = observability.NewSpanToolExecuteDefenseClawGuardrailAlertEvent(
			observability.SpanToolExecuteDefenseClawGuardrailAlertEventInput(fields))
	}
	if err == nil {
		input.Events = append(input.Events, event)
	}
}

// applyGuardrailApplyOutcome stamps the same decision on an apply_guardrail
// span.
func applyGuardrailApplyOutcome(
	input *observability.SpanGuardrailApplyInput,
	outcome hookGuardrailOutcome,
	caller auditCaller,
	connector string,
	endedAt time.Time,
) {
	if input == nil || outcome.Action == "" {
		return
	}
	fields := newGuardrailOutcomeEvent(outcome, endedAt, connector, caller.ID, caller.Name)
	input.DefenseClawGuardrailAction = observability.Present(outcome.Action)
	input.DefenseClawGuardrailRuleID = fields.DefenseClawGuardrailRuleID
	input.DefenseClawGuardrailSeverity = fields.DefenseClawGuardrailSeverity
	var event observability.TraceEventInput
	var err error
	switch outcome.Action {
	case "block":
		input.Status = observability.NewTraceStatusError(fields.DefenseClawGuardrailReason)
		event, err = observability.NewSpanGuardrailApplyDefenseClawGuardrailBlockEvent(
			observability.SpanGuardrailApplyDefenseClawGuardrailBlockEventInput(fields))
	case "ask":
		event, err = observability.NewSpanGuardrailApplyDefenseClawGuardrailAskEvent(
			observability.SpanGuardrailApplyDefenseClawGuardrailAskEventInput(fields))
	default:
		event, err = observability.NewSpanGuardrailApplyDefenseClawGuardrailAlertEvent(
			observability.SpanGuardrailApplyDefenseClawGuardrailAlertEventInput(fields))
	}
	if err == nil {
		input.Events = append(input.Events, event)
	}
}
