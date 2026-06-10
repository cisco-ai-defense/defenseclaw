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

package insightclaw

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// --- Phase 1: Core workflow Emit methods ---

// EmitMessageReceived records a message received event (prompt or tool_result
// arriving at the agent via connector hooks).
func (a *Adapter) EmitMessageReceived(ctx context.Context, channel string) {
	if a == nil {
		return
	}
	a.messagesReceived.Add(ctx, 1, metric.WithAttributes(
		attribute.String("message.channel", channel),
	))
}

// EmitMessageSent records a message sent event (completion or tool_call
// emitted by the agent).
func (a *Adapter) EmitMessageSent(ctx context.Context, channel string) {
	if a == nil {
		return
	}
	a.messagesSent.Add(ctx, 1, metric.WithAttributes(
		attribute.String("message.channel", channel),
	))
}

// EmitToolCall records a tool call observation.
func (a *Adapter) EmitToolCall(ctx context.Context, toolName, sessionKey string) {
	if a == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.tool.name", toolName),
	}
	if sessionKey != "" {
		attrs = append(attrs, attribute.String("session.key", sessionKey))
	}
	a.toolCalls.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// EmitToolError records a tool error.
func (a *Adapter) EmitToolError(ctx context.Context, toolName string) {
	if a == nil {
		return
	}
	a.toolErrors.Add(ctx, 1, metric.WithAttributes(
		attribute.String("gen_ai.tool.name", toolName),
	))
}

// EmitSessionReset records a session reset or new-session command.
func (a *Adapter) EmitSessionReset(ctx context.Context, source string) {
	if a == nil {
		return
	}
	a.sessionResets.Add(ctx, 1, metric.WithAttributes(
		attribute.String("command.source", source),
	))
}

// EmitLLMRequest records an LLM request. Called once per model invocation.
func (a *Adapter) EmitLLMRequest(ctx context.Context, model, provider string) {
	if a == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.request.model", model),
	}
	if provider != "" {
		attrs = append(attrs, attribute.String("gen_ai.provider.name", provider))
	}
	a.llmRequests.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// EmitTokenUsage records prompt, completion, and total token counts.
func (a *Adapter) EmitTokenUsage(ctx context.Context, connector, model string, prompt, completion, total int64) {
	if a == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.request.model", model),
	}
	if connector != "" {
		attrs = append(attrs, attribute.String("connector", connector))
	}

	if prompt > 0 {
		a.llmTokensPrompt.Add(ctx, prompt, metric.WithAttributes(attrs...))
	}
	if completion > 0 {
		a.llmTokensCompl.Add(ctx, completion, metric.WithAttributes(attrs...))
	}
	if total > 0 {
		a.llmTokensTotal.Add(ctx, total, metric.WithAttributes(attrs...))
	}

	// Also count as an LLM request (diagnostics-driven path).
	a.llmRequests.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// EmitAgentTurnDuration records the wall-clock duration of an agent turn.
func (a *Adapter) EmitAgentTurnDuration(ctx context.Context, model, agentID string, durationMs float64) {
	if a == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.request.model", model),
	}
	if agentID != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.id", agentID))
	}
	a.agentTurnDur.Record(ctx, durationMs, metric.WithAttributes(attrs...))
}

// EmitLLMDuration records model request latency.
func (a *Adapter) EmitLLMDuration(ctx context.Context, model string, durationMs float64) {
	if a == nil {
		return
	}
	a.llmDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("gen_ai.request.model", model),
	))
}

// EmitCostUSD records LLM cost in USD.
func (a *Adapter) EmitCostUSD(ctx context.Context, model string, costUSD float64) {
	if a == nil || costUSD <= 0 {
		return
	}
	a.costUSD.Add(ctx, costUSD, metric.WithAttributes(
		attribute.String("gen_ai.request.model", model),
	))
}

// --- Phase 2: Diagnostics-driven gateway Emit methods ---

// EmitWebhookReceived records a webhook reception event.
func (a *Adapter) EmitWebhookReceived(ctx context.Context, channel, webhookType string) {
	if a == nil {
		return
	}
	a.webhookReceived.Add(ctx, 1, metric.WithAttributes(
		attribute.String("channel", channel),
		attribute.String("webhook.type", webhookType),
	))
}

// EmitWebhookError records a webhook processing error.
func (a *Adapter) EmitWebhookError(ctx context.Context, channel, webhookType string) {
	if a == nil {
		return
	}
	a.webhookError.Add(ctx, 1, metric.WithAttributes(
		attribute.String("channel", channel),
		attribute.String("webhook.type", webhookType),
	))
}

// EmitWebhookDuration records webhook processing duration.
func (a *Adapter) EmitWebhookDuration(ctx context.Context, channel string, durationMs float64) {
	if a == nil {
		return
	}
	a.webhookDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("channel", channel),
	))
}

// EmitMessageQueued records a message being enqueued for processing.
func (a *Adapter) EmitMessageQueued(ctx context.Context, channel, source string) {
	if a == nil {
		return
	}
	a.messageQueued.Add(ctx, 1, metric.WithAttributes(
		attribute.String("channel", channel),
		attribute.String("source", source),
	))
}

// EmitMessageProcessed records a message being processed.
func (a *Adapter) EmitMessageProcessed(ctx context.Context, channel, outcome string) {
	if a == nil {
		return
	}
	a.messageProcessed.Add(ctx, 1, metric.WithAttributes(
		attribute.String("channel", channel),
		attribute.String("outcome", outcome),
	))
}

// EmitMessageDuration records message processing duration.
func (a *Adapter) EmitMessageDuration(ctx context.Context, channel string, durationMs float64) {
	if a == nil {
		return
	}
	a.messageDuration.Record(ctx, durationMs, metric.WithAttributes(
		attribute.String("channel", channel),
	))
}

// EmitQueueDepth records a queue depth snapshot.
func (a *Adapter) EmitQueueDepth(ctx context.Context, depth float64) {
	if a == nil {
		return
	}
	a.queueDepth.Record(ctx, depth)
}

// EmitQueueWait records queue wait time.
func (a *Adapter) EmitQueueWait(ctx context.Context, lane string, waitMs float64) {
	if a == nil {
		return
	}
	a.queueWaitMs.Record(ctx, waitMs, metric.WithAttributes(
		attribute.String("lane", lane),
	))
}

// EmitQueueLaneEnqueue records a queue lane enqueue event.
func (a *Adapter) EmitQueueLaneEnqueue(ctx context.Context, lane string) {
	if a == nil {
		return
	}
	a.queueLaneEnqueue.Add(ctx, 1, metric.WithAttributes(
		attribute.String("lane", lane),
	))
}

// EmitQueueLaneDequeue records a queue lane dequeue event.
func (a *Adapter) EmitQueueLaneDequeue(ctx context.Context, lane string) {
	if a == nil {
		return
	}
	a.queueLaneDequeue.Add(ctx, 1, metric.WithAttributes(
		attribute.String("lane", lane),
	))
}

// EmitSessionState records a session state transition.
func (a *Adapter) EmitSessionState(ctx context.Context, state, reason string) {
	if a == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.String("state", state),
	}
	if reason != "" {
		attrs = append(attrs, attribute.String("reason", reason))
	}
	a.sessionState.Add(ctx, 1, metric.WithAttributes(attrs...))
}

// EmitSessionStuck records a stuck session detection.
func (a *Adapter) EmitSessionStuck(ctx context.Context, state string, ageMs float64) {
	if a == nil {
		return
	}
	a.sessionStuck.Add(ctx, 1, metric.WithAttributes(
		attribute.String("state", state),
	))
	if ageMs > 0 {
		a.sessionStuckAge.Record(ctx, ageMs, metric.WithAttributes(
			attribute.String("state", state),
		))
	}
}

// EmitRunAttempt records a run attempt (including retries).
func (a *Adapter) EmitRunAttempt(ctx context.Context, attempt int) {
	if a == nil {
		return
	}
	a.runAttempt.Add(ctx, 1, metric.WithAttributes(
		attribute.Int("attempt", attempt),
	))
}

// EmitToolLoop records a tool loop detection.
func (a *Adapter) EmitToolLoop(ctx context.Context, toolName, detector, action, severity string) {
	if a == nil {
		return
	}
	a.toolLoop.Add(ctx, 1, metric.WithAttributes(
		attribute.String("gen_ai.tool.name", toolName),
		attribute.String("detector", detector),
		attribute.String("action", action),
		attribute.String("severity", severity),
	))
}
