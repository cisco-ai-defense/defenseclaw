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

// Package insightclaw provides a metrics adapter that emits InsightClaw-compatible
// openclaw.* metrics alongside DefenseClaw's native defenseclaw.* instruments.
// The adapter is toggled by otel.insight_claw.enabled config and uses the same
// OTel Meter, so all metrics flow through the existing OTLP exporter pipeline.
package insightclaw

import (
	"fmt"

	"go.opentelemetry.io/otel/metric"
)

// Config holds adapter-level settings parsed from the defenseclaw config file.
type Config struct {
	Enabled      bool   `mapstructure:"enabled"      yaml:"enabled"`
	Prefix       string `mapstructure:"prefix"       yaml:"prefix"`
	Experimental bool   `mapstructure:"experimental" yaml:"experimental"`
}

// Adapter holds InsightClaw-compatible OTel instruments. When nil, all Emit*
// methods are no-ops so callers can skip nil checks.
type Adapter struct {
	cfg Config

	// --- Phase 1: Core workflow metrics ---
	messagesReceived metric.Int64Counter
	messagesSent     metric.Int64Counter
	toolCalls        metric.Int64Counter
	toolErrors       metric.Int64Counter
	sessionResets    metric.Int64Counter
	llmRequests      metric.Int64Counter
	llmTokensPrompt  metric.Int64Counter
	llmTokensCompl   metric.Int64Counter
	llmTokensTotal   metric.Int64Counter
	agentTurnDur     metric.Float64Histogram
	llmDuration      metric.Float64Histogram
	costUSD          metric.Float64Counter

	// --- Phase 2: Diagnostics-driven gateway metrics ---
	webhookReceived  metric.Int64Counter
	webhookError     metric.Int64Counter
	webhookDuration  metric.Float64Histogram
	messageQueued    metric.Int64Counter
	messageProcessed metric.Int64Counter
	messageDuration  metric.Float64Histogram
	queueDepth       metric.Float64Histogram
	queueWaitMs      metric.Float64Histogram
	queueLaneEnqueue metric.Int64Counter
	queueLaneDequeue metric.Int64Counter
	sessionState     metric.Int64Counter
	sessionStuck     metric.Int64Counter
	sessionStuckAge  metric.Float64Histogram
	runAttempt       metric.Int64Counter
	toolLoop         metric.Int64Counter
}

// NewAdapter registers openclaw.* instruments on the given meter. Returns nil
// if cfg.Enabled is false (no-op path).
func NewAdapter(m metric.Meter, cfg Config) (*Adapter, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	prefix := cfg.Prefix
	if prefix == "" {
		prefix = "openclaw"
	}

	a := &Adapter{cfg: cfg}
	var err error

	// Helper to build metric name with prefix.
	name := func(suffix string) string {
		return fmt.Sprintf("%s.%s", prefix, suffix)
	}

	// --- Phase 1: Core workflow ---

	a.messagesReceived, err = m.Int64Counter(name("messages.received"),
		metric.WithUnit("{message}"),
		metric.WithDescription("Messages received by the agent (prompt/tool_result hooks)."))
	if err != nil {
		return nil, err
	}

	a.messagesSent, err = m.Int64Counter(name("messages.sent"),
		metric.WithUnit("{message}"),
		metric.WithDescription("Messages sent by the agent (completions/tool_call hooks)."))
	if err != nil {
		return nil, err
	}

	a.toolCalls, err = m.Int64Counter(name("tool.calls"),
		metric.WithUnit("{call}"),
		metric.WithDescription("Tool calls observed via connector hooks."))
	if err != nil {
		return nil, err
	}

	a.toolErrors, err = m.Int64Counter(name("tool.errors"),
		metric.WithUnit("{error}"),
		metric.WithDescription("Tool calls that resulted in an error."))
	if err != nil {
		return nil, err
	}

	a.sessionResets, err = m.Int64Counter(name("session.resets"),
		metric.WithUnit("{reset}"),
		metric.WithDescription("Session resets (new/reset commands)."))
	if err != nil {
		return nil, err
	}

	a.llmRequests, err = m.Int64Counter(name("llm.requests"),
		metric.WithUnit("{request}"),
		metric.WithDescription("LLM requests observed."))
	if err != nil {
		return nil, err
	}

	a.llmTokensPrompt, err = m.Int64Counter(name("llm.tokens.prompt"),
		metric.WithUnit("{token}"),
		metric.WithDescription("Prompt (input) tokens consumed."))
	if err != nil {
		return nil, err
	}

	a.llmTokensCompl, err = m.Int64Counter(name("llm.tokens.completion"),
		metric.WithUnit("{token}"),
		metric.WithDescription("Completion (output) tokens consumed."))
	if err != nil {
		return nil, err
	}

	a.llmTokensTotal, err = m.Int64Counter(name("llm.tokens.total"),
		metric.WithUnit("{token}"),
		metric.WithDescription("Total tokens consumed."))
	if err != nil {
		return nil, err
	}

	a.agentTurnDur, err = m.Float64Histogram(name("agent.turn_duration"),
		metric.WithUnit("ms"),
		metric.WithDescription("Agent turn duration."))
	if err != nil {
		return nil, err
	}

	a.llmDuration, err = m.Float64Histogram(name("llm.duration"),
		metric.WithUnit("ms"),
		metric.WithDescription("LLM request duration."))
	if err != nil {
		return nil, err
	}

	a.costUSD, err = m.Float64Counter(name("cost.usd"),
		metric.WithUnit("USD"),
		metric.WithDescription("Accumulated LLM cost in USD."))
	if err != nil {
		return nil, err
	}

	// --- Phase 2: Diagnostics-driven gateway metrics ---

	a.webhookReceived, err = m.Int64Counter(name("webhook.received"),
		metric.WithUnit("{webhook}"),
		metric.WithDescription("Webhooks received."))
	if err != nil {
		return nil, err
	}

	a.webhookError, err = m.Int64Counter(name("webhook.error"),
		metric.WithUnit("{error}"),
		metric.WithDescription("Webhook processing errors."))
	if err != nil {
		return nil, err
	}

	a.webhookDuration, err = m.Float64Histogram(name("webhook.duration_ms"),
		metric.WithUnit("ms"),
		metric.WithDescription("Webhook ingress processing duration."))
	if err != nil {
		return nil, err
	}

	a.messageQueued, err = m.Int64Counter(name("message.queued"),
		metric.WithUnit("{message}"),
		metric.WithDescription("Messages enqueued for processing."))
	if err != nil {
		return nil, err
	}

	a.messageProcessed, err = m.Int64Counter(name("message.processed"),
		metric.WithUnit("{message}"),
		metric.WithDescription("Messages processed."))
	if err != nil {
		return nil, err
	}

	a.messageDuration, err = m.Float64Histogram(name("message.duration_ms"),
		metric.WithUnit("ms"),
		metric.WithDescription("Message processing duration."))
	if err != nil {
		return nil, err
	}

	a.queueDepth, err = m.Float64Histogram(name("queue.depth"),
		metric.WithUnit("{item}"),
		metric.WithDescription("Queue depth snapshot (backlog pressure)."))
	if err != nil {
		return nil, err
	}

	a.queueWaitMs, err = m.Float64Histogram(name("queue.wait_ms"),
		metric.WithUnit("ms"),
		metric.WithDescription("Time spent waiting in the queue."))
	if err != nil {
		return nil, err
	}

	a.queueLaneEnqueue, err = m.Int64Counter(name("queue.lane.enqueue"),
		metric.WithUnit("{event}"),
		metric.WithDescription("Queue lane enqueue events."))
	if err != nil {
		return nil, err
	}

	a.queueLaneDequeue, err = m.Int64Counter(name("queue.lane.dequeue"),
		metric.WithUnit("{event}"),
		metric.WithDescription("Queue lane dequeue events."))
	if err != nil {
		return nil, err
	}

	a.sessionState, err = m.Int64Counter(name("session.state"),
		metric.WithUnit("{transition}"),
		metric.WithDescription("Session state transitions."))
	if err != nil {
		return nil, err
	}

	a.sessionStuck, err = m.Int64Counter(name("session.stuck"),
		metric.WithUnit("{event}"),
		metric.WithDescription("Sessions detected as stuck."))
	if err != nil {
		return nil, err
	}

	a.sessionStuckAge, err = m.Float64Histogram(name("session.stuck_age_ms"),
		metric.WithUnit("ms"),
		metric.WithDescription("How long sessions have been stuck."))
	if err != nil {
		return nil, err
	}

	a.runAttempt, err = m.Int64Counter(name("run.attempt"),
		metric.WithUnit("{attempt}"),
		metric.WithDescription("Run attempts (including retries)."))
	if err != nil {
		return nil, err
	}

	a.toolLoop, err = m.Int64Counter(name("tool.loop"),
		metric.WithUnit("{loop}"),
		metric.WithDescription("Tool loop detections."))
	if err != nil {
		return nil, err
	}

	return a, nil
}

// Enabled reports whether the adapter is active.
func (a *Adapter) Enabled() bool {
	return a != nil
}
