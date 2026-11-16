// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// Hook-lane judge fallbacks (#1395): the rules decided a hook check the LLM
// judge was asked to review, because the judge gave no verdict in time. The
// verdict itself does not change; the fallback is reported on the hook's
// audit row and guardrail.evaluation record (judge_fallback), in the
// defenseclaw.guardrail.judge.fallbacks counter and in the gateway health
// details that status, doctor and the TUI show.
const (
	// judgeFallbackTimeout: the judge call did not answer by its deadline,
	// including a call that waited for a slot (guardrail.judge.max_parallel)
	// past it.
	judgeFallbackTimeout = "timeout"
	// judgeFallbackError: the judge call failed (provider error, empty or
	// unparseable answer).
	judgeFallbackError = "error"
	// judgeFallbackLate: the bounded hook answer could not wait longer; the
	// judge verdict is recorded when it arrives.
	judgeFallbackLate = "late"
	// judgeFallbackBusy: the hook-lane judge was at capacity.
	judgeFallbackBusy = "busy"
	// judgeFallbackBudget: the hook's earlier judge calls spent its budget.
	judgeFallbackBudget = "budget"
)

const judgeFallbackMetricV8Producer = "gateway.judge.fallback"

type hookJudgeFallbackKey struct{}

// hookJudgeFallbackNote holds the first judge fallback of one hook call.
type hookJudgeFallbackNote struct {
	mu     sync.Mutex
	reason string
}

// withHookJudgeFallbackNote gives the hook call on ctx a fallback note that
// its finalization reads (hookJudgeFallbackReason).
func withHookJudgeFallbackNote(ctx context.Context) context.Context {
	if _, ok := ctx.Value(hookJudgeFallbackKey{}).(*hookJudgeFallbackNote); ok {
		return ctx
	}
	return context.WithValue(ctx, hookJudgeFallbackKey{}, &hookJudgeFallbackNote{})
}

// hookJudgeFallbackReason is the judge fallback of the hook call on ctx, or
// "" when the judge answered, did not take part or answers after the hook.
func hookJudgeFallbackReason(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	note, ok := ctx.Value(hookJudgeFallbackKey{}).(*hookJudgeFallbackNote)
	if !ok {
		return ""
	}
	note.mu.Lock()
	defer note.mu.Unlock()
	return note.reason
}

// recordHookJudgeFallback notes reason on the hook call of ctx and counts it
// for connector.
func (a *APIServer) recordHookJudgeFallback(ctx context.Context, connector, reason string) {
	if note, ok := ctx.Value(hookJudgeFallbackKey{}).(*hookJudgeFallbackNote); ok {
		note.mu.Lock()
		if note.reason == "" {
			note.reason = reason
		}
		note.mu.Unlock()
	}
	connector = hookDecisionMetricConnector(connector)
	judgeHealth.recordFallback(connector, reason, time.Now())
	if a == nil {
		return
	}
	if runtime, ok := a.observabilityV8RuntimeEmitter().(hookLifecycleMetricV8Runtime); ok && runtime != nil {
		recordJudgeFallbackMetricV8(ctx, runtime, connector, reason)
	}
}

func recordJudgeFallbackMetricV8(ctx context.Context, runtime hookLifecycleMetricV8Runtime, connector, reason string) {
	meta := hookDecisionMetricMeta(ctx, connector)
	meta.Source = connector
	item := newHookV8MetricBatchItemForProducer(
		ctx,
		time.Now().UTC(),
		meta,
		judgeFallbackMetricV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawGuardrailJudgeFallbacks),
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
			return builder.BuildMetricDefenseClawGuardrailJudgeFallbacks(
				observability.MetricDefenseClawGuardrailJudgeFallbacksInput{
					Envelope:                   envelope,
					Value:                      1,
					DefenseClawConnectorSource: observability.Present(connector),
					DefenseClawMetricReason:    reason,
				},
			)
		},
	)
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, []observabilityruntime.GeneratedMetricBatchItem{item})
}

// hookJudgeCallFallback is the fallback of one finished judge call: "" when
// the judge gave a verdict, else timeout when its context ran out and error
// otherwise.
func hookJudgeCallFallback(v *ScanVerdict, callCtx context.Context) string {
	if v != nil && !v.JudgeFailed {
		return ""
	}
	if callCtx.Err() != nil {
		return judgeFallbackTimeout
	}
	return judgeFallbackError
}
