// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strings"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// nativeUsageSuppressed reports whether the route-only listener or the
// guardrail proxy carries the model traffic of connector. While it does, that
// path records every call, so the usage the agent reports in its own OTLP
// stream is a cross-check only: its log.model.response import still runs, but
// nothing is counted from it (no log.model.usage, no cost or token counter,
// no store row, no budget spend). The answer comes from the loaded config, not
// from a per-call guess: a hook connector listed in routing.route_only.connectors
// sends its model calls through the gateway (D6); a hook-only connector takes
// native usage as the source. applyModelUsage refreshes it on start and on
// every reload.
var nativeUsageSuppressed = func(connector string) bool {
	set := nativeCarriedConnectors.Load()
	if set == nil {
		return false
	}
	_, carried := (*set)[strings.ToLower(strings.TrimSpace(connector))]
	return carried
}

var nativeCarriedConnectors atomic.Pointer[map[string]struct{}]

// setNativeUsageSuppression records which connectors the gateway carries the
// model traffic of, from a validated config.
func setNativeUsageSuppression(cfg *config.Config) {
	if cfg == nil {
		nativeCarriedConnectors.Store(nil)
		return
	}
	set := map[string]struct{}{}
	for _, c := range cfg.Routing.RouteOnly.Connectors {
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			set[c] = struct{}{}
		}
	}
	if len(set) == 0 {
		nativeCarriedConnectors.Store(nil)
		return
	}
	nativeCarriedConnectors.Store(&set)
}

// Inbound classes whose leaves carry one model call and derive a usage record.
const (
	nativeUsageClassClaudeAPIRequest = "otlp.claudecode.api_request.v1"
	nativeUsageClassCodexCompleted   = "otlp.codex.response_completed.v1"
)

// Alias targets the registry declares for the usage counts (registry.yaml
// inbound_bindings.alias_sets). input_tokens of Claude Code excludes the
// cache tokens, so it is not the semconv input count.
const (
	nativeUsageOutputTarget        = "gen_ai.usage.output_tokens"
	nativeUsageInputTarget         = "gen_ai.usage.input_tokens"
	nativeUsageCachedInputTarget   = "$derived_cached_input_tokens"
	nativeUsageReasoningTarget     = "$derived_reasoning_tokens"
	nativeUsageUncachedInputTarget = "$derived_uncached_input_tokens"
	nativeUsageCacheReadTarget     = "$derived_cache_read_tokens"
	nativeUsageCacheCreationTarget = "$derived_cache_creation_tokens"
	nativeUsageModelTarget         = "gen_ai.request.model"
	// nativeUsageMaxReportedUSD bounds one reported per-call cost.
	nativeUsageMaxReportedUSD = 1e6
)

// recordNativeOTLPUsageV8 derives the log.model.usage record of one imported
// agent model call and hands it to the process usage engine, which prices,
// labels and counts it like a proxied call. It never fails the import.
func (a *APIServer) recordNativeOTLPUsageV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	authenticatedSource string,
	receipt time.Time,
) (modelusage.Record, bool) {
	if a == nil || leaf.logRecord == nil {
		return modelusage.Record{}, false
	}
	switch match.ClassID() {
	case nativeUsageClassClaudeAPIRequest, nativeUsageClassCodexCompleted:
	default:
		return modelusage.Record{}, false
	}
	engine := processModelUsage.Load()
	if engine == nil || !engine.NativeImportEnabled(authenticatedSource) ||
		nativeUsageSuppressed(authenticatedSource) {
		return modelusage.Record{}, false
	}
	rec, ok := a.nativeOTLPUsageRecordV8(ctx, leaf, match, authenticatedSource, receipt)
	if !ok {
		return modelusage.Record{}, false
	}
	return engine.RecordNative(rec)
}

func (a *APIServer) nativeOTLPUsageRecordV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	source string,
	receipt time.Time,
) (modelusage.Record, bool) {
	target, ok := nativeUsagePrimaryTarget(match)
	if !ok {
		return modelusage.Record{}, false
	}
	// The same correlation the imported record carries: the connector native
	// profile (session, turn, request ids), then the exact hook-session join.
	correlation, err := inboundCorrelationV8(ctx, leaf, match, source)
	if err != nil {
		return modelusage.Record{}, false
	}
	if _, _, err := a.enrichInboundWithHookLifecycleV8(
		ctx, leaf, target, source, &correlation, nil, nil,
	); err != nil {
		return modelusage.Record{}, false
	}
	ended, err := selectedInboundLogTime(leaf.logRecord, receipt)
	if err != nil {
		ended = receipt
	}
	model, _ := inboundGeneratedStringValue(leaf, match, nativeUsageModelTarget, source)
	facts := modelusage.CallFacts{
		Listener: "native_otel", Connector: source, CallRole: modelusage.RoleAgent,
		RequestedModel: model, SelectedModel: model,
		Route:     modelusage.RouteFacts{Decision: modelusage.DecisionNone},
		SessionID: correlation.SessionID, TurnID: correlation.TurnID, AgentID: correlation.AgentID,
		ModelRequestID: correlation.ModelRequestID, ModelResponseID: correlation.ModelResponseID,
	}
	if caller, verified := verifiedAuditCaller(ctx); verified && caller.ID != "" {
		facts.Subject, facts.SubjectKind, facts.IdentityVerified = caller.ID, caller.IDKind, true
	}
	rec := modelusage.Record{Status: 200, Outcome: "completed", EndedAt: ended}
	switch match.ClassID() {
	case nativeUsageClassClaudeAPIRequest:
		facts.APIFamily = modelusage.FamilyMessages
		facts.SelectedProvider = nativeClaudeProvider(model)
		rec.Usage = nativeClaudeUsage(leaf, match, source)
		rec.Cost.ReportedUSD = nativeReportedCallCost(leaf)
		if seconds, state := inboundDurationAliasSecondsV8(leaf, match); state == otlpTypedAttributeUnique &&
			seconds > 0 && seconds < 86400 {
			rec.Total = time.Duration(math.Round(seconds * float64(time.Second)))
		}
		if ms, state := leaf.attributes().int64Value("ttft_ms"); state == otlpTypedAttributeUnique && ms > 0 && ms < 86400000 {
			rec.TTFB = time.Duration(ms) * time.Millisecond
		}
	case nativeUsageClassCodexCompleted:
		facts.APIFamily = modelusage.FamilyResponses
		facts.SelectedProvider = "openai"
		rec.Usage = nativeCodexUsage(leaf, match, source)
	}
	facts.RequestedProvider = facts.SelectedProvider
	rec.Usage.ResponseModel = model
	rec.Facts = facts
	return rec, true
}

func nativeUsagePrimaryTarget(match observability.InboundMatch) (observability.InboundTarget, bool) {
	for _, target := range match.Targets() {
		if target.Role() == observability.InboundTargetImport && target.Signal() == observability.SignalLogs {
			return target, true
		}
	}
	return observability.InboundTarget{}, false
}

// nativeUsageCount reads one token count through its registry alias. Absent
// stays absent; a malformed or conflicting count is reported as invalid and
// is dropped, never read as 0.
func nativeUsageCount(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target, source string,
) (value int64, present, invalid bool) {
	raw, state := inboundAliasTargetValueV8(leaf, match, target, source)
	switch state {
	case otlpTypedAttributeAbsent:
		return 0, false, false
	case otlpTypedAttributeUnique:
	default:
		return 0, false, true
	}
	integer, ok := raw.GetValue().(*commonpb.AnyValue_IntValue)
	if !ok || integer.IntValue < 0 || integer.IntValue > 1<<53 {
		return 0, false, true
	}
	return integer.IntValue, true, false
}

// nativeClaudeUsage maps claude_code.api_request. Claude Code reports
// input_tokens without the cache tokens; the canonical input is the sum of
// input_tokens, cache_read_tokens and cache_creation_tokens.
func nativeClaudeUsage(leaf otlpDecodedLeaf, match observability.InboundMatch, source string) modelusage.Usage {
	u := modelusage.Usage{}
	uncached, hasUncached, badUncached := nativeUsageCount(leaf, match, nativeUsageUncachedInputTarget, source)
	cacheRead, hasRead, badRead := nativeUsageCount(leaf, match, nativeUsageCacheReadTarget, source)
	cacheWrite, hasWrite, badWrite := nativeUsageCount(leaf, match, nativeUsageCacheCreationTarget, source)
	output, hasOutput, badOutput := nativeUsageCount(leaf, match, nativeUsageOutputTarget, source)
	if hasUncached && !badRead && !badWrite {
		u.Input, u.Has = uncached+cacheRead+cacheWrite, u.Has|modelusage.HasInput
		if hasRead {
			u.CacheRead, u.Has = cacheRead, u.Has|modelusage.HasCacheRead
		}
		if hasWrite {
			u.CacheCreation, u.Has = cacheWrite, u.Has|modelusage.HasCacheCreation
		}
	}
	if hasOutput {
		u.Output, u.Has = output, u.Has|modelusage.HasOutput
	}
	if badUncached || badRead || badWrite || badOutput {
		u.Anomaly = "invalid_count"
	}
	// The flat price table cannot price these billing features; the reported
	// cost of the call already includes them.
	if n, state := leaf.attributes().int64Value("cache_creation_1h_tokens"); state == otlpTypedAttributeUnique && n > 0 {
		u.Partial = "cache_ttl_1h"
	}
	if speed, state := leaf.attributes().stringValue("speed"); state == otlpTypedAttributeUnique && speed == "fast" {
		u.Partial = "speed:fast"
	}
	return u
}

// nativeCodexUsage maps codex.sse_event response.completed: the Responses API
// counts (input includes cached, output includes reasoning). Codex reports no
// per-call cost.
func nativeCodexUsage(leaf otlpDecodedLeaf, match observability.InboundMatch, source string) modelusage.Usage {
	u := modelusage.Usage{}
	bad := false
	for _, item := range []struct {
		target string
		bit    modelusage.Has
		dst    *int64
	}{
		{nativeUsageInputTarget, modelusage.HasInput, &u.Input},
		{nativeUsageCachedInputTarget, modelusage.HasCacheRead, &u.CacheRead},
		{nativeUsageOutputTarget, modelusage.HasOutput, &u.Output},
		{nativeUsageReasoningTarget, modelusage.HasReasoning, &u.Reasoning},
	} {
		value, present, invalid := nativeUsageCount(leaf, match, item.target, source)
		bad = bad || invalid
		if present {
			*item.dst, u.Has = value, u.Has|item.bit
		}
	}
	if bad {
		u.Anomaly = "invalid_count"
	}
	return u
}

// nativeReportedCallCost reads cost_usd of one claude_code.api_request: the
// cost of that call alone. Running totals (the claude_code.cost.usage counter,
// total_cost_usd, session_cost_usd) never come here; they stay on the
// defenseclaw.agent.reported_cost gauge.
func nativeReportedCallCost(leaf otlpDecodedLeaf) *float64 {
	value, state := leaf.attributes().lookup("cost_usd")
	if state != otlpTypedAttributeUnique {
		return nil
	}
	var usd float64
	switch number := value.GetValue().(type) {
	case *commonpb.AnyValue_DoubleValue:
		usd = number.DoubleValue
	case *commonpb.AnyValue_IntValue:
		usd = float64(number.IntValue)
	default:
		return nil
	}
	if math.IsNaN(usd) || math.IsInf(usd, 0) || usd < 0 || usd > nativeUsageMaxReportedUSD {
		return nil
	}
	return &usd
}

// nativeClaudeProvider names the provider of a Claude Code model id: Bedrock
// ids carry an anthropic. vendor prefix (after an optional region prefix) or
// are inference-profile ARNs; everything else is the Anthropic API.
func nativeClaudeProvider(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	if strings.HasPrefix(m, "arn:aws") {
		return "bedrock"
	}
	for _, region := range []string{"us-gov.", "global.", "apac.", "us.", "eu.", "jp.", "au.", "ca."} {
		m = strings.TrimPrefix(m, region)
	}
	if strings.HasPrefix(m, "anthropic.") {
		return "bedrock"
	}
	return "anthropic"
}
