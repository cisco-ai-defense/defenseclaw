// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"regexp"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const modelUsageV8Producer = "gateway.modelusage"

// The registry constrains these two optional fields; a value that does not
// fit is dropped instead of losing the whole usage record.
var (
	usageProfileNamePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	usageProfileDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// modelUsageV8Sink turns finished model-call records into the generated
// log.model.usage record and the defenseclaw.model.cost and
// defenseclaw.model.tokens counters. It runs on the modelusage engine worker,
// never on the response path. Group names never reach these records: the
// Record carries them for the local store and the admin API only.
type modelUsageV8Sink struct {
	emitter func() sidecarRuntimeEmitter
	metrics func() hookLifecycleMetricV8Runtime
}

// NewModelUsageV8Sink resolves the runtime lazily, so it follows a reload.
func newModelUsageV8Sink(
	emitter func() sidecarRuntimeEmitter,
	metrics func() hookLifecycleMetricV8Runtime,
) *modelUsageV8Sink {
	return &modelUsageV8Sink{emitter: emitter, metrics: metrics}
}

// ReportDrops implements modelusage.DropReporter: the records the engine or
// the store lost since the last report, as defenseclaw.tokenomics.dropped.
func (s *modelUsageV8Sink) ReportDrops(n int64) {
	if s == nil || s.metrics == nil || n <= 0 {
		return
	}
	runtime := s.metrics()
	if runtime == nil {
		return
	}
	at := time.Now().UTC()
	item := newHookV8MetricBatchItemForProducer(context.Background(), at, llmEventMeta{Source: "gateway"}, modelUsageV8Producer,
		observability.EventName(observability.TelemetryInstrumentDefenseClawTokenomicsDropped),
		func(b *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
			return b.BuildMetricDefenseClawTokenomicsDropped(observability.MetricDefenseClawTokenomicsDroppedInput{Envelope: e, Value: n})
		})
	_, _ = runtime.RecordGeneratedMetricBatch(context.Background(), []observabilityruntime.GeneratedMetricBatchItem{item})
}

// Emit implements modelusage.Sink.
func (s *modelUsageV8Sink) Emit(ctx context.Context, rec modelusage.Record) {
	if s == nil {
		return
	}
	if s.emitter != nil {
		if emitter := s.emitter(); emitter != nil {
			_ = emitModelUsageLogV8(ctx, emitter, rec)
		}
	}
	if s.metrics != nil {
		if runtime := s.metrics(); runtime != nil {
			_ = emitModelUsageMetricsV8(ctx, runtime, rec)
		}
	}
}

func usageOutcome(o string) observability.Outcome {
	switch o {
	case "failed":
		return observability.OutcomeFailed
	case "cancelled":
		return observability.OutcomeCancelled
	}
	return observability.OutcomeCompleted
}

func optInt64(has modelusage.Has, bit modelusage.Has, v int64) observability.Optional[int64] {
	if has&bit != 0 {
		return observability.Present(v)
	}
	return observability.Absent[int64]()
}

func optFloat(p *float64) observability.Optional[float64] {
	if p != nil && !math.IsNaN(*p) && !math.IsInf(*p, 0) {
		return observability.Present(*p)
	}
	return observability.Absent[float64]()
}

func durMs(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func emitModelUsageLogV8(ctx context.Context, emitter sidecarRuntimeEmitter, rec modelusage.Record) error {
	f := rec.Facts
	connector := usageConnectorToken(f.Connector)
	if emitter == nil {
		return nil
	}
	producerKey := observability.ProducerKey(gatewaylog.EventModelUsage)
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		observability.ClassificationContext{
			Bucket: observability.BucketModelIO, EventName: observability.EventName(observability.TelemetryEventModelUsage), RawSeverity: "INFO",
		},
		observability.SourceConnector,
		connector,
		producerKey,
	)
	if err != nil {
		return err
	}
	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return rec.EndedAt.UTC() }),
			observability.TimeOrderedOccurrenceIDs,
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		meta := llmEventMeta{
			Source: connector, RequestID: f.RequestID,
			SessionID: f.SessionID, TurnID: f.TurnID, AgentID: f.AgentID,
			PromptID: f.ModelRequestID, ResponseID: f.ModelResponseID,
		}
		envelope := hookModelLogEnvelope(ctx, snapshot, meta, connector, observability.TelemetryEventModelUsage)
		// The admitted metadata carries the model_usage action; the record must
		// carry the same one or verifyBuiltRecord refuses it. hookModelLogEnvelope
		// names every non-request model log llm_response.
		envelope.Action = string(producerKey)
		envelope.Provenance.Producer = modelUsageV8Producer
		record, buildErr := builder.BuildLogModelUsage(buildModelUsageLogInput(envelope, rec))
		if buildErr != nil {
			// An optional provenance value broke a registry constraint: keep tokens
			// and cost, drop the provenance.
			return builder.BuildLogModelUsage(buildModelUsageLogInput(envelope, stripUsageProvenance(rec)))
		}
		return record, nil
	})
	return err
}

func stripUsageProvenance(rec modelusage.Record) modelusage.Record {
	rec.Facts.Route = modelusage.RouteFacts{Decision: rec.Facts.Route.Decision}
	rec.Facts.ProfileName, rec.Facts.ProfileDigest = "", ""
	rec.Facts.RequestedProvider = ""
	rec.Facts.Subject, rec.Facts.SubjectKind = "", ""
	rec.Cost.PriceEntry, rec.Cost.TableDigest = "", ""
	return rec
}

func buildModelUsageLogInput(envelope observability.FamilyEnvelopeInput, rec modelusage.Record) observability.LogModelUsageInput {
	f, u, c := rec.Facts, rec.Usage, rec.Cost
	in := observability.LogModelUsageInput{
		Envelope: envelope, Severity: observability.Present(observability.SeverityInfo),
		LogLevel: observability.Present(observability.LogLevelInfo), Outcome: usageOutcome(rec.Outcome),
	}
	in.DefenseClawRequestID = hookModelV8OptionalID(f.RequestID)
	if f.IdentityVerified {
		in.UserID = hookModelV8OptionalID(f.Subject)
		in.DefenseClawUserIDKind = v8UserIDKind(f.SubjectKind)
	}
	in.GenAIOperationName = observability.Present("chat")
	in.GenAIProviderName = hookModelV8OptionalText(f.SelectedProvider)
	requested := f.RequestedModel
	if requested == "" {
		requested = f.SelectedModel
	}
	in.GenAIRequestModel = hookModelV8OptionalID(requested)
	in.GenAIResponseModel = hookModelV8OptionalID(u.ResponseModel)
	in.DefenseClawModelSelected = hookModelV8OptionalID(f.SelectedModel)
	if f.RequestedProvider != "" && f.RequestedProvider != f.SelectedProvider {
		in.DefenseClawProviderRequested = hookModelV8OptionalText(f.RequestedProvider)
	}
	in.GenAIUsageInputTokens = optInt64(u.Has, modelusage.HasInput, u.Input)
	in.GenAIUsageOutputTokens = optInt64(u.Has, modelusage.HasOutput, u.Output)
	in.DefenseClawUsageCacheReadTokens = optInt64(u.Has, modelusage.HasCacheRead, u.CacheRead)
	in.DefenseClawUsageCacheCreationTokens = optInt64(u.Has, modelusage.HasCacheCreation, u.CacheCreation)
	in.DefenseClawUsageReasoningTokens = optInt64(u.Has, modelusage.HasReasoning, u.Reasoning)
	in.DefenseClawTelemetryTokensReported = observability.Present(u.Has != 0)
	in.DefenseClawUsageSource = hookModelV8OptionalText(u.Source)
	in.DefenseClawUsagePartial = hookModelV8OptionalText(u.Partial)
	in.DefenseClawAPIFamily = hookModelV8OptionalText(string(f.APIFamily))
	in.DefenseClawCallRole = hookModelV8OptionalText(string(f.CallRole))
	in.DefenseClawModelStreaming = observability.Present(f.Streaming)
	in.DefenseClawModelCancelled = observability.Present(rec.Outcome == "cancelled")
	in.DefenseClawRouteDecision = hookModelV8OptionalText(f.Route.Decision)
	in.DefenseClawRouteSource = hookModelV8OptionalText(f.Route.Source)
	in.DefenseClawRouteCategory = hookModelV8OptionalText(f.Route.Category)
	in.DefenseClawRouteRuleID = hookModelV8OptionalID(f.Route.RuleID)
	if usageProfileNamePattern.MatchString(f.ProfileName) {
		in.DefenseClawGuardrailProfileName = observability.Present(f.ProfileName)
	}
	if usageProfileDigestPattern.MatchString(f.ProfileDigest) {
		in.DefenseClawGuardrailProfileDigest = observability.Present(f.ProfileDigest)
	}
	in.DefenseClawCostUsd = optFloat(c.USD)
	in.DefenseClawCostBasis = observability.Present(c.Basis)
	in.DefenseClawCostComputedUsd = optFloat(c.ComputedUSD)
	in.DefenseClawCostReportedUsd = optFloat(c.ReportedUSD)
	in.DefenseClawCostPriceEntry = hookModelV8OptionalText(c.PriceEntry)
	in.DefenseClawPricingVersion = hookModelV8OptionalText(c.TableVersion)
	in.DefenseClawPricingDigest = hookModelV8OptionalText(c.TableDigest)
	if rec.TTFB > 0 {
		in.DefenseClawModelFirstTokenMs = observability.Present(durMs(rec.TTFB))
	}
	if rec.Total > 0 {
		in.DefenseClawModelTotalMs = observability.Present(durMs(rec.Total))
	}
	return in
}

// labelValue returns the metric label value for key, or absent when the
// operator removed that label from observability.tokenomics.metrics.labels.
func labelValue(rec modelusage.Record, key string) observability.Optional[string] {
	for _, l := range rec.Labels {
		if l.Key == key {
			return observability.Present(l.Value)
		}
	}
	return observability.Absent[string]()
}

func emitModelUsageMetricsV8(ctx context.Context, runtime hookLifecycleMetricV8Runtime, rec modelusage.Record) error {
	f, u, c := rec.Facts, rec.Usage, rec.Cost
	connector := usageConnectorToken(f.Connector)
	meta := llmEventMeta{Source: connector, RequestID: f.RequestID}
	at := rec.EndedAt.UTC()
	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 6)
	add := func(family string, build hookV8MetricRecordBuilder) {
		items = append(items, newHookV8MetricBatchItemForProducer(ctx, at, meta, modelUsageV8Producer, observability.EventName(family), build))
	}
	if c.USD != nil && *c.USD > 0 && !math.IsNaN(*c.USD) && !math.IsInf(*c.USD, 0) {
		usd := *c.USD
		add(observability.TelemetryInstrumentDefenseClawModelCost, func(b *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
			return b.BuildMetricDefenseClawModelCost(observability.MetricDefenseClawModelCostInput{
				Envelope: e, Value: usd,
				DefenseClawConnectorSource:      labelValue(rec, "connector"),
				GenAIProviderName:               labelValue(rec, "provider"),
				DefenseClawCostPriceEntry:       labelValue(rec, "model"),
				DefenseClawRouteDecision:        labelValue(rec, "route_decision"),
				DefenseClawCallRole:             labelValue(rec, "call_role"),
				DefenseClawGuardrailProfileName: labelValue(rec, "profile"),
			})
		})
	}
	// Disjoint kinds: uncached input, cache read, cache creation, output
	// without reasoning, reasoning. Absent counts add nothing.
	kinds := []struct {
		kind  string
		value int64
		ok    bool
	}{}
	if u.Has&modelusage.HasInput != 0 {
		uncached := u.Input
		if u.Has&modelusage.HasCacheRead != 0 {
			uncached -= u.CacheRead
		}
		if u.Has&modelusage.HasCacheCreation != 0 {
			uncached -= u.CacheCreation
		}
		kinds = append(kinds, struct {
			kind  string
			value int64
			ok    bool
		}{"input", uncached, uncached >= 0})
	}
	if u.Has&modelusage.HasCacheRead != 0 {
		kinds = append(kinds, struct {
			kind  string
			value int64
			ok    bool
		}{"cache_read", u.CacheRead, true})
	}
	if u.Has&modelusage.HasCacheCreation != 0 {
		kinds = append(kinds, struct {
			kind  string
			value int64
			ok    bool
		}{"cache_creation", u.CacheCreation, true})
	}
	if u.Has&modelusage.HasOutput != 0 {
		out := u.Output
		if u.Has&modelusage.HasReasoning != 0 {
			out -= u.Reasoning
		}
		kinds = append(kinds, struct {
			kind  string
			value int64
			ok    bool
		}{"output", out, out >= 0})
	}
	if u.Has&modelusage.HasReasoning != 0 {
		kinds = append(kinds, struct {
			kind  string
			value int64
			ok    bool
		}{"reasoning", u.Reasoning, true})
	}
	for _, k := range kinds {
		if !k.ok || k.value <= 0 {
			continue
		}
		k := k
		add(observability.TelemetryInstrumentDefenseClawModelTokens, func(b *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
			return b.BuildMetricDefenseClawModelTokens(observability.MetricDefenseClawModelTokensInput{
				Envelope: e, Value: k.value,
				DefenseClawConnectorSource:      labelValue(rec, "connector"),
				GenAIProviderName:               labelValue(rec, "provider"),
				DefenseClawCostPriceEntry:       labelValue(rec, "model"),
				DefenseClawRouteDecision:        labelValue(rec, "route_decision"),
				DefenseClawCallRole:             labelValue(rec, "call_role"),
				DefenseClawGuardrailProfileName: labelValue(rec, "profile"),
				DefenseClawUsageTokenKind:       observability.Present(k.kind),
			})
		})
	}
	if len(items) == 0 {
		return nil
	}
	_, err := runtime.RecordGeneratedMetricBatch(ctx, items)
	return err
}

// applyModelUsageToSpanV8 puts the token and cost attributes of a finished
// call on the model span input before the span ends. S1 calls it with the
// record returned by Call.End.
func applyModelUsageToSpanV8(in *observability.SpanModelChatInput, rec modelusage.Record) {
	if in == nil || rec.Facts.RequestID == "" {
		return
	}
	f, u, c := rec.Facts, rec.Usage, rec.Cost
	in.GenAIUsageInputTokens = optInt64(u.Has, modelusage.HasInput, u.Input)
	in.GenAIUsageOutputTokens = optInt64(u.Has, modelusage.HasOutput, u.Output)
	in.DefenseClawUsageCacheReadTokens = optInt64(u.Has, modelusage.HasCacheRead, u.CacheRead)
	in.DefenseClawUsageCacheCreationTokens = optInt64(u.Has, modelusage.HasCacheCreation, u.CacheCreation)
	in.DefenseClawUsageReasoningTokens = optInt64(u.Has, modelusage.HasReasoning, u.Reasoning)
	in.DefenseClawUsageSource = hookModelV8OptionalText(u.Source)
	in.DefenseClawUsagePartial = hookModelV8OptionalText(u.Partial)
	in.GenAIResponseModel = hookModelV8OptionalID(u.ResponseModel)
	in.DefenseClawAPIFamily = hookModelV8OptionalText(string(f.APIFamily))
	in.DefenseClawCallRole = hookModelV8OptionalText(string(f.CallRole))
	in.DefenseClawModelSelected = hookModelV8OptionalID(f.SelectedModel)
	in.DefenseClawRouteDecision = hookModelV8OptionalText(f.Route.Decision)
	in.DefenseClawRouteSource = hookModelV8OptionalText(f.Route.Source)
	in.DefenseClawRouteCategory = hookModelV8OptionalText(f.Route.Category)
	in.DefenseClawRouteRuleID = hookModelV8OptionalID(f.Route.RuleID)
	in.DefenseClawCostUsd = optFloat(c.USD)
	in.DefenseClawCostBasis = observability.Present(c.Basis)
	in.DefenseClawCostComputedUsd = optFloat(c.ComputedUSD)
	in.DefenseClawCostReportedUsd = optFloat(c.ReportedUSD)
	in.DefenseClawCostPriceEntry = hookModelV8OptionalText(c.PriceEntry)
	in.DefenseClawPricingVersion = hookModelV8OptionalText(c.TableVersion)
	in.DefenseClawPricingDigest = hookModelV8OptionalText(c.TableDigest)
	if rec.Total > 0 {
		in.DefenseClawModelTotalMs = observability.Present(durMs(rec.Total))
	}
}

// usageConnectorToken is the source token of a record. Calls the gateway
// makes itself (judge, decision model, AI Defense) carry no agent connector
// and are attributed to the gateway.
func usageConnectorToken(c string) string {
	if tok := hookModelV8StableToken(c); tok != "" {
		return tok
	}
	return "gateway"
}
