// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

const routingMetricsV8Producer = "gateway.routing"

// routeLabelPattern bounds the free-form routing labels (a category, a budget
// id): a value that does not fit becomes "other" instead of a new series.
var routeLabelPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// maxRouteCategoryLabels bounds the distinct route categories one gateway
// process puts on a metric. A category can come from a remote classifier, so
// its values are not trusted to stay few: the first ones seen are kept, any
// later one is reported as other.
const maxRouteCategoryLabels = 32

type boundedLabelSet struct {
	mu   sync.Mutex
	seen map[string]struct{}
	max  int
}

var routeCategoryLabels = &boundedLabelSet{seen: map[string]struct{}{}, max: maxRouteCategoryLabels}

func (s *boundedLabelSet) bound(v string) string {
	v = routeBoundedLabel(v)
	if v == "" || v == "other" {
		return v
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.seen[v]; ok {
		return v
	}
	if len(s.seen) >= s.max {
		return "other"
	}
	s.seen[v] = struct{}{}
	return v
}

func routeBoundedLabel(v string) string {
	v = strings.TrimSpace(v)
	switch {
	case v == "":
		return ""
	case routeLabelPattern.MatchString(v):
		return v
	}
	return "other"
}

// routeFilteredByLabel is the closed set of reasons the engine narrows a
// choice (engine.eligible and the sensitive narrowing).
func routeFilteredByLabel(v string) string {
	switch v {
	case "":
		return ""
	case "sensitive", "unknown_alias", "policy", "api", "capability", "credential":
		return v
	}
	return "other"
}

// routeListenerLabel is the closed set of listeners that decide routes.
func routeListenerLabel(v string) string {
	switch v {
	case "guardrail", "route_only":
		return v
	}
	return ""
}

// routeFallbackReasonLabel is the closed failure code of a call that fell back
// to the original request (the engine's failure codes). Only a fallback record
// carries one; "none" is not a reason.
func routeFallbackReasonLabel(reason, decision string) string {
	if decision != "fallback" {
		return ""
	}
	switch reason {
	case "":
		return ""
	case SemanticRouteFailureTimeout, SemanticRouteFailureUpstreamStatus, SemanticRouteFailureDecode,
		SemanticRouteFailureUnknownAlias, SemanticRouteFailureCredential, SemanticRouteFailureConfig,
		SemanticRouteFailureFiltered, SemanticRouteFailureBreakerOpen, SemanticRouteFailureLowConfidence,
		SemanticRouteFailureNoCandidate:
		return reason
	case SemanticRouteFailureNone:
		return ""
	}
	return "other"
}

// routeSourceLabel is the closed set of decision sources (engine.Source*).
func routeSourceLabel(v string) string {
	switch v {
	case "":
		return ""
	case engine.SourceRules, engine.SourceSystemOne, engine.SourceVLLMSR, engine.SourceUserOverride,
		engine.SourceSticky, engine.SourceForce, engine.SourceDefault:
		return v
	}
	return "other"
}

// routeDenyClass reduces a routing refusal to its closed class and, for a
// budget refusal, the budget id (the suffix after the colon of the code). The
// refusal message, which names a limit and a reset time, never leaves.
func routeDenyClass(d *engine.DenyReason) (class, budgetID string) {
	if d == nil {
		return "", ""
	}
	code, id, _ := strings.Cut(d.Code, ":")
	if code == "" {
		return "routing_admin_denied", ""
	}
	switch code {
	case "budget_exceeded", "budget_unavailable", "budget_cost_unknown", "budget_downgrade_unavailable":
		return code, routeBoundedLabel(id)
	case "routing_admin_denied", "routing_sensitive_local_unavailable", "rule_deny", "identity_unconfirmed":
		// rule_deny:<rule id> and identity_unconfirmed:<fact> keep the class only.
		return code, ""
	}
	return "other", ""
}

// routedMetricOutcome is the outcome a decision metric reports: the decision
// said applied, but when the call was not in the end sent to the routed model
// (a credential that cannot cross providers, a stored response id, a missing
// origin, a failed custody check) it is a fallback, like its usage record.
// Any other outcome is reported as decided.
func routedMetricOutcome(o SemanticRouteOutcome, routed bool) SemanticRouteOutcome {
	if o.Result != SemanticRouteApplied || routed {
		return o
	}
	o.Result, o.Decision = SemanticRouteFallback, nil
	if o.FailureCode == "" || o.FailureCode == SemanticRouteFailureNone {
		o.FailureCode = SemanticRouteFailureFiltered
	}
	return o
}

// recordSemanticRoutingDecisionMetricsV8 is the one place a routing decision
// becomes defenseclaw.semantic_routing.decision and .latency, whichever
// listener decided it. It carries no prompt, model alias, endpoint, user or
// group, and no refusal text.
func recordSemanticRoutingDecisionMetricsV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	connector, listener string,
	outcome SemanticRouteOutcome,
) {
	if runtime == nil || ctx == nil {
		return
	}
	outcome = normalizeSemanticRouteOutcome(outcome)
	decisionLabel := "default"
	if outcome.OverrideApplied {
		decisionLabel = "override"
	}
	var source, category, filteredBy string
	if d := outcome.Route; d != nil {
		source, category, filteredBy = routeSourceLabel(d.Source), routeCategoryLabels.bound(d.Category), routeFilteredByLabel(d.FilteredBy)
	}
	var denyReason, budgetID string
	if outcome.Result == SemanticRouteDenied {
		denyReason, budgetID = routeDenyClass(outcome.Deny)
	}
	connector = hookDecisionMetricConnector(connector)
	meta := hookDecisionMetricMeta(ctx, connector)
	observedAt := time.Now().UTC()
	items := []observabilityruntime.GeneratedMetricBatchItem{
		proxyOperationalV8MetricItem(
			ctx, observedAt, meta, observability.TelemetryInstrumentDefenseClawSemanticRoutingDecision,
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawSemanticRoutingDecision(
					observability.MetricDefenseClawSemanticRoutingDecisionInput{
						Envelope: envelope, Value: 1,
						DefenseClawMetricResult:    observability.Present(outcome.Result),
						DefenseClawMetricErrorCode: observability.Present(outcome.FailureCode),
						DefenseClawMetricDecision:  observability.Present(decisionLabel),
						DefenseClawConnectorSource: observability.Present(connector),
						DefenseClawRouteSource:     hookModelV8OptionalText(source),
						DefenseClawRouteCategory:   hookModelV8OptionalText(category),
						DefenseClawRouteFilteredBy: hookModelV8OptionalText(filteredBy),
						DefenseClawRouteListener:   hookModelV8OptionalText(routeListenerLabel(listener)),
						DefenseClawRouteDenyReason: hookModelV8OptionalText(denyReason),
						DefenseClawBudgetID:        hookModelV8OptionalText(budgetID),
					},
				)
			},
		),
	}
	if outcome.Latency >= 0 {
		latencyMs := float64(outcome.Latency) / float64(time.Millisecond)
		if !math.IsNaN(latencyMs) && !math.IsInf(latencyMs, 0) {
			items = append(items, proxyOperationalV8MetricItem(
				ctx, observedAt, meta, observability.TelemetryInstrumentDefenseClawSemanticRoutingLatency,
				func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
					return builder.BuildMetricDefenseClawSemanticRoutingLatency(
						observability.MetricDefenseClawSemanticRoutingLatencyInput{
							Envelope: envelope, Value: latencyMs,
							DefenseClawMetricResult:    observability.Present(outcome.Result),
							DefenseClawMetricErrorCode: observability.Present(outcome.FailureCode),
						},
					)
				},
			))
		}
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

// budgetMetricBatch is the budget gauges of one tick: the limit, the spend of
// every subject added, the highest single subject and the subjects at or over
// the limit, per configured budget (at most config.RoutingAdminMaxBudgets
// series each), plus the fleet budget store state when one is configured.
// It returns nothing, and costs nothing, while no budget is configured. Spend
// whose remote part is still loading, or that the fleet store answers with
// "over the limit" only, is left out, never reported as 0. Subjects and
// groups never appear: a budget is named by its administrator-chosen id.
func (s *Sidecar) budgetMetricBatch(ctx context.Context, observedAt time.Time) []observabilityruntime.GeneratedMetricBatchItem {
	return budgetMetricBatchFor(ctx, observedAt, s.currentConfig(), routingAdminRuntime.Ledger())
}

func budgetMetricBatchFor(
	ctx context.Context,
	observedAt time.Time,
	cfg *config.Config,
	ledger *routingadmin.Ledger,
) []observabilityruntime.GeneratedMetricBatchItem {
	if cfg == nil || cfg.Routing.Admin == nil || len(cfg.Routing.Admin.Budgets) == 0 {
		return nil
	}
	store := cfg.Routing.Admin.BudgetStore
	storeOn := store != nil && strings.TrimSpace(store.URL) != ""
	item := func(family string, build hookV8MetricRecordBuilder) observabilityruntime.GeneratedMetricBatchItem {
		return newGatewayGeneratedMetricItem(ctx, observedAt, observability.SourceSystem, "", routingMetricsV8Producer, observability.EventName(family), build)
	}
	items := make([]observabilityruntime.GeneratedMetricBatchItem, 0, 4*len(cfg.Routing.Admin.Budgets)+2)
	for _, b := range cfg.Routing.Admin.Budgets {
		id, scope, period := observability.Present(routeBoundedLabel(b.ID)), observability.Present(b.Scope), observability.Present(b.Period)
		limit := b.LimitUSD
		items = append(items, item(observability.TelemetryInstrumentDefenseClawBudgetLimit,
			func(bl *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
				return bl.BuildMetricDefenseClawBudgetLimit(observability.MetricDefenseClawBudgetLimitInput{
					Envelope: e, Value: limit, DefenseClawBudgetID: id, DefenseClawBudgetScope: scope, DefenseClawBudgetPeriod: period,
				})
			}))
		snap, known := ledger.Snapshot(b.Scope+":"+b.ID+":", b.Period, b.LimitUSD, observedAt)
		if !known {
			continue
		}
		// A fleet store answers a pooled budget (a group or a connector, whose
		// spend adds up across devices) with "over the limit" only, never its
		// total: this device's share would read as the whole, so no spend is
		// reported for it; the subjects-over count still is.
		marker := snap.Peak >= budgetstore.ExceededUSD/2
		if marker {
			// The store marks a pooled budget that is over its limit with a
			// huge spend: that is the only signal, and it counts as exceeded.
			snap.Exceeded = max(snap.Exceeded, 1)
		}
		if !marker && !(storeOn && b.Scope != config.RoutingBudgetScopeUser) {
			total, peak := snap.Total, snap.Peak
			items = append(items,
				item(observability.TelemetryInstrumentDefenseClawBudgetSpend,
					func(bl *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
						return bl.BuildMetricDefenseClawBudgetSpend(observability.MetricDefenseClawBudgetSpendInput{
							Envelope: e, Value: total, DefenseClawBudgetID: id, DefenseClawBudgetScope: scope, DefenseClawBudgetPeriod: period,
						})
					}),
				item(observability.TelemetryInstrumentDefenseClawBudgetPeakSubjectSpend,
					func(bl *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
						return bl.BuildMetricDefenseClawBudgetPeakSubjectSpend(observability.MetricDefenseClawBudgetPeakSubjectSpendInput{
							Envelope: e, Value: peak, DefenseClawBudgetID: id, DefenseClawBudgetScope: scope, DefenseClawBudgetPeriod: period,
						})
					}))
		}
		exceeded := int64(snap.Exceeded)
		items = append(items, item(observability.TelemetryInstrumentDefenseClawBudgetSubjectsExceeded,
			func(bl *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
				return bl.BuildMetricDefenseClawBudgetSubjectsExceeded(observability.MetricDefenseClawBudgetSubjectsExceededInput{
					Envelope: e, Value: exceeded, DefenseClawBudgetID: id, DefenseClawBudgetScope: scope, DefenseClawBudgetPeriod: period,
				})
			}))
	}
	if storeOn {
		age, synced, healthy := ledger.StoreStatus(observedAt)
		ok := int64(0)
		if healthy {
			ok = 1
		}
		items = append(items, item(observability.TelemetryInstrumentDefenseClawBudgetStoreHealthy,
			func(bl *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
				return bl.BuildMetricDefenseClawBudgetStoreHealthy(observability.MetricDefenseClawBudgetStoreHealthyInput{Envelope: e, Value: ok})
			}))
		if synced {
			seconds := math.Max(age.Seconds(), 0)
			items = append(items, item(observability.TelemetryInstrumentDefenseClawBudgetStoreSyncAge,
				func(bl *observability.FamilyBuilder, e observability.FamilyEnvelopeInput) (observability.Record, error) {
					return bl.BuildMetricDefenseClawBudgetStoreSyncAge(observability.MetricDefenseClawBudgetStoreSyncAgeInput{Envelope: e, Value: seconds})
				}))
		}
	}
	return items
}
