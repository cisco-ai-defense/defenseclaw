// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

const apiOperationalV8Producer = "gateway.api.operational"

func (a *APIServer) apiOperationalV8Runtime() hookLifecycleMetricV8Runtime {
	if a == nil {
		return nil
	}
	runtime, _ := a.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
	return runtime
}

func recordAPIRequestV8(
	ctx context.Context,
	runtime hookLifecycleMetricV8Runtime,
	method string,
	route string,
	statusCode int,
	duration time.Duration,
) {
	if ctx == nil || runtime == nil || duration < 0 {
		return
	}
	method = canonicalHTTPMethod(method)
	if strings.TrimSpace(route) == "" {
		route = "unmatched"
	}
	connector := strings.TrimSpace(audit.EnvelopeFromContext(ctx).Connector)
	if connector != "" && !observability.IsStableToken(connector) {
		connector = ""
	}
	observedAt := time.Now().UTC()
	status := int64(statusCode)
	durationMs := float64(duration) / float64(time.Millisecond)
	items := []observabilityruntime.GeneratedMetricBatchItem{
		newGatewayGeneratedMetricItem(
			ctx, observedAt, observability.SourceGateway, connector, apiOperationalV8Producer,
			observability.EventName(observability.TelemetryInstrumentDefenseClawHTTPRequestCount),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawHTTPRequestCount(observability.MetricDefenseClawHTTPRequestCountInput{
					Envelope: envelope, Value: 1,
					HTTPRequestMethod:      observability.Present(method),
					HTTPRoute:              observability.Present(route),
					HTTPResponseStatusCode: observability.Present(status),
				})
			},
		),
		newGatewayGeneratedMetricItem(
			ctx, observedAt, observability.SourceGateway, connector, apiOperationalV8Producer,
			observability.EventName(observability.TelemetryInstrumentDefenseClawHTTPRequestDuration),
			func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) (observability.Record, error) {
				return builder.BuildMetricDefenseClawHTTPRequestDuration(observability.MetricDefenseClawHTTPRequestDurationInput{
					Envelope: envelope, Value: durationMs,
					HTTPRequestMethod:      observability.Present(method),
					HTTPRoute:              observability.Present(route),
					HTTPResponseStatusCode: observability.Present(status),
				})
			},
		),
	}
	_, _ = runtime.RecordGeneratedMetricBatch(ctx, items)
}

func canonicalHTTPMethod(method string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "QUERY", "TRACE":
		return method
	default:
		return "_OTHER"
	}
}
