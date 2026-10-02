// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// GAP-1495: Claude Code exports zero token points for unused token types and
// counters as doubles. Neither is an invalid record; a real invalid record is
// named in gateway.log.
func TestOTLPInboundClaudeTokenZeroAndDoublePoints(t *testing.T) {
	previousInstance := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("otlp-inbound-claude-zero-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstance) })
	var logged bytes.Buffer
	previousWriter := invalidInboundLeafLogWriter
	invalidInboundLeafLogWriter = &logged
	t.Cleanup(func() { invalidInboundLeafLogWriter = previousWriter })

	now := time.Now().UTC()
	request := func(temporality metricspb.AggregationTemporality, tokenType string, value float64) *collectormetricspb.ExportMetricsServiceRequest {
		return &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
				otlpClassifierStringAttribute("service.name", "claude-code"),
			}},
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
				Name: "claude_code.token.usage", Unit: "tokens",
				Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{
					AggregationTemporality: temporality, IsMonotonic: true,
					DataPoints: []*metricspb.NumberDataPoint{{
						StartTimeUnixNano: uint64(now.Add(-time.Minute).UnixNano()),
						TimeUnixNano:      uint64(now.UnixNano()),
						Attributes: []*commonpb.KeyValue{
							otlpClassifierStringAttribute("type", tokenType),
							otlpClassifierStringAttribute("model", "claude-haiku"),
						},
						Value: &metricspb.NumberDataPoint_AsDouble{AsDouble: value},
					}},
				}},
			}}}},
		}}}
	}
	delta := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA
	cumulative := metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE
	for _, tc := range []struct {
		name        string
		message     *collectormetricspb.ExportMetricsServiceRequest
		wantInvalid int64
	}{
		{"delta zero", request(delta, "cacheCreation", 0), 0},
		{"cumulative zero", request(cumulative, "cacheRead", 0), 0},
		{"cumulative double", request(cumulative, "input", 12), 0},
		{"cumulative fraction", request(cumulative, "output", 12.5), 1},
	} {
		fixture := newOTLPV8MetricFixture(t)
		api := &APIServer{}
		api.bindOTLPObservabilityRuntime(fixture.runtime)
		accounting, err := api.importDecodedOTLPRequestV8(
			context.Background(), tc.message, otelSignalMetrics, "claudecode", now,
		)
		if err != nil || !accounting.valid() || accounting.invalidRecord != tc.wantInvalid ||
			(tc.wantInvalid == 0 && accounting.derivedOnly != 1) {
			t.Fatalf("%s: accounting=%+v err=%v", tc.name, accounting, err)
		}
	}
	if got := logged.String(); strings.Count(got, "\n") != 1 ||
		!strings.Contains(got, "invalid metrics record from claudecode: metric claude_code.token.usage") {
		t.Fatalf("gateway.log line = %q", got)
	}
}
