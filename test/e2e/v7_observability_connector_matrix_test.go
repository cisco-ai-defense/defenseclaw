// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"go.opentelemetry.io/otel/codes"
)

// TestV7Observability_DestinationAppPerConnector parameterizes the
// gateway-verdict observability path (mirrors testSurfaceVerdict in
// v7_observability_test.go) across the full connector matrix.
//
// Plan E3 / S3.4 — every audit/observability surface that today
// hardcodes destination_app="openclaw" must work for the other three
// connectors too. The shape under test:
//
//   - Emit a gatewaylog.EventVerdict with destination_app=<connector>.
//   - Assert the OTel verdict counter has destination_app=<connector>
//     in its attribute set so Splunk dashboards pivoting on
//     destination_app see traffic from every framework, not just
//     OpenClaw.
func TestV7Observability_DestinationAppPerConnector(t *testing.T) {
	for _, fx := range connectorMatrix(t) {
		t.Run(fx.Name, func(t *testing.T) {
			h := newObservabilityHarness(t)

			triggerViaSidecarHTTP(t, func() {
				_, sp := h.Tel.Tracer().Start(context.Background(), "e2e.verdict."+fx.Name)
				sp.SetStatus(codes.Ok, "")
				sp.End()
				base := envelopeBase()
				ev := base
				ev.Timestamp = time.Unix(1700000010, 0).UTC()
				ev.EventType = gatewaylog.EventVerdict
				ev.Severity = gatewaylog.SeverityHigh
				ev.Verdict = &gatewaylog.VerdictPayload{
					Stage:     gatewaylog.StageFinal,
					Action:    "block",
					Reason:    "injection",
					LatencyMs: 12,
				}
				ev.PolicyID = "pol-e2e-block-injection-" + fx.Name
				ev.DestinationApp = fx.DestinationApp
				h.GW.Emit(ev)
			})

			rm := collectMetrics(t, h.Reader)
			if sumInt64Counter(rm, "defenseclaw.gateway.verdicts") < 1 {
				t.Fatalf("[%s] expected defenseclaw.gateway.verdicts counter", fx.Name)
			}
			if !metricHasAttrKeyValue(rm,
				"defenseclaw.gateway.verdicts",
				"destination_app",
				fx.DestinationApp,
			) {
				t.Errorf("[%s] expected destination_app=%q on defenseclaw.gateway.verdicts",
					fx.Name, fx.DestinationApp)
			}
			if !metricHasAttrKeyValue(rm,
				"defenseclaw.gateway.verdicts",
				"policy_id",
				"pol-e2e-block-injection-"+fx.Name,
			) {
				t.Errorf("[%s] expected policy_id=pol-e2e-block-injection-%s on defenseclaw.gateway.verdicts",
					fx.Name, fx.Name)
			}
		})
	}
}
