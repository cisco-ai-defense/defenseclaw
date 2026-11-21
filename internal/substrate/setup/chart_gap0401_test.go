// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"testing"
)

// GAP-0401: the gateway and leader pods serve only /healthz and /readyz on
// gateway.ports.metrics (9464); their metrics go over OTLP. The chart must
// not publish that port as a metrics endpoint: no Service port for it, and
// no NetworkPolicy rule that lets scrapers in to it or to the callout's
// health port. Before, a defenseclaw-gateway-metrics Service, a metrics
// port on the defenseclaw-leader Service and networkPolicy.metricsFrom
// pointed scrapers at a port that has no /metrics page.
func TestChartPublishesNoMetricsEndpointGAP0401(t *testing.T) {
	helm := helmBinary(t)
	for _, c := range chartCases {
		t.Run(c, func(t *testing.T) {
			for _, o := range decodeObjects(t, renderChart(t, helm, c)) {
				name := fmt.Sprint(o.Metadata["name"])
				switch o.Kind {
				case "Service":
					ports, _ := dig(o.Spec, "ports").([]any)
					for _, p := range ports {
						pm, _ := p.(map[string]any)
						if fmt.Sprint(pm["name"]) == "metrics" || fmt.Sprint(pm["targetPort"]) == "metrics" || fmt.Sprint(pm["port"]) == "9464" {
							t.Errorf("Service %s publishes the probe port as a metrics endpoint: %v", name, pm)
						}
					}
				case "NetworkPolicy":
					rules, _ := dig(o.Spec, "ingress").([]any)
					for _, r := range rules {
						ports, _ := dig(r, "ports").([]any)
						for _, p := range ports {
							pm, _ := p.(map[string]any)
							if port := fmt.Sprint(pm["port"]); port == "9464" || port == "9444" {
								t.Errorf("NetworkPolicy %s lets peers in to probe port %s: %v", name, port, r)
							}
						}
					}
				}
			}
		})
	}
}
