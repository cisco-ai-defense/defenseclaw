// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// A Secure Client plan with no AI Defense endpoint yet (enrollment, or a
// reload that clears it) has no drop routes for the managed inventory. Before
// GAP-1835 its managed_* records then reached the operator's destinations.
func TestManagedInventoryNeverReachesAnOperatorDestination(t *testing.T) {
	evaluator := mustEvaluator(t, &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "logs", Kind: config.ObservabilityV8DestinationConsole},
		{Name: "otlp", Kind: config.ObservabilityV8DestinationOTLP, Endpoint: "https://collector.example.com"},
	}})
	for action, want := range map[observability.ProducerKey][]string{
		config.ObservabilityV8ManagedAgentInventoryAction:     {"local-sqlite"},
		config.ObservabilityV8ManagedConnectorInventoryAction: {"local-sqlite"},
		config.ObservabilityV8ManagedMCPInventoryAction:       {"local-sqlite"},
		config.ObservabilityV8ManagedSkillInventoryAction:     {"local-sqlite"},
		config.ObservabilityV8ManagedPluginInventoryAction:    {"local-sqlite"},
		config.ObservabilityV8MCPInventoryAction:              {"local-sqlite", "logs", "otlp"},
	} {
		metadata, err := NewClassifiedLogMetadata(
			observability.ProducerGatewayEvent,
			observability.ProducerKey("ai_discovery"),
			observability.ClassificationContext{
				Bucket: observability.BucketAIDiscovery, EventName: "ai_component.confidence.changed", RawSeverity: "INFO",
			},
			observability.SourceSystem,
			"",
			action,
		)
		if err != nil {
			t.Fatal(err)
		}
		admission, err := evaluator.Admit(metadata)
		if err != nil || admission != AdmissionOrdinary {
			t.Fatalf("%s admission = %v, %v", action, admission, err)
		}
		if got := deliveryNames(evaluator.route(metadata, admission)); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s destinations = %v, want %v", action, got, want)
		}
	}
}
