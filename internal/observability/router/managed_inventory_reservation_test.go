// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// A managed Secure Client plan with no Cisco AI Defense endpoint has no
// managed destination. Its managed endpoint inventory and the local
// inventory diagnostics were still sent to every operator log destination,
// because the reservation ran only on the path that adds the managed
// destination (#1453). They stay local now, also after a reload that clears
// the endpoint; other ai.discovery records and other profiles are unchanged.

const reservationOperator = "operator-archive"

var reservedInventoryActions = []observability.ProducerKey{
	config.ObservabilityV8ManagedAgentInventoryAction,
	config.ObservabilityV8ManagedConnectorInventoryAction,
	config.ObservabilityV8ManagedMCPInventoryAction,
	config.ObservabilityV8ManagedSkillInventoryAction,
	config.ObservabilityV8ManagedPluginInventoryAction,
	config.ObservabilityV8LocalInventoryDiagnosticAction,
}

func reservationBasePlan(t *testing.T) *config.ObservabilityV8Plan {
	t.Helper()
	collect := true
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Defaults: config.ObservabilityV8BucketPolicySource{
			Collect: config.ObservabilityV8CollectSource{Logs: &collect},
		},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: reservationOperator, Kind: config.ObservabilityV8DestinationJSONL,
			Path: "/tmp/defenseclaw-operator.jsonl",
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalLogs},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func reservationPlan(t *testing.T, base *config.ObservabilityV8Plan, profile, endpoint string) *config.ObservabilityV8Plan {
	t.Helper()
	plan, err := config.WithObservabilityV8ManagedAIDDestination(base, config.ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Profile: profile, Endpoint: endpoint,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func inventoryMetadata(t *testing.T, action observability.ProducerKey) Metadata {
	t.Helper()
	metadata, err := NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent, "ai_discovery",
		observability.ClassificationContext{
			Bucket: observability.BucketAIDiscovery, EventName: "ai.discovery.completed", RawSeverity: "INFO",
		},
		observability.SourceGateway, "", action,
	)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func deliveredTo(t *testing.T, plan *config.ObservabilityV8Plan, action observability.ProducerKey) map[string]bool {
	t.Helper()
	evaluator, err := New(plan)
	if err != nil {
		t.Fatal(err)
	}
	metadata := inventoryMetadata(t, action)
	admission, err := evaluator.Admit(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if admission == AdmissionDrop {
		t.Fatalf("%s was not collected", action)
	}
	names := map[string]bool{}
	for _, delivery := range evaluator.route(metadata, admission) {
		names[delivery.DestinationName] = true
	}
	return names
}

func operatorRoutes(t *testing.T, plan *config.ObservabilityV8Plan) []config.ObservabilityV8EffectiveRoute {
	t.Helper()
	destination, ok := plan.RuntimeDestination(reservationOperator)
	if !ok {
		t.Fatal("operator destination is missing")
	}
	return destination.Routes
}

func TestManagedInventoryStaysOffOperatorDestinationsWithoutAnAIDefenseEndpoint(t *testing.T) {
	base := reservationBasePlan(t)
	for _, action := range append([]observability.ProducerKey{""}, reservedInventoryActions...) {
		if !deliveredTo(t, base, action)[reservationOperator] {
			t.Fatalf("precondition: the unmanaged plan does not send %q to the operator", action)
		}
	}
	plan := reservationPlan(t, base, "secure_client", "")
	if _, ok := plan.RuntimeDestination(config.ObservabilityV8ManagedAIDDestinationName); ok {
		t.Fatal("a managed destination was added without an endpoint")
	}
	for _, action := range reservedInventoryActions {
		delivered := deliveredTo(t, plan, action)
		if delivered[reservationOperator] {
			t.Fatalf("%s reached the operator destination without an AI Defense endpoint", action)
		}
		if len(delivered) == 0 {
			t.Fatalf("%s reached no destination; local SQLite must keep it", action)
		}
	}
	if !deliveredTo(t, plan, "")[reservationOperator] {
		t.Fatal("an ordinary ai.discovery record no longer reaches the operator destination")
	}
	if !deliveredTo(t, base, config.ObservabilityV8ManagedMCPInventoryAction)[reservationOperator] {
		t.Fatal("the reservation mutated the source plan")
	}
}

func TestManagedInventoryReservationIsIdempotentAndKeepsRouteOrder(t *testing.T) {
	base := reservationBasePlan(t)
	before := operatorRoutes(t, base)
	once := reservationPlan(t, base, "secure_client", "")
	if again := reservationPlan(t, once, "secure_client", ""); again != once {
		t.Fatal("a repeated reservation built a new plan")
	}
	withEndpoint := reservationPlan(t, once, "secure_client", "https://aid.example.test")
	for _, plan := range []*config.ObservabilityV8Plan{once, withEndpoint} {
		routes := operatorRoutes(t, plan)
		if len(routes) != len(before)+1 || routes[0].Name != "drop-managed-endpoint-inventory" || !routes[0].Generated {
			t.Fatalf("operator routes = %+v, want one reservation route before %d operator routes", routes, len(before))
		}
		for index, route := range routes[1:] {
			if route.Name != before[index].Name || route.Index != index+1 || route.Action != before[index].Action {
				t.Fatalf("operator route %d = %+v, want %+v at index %d", index, route, before[index], index+1)
			}
		}
	}
	if _, ok := withEndpoint.RuntimeDestination(config.ObservabilityV8ManagedAIDDestinationName); !ok {
		t.Fatal("the endpoint did not add the managed destination")
	}
	if delivered := deliveredTo(t, withEndpoint, config.ObservabilityV8ManagedAgentInventoryAction); delivered[reservationOperator] ||
		!delivered[config.ObservabilityV8ManagedAIDDestinationName] {
		t.Fatalf("with an endpoint the agent inventory went to %v, want the managed destination only", delivered)
	}
}

// A reload compiles the candidate from source and applies the managed
// options of the new config: clearing the endpoint drops the managed
// destination and keeps the inventory off the operator destination.
func TestEndpointClearingReloadKeepsManagedInventoryOffOperatorDestinations(t *testing.T) {
	base := reservationBasePlan(t)
	active := reservationPlan(t, base, "secure_client", "https://aid.example.test")
	cleared := reservationPlan(t, base, "secure_client", "")
	if cleared.ReloadEquivalent(active) {
		t.Fatal("clearing the endpoint is not a plan change")
	}
	for _, action := range reservedInventoryActions {
		for name, plan := range map[string]*config.ObservabilityV8Plan{"active": active, "cleared": cleared} {
			if deliveredTo(t, plan, action)[reservationOperator] {
				t.Fatalf("%s plan sends %s to the operator destination", name, action)
			}
		}
	}
}

// A standalone managed deployment exports to the administrator destinations,
// and an unmanaged one has nothing to reserve: both keep their plan.
func TestManagedInventoryReservationLeavesOtherProfilesAlone(t *testing.T) {
	base := reservationBasePlan(t)
	for _, options := range []config.ObservabilityV8ManagedAIDOptions{
		{DeploymentMode: "managed_enterprise", Profile: "standalone"},
		{DeploymentMode: "managed_enterprise", Profile: "standalone", Endpoint: "https://aid.example.test"},
		{DeploymentMode: "unmanaged_byod"},
	} {
		plan, err := config.WithObservabilityV8ManagedAIDDestination(base, options)
		if err != nil || plan != base {
			t.Fatalf("%+v returned plan=%p err=%v, want the original plan", options, plan, err)
		}
	}
}
