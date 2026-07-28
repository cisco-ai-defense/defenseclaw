// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestManagedAgentInventoryIsForceCollectedAndReservedToManagedDestination(t *testing.T) {
	disabled := false
	base := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		Buckets: map[observability.Bucket]ObservabilityV8BucketPolicySource{
			observability.BucketAIDiscovery: {
				Collect: ObservabilityV8CollectSource{Logs: &disabled},
			},
			observability.BucketAgentLifecycle: {
				Collect: ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
		Destinations: []ObservabilityV8DestinationSource{{
			Name: "operator-console", Kind: ObservabilityV8DestinationConsole,
		}},
	})
	plan, err := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	inventory, ok := plan.Bucket(observability.BucketAIDiscovery)
	if !ok || !inventory.Collect.Logs {
		t.Fatalf("managed ai.discovery collection=%+v present=%t", inventory, ok)
	}
	lifecycle, ok := plan.Bucket(observability.BucketAgentLifecycle)
	if !ok || lifecycle.Collect.Logs {
		t.Fatalf("managed agent.lifecycle collection was broadened=%+v present=%t", lifecycle, ok)
	}

	baseOperator, ok := base.RuntimeDestination("operator-console")
	if !ok || len(baseOperator.Routes) != 1 || baseOperator.Routes[0].Index != 0 {
		t.Fatalf("base operator route=%+v present=%t", baseOperator.Routes, ok)
	}
	operator, ok := plan.RuntimeDestination("operator-console")
	if !ok || len(operator.Routes) != 2 {
		t.Fatalf("managed operator routes=%+v present=%t", operator.Routes, ok)
	}
	drop := operator.Routes[0]
	if drop.Index != 0 || !drop.Generated || drop.Action != ObservabilityV8RouteDrop ||
		!reflect.DeepEqual(drop.Signals, []observability.Signal{observability.SignalLogs}) ||
		!reflect.DeepEqual(drop.Selector.Buckets, []observability.Bucket{observability.BucketAIDiscovery}) ||
		!reflect.DeepEqual(drop.Selector.Actions, []observability.ProducerKey{
			ObservabilityV8ManagedAgentInventoryAction,
			ObservabilityV8ManagedConnectorInventoryAction,
			ObservabilityV8ManagedMCPInventoryAction,
			ObservabilityV8LocalInventoryDiagnosticAction,
		}) {
		t.Fatalf("reserved operator drop route=%+v", drop)
	}
	if operator.Routes[1].Index != 1 || operator.Routes[1].Action != ObservabilityV8RouteSend {
		t.Fatalf("operator original route not shifted intact=%+v", operator.Routes[1])
	}
	managed, ok := plan.RuntimeDestination(ObservabilityV8ManagedAIDDestinationName)
	if !ok || len(managed.Routes) != 3 || managed.Routes[0].Action != ObservabilityV8RouteDrop ||
		managed.Routes[1].Action != ObservabilityV8RouteDrop ||
		managed.Routes[2].Action != ObservabilityV8RouteSend ||
		!managed.Routes[2].Selector.BucketWildcard {
		t.Fatalf("managed inventory route=%+v present=%t", managed.Routes, ok)
	}

	idempotent, err := WithObservabilityV8ManagedAIDDestination(plan, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
	})
	if err != nil || idempotent != plan {
		t.Fatalf("managed inventory reservation not idempotent plan=%p want=%p err=%v", idempotent, plan, err)
	}
}
