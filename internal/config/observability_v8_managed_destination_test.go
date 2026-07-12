// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestManagedAIDDestinationIsReleaseOwnedAndSensitive(t *testing.T) {
	disabled := false
	base := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		Buckets: map[observability.Bucket]ObservabilityV8BucketPolicySource{
			observability.BucketPlatformHealth: {
				Collect: ObservabilityV8CollectSource{Logs: &disabled},
			},
			observability.BucketDiagnostic: {
				Collect: ObservabilityV8CollectSource{Logs: &disabled},
			},
			observability.BucketAIDiscovery: {
				Collect: ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
	})
	baseDigest := base.Digest()
	plan, err := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan == nil || plan.Digest() == baseDigest {
		t.Fatal("managed destination did not produce a distinct immutable plan")
	}
	if _, ok := base.Destination(ObservabilityV8ManagedAIDDestinationName); ok {
		t.Fatal("managed destination mutated the source plan")
	}
	baseHealth, ok := base.Bucket(observability.BucketPlatformHealth)
	if !ok || baseHealth.Collect.Logs {
		t.Fatalf("source platform-health collection was mutated: %+v, present=%v", baseHealth, ok)
	}
	managedHealth, ok := plan.Bucket(observability.BucketPlatformHealth)
	if !ok || !managedHealth.Collect.Logs {
		t.Fatalf("managed platform-health collection = %+v, present=%v", managedHealth, ok)
	}
	baseInventory, ok := base.Bucket(observability.BucketAIDiscovery)
	if !ok || baseInventory.Collect.Logs {
		t.Fatalf("source AI-discovery collection was mutated: %+v, present=%v", baseInventory, ok)
	}
	managedInventory, ok := plan.Bucket(observability.BucketAIDiscovery)
	if !ok || !managedInventory.Collect.Logs {
		t.Fatalf("managed AI-discovery collection = %+v, present=%v", managedInventory, ok)
	}
	managedDiagnostic, ok := plan.Bucket(observability.BucketDiagnostic)
	if !ok || managedDiagnostic.Collect.Logs {
		t.Fatalf("managed diagnostic collection was broadened: %+v, present=%v", managedDiagnostic, ok)
	}
	snapshot := plan.Snapshot()
	for bucket, detail := range map[observability.Bucket]string{
		observability.BucketPlatformHealth: "fail-open availability",
		observability.BucketAIDiscovery:    "endpoint inventory",
	} {
		provenancePath := "observability.buckets." + string(bucket) + ".collect.logs"
		var generated *ObservabilityV8Provenance
		for index := range snapshot.Provenance {
			candidate := snapshot.Provenance[index]
			if candidate.Path == provenancePath {
				generated = &candidate
				break
			}
		}
		if generated == nil || generated.Origin != "generated" ||
			!strings.Contains(generated.Detail, detail) {
			t.Fatalf("managed %s provenance = %+v", bucket, generated)
		}
	}
	destination, ok := plan.RuntimeDestination(ObservabilityV8ManagedAIDDestinationName)
	if !ok || !destination.Generated || destination.Kind != ObservabilityV8DestinationOTLP || !destination.Enabled {
		t.Fatalf("managed destination = %+v, present=%v", destination, ok)
	}
	if destination.Transport.Endpoint != "https://aid.example.test"+ObservabilityV8ManagedAIDIngestPath ||
		destination.Transport.Method != "POST" || destination.Transport.Protocol != "http/json" {
		t.Fatalf("managed transport = %+v", destination.Transport)
	}
	if len(destination.Transport.Headers) != 0 || destination.Transport.TokenEnv != "" ||
		destination.Transport.BearerEnv != "" {
		t.Fatalf("managed transport accepted user credentials: %+v", destination.Transport)
	}
	if len(destination.Routes) != 1 || !destination.Routes[0].Generated ||
		!destination.Routes[0].Selector.BucketWildcard {
		t.Fatalf("managed route = %+v", destination.Routes)
	}
	for bucket, profile := range destination.Routes[0].RedactionProfileByBucket {
		if profile != "sensitive" {
			t.Fatalf("managed profile for %s = %q", bucket, profile)
		}
	}
	if len(destination.Routes[0].RedactionProfileByBucket) != len(snapshot.Buckets) {
		t.Fatal("managed route does not cover the complete bucket catalog")
	}
	if !reflect.DeepEqual(destination.SelectedSignals, []observability.Signal{observability.SignalLogs}) {
		t.Fatalf("managed signals = %v", destination.SelectedSignals)
	}
	idempotent, err := WithObservabilityV8ManagedAIDDestination(plan, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test/",
	})
	if err != nil || idempotent != plan {
		t.Fatalf("idempotent managed destination returned plan=%p err=%v, want original %p", idempotent, err, plan)
	}
}

func TestManagedAIDDestinationGateAndReloadDigest(t *testing.T) {
	base := mustCompileObservabilityV8(t, nil)
	for _, options := range []ObservabilityV8ManagedAIDOptions{
		{DeploymentMode: "unmanaged_byod", Endpoint: "https://aid.example.test"},
		{DeploymentMode: "managed_enterprise", Endpoint: "   "},
	} {
		got, err := WithObservabilityV8ManagedAIDDestination(base, options)
		if err != nil || got != base {
			t.Fatalf("inactive gate returned plan=%p err=%v, want original plan", got, err)
		}
	}
	first, err := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://one.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://two.example.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() == second.Digest() || first.ReloadEquivalent(second) {
		t.Fatal("managed endpoint change was not represented in reload identity")
	}
}

func TestManagedAIDDestinationNameCannotAppearInSource(t *testing.T) {
	_, err := CompileObservabilityV8(&ObservabilityV8Source{Destinations: []ObservabilityV8DestinationSource{{
		Name: ObservabilityV8ManagedAIDDestinationName, Kind: ObservabilityV8DestinationOTLP,
		Endpoint: "https://attacker.example.test",
		Headers: map[string]ObservabilityV8HeaderValue{
			"Authorization": ObservabilityV8StaticHeader("attacker-controlled"),
		},
	}}})
	if err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("source managed destination error = %v", err)
	}
}
