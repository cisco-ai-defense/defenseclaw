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
	if len(destination.Routes) != 3 || !destination.Routes[0].Generated ||
		destination.Routes[0].Action != ObservabilityV8RouteDrop ||
		!reflect.DeepEqual(destination.Routes[0].Selector.Actions,
			[]observability.ProducerKey{ObservabilityV8LocalInventoryDiagnosticAction}) ||
		destination.Routes[1].Action != ObservabilityV8RouteDrop ||
		!reflect.DeepEqual(destination.Routes[1].Selector.EventNames,
			[]observability.EventName{"ai_component.observed"}) ||
		!destination.Routes[2].Generated || !destination.Routes[2].Selector.BucketWildcard {
		t.Fatalf("managed route = %+v", destination.Routes)
	}
	for bucket, profile := range destination.Routes[2].RedactionProfileByBucket {
		if profile != "sensitive" {
			t.Fatalf("managed profile for %s = %q", bucket, profile)
		}
	}
	if len(destination.Routes[2].RedactionProfileByBucket) != len(snapshot.Buckets) {
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
		{DeploymentMode: "managed_enterprise", Endpoint: ""},
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

func TestManagedAIDDestinationPinsExactSourceHashWithoutPublishingIt(t *testing.T) {
	base := mustCompileObservabilityV8(t, nil)
	rawA := []byte("config_version: 8\nmode: one\n")
	rawB := []byte("config_version: 8\nmode: two\n")
	hashA := ObservabilityV8SourceContentHash(rawA)
	hashB := ObservabilityV8SourceContentHash(rawB)
	if hashA == "" || hashB == "" || hashA == hashB ||
		hashA != "f2e486923732263ec9e11dfdd29bb421209b4cdf87c5f50f2f74f36e172297d5" {
		t.Fatalf("exact source hashes = %q/%q", hashA, hashB)
	}
	first, err := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
		SourceContentHash: hashA,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
		SourceContentHash: hashB,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest() != second.Digest() || first.ReloadEquivalent(second) ||
		!reflect.DeepEqual(first.EffectiveJSON(), second.EffectiveJSON()) ||
		strings.Contains(string(first.EffectiveJSON()), hashA) || strings.Contains(string(second.EffectiveJSON()), hashB) {
		t.Fatal("source hash must affect only secret runtime reload identity")
	}
	firstDestination, _ := first.RuntimeDestination(ObservabilityV8ManagedAIDDestinationName)
	secondDestination, _ := second.RuntimeDestination(ObservabilityV8ManagedAIDDestinationName)
	if got, ok := ObservabilityV8ManagedAIDSourceContentHash(firstDestination); !ok || got != hashA {
		t.Fatalf("first source binding = %q/%v", got, ok)
	}
	if got, ok := ObservabilityV8ManagedAIDSourceContentHash(secondDestination); !ok || got != hashB {
		t.Fatalf("second source binding = %q/%v", got, ok)
	}
	updated, err := WithObservabilityV8ManagedAIDDestination(first, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
		SourceContentHash: hashB,
	})
	if err != nil || updated == first || updated.ReloadEquivalent(first) || !updated.ReloadEquivalent(second) {
		t.Fatalf("updated binding plan=%p err=%v", updated, err)
	}
	if got, err := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test",
		SourceContentHash: strings.Repeat("A", 64),
	}); err == nil || got != nil {
		t.Fatalf("invalid source hash plan=%p err=%v", got, err)
	}
}

func TestManagedAIDDestinationRequiresHTTPSBareOrigin(t *testing.T) {
	base := mustCompileObservabilityV8(t, nil)
	accepted, err := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise", Endpoint: "https://aid.example.test:8443/",
	})
	if err != nil {
		t.Fatal(err)
	}
	destination, ok := accepted.RuntimeDestination(ObservabilityV8ManagedAIDDestinationName)
	if !ok || destination.Transport.Endpoint !=
		"https://aid.example.test:8443"+ObservabilityV8ManagedAIDIngestPath {
		t.Fatalf("accepted managed endpoint = %+v, present=%v", destination.Transport, ok)
	}

	for _, endpoint := range []string{
		"   ",
		" http://aid.example.test",
		"http://aid.example.test",
		"https://user@aid.example.test",
		"https://aid.example.test?tenant=operator",
		"https://aid.example.test?",
		"https://aid.example.test#fragment",
		"https://aid.example.test#",
		"https://aid.example.test/operator-path",
		"https://aid.example.test//",
		"https://aid.example.test/%2f",
		"https://aid.example.test:70000",
		"https://aid.example.test:",
		"https://[invalid",
		"https://",
	} {
		t.Run(endpoint, func(t *testing.T) {
			got, endpointErr := WithObservabilityV8ManagedAIDDestination(base, ObservabilityV8ManagedAIDOptions{
				DeploymentMode: "managed_enterprise", Endpoint: endpoint,
			})
			if endpointErr == nil || got != nil {
				t.Fatalf("managed endpoint %q returned plan=%p err=%v, want rejection", endpoint, got, endpointErr)
			}
		})
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
