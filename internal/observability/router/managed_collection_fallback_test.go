// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func managedFallbackPlan(t *testing.T, collectLogs bool) *config.ObservabilityV8Plan {
	t.Helper()
	base, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Defaults: config.ObservabilityV8BucketPolicySource{
			Collect: config.ObservabilityV8CollectSource{Logs: &collectLogs},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := config.WithObservabilityV8ManagedAIDDestination(
		base,
		config.ObservabilityV8ManagedAIDOptions{
			DeploymentMode: "managed_enterprise",
			Endpoint:       "https://aid.example.test",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func managedFallbackDestination(t *testing.T) config.ObservabilityV8EffectiveDestination {
	t.Helper()
	for _, destination := range managedFallbackPlan(t, false).Snapshot().Destinations {
		if destination.Name == config.ObservabilityV8ManagedAIDDestinationName {
			return destination
		}
	}
	t.Fatal("generated managed destination is missing")
	return config.ObservabilityV8EffectiveDestination{}
}

func TestManagedFallbackDestinationIdentityFailsClosed(t *testing.T) {
	valid := managedFallbackDestination(t)
	if !validManagedFallbackDestination(valid, compileDestinationIndex(valid)) {
		t.Fatal("release-owned managed destination was not recognized")
	}
	tests := []struct {
		name   string
		mutate func(*config.ObservabilityV8EffectiveDestination)
	}{
		{name: "not generated", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Generated = false
		}},
		{name: "wrong kind", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Kind = config.ObservabilityV8DestinationConsole
		}},
		{name: "source-shaped policy", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.PolicyForm = config.ObservabilityV8PolicyAdvancedRoutes
		}},
		{name: "non-sensitive route", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Routes[2].RedactionProfileByBucket[observability.BucketDiagnostic] = "none"
		}},
		{name: "operator selector", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Routes[2].Selector.Sources = []observability.Source{observability.SourceGateway}
		}},
		{name: "floor route", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Routes[2].IncludesMandatoryFloor = true
		}},
		{name: "diagnostic drop removed", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Routes = destination.Routes[1:]
		}},
		{name: "component drop broadened", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Routes[1].Selector.EventNames = nil
		}},
		{name: "arbitrary endpoint path", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Transport.Endpoint = "https://aid.example.test/operator-route"
		}},
		{name: "source credentials", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.Transport.BearerEnv = "OPERATOR_TOKEN"
		}},
		{name: "wrong reload identity", mutate: func(destination *config.ObservabilityV8EffectiveDestination) {
			destination.ReloadApplicability.Policy = config.ObservabilityV8LiveReloadable
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Capabilities.Signals = append([]observability.Signal(nil), valid.Capabilities.Signals...)
			candidate.SelectedSignals = append([]observability.Signal(nil), valid.SelectedSignals...)
			candidate.Routes = append([]config.ObservabilityV8EffectiveRoute(nil), valid.Routes...)
			for routeIndex := range candidate.Routes {
				candidate.Routes[routeIndex].Signals = append([]observability.Signal(nil), valid.Routes[routeIndex].Signals...)
				candidate.Routes[routeIndex].Selector.Buckets = append([]observability.Bucket(nil), valid.Routes[routeIndex].Selector.Buckets...)
				candidate.Routes[routeIndex].Selector.Sources = append([]observability.Source(nil), valid.Routes[routeIndex].Selector.Sources...)
				candidate.Routes[routeIndex].Selector.Actions = append([]observability.ProducerKey(nil), valid.Routes[routeIndex].Selector.Actions...)
				candidate.Routes[routeIndex].Selector.EventNames = append([]observability.EventName(nil), valid.Routes[routeIndex].Selector.EventNames...)
				candidate.Routes[routeIndex].RedactionProfileByBucket = make(map[observability.Bucket]string, len(valid.Routes[routeIndex].RedactionProfileByBucket))
				for bucket, profile := range valid.Routes[routeIndex].RedactionProfileByBucket {
					candidate.Routes[routeIndex].RedactionProfileByBucket[bucket] = profile
				}
			}
			test.mutate(&candidate)
			if validManagedFallbackDestination(candidate, compileDestinationIndex(candidate)) {
				t.Fatal("malformed managed destination obtained the fallback capability")
			}
		})
	}
}

func TestManagedFallbackBuildsOnlyAfterDropAndNeverDuplicatesOrdinary(t *testing.T) {
	disabled, err := New(managedFallbackPlan(t, false))
	if err != nil {
		t.Fatal(err)
	}
	metadata := diagnosticMetadata()
	var disabledBuilds atomic.Int64
	fallback, err := disabled.EvaluateManagedLogFallback(metadata, func(admission Admission) (observability.Record, error) {
		disabledBuilds.Add(1)
		if admission != AdmissionOrdinary {
			t.Fatalf("fallback builder admission=%s", admission)
		}
		return newRecordNoTest(metadata, admission)
	})
	if err != nil {
		t.Fatal(err)
	}
	if disabledBuilds.Load() != 1 {
		t.Fatalf("fallback builder calls=%d", disabledBuilds.Load())
	}
	if _, ok := fallback.Record(); !ok {
		t.Fatal("managed fallback omitted the canonical record")
	}
	delivery, ok := fallback.Delivery()
	if !ok || delivery.DestinationName != config.ObservabilityV8ManagedAIDDestinationName ||
		delivery.RedactionProfile != "sensitive" || delivery.MandatoryFloor {
		t.Fatalf("managed fallback delivery=%+v present=%t", delivery, ok)
	}

	enabled, err := New(managedFallbackPlan(t, true))
	if err != nil {
		t.Fatal(err)
	}
	var enabledBuilds atomic.Int64
	ordinary, err := enabled.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		enabledBuilds.Add(1)
		return newRecordNoTest(metadata, admission)
	})
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.Admission() != AdmissionOrdinary || enabledBuilds.Load() != 1 ||
		!reflect.DeepEqual(deliveryNames(ordinary.Deliveries()), []string{
			config.ObservabilityV8LocalDestinationName,
			config.ObservabilityV8ManagedAIDDestinationName,
		}) {
		t.Fatalf("ordinary admission=%s builds=%d destinations=%v",
			ordinary.Admission(), enabledBuilds.Load(), deliveryNames(ordinary.Deliveries()))
	}
	second, err := enabled.EvaluateManagedLogFallback(metadata, func(Admission) (observability.Record, error) {
		enabledBuilds.Add(1)
		return observability.Record{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := second.Record(); ok || enabledBuilds.Load() != 1 {
		t.Fatalf("enabled ordinary route duplicated managed fallback; builds=%d", enabledBuilds.Load())
	}
}

func TestManagedFallbackMalformedMetadataAndRecordFailClosed(t *testing.T) {
	evaluator, err := New(managedFallbackPlan(t, false))
	if err != nil {
		t.Fatal(err)
	}
	metadata := diagnosticMetadata()

	invalidMetadata := metadata
	invalidMetadata.identity.Name = "future.unregistered"
	var invalidBuilds atomic.Int64
	if _, err := evaluator.EvaluateManagedLogFallback(invalidMetadata, func(Admission) (observability.Record, error) {
		invalidBuilds.Add(1)
		return observability.Record{}, nil
	}); err == nil || invalidBuilds.Load() != 0 {
		t.Fatalf("invalid metadata error=%v builder_calls=%d", err, invalidBuilds.Load())
	}

	inboundMetadata := metadata
	inboundMetadata.source = observability.SourceOTelReceiver
	var inboundBuilds atomic.Int64
	inbound, err := evaluator.EvaluateManagedLogFallback(inboundMetadata, func(Admission) (observability.Record, error) {
		inboundBuilds.Add(1)
		return observability.Record{}, nil
	})
	if err != nil || inboundBuilds.Load() != 0 {
		t.Fatalf("inbound fallback error=%v builder_calls=%d", err, inboundBuilds.Load())
	}
	if _, ok := inbound.Record(); ok {
		t.Fatal("inbound imported metadata obtained managed fallback work")
	}

	var mismatchedBuilds atomic.Int64
	if _, err := evaluator.EvaluateManagedLogFallback(metadata, func(admission Admission) (observability.Record, error) {
		mismatchedBuilds.Add(1)
		return newRecordNoTest(findingMetadata(), admission)
	}); err == nil || mismatchedBuilds.Load() != 1 {
		t.Fatalf("mismatched record error=%v builder_calls=%d", err, mismatchedBuilds.Load())
	}
}
