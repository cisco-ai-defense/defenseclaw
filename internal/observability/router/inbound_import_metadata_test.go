// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestInboundImportedLogMetadataCannotAcquireFloorAndRoutesSQLiteFirst(t *testing.T) {
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	target, ok := catalog.Target("otlp.native.log.v8.log.config.change.applied.log.config.change.applied")
	if !ok {
		t.Fatal("missing config-change inbound target")
	}
	context, ok := target.ImportContext()
	if !ok {
		t.Fatal("config-change target has no import context")
	}
	severity := observability.SeverityInfo
	metadata, err := NewInboundImportedLogMetadata(target, context, &severity, "codex")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Identity() != (observability.EventIdentity{
		Bucket: observability.BucketComplianceActivity,
		Signal: observability.SignalLogs,
		Name:   observability.EventName(observability.TelemetryEventConfigChangeApplied),
	}) || metadata.Source() != observability.SourceOTelReceiver ||
		metadata.Connector() != "codex" || metadata.Action() != "" || metadata.mandatory {
		t.Fatalf("import metadata = %#v", metadata)
	}

	falseValue := false
	disabled := mustEvaluator(t, &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {
				Collect: config.ObservabilityV8CollectSource{Logs: &falseValue},
			},
		},
	})
	var builds atomic.Int64
	result, err := disabled.Evaluate(metadata, func(Admission) (observability.Record, error) {
		builds.Add(1)
		return observability.Record{}, errors.New("disabled imported log builder invoked")
	})
	if err != nil || result.Admission() != AdmissionDrop || builds.Load() != 0 ||
		len(result.Deliveries()) != 0 {
		t.Fatalf("disabled import result=%+v builds=%d err=%v", result, builds.Load(), err)
	}

	enabled := mustEvaluator(t, &config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "remote-a", Kind: config.ObservabilityV8DestinationConsole},
			{Name: "remote-b", Kind: config.ObservabilityV8DestinationConsole},
		},
	})
	result, err = enabled.Evaluate(metadata, func(admission Admission) (observability.Record, error) {
		if admission != AdmissionOrdinary {
			t.Fatalf("import builder admission = %s", admission)
		}
		return newRecordNoTest(metadata, admission)
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Admission() != AdmissionOrdinary {
		t.Fatalf("enabled import admission = %s", result.Admission())
	}
	if got, want := deliveryNames(result.Deliveries()), []string{"local-sqlite", "remote-a", "remote-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("delivery order = %v, want %v", got, want)
	}
	for _, delivery := range result.Deliveries() {
		if delivery.MandatoryFloor {
			t.Fatalf("imported log acquired floor delivery: %+v", delivery)
		}
	}
}

func TestInboundImportedLogMetadataRejectsInvalidContextAndSource(t *testing.T) {
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	target, _ := catalog.Target("otlp.codex.user_prompt.v1.log.model.request.log.model.request")
	context, _ := target.ImportContext()
	severity := observability.SeverityInfo
	if _, err := NewInboundImportedLogMetadata(
		observability.InboundTarget{}, context, &severity, "codex",
	); err == nil {
		t.Fatal("default target was accepted")
	}
	if _, err := NewInboundImportedLogMetadata(
		target, observability.InboundImportContext{}, &severity, "codex",
	); err == nil {
		t.Fatal("default context was accepted")
	}
	if _, err := NewInboundImportedLogMetadata(target, context, &severity, "claudecode"); err == nil {
		t.Fatal("source outside the generated match was accepted")
	}
	if _, err := NewInboundImportedLogMetadata(target, context, &severity, "any_authenticated"); err == nil {
		t.Fatal("source wildcard was accepted as a concrete source")
	}
	other, _ := catalog.Target("otlp.native.log.v8.log.diagnostic.message.log.diagnostic.message")
	otherContext, _ := other.ImportContext()
	if _, err := NewInboundImportedLogMetadata(target, otherContext, &severity, "codex"); err == nil {
		t.Fatal("foreign import context was accepted")
	}
}

func TestInboundImportedLogMetadataCoversEveryGeneratedLogTarget(t *testing.T) {
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	severity := observability.SeverityInfo
	count := 0
	for _, target := range catalog.Targets() {
		if target.Signal() != observability.SignalLogs || target.Role() != observability.InboundTargetImport {
			continue
		}
		count++
		context, ok := target.ImportContext()
		if !ok {
			t.Fatalf("target %s has no import context", target.ID())
		}
		match, ok := catalog.Match(target.MatchID())
		if !ok || len(match.Sources()) == 0 {
			t.Fatalf("target %s has no generated source policy", target.ID())
		}
		authenticatedSource := match.Sources()[0]
		if authenticatedSource == "any_authenticated" {
			authenticatedSource = "codex"
		}
		metadata, metadataErr := NewInboundImportedLogMetadata(
			target, context, &severity, authenticatedSource,
		)
		if metadataErr != nil {
			t.Fatalf("target %s source %s: %v", target.ID(), authenticatedSource, metadataErr)
		}
		if metadata.Identity() != (observability.EventIdentity{
			Bucket: target.Bucket(), Signal: observability.SignalLogs, Name: target.EventName(),
		}) || metadata.Source() != observability.SourceOTelReceiver ||
			metadata.Connector() != authenticatedSource || metadata.Action() != "" || metadata.mandatory {
			t.Fatalf("target %s metadata = %#v", target.ID(), metadata)
		}
	}
	if count == 0 {
		t.Fatal("imported log metadata target inventory is empty")
	}
}
