// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

func managedFallbackPipeline(
	t *testing.T,
	collectLogs bool,
) (*LocalLogPipeline, *recordingAppender) {
	t.Helper()
	base, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Defaults: config.ObservabilityV8BucketPolicySource{
			Collect: config.ObservabilityV8CollectSource{Logs: &collectLogs},
		},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "operator-console", Kind: config.ObservabilityV8DestinationConsole,
		}},
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
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	return mustPipelineFromPlan(t, plan, evaluator, mustEngine(t))
}

func TestManagedLogFallbackProjectsOnlyGeneratedManagedDestination(t *testing.T) {
	localPipeline, appender := managedFallbackPipeline(t, false)
	test := findCatalogLogCase(t, observability.BucketDiagnostic)
	metadata := mustMetadata(t, test)
	const content = "managed-only-user@example.test"
	var builds atomic.Int64
	builder := func(admission router.Admission) (observability.Record, error) {
		builds.Add(1)
		return buildClassifiedLogWithContent(test, admission, "managed-only-record", content)
	}

	ordinary, err := localPipeline.Process(context.Background(), metadata, builder)
	if err != nil {
		t.Fatal(err)
	}
	if ordinary.Admission() != router.AdmissionDrop || ordinary.LocalPersisted() ||
		ordinary.ManagedOnly() || builds.Load() != 0 || len(appender.snapshot()) != 0 {
		t.Fatalf("ordinary drop=%s persisted=%t managed=%t builds=%d appends=%d",
			ordinary.Admission(), ordinary.LocalPersisted(), ordinary.ManagedOnly(),
			builds.Load(), len(appender.snapshot()))
	}

	fallback, err := localPipeline.ProcessManagedLogFallback(context.Background(), metadata, builder)
	if err != nil {
		t.Fatal(err)
	}
	if fallback.Admission() != router.AdmissionDrop || fallback.LocalPersisted() ||
		!fallback.ManagedOnly() || builds.Load() != 1 || len(appender.snapshot()) != 0 ||
		len(fallback.OptionalFailures()) != 0 {
		t.Fatalf("fallback drop=%s persisted=%t managed=%t builds=%d appends=%d failures=%d",
			fallback.Admission(), fallback.LocalPersisted(), fallback.ManagedOnly(),
			builds.Load(), len(appender.snapshot()), len(fallback.OptionalFailures()))
	}
	work := fallback.OptionalWork()
	if len(work) != 1 {
		t.Fatalf("managed work=%d, want one", len(work))
	}
	delivery := work[0].Delivery()
	if delivery.DestinationName != config.ObservabilityV8ManagedAIDDestinationName ||
		delivery.DestinationKind != config.ObservabilityV8DestinationOTLP ||
		delivery.RedactionProfile != string(redaction.ProfileSensitive) || delivery.MandatoryFloor {
		t.Fatalf("managed delivery=%+v", delivery)
	}
	projected, err := work[0].Projection().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(projected, []byte(content)) ||
		work[0].Projection().Metadata().RedactionProfile != string(redaction.ProfileSensitive) {
		t.Fatal("managed fallback did not apply the central sensitive projection")
	}
}

func TestManagedLogFallbackAppliesRequestSinkPolicy(t *testing.T) {
	localPipeline, _ := managedFallbackPipeline(t, false)
	test := findCatalogLogCase(t, observability.BucketDiagnostic)
	metadata := mustMetadata(t, test)
	tests := []struct {
		name        string
		policy      legacyredaction.SinkPolicy
		profile     redaction.ProfileName
		wantContent bool
	}{
		{name: "raw", policy: legacyredaction.SinkPolicyRaw, profile: redaction.ProfileNone, wantContent: true},
		{name: "redact", policy: legacyredaction.SinkPolicyRedact, profile: redaction.ProfileSensitive},
	}
	for _, testPolicy := range tests {
		t.Run(testPolicy.name, func(t *testing.T) {
			content := "cloud-policy-" + testPolicy.name + "@example.test"
			ctx := legacyredaction.WithSinkPolicy(context.Background(), testPolicy.policy)
			outcome, err := localPipeline.ProcessManagedLogFallback(ctx, metadata, func(admission router.Admission) (observability.Record, error) {
				return buildClassifiedLogWithContent(
					test, admission, "managed-policy-"+testPolicy.name, content,
				)
			})
			if err != nil {
				t.Fatal(err)
			}
			work := outcome.OptionalWork()
			if len(work) != 1 || !outcome.ManagedOnly() {
				t.Fatalf("managed policy work=%d managed=%t", len(work), outcome.ManagedOnly())
			}
			projected, err := work[0].Projection().Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if got := bytes.Contains(projected, []byte(content)); got != testPolicy.wantContent ||
				work[0].Projection().Metadata().RedactionProfile != string(testPolicy.profile) {
				t.Fatalf("request SinkPolicy projection profile=%q contains_content=%t",
					work[0].Projection().Metadata().RedactionProfile, got)
			}
		})
	}
}

func TestManagedLogFallbackWithoutManagedPlanRemainsLazy(t *testing.T) {
	falseValue := false
	localPipeline, appender := mustPipeline(t, &config.ObservabilityV8Source{
		Defaults: config.ObservabilityV8BucketPolicySource{
			Collect: config.ObservabilityV8CollectSource{Logs: &falseValue},
		},
	}, mustEngine(t))
	test := findCatalogLogCase(t, observability.BucketDiagnostic)
	var builds atomic.Int64
	outcome, err := localPipeline.ProcessManagedLogFallback(
		context.Background(), mustMetadata(t, test),
		func(router.Admission) (observability.Record, error) {
			builds.Add(1)
			return observability.Record{}, nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.Admission() != router.AdmissionDrop || outcome.ManagedOnly() ||
		outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 ||
		builds.Load() != 0 || len(appender.snapshot()) != 0 {
		t.Fatalf("non-managed fallback=%+v builds=%d appends=%d",
			outcome, builds.Load(), len(appender.snapshot()))
	}
}
