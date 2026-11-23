// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestManagedManifestGuardDisabledAllocatesNothing(t *testing.T) {
	ctx := context.Background()
	if allocations := testing.AllocsPerRun(100, func() {
		if !managedManifestGenerationMatches(ctx, 1) || !managedManifestProjectionMatches(ctx, pipeline.LocalLogOutcome{}) {
			t.Fatal("disabled guard rejected ordinary event")
		}
	}); allocations != 0 {
		t.Fatalf("disabled guard allocations=%v", allocations)
	}
}

func BenchmarkManagedManifestGuardDisabled(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for range b.N {
		managedManifestGenerationMatches(ctx, 1)
		managedManifestProjectionMatches(ctx, pipeline.LocalLogOutcome{})
	}
}

func TestManagedManifestGuardRejectsBeforeLocalAppend(t *testing.T) {
	for _, collect := range []bool{false, true} {
		for _, matches := range []bool{false, true} {
			t.Run(fmt.Sprintf("collect=%t/matches=%t", collect, matches), func(t *testing.T) {
				deps := newRuntimeTestDependencies(t)
				base := runtimeTestPlan(t, deps.storePath, deps.judgePath, 90, func(source *config.ObservabilityV8Source) {
					source.Defaults.Collect.Logs = &collect
					source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{observability.BucketAIDiscovery: {Collect: config.ObservabilityV8CollectSource{Logs: &collect}}}
					source.Destinations = []config.ObservabilityV8DestinationSource{runtimeConsoleDestination("operator-console", "none", 0)}
				})
				plan, planErr := config.WithObservabilityV8ManagedAIDDestination(base, config.ObservabilityV8ManagedAIDOptions{DeploymentMode: "managed_enterprise", Endpoint: "https://guard.example.test"})
				if planErr != nil {
					t.Fatal(planErr)
				}
				adapters := newManagedFallbackAdapters()
				runtime := newManagedFallbackRuntime(t, deps, plan, adapters)
				const id = "guarded-manifest-record"
				const text = "safe synthetic manifest\n"
				rawHash := sha256.Sum256([]byte(text))
				manifestHash := "sha256:" + hex.EncodeToString(rawHash[:])

				builds := 0
				builder := func(snapshot EmitContext, _ router.Admission) (observability.Record, error) {
					builds++
					rb, err := observability.NewFamilyBuilder(observability.ClockFunc(func() time.Time { return time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC) }), observability.OccurrenceIDGeneratorFunc(func() (string, error) { return id, nil }))
					if err != nil {
						return observability.Record{}, err
					}
					record, buildErr := rb.BuildLogAIComponentObserved(observability.LogAIComponentObservedInput{
						Envelope: observability.FamilyEnvelopeInput{Source: observability.SourceSystem, Action: "ai_discovery", Provenance: observability.FamilyProvenanceInput{Producer: "managed_manifest_guard_test", BinaryVersion: "test", ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest()}},
						Severity: observability.Present(observability.SeverityInfo), LogLevel: observability.Present(observability.LogLevelInfo),
						DefenseClawAIComponentID: "synthetic-skill", DefenseClawAIComponentType: "skill",
						DefenseClawInventorySkillManifestHash:  observability.Present(manifestHash),
						DefenseClawInventorySkillManifest:      observability.Present(text),
						DefenseClawInventorySkillManifestPart:  observability.Present(int64(1)),
						DefenseClawInventorySkillManifestParts: observability.Present(int64(1)),
					})
					if buildErr != nil {
						t.Fatalf("synthetic fixture build: %v", buildErr)
					}
					return record, nil
				}
				metadata, metadataErr := router.NewClassifiedLogMetadata(observability.ProducerGatewayEvent, "ai_discovery", observability.ClassificationContext{Bucket: observability.BucketAIDiscovery, EventName: "ai_component.observed", RawSeverity: "INFO"}, observability.SourceSystem, "", "ai_discovery")
				if metadataErr != nil {
					t.Fatal(metadataErr)
				}
				preview, previewErr := runtime.ProjectManagedLog(t.Context(), metadata, builder)
				if previewErr != nil {
					t.Fatal(previewErr)
				}
				var projected struct {
					Body map[string]json.RawMessage `json:"body"`
				}
				work := preview.OptionalWork()
				if len(work) != 1 {
					t.Fatalf("preview work=%d", len(work))
				}
				encoded, encodeErr := work[0].Projection().Bytes()
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				if err := json.Unmarshal(encoded, &projected); err != nil {
					t.Fatal(err)
				}
				var projectedText string
				if err := json.Unmarshal(projected.Body["defenseclaw.inventory.skill.manifest"], &projectedText); err != nil {
					t.Fatal("synthetic manifest projection missing")
				}
				sum := sha256.Sum256([]byte(projectedText))
				expected := "sha256:" + hex.EncodeToString(sum[:])
				if !matches {
					other := sha256.Sum256([]byte("different synthetic projection"))
					expected = "sha256:" + hex.EncodeToString(other[:])
				}
				ctx := WithManagedManifestDigest(t.Context(), manifestHash, expected, 1, 1)
				builds = 0
				before := managedPreviewEnqueueCounts(t, runtime)
				outcome, err := runtime.Emit(ctx, metadata, builder)
				if !matches {
					if err == nil {
						t.Fatal("mismatched projection was accepted")
					}
					if count := countRuntimeRecord(t, deps, id); count != 0 {
						t.Fatalf("mismatch appended %d local rows", count)
					}
					if outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 {
						t.Fatal("mismatch returned persisted or exportable work")
					}
					if after := managedPreviewEnqueueCounts(t, runtime); !reflect.DeepEqual(before, after) {
						t.Fatalf("mismatch enqueued work: before=%v after=%v", before, after)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				wantRows := 0
				if preview.Admission() != router.AdmissionDrop && !preview.ManagedOnly() {
					wantRows = 1
				}
				if count := countRuntimeRecord(t, deps, id); count != wantRows {
					t.Fatalf("matching projection local rows=%d want=%d", count, wantRows)
				}
				if builds != 1 {
					t.Fatalf("guard rebuilt occurrence %d times", builds)
				}
				if !managedManifestProjectionMatches(ctx, outcome) {
					t.Fatal("returned managed work differs from checked projection")
				}
				after := managedPreviewEnqueueCounts(t, runtime)
				if after[config.ObservabilityV8ManagedAIDDestinationName][0] != before[config.ObservabilityV8ManagedAIDDestinationName][0]+1 {
					t.Fatalf("matching projection enqueue counters=%v", after)
				}
				wantOperator := before["operator-console"][0]
				for _, work := range outcome.OptionalWork() {
					if work.Delivery().DestinationName == "operator-console" {
						wantOperator++
					}
				}
				if after["operator-console"][0] != wantOperator {
					t.Fatalf("operator fanout changed: before=%v after=%v", before, after)
				}
			})
		}
	}
}
