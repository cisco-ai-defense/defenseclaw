// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

func TestRuntimeReadsLifecycleHistoryThroughActiveGenerationWriter(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := redaction.LoadOrCreateCorrelationKey(keyDir)
	if redaction.IsKeyStoreError(err, redaction.KeyStoreErrorUnsupported) {
		t.Skip("correlation-key custody is unavailable on this platform")
	}
	if err != nil {
		t.Fatal(err)
	}
	signer, err := pipeline.NewCorrelationKeyProjectionIntegritySigner(key)
	if err != nil {
		t.Fatal(err)
	}
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	options := dependencies.options()
	options.Signer = signer
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close runtime: %v", err)
		}
	})

	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("lifecycle"),
		observability.ClassificationContext{
			Bucket: observability.BucketAgentLifecycle, EventName: "turn_start", RawSeverity: "INFO",
		},
		observability.SourceConnector,
		"codex",
		observability.ProducerKey("lifecycle"),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runtime.Emit(t.Context(), metadata, func(snapshot EmitContext, _ router.Admission) (observability.Record, error) {
		severity := observability.SeverityInfo
		return observability.NewRecord(observability.RecordInput{
			Timestamp: time.Date(2026, 7, 10, 12, 0, 0, 1, time.UTC),
			RecordID:  "runtime-lifecycle-history",
			Identity: observability.EventIdentity{
				Bucket: observability.BucketAgentLifecycle, Signal: observability.SignalLogs, Name: "turn_start",
			},
			Severity: &severity, LogLevel: observability.LogLevelInfo,
			Source: observability.SourceConnector, Connector: "codex", Action: "lifecycle", Phase: "planning",
			Outcome: observability.OutcomeAttempted,
			Correlation: observability.Correlation{
				SessionID: "session-child", AgentID: "agent-child", ConnectorID: "codex",
			},
			Provenance: observability.Provenance{
				Producer: "gateway.hook.lifecycle", BinaryVersion: "v8-test",
				RegistrySchemaVersion: 1, ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
			},
			Body: map[string]any{
				"gen_ai.conversation.id":               "session-child",
				"gen_ai.agent.id":                      "agent-child",
				"defenseclaw.agent.root.id":            "agent-root",
				"defenseclaw.agent.parent.id":          "agent-root",
				"defenseclaw.agent.lineage.provenance": "reported",
				"defenseclaw.session.root.id":          "session-root",
				"defenseclaw.session.parent.id":        "session-root",
				"defenseclaw.agent.lifecycle.id":       "lifecycle-child",
				"defenseclaw.agent.execution.id":       "execution-child",
				"defenseclaw.agent.depth":              int64(1),
				"defenseclaw.agent.lifecycle.event":    "turn_start",
				"defenseclaw.agent.lifecycle.state":    "active",
				"defenseclaw.agent.phase":              "planning",
				"defenseclaw.agent.sequence":           int64(7),
			},
			FieldClasses: map[string]observability.FieldClass{
				"/gen_ai.conversation.id":               observability.FieldClassIdentifier,
				"/gen_ai.agent.id":                      observability.FieldClassIdentifier,
				"/defenseclaw.agent.root.id":            observability.FieldClassIdentifier,
				"/defenseclaw.agent.parent.id":          observability.FieldClassIdentifier,
				"/defenseclaw.agent.lineage.provenance": observability.FieldClassMetadata,
				"/defenseclaw.session.root.id":          observability.FieldClassIdentifier,
				"/defenseclaw.session.parent.id":        observability.FieldClassIdentifier,
				"/defenseclaw.agent.lifecycle.id":       observability.FieldClassIdentifier,
				"/defenseclaw.agent.execution.id":       observability.FieldClassIdentifier,
				"/defenseclaw.agent.depth":              observability.FieldClassMetadata,
				"/defenseclaw.agent.lifecycle.event":    observability.FieldClassMetadata,
				"/defenseclaw.agent.lifecycle.state":    observability.FieldClassMetadata,
				"/defenseclaw.agent.phase":              observability.FieldClassMetadata,
				"/defenseclaw.agent.sequence":           observability.FieldClassMetadata,
			},
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	got, found, err := runtime.LatestLifecycleProjection(t.Context(), audit.LifecycleProjectionQuery{
		Connector: "codex", SessionID: "session-child", AgentID: "agent-child",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found || got.RecordID != "runtime-lifecycle-history" || got.ExecutionID != "execution-child" ||
		got.Sequence != 7 {
		t.Fatalf("runtime lifecycle projection found=%t value=%#v", found, got)
	}
}
