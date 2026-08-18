// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func TestAlertCanonicalEventFactoryDefaultsToRawLocalProjection(t *testing.T) {
	plan := alertPlan(t, nil)
	factory := alertFactory(t, plan, alertEngine(t), nil)
	input := alertComplianceInput("operator@example.test", observability.OutcomeApplied)

	record, projection, err := factory.BuildAlertCanonicalEvent(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if record.RecordID() != "alert-event-1" ||
		!record.Timestamp().Equal(time.Date(2026, 7, 3, 12, 0, 1, 0, time.UTC)) {
		t.Fatalf("builder-owned occurrence = %q at %s", record.RecordID(), record.Timestamp())
	}
	severity, present := record.Severity()
	if record.Bucket() != observability.BucketComplianceActivity ||
		record.EventName() != "alert.acknowledgement.requested" ||
		record.Signal() != observability.SignalLogs || record.Outcome() != observability.OutcomeApplied ||
		!record.Mandatory() || !present || severity != observability.SeverityInfo ||
		record.Source() != observability.SourceOperatorAPI ||
		record.Action() != "alert.acknowledgement.requested" {
		t.Fatalf("canonical record envelope = %#v", record)
	}
	provenance := record.Provenance()
	if provenance.Producer != alertCanonicalProducer || provenance.BinaryVersion != "v8-test" ||
		provenance.RegistrySchemaVersion != 1 || provenance.ConfigGeneration != 41 ||
		provenance.ConfigDigest != plan.Digest() {
		t.Fatalf("record provenance = %#v", provenance)
	}
	wantClasses := alertComplianceClasses(false)
	if got := record.FieldClasses(); !reflect.DeepEqual(got, wantClasses) {
		t.Fatalf("field classes = %#v, want %#v", got, wantClasses)
	}
	metadata := projection.Metadata()
	if metadata.RedactionProfile != string(redaction.ProfileNone) ||
		metadata.State != redaction.ProjectionStateRaw {
		t.Fatalf("default projection = %#v", metadata)
	}
	payload, err := projection.Payload().Object()
	if err != nil {
		t.Fatal(err)
	}
	if payload["actor"] != "operator@example.test" {
		t.Fatalf("raw default actor = %#v", payload["actor"])
	}
	if _, present := payload["command_fingerprint"]; present {
		t.Fatal("canonical alert projection exposed the protected command fingerprint")
	}
}

func TestAlertCanonicalEventFactoryGovernsActorButPreservesReplayControls(t *testing.T) {
	for _, test := range []struct {
		name        string
		profile     string
		wantPresent bool
	}{
		{name: "sensitive transforms", profile: "sensitive", wantPresent: true},
		{name: "strict removes", profile: "strict", wantPresent: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := alertPlan(t, &config.ObservabilityV8Source{
				Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
					observability.BucketComplianceActivity: {RedactionProfile: test.profile},
				},
			})
			factory := alertFactory(t, plan, alertEngine(t), nil)
			input := alertComplianceInput("operator@example.test", observability.OutcomeRejected)
			input.Body.(map[string]any)["rejection_reason"] = "stale_projection_version"

			record, projection, err := factory.BuildAlertCanonicalEvent(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			projected, err := projection.Payload().Object()
			if err != nil {
				t.Fatal(err)
			}
			actor, present := projected["actor"]
			if present != test.wantPresent {
				t.Fatalf("actor presence = %t, want %t; payload=%#v", present, test.wantPresent, projected)
			}
			if present && (actor == "operator@example.test" || actor == "") {
				t.Fatalf("sensitive projection retained raw actor: %#v", actor)
			}
			original := input.Body.(map[string]any)
			for key, value := range original {
				if key == "actor" {
					continue
				}
				if fmt.Sprint(projected[key]) != fmt.Sprint(value) {
					t.Errorf("control %s changed: got %#v, want %#v", key, projected[key], value)
				}
			}
			if class := record.FieldClasses()["/actor"]; class != observability.FieldClassContent {
				t.Fatalf("actor class = %q", class)
			}
			encoded, err := projection.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte("operator@example.test")) {
				t.Fatal("projection bytes leaked raw actor")
			}
		})
	}
}

func TestAlertCanonicalEventFactoryUsesBucketProfileBindingAndImmutableSnapshot(t *testing.T) {
	source := &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {RedactionProfile: "content"},
		},
	}
	plan := alertPlan(t, source)
	factory := alertFactory(t, plan, alertEngine(t), nil)

	// Neither mutating the source nor accessor snapshots can alter this graph.
	source.Buckets[observability.BucketComplianceActivity] = config.ObservabilityV8BucketPolicySource{RedactionProfile: "strict"}
	snapshot := plan.Snapshot()
	for index := range snapshot.Buckets {
		if snapshot.Buckets[index].Bucket == observability.BucketComplianceActivity {
			snapshot.Buckets[index].RedactionProfile = "none"
		}
	}

	_, compliance, err := factory.BuildAlertCanonicalEvent(
		context.Background(), alertComplianceInput("private actor", observability.OutcomeApplied),
	)
	if err != nil {
		t.Fatal(err)
	}
	if metadata := compliance.Metadata(); metadata.RedactionProfile != "content" ||
		metadata.State != redaction.ProjectionStateTransformed {
		t.Fatalf("snapshotted compliance profile = %#v", metadata)
	}
	_, health, err := factory.BuildAlertCanonicalEvent(context.Background(), alertHealthInput())
	if err != nil {
		t.Fatal(err)
	}
	if metadata := health.Metadata(); metadata.RedactionProfile != "none" ||
		metadata.State != redaction.ProjectionStateRaw {
		t.Fatalf("bucket-specific health profile = %#v", metadata)
	}
}

func TestAlertCanonicalEventFactoryBuildsBoundedHealthEvent(t *testing.T) {
	plan := alertPlan(t, nil)
	factory := alertFactory(t, plan, alertEngine(t), nil)
	record, projection, err := factory.BuildAlertCanonicalEvent(context.Background(), alertHealthInput())
	if err != nil {
		t.Fatal(err)
	}
	severity, present := record.Severity()
	if record.Bucket() != observability.BucketPlatformHealth ||
		record.EventName() != "subsystem.degraded" || record.Outcome() != observability.OutcomeFailed ||
		record.Source() != observability.SourceSystem || record.Action() != "subsystem.degraded" ||
		!record.Mandatory() || !present || severity != observability.SeverityInfo {
		t.Fatalf("health record envelope is invalid: %#v", record)
	}
	wantClasses := map[string]observability.FieldClass{
		"/target": observability.FieldClassMetadata, "/alert_id": observability.FieldClassMetadata,
		"/code": observability.FieldClassMetadata,
	}
	if !reflect.DeepEqual(record.FieldClasses(), wantClasses) {
		t.Fatalf("health field classes = %#v", record.FieldClasses())
	}
	payload, err := projection.Payload().Object()
	if err != nil {
		t.Fatal(err)
	}
	if payload["target"] != "alert-17" || payload["alert_id"] != "alert-17" || payload["code"] != "version_gap" {
		t.Fatalf("health payload = %#v", payload)
	}
}

func TestAlertCanonicalEventFactoryIntegratesWithStrictAuditProjection(t *testing.T) {
	plan := alertPlan(t, &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {RedactionProfile: "strict"},
		},
	})
	store, err := audit.NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine := alertEngine(t)
	binding, err := NewLocalProjectionBinding(plan, engine)
	if err != nil {
		t.Fatal(err)
	}
	history, err := audit.NewEventHistoryWriter(store, newPipelineCorrelationSigner(t), nil, binding)
	if err != nil {
		t.Fatal(err)
	}
	events := alertFactory(t, plan, engine, nil)
	writer, err := audit.NewAlertAcknowledgementWriter(store, history, events)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.LogEvent(audit.Event{
		ID: "strict-alert", Timestamp: time.Date(2026, 7, 3, 11, 59, 0, 0, time.UTC),
		Action: "scan-finding", Actor: "scanner", Details: "eligible test finding", Severity: "HIGH",
	}); err != nil {
		t.Fatal(err)
	}

	result, err := writer.ApplyAlertAcknowledgement(context.Background(), audit.AlertAcknowledgementCommand{
		OperationID: "strict-operation", AlertID: "strict-alert",
		Actor: "operator@example.test", Disposition: audit.AlertDispositionAcknowledged,
		ExpectedProjectionVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Actor != "redacted" || result.EventID == "" || result.CreatedAt.IsZero() {
		t.Fatalf("strict acknowledgement result = %#v", result)
	}
	projection, err := writer.ReconcileAlertAcknowledgement(context.Background(), "strict-alert")
	if err != nil {
		t.Fatal(err)
	}
	if projection.Actor != "redacted" || projection.SourceEventID != result.EventID {
		t.Fatalf("strict reconciled projection = %#v", projection)
	}
}

func TestAlertCanonicalEventFactoryRejectsInvalidDependenciesAndProjectionMismatch(t *testing.T) {
	plan := alertPlan(t, &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {RedactionProfile: "sensitive"},
		},
	})
	builder := alertBuilder(t, nil)
	provenance := alertProvenance()
	engine := alertEngine(t)

	for name, build := range map[string]func() error{
		"nil plan": func() error {
			_, err := NewAlertCanonicalEventFactory(nil, engine, builder, provenance)
			return err
		},
		"nil projector": func() error {
			_, err := NewAlertCanonicalEventFactory(plan, nil, builder, provenance)
			return err
		},
		"typed nil projector": func() error {
			var typedNil *redaction.Engine
			_, err := NewAlertCanonicalEventFactory(plan, typedNil, builder, provenance)
			return err
		},
		"nil builder": func() error {
			_, err := NewAlertCanonicalEventFactory(plan, engine, nil, provenance)
			return err
		},
		"digest mismatch": func() error {
			wrong := provenance
			wrong.ConfigDigest = strings.Repeat("0", 64)
			_, err := NewAlertCanonicalEventFactory(plan, engine, builder, wrong)
			return err
		},
		"invalid provenance": func() error {
			invalid := provenance
			invalid.BinaryVersion = ""
			_, err := NewAlertCanonicalEventFactory(plan, engine, builder, invalid)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := build(); err == nil {
				t.Fatal("invalid constructor input was accepted")
			}
		})
	}

	none, _ := redaction.BuiltInProfile(redaction.ProfileNone)
	mismatch := &alertFixedProfileProjector{engine: engine, profile: none}
	factory := alertFactory(t, plan, mismatch, nil)
	if _, _, err := factory.BuildAlertCanonicalEvent(
		context.Background(), alertComplianceInput("actor@example.test", observability.OutcomeApplied),
	); err == nil || !strings.Contains(err.Error(), "profile mismatch") {
		t.Fatalf("mismatched projector error = %v", err)
	}
}

func TestAlertCanonicalEventFactoryRejectsMalformedSemanticInputAndBody(t *testing.T) {
	var consumed atomic.Int64
	plan := alertPlan(t, nil)
	factory := alertFactory(t, plan, alertEngine(t), &consumed)
	base := alertComplianceInput("actor", observability.OutcomeApplied)

	tests := []struct {
		name   string
		mutate func(*audit.AlertCanonicalEventInput)
	}{
		{name: "empty alert", mutate: func(input *audit.AlertCanonicalEventInput) { input.AlertID = "" }},
		{name: "wrong bucket", mutate: func(input *audit.AlertCanonicalEventInput) { input.Bucket = observability.BucketSecurityFinding }},
		{name: "wrong event", mutate: func(input *audit.AlertCanonicalEventInput) { input.EventName = "config.change.applied" }},
		{name: "wrong outcome", mutate: func(input *audit.AlertCanonicalEventInput) { input.Outcome = observability.OutcomeFailed }},
		{name: "non object", mutate: func(input *audit.AlertCanonicalEventInput) { input.Body = []any{"secret"} }},
		{name: "extra field", mutate: func(input *audit.AlertCanonicalEventInput) { input.Body.(map[string]any)["secret_extra"] = "value" }},
		{name: "protected fingerprint field", mutate: func(input *audit.AlertCanonicalEventInput) {
			input.Body.(map[string]any)["command_fingerprint"] = "must-stay-in-receipt-ledger"
		}},
		{name: "missing control", mutate: func(input *audit.AlertCanonicalEventInput) { delete(input.Body.(map[string]any), "operation_id") }},
		{name: "target mismatch", mutate: func(input *audit.AlertCanonicalEventInput) { input.Body.(map[string]any)["target"] = "other" }},
		{name: "event disposition mismatch", mutate: func(input *audit.AlertCanonicalEventInput) {
			input.Body.(map[string]any)["requested_disposition"] = "dismissed"
		}},
		{name: "actor wrong type", mutate: func(input *audit.AlertCanonicalEventInput) { input.Body.(map[string]any)["actor"] = 7 }},
		{name: "negative version", mutate: func(input *audit.AlertCanonicalEventInput) {
			input.Body.(map[string]any)["projection_version_after"] = -1
		}},
		{name: "missing rejection reason", mutate: func(input *audit.AlertCanonicalEventInput) {
			input.Outcome = observability.OutcomeRejected
			input.Body.(map[string]any)["outcome"] = string(observability.OutcomeRejected)
			input.Body.(map[string]any)["projection_version_after"] = 0
		}},
		{name: "invalid applied transition", mutate: func(input *audit.AlertCanonicalEventInput) {
			input.Body.(map[string]any)["projection_version_after"] = 0
		}},
		{name: "observed before mismatch", mutate: func(input *audit.AlertCanonicalEventInput) {
			input.Body.(map[string]any)["observed_projection_version"] = 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneAlertInput(t, base)
			test.mutate(&input)
			if _, _, err := factory.BuildAlertCanonicalEvent(context.Background(), input); err == nil {
				t.Fatal("malformed alert event was accepted")
			}
		})
	}
	if consumed.Load() != 0 {
		t.Fatalf("malformed inputs consumed %d occurrence IDs", consumed.Load())
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := factory.BuildAlertCanonicalEvent(cancelled, base)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled build error = %v", err)
	}
	if _, _, err := factory.BuildAlertCanonicalEvent(nil, base); err == nil {
		t.Fatal("nil context was accepted")
	}
}

type alertFixedProfileProjector struct {
	engine  *redaction.Engine
	profile redaction.Profile
}

func (projector *alertFixedProfileProjector) Project(
	record observability.Record,
	_ redaction.Profile,
) (redaction.Projection, redaction.SafeReport, error) {
	return projector.engine.Project(record, projector.profile)
}

func alertFactory(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
	projector Projector,
	consumed *atomic.Int64,
) *AlertCanonicalEventFactory {
	t.Helper()
	factory, err := NewAlertCanonicalEventFactory(plan, projector, alertBuilder(t, consumed), alertProvenance())
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func alertBuilder(t *testing.T, consumed *atomic.Int64) *observability.RecordBuilder {
	t.Helper()
	if consumed == nil {
		consumed = &atomic.Int64{}
	}
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, 7, 3, 12, 0, int(consumed.Load()+1), 0, time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("alert-event-%d", consumed.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder
}

func alertPlan(t *testing.T, source *config.ObservabilityV8Source) *config.ObservabilityV8Plan {
	t.Helper()
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func alertEngine(t *testing.T) *redaction.Engine {
	t.Helper()
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func alertProvenance() observability.Provenance {
	return observability.Provenance{
		Producer: "caller_is_overridden", BinaryVersion: "v8-test",
		RegistrySchemaVersion: 1, ConfigGeneration: 41,
	}
}

func alertComplianceInput(actor string, outcome observability.Outcome) audit.AlertCanonicalEventInput {
	after := 1
	if outcome != observability.OutcomeApplied {
		after = 0
	}
	return audit.AlertCanonicalEventInput{
		Bucket: observability.BucketComplianceActivity, EventName: "alert.acknowledgement.requested",
		Outcome: outcome, AlertID: "alert-17",
		Body: map[string]any{
			"target": "alert-17", "operation_id": "operation-23", "target_event_id": "alert-17",
			"requested_disposition": "acknowledged", "actor": actor, "outcome": string(outcome),
			"expected_projection_version": 0, "observed_projection_version": 0,
			"projection_version_before": 0, "projection_version_after": after,
		},
	}
}

func alertHealthInput() audit.AlertCanonicalEventInput {
	return audit.AlertCanonicalEventInput{
		Bucket: observability.BucketPlatformHealth, EventName: "subsystem.degraded",
		Outcome: observability.OutcomeFailed, AlertID: "alert-17",
		Body: map[string]any{"target": "alert-17", "alert_id": "alert-17", "code": "version_gap"},
	}
}

func alertComplianceClasses(withRejection bool) map[string]observability.FieldClass {
	classes := map[string]observability.FieldClass{
		"/target": observability.FieldClassMetadata, "/operation_id": observability.FieldClassMetadata,
		"/target_event_id": observability.FieldClassMetadata, "/requested_disposition": observability.FieldClassMetadata,
		"/actor": observability.FieldClassContent, "/outcome": observability.FieldClassMetadata,
		"/expected_projection_version": observability.FieldClassMetadata,
		"/observed_projection_version": observability.FieldClassMetadata,
		"/projection_version_before":   observability.FieldClassMetadata,
		"/projection_version_after":    observability.FieldClassMetadata,
	}
	if withRejection {
		classes["/rejection_reason"] = observability.FieldClassMetadata
	}
	return classes
}

func cloneAlertInput(t *testing.T, input audit.AlertCanonicalEventInput) audit.AlertCanonicalEventInput {
	t.Helper()
	encoded, err := json.Marshal(input.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	input.Body = body
	return input
}
