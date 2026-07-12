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
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type realLocalPipelineHarness struct {
	plan     *config.ObservabilityV8Plan
	engine   *redaction.Engine
	pipeline *LocalLogPipeline
	reader   *sql.DB
}

func newRealLocalPipelineHarness(
	t *testing.T,
	source *config.ObservabilityV8Source,
) realLocalPipelineHarness {
	t.Helper()

	plan, evaluator := mustPlanEvaluator(t, source)
	storePath := filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.NewStore(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if closeErr := store.Close(); closeErr != nil {
			t.Errorf("close audit store: %v", closeErr)
		}
	})
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	engine := mustEngine(t)
	binding, err := NewLocalProjectionBinding(plan, engine)
	if err != nil {
		t.Fatal(err)
	}
	history, err := audit.NewEventHistoryWriter(store, nil, nil, binding)
	if err != nil {
		t.Fatal(err)
	}
	localPipeline, err := NewLocalLogPipeline(
		plan,
		evaluator,
		engine,
		history,
		mustFailureFactory(t),
	)
	if err != nil {
		t.Fatal(err)
	}

	// This is intentionally a separately pooled connection rather than a test
	// accessor on audit.Store: the integration boundary is the durable SQLite
	// representation visible to independent local readers.
	reader, err := sql.Open("sqlite", storePath)
	if err != nil {
		t.Fatal(err)
	}
	reader.SetMaxOpenConns(1)
	reader.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if closeErr := reader.Close(); closeErr != nil {
			t.Errorf("close independent audit reader: %v", closeErr)
		}
	})
	if err := reader.PingContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	return realLocalPipelineHarness{
		plan: plan, engine: engine, pipeline: localPipeline, reader: reader,
	}
}

type expectedPersistedLog struct {
	record         observability.Record
	projectedBytes []byte
	profile        redaction.ProfileName
}

func TestRealLocalLogPipelinePersistsEveryCatalogBucketExactlyOnce(t *testing.T) {
	harness := newRealLocalPipelineHarness(t, nil)
	catalog, err := harness.plan.RedactionProfileCatalog()
	if err != nil {
		t.Fatal(err)
	}
	cases := catalogLogCases()
	if len(cases) != len(observability.Buckets()) {
		t.Fatalf("test cases = %d, catalog buckets = %d", len(cases), len(observability.Buckets()))
	}
	expected := make(map[string]expectedPersistedLog, len(cases))

	for index, test := range cases {
		recordID := fmt.Sprintf("real-sqlite-bucket-%02d", index)
		var built observability.Record
		var builds atomic.Int64
		outcome, processErr := harness.pipeline.Process(
			context.Background(),
			mustMetadata(t, test),
			func(admission router.Admission) (observability.Record, error) {
				builds.Add(1)
				var buildErr error
				built, buildErr = buildClassifiedLog(test, admission, recordID)
				return built, buildErr
			},
		)
		if processErr != nil {
			t.Fatalf("bucket %s: %v", test.bucket, processErr)
		}
		if builds.Load() != 1 || outcome.Admission() != router.AdmissionOrdinary ||
			!outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 ||
			len(outcome.OptionalFailures()) != 0 {
			t.Fatalf(
				"bucket %s outcome = admission:%v persisted:%t builds:%d work:%d failures:%d",
				test.bucket, outcome.Admission(), outcome.LocalPersisted(), builds.Load(),
				len(outcome.OptionalWork()), len(outcome.OptionalFailures()),
			)
		}

		profileName, resolveErr := harness.plan.ResolveLocalRedactionProfile(test.bucket)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		profile, ok := catalog.Resolve(profileName)
		if !ok {
			t.Fatalf("bucket %s local profile %s is absent", test.bucket, profileName)
		}
		projection, _, projectErr := harness.engine.Project(built, profile)
		if projectErr != nil {
			t.Fatal(projectErr)
		}
		projectedBytes, bytesErr := projection.Bytes()
		if bytesErr != nil {
			t.Fatal(bytesErr)
		}
		expected[recordID] = expectedPersistedLog{
			record: built, projectedBytes: projectedBytes, profile: profileName,
		}
	}

	assertPersistedLogsExactlyOnce(t, harness.reader, expected)
}

type mandatoryFloorIntegrationCase struct {
	name      string
	factField string
	log       classifiedLogCase
}

func TestRealLocalLogPipelinePersistsEveryMandatoryFactWhenCollectionIsDisabled(t *testing.T) {
	falseValue := false
	source := &config.ObservabilityV8Source{
		Defaults: config.ObservabilityV8BucketPolicySource{
			Collect: config.ObservabilityV8CollectSource{Logs: &falseValue},
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "optional-console-a", Kind: config.ObservabilityV8DestinationConsole},
			{Name: "optional-console-b", Kind: config.ObservabilityV8DestinationConsole},
		},
	}
	harness := newRealLocalPipelineHarness(t, source)
	catalog, err := harness.plan.RedactionProfileCatalog()
	if err != nil {
		t.Fatal(err)
	}
	cases := mandatoryFloorIntegrationCases()
	assertMandatoryFactCoverage(t, cases)
	expected := make(map[string]expectedPersistedLog, len(cases))

	for index, test := range cases {
		policy, ok := harness.plan.Bucket(test.log.bucket)
		if !ok || policy.Collect.Logs {
			t.Fatalf("%s owning bucket %s logs are not disabled", test.name, test.log.bucket)
		}
		recordID := fmt.Sprintf("real-sqlite-floor-%02d", index)
		var built observability.Record
		var builds atomic.Int64
		outcome, processErr := harness.pipeline.Process(
			context.Background(),
			mustMetadata(t, test.log),
			func(admission router.Admission) (observability.Record, error) {
				builds.Add(1)
				var buildErr error
				built, buildErr = buildClassifiedLog(test.log, admission, recordID)
				return built, buildErr
			},
		)
		if processErr != nil {
			t.Fatalf("%s: %v", test.name, processErr)
		}
		if builds.Load() != 1 || outcome.Admission() != router.AdmissionFloor ||
			!outcome.LocalPersisted() || !built.Mandatory() || !built.IsFloorOnly() ||
			len(outcome.OptionalWork()) != 0 || len(outcome.OptionalFailures()) != 0 {
			t.Fatalf(
				"%s outcome = admission:%v persisted:%t builds:%d mandatory:%t floor:%t work:%d failures:%d",
				test.name, outcome.Admission(), outcome.LocalPersisted(), builds.Load(),
				built.Mandatory(), built.IsFloorOnly(), len(outcome.OptionalWork()),
				len(outcome.OptionalFailures()),
			)
		}

		profileName, resolveErr := harness.plan.ResolveLocalRedactionProfile(test.log.bucket)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		profile, found := catalog.Resolve(profileName)
		if !found {
			t.Fatalf("%s local profile %s is absent", test.name, profileName)
		}
		projection, _, projectErr := harness.engine.Project(built, profile)
		if projectErr != nil {
			t.Fatal(projectErr)
		}
		projectedBytes, bytesErr := projection.Bytes()
		if bytesErr != nil {
			t.Fatal(bytesErr)
		}
		expected[recordID] = expectedPersistedLog{
			record: built, projectedBytes: projectedBytes, profile: profileName,
		}
	}

	assertPersistedLogsExactlyOnce(t, harness.reader, expected)
}

func mandatoryFloorIntegrationCases() []mandatoryFloorIntegrationCase {
	makeCase := func(
		name string,
		factField string,
		bucket observability.Bucket,
		key observability.ProducerKey,
		event observability.EventName,
		facts observability.MandatoryFacts,
	) mandatoryFloorIntegrationCase {
		return mandatoryFloorIntegrationCase{
			name: name, factField: factField,
			log: classifiedLogCase{
				bucket: bucket, kind: observability.ProducerAuditAction, key: key,
				context: observability.ClassificationContext{
					EventName: event, RawSeverity: "INFO", MandatoryFacts: facts,
				},
			},
		}
	}
	return []mandatoryFloorIntegrationCase{
		makeCase(
			"control plane mutation", "ControlPlaneMutation",
			observability.BucketComplianceActivity, "config-update", "config.change.applied",
			observability.MandatoryFacts{ControlPlaneMutation: true},
		),
		makeCase(
			"approval resolution", "ApprovalResolution",
			observability.BucketComplianceActivity, "approval-granted", "approval.resolved",
			observability.MandatoryFacts{ApprovalResolution: true},
		),
		makeCase(
			"alert mutation", "AlertMutation",
			observability.BucketComplianceActivity, "acknowledge-alerts", "alert.acknowledgement.requested",
			observability.MandatoryFacts{AlertMutation: true},
		),
		makeCase(
			"protected-boundary authentication failure", "ProtectedBoundaryAuthFailure",
			observability.BucketComplianceActivity, "api-auth-failure", "authentication.failed",
			observability.MandatoryFacts{ProtectedBoundaryAuthFailure: true},
		),
		makeCase(
			"enforced outcome", "EnforcedOutcome",
			observability.BucketNetworkEgress, "network-egress-blocked", "egress.blocked",
			observability.MandatoryFacts{EnforcedOutcome: true},
		),
		makeCase(
			"enforcement state change", "EnforcementStateChange",
			observability.BucketEnforcementAction, "quarantine", "enforcement.quarantine.applied",
			observability.MandatoryFacts{EnforcementStateChange: true},
		),
		{
			name: "schema validation failure", factField: "SchemaValidationFailure",
			log: classifiedLogCase{
				bucket: observability.BucketPlatformHealth,
				kind:   observability.ProducerGatewayEvent,
				key:    "error",
				context: observability.ClassificationContext{
					Bucket: observability.BucketPlatformHealth, EventName: "schema.validation_failed", RawSeverity: "ERROR",
					MandatoryFacts: observability.MandatoryFacts{SchemaValidationFailure: true},
				},
			},
		},
		makeCase(
			"SQLite failure", "SQLiteFailure",
			observability.BucketPlatformHealth, "sink-failure", "sqlite.write_failed",
			observability.MandatoryFacts{SQLiteFailure: true},
		),
		makeCase(
			"exporter initialization failure", "ExporterInitializationFailure",
			observability.BucketPlatformHealth, "sink-failure", "destination.export_failed",
			observability.MandatoryFacts{ExporterInitializationFailure: true},
		),
		makeCase(
			"durable health transition", "DurableHealthTransition",
			observability.BucketPlatformHealth, "gateway-ready", "subsystem.ready",
			observability.MandatoryFacts{DurableHealthTransition: true},
		),
		{
			name: "destination test activity", factField: "DestinationTestActivity",
			log: classifiedLogCase{
				bucket: observability.BucketComplianceActivity,
				kind:   observability.ProducerGatewayEvent,
				key:    "destination_test",
				context: observability.ClassificationContext{
					Bucket:    observability.BucketComplianceActivity,
					EventName: "destination.test.attempted", RawSeverity: "INFO",
					MandatoryFacts: observability.MandatoryFacts{DestinationTestActivity: true},
				},
			},
		},
	}
}

func assertMandatoryFactCoverage(t *testing.T, cases []mandatoryFloorIntegrationCase) {
	t.Helper()
	covered := make(map[string]struct{}, len(cases))
	for _, test := range cases {
		if _, duplicate := covered[test.factField]; duplicate {
			t.Fatalf("mandatory fact %s has duplicate integration coverage", test.factField)
		}
		covered[test.factField] = struct{}{}
	}
	factsType := reflect.TypeOf(observability.MandatoryFacts{})
	for index := 0; index < factsType.NumField(); index++ {
		field := factsType.Field(index)
		if _, ok := covered[field.Name]; !ok {
			t.Errorf("mandatory fact %s has no real-pipeline integration case", field.Name)
		}
	}
	if len(covered) != factsType.NumField() {
		t.Fatalf("covered mandatory facts = %d, registry fact fields = %d", len(covered), factsType.NumField())
	}
}

func assertPersistedLogsExactlyOnce(
	t *testing.T,
	reader *sql.DB,
	expected map[string]expectedPersistedLog,
) {
	t.Helper()
	var total int
	if err := reader.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_events`).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != len(expected) {
		t.Fatalf("audit_events rows = %d, want %d", total, len(expected))
	}

	for recordID, want := range expected {
		var (
			count           int
			bucket          string
			eventName       string
			profile         string
			projectedRecord []byte
		)
		if err := reader.QueryRowContext(context.Background(), `
			SELECT COUNT(*), COALESCE(bucket,''), COALESCE(event_name,''),
			       COALESCE(redaction_profile,''), COALESCE(projected_record_json,'')
			FROM audit_events
			WHERE id = ?`, recordID).Scan(
			&count, &bucket, &eventName, &profile, &projectedRecord,
		); err != nil {
			t.Fatalf("read persisted record %s: %v", recordID, err)
		}
		if count != 1 {
			t.Errorf("record %s persisted %d times, want exactly once", recordID, count)
		}
		if bucket != string(want.record.Bucket()) {
			t.Errorf("record %s bucket = %s, want %s", recordID, bucket, want.record.Bucket())
		}
		if eventName != string(want.record.EventName()) {
			t.Errorf("record %s event = %s, want %s", recordID, eventName, want.record.EventName())
		}
		if profile != string(want.profile) {
			t.Errorf("record %s redaction profile = %s, want %s", recordID, profile, want.profile)
		}
		if !bytes.Equal(projectedRecord, want.projectedBytes) {
			t.Errorf("record %s projected bytes differ from the real engine projection", recordID)
		}
	}
}
