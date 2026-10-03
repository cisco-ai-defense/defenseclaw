// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// GAP-1635: alert acknowledgement and dismissal records are appended to SQLite
// inside the alert transaction, so ProjectCommitted must hand them to the
// optional destinations that ordinary routing selects, without a second local
// append.
func TestProjectCommittedRoutesAlertComplianceRecordToOptionalDestinations(t *testing.T) {
	source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "siem", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalLogs},
			Buckets: []observability.Bucket{"*"}, RedactionProfile: "sensitive",
		}},
	}}
	plan, evaluator := mustPlanEvaluator(t, source)
	engine := alertEngine(t)
	factory := alertFactory(t, plan, engine, nil)
	pipeline, appender := mustPipelineFromPlan(t, plan, evaluator, engine)

	for _, input := range []struct {
		name        string
		event       observability.EventName
		disposition string
	}{
		{"acknowledge", "alert.acknowledgement.requested", "acknowledged"},
		{"dismiss", "alert.dismissal.requested", "dismissed"},
	} {
		request := alertComplianceInput("operator@example.test", observability.OutcomeApplied)
		request.EventName = input.event
		request.Body.(map[string]any)["requested_disposition"] = input.disposition
		record, _, err := factory.BuildAlertCanonicalEvent(context.Background(), request)
		if err != nil {
			t.Fatalf("%s: %v", input.name, err)
		}
		outcome := pipeline.ProjectCommitted(context.Background(), record)
		work := outcome.OptionalWork()
		if outcome.Admission() != router.AdmissionOrdinary || !outcome.LocalPersisted() ||
			len(work) != 1 || len(outcome.OptionalFailures()) != 0 {
			t.Fatalf("%s: admission=%s persisted=%t work=%d failures=%d", input.name,
				outcome.Admission(), outcome.LocalPersisted(), len(work), len(outcome.OptionalFailures()))
		}
		if work[0].Delivery().DestinationName != "siem" || work[0].Identity().EventName() != input.event ||
			work[0].Identity().Bucket() != observability.BucketComplianceActivity {
			t.Fatalf("%s: delivery=%+v event=%s", input.name, work[0].Delivery(), work[0].Identity().EventName())
		}
	}
	if calls := appender.snapshot(); len(calls) != 0 {
		t.Fatalf("committed records were appended locally again: %d", len(calls))
	}
}

func TestProjectCommittedKeepsUncollectedComplianceLogsLocal(t *testing.T) {
	disabled := false
	source := &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {Collect: config.ObservabilityV8CollectSource{Logs: &disabled}},
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "siem", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalLogs},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "sensitive",
			}},
		},
	}
	plan, evaluator := mustPlanEvaluator(t, source)
	engine := alertEngine(t)
	factory := alertFactory(t, plan, engine, nil)
	pipeline, _ := mustPipelineFromPlan(t, plan, evaluator, engine)
	record, _, err := factory.BuildAlertCanonicalEvent(
		context.Background(), alertComplianceInput("operator@example.test", observability.OutcomeApplied),
	)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := pipeline.ProjectCommitted(context.Background(), record); len(outcome.OptionalWork()) != 0 {
		t.Fatalf("uncollected compliance log was exported: %d", len(outcome.OptionalWork()))
	}
}
