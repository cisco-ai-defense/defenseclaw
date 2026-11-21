// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

// The final drain of a generation keeps the row cap: the rows it writes are
// trimmed before the writer ends, not left past the cap until the next run
// of the store (GAP-0072). The writer picks the queue or the stop signal at
// random when both are ready, so the run repeats; one run past the cap fails.
func TestRejectedRecordFinalDrainKeepsTheCap(t *testing.T) {
	for attempt := 0; attempt < 4; attempt++ {
		dependencies := newRuntimeTestDependencies(t)
		full := make([]audit.RejectedRecordRow, 0, audit.RejectedRecordMaxBatch)
		for len(full) < 10 {
			full = append(full, audit.RejectedRecordRow{Signal: "logs", ReasonCode: "constraint_violation"})
		}
		for written := 0; written < audit.RejectedRecordsMinRows; written += len(full) {
			if err := dependencies.store.InsertRejectedRecords(t.Context(), full, audit.RejectedRecordsMinRows); err != nil {
				t.Fatal(err)
			}
		}
		writer := idleRejectedWriter(&rejectedRecordFactory{store: dependencies.store, engine: dependencies.engine},
			audit.RejectedRecordsMinRows, 4*audit.RejectedRecordMaxBatch)
		writer.trimPause = time.Millisecond
		for len(writer.queue) < cap(writer.queue) {
			writer.queue <- observability.RejectedRecord{
				Signal: observability.SignalLogs, Bucket: observability.BucketComplianceActivity,
				Reason: observability.FamilyBuildConstraint, Body: map[string]any{},
				FieldClasses: map[string]observability.FieldClass{},
			}
		}
		close(writer.stop)
		writer.run()
		count, err := dependencies.store.CountRejectedRecords(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if count != audit.RejectedRecordsMinRows {
			t.Fatalf("attempt %d: rows after the final drain=%d, want the cap %d", attempt, count, audit.RejectedRecordsMinRows)
		}
	}
}

// A bucket whose local profile is a custom profile that neither keeps less
// than sensitive nor more in every class gets the merged profile
// (redaction.StricterProfile), named for the bucket: per class, the stricter
// mode of the two (GAP-0072).
func TestRejectedRecordMergesACustomLocalProfileWithSensitive(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	keep := true
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, func(source *config.ObservabilityV8Source) {
		source.Local.KeepRejectedRecords = &keep
		source.RedactionProfiles = map[string]config.ObservabilityV8RedactionProfileSource{
			// Stricter than sensitive on content (hash), weaker on paths (detect).
			"hash_content_keep_paths": {
				Extends: "sensitive",
				FieldClasses: map[config.ObservabilityV8FieldClass]config.ObservabilityV8FieldMode{
					config.ObservabilityV8FieldContent: config.ObservabilityV8ModeHash,
					config.ObservabilityV8FieldPath:    config.ObservabilityV8ModeDetect,
				},
			},
		}
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketComplianceActivity: {RedactionProfile: "hash_content_keep_paths"},
		}
	})
	keyed, err := redaction.NewEngine(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	factory := &rejectedRecordFactory{store: dependencies.store, engine: keyed}
	component, err := factory.Prepare(context.Background(),
		runtimegraph.BuildInput{Config: runtimegraph.ConfigFromPlan(plan, false)}, &runtimegraph.Acquisitions{})
	if err != nil {
		t.Fatal(err)
	}
	writer := component.(*rejectedRecordWriter)
	if !writer.catalogOK {
		t.Fatal("the plan's redaction profile catalog did not resolve")
	}

	merged := writer.profileFor(observability.BucketComplianceActivity)
	if got, want := merged.Name(), redaction.ProfileName("rejected_records_"+string(observability.BucketComplianceActivity)); got != want {
		t.Fatalf("profile for the custom bucket = %q, want the merged profile %q", got, want)
	}
	local, ok := writer.catalog.Resolve("hash_content_keep_paths")
	if !ok {
		t.Fatal("custom profile not in the catalog")
	}
	for _, class := range observability.FieldClasses() {
		got, _ := merged.Mode(class)
		fromSensitive, _ := writer.sensitive.Mode(class)
		fromLocal, _ := local.Mode(class)
		want := fromSensitive
		if class == observability.FieldClassContent {
			want = fromLocal
		}
		if got != want {
			t.Fatalf("class %s: merged mode %s, want %s (sensitive %s, local %s)", class, got, want, fromSensitive, fromLocal)
		}
	}

	record := rejectedSecretsRecord(observability.BucketComplianceActivity)
	record.Body["defenseclaw.file.path"] = "/home/someone/private/plans-bluefin.txt"
	record.FieldClasses["/defenseclaw.file.path"] = observability.FieldClassPath
	row := writer.row(record, time.Now())
	for _, leaked := range []string{"bluebird", "BEGIN PRIVATE KEY", "plans-bluefin"} {
		if bytes.Contains(row.Payload, []byte(leaked)) {
			t.Fatalf("the merged profile kept %q: %s", leaked, row.Payload)
		}
	}
	if !bytes.Contains(row.Payload, []byte(`"defenseclaw.hook.result":"success"`)) {
		t.Fatalf("metadata lost: %s", row.Payload)
	}
}
