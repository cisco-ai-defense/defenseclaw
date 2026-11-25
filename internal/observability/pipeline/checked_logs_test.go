// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type checkedOptionalProjector struct {
	engine *redaction.Engine
	calls  int
}

func (p *checkedOptionalProjector) Project(record observability.Record, profile redaction.Profile) (redaction.Projection, redaction.SafeReport, error) {
	if profile.Name() == redaction.ProfileSensitive {
		p.calls++
	}
	return p.engine.Project(record, profile)
}

func TestLocalLogPipelineCheckedProjectionPrecedesAppendAndIsReused(t *testing.T) {
	for _, name := range []string{"accept", "reject", "append failure"} {
		t.Run(name, func(t *testing.T) {
			source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{{Name: "checked", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{Signals: []observability.Signal{observability.SignalLogs}, Buckets: []observability.Bucket{"*"}, RedactionProfile: "sensitive"}}}}
			projector := &checkedOptionalProjector{engine: mustEngine(t)}
			coordinator, appender := mustPipeline(t, source, projector)
			if name == "append failure" {
				appender.err = errors.New("synthetic append failure")
			}
			test := findCatalogLogCase(t, observability.BucketPlatformHealth)
			var checked []byte
			builds, checks := 0, 0
			outcome, err := coordinator.ProcessChecked(context.Background(), mustMetadata(t, test), func(admission router.Admission) (observability.Record, error) {
				builds++
				return buildClassifiedLogWithContent(test, admission, "checked-projection", "safe synthetic content")
			}, func(candidate LocalLogOutcome) bool {
				checks++
				if len(appender.snapshot()) != 0 {
					t.Fatal("local append preceded projection validation")
				}
				if candidate.LocalPersisted() {
					t.Fatal("pre-append outcome claimed persistence")
				}
				work := candidate.OptionalWork()
				if len(work) != 1 {
					t.Fatalf("work=%d want1", len(work))
				}
				var encodeErr error
				checked, encodeErr = work[0].Projection().Bytes()
				if encodeErr != nil {
					t.Fatal(encodeErr)
				}
				return name != "reject"
			})
			if builds != 1 || checks != 1 || projector.calls != 1 {
				t.Fatalf("builds=%d checks=%d optional projections=%d", builds, checks, projector.calls)
			}
			if name == "reject" {
				if err == nil || len(appender.snapshot()) != 0 || outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 {
					t.Fatal("rejected projection produced persistence or exportable work")
				}
				return
			}
			if len(appender.snapshot()) != 1 {
				t.Fatal("matching projection did not attempt exactly one append")
			}
			if (err != nil) != (name == "append failure") {
				t.Fatalf("unexpected append result: %v", err)
			}
			if outcome.LocalPersisted() != (name == "accept") {
				t.Fatal("append result lost persistence state")
			}
			work := outcome.OptionalWork()
			if len(work) != 1 {
				t.Fatalf("returned work=%d", len(work))
			}
			returned, encodeErr := work[0].Projection().Bytes()
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			if !bytes.Equal(checked, returned) {
				t.Fatal("returned work differs from checked projection")
			}
		})
	}
}
