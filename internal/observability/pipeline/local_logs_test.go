// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	legacyredaction "github.com/defenseclaw/defenseclaw/internal/redaction"
)

type appendCall struct {
	record     observability.Record
	projection redaction.Projection
}

type recordingAppender struct {
	mu          sync.Mutex
	calls       []appendCall
	err         error
	graphDigest string
}

func (appender *recordingAppender) GraphDigest() string {
	if appender == nil {
		return ""
	}
	return appender.graphDigest
}

type selectiveProjector struct {
	engine      *redaction.Engine
	failBucket  observability.Bucket
	failProfile redaction.ProfileName
	failure     redaction.ProjectionErrorCode
}

func (projector *selectiveProjector) Project(
	record observability.Record,
	profile redaction.Profile,
) (redaction.Projection, redaction.SafeReport, error) {
	if (projector.failBucket == "" || record.Bucket() == projector.failBucket) &&
		(projector.failProfile == "" || profile.Name() == projector.failProfile) {
		return redaction.Projection{}, redaction.SafeReport{}, &redaction.ProjectionError{Code: projector.failure}
	}
	return projector.engine.Project(record, profile)
}

func (appender *recordingAppender) AppendContext(
	ctx context.Context,
	record observability.Record,
	projection redaction.Projection,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	appender.mu.Lock()
	defer appender.mu.Unlock()
	appender.calls = append(appender.calls, appendCall{record: record.Clone(), projection: projection})
	return appender.err
}

func (appender *recordingAppender) snapshot() []appendCall {
	appender.mu.Lock()
	defer appender.mu.Unlock()
	return append([]appendCall(nil), appender.calls...)
}

type classifiedLogCase struct {
	bucket  observability.Bucket
	kind    observability.ProducerKind
	key     observability.ProducerKey
	context observability.ClassificationContext
}

func TestLocalLogPipelinePersistsEveryCatalogBucketExactlyOnce(t *testing.T) {
	pipeline, appender := mustPipeline(t, nil, mustEngine(t))
	cases := catalogLogCases()
	if len(cases) != len(observability.Buckets()) {
		t.Fatalf("test cases = %d, catalog buckets = %d", len(cases), len(observability.Buckets()))
	}
	seen := make(map[observability.Bucket]bool, len(cases))
	for index, test := range cases {
		metadata := mustMetadata(t, test)
		var builds atomic.Int64
		outcome, err := pipeline.Process(context.Background(), metadata, func(admission router.Admission) (observability.Record, error) {
			builds.Add(1)
			return buildClassifiedLog(test, admission, fmt.Sprintf("record-%02d", index))
		})
		if err != nil {
			t.Fatalf("bucket %s: %v", test.bucket, err)
		}
		if outcome.Admission() != router.AdmissionOrdinary || !outcome.LocalPersisted() ||
			len(outcome.OptionalWork()) != 0 || len(outcome.OptionalFailures()) != 0 {
			t.Fatalf("bucket %s outcome = admission:%v persisted:%t work:%d failures:%d",
				test.bucket, outcome.Admission(), outcome.LocalPersisted(), len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
		}
		if builds.Load() != 1 {
			t.Fatalf("bucket %s builder calls = %d", test.bucket, builds.Load())
		}
		seen[test.bucket] = true
	}

	for _, bucket := range observability.Buckets() {
		if !seen[bucket] {
			t.Errorf("catalog bucket %s was not exercised", bucket)
		}
	}
	calls := appender.snapshot()
	if len(calls) != len(cases) {
		t.Fatalf("local appends = %d, want %d", len(calls), len(cases))
	}
	for index, call := range calls {
		if call.record.Bucket() != cases[index].bucket {
			t.Errorf("append %d bucket = %s, want %s", index, call.record.Bucket(), cases[index].bucket)
		}
		metadata := call.projection.Metadata()
		if metadata.RedactionProfile != string(redaction.ProfileNone) || metadata.State != redaction.ProjectionStateRaw {
			t.Errorf("append %d local projection = %+v", index, metadata)
		}
	}
}

func TestLocalLogPipelineAdmissionIsLazyAndFloorIsLocalOnly(t *testing.T) {
	falseValue := false
	source := &config.ObservabilityV8Source{
		Defaults: config.ObservabilityV8BucketPolicySource{
			Collect: config.ObservabilityV8CollectSource{Logs: &falseValue},
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "remote-a", Kind: config.ObservabilityV8DestinationConsole},
			{Name: "remote-b", Kind: config.ObservabilityV8DestinationConsole},
		},
	}
	pipeline, appender := mustPipeline(t, source, mustEngine(t))

	nonmandatory := classifiedLogCase{
		bucket: observability.BucketDiagnostic, kind: observability.ProducerGatewayEvent,
		key: "diagnostic", context: observability.ClassificationContext{RawSeverity: "INFO"},
	}
	var droppedBuilds atomic.Int64
	dropped, err := pipeline.Process(context.Background(), mustMetadata(t, nonmandatory), func(router.Admission) (observability.Record, error) {
		droppedBuilds.Add(1)
		return observability.Record{}, errors.New("must not run")
	})
	if err != nil {
		t.Fatal(err)
	}
	if dropped.Admission() != router.AdmissionDrop || dropped.LocalPersisted() ||
		droppedBuilds.Load() != 0 || len(appender.snapshot()) != 0 {
		t.Fatalf("dropped outcome = admission:%v persisted:%t builds:%d appends:%d",
			dropped.Admission(), dropped.LocalPersisted(), droppedBuilds.Load(), len(appender.snapshot()))
	}

	mandatory := classifiedLogCase{
		bucket: observability.BucketComplianceActivity, kind: observability.ProducerGatewayEvent,
		key: "activity", context: observability.ClassificationContext{
			Bucket:    observability.BucketComplianceActivity,
			EventName: "config.change.applied", RawSeverity: "INFO",
			MandatoryFacts: observability.MandatoryFacts{ControlPlaneMutation: true},
		},
	}
	var floorBuilds atomic.Int64
	floor, err := pipeline.Process(context.Background(), mustMetadata(t, mandatory), func(admission router.Admission) (observability.Record, error) {
		floorBuilds.Add(1)
		return buildClassifiedLog(mandatory, admission, "floor-record")
	})
	if err != nil {
		t.Fatal(err)
	}
	if floor.Admission() != router.AdmissionFloor || !floor.LocalPersisted() || floorBuilds.Load() != 1 ||
		len(floor.OptionalWork()) != 0 || len(floor.OptionalFailures()) != 0 {
		t.Fatalf("floor outcome = admission:%v persisted:%t builds:%d work:%d failures:%d",
			floor.Admission(), floor.LocalPersisted(), floorBuilds.Load(), len(floor.OptionalWork()), len(floor.OptionalFailures()))
	}
	calls := appender.snapshot()
	if len(calls) != 1 || !calls[0].record.Mandatory() || !calls[0].record.IsFloorOnly() {
		t.Fatalf("floor append = %+v", calls)
	}
}

func TestLocalLogPipelineUsesCustomBucketProfileForLocalProjection(t *testing.T) {
	const secret = "operator@example.test"
	source := &config.ObservabilityV8Source{
		RedactionProfiles: map[string]config.ObservabilityV8RedactionProfileSource{
			"soc-local": {
				Extends:   "sensitive",
				Detectors: []config.ObservabilityV8DetectorGroup{config.ObservabilityV8DetectorPII},
				FieldClasses: map[config.ObservabilityV8FieldClass]config.ObservabilityV8FieldMode{
					config.ObservabilityV8FieldContent: config.ObservabilityV8ModeWhole,
				},
			},
		},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketSecurityFinding: {RedactionProfile: "soc-local"},
		},
	}
	pipeline, appender := mustPipeline(t, source, mustEngine(t))
	test := findCatalogLogCase(t, observability.BucketSecurityFinding)
	outcome, err := pipeline.Process(context.Background(), mustMetadata(t, test), func(admission router.Admission) (observability.Record, error) {
		return buildClassifiedLogWithContent(test, admission, "custom-profile", secret)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.LocalPersisted() {
		t.Fatal("custom local projection was not persisted")
	}
	calls := appender.snapshot()
	if len(calls) != 1 {
		t.Fatalf("local appends = %d", len(calls))
	}
	metadata := calls[0].projection.Metadata()
	if metadata.RedactionProfile != "soc-local" || metadata.State != redaction.ProjectionStateTransformed {
		t.Fatalf("projection metadata = %+v", metadata)
	}
	projected, err := calls[0].projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(projected, []byte(secret)) {
		t.Fatal("custom local projection retained governed content")
	}
}

func TestLocalLogPipelineWithholdsOptionalWorkOnLocalFailure(t *testing.T) {
	source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "remote-a", Kind: config.ObservabilityV8DestinationConsole},
		{Name: "remote-b", Kind: config.ObservabilityV8DestinationConsole},
	}}
	test := findCatalogLogCase(t, observability.BucketSecurityFinding)
	metadata := mustMetadata(t, test)

	t.Run("projection", func(t *testing.T) {
		projector := &selectiveProjector{
			engine: mustEngine(t), failBucket: observability.BucketSecurityFinding,
			failure: redaction.ProjectionFailureSerialization,
		}
		pipeline, appender := mustPipeline(t, source, projector)
		outcome, err := pipeline.Process(context.Background(), metadata, func(admission router.Admission) (observability.Record, error) {
			return buildClassifiedLog(test, admission, "raw-original-marker-8172")
		})
		assertPipelineError(t, err, ErrorLocalProjection)
		calls := appender.snapshot()
		if outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 || len(calls) != 1 {
			t.Fatalf("projection failure leaked work: %+v", outcome)
		}
		if calls[0].record.Bucket() != observability.BucketPlatformHealth ||
			calls[0].record.EventName() != "redaction.failed_closed" ||
			!calls[0].record.Mandatory() {
			t.Fatalf("projection failure record = bucket:%s event:%s mandatory:%t",
				calls[0].record.Bucket(), calls[0].record.EventName(), calls[0].record.Mandatory())
		}
		projected, projectErr := calls[0].projection.Bytes()
		if projectErr != nil {
			t.Fatal(projectErr)
		}
		if bytes.Contains(projected, []byte("raw-original-marker-8172")) {
			t.Fatal("projection failure health record retained the failed record ID")
		}
	})

	t.Run("failure record cannot project", func(t *testing.T) {
		pipeline, appender := mustPipeline(t, source, &redaction.Engine{})
		_, err := pipeline.Process(context.Background(), metadata, func(admission router.Admission) (observability.Record, error) {
			return buildClassifiedLog(test, admission, "recursive-projection-failure")
		})
		assertPipelineError(t, err, ErrorFailureRecord)
		if len(appender.snapshot()) != 0 {
			t.Fatal("unprojectable health record reached SQLite")
		}
	})

	t.Run("write", func(t *testing.T) {
		pipeline, appender := mustPipeline(t, source, mustEngine(t))
		appender.err = errors.New("private sqlite failure: bearer-value")
		outcome, err := pipeline.Process(context.Background(), metadata, func(admission router.Admission) (observability.Record, error) {
			return buildClassifiedLog(test, admission, "write-failure")
		})
		assertPipelineError(t, err, ErrorLocalWrite)
		if strings.Contains(err.Error(), "bearer-value") {
			t.Fatalf("write failure leaked persistence diagnostics: %v", err)
		}
		if outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 || len(appender.snapshot()) != 1 {
			t.Fatalf("write failure leaked work: %+v calls:%d", outcome, len(appender.snapshot()))
		}
	})

	t.Run("cancel during write", func(t *testing.T) {
		pipeline, appender := mustPipeline(t, source, mustEngine(t))
		appender.err = context.Canceled
		_, err := pipeline.Process(context.Background(), metadata, func(admission router.Admission) (observability.Record, error) {
			return buildClassifiedLog(test, admission, "cancelled-write")
		})
		assertPipelineError(t, err, ErrorLocalWrite)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("mid-write cancellation identity was lost: %v", err)
		}
	})

	t.Run("deadline during write", func(t *testing.T) {
		pipeline, appender := mustPipeline(t, source, mustEngine(t))
		appender.err = context.DeadlineExceeded
		_, err := pipeline.Process(context.Background(), metadata, func(admission router.Admission) (observability.Record, error) {
			return buildClassifiedLog(test, admission, "deadline-write")
		})
		assertPipelineError(t, err, ErrorLocalWrite)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("mid-write deadline identity was lost: %v", err)
		}
	})
}

func TestLocalLogPipelineIsolatesOptionalProjectionFailure(t *testing.T) {
	logs := []observability.Signal{observability.SignalLogs}
	allBuckets := []observability.Bucket{"*"}
	source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "raw", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
			Signals: logs, Buckets: allBuckets, RedactionProfile: "none",
		}},
		{Name: "broken", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
			Signals: logs, Buckets: allBuckets, RedactionProfile: "sensitive",
		}},
		{Name: "strict", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
			Signals: logs, Buckets: allBuckets, RedactionProfile: "strict",
		}},
	}}
	projector := &selectiveProjector{
		engine: mustEngine(t), failProfile: redaction.ProfileSensitive,
		failure: redaction.ProjectionFailureSerialization,
	}
	pipeline, appender := mustPipeline(t, source, projector)
	test := findCatalogLogCase(t, observability.BucketSecurityFinding)
	outcome, err := pipeline.Process(context.Background(), mustMetadata(t, test), func(admission router.Admission) (observability.Record, error) {
		return buildClassifiedLogWithContent(test, admission, "optional-isolation", "private@example.test")
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.LocalPersisted() || len(appender.snapshot()) != 1 ||
		len(outcome.OptionalWork()) != 2 || len(outcome.OptionalFailures()) != 1 {
		t.Fatalf("optional isolation = local:%t appends:%d work:%d failures:%d",
			outcome.LocalPersisted(), len(appender.snapshot()), len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
	}
	failure := outcome.OptionalFailures()[0]
	if failure.DestinationName() != "broken" || failure.Code() != OptionalFailureSerialization {
		t.Fatalf("optional failure = destination:%s code:%s", failure.DestinationName(), failure.Code())
	}
	if got := []string{
		outcome.OptionalWork()[0].Delivery().DestinationName,
		outcome.OptionalWork()[1].Delivery().DestinationName,
	}; !reflect.DeepEqual(got, []string{"raw", "strict"}) {
		t.Fatalf("surviving optional destinations = %v", got)
	}
}

func TestLocalLogPipelineLocalOnlyNeverProjectsOptionalDestinations(t *testing.T) {
	logs := []observability.Signal{observability.SignalLogs}
	allBuckets := []observability.Bucket{"*"}
	source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "must-not-project", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
			Signals: logs, Buckets: allBuckets, RedactionProfile: "sensitive",
		}},
	}}
	projector := &selectiveProjector{
		engine: mustEngine(t), failProfile: redaction.ProfileSensitive,
		failure: redaction.ProjectionFailureSerialization,
	}
	pipeline, appender := mustPipeline(t, source, projector)
	test := findCatalogLogCase(t, observability.BucketComplianceActivity)
	outcome, err := pipeline.ProcessLocalOnly(
		context.Background(), mustMetadata(t, test),
		func(admission router.Admission) (observability.Record, error) {
			return buildClassifiedLogWithContent(test, admission, "local-only", "private@example.test")
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !outcome.LocalPersisted() || len(appender.snapshot()) != 1 ||
		len(outcome.OptionalWork()) != 0 || len(outcome.OptionalFailures()) != 0 {
		t.Fatalf("local-only outcome = local:%t appends:%d work:%d failures:%d",
			outcome.LocalPersisted(), len(appender.snapshot()),
			len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
	}
}

func TestLocalLogPipelineFansOutIndependentDestinationProjectionsAfterLocalWrite(t *testing.T) {
	logs := []observability.Signal{observability.SignalLogs}
	allBuckets := []observability.Bucket{"*"}
	source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "raw", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
			Signals: logs, Buckets: allBuckets, RedactionProfile: "none",
		}},
		{Name: "detected", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
			Signals: logs, Buckets: allBuckets, RedactionProfile: "sensitive",
		}},
		{Name: "minimal", Kind: config.ObservabilityV8DestinationConsole, Send: &config.ObservabilityV8SendSource{
			Signals: logs, Buckets: allBuckets, RedactionProfile: "strict",
		}},
	}}
	pipeline, appender := mustPipeline(t, source, mustEngine(t))
	test := findCatalogLogCase(t, observability.BucketSecurityFinding)
	const content = "fanout-person@example.test"
	var builds atomic.Int64
	outcome, err := pipeline.Process(context.Background(), mustMetadata(t, test), func(admission router.Admission) (observability.Record, error) {
		builds.Add(1)
		return buildClassifiedLogWithContent(test, admission, "fanout", content)
	})
	if err != nil {
		t.Fatal(err)
	}
	if builds.Load() != 1 || !outcome.LocalPersisted() || len(appender.snapshot()) != 1 ||
		len(outcome.OptionalWork()) != 3 || len(outcome.OptionalFailures()) != 0 {
		t.Fatalf("fanout = builds:%d persisted:%t local:%d work:%d failures:%d",
			builds.Load(), outcome.LocalPersisted(), len(appender.snapshot()), len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
	}

	localBytes, err := appender.snapshot()[0].projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(localBytes, []byte(content)) {
		t.Fatal("default local none projection lost content")
	}
	wantNames := []string{"raw", "detected", "minimal"}
	wantProfiles := []string{"none", "sensitive", "strict"}
	for index, work := range outcome.OptionalWork() {
		delivery := work.Delivery()
		if delivery.DestinationName != wantNames[index] || delivery.RedactionProfile != wantProfiles[index] {
			t.Errorf("work %d delivery = %+v", index, delivery)
		}
		projected, bytesErr := work.Projection().Bytes()
		if bytesErr != nil {
			t.Fatal(bytesErr)
		}
		if index == 0 && !bytes.Contains(projected, []byte(content)) {
			t.Error("none destination lost content")
		}
		if index > 0 && bytes.Contains(projected, []byte(content)) {
			t.Errorf("redacting destination %s retained content", delivery.DestinationName)
		}
	}
}

func TestLocalLogPipelineSinkPolicyOverridesEveryProjectionWithoutChangingRoutes(t *testing.T) {
	source := sinkPolicyProjectionSource(redaction.ProfileStrict)
	plan, evaluator := mustPlanEvaluator(t, source)
	configuredLocal, err := plan.ResolveLocalRedactionProfile(observability.BucketSecurityFinding)
	if err != nil || configuredLocal != redaction.ProfileStrict {
		t.Fatalf("configured local profile = %s, want strict: %v", configuredLocal, err)
	}
	configuredOptional := []string{
		string(redaction.ProfileNone), string(redaction.ProfileSensitive), string(redaction.ProfileStrict),
	}
	test := findCatalogLogCase(t, observability.BucketSecurityFinding)

	tests := []struct {
		name         string
		context      func() context.Context
		wantLocal    redaction.ProfileName
		wantOptional []redaction.ProfileName
	}{
		{
			name: "default keeps compiled profiles",
			context: func() context.Context {
				return context.Background()
			},
			wantLocal: redaction.ProfileStrict,
			wantOptional: []redaction.ProfileName{
				redaction.ProfileNone, redaction.ProfileSensitive, redaction.ProfileStrict,
			},
		},
		{
			name: "raw forces none",
			context: func() context.Context {
				return legacyredaction.WithSinkPolicy(context.Background(), legacyredaction.SinkPolicyRaw)
			},
			wantLocal: redaction.ProfileNone,
			wantOptional: []redaction.ProfileName{
				redaction.ProfileNone, redaction.ProfileNone, redaction.ProfileNone,
			},
		},
		{
			name: "redact forces sensitive",
			context: func() context.Context {
				return legacyredaction.WithSinkPolicy(context.Background(), legacyredaction.SinkPolicyRedact)
			},
			wantLocal: redaction.ProfileSensitive,
			wantOptional: []redaction.ProfileName{
				redaction.ProfileSensitive, redaction.ProfileSensitive, redaction.ProfileSensitive,
			},
		},
	}

	for index, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			pipeline, appender := mustPipelineFromPlan(t, plan, evaluator, mustEngine(t))
			content := fmt.Sprintf("sink-policy-%d@example.test", index)
			var canonical observability.Record
			var canonicalBefore []byte
			outcome, processErr := pipeline.Process(
				testCase.context(), mustMetadata(t, test),
				func(admission router.Admission) (observability.Record, error) {
					var buildErr error
					canonical, buildErr = buildClassifiedLogWithContent(
						test, admission, fmt.Sprintf("sink-policy-%d", index), content,
					)
					if buildErr == nil {
						canonicalBefore, buildErr = canonical.Bytes()
					}
					return canonical, buildErr
				},
			)
			if processErr != nil {
				t.Fatal(processErr)
			}
			calls := appender.snapshot()
			if !outcome.LocalPersisted() || len(calls) != 1 || len(outcome.OptionalWork()) != 3 ||
				len(outcome.OptionalFailures()) != 0 {
				t.Fatalf("outcome = local:%t appends:%d work:%d failures:%d",
					outcome.LocalPersisted(), len(calls), len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
			}
			assertProjectionProfileAndContent(
				t, calls[0].projection, testCase.wantLocal, content,
			)
			for optionalIndex, work := range outcome.OptionalWork() {
				if work.Delivery().RedactionProfile != configuredOptional[optionalIndex] {
					t.Errorf("delivery %d profile changed to %q, want compiled %q",
						optionalIndex, work.Delivery().RedactionProfile, configuredOptional[optionalIndex])
				}
				assertProjectionProfileAndContent(
					t, work.Projection(), testCase.wantOptional[optionalIndex], content,
				)
			}
			canonicalAfter, bytesErr := canonical.Bytes()
			if bytesErr != nil {
				t.Fatal(bytesErr)
			}
			if !bytes.Equal(canonicalBefore, canonicalAfter) {
				t.Fatal("sink policy projection mutated the canonical record")
			}
			stillConfigured, resolveErr := plan.ResolveLocalRedactionProfile(observability.BucketSecurityFinding)
			if resolveErr != nil || stillConfigured != configuredLocal {
				t.Fatalf("compiled local profile changed to %s: %v", stillConfigured, resolveErr)
			}
		})
	}
}

func TestLocalLogPipelineSpecialPathsInheritSinkPolicyContext(t *testing.T) {
	test := findCatalogLogCase(t, observability.BucketSecurityFinding)

	t.Run("local only raw", func(t *testing.T) {
		pipeline, appender := mustPipeline(
			t, sinkPolicyProjectionSource(redaction.ProfileStrict), mustEngine(t),
		)
		ctx := legacyredaction.WithSinkPolicy(t.Context(), legacyredaction.SinkPolicyRaw)
		outcome, err := pipeline.ProcessLocalOnly(
			ctx, mustMetadata(t, test),
			func(admission router.Admission) (observability.Record, error) {
				return buildClassifiedLogWithContent(
					test, admission, "local-only-policy", "local-only@example.test",
				)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		calls := appender.snapshot()
		if !outcome.LocalPersisted() || len(calls) != 1 || len(outcome.OptionalWork()) != 0 ||
			len(outcome.OptionalFailures()) != 0 {
			t.Fatalf("local-only outcome = local:%t appends:%d work:%d failures:%d",
				outcome.LocalPersisted(), len(calls), len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
		}
		assertProjectionProfileAndContent(
			t, calls[0].projection, redaction.ProfileNone, "local-only@example.test",
		)
	})

	t.Run("imported redact", func(t *testing.T) {
		pipeline, appender := mustPipeline(
			t, sinkPolicyProjectionSource(redaction.ProfileNone), mustEngine(t),
		)
		ctx := legacyredaction.WithSinkPolicy(t.Context(), legacyredaction.SinkPolicyRedact)
		outcome, err := pipeline.ProcessImported(
			ctx, mustMetadata(t, test), "upstream", false,
			func(admission router.Admission) (observability.Record, error) {
				return buildClassifiedLogWithContent(
					test, admission, "imported-policy", "imported@example.test",
				)
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		calls := appender.snapshot()
		if !outcome.LocalPersisted() || len(calls) != 1 || len(outcome.OptionalWork()) != 3 ||
			len(outcome.OptionalFailures()) != 0 {
			t.Fatalf("imported outcome = local:%t appends:%d work:%d failures:%d",
				outcome.LocalPersisted(), len(calls), len(outcome.OptionalWork()), len(outcome.OptionalFailures()))
		}
		assertProjectionProfileAndContent(
			t, calls[0].projection, redaction.ProfileSensitive, "imported@example.test",
		)
		for index, work := range outcome.OptionalWork() {
			if work.Identity().OriginDestination() != "upstream" {
				t.Errorf("optional %d origin = %q, want upstream", index, work.Identity().OriginDestination())
			}
			assertProjectionProfileAndContent(
				t, work.Projection(), redaction.ProfileSensitive, "imported@example.test",
			)
		}
	})
}

func TestLocalLogPipelineSinkPolicyIsPerRecordUnderConcurrentBatchUse(t *testing.T) {
	pipeline, appender := mustPipeline(
		t, sinkPolicyProjectionSource(redaction.ProfileStrict), mustEngine(t),
	)
	test := findCatalogLogCase(t, observability.BucketSecurityFinding)
	metadata := mustMetadata(t, test)
	type expected struct {
		local    redaction.ProfileName
		optional []redaction.ProfileName
	}
	policies := []struct {
		policy legacyredaction.SinkPolicy
		want   expected
	}{
		{legacyredaction.SinkPolicyDefault, expected{
			local: redaction.ProfileStrict,
			optional: []redaction.ProfileName{
				redaction.ProfileNone, redaction.ProfileSensitive, redaction.ProfileStrict,
			},
		}},
		{legacyredaction.SinkPolicyRaw, expected{
			local: redaction.ProfileNone,
			optional: []redaction.ProfileName{
				redaction.ProfileNone, redaction.ProfileNone, redaction.ProfileNone,
			},
		}},
		{legacyredaction.SinkPolicyRedact, expected{
			local: redaction.ProfileSensitive,
			optional: []redaction.ProfileName{
				redaction.ProfileSensitive, redaction.ProfileSensitive, redaction.ProfileSensitive,
			},
		}},
	}

	const workers = 48
	wants := make(map[string]expected, workers)
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for index := 0; index < workers; index++ {
		entry := policies[index%len(policies)]
		recordID := fmt.Sprintf("sink-policy-concurrent-%02d", index)
		wants[recordID] = entry.want
		wait.Add(1)
		go func() {
			defer wait.Done()
			ctx := context.Background()
			if entry.policy != legacyredaction.SinkPolicyDefault {
				ctx = legacyredaction.WithSinkPolicy(ctx, entry.policy)
			}
			outcome, err := pipeline.Process(ctx, metadata, func(admission router.Admission) (observability.Record, error) {
				return buildClassifiedLogWithContent(
					test, admission, recordID, recordID+"@example.test",
				)
			})
			if err != nil {
				errorsSeen <- err
				return
			}
			work := outcome.OptionalWork()
			if !outcome.LocalPersisted() || len(work) != len(entry.want.optional) ||
				len(outcome.OptionalFailures()) != 0 {
				errorsSeen <- fmt.Errorf("record %s returned an invalid outcome", recordID)
				return
			}
			for optionalIndex := range work {
				if got := redaction.ProfileName(work[optionalIndex].Projection().Metadata().RedactionProfile); got != entry.want.optional[optionalIndex] {
					errorsSeen <- fmt.Errorf(
						"record %s optional %d profile = %s, want %s",
						recordID, optionalIndex, got, entry.want.optional[optionalIndex],
					)
					return
				}
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	calls := appender.snapshot()
	if len(calls) != workers {
		t.Fatalf("local appends = %d, want %d", len(calls), workers)
	}
	for _, call := range calls {
		want, ok := wants[call.record.RecordID()]
		if !ok {
			t.Errorf("unexpected local record %q", call.record.RecordID())
			continue
		}
		if got := redaction.ProfileName(call.projection.Metadata().RedactionProfile); got != want.local {
			t.Errorf("record %s local profile = %s, want %s", call.record.RecordID(), got, want.local)
		}
	}
}

func TestLocalLogPipelineMissingSinkPolicyProfileFailsClosed(t *testing.T) {
	for _, policy := range []legacyredaction.SinkPolicy{
		legacyredaction.SinkPolicyDefault,
		legacyredaction.SinkPolicyRaw,
		legacyredaction.SinkPolicyRedact,
	} {
		t.Run(fmt.Sprintf("policy-%d", policy), func(t *testing.T) {
			pipeline, appender := mustPipeline(
				t, sinkPolicyProjectionSource(redaction.ProfileStrict), mustEngine(t),
			)
			pipeline.catalog = redaction.ProfileCatalog{}
			ctx := legacyredaction.WithSinkPolicy(t.Context(), policy)
			test := findCatalogLogCase(t, observability.BucketSecurityFinding)
			outcome, err := pipeline.Process(
				ctx, mustMetadata(t, test),
				func(admission router.Admission) (observability.Record, error) {
					return buildClassifiedLog(test, admission, fmt.Sprintf("missing-profile-%d", policy))
				},
			)
			assertPipelineError(t, err, ErrorLocalProfile)
			if outcome.LocalPersisted() || len(outcome.OptionalWork()) != 0 ||
				len(outcome.OptionalFailures()) != 0 || len(appender.snapshot()) != 0 {
				t.Fatalf("missing profile leaked projection work: %+v", outcome)
			}
		})
	}
}

func TestLocalLogPipelinePreservesCanonicalAndOutcomeImmutability(t *testing.T) {
	source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "one", Kind: config.ObservabilityV8DestinationConsole},
		{Name: "two", Kind: config.ObservabilityV8DestinationConsole},
	}}
	pipeline, appender := mustPipeline(t, source, mustEngine(t))
	test := findCatalogLogCase(t, observability.BucketModelIO)
	var canonical observability.Record
	outcome, err := pipeline.Process(context.Background(), mustMetadata(t, test), func(admission router.Admission) (observability.Record, error) {
		var buildErr error
		canonical, buildErr = buildClassifiedLogWithContent(test, admission, "immutable", "immutable-content")
		return canonical, buildErr
	})
	if err != nil {
		t.Fatal(err)
	}
	before, err := canonical.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	work := outcome.OptionalWork()
	if len(work) != 2 {
		t.Fatalf("optional work = %d", len(work))
	}
	identity := work[0].Identity()
	if identity.RecordID() != canonical.RecordID() || identity.Bucket() != canonical.Bucket() ||
		identity.Signal() != canonical.Signal() || identity.EventName() != canonical.EventName() ||
		identity.OriginDestination() != "" {
		t.Fatalf("projected delivery identity = %#v", identity)
	}
	work[0].delivery.DestinationName = "mutated"
	projectionBytes, err := work[1].projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	projectionBytes[0] ^= 0xff
	failures := outcome.OptionalFailures()
	failures = append(failures, OptionalFailure{destinationName: "mutated"})

	after, err := canonical.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("destination projection mutated the canonical record")
	}
	fresh := outcome.OptionalWork()
	if fresh[0].Delivery().DestinationName != "one" {
		t.Fatal("returned optional work aliased outcome storage")
	}
	freshProjectionBytes, err := fresh[1].Projection().Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(projectionBytes, freshProjectionBytes) {
		t.Fatal("projection Bytes returned mutable internal storage")
	}
	if len(outcome.OptionalFailures()) != 0 {
		t.Fatal("returned optional failures aliased outcome storage")
	}
	if len(appender.snapshot()) != 1 {
		t.Fatal("canonical record was persisted more than once")
	}
}

func TestLocalLogPipelineIsConcurrentAndRaceSafe(t *testing.T) {
	source := &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "one", Kind: config.ObservabilityV8DestinationConsole},
		{Name: "two", Kind: config.ObservabilityV8DestinationConsole},
	}}
	pipeline, appender := mustPipeline(t, source, mustEngine(t))
	test := findCatalogLogCase(t, observability.BucketToolActivity)
	metadata := mustMetadata(t, test)
	var identifiers atomic.Int64

	const workers = 32
	const perWorker = 25
	var wait sync.WaitGroup
	failures := make(chan error, workers)
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < perWorker; iteration++ {
				identifier := fmt.Sprintf("concurrent-%d", identifiers.Add(1))
				outcome, err := pipeline.Process(context.Background(), metadata, func(admission router.Admission) (observability.Record, error) {
					return buildClassifiedLog(test, admission, identifier)
				})
				if err != nil {
					failures <- err
					return
				}
				if !outcome.LocalPersisted() || len(outcome.OptionalWork()) != 2 || len(outcome.OptionalFailures()) != 0 {
					failures <- fmt.Errorf("unexpected concurrent outcome")
					return
				}
			}
		}()
	}
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if got, want := len(appender.snapshot()), workers*perWorker; got != want {
		t.Fatalf("local appends = %d, want %d", got, want)
	}
}

func TestLocalLogPipelineRejectsMismatchedGraphAndSanitizesBuilderError(t *testing.T) {
	planA, evaluatorA := mustPlanEvaluator(t, nil)
	planB, evaluatorB := mustPlanEvaluator(t, &config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "other", Kind: config.ObservabilityV8DestinationConsole},
	}})
	if _, err := NewLocalLogPipeline(
		planB, evaluatorA, mustEngine(t), &recordingAppender{}, mustFailureFactory(t),
	); err == nil {
		t.Fatal("pipeline accepted evaluator from another compiled graph")
	}
	if _, err := NewLocalLogPipeline(
		planA, evaluatorA, mustEngine(t),
		&recordingAppender{graphDigest: planB.Digest()}, mustFailureFactory(t),
	); err == nil {
		t.Fatal("pipeline accepted a local appender from another compiled graph")
	}
	if _, err := NewLocalLogPipeline(
		planB, evaluatorB, mustEngine(t),
		&recordingAppender{graphDigest: planA.Digest()}, mustFailureFactory(t),
	); err == nil {
		t.Fatal("reloaded pipeline accepted the prior generation's local appender")
	}

	pipeline, _ := mustPipelineFromPlan(t, planA, evaluatorA, mustEngine(t))
	test := findCatalogLogCase(t, observability.BucketDiagnostic)
	_, err := pipeline.Process(context.Background(), mustMetadata(t, test), func(router.Admission) (observability.Record, error) {
		return observability.Record{}, errors.New("producer secret payload 90817")
	})
	assertPipelineError(t, err, ErrorRecordBuild)
	if strings.Contains(err.Error(), "90817") {
		t.Fatalf("builder error leaked producer diagnostics: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = pipeline.Process(cancelled, mustMetadata(t, test), nil)
	assertPipelineError(t, err, ErrorContextDone)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("context cancellation identity was lost: %v", err)
	}
}

func TestLocalLogPipelineGraphBindingIsCoherentDuringConcurrentReloadAssembly(t *testing.T) {
	planA, evaluatorA := mustPlanEvaluator(t, nil)
	planB, evaluatorB := mustPlanEvaluator(t, &config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{
			{Name: "reload-console", Kind: config.ObservabilityV8DestinationConsole},
		},
	})
	engine := mustEngine(t)
	failures := mustFailureFactory(t)
	type generation struct {
		plan      *config.ObservabilityV8Plan
		evaluator *router.Evaluator
	}
	generations := []generation{{planA, evaluatorA}, {planB, evaluatorB}}
	var workers sync.WaitGroup
	errorsSeen := make(chan error, 128)
	for worker := 0; worker < 64; worker++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			active := generations[index%len(generations)]
			other := generations[(index+1)%len(generations)]
			if _, err := NewLocalLogPipeline(
				active.plan, active.evaluator, engine,
				&recordingAppender{graphDigest: active.plan.Digest()}, failures,
			); err != nil {
				errorsSeen <- fmt.Errorf("matching generation rejected: %w", err)
			}
			if _, err := NewLocalLogPipeline(
				active.plan, active.evaluator, engine,
				&recordingAppender{graphDigest: other.plan.Digest()}, failures,
			); err == nil {
				errorsSeen <- errors.New("cross-generation appender accepted")
			}
		}(worker)
	}
	workers.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
}

func sinkPolicyProjectionSource(localProfile redaction.ProfileName) *config.ObservabilityV8Source {
	logs := []observability.Signal{observability.SignalLogs}
	allBuckets := []observability.Bucket{"*"}
	return &config.ObservabilityV8Source{
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketSecurityFinding: {RedactionProfile: string(localProfile)},
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{
				Name: "configured-none", Kind: config.ObservabilityV8DestinationConsole,
				Send: &config.ObservabilityV8SendSource{
					Signals: logs, Buckets: allBuckets, RedactionProfile: string(redaction.ProfileNone),
				},
			},
			{
				Name: "configured-sensitive", Kind: config.ObservabilityV8DestinationConsole,
				Send: &config.ObservabilityV8SendSource{
					Signals: logs, Buckets: allBuckets, RedactionProfile: string(redaction.ProfileSensitive),
				},
			},
			{
				Name: "configured-strict", Kind: config.ObservabilityV8DestinationConsole,
				Send: &config.ObservabilityV8SendSource{
					Signals: logs, Buckets: allBuckets, RedactionProfile: string(redaction.ProfileStrict),
				},
			},
		},
	}
}

func assertProjectionProfileAndContent(
	t *testing.T,
	projection redaction.Projection,
	wantProfile redaction.ProfileName,
	content string,
) {
	t.Helper()
	metadata := projection.Metadata()
	if metadata.RedactionProfile != string(wantProfile) {
		t.Errorf("projection profile = %q, want %q", metadata.RedactionProfile, wantProfile)
	}
	projected, err := projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	containsContent := bytes.Contains(projected, []byte(content))
	if wantProfile == redaction.ProfileNone && !containsContent {
		t.Errorf("none projection did not preserve %q", content)
	}
	if wantProfile != redaction.ProfileNone && containsContent {
		t.Errorf("%s projection retained governed content %q", wantProfile, content)
	}
}

func mustPipeline(
	t *testing.T,
	source *config.ObservabilityV8Source,
	projector Projector,
) (*LocalLogPipeline, *recordingAppender) {
	t.Helper()
	plan, evaluator := mustPlanEvaluator(t, source)
	return mustPipelineFromPlan(t, plan, evaluator, projector)
}

func mustPipelineFromPlan(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
	evaluator *router.Evaluator,
	projector Projector,
) (*LocalLogPipeline, *recordingAppender) {
	t.Helper()
	appender := &recordingAppender{graphDigest: plan.Digest()}
	pipeline, err := NewLocalLogPipeline(plan, evaluator, projector, appender, mustFailureFactory(t))
	if err != nil {
		t.Fatal(err)
	}
	return pipeline, appender
}

func mustPlanEvaluator(
	t *testing.T,
	source *config.ObservabilityV8Source,
) (*config.ObservabilityV8Plan, *router.Evaluator) {
	t.Helper()
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, evaluator
}

func mustEngine(t *testing.T) *redaction.Engine {
	t.Helper()
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func mustFailureFactory(t *testing.T) *CanonicalProjectionFailureFactory {
	t.Helper()
	var identifiers atomic.Int64
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, 7, 3, 4, 5, 6, int(identifiers.Load()), time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("projection-failure-%d", identifiers.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewCanonicalProjectionFailureFactory(builder)
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func mustMetadata(t *testing.T, test classifiedLogCase) router.Metadata {
	t.Helper()
	metadata, err := router.NewClassifiedLogMetadata(
		test.kind,
		test.key,
		test.context,
		observability.SourceSystem,
		"",
		test.key,
	)
	if err != nil {
		t.Fatalf("metadata for %s: %v", test.bucket, err)
	}
	if metadata.Identity().Bucket != test.bucket {
		t.Fatalf("metadata bucket = %s, want %s", metadata.Identity().Bucket, test.bucket)
	}
	return metadata
}

func buildClassifiedLog(
	test classifiedLogCase,
	admission router.Admission,
	recordID string,
) (observability.Record, error) {
	return buildClassifiedLogWithContent(test, admission, recordID, "catalog-content")
}

func buildClassifiedLogWithContent(
	test classifiedLogCase,
	admission router.Admission,
	recordID string,
	content string,
) (observability.Record, error) {
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(1_700_000_000, 123).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return recordID, nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	provenance := observability.Provenance{
		Producer: "pipeline-test", BinaryVersion: "test",
		RegistrySchemaVersion: 1, ConfigGeneration: 1,
	}
	if admission == router.AdmissionFloor {
		return builder.BuildMandatoryFloorLog(observability.MandatoryFloorLogInput{
			ProducerKind: test.kind, ProducerKey: test.key, ClassificationContext: test.context,
			Source: observability.SourceSystem, Action: string(test.key), Provenance: provenance,
		})
	}
	return builder.BuildClassifiedLog(observability.ClassifiedLogInput{
		ProducerKind: test.kind, ProducerKey: test.key, ClassificationContext: test.context,
		Source: observability.SourceSystem, Action: string(test.key), Provenance: provenance,
		Body: map[string]any{"content": content},
		FieldClasses: map[string]observability.FieldClass{
			"/content": observability.FieldClassContent,
		},
	})
}

func findCatalogLogCase(t *testing.T, bucket observability.Bucket) classifiedLogCase {
	t.Helper()
	for _, test := range catalogLogCases() {
		if test.bucket == bucket {
			return test
		}
	}
	t.Fatalf("no log case for %s", bucket)
	return classifiedLogCase{}
}

func catalogLogCases() []classifiedLogCase {
	audit := func(bucket observability.Bucket, key observability.ProducerKey, severity string) classifiedLogCase {
		return classifiedLogCase{
			bucket: bucket, kind: observability.ProducerAuditAction, key: key,
			context: observability.ClassificationContext{RawSeverity: severity},
		}
	}
	return []classifiedLogCase{
		audit(observability.BucketComplianceActivity, "config-update", "INFO"),
		audit(observability.BucketSecurityFinding, "scan-finding", "HIGH"),
		audit(observability.BucketGuardrailEvaluation, "guardrail-allow", "NONE"),
		audit(observability.BucketEnforcementAction, "quarantine", "INFO"),
		audit(observability.BucketModelIO, "gateway-session-message", "INFO"),
		audit(observability.BucketToolActivity, "tool-call", "INFO"),
		audit(observability.BucketAssetScan, "scan", "INFO"),
		audit(observability.BucketAssetLifecycle, "deploy", "INFO"),
		audit(observability.BucketNetworkEgress, "network-egress-allowed", "INFO"),
		audit(observability.BucketAgentLifecycle, "gateway-agent-start", "INFO"),
		{
			bucket: observability.BucketAIDiscovery, kind: observability.ProducerGatewayEvent, key: "ai_discovery",
			context: observability.ClassificationContext{
				Bucket: observability.BucketAIDiscovery, EventName: "ai_component.discovered", RawSeverity: "INFO",
			},
		},
		audit(observability.BucketTelemetryIngest, "otel.ingest.logs", "INFO"),
		audit(observability.BucketPlatformHealth, "webhook-delivered", "INFO"),
		{
			bucket: observability.BucketDiagnostic, kind: observability.ProducerGatewayEvent, key: "diagnostic",
			context: observability.ClassificationContext{RawSeverity: "INFO"},
		},
	}
}

func assertPipelineError(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var pipelineError *Error
	if !errors.As(err, &pipelineError) || pipelineError.Code() != code {
		t.Fatalf("error = %v, want pipeline code %s", err, code)
	}
}

func TestOptionalFailureValuesAreDetachedAndContentFree(t *testing.T) {
	failure := newOptionalFailure(router.Delivery{
		DestinationName: "destination", DestinationKind: config.ObservabilityV8DestinationOTLP,
		RouteName: "route", RouteIndex: 7,
	}, OptionalFailureSerialization)
	if failure.DestinationName() != "destination" || failure.DestinationKind() != config.ObservabilityV8DestinationOTLP ||
		failure.RouteName() != "route" || failure.RouteIndex() != 7 || failure.Code() != OptionalFailureSerialization {
		t.Fatalf("optional failure identity = %+v", failure)
	}
	outcome := LocalLogOutcome{optionalFailure: []OptionalFailure{failure}}
	detached := outcome.OptionalFailures()
	detached[0].destinationName = "changed"
	if !reflect.DeepEqual(outcome.OptionalFailures(), []OptionalFailure{failure}) {
		t.Fatal("optional failure result was not detached")
	}
}
