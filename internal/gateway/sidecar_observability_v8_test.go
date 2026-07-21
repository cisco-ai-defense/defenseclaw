// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type discardSidecarGraphReporter struct{}

func (*discardSidecarGraphReporter) PlatformHealth(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

func (*discardSidecarGraphReporter) ComplianceActivity(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

type sidecarRuntimeFixture struct {
	runtime *observabilityruntime.Runtime
	store   *audit.Store
	path    string
	plan    *config.ObservabilityV8Plan
}

func newSidecarRuntimeFixture(t *testing.T, collectLifecycle bool) sidecarRuntimeFixture {
	return newSidecarRuntimeFixtureWithSigner(t, collectLifecycle, nil)
}

func newSignedSidecarRuntimeFixture(t *testing.T, collectLifecycle bool) sidecarRuntimeFixture {
	t.Helper()
	keyDirectory := t.TempDir()
	if err := os.Chmod(keyDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	key, err := redaction.LoadOrCreateCorrelationKey(keyDirectory)
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
	return newSidecarRuntimeFixtureWithSigner(t, collectLifecycle, signer)
}

func newSidecarRuntimeFixtureWithSigner(
	t *testing.T,
	collectLifecycle bool,
	signer audit.ProjectionIntegritySigner,
) sidecarRuntimeFixture {
	t.Helper()
	previousInstanceID := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("sidecar-runtime-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstanceID) })
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	retentionDays := 0
	source := &config.ObservabilityV8Source{Local: config.ObservabilityV8LocalSource{
		Path: path, JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
		RetentionDays: &retentionDays,
	}}
	if !collectLifecycle {
		disabled := false
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketAgentLifecycle: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		}
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var failureIDs atomic.Uint64
	failureBuilder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("sidecar-failure-%d", failureIDs.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := observabilityruntime.New(
		t.Context(),
		runtimegraph.ConfigFromPlan(plan, false),
		observabilityruntime.Options{
			Store: store, Engine: engine, Signer: signer, RecordBuilder: failureBuilder,
			Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
			TelemetryProviderFactory: telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
				Version: "8.0.0", Environment: "test", ServiceInstanceID: "sidecar-runtime-test",
				DefenseClawInstanceID: "sidecar-runtime-test",
			}),
		},
	)
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
	return sidecarRuntimeFixture{runtime: runtime, store: store, path: path, plan: plan}
}

type storedSidecarLifecycle struct {
	action            string
	actor             string
	details           string
	severity          string
	bucket            string
	eventName         string
	source            string
	digest            string
	generation        int64
	runID             string
	sidecarInstanceID string
}

func readStoredSidecarLifecycle(t *testing.T, path string) []storedSidecarLifecycle {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT action, actor, details, COALESCE(severity,''), COALESCE(bucket,''), COALESCE(event_name,''),
		COALESCE(source,''), COALESCE(content_hash,''), COALESCE(generation,0),
		COALESCE(run_id,''), COALESCE(sidecar_instance_id,'')
		FROM audit_events WHERE action IN ('sidecar-start','sidecar-stop') ORDER BY action`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []storedSidecarLifecycle
	for rows.Next() {
		var event storedSidecarLifecycle
		if err := rows.Scan(
			&event.action, &event.actor, &event.details, &event.severity, &event.bucket, &event.eventName, &event.source,
			&event.digest, &event.generation, &event.runID, &event.sidecarInstanceID,
		); err != nil {
			t.Fatal(err)
		}
		result = append(result, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func installSidecarLifecycleIDs(t *testing.T) {
	t.Helper()
	gatewaylog.SetProcessRunID("sidecar-v8-run")
	gatewaylog.SetSidecarInstanceID("sidecar-v8-instance")
	t.Cleanup(func() {
		gatewaylog.SetProcessRunID("")
		gatewaylog.SetSidecarInstanceID("")
	})
}

func TestSidecarCanonicalLifecyclePersistsExactlyOnceWithGraphProvenance(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	installSidecarLifecycleIDs(t)
	sidecar := &Sidecar{logger: audit.NewLogger(fixture.store)}
	if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.recordSidecarLifecycle(t.Context(), audit.ActionSidecarStart); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := sidecar.recordSidecarLifecycle(canceled, audit.ActionSidecarStop); err != nil {
		t.Fatalf("canonical stop rejected canceled run context: %v", err)
	}

	rows := readStoredSidecarLifecycle(t, fixture.path)
	if len(rows) != 2 {
		t.Fatalf("lifecycle rows=%d want 2: %#v", len(rows), rows)
	}
	wantEvents := map[string]string{
		"sidecar-start": "subsystem.lifecycle",
		"sidecar-stop":  "subsystem.lifecycle",
	}
	wantDetails := map[string]string{
		"sidecar-start": "subsystem.lifecycle",
		"sidecar-stop":  "subsystem.lifecycle",
	}
	for _, row := range rows {
		if row.bucket != string(observability.BucketPlatformHealth) ||
			row.eventName != wantEvents[row.action] || row.actor != "defenseclaw" ||
			row.details != wantDetails[row.action] || row.severity != "INFO" ||
			row.source != string(observability.SourceGateway) ||
			row.digest != fixture.plan.Digest() || row.generation != 1 ||
			row.runID != "sidecar-v8-run" || row.sidecarInstanceID != "sidecar-v8-instance" {
			t.Errorf("canonical lifecycle row=%#v", row)
		}
	}
}

func TestSidecarBindsLifecycleRuntimeToEveryConsumerInEitherConstructionOrder(t *testing.T) {
	for _, bindFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("bind-first-%t", bindFirst), func(t *testing.T) {
			fixture := newSidecarRuntimeFixture(t, true)
			sidecar := &Sidecar{}
			api := &APIServer{}
			router := &EventRouter{}
			proxy := &GuardrailProxy{}
			if bindFirst {
				if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
					t.Fatal(err)
				}
				sidecar.setAPIServer(api)
				sidecar.setEventRouter(router)
				sidecar.setGuardrailProxy(proxy)
			} else {
				sidecar.setAPIServer(api)
				sidecar.setEventRouter(router)
				sidecar.setGuardrailProxy(proxy)
				if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
					t.Fatal(err)
				}
			}
			if sidecar.observabilityV8LifecycleRuntime() != fixture.runtime ||
				api.observabilityV8RuntimeEmitter() != fixture.runtime ||
				api.observabilityV8CanaryRuntime() != fixture.runtime ||
				api.observabilityV8LocalOnlyRuntime() != fixture.runtime ||
				api.observabilityV8LifecycleRuntime() != fixture.runtime ||
				router.observabilityV8LifecycleRuntime() != fixture.runtime ||
				proxy.observabilityV8TraceRuntime() != fixture.runtime {
				t.Fatalf(
					"lifecycle bindings sidecar=%T api=%T router=%T proxy=%T",
					sidecar.observabilityV8LifecycleRuntime(), api.observabilityV8LifecycleRuntime(),
					router.observabilityV8LifecycleRuntime(), proxy.observabilityV8TraceRuntime(),
				)
			}
		})
	}
}

func TestSidecarBindsAndDetachesOperationalMetricConsumers(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	judgeStore := &JudgeStore{}
	webhooks := &WebhookDispatcher{}
	sidecar := &Sidecar{judgeStore: judgeStore, webhooks: webhooks}
	if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
		t.Fatal(err)
	}
	if judgeStore.observabilityV8Snapshot() != fixture.runtime ||
		webhooks.observabilityV8Snapshot() != fixture.runtime {
		t.Fatalf("operational consumers were not bound judge=%T webhook=%T",
			judgeStore.observabilityV8Snapshot(), webhooks.observabilityV8Snapshot())
	}

	sidecar.observabilityV8Mu.Lock()
	sidecar.observabilityV8ConsumersDetached = true
	sidecar.bindObservabilityV8ConsumersLocked()
	sidecar.observabilityV8Mu.Unlock()
	if judgeStore.observabilityV8Snapshot() != nil || webhooks.observabilityV8Snapshot() != nil {
		t.Fatal("operational consumers retained the runtime after detach")
	}
}

func TestSidecarConcurrentConsumerConstructionAndRuntimeBindIsAtomic(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	for iteration := 0; iteration < 64; iteration++ {
		sidecar := &Sidecar{}
		api := &APIServer{}
		router := &EventRouter{}
		proxy := &GuardrailProxy{}
		start := make(chan struct{})
		errCh := make(chan error, 1)
		done := make(chan struct{}, 1)
		go func() {
			<-start
			sidecar.setAPIServer(api)
			sidecar.setEventRouter(router)
			sidecar.setGuardrailProxy(proxy)
			done <- struct{}{}
		}()
		go func() {
			<-start
			errCh <- sidecar.BindObservabilityRuntime(fixture.runtime)
		}()
		close(start)
		<-done
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
		if sidecar.observabilityV8LifecycleRuntime() != fixture.runtime ||
			api.observabilityV8RuntimeEmitter() != fixture.runtime ||
			api.observabilityV8CanaryRuntime() != fixture.runtime ||
			api.observabilityV8LocalOnlyRuntime() != fixture.runtime ||
			api.observabilityV8LifecycleRuntime() != fixture.runtime ||
			router.observabilityV8LifecycleRuntime() != fixture.runtime ||
			proxy.observabilityV8TraceRuntime() != fixture.runtime {
			t.Fatalf("iteration %d observed a partially published runtime", iteration)
		}
	}
}

func TestSidecarReplacementDetachesEveryRuntimeSeamFromOldConsumer(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	sidecar := &Sidecar{}
	if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
		t.Fatal(err)
	}
	oldAPI, nextAPI := &APIServer{}, &APIServer{}
	oldRouter, nextRouter := &EventRouter{}, &EventRouter{}
	oldProxy, nextProxy := &GuardrailProxy{}, &GuardrailProxy{}
	sidecar.setAPIServer(oldAPI)
	sidecar.setEventRouter(oldRouter)
	sidecar.setGuardrailProxy(oldProxy)
	sidecar.setAPIServer(nextAPI)
	sidecar.setEventRouter(nextRouter)
	sidecar.setGuardrailProxy(nextProxy)

	if oldAPI.observabilityV8RuntimeEmitter() != nil ||
		oldAPI.observabilityV8CanaryRuntime() != nil ||
		oldAPI.observabilityV8LocalOnlyRuntime() != nil ||
		oldAPI.observabilityV8LifecycleRuntime() != nil ||
		oldRouter.observabilityV8LifecycleRuntime() != nil ||
		oldProxy.observabilityV8TraceRuntime() != nil {
		t.Fatal("replaced consumer retained a runtime acquisition seam")
	}
	if nextAPI.observabilityV8RuntimeEmitter() != fixture.runtime ||
		nextAPI.observabilityV8CanaryRuntime() != fixture.runtime ||
		nextAPI.observabilityV8LocalOnlyRuntime() != fixture.runtime ||
		nextAPI.observabilityV8LifecycleRuntime() != fixture.runtime ||
		nextRouter.observabilityV8LifecycleRuntime() != fixture.runtime ||
		nextProxy.observabilityV8TraceRuntime() != fixture.runtime {
		t.Fatal("replacement consumer did not receive the active runtime")
	}

	sidecar.setAPIServer(nil)
	sidecar.setEventRouter(nil)
	sidecar.setGuardrailProxy(nil)
	if nextAPI.observabilityV8RuntimeEmitter() != nil ||
		nextAPI.observabilityV8CanaryRuntime() != nil ||
		nextAPI.observabilityV8LocalOnlyRuntime() != nil ||
		nextAPI.observabilityV8LifecycleRuntime() != nil ||
		nextRouter.observabilityV8LifecycleRuntime() != nil ||
		nextProxy.observabilityV8TraceRuntime() != nil {
		t.Fatal("cleared consumer retained a runtime acquisition seam")
	}
}

func TestSidecarBindsProcessOwnedRuntimeToEveryAPIV8Seam(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	sidecar := &Sidecar{}
	if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
		t.Fatal(err)
	}
	api := &APIServer{}
	sidecar.bindAPIServerObservabilityV8(api)
	if api.observabilityV8RuntimeEmitter() != fixture.runtime ||
		api.observabilityV8CanaryRuntime() != fixture.runtime ||
		api.observabilityV8LocalOnlyRuntime() != fixture.runtime ||
		api.observabilityV8LifecycleRuntime() != fixture.runtime {
		t.Fatalf(
			"api bindings ordinary=%T canary=%T local=%T lifecycle=%T",
			api.observabilityV8RuntimeEmitter(), api.observabilityV8CanaryRuntime(),
			api.observabilityV8LocalOnlyRuntime(),
			api.observabilityV8LifecycleRuntime(),
		)
	}
	if _, metricCapable := api.observabilityV8RuntimeEmitter().(otlpGeneratedMetricRuntime); !metricCapable {
		t.Fatal("production API v8 binding lost generated metric capability")
	}
}

type fakeSidecarEmitter struct {
	emit func(context.Context, router.Metadata, observabilityruntime.EmitBuilder) (pipeline.LocalLogOutcome, error)
}

func (emitter *fakeSidecarEmitter) Emit(
	ctx context.Context,
	metadata router.Metadata,
	builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return emitter.emit(ctx, metadata, builder)
}

func TestSidecarBoundFailureFailsRunWithoutPersistence(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	sidecar := &Sidecar{
		cfg:    &config.Config{ConfigVersion: config.ObservabilityV8ConfigVersion},
		logger: audit.NewLogger(fixture.store),
	}
	if err := sidecar.bindObservabilityRuntime(&fakeSidecarEmitter{emit: func(
		context.Context, router.Metadata, observabilityruntime.EmitBuilder,
	) (pipeline.LocalLogOutcome, error) {
		return pipeline.LocalLogOutcome{}, errors.New("unbounded backend detail")
	}}); err != nil {
		t.Fatal(err)
	}
	err := sidecar.Run(t.Context())
	var bounded *sidecarObservabilityError
	if !errors.As(err, &bounded) || bounded.Code() != sidecarObservabilityEmitFailed ||
		err.Error() == "unbounded backend detail" {
		t.Fatalf("run error=%v", err)
	}
	if rows := readStoredSidecarLifecycle(t, fixture.path); len(rows) != 0 {
		t.Fatalf("bound failure persisted lifecycle rows: %#v", rows)
	}
}

func TestSidecarMandatoryLifecycleBypassesDisabledCollection(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, false)
	sidecar := &Sidecar{logger: audit.NewLogger(fixture.store)}
	if err := sidecar.BindObservabilityRuntime(fixture.runtime); err != nil {
		t.Fatal(err)
	}
	if err := sidecar.recordSidecarLifecycle(t.Context(), audit.ActionSidecarStart); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := sidecar.recordSidecarLifecycle(canceled, audit.ActionSidecarStop); err != nil {
		t.Fatal(err)
	}
	if rows := readStoredSidecarLifecycle(t, fixture.path); len(rows) != 2 {
		t.Fatalf("mandatory lifecycle floor rows=%d, want 2: %#v", len(rows), rows)
	} else {
		for _, row := range rows {
			if row.bucket != string(observability.BucketPlatformHealth) ||
				row.eventName != "subsystem.lifecycle" {
				t.Fatalf("mandatory lifecycle floor row=%#v", row)
			}
		}
	}
}

func TestSidecarAmbiguousBoundOutcomeDoesNotPersist(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	sidecar := &Sidecar{logger: audit.NewLogger(fixture.store)}
	if err := sidecar.bindObservabilityRuntime(&fakeSidecarEmitter{emit: func(
		_ context.Context,
		_ router.Metadata,
		builder observabilityruntime.EmitBuilder,
	) (pipeline.LocalLogOutcome, error) {
		// A real Runtime never builds a record and then reports AdmissionDrop.
		// Exercise the bridge's defensive ambiguity check without granting the
		// fake access to LocalLogOutcome's private persistence fields.
		_, _ = builder(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
		return pipeline.LocalLogOutcome{}, nil
	}}); err != nil {
		t.Fatal(err)
	}
	err := sidecar.recordSidecarLifecycle(t.Context(), audit.ActionSidecarStart)
	var bounded *sidecarObservabilityError
	if !errors.As(err, &bounded) || bounded.Code() != sidecarObservabilityAmbiguous {
		t.Fatalf("ambiguous outcome error=%v", err)
	}
	if rows := readStoredSidecarLifecycle(t, fixture.path); len(rows) != 0 {
		t.Fatalf("ambiguous outcome persisted lifecycle rows: %#v", rows)
	}
}

func TestSidecarUnboundLifecycleFailsWithoutPersistence(t *testing.T) {
	fixture := newSidecarRuntimeFixture(t, true)
	sidecar := &Sidecar{logger: audit.NewLogger(fixture.store)}
	err := sidecar.recordSidecarLifecycle(t.Context(), audit.ActionSidecarStart)
	var bounded *sidecarObservabilityError
	if !errors.As(err, &bounded) || bounded.Code() != sidecarObservabilityInvalidBinding {
		t.Fatalf("unbound lifecycle error=%v", err)
	}
	rows := readStoredSidecarLifecycle(t, fixture.path)
	if len(rows) != 0 {
		t.Fatalf("unbound lifecycle rows=%#v", rows)
	}
}

var _ sidecarRuntimeEmitter = (*fakeSidecarEmitter)(nil)
var _ runtimegraph.Reporter = (*discardSidecarGraphReporter)(nil)
