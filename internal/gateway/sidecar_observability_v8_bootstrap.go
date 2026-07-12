// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/localobservability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/prometheus"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/push"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

const sidecarObservabilityV8CloseTimeout = 30 * time.Second

type sidecarObservabilityV8BootstrapErrorCode string

const (
	sidecarObservabilityV8BootstrapInvalid      sidecarObservabilityV8BootstrapErrorCode = "invalid_input"
	sidecarObservabilityV8BootstrapCompile      sidecarObservabilityV8BootstrapErrorCode = "config_rejected"
	sidecarObservabilityV8BootstrapStore        sidecarObservabilityV8BootstrapErrorCode = "store_unavailable"
	sidecarObservabilityV8BootstrapRedaction    sidecarObservabilityV8BootstrapErrorCode = "redaction_unavailable"
	sidecarObservabilityV8BootstrapReporter     sidecarObservabilityV8BootstrapErrorCode = "reporter_unavailable"
	sidecarObservabilityV8BootstrapDestinations sidecarObservabilityV8BootstrapErrorCode = "destinations_unavailable"
	sidecarObservabilityV8BootstrapRuntime      sidecarObservabilityV8BootstrapErrorCode = "runtime_unavailable"
	sidecarObservabilityV8BootstrapBinding      sidecarObservabilityV8BootstrapErrorCode = "binding_rejected"
	sidecarObservabilityV8BootstrapReload       sidecarObservabilityV8BootstrapErrorCode = "reload_rejected"
	sidecarObservabilityV8BootstrapClose        sidecarObservabilityV8BootstrapErrorCode = "shutdown_degraded"
)

// sidecarObservabilityV8BootstrapError is content-free. Config validation
// remains the operator-facing source-location boundary; runtime assembly must
// not return database paths, endpoints, secret references, or driver errors.
type sidecarObservabilityV8BootstrapError struct {
	code  sidecarObservabilityV8BootstrapErrorCode
	cause error
}

func (err *sidecarObservabilityV8BootstrapError) Error() string {
	if err == nil {
		return "sidecar observability v8 bootstrap failed"
	}
	message := "sidecar observability v8 bootstrap failed: " + string(err.code)
	// KeyStoreError contains only a bounded enum specifically documented as
	// safe for health telemetry. Preserve that diagnostic precision without
	// exposing a path, ACL, key material, or raw operating-system error.
	var keyErr *redaction.KeyStoreError
	if err.code == sidecarObservabilityV8BootstrapRedaction && errors.As(err.cause, &keyErr) {
		message += ":" + string(keyErr.Code)
	}
	return message
}

func (err *sidecarObservabilityV8BootstrapError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *sidecarObservabilityV8BootstrapError) Code() sidecarObservabilityV8BootstrapErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// BootstrapObservabilityRuntime validates and assembles the complete
// observability-v8 graph before Sidecar.Run starts serving. A non-v8 document is
// rejected without mutating runtime state. A v8 document is parsed through the authoritative schema/compiler in this
// method. Assembly or binding failure returns an error and leaves the Sidecar
// unbound, so a caller cannot accidentally serve with a partial v8 runtime.
func (s *Sidecar) BootstrapObservabilityRuntime(
	ctx context.Context,
	sourceName string,
	raw []byte,
) (bool, error) {
	if s == nil || ctx == nil || strings.TrimSpace(sourceName) == "" || len(raw) == 0 {
		return false, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	configVersion, err := sidecarObservabilityConfigVersion(raw)
	if err != nil {
		return false, err
	}
	if configVersion != 8 {
		return false, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	cfg := s.currentConfig()
	if cfg == nil || cfg.ConfigVersion != 8 || strings.TrimSpace(cfg.DataDir) == "" {
		return false, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	s.observabilityV8Mu.Lock()
	alreadyBound := s.observabilityV8 != nil || s.observabilityV8Run
	s.observabilityV8Mu.Unlock()
	if alreadyBound {
		return false, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapBinding, nil)
	}
	compiled, err := config.ParseCompileObservabilityV8(
		sourceName,
		raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: cfg.DataDir},
	)
	if err != nil || compiled == nil || compiled.Plan == nil {
		if err != nil {
			return false, err
		}
		return false, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapCompile, nil)
	}
	owner, err := s.prepareObservabilityV8Runtime(ctx, compiled)
	if err != nil {
		return false, err
	}
	if err := s.bindObservabilityRuntime(owner); err != nil {
		_ = owner.closeWithTimeout()
		return false, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapBinding, err)
	}
	if s.logger != nil {
		s.logger.SetRuntimeV8Emitter(owner)
	}
	return true, nil
}

// ReloadObservabilityRuntime validates a complete v8 document before asking
// the existing process-owned Runtime to transactionally publish a successor
// graph. v7 documents and data-directory changes are rejected; neither can
// mutate the active generation.
func (s *Sidecar) ReloadObservabilityRuntime(
	ctx context.Context,
	sourceName string,
	raw []byte,
) (runtimegraph.ReloadResult, error) {
	if s == nil || ctx == nil || strings.TrimSpace(sourceName) == "" || len(raw) == 0 {
		return runtimegraph.ReloadResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	version, err := sidecarObservabilityConfigVersion(raw)
	if err != nil || version != 8 {
		if err != nil {
			return runtimegraph.ReloadResult{}, err
		}
		return runtimegraph.ReloadResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapCompile, nil)
	}
	s.observabilityV8Mu.Lock()
	owner, ok := s.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	s.observabilityV8Mu.Unlock()
	if !ok || owner == nil {
		return runtimegraph.ReloadResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	compiled, compileErr := config.ParseCompileObservabilityV8(
		sourceName,
		raw,
		config.ObservabilityV8CompileOptions{DefaultDataDir: owner.dataDir},
	)
	if compileErr != nil || compiled == nil || compiled.Plan == nil ||
		filepath.Clean(compiled.DataDir) != owner.dataDir {
		if compileErr != nil {
			return runtimegraph.ReloadResult{}, compileErr
		}
		return runtimegraph.ReloadResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapCompile, nil)
	}
	result, reloadErr := owner.reload(ctx, compiled.Plan, owner.retainJudgeBodies)
	if reloadErr != nil {
		return result, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapReload, reloadErr)
	}
	return result, nil
}

func (s *Sidecar) prepareObservabilityV8Runtime(
	ctx context.Context,
	compiled *config.ObservabilityV8CompiledConfig,
) (*sidecarOwnedObservabilityV8Runtime, error) {
	if s == nil || ctx == nil || compiled == nil || compiled.Plan == nil || s.store == nil ||
		!s.store.Ready() || s.currentConfig() == nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	snapshot := compiled.Plan.Snapshot()
	if snapshot.Local.Path == "" || filepath.Clean(snapshot.Local.Path) != filepath.Clean(s.store.DatabasePath()) {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapStore, nil)
	}
	if s.judgeBodyStore != nil {
		configuredJudgePath := strings.TrimSpace(s.currentConfig().JudgeBodiesDB)
		if configuredJudgePath == "" {
			configuredJudgePath = filepath.Join(compiled.DataDir, config.DefaultJudgeBodiesDBName)
		}
		if filepath.Clean(snapshot.Local.JudgeBodiesPath) != filepath.Clean(configuredJudgePath) {
			return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapStore, nil)
		}
	}
	key, err := redaction.LoadOrCreateCorrelationKey(compiled.DataDir)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapRedaction, err)
	}
	engine, err := redaction.NewEngineWithCorrelationKey(key)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapRedaction, err)
	}
	signer, err := pipeline.NewCorrelationKeyProjectionIntegritySigner(key)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapRedaction, err)
	}
	processRunID := gatewaylog.ProcessRunID()
	if processRunID == "" {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapReporter, nil)
	}
	binaryVersion := version.Current().BinaryVersion
	if binaryVersion == "" {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapReporter, nil)
	}
	reporter, err := observabilityruntime.NewReloadReporter(
		s.store, engine, signer, processRunID, binaryVersion,
	)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapReporter, err)
	}
	failureBuilder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapRuntime, err)
	}
	reaper, err := audit.NewRetentionReaper(
		s.store, s.judgeBodyStore, int64(snapshot.Local.RetentionDays), audit.RetentionOptions{},
	)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapRuntime, err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{Reporter: sidecarV8RetentionObserver{s: s}},
	)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapRuntime, err)
	}
	deliveryObserver := delivery.ObserverFunc(func(transition delivery.HealthTransition) {
		s.observeObservabilityV8Delivery(transition)
	})
	destinationFactory, err := destinations.NewFactory(destinations.Options{
		ConsoleStream: destinations.ConsoleStderr,
		Stdout:        os.Stdout, Stderr: os.Stderr,
		Secrets:  sidecarObservabilityV8SecretResolver{},
		CALoader: destinations.CAFileLoaderFunc(sidecarLoadObservabilityV8CA),
		Resolver: net.DefaultResolver, Dialer: &net.Dialer{},
		Warnings: push.WarningObserverFunc(func(warning push.Warning) {
			s.observeObservabilityV8Warning(warning)
		}),
		RedactionEngine: engine, DeliveryObserver: deliveryObserver,
		OTLPCanonicalObserver: otlp.CanonicalObserverFunc(func(failure otlp.CanonicalFailure) {
			s.observeObservabilityV8OTLP(failure)
		}),
		GalileoObserver: galileo.CanonicalObserverFunc(func(failure galileo.CanonicalFailure) {
			s.observeObservabilityV8Galileo(failure)
		}),
		LocalObserver: localobservability.ObserverFunc(func(failure localobservability.Failure) {
			s.observeObservabilityV8Local(failure)
		}),
	})
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapDestinations, err)
	}
	cfg := s.currentConfig()
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: binaryVersion, Environment: cfg.Environment,
		ServiceInstanceID:     gatewaylog.SidecarInstanceID(),
		DefenseClawInstanceID: gatewaylog.SidecarInstanceID(),
		TenantID:              cfg.TenantID, WorkspaceID: cfg.WorkspaceID,
		DeploymentMode: cfg.DeploymentMode, ConnectorMode: string(cfg.Claw.Mode),
		DiscoverySource: cfg.DiscoverySource, DeviceKeyFile: cfg.Gateway.DeviceKeyFile,
		GenerationPipelines: destinationFactory.GenerationPipelineFactory(prometheus.Options{}),
	})
	retainJudgeBodies := s.judgeStore != nil && s.judgeStore.RetainsJudgeBodies()
	runtime, err := observabilityruntime.New(
		ctx,
		runtimegraph.ConfigFromPlan(compiled.Plan, retainJudgeBodies),
		observabilityruntime.Options{
			Store: s.store, Engine: engine, Signer: signer,
			RecordBuilder: failureBuilder, Reporter: reporter,
			EventHistoryHealthReporter: sidecarV8EventHistoryObserver{s: s},
			RetentionController:        retention,
			DestinationAdapterFactory:  destinationFactory,
			DestinationObserver:        deliveryObserver,
			TelemetryProviderFactory:   providerFactory,
		},
	)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapRuntime, err)
	}
	return &sidecarOwnedObservabilityV8Runtime{
		runtime: runtime, dataDir: filepath.Clean(compiled.DataDir),
		retainJudgeBodies: retainJudgeBodies,
	}, nil
}

type sidecarOwnedObservabilityV8Runtime struct {
	runtime           *observabilityruntime.Runtime
	dataDir           string
	retainJudgeBodies bool
	lifecycleMu       sync.RWMutex
	closed            bool
}

func (owner *sidecarOwnedObservabilityV8Runtime) ApplyAlertAcknowledgement(
	ctx context.Context,
	command audit.AlertAcknowledgementCommand,
) (audit.AlertAcknowledgementResult, error) {
	if owner == nil || owner.runtime == nil {
		return audit.AlertAcknowledgementResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return audit.AlertAcknowledgementResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.ApplyAlertAcknowledgement(ctx, command)
}

var _ otlpGeneratedMetricRuntime = (*sidecarOwnedObservabilityV8Runtime)(nil)
var _ otlpInboundImportRuntime = (*sidecarOwnedObservabilityV8Runtime)(nil)

func (owner *sidecarOwnedObservabilityV8Runtime) BeginInboundImportBatch(
	ctx context.Context,
) (*observabilityruntime.InboundImportBatch, error) {
	if owner == nil || owner.runtime == nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	// The returned runtime-graph lease, rather than this owner mutex, pins the
	// generation until batch.Close. Runtime shutdown already waits for retired
	// leases, so holding lifecycleMu across request processing would only create
	// an unnecessary shutdown lock dependency.
	return owner.runtime.BeginInboundImportBatch(ctx)
}

func (owner *sidecarOwnedObservabilityV8Runtime) Emit(
	ctx context.Context,
	metadata router.Metadata,
	builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	if owner == nil || owner.runtime == nil {
		return pipeline.LocalLogOutcome{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return pipeline.LocalLogOutcome{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.Emit(ctx, metadata, builder)
}

func (owner *sidecarOwnedObservabilityV8Runtime) EmitLocalOnly(
	ctx context.Context,
	metadata router.Metadata,
	builder observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	if owner == nil || owner.runtime == nil {
		return pipeline.LocalLogOutcome{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return pipeline.LocalLogOutcome{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.EmitLocalOnly(ctx, metadata, builder)
}

// EmitRuntimeV8 adapts the audit package's cycle-free producer seam to
// the generation-pinned runtime builder contract. The adapter never derives
// provenance from the legacy process-global version state: both generation
// and digest come from the exact graph lease that admitted this emission.
func (owner *sidecarOwnedObservabilityV8Runtime) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	if builder == nil {
		return audit.RuntimeV8EmitOutcome{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	outcome, err := owner.Emit(
		ctx,
		metadata,
		func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
			return builder(audit.RuntimeV8BuildContext{
				ConfigGeneration: snapshot.Generation(),
				ConfigDigest:     snapshot.Digest(),
			}, admission)
		},
	)
	return audit.RuntimeV8EmitOutcome{
		Admission: outcome.Admission(), LocalPersisted: outcome.LocalPersisted(),
	}, err
}

// EmitRuntimeV8LogBatch adapts audit's opaque generated operations to the
// runtime's short-lived generation-pinned batch. Collection, local
// persistence, redaction, and destination routing remain independent per
// operation; only the immutable generation lease is shared.
func (owner *sidecarOwnedObservabilityV8Runtime) EmitRuntimeV8LogBatch(
	ctx context.Context,
	operations []audit.RuntimeV8LogOperation,
) ([]audit.RuntimeV8EmitOutcome, error) {
	if owner == nil || owner.runtime == nil || ctx == nil || len(operations) == 0 ||
		len(operations) > observabilityruntime.MaxLogBatchItems {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	items := make([]observabilityruntime.LogBatchItem, len(operations))
	for index := range operations {
		operation := operations[index]
		items[index] = observabilityruntime.LogBatchItem{
			Context: operation.Context(), Metadata: operation.Metadata(),
			Builder: func(snapshot observabilityruntime.EmitContext, admission router.Admission) (observability.Record, error) {
				return operation.Build(audit.RuntimeV8BuildContext{
					ConfigGeneration: snapshot.Generation(), ConfigDigest: snapshot.Digest(),
				}, admission)
			},
		}
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	outcomes, err := owner.runtime.EmitBatch(ctx, items)
	converted := make([]audit.RuntimeV8EmitOutcome, len(outcomes))
	for index := range outcomes {
		converted[index] = audit.RuntimeV8EmitOutcome{
			Admission: outcomes[index].Admission(), LocalPersisted: outcomes[index].LocalPersisted(),
		}
	}
	return converted, err
}

func (owner *sidecarOwnedObservabilityV8Runtime) EmitTraceCanary(
	ctx context.Context,
	destination string,
) (observabilityruntime.TraceCanaryResult, error) {
	if owner == nil || owner.runtime == nil {
		return observabilityruntime.TraceCanaryResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return observabilityruntime.TraceCanaryResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.EmitTraceCanary(ctx, destination)
}

// EmitRuntimeV8AssetScanTrace adapts audit's cycle-free one-shot scan seam to
// the generated runtime. No SDK span handle or mutable provider crosses the
// package boundary.
func (owner *sidecarOwnedObservabilityV8Runtime) EmitRuntimeV8AssetScanTrace(
	ctx context.Context,
	input observability.SpanAssetScanInput,
) error {
	if owner == nil || owner.runtime == nil || ctx == nil {
		return newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.EmitAssetScanTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) RecordGeneratedMetric(
	ctx context.Context,
	family observability.EventName,
	builder observabilityruntime.GeneratedMetricBuilder,
) (telemetry.V8MetricRecordResult, error) {
	if owner == nil || owner.runtime == nil {
		return telemetry.V8MetricRecordResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return telemetry.V8MetricRecordResult{}, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.RecordGeneratedMetric(ctx, family, builder)
}

func (owner *sidecarOwnedObservabilityV8Runtime) DestinationHealthSnapshot(
	ctx context.Context,
) (observabilityruntime.DestinationHealthSnapshot, error) {
	if owner == nil || owner.runtime == nil || ctx == nil {
		return observabilityruntime.DestinationHealthSnapshot{},
			newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	// Runtime's graph manager is the synchronization authority for this
	// read-only lease. Avoid the owner's shutdown mutex here so a health request
	// remains context-bounded while Close is waiting on graph retirement.
	return owner.runtime.DestinationHealthSnapshot(ctx)
}

func (owner *sidecarOwnedObservabilityV8Runtime) StartAgentTrace(
	ctx context.Context,
	input observability.SpanAgentInvokeInput,
) (context.Context, *observabilityruntime.AgentTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartAgentTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) StartAgentTransitionTrace(
	ctx context.Context,
	input observability.SpanAgentTransitionInput,
) (context.Context, *observabilityruntime.AgentTransitionTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartAgentTransitionTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) StartModelTrace(
	ctx context.Context,
	input observability.SpanModelChatInput,
) (context.Context, *observabilityruntime.ModelTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartModelTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) StartJudgeTrace(
	ctx context.Context,
	input observability.SpanGuardrailJudgeInput,
) (context.Context, *observabilityruntime.JudgeTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartJudgeTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) StartGuardrailApplyTrace(
	ctx context.Context,
	input observability.SpanGuardrailApplyInput,
) (context.Context, *observabilityruntime.GuardrailApplyTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartGuardrailApplyTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) StartToolTrace(
	ctx context.Context,
	input observability.SpanToolExecuteInput,
) (context.Context, *observabilityruntime.ToolTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartToolTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) StartApprovalTrace(
	ctx context.Context,
	input observability.SpanApprovalResolveInput,
) (context.Context, *observabilityruntime.ApprovalTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartApprovalTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) StartTelemetryReceiveTrace(
	ctx context.Context,
	input observability.SpanTelemetryReceiveInput,
) (context.Context, *observabilityruntime.TelemetryReceiveTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartTelemetryReceiveTrace(ctx, input)
}

func (owner *sidecarOwnedObservabilityV8Runtime) reload(
	ctx context.Context,
	plan *config.ObservabilityV8Plan,
	retainJudgeBodies bool,
) (runtimegraph.ReloadResult, *runtimegraph.Error) {
	if owner == nil || owner.runtime == nil {
		var manager *runtimegraph.Manager
		_, err := manager.Acquire(ctx)
		return runtimegraph.ReloadResult{}, err
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		var manager *runtimegraph.Manager
		_, err := manager.Acquire(ctx)
		return runtimegraph.ReloadResult{}, err
	}
	return owner.runtime.Reload(ctx, runtimegraph.ConfigFromPlan(plan, retainJudgeBodies))
}

func (owner *sidecarOwnedObservabilityV8Runtime) closeWithTimeout() error {
	ctx, cancel := context.WithTimeout(context.Background(), sidecarObservabilityV8CloseTimeout)
	defer cancel()
	return owner.close(ctx)
}

func (owner *sidecarOwnedObservabilityV8Runtime) close(ctx context.Context) error {
	if owner == nil || owner.runtime == nil {
		return nil
	}
	owner.lifecycleMu.Lock()
	defer owner.lifecycleMu.Unlock()
	if owner.closed {
		return nil
	}
	if err := owner.runtime.Close(ctx); err != nil {
		return newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, err)
	}
	owner.closed = true
	return nil
}

// closeOwnedObservabilityV8Runtime closes only bootstrap-owned runtimes. The
// public BindObservabilityRuntime path remains caller-owned for tests and
// embedders that provide an already-assembled canonical runtime.
func (s *Sidecar) closeOwnedObservabilityV8Runtime() error {
	if s == nil {
		return nil
	}
	s.observabilityV8Mu.Lock()
	owner, ok := s.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	s.observabilityV8Mu.Unlock()
	if !ok || owner == nil {
		return nil
	}
	// Stop new control-plane producers from acquiring this owner before Close
	// waits for already-started emissions. Sidecar shutdown has already joined
	// the config/API/proxy producers, so no selected v8 action can legitimately
	// fall back to the legacy path after this detach.
	if s.logger != nil {
		s.logger.SetRuntimeV8Emitter(nil)
	}
	// Generated trace producers must lose their acquisition seam before Close
	// begins waiting for leases already held by request-bounded handles. This
	// prevents a producer from extending shutdown by starting new work while an
	// older handle is completing.
	s.observabilityV8Mu.Lock()
	if s.observabilityV8 == owner {
		s.observabilityV8Lifecycle = nil
		s.observabilityV8ConsumersDetached = true
		s.bindObservabilityV8ConsumersLocked()
	}
	s.observabilityV8Mu.Unlock()
	if err := owner.closeWithTimeout(); err != nil {
		return err
	}
	if s.health != nil {
		s.health.clearObservabilityV8HealthSource()
	}
	s.observabilityV8Mu.Lock()
	if s.observabilityV8 == owner {
		s.observabilityV8 = nil
		s.observabilityV8Lifecycle = nil
	}
	s.observabilityV8Mu.Unlock()
	return nil
}

// observabilityV8ActivePlanDigest returns the plan identity actually owned by
// the live graph. ConfigManager must seed from this value rather than rereading
// config.yaml: the file can legitimately change after bootstrap but before the
// watcher starts, and treating that newer file as already active would suppress
// the first required reload.
func (s *Sidecar) observabilityV8ActivePlanDigest() string {
	plan := s.observabilityV8ActivePlan()
	if plan == nil {
		return ""
	}
	return plan.Digest()
}

func (s *Sidecar) observabilityV8ActivePlan() *config.ObservabilityV8Plan {
	if s == nil {
		return nil
	}
	s.observabilityV8Mu.Lock()
	owner, ok := s.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
	s.observabilityV8Mu.Unlock()
	if !ok || owner == nil || owner.runtime == nil {
		return nil
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed || owner.runtime.Active() == nil {
		return nil
	}
	return owner.runtime.Active().Plan()
}

type sidecarObservabilityV8SecretResolver struct{}

func (sidecarObservabilityV8SecretResolver) ResolveObservabilitySecret(name string) (string, bool) {
	if value, ok := config.GetKey(name); ok && strings.TrimSpace(value) != "" {
		return value, true
	}
	value, ok := os.LookupEnv(name)
	return value, ok && strings.TrimSpace(value) != ""
}

func sidecarLoadObservabilityV8CA(ctx context.Context, path string) ([]byte, error) {
	if ctx == nil || strings.TrimSpace(path) == "" {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapInvalid, nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapDestinations, nil)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func sidecarObservabilityConfigVersion(raw []byte) (int, error) {
	if len(raw) > config.V8YAMLMaxSourceBytes {
		return 0, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapCompile, nil)
	}
	var envelope struct {
		ConfigVersion int `yaml:"config_version"`
	}
	if err := yaml.Unmarshal(raw, &envelope); err != nil {
		return 0, err
	}
	return envelope.ConfigVersion, nil
}

func (s *Sidecar) observeObservabilityV8Delivery(transition delivery.HealthTransition) {
	if s == nil || s.health == nil {
		return
	}
	if transition.Generation == 0 || transition.OccurredAt.IsZero() {
		return
	}
	if transition.Current == delivery.HealthDegraded || transition.Current == delivery.HealthFailing {
		s.health.observeObservabilityV8Failure(
			transition.Destination, transition.Generation, string(transition.Reason), transition.OccurredAt,
		)
	}
}

func (s *Sidecar) observeObservabilityV8Warning(warning push.Warning) {
	// Preparation warnings have no graph generation and may belong to a
	// candidate that is never published. The effective plan already exposes
	// them; live destination state must not attach them to an active generation.
	_ = s
	_ = warning
}

func (s *Sidecar) observeObservabilityV8Galileo(failure galileo.CanonicalFailure) {
	if s == nil || s.health == nil {
		return
	}
	s.health.observeObservabilityV8Failure(
		failure.Destination, failure.Generation, string(failure.Code), time.Now().UTC(),
	)
}

func (s *Sidecar) observeObservabilityV8OTLP(failure otlp.CanonicalFailure) {
	if s == nil || s.health == nil {
		return
	}
	s.health.observeObservabilityV8Failure(
		failure.Destination, failure.Generation, string(failure.Code), time.Now().UTC(),
	)
}

func (s *Sidecar) observeObservabilityV8Local(failure localobservability.Failure) {
	if s == nil || s.health == nil {
		return
	}
	s.health.observeObservabilityV8Failure(
		failure.Destination, failure.Generation, string(failure.Code), time.Now().UTC(),
	)
}

type sidecarV8RetentionObserver struct{ s *Sidecar }

func (observer sidecarV8RetentionObserver) ReportRetentionController(
	status observabilityruntime.RetentionControllerStatus,
) {
	if observer.s == nil || observer.s.health == nil {
		return
	}
	observer.s.health.setObservabilityV8Retention(
		string(status.State), status.RetentionDays, string(status.Failure),
	)
}

type sidecarV8EventHistoryObserver struct{ s *Sidecar }

func (observer sidecarV8EventHistoryObserver) ReportEventHistoryHealth(
	code audit.EventHistoryHealthCode,
) {
	if observer.s == nil || observer.s.health == nil {
		return
	}
	observer.s.health.setObservabilityV8EventHistoryFailure(string(code))
}

func newSidecarObservabilityV8BootstrapError(
	code sidecarObservabilityV8BootstrapErrorCode,
	cause error,
) error {
	var keyErr *redaction.KeyStoreError
	switch {
	case cause == context.Canceled:
		cause = context.Canceled
	case cause == context.DeadlineExceeded:
		cause = context.DeadlineExceeded
	case errors.As(cause, &keyErr):
		// Copy only the bounded code. Never retain an outer wrapper or any
		// operating-system/path context that may accompany it.
		cause = &redaction.KeyStoreError{Code: keyErr.Code}
	default:
		cause = nil
	}
	return &sidecarObservabilityV8BootstrapError{code: code, cause: cause}
}

var (
	_ sidecarRuntimeEmitter                = (*sidecarOwnedObservabilityV8Runtime)(nil)
	_ sidecarRuntimeCanaryEmitter          = (*sidecarOwnedObservabilityV8Runtime)(nil)
	_ sidecarRuntimeLocalOnlyEmitter       = (*sidecarOwnedObservabilityV8Runtime)(nil)
	_ lifecycleV8Runtime                   = (*sidecarOwnedObservabilityV8Runtime)(nil)
	_ audit.RuntimeV8Emitter               = (*sidecarOwnedObservabilityV8Runtime)(nil)
	_ config.ObservabilityV8SecretResolver = sidecarObservabilityV8SecretResolver{}
)
