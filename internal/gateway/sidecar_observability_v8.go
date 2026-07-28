// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
)

const sidecarLifecycleStopPersistTimeout = 5 * time.Second

type sidecarRuntimeEmitter interface {
	Emit(
		context.Context,
		router.Metadata,
		observabilityruntime.EmitBuilder,
	) (pipeline.LocalLogOutcome, error)
}

type sidecarRuntimeLocalOnlyEmitter interface {
	EmitLocalOnly(
		context.Context,
		router.Metadata,
		observabilityruntime.EmitBuilder,
	) (pipeline.LocalLogOutcome, error)
}

// sidecarRuntimeCanaryEmitter is intentionally separate from
// sidecarRuntimeEmitter. Log-only test doubles and integrations do not need to
// implement the trace diagnostic, while the real v8 Runtime exposes both on
// the same generation-owned object.
type sidecarRuntimeCanaryEmitter interface {
	EmitTraceCanary(
		context.Context,
		string,
	) (observabilityruntime.TraceCanaryResult, error)
}

type sidecarObservabilityErrorCode string

const (
	sidecarObservabilityInvalidBinding sidecarObservabilityErrorCode = "invalid_binding"
	sidecarObservabilityAlreadyBound   sidecarObservabilityErrorCode = "already_bound"
	sidecarObservabilityRunStarted     sidecarObservabilityErrorCode = "run_started"
	sidecarObservabilityBuildFailed    sidecarObservabilityErrorCode = "record_build_failed"
	sidecarObservabilityEmitFailed     sidecarObservabilityErrorCode = "emit_failed"
	sidecarObservabilityAmbiguous      sidecarObservabilityErrorCode = "ambiguous_outcome"
)

// sidecarObservabilityError is deliberately bounded and content-free. In
// particular, it never retains the SQLite, redaction, or producer error that
// caused a canonical lifecycle write to fail.
type sidecarObservabilityError struct{ code sidecarObservabilityErrorCode }

func (err *sidecarObservabilityError) Error() string {
	if err == nil {
		return "sidecar observability lifecycle failed"
	}
	return "sidecar observability lifecycle failed: " + string(err.code)
}

func (err *sidecarObservabilityError) Code() sidecarObservabilityErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// BindObservabilityRuntime opts this Sidecar into the canonical v8 SQLite
// lifecycle path. It must be called exactly once before Run. The Runtime and
// its stores remain owned by the caller.
func (s *Sidecar) BindObservabilityRuntime(runtime *observabilityruntime.Runtime) error {
	if runtime == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	return s.bindObservabilityRuntime(runtime)
}

func (s *Sidecar) bindObservabilityRuntime(emitter sidecarRuntimeEmitter) error {
	if s == nil || emitter == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	s.observabilityV8Mu.Lock()
	if s.observabilityV8Run {
		s.observabilityV8Mu.Unlock()
		return &sidecarObservabilityError{code: sidecarObservabilityRunStarted}
	}
	if s.observabilityV8 != nil {
		s.observabilityV8Mu.Unlock()
		return &sidecarObservabilityError{code: sidecarObservabilityAlreadyBound}
	}
	s.observabilityV8 = emitter
	s.observabilityV8Lifecycle, _ = emitter.(lifecycleV8Runtime)
	s.observabilityV8ConsumersDetached = false
	s.bindObservabilityV8ConsumersLocked()
	s.observabilityV8Mu.Unlock()
	if source, ok := emitter.(observabilityV8HealthSource); ok && s.health != nil {
		s.health.bindObservabilityV8HealthSource(source)
	}
	return nil
}

func (s *Sidecar) beginObservabilityV8Run() error {
	if s == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	if s.observabilityV8Run {
		return &sidecarObservabilityError{code: sidecarObservabilityRunStarted}
	}
	// The target process must have completed mandatory runtime assembly before
	// any subsystem starts serving.
	if cfg := s.currentConfig(); cfg == nil || cfg.ConfigVersion != config.ObservabilityV8ConfigVersion || s.observabilityV8 == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}
	s.observabilityV8Run = true
	return nil
}

func (s *Sidecar) observabilityV8Emitter() sidecarRuntimeEmitter {
	if s == nil {
		return nil
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	return s.observabilityV8
}

func (s *Sidecar) observabilityV8LifecycleRuntime() lifecycleV8Runtime {
	if s == nil {
		return nil
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	if s.observabilityV8ConsumersDetached {
		return nil
	}
	return s.observabilityV8Lifecycle
}

func (s *Sidecar) observabilityV8CanaryEmitter() sidecarRuntimeCanaryEmitter {
	if s == nil {
		return nil
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	if s.observabilityV8ConsumersDetached {
		return nil
	}
	canary, _ := s.observabilityV8.(sidecarRuntimeCanaryEmitter)
	return canary
}

func (s *Sidecar) observabilityV8LocalOnlyEmitter() sidecarRuntimeLocalOnlyEmitter {
	if s == nil {
		return nil
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	if s.observabilityV8ConsumersDetached {
		return nil
	}
	localOnly, _ := s.observabilityV8.(sidecarRuntimeLocalOnlyEmitter)
	return localOnly
}

func (a *APIServer) bindTelemetryCanaryRuntime(emitter sidecarRuntimeCanaryEmitter) {
	if a == nil {
		return
	}
	a.observabilityV8Mu.Lock()
	a.observabilityV8Canary = emitter
	a.observabilityV8Mu.Unlock()
}

func (a *APIServer) bindLocalOnlyObservabilityRuntime(emitter sidecarRuntimeLocalOnlyEmitter) {
	if a == nil {
		return
	}
	a.observabilityV8Mu.Lock()
	a.observabilityV8LocalOnly = emitter
	a.observabilityV8Mu.Unlock()
}

func (a *APIServer) bindObservabilityV8Lifecycle(runtime lifecycleV8Runtime) {
	if a == nil {
		return
	}
	a.observabilityV8Mu.Lock()
	a.observabilityV8Lifecycle = runtime
	a.observabilityV8Mu.Unlock()
}

func (a *APIServer) bindObservabilityV8Runtimes(
	emitter sidecarRuntimeEmitter,
	canary sidecarRuntimeCanaryEmitter,
	localOnly sidecarRuntimeLocalOnlyEmitter,
	lifecycle lifecycleV8Runtime,
) {
	if a == nil {
		return
	}
	a.observabilityV8Mu.Lock()
	a.observabilityV8 = emitter
	a.observabilityV8Canary = canary
	a.observabilityV8LocalOnly = localOnly
	a.observabilityV8Lifecycle = lifecycle
	a.observabilityV8Mu.Unlock()
	metricRuntime, _ := lifecycle.(hookLifecycleMetricV8Runtime)
	if a.ciscoInspector != nil {
		a.ciscoInspector.bindObservabilityV8(metricRuntime)
	}
}

func (a *APIServer) observabilityV8RuntimeEmitter() sidecarRuntimeEmitter {
	if a == nil {
		return nil
	}
	a.observabilityV8Mu.RLock()
	defer a.observabilityV8Mu.RUnlock()
	return a.observabilityV8
}

func (a *APIServer) observabilityV8CanaryRuntime() sidecarRuntimeCanaryEmitter {
	if a == nil {
		return nil
	}
	a.observabilityV8Mu.RLock()
	defer a.observabilityV8Mu.RUnlock()
	return a.observabilityV8Canary
}

func (a *APIServer) observabilityV8LocalOnlyRuntime() sidecarRuntimeLocalOnlyEmitter {
	if a == nil {
		return nil
	}
	a.observabilityV8Mu.RLock()
	defer a.observabilityV8Mu.RUnlock()
	return a.observabilityV8LocalOnly
}

func (a *APIServer) observabilityV8LifecycleRuntime() lifecycleV8Runtime {
	if a == nil {
		return nil
	}
	a.observabilityV8Mu.RLock()
	defer a.observabilityV8Mu.RUnlock()
	return a.observabilityV8Lifecycle
}

func (r *EventRouter) bindObservabilityV8Capabilities(
	emitter sidecarRuntimeEmitter,
	lifecycle lifecycleV8Runtime,
) {
	if r == nil {
		return
	}
	r.observabilityV8LifecycleMu.Lock()
	r.observabilityV8Emitter = emitter
	r.observabilityV8Lifecycle = lifecycle
	if emitter != nil || lifecycle != nil {
		r.observabilityV8Authoritative = true
	}
	r.observabilityV8LifecycleMu.Unlock()
}

func (r *EventRouter) observabilityV8RuntimeEmitter() sidecarRuntimeEmitter {
	if r == nil {
		return nil
	}
	r.observabilityV8LifecycleMu.RLock()
	defer r.observabilityV8LifecycleMu.RUnlock()
	return r.observabilityV8Emitter
}

func (r *EventRouter) observabilityV8LifecycleRuntime() lifecycleV8Runtime {
	if r == nil {
		return nil
	}
	r.observabilityV8LifecycleMu.RLock()
	defer r.observabilityV8LifecycleMu.RUnlock()
	return r.observabilityV8Lifecycle
}

func (r *EventRouter) observabilityV8LifecycleSnapshot() (lifecycleV8Runtime, bool) {
	_, lifecycle, authoritative := r.observabilityV8CapabilitiesSnapshot()
	return lifecycle, authoritative
}

func (r *EventRouter) observabilityV8CapabilitiesSnapshot() (
	sidecarRuntimeEmitter,
	lifecycleV8Runtime,
	bool,
) {
	if r == nil {
		return nil, nil, false
	}
	r.observabilityV8LifecycleMu.RLock()
	defer r.observabilityV8LifecycleMu.RUnlock()
	return r.observabilityV8Emitter, r.observabilityV8Lifecycle, r.observabilityV8Authoritative
}

func (s *Sidecar) bindAPIServerObservabilityV8(api *APIServer) {
	if s == nil || api == nil {
		return
	}
	s.observabilityV8Mu.Lock()
	defer s.observabilityV8Mu.Unlock()
	s.bindAPIServerObservabilityV8Locked(api)
}

// bindAPIServerObservabilityV8Locked publishes the complete API capability set
// in one critical section. The caller MUST hold observabilityV8Mu.
func (s *Sidecar) bindAPIServerObservabilityV8Locked(api *APIServer) {
	if s == nil || api == nil {
		return
	}
	emitter := s.observabilityV8
	lifecycle := s.observabilityV8Lifecycle
	if s.observabilityV8ConsumersDetached {
		emitter = nil
		lifecycle = nil
	}
	canary, _ := emitter.(sidecarRuntimeCanaryEmitter)
	localOnly, _ := emitter.(sidecarRuntimeLocalOnlyEmitter)
	api.bindObservabilityV8Runtimes(emitter, canary, localOnly, lifecycle)
}

// bindObservabilityV8ConsumersLocked synchronizes runtime publication with
// consumer construction and shutdown. Lock order is observabilityV8Mu, then
// apiMu/proxyMu, then the consumer's own runtime lock. The caller MUST hold
// observabilityV8Mu; helpers invoked here must not reacquire it.
func (s *Sidecar) bindObservabilityV8ConsumersLocked() {
	emitter := s.observabilityV8
	lifecycle := s.observabilityV8Lifecycle
	if s.observabilityV8ConsumersDetached {
		emitter = nil
		lifecycle = nil
	}
	canary, _ := emitter.(sidecarRuntimeCanaryEmitter)
	localOnly, _ := emitter.(sidecarRuntimeLocalOnlyEmitter)
	judgeRuntime, _ := emitter.(judgeTraceV8Runtime)
	if judge := s.sharedJudge(); judge != nil {
		judge.bindJudgeTraceV8(judgeRuntime)
	}
	metricRuntime, _ := lifecycle.(hookLifecycleMetricV8Runtime)
	if s.judgeStore != nil {
		s.judgeStore.bindObservabilityV8(metricRuntime)
	}
	s.webhooksMu.RLock()
	if s.webhooks != nil {
		s.webhooks.BindObservabilityV8(metricRuntime)
	}
	s.webhooksMu.RUnlock()
	hiltRuntime, _ := emitter.(hiltObservabilityV8Runtime)
	if s.hilt != nil {
		s.hilt.bindObservabilityV8(hiltRuntime)
	}
	if discovery := s.aiDiscoverySnapshot(); discovery != nil {
		discovery.BindObservabilityV8(newAIDiscoveryV8Adapter(emitter))
	}

	s.apiMu.RLock()
	if api := s.apiServer; api != nil {
		api.bindObservabilityV8Runtimes(emitter, canary, localOnly, lifecycle)
	}
	s.apiMu.RUnlock()
	if s.router != nil {
		s.router.bindObservabilityV8Capabilities(emitter, lifecycle)
	}
	s.proxyMu.RLock()
	if proxy := s.guardrailProxy; proxy != nil {
		proxy.bindObservabilityV8TraceMode(lifecycle, true)
	}
	s.proxyMu.RUnlock()
}

func (s *Sidecar) recordSidecarLifecycle(ctx context.Context, action audit.Action) error {
	emitter := s.observabilityV8Emitter()
	if emitter == nil {
		return &sidecarObservabilityError{code: sidecarObservabilityInvalidBinding}
	}

	outcome, phase, healthState := observability.OutcomeAttempted, "startup", "starting"
	if action == audit.ActionSidecarStop {
		outcome, phase, healthState = observability.OutcomeCompleted, "shutdown", "stopped"
		// Run's lifecycle context is canceled before shutdown. Preserve all
		// correlation values while giving mandatory local persistence a fresh,
		// bounded cancellation budget.
		withoutCancellation := context.WithoutCancel(ctx)
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(withoutCancellation, sidecarLifecycleStopPersistTimeout)
		defer cancel()
	} else if action != audit.ActionSidecarStart {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}

	classification := observability.ClassificationContext{
		Bucket:      observability.BucketPlatformHealth,
		EventName:   observability.EventName(observability.TelemetryEventSubsystemLifecycle),
		RawSeverity: "INFO",
		MandatoryFacts: observability.MandatoryFacts{
			DurableHealthTransition: true,
		},
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerAuditAction,
		observability.ProducerKey(action),
		classification,
		observability.SourceGateway,
		"",
		observability.ProducerKey(action),
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	var builds atomic.Int32
	result, emitErr := emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		builds.Add(1)
		if snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		if admission != router.AdmissionOrdinary && admission != router.AdmissionFloor {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		return builder.BuildLogSubsystemLifecycle(observability.LogSubsystemLifecycleInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: observability.SourceGateway, Action: string(action), Phase: phase,
				Correlation: observability.Correlation{
					RunID:             gatewaylog.ProcessRunID(),
					SidecarInstanceID: gatewaylog.SidecarInstanceID(),
				},
				Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: version.Current().BinaryVersion,
					ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			},
			Severity: observability.Present(observability.SeverityInfo),
			LogLevel: observability.Present(observability.LogLevelInfo),
			Outcome:  outcome, DefenseClawHealthSubsystem: "sidecar",
			DefenseClawHealthState: healthState, MandatoryDurableHealthTransition: true,
		})
	})
	if emitErr != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityEmitFailed}
	}
	switch result.Admission() {
	case router.AdmissionDrop:
		if result.LocalPersisted() || builds.Load() != 0 {
			return &sidecarObservabilityError{code: sidecarObservabilityAmbiguous}
		}
		return nil
	case router.AdmissionOrdinary, router.AdmissionFloor:
		if !result.LocalPersisted() || builds.Load() != 1 {
			return &sidecarObservabilityError{code: sidecarObservabilityAmbiguous}
		}
		return nil
	default:
		return &sidecarObservabilityError{code: sidecarObservabilityAmbiguous}
	}
}

var _ sidecarRuntimeEmitter = (*observabilityruntime.Runtime)(nil)
var _ sidecarRuntimeCanaryEmitter = (*observabilityruntime.Runtime)(nil)
var _ sidecarRuntimeLocalOnlyEmitter = (*observabilityruntime.Runtime)(nil)
