// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// GeneratedTraceErrorCode is a fixed, content-free failure identity. The
// generated tracing API deliberately does not retain or return prompts, model
// output, tool arguments, configured endpoints, or builder diagnostics.
type GeneratedTraceErrorCode string

const (
	GeneratedTraceInvalidInput       GeneratedTraceErrorCode = "invalid_input"
	GeneratedTraceUnavailable        GeneratedTraceErrorCode = "unavailable"
	GeneratedTraceClosed             GeneratedTraceErrorCode = "closed"
	GeneratedTraceChildrenActive     GeneratedTraceErrorCode = "children_active"
	GeneratedTraceBuildRejected      GeneratedTraceErrorCode = "build_rejected"
	GeneratedTraceRegistrationFailed GeneratedTraceErrorCode = "registration_failed"
)

// GeneratedTraceError is safe to expose at an API or health boundary.
type GeneratedTraceError struct{ code GeneratedTraceErrorCode }

func (err *GeneratedTraceError) Error() string {
	if err == nil {
		return "generated trace operation failed"
	}
	return "generated trace operation failed: " + string(err.code)
}

func (err *GeneratedTraceError) Code() GeneratedTraceErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

// AgentTrace is one generated span.agent.invoke. A request-bounded root owns
// the generation lease for the complete hierarchy; descendants share that
// lease and therefore cannot cross a reload generation. It MUST NOT be retained
// as process-wide or cross-delivery OpenClaw/hook session state. The type
// intentionally does not expose the mutable SDK span.
type AgentTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// ModelTrace is one generated span.model.chat nested under an AgentTrace.
type ModelTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// JudgeTrace is one generated span.guardrail.judge for an actual local LLM
// judge provider call. The handle is request bounded and keeps the exact
// runtime generation alive until End or Abort.
type JudgeTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// GuardrailApplyTrace is one generated span.guardrail.apply for a completed
// non-model guardrail evaluation. Policy outcomes remain domain fields and do
// not become OTel technical errors.
type GuardrailApplyTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// GuardrailPhaseTrace is one generated span.guardrail.phase nested under the
// exact bounded guardrail evaluation which observed it. Concurrent phases
// share their parent's generation lease and may therefore safely represent
// judge-first fan-out without crossing a reload generation.
type GuardrailPhaseTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// ToolTrace is one generated span.tool.execute nested under an AgentTrace or
// ModelTrace.
type ToolTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// AgentTransitionTrace is one generated span.agent.transition nested under a
// bounded AgentTrace. It represents source-observed lifecycle/phase evidence;
// callers must not synthesize a transition merely to complete a trace shape.
type AgentTransitionTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// ApprovalTrace is one generated span.approval.resolve nested under the exact
// bounded agent or tool operation which observed the approval. The handle does
// not infer an approval identity, actor, result, or duration.
type ApprovalTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// TelemetryReceiveTrace is one request-bounded span.telemetry.receive root.
// Its optional normalize child shares the exact runtime-graph lease so a
// config reload cannot split the receive/normalize pair across generations.
type TelemetryReceiveTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// TelemetryNormalizeTrace is one span.telemetry.normalize child under the
// exact receive operation which decoded and classified the inbound batch.
type TelemetryNormalizeTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// AssetScanTrace is one generated span.asset.scan. Scanner implementations do
// not own SDK tracers; the audit/runtime boundary retrospectively records the
// bounded source timestamps after forensic persistence has assigned scan_id.
type AssetScanTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

type generatedTraceSession struct {
	mu                  sync.Mutex
	lease               *runtimegraph.Lease
	store               *audit.Store
	provider            *telemetry.Provider
	builder             *observability.FamilyBuilder
	correlationDefaults observability.Correlation
	resource            telemetry.V8TraceResourceFields
	digest              string
	generation          uint64
	version             string
	root                *generatedTraceNode
	nodes               []*generatedTraceNode
	closed              bool
}

type generatedTraceNode struct {
	family      string
	bucket      observability.Bucket
	kind        string
	nameKey     string
	start       time.Time
	parent      trace.SpanContext
	spanContext trace.SpanContext
	ctx         context.Context
	span        trace.Span
	parentNode  *generatedTraceNode
	ended       bool
}

// StartAgentTrace acquires exactly one active runtime-graph lease before any
// trace construction. A nil handle with a nil error is normal admission: the
// bucket is not collected or sampling declined the root. In either case no
// generated canonical record is built and the lease is released immediately.
//
// The input is the generated span.agent.invoke vocabulary. Start-time,
// provider/generation/resource identity, trace identity, parent identity,
// flags, and scope are runtime-owned and are sealed by this API. All semantic
// fields remain producer supplied; in particular the API never invents
// lifecycle, execution, phase, sequence, operation, cost, or content values.
// Source and provenance Producer are also required producer facts; omitting
// either causes generated-builder rejection rather than a synthetic default.
// The caller must End or Abort before its bounded request/delivery operation
// returns. Cross-delivery session correlation belongs in canonical IDs/links,
// not in a lease retained for the lifetime of an external agent session.
// Callers should immediately defer Abort after a non-nil handle; Abort is a
// no-op after successful End and guarantees release during caller panics.
func (runtime *Runtime) StartAgentTrace(
	ctx context.Context,
	input observability.SpanAgentInvokeInput,
) (context.Context, *AgentTrace, error) {
	if input.DefenseClawAgentType == "" {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketAgentLifecycle, observability.TelemetryFamilyAgentInvoke,
		input.Kind, input.DefenseClawAgentType, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &AgentTrace{session: session, node: node}, nil
}

// StartAgentTransitionTrace starts a request-bounded lifecycle transition when
// the producer observed a real transition but no bounded agent invocation.
// This avoids fabricating a completed span.agent.invoke merely to provide a
// parent for independently delivered connector hooks.
func (runtime *Runtime) StartAgentTransitionTrace(
	ctx context.Context,
	input observability.SpanAgentTransitionInput,
) (context.Context, *AgentTransitionTrace, error) {
	if input.GenAIConversationID == "" || input.GenAIAgentID == "" ||
		input.DefenseClawAgentRootID == "" || input.DefenseClawSessionRootID == "" ||
		input.DefenseClawAgentLifecycleID == "" || input.DefenseClawAgentExecutionID == "" ||
		input.DefenseClawAgentLifecycleEvent == "" || input.DefenseClawAgentLifecycleState == "" {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketAgentLifecycle, observability.TelemetryFamilyAgentTransition,
		input.Kind, input.DefenseClawAgentLifecycleEvent, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &AgentTransitionTrace{session: session, node: node}, nil
}

// StartModelTrace starts a request-bounded root span.model.chat when the
// producer observed a real model operation but no real agent invocation. This
// avoids fabricating an agent root solely to satisfy trace shape.
func (runtime *Runtime) StartModelTrace(
	ctx context.Context,
	input observability.SpanModelChatInput,
) (context.Context, *ModelTrace, error) {
	if input.GenAIRequestModel == "" {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketModelIO, observability.TelemetryFamilyModelChat,
		input.Kind, input.GenAIRequestModel, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &ModelTrace{session: session, node: node}, nil
}

// StartJudgeTrace starts a request-bounded span.guardrail.judge for a real
// local judge model call. A nil handle with a nil error means collection or
// sampling declined the span; callers must not fall back to a legacy span in
// that case because the active v8 runtime remains authoritative.
func (runtime *Runtime) StartJudgeTrace(
	ctx context.Context,
	input observability.SpanGuardrailJudgeInput,
) (context.Context, *JudgeTrace, error) {
	if input.GenAIRequestModel == "" || input.DefenseClawJudgeKind == "" {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketGuardrailEvaluation, observability.TelemetryFamilyGuardrailJudge,
		input.Kind, input.GenAIRequestModel, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &JudgeTrace{session: session, node: node}, nil
}

// StartGuardrailApplyTrace starts a request-bounded span.guardrail.apply for a
// real guardrail evaluation. The guardrail name and target type jointly own the
// immutable physical/canonical span name; neither may change at End.
func (runtime *Runtime) StartGuardrailApplyTrace(
	ctx context.Context,
	input observability.SpanGuardrailApplyInput,
) (context.Context, *GuardrailApplyTrace, error) {
	nameKey, valid := generatedGuardrailApplyNameKey(
		input.DefenseClawGuardrailName,
		input.DefenseClawGuardrailTargetType,
	)
	if !valid {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketGuardrailEvaluation, observability.TelemetryFamilyGuardrailApply,
		input.Kind, nameKey, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &GuardrailApplyTrace{session: session, node: node}, nil
}

// StartToolTrace starts a request-bounded root span.tool.execute when a real
// tool operation has no observed agent/model parent. It does not synthesize an
// agent identity or parent.
func (runtime *Runtime) StartToolTrace(
	ctx context.Context,
	input observability.SpanToolExecuteInput,
) (context.Context, *ToolTrace, error) {
	if input.GenAIToolName == "" {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketToolActivity, observability.TelemetryFamilyToolExecute,
		input.Kind, input.GenAIToolName, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &ToolTrace{session: session, node: node}, nil
}

// StartApprovalTrace starts a request-bounded root span.approval.resolve when
// the producer observed an approval operation but no exact active agent or tool
// parent is available. Agent and session fields remain optional producer facts;
// this API never creates an agent anchor solely to complete the trace shape.
func (runtime *Runtime) StartApprovalTrace(
	ctx context.Context,
	input observability.SpanApprovalResolveInput,
) (context.Context, *ApprovalTrace, error) {
	approvalID, reported := input.DefenseClawApprovalID.Get()
	if !reported || approvalID == "" {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketEnforcementAction, observability.TelemetryFamilyApprovalResolve,
		input.Kind, "approval", input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &ApprovalTrace{session: session, node: node}, nil
}

// StartTelemetryReceiveTrace starts the authenticated HTTP receive boundary.
// The HTTP method is a required source fact and is sealed into both the
// physical and canonical span name. Payload facts are supplied only at End,
// after the receiver has actually observed them.
func (runtime *Runtime) StartTelemetryReceiveTrace(
	ctx context.Context,
	input observability.SpanTelemetryReceiveInput,
) (context.Context, *TelemetryReceiveTrace, error) {
	if input.HTTPRequestMethod == "" {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketTelemetryIngest, observability.TelemetryFamilyTelemetryReceive,
		input.Kind, input.HTTPRequestMethod, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &TelemetryReceiveTrace{session: session, node: node}, nil
}

// StartAssetScanTrace starts the canonical scan operation. A nil handle with a
// nil error is normal collection/sampling decline and must never fall back to a
// package-global SDK tracer.
func (runtime *Runtime) StartAssetScanTrace(
	ctx context.Context,
	input observability.SpanAssetScanInput,
) (context.Context, *AssetScanTrace, error) {
	scannerName, present := input.DefenseClawScanScanner.Get()
	if !present || scannerName == "" {
		return ctx, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx, observability.BucketAssetScan, observability.TelemetryFamilyAssetScan,
		input.Kind, scannerName, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &AssetScanTrace{session: session, node: node}, nil
}

// EmitAssetScanTrace is the one-shot cycle-free adapter used by audit.Logger.
// It retains start/end parity while preventing a generated handle from being
// stored outside the bounded scan occurrence.
func (runtime *Runtime) EmitAssetScanTrace(
	ctx context.Context,
	input observability.SpanAssetScanInput,
) error {
	_, span, err := runtime.StartAssetScanTrace(ctx, input)
	if err != nil || span == nil {
		return err
	}
	defer span.Abort()
	return span.End(input)
}

func (runtime *Runtime) startGeneratedTrace(
	ctx context.Context,
	bucket observability.Bucket,
	family, kind, nameKey string,
	startNanos uint64,
) (context.Context, *generatedTraceSession, *generatedTraceNode, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || nameKey == "" ||
		!generatedTraceFamilyKind(family, kind) {
		return ctx, nil, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return ctx, nil, nil, err
	}
	release := true
	var started trace.Span
	defer func() {
		if release {
			safeEndGeneratedSpan(started)
			lease.Release()
		}
	}()
	graph := lease.Graph()
	provider, ok := telemetry.V8ProviderFromLease(lease)
	if graph == nil || !ok {
		return ctx, nil, nil, generatedTraceError(GeneratedTraceUnavailable)
	}
	digest, generation, bound := provider.V8PlanBinding()
	if !bound || digest == "" || digest != graph.Digest() || generation != graph.Generation() {
		return ctx, nil, nil, generatedTraceError(GeneratedTraceUnavailable)
	}
	// Collection is checked before span name, resource, builder, or canonical
	// payload construction. Routes can only narrow this decision later.
	if !provider.TraceBucketEnabled(bucket) {
		return ctx, nil, nil, nil
	}
	start, valid := generatedTraceStartTime(startNanos)
	if !valid {
		return ctx, nil, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	name := generatedTraceName(family, nameKey)
	if name == "" {
		return ctx, nil, nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	startedContext, span := startGeneratedPhysicalSpan(
		provider, ctx, bucket, family, name, kind, start, generation,
	)
	started = span
	spanContext := span.SpanContext()
	if !span.IsRecording() || !provider.TraceExportEligible(bucket, spanContext) {
		return startedContext, nil, nil, nil
	}
	resourceContext, resourceOK := provider.V8ResourceContext()
	if !resourceOK {
		return ctx, nil, nil, generatedTraceError(GeneratedTraceUnavailable)
	}
	resourceValues := resourceContext.Values()
	version := resourceValues["service.version"]
	if version == "" {
		return ctx, nil, nil, generatedTraceError(GeneratedTraceUnavailable)
	}
	builder, builderErr := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
	if builderErr != nil {
		return ctx, nil, nil, generatedTraceError(GeneratedTraceUnavailable)
	}
	node := &generatedTraceNode{
		family: family, bucket: bucket, kind: kind, nameKey: nameKey, start: start,
		parent: trace.SpanContextFromContext(ctx), spanContext: spanContext,
		ctx: startedContext, span: span,
	}
	session := &generatedTraceSession{
		lease: lease, store: runtime.store, provider: provider, builder: builder,
		correlationDefaults: correlationDefaultsFromContext(ctx, correlationDefaultsGeneratedTrace),
		resource:            resourceContext.TraceResourceFields(), digest: digest,
		generation: generation, version: version, root: node,
		nodes: []*generatedTraceNode{node},
	}
	release = false
	started = nil
	return startedContext, session, node, nil
}

// StartAgent starts a child span.agent.invoke (for example a delegated
// sub-agent) under this exact agent span without acquiring another lease.
func (span *AgentTrace) StartAgent(input observability.SpanAgentInvokeInput) (*AgentTrace, error) {
	if span == nil || span.session == nil || span.node == nil || input.DefenseClawAgentType == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketAgentLifecycle, observability.TelemetryFamilyAgentInvoke,
		input.Kind, input.DefenseClawAgentType, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &AgentTrace{session: span.session, node: node}, nil
}

// StartModel starts a generated span.model.chat child under this agent.
func (span *AgentTrace) StartModel(input observability.SpanModelChatInput) (*ModelTrace, error) {
	if span == nil || span.session == nil || span.node == nil || input.GenAIRequestModel == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketModelIO, observability.TelemetryFamilyModelChat,
		input.Kind, input.GenAIRequestModel, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &ModelTrace{session: span.session, node: node}, nil
}

// StartTool starts a generated span.tool.execute child under this agent.
func (span *AgentTrace) StartTool(input observability.SpanToolExecuteInput) (*ToolTrace, error) {
	if span == nil || span.session == nil || span.node == nil || input.GenAIToolName == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketToolActivity, observability.TelemetryFamilyToolExecute,
		input.Kind, input.GenAIToolName, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &ToolTrace{session: span.session, node: node}, nil
}

// StartTransition starts a generated lifecycle transition under this exact
// bounded agent anchor. Lifecycle event is the span-name key and remains
// producer supplied; the runtime only seals trace/resource identity.
func (span *AgentTrace) StartTransition(input observability.SpanAgentTransitionInput) (*AgentTransitionTrace, error) {
	if span == nil || span.session == nil || span.node == nil ||
		input.GenAIConversationID == "" || input.GenAIAgentID == "" ||
		input.DefenseClawAgentRootID == "" || input.DefenseClawSessionRootID == "" ||
		input.DefenseClawAgentLifecycleID == "" || input.DefenseClawAgentExecutionID == "" ||
		input.DefenseClawAgentLifecycleEvent == "" || input.DefenseClawAgentLifecycleState == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketAgentLifecycle, observability.TelemetryFamilyAgentTransition,
		input.Kind, input.DefenseClawAgentLifecycleEvent, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &AgentTransitionTrace{session: span.session, node: node}, nil
}

// StartApproval starts a generated approval span under this exact bounded
// agent anchor when no narrower active tool parent is available.
func (span *AgentTrace) StartApproval(input observability.SpanApprovalResolveInput) (*ApprovalTrace, error) {
	if span == nil || span.session == nil || span.node == nil {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketEnforcementAction, observability.TelemetryFamilyApprovalResolve,
		input.Kind, "approval", input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &ApprovalTrace{session: span.session, node: node}, nil
}

// StartPhase starts a generated phase child under this exact guardrail
// evaluation. The phase is both the physical/canonical span-name key and a
// required family fact; End cannot rename it.
func (span *GuardrailApplyTrace) StartPhase(
	input observability.SpanGuardrailPhaseInput,
) (*GuardrailPhaseTrace, error) {
	if span == nil || span.session == nil || span.node == nil ||
		input.DefenseClawGuardrailPhase == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketGuardrailEvaluation, observability.TelemetryFamilyGuardrailPhase,
		input.Kind, input.DefenseClawGuardrailPhase, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &GuardrailPhaseTrace{session: span.session, node: node}, nil
}

// StartTool starts a generated span.tool.execute child under this model call.
func (span *ModelTrace) StartTool(input observability.SpanToolExecuteInput) (*ToolTrace, error) {
	if span == nil || span.session == nil || span.node == nil || input.GenAIToolName == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketToolActivity, observability.TelemetryFamilyToolExecute,
		input.Kind, input.GenAIToolName, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &ToolTrace{session: span.session, node: node}, nil
}

// StartApproval starts a generated approval span under the tool operation that
// requested it. This preserves causal OTel parentage independently from the
// logical root/parent-agent lineage carried by canonical attributes.
func (span *ToolTrace) StartApproval(input observability.SpanApprovalResolveInput) (*ApprovalTrace, error) {
	if span == nil || span.session == nil || span.node == nil {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketEnforcementAction, observability.TelemetryFamilyApprovalResolve,
		input.Kind, "approval", input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &ApprovalTrace{session: span.session, node: node}, nil
}

// StartNormalize starts the decode/validate/normalize/classify child for this
// exact receive operation. The signal is required and is the canonical name
// substitution; the runtime never derives it from an endpoint or payload.
func (span *TelemetryReceiveTrace) StartNormalize(
	input observability.SpanTelemetryNormalizeInput,
) (*TelemetryNormalizeTrace, error) {
	if span == nil || span.session == nil || span.node == nil ||
		input.DefenseClawTelemetrySignal == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node, observability.BucketTelemetryIngest, observability.TelemetryFamilyTelemetryNormalize,
		input.Kind, input.DefenseClawTelemetrySignal, input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &TelemetryNormalizeTrace{session: span.session, node: node}, nil
}

// Context returns the immutable OTel context for parenting work which has not
// yet migrated. It returns nil after the handle is invalid; callers cannot use
// it to mutate the generated span.
func (span *AgentTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *ModelTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *JudgeTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *GuardrailApplyTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *GuardrailPhaseTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *ToolTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *AgentTransitionTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *ApprovalTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *TelemetryReceiveTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}
func (span *TelemetryNormalizeTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}

func (span *AgentTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *ModelTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *JudgeTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *GuardrailApplyTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *GuardrailPhaseTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *ToolTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *AgentTransitionTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *ApprovalTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *TelemetryReceiveTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}
func (span *TelemetryNormalizeTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}

func (span *AgentTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *ModelTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *JudgeTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *GuardrailApplyTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *GuardrailPhaseTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *ToolTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *AgentTransitionTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *ApprovalTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *TelemetryReceiveTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}
func (span *TelemetryNormalizeTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}

func (span *AgentTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *ModelTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *JudgeTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *GuardrailApplyTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *GuardrailPhaseTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *ToolTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *AgentTransitionTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *ApprovalTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *TelemetryReceiveTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}
func (span *TelemetryNormalizeTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}

// RecordGeneratedMetricBatch records metric siblings on the exact graph lease
// and generation already owned by this live trace hierarchy. The operation is
// independent of span completion: disabled metric collection is a no-op and a
// metric failure does not abort the trace.
func (span *AgentTrace) RecordGeneratedMetricBatch(
	ctx context.Context,
	items []GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	if span == nil || span.session == nil || span.node == nil {
		return nil, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	return span.session.recordGeneratedMetricBatch(ctx, span.node, items)
}

func (span *ModelTrace) RecordGeneratedMetricBatch(
	ctx context.Context,
	items []GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	if span == nil || span.session == nil || span.node == nil {
		return nil, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	return span.session.recordGeneratedMetricBatch(ctx, span.node, items)
}

// RecordGeneratedMetricBatch records metric siblings while this guardrail
// phase is still live. Remote inspection clients use this seam so their
// latency/error metrics share the phase's exact graph-generation lease instead
// of racing a configuration reload through the process-level runtime.
func (span *GuardrailPhaseTrace) RecordGeneratedMetricBatch(
	ctx context.Context,
	items []GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	if span == nil || span.session == nil || span.node == nil {
		return nil, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	return span.session.recordGeneratedMetricBatch(ctx, span.node, items)
}

func (span *ToolTrace) RecordGeneratedMetricBatch(
	ctx context.Context,
	items []GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	if span == nil || span.session == nil || span.node == nil {
		return nil, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	return span.session.recordGeneratedMetricBatch(ctx, span.node, items)
}

func (session *generatedTraceSession) recordGeneratedMetricBatch(
	ctx context.Context,
	node *generatedTraceNode,
	items []GeneratedMetricBatchItem,
) ([]telemetry.V8MetricRecordResult, error) {
	if session == nil || ctx == nil || node == nil {
		return nil, &GeneratedMetricError{code: GeneratedMetricInvalidInput}
	}
	if err := validateGeneratedMetricBatchItems(items); err != nil {
		return nil, err
	}
	session.mu.Lock()
	if session.closed || node.ended || !session.containsNodeLocked(node) ||
		session.lease == nil || session.lease.Graph() == nil {
		session.mu.Unlock()
		return nil, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	lease := session.lease.Fork()
	session.mu.Unlock()
	if lease == nil {
		return nil, &GeneratedMetricError{code: GeneratedMetricUnavailable}
	}
	defer lease.Release()
	results := make([]telemetry.V8MetricRecordResult, len(items))
	for index, item := range items {
		result, err := recordGeneratedMetricWithLease(
			ctx, lease, session.store, item.Family, item.Builder, session.correlationDefaults,
		)
		results[index] = result
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

// End builds and registers the exact generated agent record. Ending the root
// releases the sole graph lease. Any rejection is terminal and aborts the
// complete hierarchy so a partially canonical trace cannot continue.
func (span *AgentTrace) End(input observability.SpanAgentInvokeInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endAgent(span.node, input)
}

func (span *ModelTrace) End(input observability.SpanModelChatInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endModel(span.node, input)
}

func (span *JudgeTrace) End(input observability.SpanGuardrailJudgeInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endJudge(span.node, input)
}

func (span *GuardrailApplyTrace) End(input observability.SpanGuardrailApplyInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endGuardrailApply(span.node, input)
}

func (span *GuardrailPhaseTrace) End(input observability.SpanGuardrailPhaseInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endGuardrailPhase(span.node, input)
}

func (span *ToolTrace) End(input observability.SpanToolExecuteInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endTool(span.node, input)
}

func (span *AgentTransitionTrace) End(input observability.SpanAgentTransitionInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endAgentTransition(span.node, input)
}

func (span *ApprovalTrace) End(input observability.SpanApprovalResolveInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endApproval(span.node, input)
}

func (span *TelemetryReceiveTrace) End(input observability.SpanTelemetryReceiveInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endTelemetryReceive(span.node, input)
}

func (span *TelemetryNormalizeTrace) End(input observability.SpanTelemetryNormalizeInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endTelemetryNormalize(span.node, input)
}

func (span *AssetScanTrace) End(input observability.SpanAssetScanInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endAssetScan(span.node, input)
}

// Abort ends every still-recording physical span without canonical handoff and
// releases the root lease. It is safe to call from every caller cleanup path;
// a repeated call is a no-op.
func (span *AgentTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *ModelTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *JudgeTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *GuardrailApplyTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *GuardrailPhaseTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *ToolTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *AgentTransitionTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *ApprovalTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *TelemetryReceiveTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *TelemetryNormalizeTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *AssetScanTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (session *generatedTraceSession) startChild(
	parent *generatedTraceNode,
	bucket observability.Bucket,
	family, kind, nameKey string,
	startNanos uint64,
) (result *generatedTraceNode, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			session.abort()
			panic(recovered)
		}
	}()
	if session == nil || parent == nil || nameKey == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.lease == nil || session.lease.Graph() == nil {
		return nil, generatedTraceError(GeneratedTraceClosed)
	}
	if parent.ended || !session.containsNodeLocked(parent) {
		session.abortLocked()
		return nil, generatedTraceError(GeneratedTraceClosed)
	}
	// Child collection is checked before timestamp, name, or SDK signal
	// construction. A disabled bucket is a normal no-op and leaves the parent
	// hierarchy live.
	if !session.provider.TraceBucketEnabled(bucket) {
		return nil, nil
	}
	if !generatedTraceFamilyKind(family, kind) {
		session.abortLocked()
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	start, valid := generatedTraceStartTime(startNanos)
	if !valid {
		session.abortLocked()
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	name := generatedTraceName(family, nameKey)
	if name == "" {
		session.abortLocked()
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	ctx, physical := startGeneratedPhysicalSpan(
		session.provider, parent.ctx, bucket, family, name, kind, start, session.generation,
	)
	spanContext := physical.SpanContext()
	if !physical.IsRecording() || !session.provider.TraceExportEligible(bucket, spanContext) {
		safeEndGeneratedSpan(physical)
		return nil, nil
	}
	node := &generatedTraceNode{
		family: family, bucket: bucket, kind: kind, nameKey: nameKey, start: start,
		parent: parent.spanContext, spanContext: spanContext, ctx: ctx, span: physical,
		parentNode: parent,
	}
	session.nodes = append(session.nodes, node)
	return node, nil
}

func (session *generatedTraceSession) endAgent(
	node *generatedTraceNode,
	input observability.SpanAgentInvokeInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealAgentInput(input, node, end)
	record, buildErr := session.builder.BuildSpanAgentInvoke(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endModel(
	node *generatedTraceNode,
	input observability.SpanModelChatInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealModelInput(input, node, end)
	record, buildErr := session.builder.BuildSpanModelChat(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endJudge(
	node *generatedTraceNode,
	input observability.SpanGuardrailJudgeInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealJudgeInput(input, node, end)
	record, buildErr := session.builder.BuildSpanGuardrailJudge(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endGuardrailApply(
	node *generatedTraceNode,
	input observability.SpanGuardrailApplyInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input, ok = session.sealGuardrailApplyInput(input, node, end)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	record, buildErr := session.builder.BuildSpanGuardrailApply(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endGuardrailPhase(
	node *generatedTraceNode,
	input observability.SpanGuardrailPhaseInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealGuardrailPhaseInput(input, node, end)
	record, buildErr := session.builder.BuildSpanGuardrailPhase(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endTool(
	node *generatedTraceNode,
	input observability.SpanToolExecuteInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealToolInput(input, node, end)
	record, buildErr := session.builder.BuildSpanToolExecute(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endAgentTransition(
	node *generatedTraceNode,
	input observability.SpanAgentTransitionInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealAgentTransitionInput(input, node, end)
	record, buildErr := session.builder.BuildSpanAgentTransition(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endApproval(
	node *generatedTraceNode,
	input observability.SpanApprovalResolveInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealApprovalInput(input, node, end)
	record, buildErr := session.builder.BuildSpanApprovalResolve(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endTelemetryReceive(
	node *generatedTraceNode,
	input observability.SpanTelemetryReceiveInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealTelemetryReceiveInput(input, node, end)
	record, buildErr := session.builder.BuildSpanTelemetryReceive(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endTelemetryNormalize(
	node *generatedTraceNode,
	input observability.SpanTelemetryNormalizeInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealTelemetryNormalizeInput(input, node, end)
	record, buildErr := session.builder.BuildSpanTelemetryNormalize(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endAssetScan(
	node *generatedTraceNode,
	input observability.SpanAssetScanInput,
) (err error) {
	defer session.abortOnPanic()
	session.mu.Lock()
	defer session.mu.Unlock()
	if err := session.preflightEndLocked(node); err != nil {
		return err
	}
	end, ok := generatedTraceEndTime(input.EndTimeUnixNano, node.start)
	if !ok {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	input = session.sealAssetScanInput(input, node, end)
	record, buildErr := session.builder.BuildSpanAssetScan(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) preflightEndLocked(node *generatedTraceNode) error {
	if session == nil || session.closed || session.lease == nil || session.lease.Graph() == nil {
		return generatedTraceError(GeneratedTraceClosed)
	}
	if node == nil || node.ended || !session.containsNodeLocked(node) {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceClosed)
	}
	for _, candidate := range session.nodes {
		if candidate != nil && !candidate.ended && candidate.parentNode == node {
			session.abortLocked()
			return generatedTraceError(GeneratedTraceChildrenActive)
		}
	}
	digest, generation, bound := session.provider.V8PlanBinding()
	if !bound || digest != session.digest || generation != session.generation {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceUnavailable)
	}
	return nil
}

func (session *generatedTraceSession) registerEndLocked(
	node *generatedTraceNode,
	status observability.TraceStatusInput,
	record observability.Record,
) error {
	if !setGeneratedPhysicalStatus(node.span, status) {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	var err error
	record, err = stampRuntimeCorrelation(record, session.correlationDefaults)
	if err != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	if err := persistRuntimeCorrelationObservation(node.ctx, session.store, record); err != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceRegistrationFailed)
	}
	registration := session.provider.EndV8CanonicalSpan(node.span, record)
	// EndV8CanonicalSpan ends the physical span on every registration result.
	node.ended = true
	if registration != telemetry.V8CanonicalSpanRegistered {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceRegistrationFailed)
	}
	if node == session.root {
		session.releaseLocked()
	}
	return nil
}

func (session *generatedTraceSession) sealAgentInput(
	input observability.SpanAgentInvokeInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanAgentInvokeInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	// The span name was established at Start and is part of physical/canonical
	// parity. Do not allow a mutable end snapshot to rename it.
	input.DefenseClawAgentType = node.nameKey
	return input
}

func (session *generatedTraceSession) sealModelInput(
	input observability.SpanModelChatInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanModelChatInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.GenAIRequestModel = node.nameKey
	return input
}

func (session *generatedTraceSession) sealJudgeInput(
	input observability.SpanGuardrailJudgeInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanGuardrailJudgeInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.GenAIRequestModel = node.nameKey
	return input
}

func (session *generatedTraceSession) sealGuardrailApplyInput(
	input observability.SpanGuardrailApplyInput,
	node *generatedTraceNode,
	end time.Time,
) (observability.SpanGuardrailApplyInput, bool) {
	guardrailName, targetType, valid := generatedGuardrailApplyNameKeyParts(node.nameKey)
	if !valid {
		return observability.SpanGuardrailApplyInput{}, false
	}
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.DefenseClawGuardrailName = guardrailName
	input.DefenseClawGuardrailTargetType = targetType
	return input, true
}

func (session *generatedTraceSession) sealGuardrailPhaseInput(
	input observability.SpanGuardrailPhaseInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanGuardrailPhaseInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.DefenseClawGuardrailPhase = node.nameKey
	return input
}

func (session *generatedTraceSession) sealToolInput(
	input observability.SpanToolExecuteInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanToolExecuteInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.GenAIToolName = node.nameKey
	return input
}

func (session *generatedTraceSession) sealAgentTransitionInput(
	input observability.SpanAgentTransitionInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanAgentTransitionInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.DefenseClawAgentLifecycleEvent = node.nameKey
	return input
}

func (session *generatedTraceSession) sealApprovalInput(
	input observability.SpanApprovalResolveInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanApprovalResolveInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	return input
}

func (session *generatedTraceSession) sealTelemetryReceiveInput(
	input observability.SpanTelemetryReceiveInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanTelemetryReceiveInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.HTTPRequestMethod = node.nameKey
	return input
}

func (session *generatedTraceSession) sealTelemetryNormalizeInput(
	input observability.SpanTelemetryNormalizeInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanTelemetryNormalizeInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.DefenseClawTelemetrySignal = node.nameKey
	return input
}

func (session *generatedTraceSession) sealAssetScanInput(
	input observability.SpanAssetScanInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanAssetScanInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano = node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags = generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	input.Resource, input.Scope = session.resource.Resource, observability.TraceScopeInput{}
	input.ResourceServiceName = session.resource.ServiceName
	input.ResourceServiceNamespace = session.resource.ServiceNamespace
	input.ResourceServiceInstanceID = session.resource.ServiceInstanceID
	input.ResourceDeploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	input.ResourceHostName, input.ResourceHostArch, input.ResourceOsType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	input.ResourceTenantID, input.ResourceWorkspaceID = session.resource.TenantID, session.resource.WorkspaceID
	input.ResourceDefenseClawDeploymentMode = session.resource.DefenseClawDeploymentMode
	input.ResourceDefenseClawClawMode = session.resource.DefenseClawClawMode
	input.ResourceDefenseClawInstanceID = session.resource.DefenseClawInstanceID
	input.ResourceDefenseClawDevicePublicKeyFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
	input.DefenseClawScanScanner = observability.Present(node.nameKey)
	return input
}

func (session *generatedTraceSession) sealEnvelope(
	envelope observability.FamilyEnvelopeInput,
	node *generatedTraceNode,
) observability.FamilyEnvelopeInput {
	envelope.Correlation.TraceID = node.spanContext.TraceID().String()
	envelope.Correlation.SpanID = node.spanContext.SpanID().String()
	envelope.Provenance.BinaryVersion = session.version
	envelope.Provenance.ConfigGeneration = int64(session.generation)
	envelope.Provenance.ConfigDigest = session.digest
	return envelope
}

func (session *generatedTraceSession) abortOnPanic() {
	if recovered := recover(); recovered != nil {
		session.abort()
		panic(recovered)
	}
}

func (session *generatedTraceSession) abort() {
	if session == nil {
		return
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	session.abortLocked()
}

func (session *generatedTraceSession) abortLocked() {
	if session == nil || session.closed {
		return
	}
	for index := len(session.nodes) - 1; index >= 0; index-- {
		node := session.nodes[index]
		if node != nil && !node.ended {
			safeEndGeneratedSpan(node.span)
			node.ended = true
		}
	}
	session.releaseLocked()
}

func (session *generatedTraceSession) releaseLocked() {
	if session == nil || session.closed {
		return
	}
	session.closed = true
	if session.lease != nil {
		session.lease.Release()
		session.lease = nil
	}
}

func (session *generatedTraceSession) containsNodeLocked(node *generatedTraceNode) bool {
	for _, candidate := range session.nodes {
		if candidate == node {
			return true
		}
	}
	return false
}

func startGeneratedPhysicalSpan(
	provider *telemetry.Provider,
	ctx context.Context,
	bucket observability.Bucket,
	family, name, kind string,
	start time.Time,
	generation uint64,
) (context.Context, trace.Span) {
	spanKind, valid := generatedTraceSpanKind(kind)
	familyVersion, familyValid := observability.FamilySchemaVersion(family)
	if !valid || !familyValid {
		return trace.NewNoopTracerProvider().Tracer("defenseclaw/generated-trace").Start(ctx, name)
	}
	return provider.TracerForBucket(bucket).Start(
		ctx, name,
		trace.WithSpanKind(spanKind),
		trace.WithTimestamp(start),
		trace.WithAttributes(
			attribute.String("defenseclaw.bucket", string(bucket)),
			attribute.Int64("defenseclaw.config.generation", int64(generation)),
			attribute.String("defenseclaw.span.family", family),
			attribute.Int64("defenseclaw.span.family_schema_version", familyVersion),
		),
	)
}

func generatedTraceSpanKind(value string) (trace.SpanKind, bool) {
	switch value {
	case "INTERNAL":
		return trace.SpanKindInternal, true
	case "CLIENT":
		return trace.SpanKindClient, true
	case "SERVER":
		return trace.SpanKindServer, true
	case "PRODUCER":
		return trace.SpanKindProducer, true
	case "CONSUMER":
		return trace.SpanKindConsumer, true
	default:
		return trace.SpanKindUnspecified, false
	}
}

func generatedTraceFamilyKind(family, kind string) bool {
	switch family {
	case observability.TelemetryFamilyAgentInvoke, observability.TelemetryFamilyToolExecute:
		return kind == "INTERNAL" || kind == "CLIENT"
	case observability.TelemetryFamilyModelChat:
		return kind == "CLIENT"
	case observability.TelemetryFamilyGuardrailJudge:
		return kind == "CLIENT"
	case observability.TelemetryFamilyGuardrailApply:
		return kind == "INTERNAL"
	case observability.TelemetryFamilyGuardrailPhase:
		return kind == "INTERNAL" || kind == "CLIENT"
	case observability.TelemetryFamilyAgentTransition, observability.TelemetryFamilyApprovalResolve:
		return kind == "INTERNAL"
	case observability.TelemetryFamilyTelemetryReceive:
		return kind == "SERVER"
	case observability.TelemetryFamilyTelemetryNormalize:
		return kind == "INTERNAL"
	case observability.TelemetryFamilyAIDiscovery, observability.TelemetryFamilyAIDiscoveryDetector:
		return kind == "INTERNAL"
	case observability.TelemetryFamilyAssetScan:
		return kind == "INTERNAL"
	default:
		return false
	}
}

func generatedTraceName(family, key string) string {
	if key == "" {
		return ""
	}
	switch family {
	case observability.TelemetryFamilyAgentInvoke:
		return "invoke_agent " + key
	case observability.TelemetryFamilyModelChat:
		return "chat " + key
	case observability.TelemetryFamilyGuardrailJudge:
		return "chat " + key
	case observability.TelemetryFamilyGuardrailApply:
		name, targetType, valid := generatedGuardrailApplyNameKeyParts(key)
		if !valid {
			return ""
		}
		return "apply_guardrail " + name + " " + targetType
	case observability.TelemetryFamilyGuardrailPhase:
		return "guardrail." + key
	case observability.TelemetryFamilyToolExecute:
		return "execute_tool " + key
	case observability.TelemetryFamilyAgentTransition:
		return "agent.transition " + key
	case observability.TelemetryFamilyApprovalResolve:
		return "exec." + key
	case observability.TelemetryFamilyTelemetryReceive:
		return key + " telemetry"
	case observability.TelemetryFamilyTelemetryNormalize:
		return "telemetry.normalize " + key
	case observability.TelemetryFamilyAIDiscovery:
		return "defenseclaw.ai.discovery"
	case observability.TelemetryFamilyAIDiscoveryDetector:
		return "defenseclaw.ai.discovery.detector"
	case observability.TelemetryFamilyAssetScan:
		return "asset.scan"
	default:
		return ""
	}
}

const generatedGuardrailApplyNameSeparator = "\x00"

func generatedGuardrailApplyNameKey(name, targetType string) (string, bool) {
	if name == "" || targetType == "" || strings.Contains(name, generatedGuardrailApplyNameSeparator) ||
		strings.Contains(targetType, generatedGuardrailApplyNameSeparator) {
		return "", false
	}
	return name + generatedGuardrailApplyNameSeparator + targetType, true
}

func generatedGuardrailApplyNameKeyParts(key string) (string, string, bool) {
	name, targetType, found := strings.Cut(key, generatedGuardrailApplyNameSeparator)
	return name, targetType, found && name != "" && targetType != "" &&
		!strings.Contains(targetType, generatedGuardrailApplyNameSeparator)
}

func generatedTraceStartTime(nanos uint64) (time.Time, bool) {
	if nanos == 0 {
		return time.Now().UTC(), true
	}
	if nanos > math.MaxInt64 {
		return time.Time{}, false
	}
	value := time.Unix(0, int64(nanos)).UTC()
	return value, !value.IsZero() && value.UnixNano() > 0
}

func generatedTraceEndTime(nanos uint64, start time.Time) (time.Time, bool) {
	if nanos > math.MaxInt64 {
		return time.Time{}, false
	}
	end := time.Now().UTC()
	if nanos != 0 {
		end = time.Unix(0, int64(nanos)).UTC()
	}
	return end, !end.IsZero() && end.UnixNano() > 0 && !end.Before(start)
}

func generatedTraceParent(node *generatedTraceNode) observability.Optional[string] {
	if node == nil || !node.parent.IsValid() {
		return observability.Absent[string]()
	}
	return observability.Present(node.parent.SpanID().String())
}

func generatedTraceState(spanContext trace.SpanContext) observability.Optional[string] {
	if value := spanContext.TraceState().String(); value != "" {
		return observability.Present(value)
	}
	return observability.Absent[string]()
}

func generatedTraceFlags(node *generatedTraceNode) uint32 {
	if node == nil {
		return 0
	}
	flags := uint32(node.spanContext.TraceFlags()) | 0x100
	if node.parent.IsValid() && node.parent.IsRemote() {
		flags |= 0x200
	}
	return flags
}

func setGeneratedPhysicalStatus(span trace.Span, status observability.TraceStatusInput) bool {
	if span == nil {
		return false
	}
	switch status.Code() {
	case observability.TraceStatusUnset:
		return true
	case observability.TraceStatusOK:
		span.SetStatus(codes.Ok, "")
		return true
	case observability.TraceStatusError:
		description, _ := status.Description()
		span.SetStatus(codes.Error, description)
		return true
	default:
		return false
	}
}

func safeEndGeneratedSpan(span trace.Span) {
	if span == nil {
		return
	}
	defer func() { _ = recover() }()
	span.End()
}

func generatedNodeContext(session *generatedTraceSession, node *generatedTraceNode) context.Context {
	if session == nil || node == nil {
		return nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || node.ended || !session.containsNodeLocked(node) {
		return nil
	}
	return node.ctx
}

func generatedNodeGeneration(session *generatedTraceSession, node *generatedTraceNode) uint64 {
	if session == nil || node == nil {
		return 0
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.containsNodeLocked(node) {
		return 0
	}
	return session.generation
}

func generatedNodeTraceID(session *generatedTraceSession, node *generatedTraceNode) string {
	if session == nil || node == nil {
		return ""
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.containsNodeLocked(node) || !node.spanContext.IsValid() {
		return ""
	}
	return node.spanContext.TraceID().String()
}

func generatedNodeSpanID(session *generatedTraceSession, node *generatedTraceNode) string {
	if session == nil || node == nil {
		return ""
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if !session.containsNodeLocked(node) || !node.spanContext.IsValid() {
		return ""
	}
	return node.spanContext.SpanID().String()
}

func generatedTraceError(code GeneratedTraceErrorCode) error {
	return &GeneratedTraceError{code: code}
}

var _ error = (*GeneratedTraceError)(nil)
