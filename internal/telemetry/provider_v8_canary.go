// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

const v8CanaryFamilySchemaVersion int64 = 1

// V8CanaryResult is the bounded result of one generation-pinned, two-span
// runtime pipeline test. It contains no configured endpoint or telemetry
// content. Acknowledged is true only after the exact destination has accepted
// the complete generated pair and the generation's pipeline has flushed.
type V8CanaryResult struct {
	TraceID      string
	Destination  string
	Generation   uint64
	Acknowledged bool
}

// EmitV8GeneratedCanary emits the release diagnostic as a generated
// span.agent.invoke root and span.model.chat child. The caller must retain the
// supplied runtime-graph lease until this method returns; that pins the exact
// provider, routing plan, processors, resource, flush, and acknowledgement
// lookup to one generation even while a reload publishes its successor.
func (p *Provider) EmitV8GeneratedCanary(
	ctx context.Context,
	lease *runtimegraph.Lease,
	destination string,
) (V8CanaryResult, error) {
	result := V8CanaryResult{}
	if ctx == nil || lease == nil || p == nil || p.v8 == nil || p.tracerProvider == nil ||
		!observability.IsStableToken(destination) {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	result.Destination = destination
	graph := lease.Graph()
	leasedProvider, leased := V8ProviderFromLease(lease)
	if graph == nil || !leased || leasedProvider != p || !p.Enabled() || !p.v8.active.Load() {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	digest, generation, bound := p.V8PlanBinding()
	result.Generation = generation
	if !bound || generation != graph.Generation() || digest == "" || digest != graph.Digest() {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	destinationPlan, exists := graph.Plan().Destination(destination)
	if !exists || !destinationPlan.Enabled ||
		!destinationPlan.Capabilities.Supports(observability.SignalTraces) ||
		!v8CanarySignalSelected(destinationPlan.SelectedSignals, observability.SignalTraces) {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	// Collection admission is evaluated before constructing either span. A
	// route cannot resurrect one side of a pair whose bucket is not collected.
	if !p.TraceBucketEnabled(observability.BucketAgentLifecycle) ||
		!p.TraceBucketEnabled(observability.BucketModelIO) || p.v8.handoff == nil {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}

	resourceContext, ok := p.V8ResourceContext()
	if !ok {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	resource := resourceContext.TraceResourceFields()
	resourceValues := resourceContext.Values()
	binaryVersion := resourceValues["service.version"]
	if binaryVersion == "" {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
	if err != nil {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}

	// Detach an inbound HTTP/server span. The canary is a self-contained trace
	// whose only parent relation is the generated model child to generated agent
	// root relation below.
	rootParent := trace.SpanContext{}
	rootContext := trace.ContextWithSpanContext(ctx, rootParent)
	rootStart := time.Now().UTC()
	rootContext, root := p.tracer.Start(
		rootContext,
		"invoke_agent diagnostic",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithTimestamp(rootStart),
		trace.WithAttributes(p.v8CanaryStartAttributes(
			observability.BucketAgentLifecycle,
			observability.TelemetryFamilyAgentInvoke,
			destination,
		)...),
	)
	rootEnded := false
	var child trace.Span
	childEnded := false
	defer func() {
		if child != nil && !childEnded {
			child.End()
		}
		if root != nil && !rootEnded {
			root.End()
		}
	}()
	root.SetStatus(codes.Ok, "")
	root.SetAttributes(
		attribute.String("gen_ai.operation.name", "invoke_agent"),
		attribute.String("gen_ai.agent.name", "defenseclaw"),
		attribute.String("defenseclaw.agent.type", "diagnostic"),
	)

	childStart := time.Now().UTC()
	_, child = p.tracer.Start(
		rootContext,
		"chat gpt-4o-mini",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithTimestamp(childStart),
		trace.WithAttributes(p.v8CanaryStartAttributes(
			observability.BucketModelIO,
			observability.TelemetryFamilyModelChat,
			destination,
		)...),
	)
	child.SetStatus(codes.Ok, "")
	child.SetAttributes(
		attribute.String("gen_ai.operation.name", "chat"),
		attribute.String("gen_ai.provider.name", "openai"),
		attribute.String("gen_ai.request.model", "gpt-4o-mini"),
	)

	rootSpanContext := root.SpanContext()
	childSpanContext := child.SpanContext()
	if !rootSpanContext.IsValid() || !rootSpanContext.IsSampled() ||
		!childSpanContext.IsValid() || !childSpanContext.IsSampled() ||
		rootSpanContext.TraceID() != childSpanContext.TraceID() {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	result.TraceID = rootSpanContext.TraceID().String()
	childEnd := time.Now().UTC()
	rootEnd := time.Now().UTC()
	traceState := v8CanaryTraceState(rootSpanContext.TraceState())
	provenance := observability.FamilyProvenanceInput{
		Producer: "defenseclaw", BinaryVersion: binaryVersion,
		ConfigGeneration: int64(generation), ConfigDigest: digest,
	}
	marker := observability.Present(true)
	canaryOperation := observability.Present(v8CanaryOperationValue)
	canaryDestination := observability.Present(destination)
	conversationID := observability.Present("defenseclaw-runtime-canary")
	agentID := observability.Present("defenseclaw-runtime-canary")

	rootRecord, buildErr := builder.BuildSpanAgentInvoke(observability.SpanAgentInvokeInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceSystem,
			Correlation: observability.Correlation{
				TraceID: result.TraceID, SpanID: rootSpanContext.SpanID().String(),
			},
			Provenance: provenance,
		},
		Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(rootStart.UnixNano()), EndTimeUnixNano: uint64(rootEnd.UnixNano()),
		ParentSpanID: observability.Absent[string](), TraceState: traceState,
		Flags: v8CanaryOTLPFlags(rootSpanContext, rootParent), Status: observability.NewTraceStatusOK(),
		Resource: resource.Resource, Scope: observability.TraceScopeInput{},
		ResourceServiceName: resource.ServiceName, ResourceServiceNamespace: resource.ServiceNamespace,
		ResourceServiceInstanceID:         resource.ServiceInstanceID,
		ResourceDeploymentEnvironmentName: resource.DeploymentEnvironmentName,
		ResourceHostName:                  resource.HostName, ResourceHostArch: resource.HostArch, ResourceOsType: resource.OSType,
		ResourceTenantID: resource.TenantID, ResourceWorkspaceID: resource.WorkspaceID,
		ResourceDefenseClawDeploymentMode:             resource.DefenseClawDeploymentMode,
		ResourceDefenseClawClawMode:                   resource.DefenseClawClawMode,
		ResourceDefenseClawInstanceID:                 resource.DefenseClawInstanceID,
		ResourceDefenseClawDevicePublicKeyFingerprint: resource.DefenseClawDevicePublicKeyFingerprint,
		DefenseClawTelemetryCanary:                    marker, DefenseClawTelemetryCanaryOperation: canaryOperation,
		DefenseClawTelemetryCanaryDestination: canaryDestination,
		GenAIConversationID:                   conversationID, GenAIAgentID: agentID,
		GenAIAgentName: observability.Present("defenseclaw"), DefenseClawAgentType: "diagnostic",
		GenAIOperationName:                  observability.Present("invoke_agent"),
		GenAIProviderName:                   observability.Present("openai"),
		DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:   false, DefenseClawContentInputState: "not_reported",
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		ConditionConnectorKnown: false, ConditionOperationTerminal: true, ConditionTechnicalFailure: false,
	})
	if buildErr != nil {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}

	childRecord, buildErr := builder.BuildSpanModelChat(observability.SpanModelChatInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceSystem,
			Correlation: observability.Correlation{
				TraceID: result.TraceID, SpanID: childSpanContext.SpanID().String(),
			},
			Provenance: provenance,
		},
		Outcome: observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: uint64(childStart.UnixNano()), EndTimeUnixNano: uint64(childEnd.UnixNano()),
		ParentSpanID: observability.Present(rootSpanContext.SpanID().String()), TraceState: traceState,
		Flags: v8CanaryOTLPFlags(childSpanContext, rootSpanContext), Status: observability.NewTraceStatusOK(),
		Resource: resource.Resource, Scope: observability.TraceScopeInput{},
		ResourceServiceName: resource.ServiceName, ResourceServiceNamespace: resource.ServiceNamespace,
		ResourceServiceInstanceID:         resource.ServiceInstanceID,
		ResourceDeploymentEnvironmentName: resource.DeploymentEnvironmentName,
		ResourceHostName:                  resource.HostName, ResourceHostArch: resource.HostArch, ResourceOsType: resource.OSType,
		ResourceTenantID: resource.TenantID, ResourceWorkspaceID: resource.WorkspaceID,
		ResourceDefenseClawDeploymentMode:             resource.DefenseClawDeploymentMode,
		ResourceDefenseClawClawMode:                   resource.DefenseClawClawMode,
		ResourceDefenseClawInstanceID:                 resource.DefenseClawInstanceID,
		ResourceDefenseClawDevicePublicKeyFingerprint: resource.DefenseClawDevicePublicKeyFingerprint,
		DefenseClawTelemetryCanary:                    marker, DefenseClawTelemetryCanaryOperation: canaryOperation,
		DefenseClawTelemetryCanaryDestination: canaryDestination,
		GenAIConversationID:                   conversationID, GenAIAgentID: agentID,
		GenAIAgentName:                      observability.Present("defenseclaw"),
		DefenseClawAgentType:                observability.Present("diagnostic"),
		DefenseClawAgentReportedCostPresent: false,
		DefenseClawTelemetryInputReported:   false, DefenseClawContentInputState: "not_reported",
		DefenseClawTelemetryOutputReported: false, DefenseClawContentOutputState: "not_reported",
		GenAIOperationName: observability.Present("chat"),
		GenAIProviderName:  observability.Present("openai"), GenAIRequestModel: "gpt-4o-mini",
		DefenseClawTelemetryTokensReported: observability.Present(false),
		ConditionConnectorKnown:            false, ConditionOperationTerminal: true, ConditionTechnicalFailure: false,
	})
	if buildErr != nil {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}

	if registration := p.EndV8CanonicalSpan(child, childRecord); registration != V8CanonicalSpanRegistered {
		childEnded = true
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	childEnded = true
	if registration := p.EndV8CanonicalSpan(root, rootRecord); registration != V8CanonicalSpanRegistered {
		rootEnded = true
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	rootEnded = true
	if err := p.tracerProvider.ForceFlush(ctx); err != nil {
		return result, newV8ProviderError(V8ProviderErrorFlush, err)
	}
	result.Acknowledged = p.DestinationAcknowledgedCanaryTrace(destination, result.TraceID)
	if !result.Acknowledged {
		return result, newV8ProviderError(V8ProviderErrorCanary, nil)
	}
	return result, nil
}

func (p *Provider) v8CanaryStartAttributes(
	bucket observability.Bucket,
	family string,
	destination string,
) []attribute.KeyValue {
	return append(p.v8StartAttributes(bucket),
		attribute.String("defenseclaw.span.family", family),
		attribute.Int64("defenseclaw.span.family_schema_version", v8CanaryFamilySchemaVersion),
		attribute.String("defenseclaw.source", string(observability.SourceSystem)),
		attribute.String("defenseclaw.outcome", string(observability.OutcomeCompleted)),
		attribute.Bool(telemetryCanaryAttribute, true),
		attribute.String(v8CanaryOperationAttribute, v8CanaryOperationValue),
		attribute.String(telemetryCanaryDestinationAttribute, destination),
	)
}

func v8CanarySignalSelected(selected []observability.Signal, signal observability.Signal) bool {
	for _, candidate := range selected {
		if candidate == signal {
			return true
		}
	}
	return false
}

func v8CanaryTraceState(state trace.TraceState) observability.Optional[string] {
	if state.String() == "" {
		return observability.Absent[string]()
	}
	return observability.Present(state.String())
}

func v8CanaryOTLPFlags(span, parent trace.SpanContext) uint32 {
	flags := uint32(span.TraceFlags()) | 0x100
	if parent.IsValid() && parent.IsRemote() {
		flags |= 0x200
	}
	return flags
}
