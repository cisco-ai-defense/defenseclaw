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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

// AIDiscoveryTrace is one bounded continuous-discovery scan. Detector children
// share its generation lease so a reload cannot split one scan across two
// routing, resource, or sampling policies.
type AIDiscoveryTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// AIDiscoveryDetectorTrace is one real detector invocation nested under the
// scan which invoked it. Detector identity and terminal facts remain entirely
// producer supplied.
type AIDiscoveryDetectorTrace struct {
	session *generatedTraceSession
	node    *generatedTraceNode
}

// StartAIDiscoveryTrace starts a real continuous-discovery scan. A nil handle
// with a nil error means collection or sampling declined the span. The active
// v8 runtime remains authoritative in that case and callers must not resurrect
// a legacy SDK span.
func (runtime *Runtime) StartAIDiscoveryTrace(
	ctx context.Context,
	input observability.SpanAIDiscoveryInput,
) (context.Context, *AIDiscoveryTrace, error) {
	startedContext, session, node, err := runtime.startGeneratedTrace(
		ctx,
		observability.BucketAIDiscovery,
		observability.TelemetryFamilyAIDiscovery,
		input.Kind,
		"scan",
		input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return startedContext, nil, err
	}
	return startedContext, &AIDiscoveryTrace{session: session, node: node}, nil
}

// StartDetector starts a generated detector child under this exact scan. A nil
// child with a nil error is normal when child collection or sampling declines
// the occurrence; it does not terminate the parent scan.
func (span *AIDiscoveryTrace) StartDetector(
	input observability.SpanAIDiscoveryDetectorInput,
) (*AIDiscoveryDetectorTrace, error) {
	if span == nil || span.session == nil || span.node == nil ||
		input.DefenseClawAIDiscoveryDetector == "" {
		return nil, generatedTraceError(GeneratedTraceInvalidInput)
	}
	node, err := span.session.startChild(
		span.node,
		observability.BucketAIDiscovery,
		observability.TelemetryFamilyAIDiscoveryDetector,
		input.Kind,
		input.DefenseClawAIDiscoveryDetector,
		input.StartTimeUnixNano,
	)
	if err != nil || node == nil {
		return nil, err
	}
	return &AIDiscoveryDetectorTrace{session: span.session, node: node}, nil
}

func (span *AIDiscoveryTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}

func (span *AIDiscoveryDetectorTrace) Context() context.Context {
	if span == nil {
		return nil
	}
	return generatedNodeContext(span.session, span.node)
}

func (span *AIDiscoveryTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}

func (span *AIDiscoveryDetectorTrace) Generation() uint64 {
	if span == nil {
		return 0
	}
	return generatedNodeGeneration(span.session, span.node)
}

func (span *AIDiscoveryTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}

func (span *AIDiscoveryDetectorTrace) TraceID() string {
	if span == nil {
		return ""
	}
	return generatedNodeTraceID(span.session, span.node)
}

func (span *AIDiscoveryTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}

func (span *AIDiscoveryDetectorTrace) SpanID() string {
	if span == nil {
		return ""
	}
	return generatedNodeSpanID(span.session, span.node)
}

func (span *AIDiscoveryTrace) End(input observability.SpanAIDiscoveryInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endAIDiscovery(span.node, input)
}

func (span *AIDiscoveryDetectorTrace) End(input observability.SpanAIDiscoveryDetectorInput) error {
	if span == nil || span.session == nil || span.node == nil {
		return generatedTraceError(GeneratedTraceInvalidInput)
	}
	return span.session.endAIDiscoveryDetector(span.node, input)
}

func (span *AIDiscoveryTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (span *AIDiscoveryDetectorTrace) Abort() {
	if span != nil && span.session != nil {
		span.session.abort()
	}
}

func (session *generatedTraceSession) endAIDiscovery(
	node *generatedTraceNode,
	input observability.SpanAIDiscoveryInput,
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
	input = session.sealAIDiscoveryInput(input, node, end)
	record, buildErr := session.builder.BuildSpanAIDiscovery(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) endAIDiscoveryDetector(
	node *generatedTraceNode,
	input observability.SpanAIDiscoveryDetectorInput,
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
	input = session.sealAIDiscoveryDetectorInput(input, node, end)
	record, buildErr := session.builder.BuildSpanAIDiscoveryDetector(input)
	if buildErr != nil {
		session.abortLocked()
		return generatedTraceError(GeneratedTraceBuildRejected)
	}
	return session.registerEndLocked(node, input.Status, record)
}

func (session *generatedTraceSession) sealAIDiscoveryInput(
	input observability.SpanAIDiscoveryInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanAIDiscoveryInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano =
		node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags =
		generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	sealAIDiscoveryResource(session, &input.Resource, &input.Scope,
		&input.ResourceServiceName, &input.ResourceServiceNamespace,
		&input.ResourceServiceInstanceID, &input.ResourceDeploymentEnvironmentName,
		&input.ResourceHostName, &input.ResourceHostArch, &input.ResourceOsType,
		&input.ResourceTenantID, &input.ResourceWorkspaceID,
		&input.ResourceDefenseClawDeploymentMode, &input.ResourceDefenseClawClawMode,
		&input.ResourceDefenseClawInstanceID, &input.ResourceDefenseClawDevicePublicKeyFingerprint)
	return input
}

func (session *generatedTraceSession) sealAIDiscoveryDetectorInput(
	input observability.SpanAIDiscoveryDetectorInput,
	node *generatedTraceNode,
	end time.Time,
) observability.SpanAIDiscoveryDetectorInput {
	input.Envelope = session.sealEnvelope(input.Envelope, node)
	input.Kind, input.StartTimeUnixNano, input.EndTimeUnixNano =
		node.kind, uint64(node.start.UnixNano()), uint64(end.UnixNano())
	input.ParentSpanID, input.TraceState, input.Flags =
		generatedTraceParent(node), generatedTraceState(node.spanContext), generatedTraceFlags(node)
	sealAIDiscoveryResource(session, &input.Resource, &input.Scope,
		&input.ResourceServiceName, &input.ResourceServiceNamespace,
		&input.ResourceServiceInstanceID, &input.ResourceDeploymentEnvironmentName,
		&input.ResourceHostName, &input.ResourceHostArch, &input.ResourceOsType,
		&input.ResourceTenantID, &input.ResourceWorkspaceID,
		&input.ResourceDefenseClawDeploymentMode, &input.ResourceDefenseClawClawMode,
		&input.ResourceDefenseClawInstanceID, &input.ResourceDefenseClawDevicePublicKeyFingerprint)
	// The detector name established the child at Start and cannot be renamed by
	// a mutable terminal snapshot.
	input.DefenseClawAIDiscoveryDetector = node.nameKey
	return input
}

func sealAIDiscoveryResource(
	session *generatedTraceSession,
	resource *observability.TraceResourceInput,
	scope *observability.TraceScopeInput,
	serviceName, serviceNamespace, serviceInstanceID, deploymentEnvironmentName *string,
	hostName, hostArch, osType, tenantID, workspaceID *observability.Optional[string],
	deploymentMode, clawMode *observability.Optional[string],
	instanceID *string,
	deviceFingerprint *observability.Optional[string],
) {
	*resource, *scope = session.resource.Resource, observability.TraceScopeInput{}
	*serviceName = session.resource.ServiceName
	*serviceNamespace = session.resource.ServiceNamespace
	*serviceInstanceID = session.resource.ServiceInstanceID
	*deploymentEnvironmentName = session.resource.DeploymentEnvironmentName
	*hostName, *hostArch, *osType = session.resource.HostName, session.resource.HostArch, session.resource.OSType
	*tenantID, *workspaceID = session.resource.TenantID, session.resource.WorkspaceID
	*deploymentMode = session.resource.DefenseClawDeploymentMode
	*clawMode = session.resource.DefenseClawClawMode
	*instanceID = session.resource.DefenseClawInstanceID
	*deviceFingerprint = session.resource.DefenseClawDevicePublicKeyFingerprint
}
