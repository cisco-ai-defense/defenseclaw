// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// ProjectManagedLog pins the current generation and returns its managed-only
// redaction projection without local persistence or dispatcher side effects.
// It does not resolve credentials, send network traffic, or bypass routing.
func (runtime *Runtime) ProjectManagedLog(ctx context.Context, metadata router.Metadata, builder EmitBuilder) (pipeline.LocalLogOutcome, error) {
	outcomes, err := runtime.ProjectManagedLogBatch(ctx, []LogBatchItem{{Context: ctx, Metadata: metadata, Builder: builder}})
	if err != nil {
		return pipeline.LocalLogOutcome{}, err
	}
	return outcomes[0], nil
}

// ProjectManagedLogBatch binds at most one bounded manifest's parts to one
// runtime generation, so reload cannot mix redaction policies mid-preview.
func (runtime *Runtime) ProjectManagedLogBatch(ctx context.Context, items []LogBatchItem) ([]pipeline.LocalLogOutcome, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil || len(items) == 0 || len(items) > 128 {
		return nil, &Error{code: ErrorInvalidDependency}
	}
	for _, item := range items {
		if item.Context == nil || item.Builder == nil {
			return nil, &Error{code: ErrorInvalidDependency}
		}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer lease.Release()
	graph := lease.Graph()
	component, ok := lease.Component(LocalLogComponentName)
	if graph == nil || !ok {
		return nil, &Error{code: ErrorComponentUnavailable}
	}
	local, ok := component.(*localLogComponent)
	if !ok || local.pipeline == nil || !local.active.Load() || local.closed.Load() || local.digest != graph.Digest() {
		return nil, &Error{code: ErrorComponentUnavailable}
	}
	snapshot := EmitContext{plan: graph.Plan(), digest: graph.Digest(), generation: graph.Generation()}
	outcomes := make([]pipeline.LocalLogOutcome, 0, len(items))
	for _, item := range items {
		if !managedManifestGenerationMatches(item.Context, graph.Generation()) {
			return nil, &Error{code: ErrorComponentUnavailable}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		outcome, err := local.pipeline.ProjectManagedLog(item.Context, item.Metadata, leaseRecordBuilder(item.Context, lease, snapshot, item.Builder, false))
		if err != nil {
			return nil, err
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}
