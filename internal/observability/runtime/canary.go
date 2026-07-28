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

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// TraceCanaryResult is the content-free public runtime result used by the
// diagnostic API. Generation identifies the exact graph retained through
// acknowledgement.
type TraceCanaryResult struct {
	TraceID      string
	Destination  string
	Generation   uint64
	Acknowledged bool
}

// EmitTraceCanary acquires exactly one runtime graph and retains its lease
// through generated record construction, canonical handoff, flush, and exact
// destination acknowledgement. Reload may publish a successor concurrently,
// but cannot retire this generation until the method releases its lease.
func (runtime *Runtime) EmitTraceCanary(
	ctx context.Context,
	destination string,
) (TraceCanaryResult, error) {
	result := TraceCanaryResult{}
	if runtime == nil || runtime.manager == nil || ctx == nil || !observability.IsStableToken(destination) {
		return result, &Error{code: ErrorInvalidDependency}
	}
	result.Destination = destination
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return result, err
	}
	defer lease.Release()
	provider, ok := telemetry.V8ProviderFromLease(lease)
	if !ok {
		return result, &Error{code: ErrorComponentUnavailable}
	}
	canary, canaryErr := provider.EmitV8GeneratedCanary(ctx, lease, destination)
	result = TraceCanaryResult{
		TraceID: canary.TraceID, Destination: canary.Destination,
		Generation: canary.Generation, Acknowledged: canary.Acknowledged,
	}
	return result, canaryErr
}
