// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

func (owner *sidecarOwnedObservabilityV8Runtime) StartAIDiscoveryTrace(
	ctx context.Context,
	input observability.SpanAIDiscoveryInput,
) (context.Context, *observabilityruntime.AIDiscoveryTrace, error) {
	if owner == nil || owner.runtime == nil {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	owner.lifecycleMu.RLock()
	defer owner.lifecycleMu.RUnlock()
	if owner.closed {
		return ctx, nil, newSidecarObservabilityV8BootstrapError(sidecarObservabilityV8BootstrapClose, nil)
	}
	return owner.runtime.StartAIDiscoveryTrace(ctx, input)
}

var _ aiDiscoveryV8Runtime = (*sidecarOwnedObservabilityV8Runtime)(nil)
