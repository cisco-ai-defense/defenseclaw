// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// LatestLifecycleProjection pins the active graph generation and reads one
// exact lifecycle projection through that generation's integrity-aware local
// writer. A reload therefore cannot verify a row with one signer and consume
// it through another generation's component.
func (runtime *Runtime) LatestLifecycleProjection(
	ctx context.Context,
	query audit.LifecycleProjectionQuery,
) (audit.LifecycleProjection, bool, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil {
		return audit.LifecycleProjection{}, false, &Error{code: ErrorInvalidDependency}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return audit.LifecycleProjection{}, false, err
	}
	defer lease.Release()
	graph := lease.Graph()
	component, ok := lease.Component(LocalLogComponentName)
	if graph == nil || !ok {
		return audit.LifecycleProjection{}, false, &Error{code: ErrorComponentUnavailable}
	}
	local, ok := component.(*localLogComponent)
	if !ok || local.digest != graph.Digest() || local.history == nil ||
		!local.active.Load() || local.closed.Load() {
		return audit.LifecycleProjection{}, false, &Error{code: ErrorComponentUnavailable}
	}
	return local.history.LatestLifecycleProjection(ctx, query)
}
