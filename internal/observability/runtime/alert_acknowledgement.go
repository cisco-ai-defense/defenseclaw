// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// ApplyAlertAcknowledgement pins the active graph generation across canonical
// compliance-event construction and the protected-state CAS transaction.
func (runtime *Runtime) ApplyAlertAcknowledgement(
	ctx context.Context,
	command audit.AlertAcknowledgementCommand,
) (audit.AlertAcknowledgementResult, error) {
	if runtime == nil || runtime.manager == nil || ctx == nil {
		return audit.AlertAcknowledgementResult{}, &Error{code: ErrorInvalidDependency}
	}
	lease, err := runtime.manager.Acquire(ctx)
	if err != nil {
		return audit.AlertAcknowledgementResult{}, err
	}
	defer lease.Release()
	graph := lease.Graph()
	componentValue, ok := lease.Component(LocalLogComponentName)
	component, typeOK := componentValue.(*localLogComponent)
	if graph == nil || !ok || !typeOK || component == nil || component.digest != graph.Digest() {
		return audit.AlertAcknowledgementResult{}, &Error{code: ErrorComponentUnavailable}
	}
	return component.applyAlertAcknowledgement(ctx, command)
}
