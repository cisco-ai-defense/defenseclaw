// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A managed gateway that can't open its audit store usually lost its write
// entry to permission drift; the LocalSystem guardian puts it back within a
// tick. Waiting here keeps the service up instead of exiting into a restart
// loop. Only the long-running gateway (the root sidecar command) waits;
// short-lived subcommands and non-managed deployments return the first
// failure as before.
var (
	gatewayAuditOpenBudget       = 3 * time.Minute
	gatewayAuditOpenInitialDelay = 5 * time.Second
	gatewayAuditOpenMaxDelay     = 30 * time.Second
)

// openAuditStoreWaitingForRepair runs attempt and, in a managed deployment,
// retries it on the gatewayAuditOpen* backoff until it succeeds, the budget
// runs out or ctx ends. Outside managed mode the first failure is returned.
func openAuditStoreWaitingForRepair(
	ctx context.Context,
	deploymentMode, path string,
	attempt func() (*audit.Store, error),
) (*audit.Store, error) {
	store, err := attempt()
	if err == nil || !managed.IsManagedEnterprise(deploymentMode) {
		return store, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
		"subsystem": "audit store",
		"path":      path,
		"reason":    "audit store unavailable at startup; waiting for the guardian to repair it: " + err.Error(),
	})
	deadline := time.Now().Add(gatewayAuditOpenBudget)
	delay := gatewayAuditOpenInitialDelay
	for time.Now().Before(deadline) {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
		if store, err = attempt(); err == nil {
			managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
				"subsystem": "audit store",
				"path":      path,
				"reason":    "audit store available again",
			})
			return store, nil
		}
		if delay *= 2; delay > gatewayAuditOpenMaxDelay {
			delay = gatewayAuditOpenMaxDelay
		}
	}
	return nil, err
}
