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
// tick. On macOS the gateway runs as root and owns the store, so it repairs
// the store itself before each attempt and never gives up. Waiting here keeps
// the service up instead of exiting into a restart loop. Only the
// long-running gateway (the root sidecar command) waits; short-lived
// subcommands and non-managed deployments return the first failure as
// before.
var (
	gatewayAuditOpenBudget       = 3 * time.Minute
	gatewayAuditOpenInitialDelay = 5 * time.Second
	gatewayAuditOpenMaxDelay     = 30 * time.Second
)

// openAuditStoreWaitingForRepair runs attempt and, in a managed deployment,
// retries it on the gatewayAuditOpen* backoff until it succeeds, the budget
// runs out (never, for the macOS Secure Client gateway) or ctx ends. Before
// each retry the platform repair runs. Outside managed mode the first failure
// is returned.
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
	reason, unbounded := gatewayAuditOpenWait()
	managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
		"subsystem": "audit store",
		"path":      path,
		"reason":    reason + err.Error(),
	})
	deadline := time.Now().Add(gatewayAuditOpenBudget)
	delay := gatewayAuditOpenInitialDelay
	for unbounded || time.Now().Before(deadline) {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
		repairGatewayAuditStorePlatform(deploymentMode, path)
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

// gatewayAuditGuardianWaitReason is the degraded line of a gateway that waits
// for the guardian to repair its audit store.
const gatewayAuditGuardianWaitReason = "audit store unavailable at startup; waiting for the guardian to repair it: "

// gatewayAuditOpenWait is how this process waits for a managed audit store:
// the reason it logs and whether it keeps retrying past the budget. Only the
// macOS Secure Client gateway repairs its own store and never gives up; a
// standalone process waits for the guardian within the budget, as before.
func gatewayAuditOpenWait() (reason string, unbounded bool) {
	if managed.StandaloneTrustScope() {
		return gatewayAuditGuardianWaitReason, false
	}
	return gatewayAuditOpenWaitReason, gatewayAuditOpenUnbounded
}
