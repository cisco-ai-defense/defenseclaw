// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

import (
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// keepProtectedHooksOnRepairFailure reports whether a failed install must
// leave the connector's hooks in place instead of tearing them down. A target
// with a hook contract lock was protected before this pass, so the failure is
// a repair failure: Teardown would strip DefenseClaw's entries and leave the
// exit 0 tombstone, opening the agent regardless of the fail mode until a later
// pass succeeds. The scripts Setup just wrote, or the ones already there, keep
// enforcing; the lock is restored so the next pass verifies and repairs again.
// Teardown happens only on a fresh, never-protected install and on revoke.
func keepProtectedHooksOnRepairFailure(previous connector.HookContractLockEntry) bool {
	return strings.TrimSpace(previous.Connector) != ""
}

// protectedHookRepairFailures holds the targets whose degraded line was
// already logged in the current failure streak.
var protectedHookRepairFailures sync.Map

func protectedHookRepairKey(dataDir, connectorName string) string {
	return filepath.Clean(dataDir) + "\x00" + connectorName
}

// reportProtectedHookRepairFailure logs one defenseclaw_degraded line per
// failure streak for a target whose hooks were kept after a failed repair.
func reportProtectedHookRepairFailure(dataDir, connectorName string, cause error) {
	if _, seen := protectedHookRepairFailures.LoadOrStore(protectedHookRepairKey(dataDir, connectorName), struct{}{}); seen {
		return
	}
	reason := "hook repair failed; installed hooks kept, retrying next pass"
	if cause != nil {
		reason += ": " + cause.Error()
	}
	managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
		"subsystem": "hooks",
		"connector": connectorName,
		"path":      filepath.Clean(dataDir),
		"reason":    reason,
	})
}

// clearProtectedHookRepairFailure ends the failure streak after a successful
// install, so the next failure is logged again.
func clearProtectedHookRepairFailure(dataDir, connectorName string) {
	protectedHookRepairFailures.Delete(protectedHookRepairKey(dataDir, connectorName))
}
