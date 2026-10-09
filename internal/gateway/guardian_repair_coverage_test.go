// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestGuardianRepairCoverageRequiresMatchingProtectedProof(t *testing.T) {
	for _, name := range []string{"valid", "valid-customer-six-targets", "stale-state", "wrong-manifest", "missing-history", "duplicate-target", "different-profile", "pending-error", "pending-result", "invalid-reconcile", "invalid-digest", "untrusted-proof", "missing-state"} {
		t.Run(name, func(t *testing.T) {
			dataDir := t.TempDir()
			authorizationDir := t.TempDir()
			t.Setenv(managed.HookGuardianAuthorizationDirEnv, authorizationDir)
			priorValidate := validateManagedGuardianAuthorization
			validateManagedGuardianAuthorization = func(_, _ string) error { return nil }
			t.Cleanup(func() { validateManagedGuardianAuthorization = priorValidate })
			fresh := time.Now().UTC().Format(time.RFC3339Nano)
			active := managedGuardianAuthorizationTarget{Connector: "codex", SID: "S-1-5-21-1-2-3-1001", UserHome: filepath.Join(dataDir, "active"), OK: true}
			history := managedGuardianAuthorizationTarget{Connector: "codex", SID: "S-1-5-21-1-2-3-1002", UserHome: filepath.Join(dataDir, "offline"), OK: true}
			offline := history
			offline.OK = false
			authorization := managedGuardianAuthorization{Version: 1, UpdatedAt: fresh, OK: true, TargetCount: 2, SuccessCount: 1, PendingCount: 1, ProtectedTargets: []managedGuardianAuthorizationTarget{active, history}}
			state := managedGuardianCoverageProof{Version: 1, UpdatedAt: fresh, Manifest: filepath.Join(dataDir, "targets.yaml"), OK: true, TargetCount: 2, SuccessCount: 1, PendingCount: 1, Results: []managedGuardianCurrentTarget{{managedGuardianAuthorizationTarget: active}, {managedGuardianAuthorizationTarget: offline, Pending: true}}}
			activation := state
			activation.Results = nil
			activation.ReconcileID = strings.Repeat("a", 32)
			activation.ManifestSHA256 = strings.Repeat("b", 64)
			activation.ProtectedTargets = append([]managedGuardianAuthorizationTarget(nil), authorization.ProtectedTargets...)
			connectors := []string{"codex"}
			switch name {
			case "valid-customer-six-targets":
				connectors = []string{"claudecode", "codex", "cursor"}
				authorization.TargetCount, authorization.SuccessCount, authorization.PendingCount = 6, 3, 3
				state.TargetCount, state.SuccessCount, state.PendingCount = 6, 3, 3
				activation.TargetCount, activation.SuccessCount, activation.PendingCount = 6, 3, 3
				authorization.ProtectedTargets, state.Results = nil, nil
				for _, connector := range connectors {
					currentActive, priorOffline := active, history
					currentActive.Connector, priorOffline.Connector = connector, connector
					currentOffline := priorOffline
					currentOffline.OK = false
					authorization.ProtectedTargets = append(authorization.ProtectedTargets, currentActive, priorOffline)
					state.Results = append(state.Results, managedGuardianCurrentTarget{managedGuardianAuthorizationTarget: currentActive}, managedGuardianCurrentTarget{managedGuardianAuthorizationTarget: currentOffline, Pending: true})
				}
				activation.ProtectedTargets = append([]managedGuardianAuthorizationTarget(nil), authorization.ProtectedTargets...)
			case "stale-state":
				state.UpdatedAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
			case "wrong-manifest":
				activation.Manifest = filepath.Join(dataDir, "other.yaml")
			case "missing-history":
				activation.ProtectedTargets = activation.ProtectedTargets[:1]
			case "duplicate-target":
				state.Results[1] = state.Results[0]
			case "different-profile":
				state.Results[1].UserHome += "-other"
			case "pending-error":
				state.Results[1].Error = "identity mismatch"
			case "pending-result":
				state.Results[1].Result = &enterprisehooks.InstallResult{Connector: "codex"}
			case "invalid-reconcile":
				activation.ReconcileID = "invalid"
			case "invalid-digest":
				activation.ManifestSHA256 = "invalid"
			case "untrusted-proof":
				validateManagedGuardianAuthorization = func(path, _ string) error {
					if filepath.Base(path) == "activation.json" {
						return errors.New("untrusted activation")
					}
					return nil
				}
			}
			write := func(path string, value any) {
				t.Helper()
				body, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			write(managed.HookGuardianAuthorizationPath(dataDir), authorization)
			if name != "missing-state" {
				write(filepath.Join(dataDir, "hook_guardian_state.json"), state)
			}
			write(filepath.Join(authorizationDir, "activation.json"), activation)
			ok, reason := managedGuardianCoversConnectors(dataDir, connectors)
			if strings.HasPrefix(name, "valid") != ok {
				t.Fatalf("coverage=%v reason=%s", ok, reason)
			}
		})
	}
}
