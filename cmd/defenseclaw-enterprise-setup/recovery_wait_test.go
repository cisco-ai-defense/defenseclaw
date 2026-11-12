// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// rel-1-0-6:GAP-1080: every run that changes the deployment waits for an armed
// uninstall recovery; read-only runs and the recovery's own run do not.
func TestStandaloneSetupRunsThatWaitForAnArmedUninstallRecovery(t *testing.T) {
	for _, action := range []string{"install", "upgrade", "repair", "ensure", "uninstall"} {
		if !standaloneSetupWaitsForRecovery(enterpriseSetupOptions{Action: action, Standalone: true}) {
			t.Errorf("standalone %s does not wait for the armed recovery", action)
		}
	}
	for _, action := range []string{"status", "verify", "recover", "reconcile", ""} {
		if standaloneSetupWaitsForRecovery(enterpriseSetupOptions{Action: action, Standalone: true}) {
			t.Errorf("standalone %s waits for the armed recovery", action)
		}
	}
	if standaloneSetupWaitsForRecovery(enterpriseSetupOptions{Action: "uninstall"}) {
		t.Error("the Secure Client Setup waits for a standalone recovery")
	}
}

func TestStandaloneRecoveryWaitLeavesTheLifecycleItsStart(t *testing.T) {
	previous := enterpriseSetupRecoveryWaitLimit
	t.Cleanup(func() { enterpriseSetupRecoveryWaitLimit = previous })
	enterpriseSetupRecoveryWaitLimit = 10 * time.Minute
	now := time.Now()
	if got := standaloneRecoveryWaitBound(enterpriseSetupOptions{LifecycleTimeout: 30 * time.Minute, Started: now}, now); got != 10*time.Minute {
		t.Errorf("default TIMEOUTSECONDS: wait %s, want the 10 minute limit", got)
	}
	if got := standaloneRecoveryWaitBound(enterpriseSetupOptions{LifecycleTimeout: 5 * time.Minute, Started: now}, now); got != 150*time.Second {
		t.Errorf("TIMEOUTSECONDS=300: wait %s, want 2m30s (the action keeps half of TIMEOUTSECONDS)", got)
	}
	// An upgrade after the longest wait still has half of its own budget:
	// a wait to the 60-second start minimum left it a minute, and it timed
	// out midway and rolled back (1.0.10 T1 review).
	if got := standaloneRecoveryWaitBound(enterpriseSetupOptions{LifecycleTimeout: 11 * time.Minute, Started: now}, now); got != 330*time.Second {
		t.Errorf("TIMEOUTSECONDS=660: wait %s, want 5m30s", got)
	}
	if got := standaloneRecoveryWaitBound(enterpriseSetupOptions{LifecycleTimeout: 90 * time.Second, Started: now}, now); got != 30*time.Second {
		t.Errorf("TIMEOUTSECONDS=90: wait %s, want 30s (never under the 60 s start)", got)
	}
	if got := standaloneRecoveryWaitBound(enterpriseSetupOptions{LifecycleTimeout: 5 * time.Minute, Started: now.Add(-6 * time.Minute)}, now); got != 0 {
		t.Errorf("spent TIMEOUTSECONDS: wait %s, want a check only", got)
	}
}

// The refusal is the retryable 1618 lifecycle_busy an MDM reruns, says that
// nothing changed and points at the rerun, and offers no FORCE.
func TestStandaloneRecoveryBusyIsTheRetryableBusyResult(t *testing.T) {
	err := error(enterpriseSetupRecoveryBusy{action: "uninstall", waited: 10*time.Minute + 300*time.Millisecond})
	if !errors.Is(err, errEnterpriseSetupEnsureBusy) {
		t.Fatal("the recovery wait refusal is not the retryable busy result")
	}
	text := err.Error()
	for _, want := range []string{"lifecycle_busy: ", "earlier Setup /uninstall", "waited 10m0s", "changed nothing", "run Setup /uninstall again", "1618"} {
		if !strings.Contains(text, want) {
			t.Errorf("refusal %q does not say %q", text, want)
		}
	}
	if strings.Contains(text, "FORCE") {
		t.Errorf("refusal offers FORCE: %q", text)
	}
	var stdout, stderr bytes.Buffer
	writeEnterpriseSetupFailureFor(&stdout, &stderr, true, standaloneSetupArtifactName,
		enterpriseSetupOptions{Action: "uninstall", JSON: true}, err, enterpriseBusyExitCode)
	var result struct {
		ExitCode int `json:"exit_code"`
		Errors   []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.ExitCode != enterpriseBusyExitCode ||
		len(result.Errors) != 1 || result.Errors[0].Code != "lifecycle_busy" {
		t.Fatalf("JSON refusal: %s (parse %v)", stdout.String(), err)
	}
}
