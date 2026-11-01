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

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// An upgrade on saturated processors stops at once with the retryable
// lifecycle_busy (1618) and the next step, instead of running past
// TIMEOUTSECONDS into lifecycle_timeout (GAP-2265). A no-op ensure, a repair,
// an uninstall, a fresh install, a quiet computer and an unknown idle share
// are never refused.
func TestEnterpriseSetupRefusesAnUpgradeOnSaturatedProcessors(t *testing.T) {
	original := enterpriseSetupHostIdlePercent
	t.Cleanup(func() { enterpriseSetupHostIdlePercent = original })
	measured := 0
	idle, known := 3, true
	enterpriseSetupHostIdlePercent = func(window time.Duration) (int, bool) {
		measured++
		if window != enterpriseSetupBusySampleWindow {
			t.Fatalf("sample window %s, want %s", window, enterpriseSetupBusySampleWindow)
		}
		return idle, known
	}
	installed := winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentInstalled, ProductVersion: "1.0.3"}

	for _, action := range []string{"ensure", "upgrade"} {
		err := requireEnterpriseSetupHostCapacity(action, installed, "1.0.5")
		if err == nil || !errors.Is(err, errEnterpriseSetupEnsureBusy) {
			t.Fatalf("%s on saturated processors: %v", action, err)
		}
		for _, want := range []string{"lifecycle_busy:", "only 3% idle", "from 1.0.3 to 1.0.5", "Nothing was changed",
			"run Setup /ensure again when the computer is less busy", "1618"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s refusal lacks %q: %v", action, want, err)
			}
		}
	}

	// The Setup JSON result is the retryable busy result an MDM retries.
	var stdout, stderr bytes.Buffer
	refusal := requireEnterpriseSetupHostCapacity("ensure", installed, "1.0.5")
	writeEnterpriseSetupFailureFor(&stdout, &stderr, true, standaloneSetupArtifactName,
		enterpriseSetupOptions{JSON: true, Action: "ensure"}, refusal, enterpriseBusyExitCode)
	var result struct {
		ExitCode int `json:"exit_code"`
		Errors   []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode %s: %v", stdout.String(), err)
	}
	if result.ExitCode != enterpriseBusyExitCode || len(result.Errors) != 1 || result.Errors[0].Code != "lifecycle_busy" {
		t.Fatalf("busy refusal result: %s", stdout.String())
	}

	measured = 0
	for _, quiet := range []struct {
		name       string
		action     string
		deployment winpath.EnterpriseDeployment
		version    string
	}{
		{"no-op ensure of the installed release", "ensure", installed, "1.0.3"},
		{"repair", "repair", installed, "1.0.5"},
		{"uninstall", "uninstall", installed, "1.0.5"},
		{"fresh install", "ensure", winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentAbsent}, "1.0.5"},
		{"tombstone", "ensure", winpath.EnterpriseDeployment{State: winpath.EnterpriseDeploymentTombstone, ProductVersion: "1.0.3"}, "1.0.5"},
	} {
		if err := requireEnterpriseSetupHostCapacity(quiet.action, quiet.deployment, quiet.version); err != nil {
			t.Fatalf("%s refused: %v", quiet.name, err)
		}
	}
	if measured != 0 {
		t.Fatalf("runs that replace no release measured the processors %d times", measured)
	}

	idle = enterpriseSetupBusyIdlePercent
	if err := requireEnterpriseSetupHostCapacity("ensure", installed, "1.0.5"); err != nil {
		t.Fatalf("upgrade with %d%% idle refused: %v", idle, err)
	}
	idle, known = 0, false
	if err := requireEnterpriseSetupHostCapacity("ensure", installed, "1.0.5"); err != nil {
		t.Fatalf("unknown idle share blocked Setup: %v", err)
	}
}
