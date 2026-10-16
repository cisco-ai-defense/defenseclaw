// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// #1207: under a profile that alerts at LOW itself (an offline floor's
// alert_at: low) an allowed LOW marker was flagged by the gateway and in the
// agent's TUI, but the feed and the session summary (which reads the feed's
// findings) dropped it with every LOW alert. A LOW alert of such a profile is
// a finding of the session; one of the rule pack's own levels still is not
// (GAP-0091, TestLowAlertsAreNoSessionFinding).
func TestLowAlertsOfALowAlertingProfileAreSessionFindings(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "lowfloor"})
	binding, d := e.binding("lowfloor"), e.decider("lowfloor", "Bash")
	e.m.ObserveIngress(binding, sandboxauth.RouteHook)
	packLow := d("PostToolUse", "t1", "alert")
	packLow.Severity, packLow.Reason = "LOW", "Allowed but flagged by DefenseClaw rule ENT-EMAIL-BULK: Email address."
	e.m.ObserveHookDecision(packLow)
	if got := e.events("lowfloor", sandboxapi.ActivityFinding, sandboxapi.ReasonHookFinding); len(got) != 0 {
		t.Fatalf("a rule pack LOW alert on the feed: %+v", got)
	}
	profileLow := d("PostToolUse", "t2", "alert")
	profileLow.Severity, profileLow.AlertsLow = "LOW", true
	profileLow.Reason = "Allowed but flagged by DefenseClaw rule E2E-SANDBOX-LOW: E2E sandbox LOW marker."
	e.m.ObserveHookDecision(profileLow)
	got := e.events("lowfloor", sandboxapi.ActivityFinding, sandboxapi.ReasonHookFinding)
	if len(got) != 1 || got[0].Severity != "LOW" {
		t.Fatalf("findings = %+v, want the profile's LOW alert", got)
	}
	// An allow below the threshold is still no finding, whatever the profile.
	allow := d("PostToolUse", "t3", "allow")
	allow.Severity, allow.AlertsLow, allow.Reason = "LOW", true, "kept"
	e.m.ObserveHookDecision(allow)
	if got := e.events("lowfloor", sandboxapi.ActivityFinding, sandboxapi.ReasonHookFinding); len(got) != 1 {
		t.Fatalf("findings after a plain allow = %+v", got)
	}
}
