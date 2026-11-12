// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

var endpointHealthTestNow = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

// healthyEndpointHealthSources is a managed endpoint with nothing wrong.
func healthyEndpointHealthSources() endpointHealthSources {
	started := endpointHealthTestNow.Add(-2 * time.Hour)
	running := func() SubsystemHealth { return SubsystemHealth{State: StateRunning, Since: started} }
	activity := endpointHealthTestNow.Add(-time.Minute)
	return endpointHealthSources{
		Now:              endpointHealthTestNow,
		PreviousReportAt: endpointHealthTestNow.Add(-30 * time.Minute),
		Health: HealthSnapshot{
			StartedAt: started,
			UptimeMs:  (2 * time.Hour).Milliseconds(),
			Gateway:   running(), Watcher: running(), Config: running(), API: running(),
			Guardrail: running(), Routing: SubsystemHealth{State: StateDisabled, Since: started},
			Telemetry: running(), AIDiscovery: running(), AIRuntime: running(),
			ApplicationProtection: running(),
			Managed:               &SubsystemHealth{State: StateRunning, Since: started},
			Configuration:         &ConfigurationHealth{State: ConfigStateReady, Since: started},
			Connectors: []ConnectorHealth{
				{Name: "claudecode", State: StateRunning, LastActivityAt: &activity, ToolInspectionMode: "enforce"},
				{Name: "codex", State: StateRunning, ToolInspectionMode: "enforce"},
			},
		},
		CloudDelivery: &observabilityruntime.DestinationHealth{
			Name: "managed-enterprise-ai-defense", State: delivery.HealthHealthy,
			CircuitState: delivery.CircuitClosed, LastSuccess: endpointHealthTestNow.Add(-time.Minute),
		},
		InspectionEnabled:   true,
		InspectionAvailable: true,
		InspectionObserved:  true,
		CMIDTokenOK:         true,
		CMIDLastSuccess:     endpointHealthTestNow.Add(-time.Minute),
		Guardian: endpointHealthGuardianSource{
			Present:   true,
			UpdatedAt: endpointHealthTestNow.Add(-30 * time.Second),
			ReadAt:    endpointHealthTestNow,
			Targets: []endpointHealthGuardianTarget{
				{Connector: "claudecode", UserID: "S-1-5-21-1-2-3-1001", OK: true},
				{Connector: "codex", UserID: "S-1-5-21-1-2-3-1001", OK: true},
			},
		},
		ProductVersion:          "1.0.9",
		PolicyApplied:           true,
		PolicyBundleVersion:     "sha256:" + strings.Repeat("a", 16),
		DiscoveryEnabled:        true,
		DiscoveryLastFullScanAt: endpointHealthTestNow.Add(-20 * time.Minute),
		DiscoveryInterval:       30 * time.Minute,
		AVCVersion:              "5.1.21.4204",
		OSVersion:               "15.5",
	}
}

var endpointHealthTestMeta = endpointHealthReportMeta{
	ReportID: "6f1c2b3a-0000-4000-8000-000000000001", Sequence: 7,
	Trigger: endpointHealthTriggerScheduled, Interval: 30 * time.Minute,
}

func TestEndpointHealthHealthyBaseline(t *testing.T) {
	report := buildEndpointHealthReport(healthyEndpointHealthSources(), endpointHealthTestMeta)
	if report.Status != endpointHealthStatusHealthy || len(report.Reasons) != 0 {
		t.Fatalf("status = %s reasons = %+v, want healthy and none", report.Status, report.Reasons)
	}
	if report.ReportIntervalS != 1800 || report.Sequence != 7 || report.Trigger != "scheduled" ||
		report.GatewayConfiguration != "ready" || report.GuardianState != "running" ||
		report.HooksTargets != 2 || report.HooksOK != 2 || report.InspectionAIDefense != "ok" ||
		report.InspectionCMIDToken != "ok" || report.CloudDeliveryState != "healthy" ||
		report.LocalStoreAuditStore != "ok" || report.AVCVersion != "5.1.21.4204" ||
		report.GatewayUptimeS != 7200 {
		t.Fatalf("unexpected report fields: %+v", report)
	}
	if len(report.HooksConnectors) != 2 || report.HooksConnectors[0].Connector != "claudecode" ||
		report.HooksConnectors[0].ToolInspectionMode != "enforce" || report.HooksConnectors[0].LastActivityAt == "" {
		t.Fatalf("connectors = %+v", report.HooksConnectors)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		`"defenseclaw.health.reasons":[]`, `"defenseclaw.health.hooks.failing_targets":[]`,
		`"defenseclaw.health.version.avc":"5.1.21.4204"`, `"defenseclaw.health.local_store.audit_store":"ok"`,
	} {
		if !strings.Contains(string(encoded), key) {
			t.Errorf("encoded report lacks %s: %s", key, encoded)
		}
	}
}

func TestEndpointHealthReasonTable(t *testing.T) {
	type want struct {
		code, component, severity, connector string
	}
	cases := []struct {
		name   string
		mutate func(*endpointHealthSources)
		want   []want
	}{
		{"config waiting within grace", func(s *endpointHealthSources) {
			s.Health.UptimeMs = (5 * time.Minute).Milliseconds()
			s.Health.Configuration.State = ConfigStateWaitingForConfig
		}, []want{{"CONFIG_WAITING", "configuration", "starting", ""}}},
		{"config not ready after grace", func(s *endpointHealthSources) {
			s.Health.Configuration.State = ConfigStateWaitingForTargets
		}, []want{{"CONFIG_NOT_READY", "configuration", "unhealthy", ""}}},
		{"protection subsystem error", func(s *endpointHealthSources) {
			s.Health.Guardrail = SubsystemHealth{State: StateError, LastError: "dial tcp 127.0.0.1:4000: connection refused"}
		}, []want{{"SUBSYSTEM_ERROR", "guardrail", "unhealthy", ""}}},
		{"protection subsystem stopped", func(s *endpointHealthSources) {
			s.Health.Managed = &SubsystemHealth{State: StateStopped}
		}, []want{{"SUBSYSTEM_ERROR", "managed", "unhealthy", ""}}},
		{"api error", func(s *endpointHealthSources) {
			s.Health.API = SubsystemHealth{State: StateError}
		}, []want{{"SUBSYSTEM_ERROR", "api", "unhealthy", ""}}},
		{"routing error", func(s *endpointHealthSources) {
			s.Health.Routing = SubsystemHealth{State: StateError}
		}, []want{{"SUBSYSTEM_ERROR", "routing", "unhealthy", ""}}},
		{"subsystem degraded", func(s *endpointHealthSources) {
			s.Health.Sandbox = &SubsystemHealth{State: StateDegraded}
		}, []want{{"SUBSYSTEM_DEGRADED", "sandbox", "degraded", ""}}},
		{"subsystem reconnecting", func(s *endpointHealthSources) {
			s.Health.Guardrail = SubsystemHealth{State: StateReconnecting}
		}, []want{{"SUBSYSTEM_DEGRADED", "guardrail", "degraded", ""}}},
		{"non-protection subsystem error", func(s *endpointHealthSources) {
			s.Health.Watcher = SubsystemHealth{State: StateError}
		}, []want{{"SUBSYSTEM_DEGRADED", "watcher", "degraded", ""}}},
		{"source unreadable", func(s *endpointHealthSources) {
			s.CloudDelivery = nil
			s.SourceErrors = []string{endpointHealthSourceCloudDelivery}
		}, []want{{"SUBSYSTEM_DEGRADED", "cloud_delivery", "degraded", ""}}},
		{"guardian state unreadable", func(s *endpointHealthSources) {
			s.Guardian = endpointHealthGuardianSource{}
			s.SourceErrors = []string{endpointHealthSourceGuardianState}
		}, []want{{"SUBSYSTEM_DEGRADED", "guardian_state", "degraded", ""}}},
		{"hooks none", func(s *endpointHealthSources) {
			for i := range s.Guardian.Targets {
				s.Guardian.Targets[i].OK, s.Guardian.Targets[i].Error = false, "access is denied"
			}
		}, []want{
			{"HOOKS_NONE", "hooks", "unhealthy", ""},
			{"HOOKS_PARTIAL", "hooks", "degraded", "claudecode"},
			{"HOOKS_PARTIAL", "hooks", "degraded", "codex"},
		}},
		{"hooks partial on failure", func(s *endpointHealthSources) {
			s.Guardian.Targets[1].OK, s.Guardian.Targets[1].Error = false, "write C:\\Users\\a\\.codex\\hooks.json: Access is denied."
		}, []want{{"HOOKS_PARTIAL", "hooks", "degraded", "codex"}}},
		{"hooks pending past one guardian interval", func(s *endpointHealthSources) {
			s.Guardian.Targets[1].OK, s.Guardian.Targets[1].Pending = false, true
			s.HooksPendingSince = endpointHealthTestNow.Add(-2 * time.Minute)
		}, []want{{"HOOKS_PARTIAL", "hooks", "degraded", "codex"}}},
		{"hooks pending just seen", func(s *endpointHealthSources) {
			s.Guardian.Targets[1].OK, s.Guardian.Targets[1].Pending = false, true
			s.HooksPendingSince = endpointHealthTestNow
		}, nil},
		{"guardian stale", func(s *endpointHealthSources) {
			s.Guardian.UpdatedAt = endpointHealthTestNow.Add(-6 * time.Minute)
		}, []want{{"GUARDIAN_STALE", "guardian", "degraded", ""}}},
		{"guardian absent after grace", func(s *endpointHealthSources) {
			s.Guardian = endpointHealthGuardianSource{}
		}, []want{{"GUARDIAN_ABSENT", "guardian", "unhealthy", ""}}},
		{"guardian absent within grace", func(s *endpointHealthSources) {
			s.Guardian = endpointHealthGuardianSource{}
			s.Health.UptimeMs = time.Minute.Milliseconds()
		}, nil},
		{"enumerator error", func(s *endpointHealthSources) {
			s.Health.Enumerator = &SubsystemHealth{State: StateError}
		}, []want{{"ENUMERATOR_ERROR", "enumerator", "degraded", ""}}},
		{"inspection unavailable", func(s *endpointHealthSources) {
			s.InspectionAvailable = false
			s.InspectionDetail = "credential C:\\ProgramData\\secret.key is unreadable"
		}, []want{{"INSPECTION_UNAVAILABLE", "inspection", "unhealthy", ""}}},
		{"cmid unavailable since last report", func(s *endpointHealthSources) {
			s.CMIDTokenOK = false
			s.CMIDLastSuccess = endpointHealthTestNow.Add(-time.Hour)
		}, []want{{"CMID_UNAVAILABLE", "cmid", "unhealthy", ""}}},
		{"cmid probe fails but a token was used since last report", func(s *endpointHealthSources) {
			s.CMIDTokenOK = false
		}, nil},
		{"fail-open occurred while inspection is ok", func(s *endpointHealthSources) {
			s.FailOpenSinceLast = 3
		}, []want{{"FAIL_OPEN_OCCURRED", "inspection", "degraded", ""}}},
		{"cloud delivery circuit open", func(s *endpointHealthSources) {
			s.CloudDelivery.CircuitState = delivery.CircuitOpen
		}, []want{{"CLOUD_DELIVERY_DEGRADED", "cloud_delivery", "degraded", ""}}},
		{"cloud delivery consecutive failures", func(s *endpointHealthSources) {
			s.CloudDelivery.ConsecutiveFailures = 3
		}, []want{{"CLOUD_DELIVERY_DEGRADED", "cloud_delivery", "degraded", ""}}},
		{"cloud delivery two failures is fine", func(s *endpointHealthSources) {
			s.CloudDelivery.ConsecutiveFailures = 2
		}, nil},
		{"cloud delivery drops", func(s *endpointHealthSources) {
			s.CloudDeliveryDroppedSinceLast = 1
		}, []want{{"CLOUD_DELIVERY_DEGRADED", "cloud_delivery", "degraded", ""}}},
		{"discovery subsystem error", func(s *endpointHealthSources) {
			s.Health.AIDiscovery = SubsystemHealth{State: StateError, LastError: "scan /Users/a: permission denied"}
		}, []want{{"DISCOVERY_FAILING", "ai_discovery", "degraded", ""}}},
		{"discovery no full scan in two intervals", func(s *endpointHealthSources) {
			s.DiscoveryLastFullScanAt = endpointHealthTestNow.Add(-61 * time.Minute)
		}, []want{{"DISCOVERY_FAILING", "ai_discovery", "degraded", ""}}},
		{"discovery never scanned, gateway young", func(s *endpointHealthSources) {
			s.DiscoveryLastFullScanAt = time.Time{}
			s.Health.StartedAt = endpointHealthTestNow.Add(-30 * time.Minute)
		}, nil},
		{"discovery disabled", func(s *endpointHealthSources) {
			s.DiscoveryEnabled = false
			s.DiscoveryLastFullScanAt = time.Time{}
		}, nil},
		{"audit store unavailable", func(s *endpointHealthSources) {
			s.Health.Telemetry = SubsystemHealth{State: StateError}
		}, []want{{"AUDIT_STORE_UNAVAILABLE", "audit_store", "degraded", ""}}},
		{"policy missing", func(s *endpointHealthSources) {
			s.PolicyApplied = false
			s.PolicyBundleVersion = ""
		}, []want{{"POLICY_MISSING", "policy", "unhealthy", ""}}},
		{"missing AVC version adds nothing", func(s *endpointHealthSources) {
			s.AVCVersion = ""
		}, nil},
		{"invalid AVC version adds nothing", func(s *endpointHealthSources) {
			s.AVCVersion = "C:\\Program Files\\avc.exe"
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := healthyEndpointHealthSources()
			tc.mutate(&src)
			report := buildEndpointHealthReport(src, endpointHealthTestMeta)
			got := make([]want, 0, len(report.Reasons))
			for _, reason := range report.Reasons {
				got = append(got, want{reason.Code, reason.Component, reason.Severity, reason.Connector})
			}
			if fmt.Sprint(got) != fmt.Sprint(append([]want{}, tc.want...)) {
				t.Fatalf("reasons = %v, want %v", got, tc.want)
			}
			wantStatus := endpointHealthStatusHealthy
			if len(tc.want) > 0 {
				wantStatus = tc.want[0].severity
			}
			if report.Status != wantStatus {
				t.Fatalf("status = %s, want %s", report.Status, wantStatus)
			}
		})
	}
}

func TestEndpointHealthStatusOrdering(t *testing.T) {
	src := healthyEndpointHealthSources()
	// starting + degraded + unhealthy at once.
	src.Health.UptimeMs = (5 * time.Minute).Milliseconds()
	src.Health.Configuration.State = ConfigStateWaitingForConfig
	src.FailOpenSinceLast = 1
	src.PolicyApplied = false
	report := buildEndpointHealthReport(src, endpointHealthTestMeta)
	if report.Status != endpointHealthStatusUnhealthy {
		t.Fatalf("status = %s, want unhealthy", report.Status)
	}
	codes := make([]string, 0, len(report.Reasons))
	for _, reason := range report.Reasons {
		codes = append(codes, reason.Code)
	}
	if got := strings.Join(codes, ","); got != "POLICY_MISSING,FAIL_OPEN_OCCURRED,CONFIG_WAITING" {
		t.Fatalf("reason order = %s", got)
	}

	src.PolicyApplied = true
	if got := buildEndpointHealthReport(src, endpointHealthTestMeta).Status; got != endpointHealthStatusDegraded {
		t.Fatalf("status = %s, want degraded", got)
	}
	src.FailOpenSinceLast = 0
	if got := buildEndpointHealthReport(src, endpointHealthTestMeta).Status; got != endpointHealthStatusStarting {
		t.Fatalf("status = %s, want starting", got)
	}

	// Same severity sorts by code.
	sorted := endpointHealthSortReasons([]endpointHealthReason{
		{Code: "SUBSYSTEM_DEGRADED", Component: "b", Severity: "degraded"},
		{Code: "AUDIT_STORE_UNAVAILABLE", Component: "audit_store", Severity: "degraded"},
		{Code: "SUBSYSTEM_DEGRADED", Component: "a", Severity: "degraded"},
		{Code: "SUBSYSTEM_DEGRADED", Component: "a", Severity: "degraded"},
		{Code: "CONFIG_WAITING", Component: "configuration", Severity: "starting"},
		{Code: "HOOKS_NONE", Component: "hooks", Severity: "unhealthy"},
	})
	var order []string
	for _, reason := range sorted {
		order = append(order, reason.Code+"/"+reason.Component)
	}
	if got := strings.Join(order, ","); got != "HOOKS_NONE/hooks,AUDIT_STORE_UNAVAILABLE/audit_store,"+
		"SUBSYSTEM_DEGRADED/a,SUBSYSTEM_DEGRADED/b,CONFIG_WAITING/configuration" {
		t.Fatalf("sorted = %s", got)
	}
}

func TestEndpointHealthCapsAndTruncation(t *testing.T) {
	src := healthyEndpointHealthSources()
	src.Guardian.Targets = nil
	src.Health.Connectors = nil
	for i := range 20 {
		connector := fmt.Sprintf("connector%02d", i)
		src.Health.Connectors = append(src.Health.Connectors, ConnectorHealth{Name: connector})
		for j := range 2 {
			src.Guardian.Targets = append(src.Guardian.Targets, endpointHealthGuardianTarget{
				Connector: connector, UserID: fmt.Sprintf("S-1-5-21-1-2-3-%d", 1000+j), Error: "access is denied",
			})
		}
	}
	src.Guardian.Targets = append(src.Guardian.Targets, endpointHealthGuardianTarget{Connector: "connector00", OK: true})
	for i := range 40 {
		src.SourceErrors = append(src.SourceErrors, fmt.Sprintf("source%02d", i))
	}
	report := buildEndpointHealthReport(src, endpointHealthTestMeta)
	if len(report.Reasons) != endpointHealthMaxReasons || !report.ReasonsTruncated {
		t.Fatalf("reasons = %d truncated=%v", len(report.Reasons), report.ReasonsTruncated)
	}
	if report.Status != endpointHealthStatusDegraded {
		t.Fatalf("status = %s", report.Status)
	}
	if len(report.HooksFailingTargets) != endpointHealthMaxFailingTargets || !report.HooksFailingTargetsTruncated {
		t.Fatalf("failing targets = %d truncated=%v", len(report.HooksFailingTargets), report.HooksFailingTargetsTruncated)
	}
	if len(report.HooksConnectors) != endpointHealthMaxConnectors || !report.HooksConnectorsTruncated {
		t.Fatalf("connectors = %d truncated=%v", len(report.HooksConnectors), report.HooksConnectorsTruncated)
	}
	// Totals stay exact even when the lists are cut.
	if report.HooksTargets != 41 || report.HooksFailed != 40 || report.HooksOK != 1 {
		t.Fatalf("totals = %d/%d/%d", report.HooksTargets, report.HooksOK, report.HooksFailed)
	}
	// Failed targets sort before pending ones.
	src.Guardian.Targets = append([]endpointHealthGuardianTarget{{Connector: "aaa", Pending: true}}, src.Guardian.Targets...)
	report = buildEndpointHealthReport(src, endpointHealthTestMeta)
	for _, target := range report.HooksFailingTargets {
		if target.Pending {
			t.Fatalf("a pending target outranked failed ones: %+v", report.HooksFailingTargets)
		}
	}

	untruncated := buildEndpointHealthReport(healthyEndpointHealthSources(), endpointHealthTestMeta)
	if untruncated.ReasonsTruncated || untruncated.HooksConnectorsTruncated ||
		untruncated.HooksFailingTargetsTruncated || untruncated.SubsystemsTruncated {
		t.Fatalf("a small report was marked truncated: %+v", untruncated)
	}
}

func TestEndpointHealthSizeCap(t *testing.T) {
	// The largest report the builder can produce fits the cap without
	// trimming.
	src := healthyEndpointHealthSources()
	src.Guardian.Targets, src.Health.Connectors = nil, nil
	long := strings.Repeat("x", 63)
	for i := range 40 {
		connector := fmt.Sprintf("%s%02d", long[:61], i)
		src.Health.Connectors = append(src.Health.Connectors, ConnectorHealth{Name: connector, ToolInspectionMode: "enforce"})
		src.Guardian.Targets = append(src.Guardian.Targets, endpointHealthGuardianTarget{
			Connector: connector, UserID: "S-1-5-21-1234567890-1234567890-1234567890-" + fmt.Sprint(100000+i),
			Error: "access is denied",
		})
	}
	for i := range 40 {
		src.SourceErrors = append(src.SourceErrors, fmt.Sprintf("%s%02d", long[:61], i))
	}
	report := buildEndpointHealthReport(src, endpointHealthTestMeta)
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > endpointHealthMaxBytes {
		t.Fatalf("worst-case report is %d bytes, over %d", len(encoded), endpointHealthMaxBytes)
	}

	// An oversized report is trimmed, failing targets first, until it fits.
	oversized := report
	for len(oversized.HooksFailingTargets) < 2000 {
		oversized.HooksFailingTargets = append(oversized.HooksFailingTargets, report.HooksFailingTargets...)
	}
	oversized.HooksFailingTargetsTruncated = false
	oversized.ReasonsTruncated = false
	enforceEndpointHealthReportSize(&oversized)
	encoded, err = json.Marshal(oversized)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > endpointHealthMaxBytes || !oversized.HooksFailingTargetsTruncated {
		t.Fatalf("trimmed report is %d bytes, truncated=%v", len(encoded), oversized.HooksFailingTargetsTruncated)
	}
	if oversized.ReasonsTruncated || len(oversized.Reasons) != endpointHealthMaxReasons {
		t.Fatalf("reasons were trimmed before failing targets: %d", len(oversized.Reasons))
	}
}

func TestEndpointHealthErrorClassNeverLeaksInput(t *testing.T) {
	closed := map[string]bool{}
	for _, class := range []string{
		endpointHealthErrorClassPermissionDenied, endpointHealthErrorClassConfigWriteDenied,
		endpointHealthErrorClassNotFound, endpointHealthErrorClassAccountSignedOut,
		endpointHealthErrorClassAccountUnavailable, endpointHealthErrorClassUserPath,
		endpointHealthErrorClassTimeout, endpointHealthErrorClassCanceled, endpointHealthErrorClassUnreachable,
		endpointHealthErrorClassAuthFailed, endpointHealthErrorClassInvalidConfig, endpointHealthErrorClassBusy,
		endpointHealthErrorClassDiskFull, endpointHealthErrorClassContractUnverified, endpointHealthErrorClassOther,
	} {
		closed[class] = true
	}
	cases := map[string]string{
		"":    endpointHealthErrorClassNone,
		"   ": endpointHealthErrorClassNone,
		"open C:\\Users\\alice\\.claude\\settings.json: Access is denied.":                endpointHealthErrorClassPermissionDenied,
		"write /Users/alice/.codex/hooks.json: permission denied":                         endpointHealthErrorClassConfigWriteDenied,
		"enterprise hooks: protected target waits for its account's next sign-in":         endpointHealthErrorClassAccountSignedOut,
		"refusing symlink in hook config path: /Users/bob/.claude":                        endpointHealthErrorClassUserPath,
		"context deadline exceeded":                                                       endpointHealthErrorClassTimeout,
		"dial tcp 10.0.0.1:443: connection refused":                                       endpointHealthErrorClassUnreachable,
		"Cisco AI Defense API key was rejected (HTTP 401)":                                endpointHealthErrorClassAuthFailed,
		"open /opt/x/y: no such file or directory":                                        endpointHealthErrorClassNotFound,
		"yaml: line 3: did not find expected key, invalid":                                endpointHealthErrorClassInvalidConfig,
		"The process cannot access the file because it is being used by another process.": endpointHealthErrorClassBusy,
		"write: no space left on device":                                                  endpointHealthErrorClassDiskFull,
		"agent version \"9.9\" has an unverified hook contract":                           endpointHealthErrorClassContractUnverified,
		"token=eyJhbGciOi.secret user=alice@example.com":                                  endpointHealthErrorClassOther,
	}
	for input, want := range cases {
		got := endpointHealthErrorClass(input)
		if got != want {
			t.Errorf("class(%q) = %q, want %q", input, got, want)
		}
		if got != "" && !closed[got] {
			t.Errorf("class(%q) = %q is not in the closed set", input, got)
		}
	}
}

// endpointHealthPathTolerantKey reports the string fields allowed to
// contain '/' : timestamps and versions.
func endpointHealthPathTolerantKey(key string) bool {
	return strings.HasSuffix(key, "_at") || strings.HasSuffix(key, ".since") || key == "since" ||
		strings.Contains(key, ".version.") || strings.HasSuffix(key, ".os.version") ||
		strings.HasSuffix(key, "observed_at") || strings.HasSuffix(key, "started_at")
}

func endpointHealthAssertNoPaths(t *testing.T, key string, value any) {
	t.Helper()
	switch typed := value.(type) {
	case map[string]any:
		for child, nested := range typed {
			endpointHealthAssertNoPaths(t, child, nested)
		}
	case []any:
		for _, nested := range typed {
			endpointHealthAssertNoPaths(t, key, nested)
		}
	case string:
		if strings.Contains(typed, `:\`) || strings.Contains(typed, `\`) {
			t.Errorf("%s = %q contains a path separator", key, typed)
		}
		if !endpointHealthPathTolerantKey(key) && strings.Contains(typed, "/") {
			t.Errorf("%s = %q contains a path separator", key, typed)
		}
		if strings.Contains(typed, "@") {
			t.Errorf("%s = %q looks like an email", key, typed)
		}
	}
}

func TestEndpointHealthPrivacy(t *testing.T) {
	src := healthyEndpointHealthSources()
	pathy := `C:\Users\alice@example.com\AppData\Roaming\x.json: /Users/alice/.claude/settings.json`
	src.Health.Guardrail = SubsystemHealth{State: StateError, LastError: pathy}
	src.Health.Watcher = SubsystemHealth{State: StateDegraded, LastError: pathy}
	src.Health.Connectors = append(src.Health.Connectors, ConnectorHealth{
		Name: `..\..\evil/connector`, ToolInspectionMode: "C:\\mode",
	})
	src.Guardian.Targets = append(src.Guardian.Targets,
		endpointHealthGuardianTarget{Connector: "/opt/agent", UserID: "/Users/alice", Error: pathy},
		endpointHealthGuardianTarget{Connector: "codex", UserID: "alice@example.com", Error: pathy},
		endpointHealthGuardianTarget{Connector: "codex", UserID: "501", Error: pathy},
	)
	src.InspectionAvailable, src.InspectionDetail = false, pathy
	src.ProductVersion = `C:\Program Files\DefenseClaw`
	src.AVCVersion = "/Applications/Cisco/avc"
	src.OSVersion = `\\server\share`
	src.PolicyBundleVersion = "/etc/policy"
	src.SourceErrors = []string{`C:\source`}
	src.CloudDelivery.State = delivery.HealthState("bad/state")
	src.CloudDelivery.LastFailureClass = delivery.FailureClass(`C:\x`)

	report := buildEndpointHealthReport(src, endpointHealthReportMeta{
		ReportID: "../../x", Trigger: "/bin/sh", Interval: time.Hour,
	})
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	endpointHealthAssertNoPaths(t, "", decoded)
	if strings.Contains(string(encoded), "alice") {
		t.Fatalf("report carries an account name or email: %s", encoded)
	}
	var sawUID bool
	for _, target := range report.HooksFailingTargets {
		if target.UserID == "501" && target.UserIDKind == "posix_uid" {
			sawUID = true
		}
		if target.UserID != "" && target.UserIDKind == "" {
			t.Fatalf("user id without kind: %+v", target)
		}
	}
	if !sawUID {
		t.Fatalf("the uid target lost its id: %+v", report.HooksFailingTargets)
	}
}

func TestAVCVersionNormalisation(t *testing.T) {
	for raw, want := range map[string]string{
		"5, 1, 21, 4204":          "5.1.21.4204",
		"5,1,21,4204":             "5.1.21.4204",
		" 5.1.21.4204 ":           "5.1.21.4204",
		"5.1.21.4204\x00":         "5.1.21.4204",
		"1.0.9-rc1+build_7":       "1.0.9-rc1+build_7",
		"":                        "",
		"5.1.21.4204 (build)":     "",
		`C:\avc\avcagent.exe`:     "",
		"/opt/cisco/avc":          "",
		strings.Repeat("1", 65):   "",
		strings.Repeat("1", 64):   strings.Repeat("1", 64),
		"5.1;rm -rf":              "",
		"５.1":                     "",
		"5.1.21.4204\nINJECTED=1": "",
	} {
		got, ok := normalizeEndpointHealthVersion(raw)
		if got != want || ok != (want != "") {
			t.Errorf("normalize(%q) = %q, %v; want %q", raw, got, ok, want)
		}
	}
}

func TestAVCVersionServiceExecutable(t *testing.T) {
	for image, want := range map[string]string{
		`"C:\Program Files\Cisco\Cisco Secure Client\AVC\avcagent.exe" -service`: `C:\Program Files\Cisco\Cisco Secure Client\AVC\avcagent.exe`,
		`C:\Program Files\Cisco\Cisco Secure Client\AVC\avcagent.exe -service`:   `C:\Program Files\Cisco\Cisco Secure Client\AVC\avcagent.exe`,
		`C:\Program Files\Cisco\Cisco Secure Client\AVC\AVCAGENT.EXE`:            `C:\Program Files\Cisco\Cisco Secure Client\AVC\AVCAGENT.EXE`,
		`\??\C:\avc\avcagent.exe`: `C:\avc\avcagent.exe`,
		`"C:\unterminated`:        "",
		`C:\tools\agent -x`:       `C:\tools\agent`,
		"":                        "",
	} {
		if got := endpointHealthServiceExecutable(image); got != want {
			t.Errorf("executable(%q) = %q, want %q", image, got, want)
		}
	}
}

const endpointHealthTestBinaryReceipt = "YnBsaXN0MDDVAQIDBAUGBwgJCl5QYWNrYWdlVmVyc2lvbl8QEVBhY2thZ2VJZGVudGlmaWVyXxARSW5zdGFsbFByZWZpeFBhdGhbSW5zdGFsbERhdGVVTm90ZXNbNS4xLjIxLjQyMDRfEB5jb20uY2lzY28ucGtnLnNlY3VyZWNsaWVudC5hdmNRLzNBx4O2koAAAGQAYwBhAGYA6QgTIjZKVlxoiYuUAAAAAAAAAQEAAAAAAAAACwAAAAAAAAAAAAAAAAAAAJ0="

func TestAVCVersionReceiptPlist(t *testing.T) {
	binaryReceipt, err := base64.StdEncoding.DecodeString(endpointHealthTestBinaryReceipt)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"PackageVersion":    "5.1.21.4204",
		"PackageIdentifier": "com.cisco.pkg.secureclient.avc",
		"Notes":             "café",
	} {
		got, err := plistTopLevelString(binaryReceipt, key)
		if err != nil || got != want {
			t.Errorf("binary %s = %q, %v; want %q", key, got, err, want)
		}
	}
	if _, err := plistTopLevelString(binaryReceipt, "InstallDate"); err == nil {
		t.Error("a date value was returned as a string")
	}
	if _, err := plistTopLevelString(binaryReceipt, "Absent"); !errors.Is(err, errEndpointHealthPlistKeyMissing) {
		t.Errorf("missing key error = %v", err)
	}
	// A truncated or corrupted binary plist fails cleanly.
	for _, broken := range [][]byte{binaryReceipt[:20], binaryReceipt[:len(binaryReceipt)-5], []byte("bplist15xxxx")} {
		if _, err := plistTopLevelString(broken, "PackageVersion"); err == nil {
			t.Errorf("broken plist %d bytes parsed", len(broken))
		}
	}
	corrupt := append([]byte(nil), binaryReceipt...)
	for i := len(corrupt) - 8; i < len(corrupt); i++ {
		corrupt[i] = 0xff
	}
	if _, err := plistTopLevelString(corrupt, "PackageVersion"); err == nil {
		t.Error("a corrupt trailer parsed")
	}

	xmlReceipt := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Nested</key><dict><key>PackageVersion</key><string>9.9.9</string></dict>
<key>InstallDate</key><date>2026-01-02T03:04:05Z</date>
<key>PackageVersion</key><string>5.1.21.4204</string>
</dict></plist>`)
	if got, err := plistTopLevelString(xmlReceipt, "PackageVersion"); err != nil || got != "5.1.21.4204" {
		t.Fatalf("xml PackageVersion = %q, %v", got, err)
	}
	if _, err := plistTopLevelString([]byte(`<plist><dict><key>A</key><string>x</string></dict></plist>`), "PackageVersion"); err == nil {
		t.Fatal("missing xml key returned a value")
	}
	if _, err := plistTopLevelString([]byte(`<plist><dict><key>PackageVersion`), "PackageVersion"); err == nil {
		t.Fatal("truncated xml parsed")
	}
}

func TestEndpointHealthGuardianStateReader(t *testing.T) {
	dir := t.TempDir()
	now := endpointHealthTestNow
	if source, err := readEndpointHealthGuardianState(dir, now); err != nil || source.Present {
		t.Fatalf("missing file = %+v, %v; want absent, nil", source, err)
	}
	restore := endpointHealthLookupUserID
	endpointHealthLookupUserID = func(name string) string {
		if name == "carol" {
			return "502"
		}
		return ""
	}
	defer func() { endpointHealthLookupUserID = restore }()
	state := `{"version":1,"updated_at":"2026-11-12T09:59:30Z","manifest":"C:\\x","ok":false,
"target_count":4,"success_count":1,"failure_count":2,"pending_count":1,
"results":[
 {"user":"alice","sid":"S-1-5-21-1-2-3-1001","connector":"codex","ok":true},
 {"user":"bob","sid":"S-1-5-21-1-2-3-1002","connector":"codex","ok":false,"error":"access is denied"},
 {"user":"carol","user_home":"/Users/carol","connector":"claudecode","ok":false,"error":"x"},
 {"user":"dave","uid":503,"connector":"claudecode","pending":true}
]}`
	if err := os.WriteFile(filepath.Join(dir, endpointHealthGuardianStateFile), []byte(state), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := readEndpointHealthGuardianState(dir, now)
	if err != nil || !source.Present || !source.UpdatedAt.Equal(now.Add(-30*time.Second)) || len(source.Targets) != 4 {
		t.Fatalf("source = %+v, %v", source, err)
	}
	if source.Targets[0].UserID != "" || source.Targets[1].UserID != "S-1-5-21-1-2-3-1002" ||
		source.Targets[2].UserID != "502" || source.Targets[3].UserID != "503" {
		t.Fatalf("user ids = %+v", source.Targets)
	}
	if err := os.WriteFile(filepath.Join(dir, endpointHealthGuardianStateFile), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readEndpointHealthGuardianState(dir, now); err == nil || strings.Contains(err.Error(), dir) {
		t.Fatalf("malformed state error = %v", err)
	}
}

func TestEndpointHealthSinceLastAndTimeout(t *testing.T) {
	if got := endpointHealthSinceLast(10, 4, true); got != 6 {
		t.Fatalf("delta = %d", got)
	}
	if got := endpointHealthSinceLast(3, 4, true); got != 3 {
		t.Fatalf("reset delta = %d", got)
	}
	if got := endpointHealthSinceLast(5, 0, false); got != 5 {
		t.Fatalf("first delta = %d", got)
	}
	release := make(chan struct{})
	defer close(release)
	start := time.Now()
	_, err := endpointHealthRead(context.Background(), 20*time.Millisecond, func(context.Context) (int, error) {
		<-release
		return 1, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("hung read = %v after %s", err, time.Since(start))
	}
}

func TestEndpointHealthFailOpenCounter(t *testing.T) {
	before := managedAIDFailOpenAvailabilityDecisionCount()
	_ = recordManagedAIDFailOpenMetricV8(context.Background(), nil, aidFailOpenUnavailable)
	_ = recordManagedAIDFailOpenMetricV8(context.Background(), nil, aidFailOpenUnwired)
	_ = recordManagedAIDFailOpenMetricV8(context.Background(), nil, aidFailOpenNoContent)
	if got := managedAIDFailOpenAvailabilityDecisionCount() - before; got < 2 {
		t.Fatalf("counted %d availability fail-opens, want at least 2", got)
	}
}

func TestEndpointHealthCollectorSourceFailures(t *testing.T) {
	// A sidecar with nothing bound still yields sources; every unreadable
	// source is named, nothing panics.
	sidecar := &Sidecar{health: NewSidecarHealth()}
	cursor := &endpointHealthCursor{}
	src := sidecar.collectEndpointHealthSources(context.Background(), cursor)
	joined := strings.Join(src.SourceErrors, ",")
	if !strings.Contains(joined, endpointHealthSourceCloudDelivery) || !strings.Contains(joined, endpointHealthSourceGuardianState) {
		t.Fatalf("source errors = %v", src.SourceErrors)
	}
	if cursor.previousReportAt.IsZero() || !cursor.failOpenRead {
		t.Fatalf("cursor was not advanced: %+v", cursor)
	}
	report := buildEndpointHealthReport(src, endpointHealthTestMeta)
	if report.Status == endpointHealthStatusHealthy {
		t.Fatalf("an endpoint with unreadable sources reported healthy: %+v", report.Reasons)
	}
}

func TestEndpointHealthFieldShapes(t *testing.T) {
	src := healthyEndpointHealthSources()
	src.Health.Watcher = SubsystemHealth{State: StateError, LastError: "C:\\x: access is denied"}
	src.Health.Sandbox = &SubsystemHealth{State: SubsystemState("Weird State/1")}
	src.Health.Connectors = append(src.Health.Connectors, ConnectorHealth{Name: "Bad Name", ToolInspectionMode: "Not A Mode!"})
	src.Guardian.Targets = append(src.Guardian.Targets,
		endpointHealthGuardianTarget{Connector: "codex", UserID: "S-1-5-21-9-9-9-1001", Error: "write x: access is denied"},
		endpointHealthGuardianTarget{Connector: "codex", UserID: "501", Pending: true},
		endpointHealthGuardianTarget{Connector: "codex"},
	)
	src.HooksPendingSince = endpointHealthTestNow.Add(-time.Hour)
	src.InspectionAvailable, src.InspectionDetail = false, "client not initialized"
	src.CloudDelivery.State, src.CloudDelivery.LastFailureClass = delivery.HealthFailing, delivery.FailureClassTransient
	src.SourceErrors = []string{"Not-An-Identifier"}
	src.PolicyBundleVersion = endpointHealthShortDigest("sha256:" + strings.Repeat("b", 64))
	meta := endpointHealthTestMeta
	report := buildEndpointHealthReport(src, meta)

	match := func(name, pattern, value string) {
		t.Helper()
		if !endpointHealthMatches(pattern, value) {
			t.Errorf("%s = %q does not match %s", name, value, pattern)
		}
	}
	const (
		uuid       = `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`
		identifier = `^[a-z][a-z0-9_]{0,63}$`
		state      = `^[a-z][a-z0-9_]{0,31}$`
		class      = `^[A-Z][A-Z0-9_]{0,63}$`
		connector  = `^[a-z0-9][a-z0-9_.-]{0,63}$`
		mode       = `^[a-z][a-z0-9_-]{0,31}$`
		policy     = `^[0-9A-Za-z.+_:-]{1,64}$`
		rfc3339    = `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$`
	)
	match("report_id", uuid, report.ReportID)
	match("observed_at", rfc3339, report.ObservedAt)
	match("policy_bundle", policy, report.PolicyBundleVersion)
	match("configuration", state, report.GatewayConfiguration)
	match("cloud_delivery.state", state, report.CloudDeliveryState)
	match("cloud_delivery.circuit", state, report.CloudDeliveryCircuit)
	match("cloud_delivery.last_failure_class", identifier, report.CloudDeliveryLastFailureClass)
	match("audit_store", state, report.LocalStoreAuditStore)
	match("unavailable_code", `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, report.InspectionUnavailableCode)
	for _, reason := range report.Reasons {
		match("reason.code", class, reason.Code)
		match("reason.component", identifier, reason.Component)
		match("reason.severity", `^(unhealthy|degraded|starting)$`, reason.Severity)
		if reason.Connector != "" {
			match("reason.connector", connector, reason.Connector)
		}
	}
	for _, subsystem := range report.Subsystems {
		match("subsystem.name", identifier, subsystem.Name)
		match("subsystem.state", state, subsystem.State)
		if subsystem.Since != "" {
			match("subsystem.since", rfc3339, subsystem.Since)
		}
		if subsystem.ErrorClass != "" {
			match("subsystem.error_class", class, subsystem.ErrorClass)
		}
	}
	for _, entry := range report.HooksConnectors {
		match("connector", connector, entry.Connector)
		if entry.ToolInspectionMode != "" {
			match("tool_inspection_mode", mode, entry.ToolInspectionMode)
		}
	}
	if len(report.HooksFailingTargets) != 3 {
		t.Fatalf("failing targets = %+v", report.HooksFailingTargets)
	}
	for _, target := range report.HooksFailingTargets {
		match("failing.connector", connector, target.Connector)
		match("failing.error_class", class, target.ErrorClass)
		if target.UserID != "" {
			match("failing.user.id", `^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$`, target.UserID)
			match("failing.user.id_kind", `^(windows_sid|posix_uid)$`, target.UserIDKind)
		}
	}
	if got := endpointHealthShortDigest("sha256:" + strings.Repeat("c", 64)); got != "sha256:"+strings.Repeat("c", 16) {
		t.Fatalf("short digest = %q", got)
	}
	// An empty error class or code is omitted, not sent as "".
	encoded, err := json.Marshal(buildEndpointHealthReport(healthyEndpointHealthSources(), meta))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"error_class":""`, `unavailable_code":""`, `last_failure_class":""`} {
		if strings.Contains(string(encoded), key) {
			t.Errorf("healthy report carries an empty %s", key)
		}
	}
}

func endpointHealthMatches(pattern, value string) bool {
	return regexp.MustCompile(pattern).MatchString(value)
}
