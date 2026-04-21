// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"flag"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

func TestMain(m *testing.M) {
	flag.BoolVar(&updateGolden, "update", false, "rewrite test/e2e/testdata/v7/golden/*.json")
	flag.Parse()
	os.Exit(m.Run())
}

func TestGoldenEvents(t *testing.T) {
	cases := []struct {
		name       string
		goldenFile string
		schema     string
		emit       func(t *testing.T, h *observabilityHarness) gatewaylog.Event
	}{
		{
			"scan_clean", "scan-clean.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				t.Helper()
				if err := h.Logger.LogScan(minimalScanResult(nil)); err != nil {
					t.Fatalf("LogScan: %v", err)
				}
				evs := findGatewayEvents(h, gatewaylog.EventScan)
				if len(evs) == 0 {
					t.Fatal("no scan event")
				}
				return evs[len(evs)-1]
			},
		},
		{
			"scan_with_findings", "scan-with-findings.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				t.Helper()
				ln := 10
				res := minimalScanResult([]scanner.Finding{{
					ID: "fid", Title: "t", Severity: scanner.SeverityHigh, Category: "c",
					RuleID: "R1", LineNumber: &ln,
				}})
				if err := h.Logger.LogScan(res); err != nil {
					t.Fatalf("LogScan: %v", err)
				}
				evs := findGatewayEvents(h, gatewaylog.EventScan)
				return evs[len(evs)-1]
			},
		},
		{
			"scan_finding_child", "scan-finding-child.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				t.Helper()
				ln := 3
				res := minimalScanResult([]scanner.Finding{{
					ID: "child", Title: "x", Severity: scanner.SeverityCritical, Category: "c",
					RuleID: "R9", LineNumber: &ln,
				}})
				if err := h.Logger.LogScan(res); err != nil {
					t.Fatalf("LogScan: %v", err)
				}
				evs := findGatewayEvents(h, gatewaylog.EventScanFinding)
				if len(evs) == 0 {
					t.Fatal("no finding event")
				}
				return evs[0]
			},
		},
		{
			"verdict_blocked", "verdict-blocked.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventVerdict,
					Severity:  gatewaylog.SeverityHigh,
					Verdict: &gatewaylog.VerdictPayload{
						Stage: gatewaylog.StageFinal, Action: "block", Reason: "test", LatencyMs: 1,
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventVerdict)
				return evs[len(evs)-1]
			},
		},
		{
			"verdict_allowed", "verdict-allowed.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventVerdict,
					Severity:  gatewaylog.SeverityInfo,
					Verdict: &gatewaylog.VerdictPayload{
						Stage: gatewaylog.StageFinal, Action: "allow", LatencyMs: 2,
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventVerdict)
				return evs[len(evs)-1]
			},
		},
		{
			"judge_injection", "judge-injection.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventJudge,
					Severity:  gatewaylog.SeverityMedium,
					Model:     "gpt-4",
					Judge: &gatewaylog.JudgePayload{
						Kind: "injection", Model: "gpt-4", InputBytes: 10, LatencyMs: 5,
						Action: "warn", Severity: gatewaylog.SeverityMedium, RawResponse: "{}",
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventJudge)
				return evs[len(evs)-1]
			},
		},
		{
			"judge_pii", "judge-pii.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventJudge,
					Severity:  gatewaylog.SeverityHigh,
					Model:     "gpt-4",
					Judge: &gatewaylog.JudgePayload{
						Kind: "pii", Model: "gpt-4", InputBytes: 20, LatencyMs: 7,
						Action: "block", Severity: gatewaylog.SeverityHigh, RawResponse: "{}",
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventJudge)
				return evs[len(evs)-1]
			},
		},
		{
			"judge_tool_injection", "judge-tool_injection.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventJudge,
					Severity:  gatewaylog.SeverityHigh,
					Model:     "gpt-4",
					Judge: &gatewaylog.JudgePayload{
						Kind: "tool_injection", Model: "gpt-4", InputBytes: 8, LatencyMs: 4,
						Action: "block", Severity: gatewaylog.SeverityHigh, RawResponse: "{}",
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventJudge)
				return evs[len(evs)-1]
			},
		},
		{
			"activity_policy_update", "activity-policy-update.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				err := h.Logger.LogActivity(audit.ActivityInput{
					Actor: "op", Action: audit.ActionPolicyUpdate, TargetType: "policy", TargetID: "p1",
					Before: map[string]any{"v": 1}, After: map[string]any{"v": 2},
				})
				if err != nil {
					t.Fatalf("LogActivity: %v", err)
				}
				evs := findGatewayEvents(h, gatewaylog.EventActivity)
				if len(evs) == 0 {
					t.Fatal("no activity")
				}
				return evs[len(evs)-1]
			},
		},
		{
			"activity_sink_circuit_open", "activity-sink-circuit-open.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventActivity,
					Severity:  gatewaylog.SeverityHigh,
					Activity: &gatewaylog.ActivityPayload{
						Actor: "system", Action: "action", TargetType: "sink", TargetID: "splunk",
						Reason: "sink circuit open",
						Diff:   []gatewaylog.DiffEntry{{Path: "circuit", Op: "replace", Before: "closed", After: "open"}},
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventActivity)
				return evs[len(evs)-1]
			},
		},
		{
			"lifecycle_stream_open", "lifecycle-stream-open.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventLifecycle,
					Severity:  gatewaylog.SeverityInfo,
					Lifecycle: &gatewaylog.LifecyclePayload{
						Subsystem: "gateway", Transition: "start", Details: map[string]string{"k": "v"},
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventLifecycle)
				return evs[len(evs)-1]
			},
		},
		{
			"lifecycle_stream_close", "lifecycle-stream-close.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventLifecycle,
					Severity:  gatewaylog.SeverityInfo,
					Lifecycle: &gatewaylog.LifecyclePayload{
						Subsystem: "gateway", Transition: "stop", Details: map[string]string{"k": "v"},
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventLifecycle)
				return evs[len(evs)-1]
			},
		},
		{
			"error_auth_failure", "error-auth-failure.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventError,
					Severity:  gatewaylog.SeverityHigh,
					Error: &gatewaylog.ErrorPayload{
						Subsystem: "auth", Code: string(gatewaylog.ErrCodeAuthInvalidToken), Message: "failed",
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventError)
				return evs[len(evs)-1]
			},
		},
		{
			"error_subprocess_exit", "error-subprocess-exit.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventError,
					Severity:  gatewaylog.SeverityMedium,
					Error: &gatewaylog.ErrorPayload{
						Subsystem: "scanner", Code: string(gatewaylog.ErrCodeSubprocessExit), Message: "exit 1",
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventError)
				return evs[len(evs)-1]
			},
		},
		{
			"error_policy_load_failed", "error-policy-load-failed.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventError,
					Severity:  gatewaylog.SeverityHigh,
					Error: &gatewaylog.ErrorPayload{
						Subsystem: "policy", Code: string(gatewaylog.ErrCodePolicyLoadFailed), Message: "bad yaml",
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventError)
				return evs[len(evs)-1]
			},
		},
		{
			"diagnostic_config_load_error", "diagnostic-config-load-error.golden.json", "schemas/gateway-event-envelope.json",
			func(t *testing.T, h *observabilityHarness) gatewaylog.Event {
				h.GW.Emit(gatewaylog.Event{
					Timestamp: time.Unix(1700000000, 0).UTC(),
					EventType: gatewaylog.EventDiagnostic,
					Severity:  gatewaylog.SeverityInfo,
					Diagnostic: &gatewaylog.DiagnosticPayload{
						Component: "config", Message: "load error",
					},
				})
				evs := findGatewayEvents(h, gatewaylog.EventDiagnostic)
				return evs[len(evs)-1]
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newObservabilityHarness(t)
			ev := tc.emit(t, h)
			raw := mustMarshalEvent(t, ev)
			norm := stripVolatileGatewayJSON(t, raw)
			validateAgainstSchema(t, norm, tc.schema)
			compareGolden(t, tc.goldenFile, norm)
		})
	}
}
