// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/diagnostics"
)

var healthReportNow = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

// healthReportFile is a file the gateway writes, with report fields
// overridden by report (a nil value deletes the field).
func healthReportFile(t *testing.T, schemaVersion int, report map[string]any) []byte {
	t.Helper()
	body := map[string]any{
		"defenseclaw.health.report_id":         "0193d6a2-0000-7000-8000-000000000001",
		"defenseclaw.health.sequence":          42,
		"defenseclaw.health.trigger":           "scheduled",
		"defenseclaw.health.observed_at":       "2026-11-12T11:30:00Z",
		"defenseclaw.health.report_interval_s": 1800,
		"defenseclaw.health.status":            "degraded",
		"defenseclaw.health.reasons": []map[string]any{
			{"code": "HOOKS_PARTIAL", "component": "hooks", "severity": "medium", "connector": "codex"},
			{"code": "HOOKS_PARTIAL", "component": "hooks", "severity": "medium", "connector": "cursor"},
			{"code": "SUBSYSTEM_DEGRADED", "component": "guardian", "severity": "medium"},
		},
		"defenseclaw.health.hooks.targets": 3,
	}
	for key, value := range report {
		if value == nil {
			delete(body, key)
			continue
		}
		body[key] = value
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(diagnostics.HealthReportFileContent{
		SchemaVersion: schemaVersion,
		BuiltAt:       "2026-11-12T11:30:01Z",
		Report:        raw,
		Delivery: diagnostics.HealthDelivery{
			Result: "queued", At: "2026-11-12T11:30:01Z", CloudState: "ok", CloudLastSuccessAt: "2026-11-12T11:00:00Z",
		},
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeHealthReport(t *testing.T, dataDir string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(diagnostics.Dir(dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(diagnostics.Path(dataDir, diagnostics.HealthReportFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadHealthReport(t *testing.T) {
	valid := &HealthReportState{
		Status: "degraded", ObservedAt: "2026-11-12T11:30:00Z", Sequence: 42, Trigger: "scheduled",
		ReasonCodes: []string{"HOOKS_PARTIAL", "SUBSYSTEM_DEGRADED"}, BuiltAt: "2026-11-12T11:30:01Z",
		Delivery: &HealthReportDelivery{Result: "queued", At: "2026-11-12T11:30:01Z", CloudState: "ok"},
	}
	stale := *valid
	stale.ObservedAt, stale.Stale = "2026-11-12T10:29:59Z", true
	notStale := *valid
	notStale.ObservedAt = "2026-11-12T10:30:00Z"
	shortInterval := *valid
	shortInterval.Stale = true
	invalid := &HealthReportState{Error: HealthReportInvalid}
	cases := []struct {
		name  string
		setup func(t *testing.T, dataDir string)
		want  *HealthReportState
	}{
		{name: "absent", setup: func(*testing.T, string) {}, want: nil},
		{name: "absent folder", setup: func(t *testing.T, dataDir string) {
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
		}, want: nil},
		{name: "valid", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 1, nil))
		}, want: valid},
		{name: "stale after three intervals", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 1, map[string]any{"defenseclaw.health.observed_at": "2026-11-12T10:29:59Z"}))
		}, want: &stale},
		{name: "exactly three intervals is not stale", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 1, map[string]any{"defenseclaw.health.observed_at": "2026-11-12T10:30:00Z"}))
		}, want: &notStale},
		{name: "stale with a short interval", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 1, map[string]any{"defenseclaw.health.report_interval_s": 60}))
		}, want: &shortInterval},
		{name: "other schema version", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 2, nil))
		}, want: invalid},
		{name: "unknown status", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 1, map[string]any{"defenseclaw.health.status": "fine"}))
		}, want: invalid},
		{name: "no status", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 1, map[string]any{"defenseclaw.health.status": nil}))
		}, want: invalid},
		{name: "bad observed_at", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 1, map[string]any{"defenseclaw.health.observed_at": "yesterday"}))
		}, want: invalid},
		{name: "garbage", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, []byte("not json {"))
		}, want: invalid},
		{name: "report is not an object", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, []byte(`{"schema_version":1,"built_at":"x","report":"healthy","delivery":{}}`))
		}, want: invalid},
		{name: "oversize", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, []byte(`{"pad":"`+strings.Repeat("a", healthReportMaxBytes)+`"}`))
		}, want: &HealthReportState{Error: HealthReportUnreadable}},
		{name: "directory", setup: func(t *testing.T, dataDir string) {
			if err := os.MkdirAll(diagnostics.Path(dataDir, diagnostics.HealthReportFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}, want: &HealthReportState{Error: HealthReportUnreadable}},
		{name: "untrusted values are dropped", setup: func(t *testing.T, dataDir string) {
			writeHealthReport(t, dataDir, healthReportFile(t, 1, map[string]any{
				"defenseclaw.health.trigger": "Startup now",
				"defenseclaw.health.reasons": []map[string]any{{"code": "alice@example.com"}, {"code": "HOOKS_NONE"}},
			}))
		}, want: func() *HealthReportState {
			s := *valid
			s.Trigger, s.ReasonCodes = "", []string{"HOOKS_NONE"}
			return &s
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := filepath.Join(t.TempDir(), "runtime")
			tc.setup(t, dataDir)
			got := ReadHealthReport(dataDir, healthReportNow)
			if !reflect.DeepEqual(got, tc.want) {
				gotJSON, _ := json.Marshal(got)
				wantJSON, _ := json.Marshal(tc.want)
				t.Fatalf("ReadHealthReport = %s, want %s", gotJSON, wantJSON)
			}
		})
	}
}

func TestReadHealthReportRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege on Windows")
	}
	dataDir := filepath.Join(t.TempDir(), "runtime")
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	if err := os.WriteFile(target, healthReportFile(t, 1, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(diagnostics.Dir(dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, diagnostics.Path(dataDir, diagnostics.HealthReportFile)); err != nil {
		t.Fatal(err)
	}
	got := ReadHealthReport(dataDir, healthReportNow)
	if got == nil || got.Error != HealthReportUnreadable || got.Status != "" {
		t.Fatalf("a linked report = %+v, want error %q and nothing else", got, HealthReportUnreadable)
	}
}

func TestReadHealthReportEmptyDataDir(t *testing.T) {
	if got := ReadHealthReport("  ", healthReportNow); got != nil {
		t.Fatalf("empty data dir = %+v, want nil", got)
	}
}

func TestHealthReportStateNilSafe(t *testing.T) {
	var state *HealthReportState
	if state.Summary() != "" {
		t.Fatal("a nil state must render nothing")
	}
	r := New("status", "secure_client", "darwin", "1.0.9")
	r.SetHealthReport(nil)
	var nilResult *Result
	nilResult.SetHealthReport(&HealthReportState{Status: "unhealthy"})
	if r.HealthReport != nil || len(r.Warnings) != 0 {
		t.Fatalf("SetHealthReport(nil) changed the result: %+v", r)
	}
	document, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(document), "health_report") {
		t.Fatalf("a result without a report renders health_report: %s", document)
	}
}

func TestHealthReportSummary(t *testing.T) {
	cases := map[string]struct {
		state *HealthReportState
		want  string
	}{
		"degraded": {&HealthReportState{Status: "degraded", ObservedAt: "2026-11-12T11:30:00Z", ReasonCodes: []string{"HOOKS_PARTIAL"},
			Delivery: &HealthReportDelivery{Result: "queued"}}, "degraded (HOOKS_PARTIAL) at 2026-11-12T11:30:00Z, delivery queued"},
		"healthy stale failed delivery": {&HealthReportState{Status: "healthy", ObservedAt: "2026-11-12T08:00:00Z", Stale: true,
			Delivery: &HealthReportDelivery{Result: "failed", FailureClass: "TIMEOUT"}}, "healthy at 2026-11-12T08:00:00Z, delivery failed (TIMEOUT), stale"},
		"no delivery": {&HealthReportState{Status: "starting", ObservedAt: "2026-11-12T11:30:00Z"}, "starting at 2026-11-12T11:30:00Z"},
		"error":       {&HealthReportState{Error: HealthReportInvalid}, "invalid"},
	}
	for name, tc := range cases {
		if got := tc.state.Summary(); got != tc.want {
			t.Errorf("%s: Summary() = %q, want %q", name, got, tc.want)
		}
	}
}

// The report only adds its block, on macOS as on Windows: never a warning and
// never an error, so warnings, ok and the exit code are those of the result
// without it, whatever the report says.
func TestSetHealthReportAddsOnlyTheBlock(t *testing.T) {
	cases := map[string]struct {
		state *HealthReportState
	}{
		"healthy":     {&HealthReportState{Status: "healthy", ObservedAt: "2026-11-12T11:30:00Z"}},
		"starting":    {&HealthReportState{Status: "starting", ObservedAt: "2026-11-12T11:30:00Z"}},
		"degraded":    {&HealthReportState{Status: "degraded", ReasonCodes: []string{"HOOKS_PARTIAL", "CMID_UNAVAILABLE"}}},
		"unhealthy":   {&HealthReportState{Status: "unhealthy", ReasonCodes: []string{"POLICY_MISSING"}}},
		"stale":       {&HealthReportState{Status: "healthy", Stale: true}},
		"unreadable":  {&HealthReportState{Error: HealthReportUnreadable}},
		"delivered":   {&HealthReportState{Status: "healthy", Delivery: &HealthReportDelivery{Result: "queued"}}},
		"emit failed": {&HealthReportState{Status: "healthy", Delivery: &HealthReportDelivery{Result: "failed"}}},
		"not routed":  {&HealthReportState{Status: "healthy", Delivery: &HealthReportDelivery{Result: "not_routed"}}},
	}
	for name, tc := range cases {
		for _, goos := range []string{"darwin", "windows"} {
			r := New("status", "secure_client", goos, "1.0.9")
			r.Installed = true
			r.CoverageComplete, r.SecurityComplete = true, true
			r.Finish(goos, 0)
			warningsBefore := len(r.Warnings)
			r.SetHealthReport(tc.state)
			if r.HealthReport != tc.state || !r.OK || r.ExitCode != ExitOK || len(r.Errors) != 0 {
				t.Fatalf("%s %s: result changed beyond the block: %+v", name, goos, r)
			}
			if len(r.Warnings) != warningsBefore {
				t.Fatalf("%s %s: the report added warnings %v", name, goos, r.Warnings[warningsBefore:])
			}
			if r.Finish(goos, 0) != ExitOK || !r.OK {
				t.Fatalf("%s %s: a finished result with the report is not ok", name, goos)
			}
		}
	}
}

// The health_report block validates against the lifecycle result schema and
// round-trips, in every shape ReadHealthReport returns.
func TestLifecycleSchemaAcceptsHealthReport(t *testing.T) {
	schema := compileLifecycleSchema(t)
	dataDir := filepath.Join(t.TempDir(), "runtime")
	writeHealthReport(t, dataDir, healthReportFile(t, 1, nil))
	for name, state := range map[string]*HealthReportState{
		"read":  ReadHealthReport(dataDir, healthReportNow),
		"error": {Error: HealthReportAccessDenied},
	} {
		r := New("status", "secure_client", "darwin", "1.0.9")
		r.SetHealthReport(state)
		r.Finish("darwin", 0)
		document, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateAgainstSchema(t, schema, document); err != nil {
			t.Fatalf("%s: schema rejected %s: %v", name, document, err)
		}
		var decoded Result
		if err := json.Unmarshal(document, &decoded); err != nil || !reflect.DeepEqual(decoded.HealthReport, state) {
			t.Fatalf("%s: health_report did not round-trip: %+v (%v)", name, decoded.HealthReport, err)
		}
	}
}
