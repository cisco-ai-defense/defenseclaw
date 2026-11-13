// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/diagnostics"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

const testHealthReportFile = `{
  "schema_version": 1,
  "built_at": "2026-11-12T11:30:01Z",
  "report": {
    "defenseclaw.health.sequence": 7,
    "defenseclaw.health.trigger": "scheduled",
    "defenseclaw.health.observed_at": "2026-11-12T11:30:00Z",
    "defenseclaw.health.report_interval_s": 1800,
    "defenseclaw.health.status": "degraded",
    "defenseclaw.health.reasons": [{"code": "HOOKS_PARTIAL", "component": "hooks", "severity": "medium", "connector": "codex"}]
  },
  "delivery": {"result": "queued", "at": "2026-11-12T11:30:01Z", "cloud_state": "ok"}
}
`

func stubSecureClientHealthReport(t *testing.T, secureClient, root bool) string {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "runtime")
	previousDir, previousRoot, previousHost := secureClientHealthReportDataDir, healthReportReaderIsRoot, secureClientHost
	t.Cleanup(func() {
		secureClientHealthReportDataDir, healthReportReaderIsRoot, secureClientHost = previousDir, previousRoot, previousHost
	})
	secureClientHealthReportDataDir = func() string { return dataDir }
	healthReportReaderIsRoot = func() bool { return root }
	secureClientHost = func() bool { return secureClient }
	return dataDir
}

func writeTestHealthReport(t *testing.T, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(diagnostics.Dir(dataDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(diagnostics.Path(dataDir, diagnostics.HealthReportFile), []byte(testHealthReportFile), 0o600); err != nil {
		t.Fatal(err)
	}
}

func secureClientStatusResult(action string) *enterprisestatus.Result {
	r := enterprisestatus.New(action, "standalone", "darwin", "1.0.9")
	r.Finish("darwin", 0)
	return r
}

// A macOS status as root on a Secure Client host reports the gateway's last
// health report in --json and as one text line, with one warning and the
// same ok and exit code.
func TestSecureClientMacOSStatusReportsHealthReport(t *testing.T) {
	dataDir := stubSecureClientHealthReport(t, true, true)
	writeTestHealthReport(t, dataDir)
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

	r := secureClientStatusResult("status")
	attachSecureClientHealthReport(r, "darwin", now)
	if r.HealthReport == nil || r.HealthReport.Status != "degraded" || !r.OK || r.ExitCode != 0 {
		t.Fatalf("status result = %+v, want a degraded health_report, ok, exit 0", r)
	}
	var out bytes.Buffer
	if err := printLifecycleResult(&out, r, true); err != nil {
		t.Fatal(err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	want := `{"status":"degraded","observed_at":"2026-11-12T11:30:00Z","sequence":7,"trigger":"scheduled",` +
		`"reason_codes":["HOOKS_PARTIAL"],"built_at":"2026-11-12T11:30:01Z",` +
		`"delivery":{"result":"queued","at":"2026-11-12T11:30:01Z","cloud_state":"ok"},"stale":false}`
	var compact bytes.Buffer
	if err := json.Compact(&compact, document["health_report"]); err != nil || compact.String() != want {
		t.Fatalf("health_report = %s (%v), want %s", compact.String(), err, want)
	}
	out.Reset()
	if err := printLifecycleResult(&out, r, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "  health report: degraded (HOOKS_PARTIAL) at 2026-11-12T11:30:00Z, delivery queued\n") {
		t.Fatalf("status text has no health report line:\n%s", out.String())
	}
	if len(r.Warnings) != 0 {
		t.Fatalf("a degraded report added warnings, unlike Windows: %v", r.Warnings)
	}
}

// Without a report, on another host, for another action, or for a standard
// user, the result is exactly what it was: no block, no warning.
func TestSecureClientMacOSStatusOmitsHealthReport(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name         string
		secureClient bool
		root         bool
		write        bool
		goos         string
		action       string
	}{
		{name: "no report", secureClient: true, root: true, goos: "darwin", action: "status"},
		{name: "not secure client", secureClient: false, root: true, write: true, goos: "darwin", action: "status"},
		{name: "not root", secureClient: true, root: false, write: true, goos: "darwin", action: "status"},
		{name: "verify", secureClient: true, root: true, write: true, goos: "darwin", action: "verify"},
		{name: "linux", secureClient: true, root: true, write: true, goos: "linux", action: "status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := stubSecureClientHealthReport(t, tc.secureClient, tc.root)
			if tc.write {
				writeTestHealthReport(t, dataDir)
			}
			plain := secureClientStatusResult(tc.action)
			var before bytes.Buffer
			if err := printLifecycleResult(&before, plain, true); err != nil {
				t.Fatal(err)
			}
			r := secureClientStatusResult(tc.action)
			attachSecureClientHealthReport(r, tc.goos, now)
			var after bytes.Buffer
			if err := printLifecycleResult(&after, r, true); err != nil {
				t.Fatal(err)
			}
			if r.HealthReport != nil || !bytes.Equal(before.Bytes(), after.Bytes()) {
				t.Fatalf("output changed:\n%s\n%s", before.String(), after.String())
			}
		})
	}
}
