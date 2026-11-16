// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/diagnostics"
)

const windowsSecureClientTestStatus = `{"schema_version":1,"ok":true,"action":"status","installed":true,"errors":[]}`

const windowsSecureClientTestReport = `{"schema_version":1,"built_at":"2026-11-12T11:30:01Z",
"report":{"defenseclaw.health.sequence":7,"defenseclaw.health.trigger":"scheduled",
"defenseclaw.health.observed_at":"2026-11-12T11:30:00Z","defenseclaw.health.report_interval_s":1800,
"defenseclaw.health.status":"degraded","defenseclaw.health.reasons":[{"code":"HOOKS_PARTIAL","component":"hooks","severity":"medium"}]},
"delivery":{"result":"queued","at":"2026-11-12T11:30:01Z"}}`

func stubWindowsSecureClientStatus(t *testing.T, elevated, writeReport bool, runErr error) (*cobra.Command, *bytes.Buffer) {
	t.Helper()
	dataDir := filepath.Join(t.TempDir(), "runtime")
	if writeReport {
		if err := os.MkdirAll(diagnostics.Dir(dataDir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(diagnostics.Path(dataDir, diagnostics.HealthReportFile), []byte(windowsSecureClientTestReport), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousRunner, previousElevated, previousDir := windowsEnterpriseCommandRunner, windowsEnterpriseIsElevated, windowsSecureClientHealthReportDataDir
	t.Cleanup(func() {
		windowsEnterpriseCommandRunner, windowsEnterpriseIsElevated, windowsSecureClientHealthReportDataDir = previousRunner, previousElevated, previousDir
	})
	windowsEnterpriseIsElevated = func() bool { return elevated }
	windowsSecureClientHealthReportDataDir = func(*windowsEnterpriseLifecycleOptions) string { return dataDir }
	windowsEnterpriseCommandRunner = func(_ context.Context, cmd *cobra.Command, _ string, args []string) error {
		if _, jsonOutput := windowsEnterprisePowerShellArgsAction(args); jsonOutput {
			_, _ = cmd.OutOrStdout().Write([]byte(windowsSecureClientTestStatus + "\n"))
		} else {
			_, _ = cmd.OutOrStdout().Write([]byte("DefenseClaw Windows enterprise status: OK\n  Gateway service: running\n"))
		}
		return runErr
	}
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	return cmd, &out
}

// An elevated Secure Client status reports the gateway's last health report:
// a health_report member in --json, one line in text, and the installer's
// own result (error included) unchanged.
func TestWindowsSecureClientStatusReportsHealthReport(t *testing.T) {
	failure := errors.New("installer exit")
	cmd, out := stubWindowsSecureClientStatus(t, true, true, failure)
	opts := &windowsEnterpriseLifecycleOptions{jsonOutput: true}
	if err := runWindowsSecureClientLifecycle(context.Background(), cmd, "status", opts, "install-enterprise.ps1",
		windowsEnterprisePowerShellArgs("status", opts)); !errors.Is(err, failure) {
		t.Fatalf("status error = %v, want the installer's", err)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatalf("status JSON %s: %v", out.String(), err)
	}
	if !strings.HasPrefix(out.String(), strings.TrimSuffix(windowsSecureClientTestStatus, "}")+`,"health_report":{"status":"degraded"`) {
		t.Fatalf("status JSON = %s, want the installer's document with health_report appended", out.String())
	}
	if cmd.OutOrStdout() != out {
		t.Fatal("the command's stdout was not restored")
	}

	cmd, out = stubWindowsSecureClientStatus(t, true, true, nil)
	opts = &windowsEnterpriseLifecycleOptions{}
	if err := runWindowsSecureClientLifecycle(context.Background(), cmd, "status", opts, "install-enterprise.ps1",
		windowsEnterprisePowerShellArgs("status", opts)); err != nil {
		t.Fatal(err)
	}
	// The line ends ", stale" once the fixture's time is three intervals old.
	if !strings.HasPrefix(out.String(), "DefenseClaw Windows enterprise status: OK\n  Gateway service: running\n"+
		"  Health report: degraded (HOOKS_PARTIAL) at 2026-11-12T11:30:00Z, delivery queued") || strings.Count(out.String(), "\n") != 3 {
		t.Fatalf("status text = %q", out.String())
	}
}

// Without a report, unelevated, or for another action, the output is the
// installer's byte for byte.
func TestWindowsSecureClientStatusOmitsHealthReport(t *testing.T) {
	for _, tc := range []struct {
		name     string
		action   string
		elevated bool
		write    bool
	}{
		{name: "no report", action: "status", elevated: true},
		{name: "unelevated", action: "status", write: true},
		{name: "verify", action: "verify", elevated: true, write: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, jsonOutput := range []bool{true, false} {
				cmd, out := stubWindowsSecureClientStatus(t, tc.elevated, tc.write, nil)
				opts := &windowsEnterpriseLifecycleOptions{jsonOutput: jsonOutput}
				if err := runWindowsSecureClientLifecycle(context.Background(), cmd, tc.action, opts, "install-enterprise.ps1",
					windowsEnterprisePowerShellArgs(tc.action, opts)); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(out.String(), "ealth") {
					t.Fatalf("json=%v: output names the health report: %s", jsonOutput, out.String())
				}
			}
		})
	}
}
