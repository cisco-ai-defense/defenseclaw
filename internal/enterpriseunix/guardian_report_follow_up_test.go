// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"strings"
	"testing"
	"time"
)

// rel-1-0-3 GAP-0142: two config pushes five seconds apart. The first run
// applied the first push, waited for the restarted guardian to report, then
// applied the second push in its follow-up and waited for the guardian
// again, so on macOS the first ensure took 26 s. A transaction whose inputs
// were replaced leaves the guardian report to its follow-up: one wait.
func TestAPushDuringTheRunWaitsForTheGuardianReportOnce(t *testing.T) {
	const report = 1200 * time.Millisecond
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			// No guardian answers in the fake: every wait for its report runs
			// to GuardianReportTimeout.
			h.env.GuardianReportTimeout = report
			started := time.Now()
			requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}))
			alone := time.Since(started)

			second := []byte(strings.Replace(string(DefaultConfig(h.env.Layout)), "mode: observe", "mode: action", 1))
			written := false
			hooked := &hookedServices{fakeServices: h.services}
			hooked.onStart = func(unit string) {
				if unit == unitOf(goos, "gateway") && !written {
					written = true
					if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), second, 0o640); err != nil {
						t.Errorf("write config: %v", err)
					}
				}
			}
			h.env.Services = hooked
			started = time.Now()
			r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.2")})
			pushed := time.Since(started)
			if !written {
				t.Fatal("the second push was not written during the run")
			}
			requireOK(t, r)
			if !hasWarning(r, codeInputChanged) {
				t.Fatalf("no follow-up applied the second push: %+v", r.Warnings)
			}
			record, _ := h.env.loadDeployment()
			if record.ConfigSHA256 != sha256Bytes(second) || record.ProductVersion != "1.0.2" {
				t.Fatalf("the second push is not applied: config %s version %s", record.ConfigSHA256[:8], record.ProductVersion)
			}
			if pushed >= alone+report*3/4 {
				t.Fatalf("the run with a push during it took %s, one without %s: it waited for the guardian report in both transactions (each wait %s)",
					pushed.Round(time.Millisecond), alone.Round(time.Millisecond), report)
			}
		})
	}
}
