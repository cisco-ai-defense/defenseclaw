// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// writeInstallScanRecord writes the enumerator's unprotected-agents record
// with the given generation ("" writes the current install's).
func writeInstallScanRecord(t *testing.T, h *testHost, generation string) {
	t.Helper()
	path := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
	data, err := enterprisehooks.MarshalUnprotectedAgents(nil)
	if err != nil {
		t.Fatal(err)
	}
	if generation != "" {
		data = []byte(`{"version":1,"generation":"` + generation + `","agents":[]}` + "\n")
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0726: an ensure that restarts the enumerator read the unprotected-agents
// record a moment later, while the restarted enumerator had not finished its
// first cycle, so the Enterprise Upgrade Lane (pkg) step "upgrade to 9.9.9"
// exited 0 with agent_install_scan_incomplete and coverage_complete=false.
// The change now waits, bounded by InstallScanTimeout, for the record of the
// current install; a record that arrives meanwhile is what the result reports.
func TestEnsureWaitsForTheRestartedEnumeratorsFirstRecord(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			// The previous release's enumerator wrote this a minute ago.
			writeInstallScanRecord(t, h, "0.9.9-previous")
			h.env.InstallScanTimeout = 10 * time.Second
			enumerator := unitOf(goos, "enumerator")
			published := make(chan error, 1)
			started := false
			h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
				if unit != enumerator || started {
					return
				}
				started = true
				// The restarted enumerator finishes its first cycle a moment
				// after the services are up.
				go func() {
					time.Sleep(300 * time.Millisecond)
					path := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
					data, err := enterprisehooks.MarshalUnprotectedAgents(nil)
					if err == nil {
						err = os.WriteFile(path, data, 0o600)
					}
					published <- err
				}()
			}}
			t.Cleanup(func() {
				if !started {
					return
				}
				if err := <-published; err != nil {
					t.Error(err)
				}
			})
			r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
			requireOK(t, r)
			if !started {
				t.Fatal("the change did not restart the enumerator; the test proves nothing")
			}
			if hasWarning(r, enterprisehooks.UnprotectedCodeInstallScanIncomplete) {
				t.Fatalf("ensure reported the previous install's scan as pending after the enumerator published: %+v", r.Warnings)
			}
		})
	}
}

// An enumerator that does not publish in time leaves the truthful warning
// (with its remedy) instead of a hang or a silent "complete".
func TestEnsureReportsTheScanPendingWhenTheEnumeratorDoesNotPublish(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeInstallScanRecord(t, h, "0.9.9-previous")
	h.env.InstallScanTimeout = 100 * time.Millisecond
	r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	messages := messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
	if r.CoverageComplete || !strings.Contains(messages, "from an earlier install") {
		t.Fatalf("coverage=%v warnings=%q, want the scan-pending row for the earlier install", r.CoverageComplete, messages)
	}
}

// A change that leaves a current record in place does not wait for one.
func TestEnsureDoesNotWaitForACurrentInstallScan(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeInstallScanRecord(t, h, "")
	h.env.InstallScanTimeout = time.Minute
	begun := time.Now()
	requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")}))
	if took := time.Since(begun); took > 20*time.Second {
		t.Fatalf("ensure waited %s for an install scan that was already current", took)
	}
}
