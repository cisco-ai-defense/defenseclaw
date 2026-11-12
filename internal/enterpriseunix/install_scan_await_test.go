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
					// The restarted enumerator stamps its scan with the config
					// the change just committed (GAP-0640); an unstamped record
					// would be pending by design.
					data, err := h.marshalCompletedScan(nil)
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

// writeStampedInstallScanRecord writes a completed scan of the installed
// config, as the enumerator does at the end of a cycle.
func writeStampedInstallScanRecord(t *testing.T, h *testHost) {
	t.Helper()
	data, err := h.marshalCompletedScan(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// GAP-0782: a change of the config (a connector roster pushed by ensure)
// leaves the record of the previous config generation in place, written by
// this same build a few minutes ago. The wait tested only the build and the
// age, returned at once, and the result reported the scan pending ("from a
// different config generation", coverage_complete=false: the Enterprise
// Install Lane (pkg) on macOS). The wait and the result now share one test,
// so the result reports the scan the restarted enumerator publishes.
func TestEnsureWaitsForTheScanOfTheNewConfigGeneration(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			// The enumerator scanned the config the install wrote.
			writeStampedInstallScanRecord(t, h)
			h.env.InstallScanTimeout = 10 * time.Second
			enumerator := unitOf(goos, "enumerator")
			published := make(chan error, 1)
			started := false
			h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
				if unit != enumerator || started {
					return
				}
				started = true
				go func() {
					time.Sleep(300 * time.Millisecond)
					data, err := h.marshalCompletedScan(nil)
					if err == nil {
						err = os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600)
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
				t.Fatalf("ensure reported the scan of the previous config generation as pending after the enumerator published: %+v", r.Warnings)
			}
			if !r.CoverageComplete {
				t.Fatalf("coverage_complete=false after the enumerator published the scan of the new config: %+v", r.Warnings)
			}
		})
	}
}

// An enumerator that does not publish the scan of the new config in time
// leaves the truthful warning with its remedy, after the bounded wait.
func TestEnsureReportsTheScanPendingWhenTheEnumeratorKeepsThePreviousConfigGeneration(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeStampedInstallScanRecord(t, h)
	h.env.InstallScanTimeout = 100 * time.Millisecond
	r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	messages := messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
	if r.CoverageComplete || !strings.Contains(messages, "from a different config generation") ||
		!strings.Contains(messages, "launchctl kickstart") {
		t.Fatalf("coverage=%v warnings=%q, want the scan-pending row for the previous config generation with its remedy", r.CoverageComplete, messages)
	}
}

// A change that leaves a record of the installed config in place does not
// wait for one: a repair rewrites no config, so the scan stays current.
func TestEnsureDoesNotWaitForACurrentInstallScan(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeStampedInstallScanRecord(t, h)
	h.env.InstallScanTimeout = time.Minute
	begun := time.Now()
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if took := time.Since(begun); took > 20*time.Second {
		t.Fatalf("repair waited %s for an install scan that was already current", took)
	}
}
