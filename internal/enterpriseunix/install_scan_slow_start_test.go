// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// measuredMacOSEnumeratorStart is what the standalone macOS pkg host took
// from the launchd kickstart of the enumerator to its first record (two
// measurements, GAP-0782).
const measuredMacOSEnumeratorStart = 38 * time.Second

// GAP-0782: the wait bound was 30 s and the first record of the restarted
// enumerator took 38 s on macOS, so every config-changing ensure ended
// coverage_complete=false. The bound has margin over the measured start.
func TestInstallScanWaitOutlastsTheMeasuredEnumeratorStart(t *testing.T) {
	env := &Env{}
	env.fillDefaults()
	if env.InstallScanTimeout < 2*measuredMacOSEnumeratorStart {
		t.Fatalf("the install scan wait is %s, want at least %s (twice the measured %s first record)",
			env.InstallScanTimeout, 2*measuredMacOSEnumeratorStart, measuredMacOSEnumeratorStart)
	}
}

// writeScanStartedRecord writes what the restarted enumerator publishes
// first: the new config generation, the previous agents, scan not finished.
func writeScanStartedRecord(h *testHost) error {
	state, err := configwrite.ReadGenerationState(h.env.P(h.env.Layout.ConfigPath))
	if err != nil {
		return err
	}
	data, err := enterprisehooks.MarshalUnprotectedAgentsScanStarted(nil, state.Generation, state.ConfigSHA256)
	if err != nil {
		return err
	}
	return os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600)
}

// A slow-starting enumerator (the macOS case, scaled down: it announces the
// new generation at once and finishes its scan well after the previous
// bound would have passed) ends the ensure covered, with progress lines
// while it waited.
func TestEnsureWaitsOutASlowStartingEnumerator(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			writeStampedInstallScanRecord(t, h)
			h.env.InstallScanTimeout = 10 * time.Second
			var progress []string
			h.env.Progress = func(line string) { progress = append(progress, line) }
			enumerator := unitOf(goos, "enumerator")
			published := make(chan error, 1)
			started := false
			h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
				if unit != enumerator || started {
					return
				}
				started = true
				go func() {
					time.Sleep(100 * time.Millisecond)
					err := writeScanStartedRecord(h)
					if err == nil {
						// The full scan outlasts several polls.
						time.Sleep(1500 * time.Millisecond)
						var data []byte
						if data, err = h.marshalCompletedScan(nil); err == nil {
							err = os.WriteFile(h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath)), data, 0o600)
						}
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
			if !r.CoverageComplete || hasWarning(r, enterprisehooks.UnprotectedCodeInstallScanIncomplete) {
				t.Fatalf("coverage_complete=%v after a slow enumerator finished its scan: %+v", r.CoverageComplete, r.Warnings)
			}
			if len(progress) == 0 || !strings.Contains(progress[0], "waiting for the enumerator to scan the new config") {
				t.Fatalf("progress=%q, want a line saying the change waits for the enumerator", progress)
			}
		})
	}
}

// The announcement of a scan is not its result: an enumerator that announced
// the new generation and then stopped leaves the pending warning with its
// remedy after the bound, never a covered result.
func TestEnsureReportsTheScanPendingWhenTheEnumeratorStopsAfterAnnouncingIt(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	writeStampedInstallScanRecord(t, h)
	h.env.InstallScanTimeout = 300 * time.Millisecond
	enumerator := unitOf("darwin", "enumerator")
	announced := make(chan error, 1)
	started := false
	h.env.Services = &hookedServices{fakeServices: h.services, onStart: func(unit string) {
		if unit != enumerator || started {
			return
		}
		started = true
		go func() {
			time.Sleep(50 * time.Millisecond)
			announced <- writeScanStartedRecord(h)
		}()
	}}
	t.Cleanup(func() {
		if started {
			if err := <-announced; err != nil {
				t.Error(err)
			}
		}
	})
	r := h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	messages := messagesOf(r.Warnings, enterprisehooks.UnprotectedCodeInstallScanIncomplete)
	if r.CoverageComplete || !strings.Contains(messages, "has not finished") || !strings.Contains(messages, "launchctl kickstart") {
		t.Fatalf("coverage=%v warnings=%q, want the scan-pending row for the unfinished scan with its remedy", r.CoverageComplete, messages)
	}
}
