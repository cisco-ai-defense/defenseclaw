//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// collectWindowsProfileScan runs one profile's scan and fails the test when
// it does not answer within guard.
func collectWindowsProfileScan(t *testing.T, ctx context.Context, home string, connectors []string, guard time.Duration, release chan struct{}) []UnprotectedAgent {
	t.Helper()
	var reported []UnprotectedAgent
	finished := make(chan struct{})
	go func() {
		reportWindowsPrivateInstalls(ctx, func(agent UnprotectedAgent) { reported = append(reported, agent) },
			"alice", testLocalUserTwo, home, connectors)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(guard):
		close(release)
		t.Fatal("a stalled call held the profile scan past its deadline")
	}
	return reported
}

func wantWindowsScanTimedOut(t *testing.T, reported []UnprotectedAgent, connectors ...string) {
	t.Helper()
	if len(reported) != len(connectors) {
		t.Fatalf("reported %+v, want %v timed out", reported, connectors)
	}
	for i, agent := range reported {
		if agent.Connector != connectors[i] || agent.Code != UnprotectedCodeInstallScanIncomplete || agent.SID != testLocalUserTwo ||
			agent.Reason != privateInstallIncompleteReason(PrivateInstallSkippedTimedOut) || !strings.Contains(agent.Reason, "scan timed out") {
			t.Fatalf("reported %+v, want %v NOT COVERED with scan timed out", reported, connectors)
		}
	}
}

func waitWindowsScanWorkerReleased(t *testing.T, home string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		windowsPrivateInstallsInFlight.Lock()
		busy := windowsPrivateInstallsInFlight.homes[strings.ToLower(filepath.Clean(home))]
		windowsPrivateInstallsInFlight.Unlock()
		if !busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the stalled worker never released its home")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A directory open or listing that stalls never observes the scan context.
// The profile's scan still answers by its deadline (plus the grace) with the
// scan timed out for that profile only, and a later cycle does not start a
// second worker behind the stalled one.
func TestWindowsPrivateInstallScanAnswersByItsDeadlineWhenADirectoryCallStalls(t *testing.T) {
	oldScan, oldGrace := windowsPrivateInstallsForEnumeration, windowsPrivateInstallGrace
	release := make(chan struct{})
	t.Cleanup(func() {
		windowsPrivateInstallsForEnumeration, windowsPrivateInstallGrace = oldScan, oldGrace
	})
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	windowsPrivateInstallGrace = 50 * time.Millisecond
	calls := make(chan string, 8)
	windowsPrivateInstallsForEnumeration = func(_ context.Context, home string, _ []string) []PrivateAgentInstall {
		calls <- home
		<-release // a blocked system call: the context is never read
		return nil
	}
	home := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	wantWindowsScanTimedOut(t, collectWindowsProfileScan(t, ctx, home, []string{"codex", "hermes"}, 5*time.Second, release), "codex")

	// The next cycle, while the worker is still stalled, answers at once.
	again, cancelAgain := context.WithTimeout(context.Background(), time.Minute)
	defer cancelAgain()
	start := time.Now()
	wantWindowsScanTimedOut(t, collectWindowsProfileScan(t, again, home, []string{"codex", "copilot"}, 2*time.Second, release), "codex", "copilot")
	if time.Since(start) > 2*time.Second || len(calls) != 1 {
		t.Fatalf("second cycle behind a stalled worker took %s and started %d workers, want at once and 1", time.Since(start), len(calls))
	}

	// Once the stalled call returns the home is scanned again.
	close(release)
	waitWindowsScanWorkerReleased(t, home)
	if reported := collectWindowsProfileScan(t, again, home, []string{"codex"}, 5*time.Second, make(chan struct{})); len(reported) != 0 {
		t.Fatalf("finished scan = %+v, want a clean answer", reported)
	}
	if len(calls) != 2 {
		t.Fatalf("scan workers = %d, want a new one after the stall ended", len(calls))
	}
}

// A scan that answers in time is returned as it is, and another profile is
// never held by one profile's stalled worker.
func TestWindowsPrivateInstallStallKeepsOtherProfilesScanned(t *testing.T) {
	oldScan, oldGrace := windowsPrivateInstallsForEnumeration, windowsPrivateInstallGrace
	release := make(chan struct{})
	t.Cleanup(func() {
		close(release)
		windowsPrivateInstallsForEnumeration, windowsPrivateInstallGrace = oldScan, oldGrace
	})
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	windowsPrivateInstallGrace = 50 * time.Millisecond
	stalled, healthy := t.TempDir(), t.TempDir()
	windowsPrivateInstallsForEnumeration = func(_ context.Context, home string, _ []string) []PrivateAgentInstall {
		if home == stalled {
			<-release
			return nil
		}
		return []PrivateAgentInstall{{Connector: "codex", Version: "0.1.0"}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	wantWindowsScanTimedOut(t, collectWindowsProfileScan(t, ctx, stalled, []string{"codex"}, 5*time.Second, make(chan struct{})), "codex")
	fresh, cancelFresh := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFresh()
	reported := collectWindowsProfileScan(t, fresh, healthy, []string{"codex"}, 5*time.Second, make(chan struct{}))
	if len(reported) != 1 || reported[0].Code != UnprotectedCodeHookContractUnverified || reported[0].Version != "0.1.0" {
		t.Fatalf("healthy home behind a stalled one = %+v, want its own scan", reported)
	}
}

// Round e: every call of the profile's scan runs under its deadline, not
// only the home walk. A per-user WinGet registry read that does not answer
// after the walk returned held the cycle (it ran outside the worker).
func TestWindowsPrivateInstallWinGetStallAnswersByTheDeadline(t *testing.T) {
	oldScan, oldGrace := windowsPrivateInstallsForEnumeration, windowsPrivateInstallGrace
	oldUser := windowsUserWinGetPackageVersion
	release := make(chan struct{})
	t.Cleanup(func() {
		windowsPrivateInstallsForEnumeration, windowsPrivateInstallGrace = oldScan, oldGrace
		windowsUserWinGetPackageVersion = oldUser
	})
	stubMachineWinGet(t, nil)
	windowsPrivateInstallGrace = 50 * time.Millisecond
	windowsPrivateInstallsForEnumeration = func(context.Context, string, []string) []PrivateAgentInstall { return nil }
	windowsUserWinGetPackageVersion = func(string, string) (string, string) {
		<-release // a registry read that never returns
		return "", ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	home := t.TempDir()
	wantWindowsScanTimedOut(t, collectWindowsProfileScan(t, ctx, home, []string{"codex", "hermes"}, 5*time.Second, release), "codex")
	close(release)
	waitWindowsScanWorkerReleased(t, home)
}

// Round e: an administrator-authored home ProfileList does not list is
// checked inside the profile's worker. A stat of that home that never
// answers (an offline redirected or network home) leaves every connector of
// the account NOT COVERED with scan timed out, and the cycle still returns
// by its deadline.
func TestEnumerateWindowsAuthoredHomeStatStallAnswersByTheDeadline(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubUserWinGet(t, nil)
	injectWindowsProfileList(t, map[string]string{})
	oldStat, oldGrace := windowsAuthoredHomeLstat, windowsPrivateInstallGrace
	release := make(chan struct{})
	t.Cleanup(func() { windowsAuthoredHomeLstat, windowsPrivateInstallGrace = oldStat, oldGrace })
	windowsPrivateInstallGrace = 50 * time.Millisecond
	home := filepath.Join(t.TempDir(), "offline")
	windowsAuthoredHomeLstat = func(string) (fs.FileInfo, error) {
		<-release
		return nil, fs.ErrNotExist
	}
	enabled := true
	subjects := WindowsManifestSubjects(Manifest{Version: 1, Targets: []ManifestTarget{
		{SID: testLocalUserTwo, Connector: "codex", UserHome: home, Enabled: &enabled},
		{SID: testLocalUserTwo, Connector: "hermes", UserHome: home, Enabled: &enabled},
	}})
	// 10 s of the cycle are kept for publishing, so the account gets 2 s.
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var reported []UnprotectedAgent
	finished := make(chan error, 1)
	go func() {
		_, err := EnumerateWindows(ctx, standaloneEnumeratorConfig("codex"), EnumerateOptions{
			GroupCache:        NewWindowsEnrollmentGroupCache(),
			ManifestSubjects:  subjects,
			ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
		})
		finished <- err
	}()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("a stalled authored-home stat failed the cycle: %v", err)
		}
	case <-time.After(8 * time.Second):
		close(release)
		t.Fatal("a stalled authored-home stat held the cycle past the account's deadline")
	}
	close(release)
	waitWindowsScanWorkerReleased(t, home)
	var got []string
	for _, agent := range reported {
		if agent.SID == testLocalUserTwo {
			got = append(got, agent.Connector)
			if agent.Code != UnprotectedCodeInstallScanIncomplete || !strings.Contains(agent.Reason, "scan timed out") {
				t.Fatalf("authored account reported %+v, want NOT COVERED with scan timed out", agent)
			}
		}
	}
	if strings.Join(got, ",") != "codex,hermes" {
		t.Fatalf("authored account reported %v, want codex and hermes timed out", got)
	}
}
