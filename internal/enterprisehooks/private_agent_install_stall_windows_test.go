//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A directory open or listing that stalls never observes the scan context.
// The profile's scan still answers by its deadline (plus the grace) with the
// home unreadable for that profile only, and a later cycle does not start a
// second worker behind the stalled one.
func TestWindowsPrivateInstallScanAnswersByItsDeadlineWhenADirectoryCallStalls(t *testing.T) {
	oldScan, oldGrace := windowsPrivateInstallsForEnumeration, windowsPrivateInstallGrace
	release := make(chan struct{})
	t.Cleanup(func() {
		windowsPrivateInstallsForEnumeration, windowsPrivateInstallGrace = oldScan, oldGrace
	})
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
	var reported []UnprotectedAgent
	finished := make(chan struct{})
	go func() {
		reportWindowsPrivateInstalls(ctx, func(agent UnprotectedAgent) { reported = append(reported, agent) },
			"alice", testLocalUserTwo, home, []string{"codex", "hermes"})
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("a stalled directory call held the profile scan past its deadline")
	}
	if len(reported) != 1 || reported[0].Connector != "codex" || reported[0].Code != UnprotectedCodeInstallScanIncomplete ||
		reported[0].Reason != privateInstallIncompleteReason(PrivateInstallSkippedHome) || reported[0].SID != testLocalUserTwo {
		t.Fatalf("stalled profile reported %+v, want codex home_unreadable for this profile only", reported)
	}

	// The next cycle, while the worker is still stalled, answers at once.
	again, cancelAgain := context.WithTimeout(context.Background(), time.Minute)
	defer cancelAgain()
	start := time.Now()
	installs := windowsPrivateInstallsBounded(again, home, []string{"codex", "copilot"})
	if time.Since(start) > 2*time.Second || len(installs) != 2 || !installs[0].Incomplete || installs[0].Skipped != PrivateInstallSkippedHome {
		t.Fatalf("second cycle behind a stalled worker = %+v after %s", installs, time.Since(start))
	}
	if len(calls) != 1 {
		t.Fatalf("started %d scan workers for one stalled home, want 1", len(calls))
	}

	// Once the stalled call returns the home is scanned again.
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		windowsPrivateInstallsInFlight.Lock()
		busy := windowsPrivateInstallsInFlight.homes[strings.ToLower(filepath.Clean(home))]
		windowsPrivateInstallsInFlight.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stalled worker never released its home")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if installs := windowsPrivateInstallsBounded(again, home, []string{"codex"}); len(installs) != 0 {
		t.Fatalf("finished scan = %+v, want a clean answer", installs)
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
	if installs := windowsPrivateInstallsBounded(ctx, stalled, []string{"codex"}); len(installs) != 1 || !installs[0].Incomplete {
		t.Fatalf("stalled home = %+v", installs)
	}
	fresh, cancelFresh := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFresh()
	if installs := windowsPrivateInstallsBounded(fresh, healthy, []string{"codex"}); len(installs) != 1 || installs[0].Incomplete || installs[0].Version != "0.1.0" {
		t.Fatalf("healthy home behind a stalled one = %+v, want its own scan", installs)
	}
}
