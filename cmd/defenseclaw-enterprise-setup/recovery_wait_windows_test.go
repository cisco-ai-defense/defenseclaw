// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// useTestRecoveryMutex gives the test its own recovery mutex name, so a
// recovery running on the CI host is never touched.
func useTestRecoveryMutex(t *testing.T) {
	t.Helper()
	previous := standaloneUninstallRecoveryMutex
	t.Cleanup(func() { standaloneUninstallRecoveryMutex = previous })
	standaloneUninstallRecoveryMutex = fmt.Sprintf(`Global\Cisco-DefenseClaw-Test-Uninstall-Recovery-%d-%d`, os.Getpid(), time.Now().UnixNano())
}

// holdTestRecoveryMutex holds the recovery mutex on its own OS thread, as a
// running recovery does, until the returned release runs.
func holdTestRecoveryMutex(t *testing.T) (release func()) {
	t.Helper()
	held, done := make(chan error, 1), make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		name, err := windows.UTF16PtrFromString(standaloneUninstallRecoveryMutex)
		if err != nil {
			held <- err
			return
		}
		handle, err := windows.CreateMutex(nil, true, name)
		if err != nil {
			held <- err
			return
		}
		held <- nil
		<-done
		_ = windows.ReleaseMutex(handle)
		_ = windows.CloseHandle(handle)
	}()
	if err := <-held; err != nil {
		t.Fatalf("hold the recovery mutex: %v", err)
	}
	released := false
	release = func() {
		if !released {
			released = true
			close(done)
		}
	}
	t.Cleanup(release)
	return release
}

// rel-1-0-6:GAP-1080: the armed recovery holds its mutex from the moment its
// Setup exits until the replay ends, and lets go after it.
func TestStandaloneUninstallRecoveryHoldsItsMutexThroughTheReplay(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("a Global mutex needs an elevated administrator token")
	}
	useTestRecoveryMutex(t)
	oldOpen, oldNeeded, oldReplay := setupRecoveryOpenParent, setupRecoveryNeeded, setupRecoveryReplay
	t.Cleanup(func() {
		setupRecoveryOpenParent, setupRecoveryNeeded, setupRecoveryReplay = oldOpen, oldNeeded, oldReplay
	})
	setupRecoveryOpenParent = func(int) (standaloneSetupParent, error) {
		return &fakeStandaloneSetupParent{wait: func() error {
			if err := awaitStandaloneUninstallRecovery(0); err != nil {
				t.Errorf("the recovery held its mutex while its Setup still ran: %v", err)
			}
			return nil
		}}, nil
	}
	setupRecoveryNeeded = func() (bool, error) { return true, nil }
	replayed := false
	setupRecoveryReplay = func() error {
		replayed = true
		// Another Setup asks from another thread, as a rerun does.
		answer := make(chan error, 1)
		go func() { answer <- awaitStandaloneUninstallRecovery(0) }()
		if err := <-answer; !errors.Is(err, errStandaloneSetupMutexHeld) {
			t.Errorf("a rerun during the replay did not see the recovery running: %v", err)
		}
		return nil
	}
	var output bytes.Buffer
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != 0 || !replayed {
		t.Fatalf("recovery exit=%d replayed=%v: %s", code, replayed, output.String())
	}
	if err := awaitStandaloneUninstallRecovery(0); err != nil {
		t.Fatalf("the recovery did not let go of its mutex after the replay: %v", err)
	}
}

// A rerun waits for the running recovery and goes on once it ends.
func TestStandaloneRerunWaitsForTheArmedRecoveryToFinish(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("a Global mutex needs an elevated administrator token")
	}
	useTestRecoveryMutex(t)
	release := holdTestRecoveryMutex(t)
	time.AfterFunc(300*time.Millisecond, release)
	started := time.Now()
	opts := enterpriseSetupOptions{Action: "uninstall", Standalone: true, LifecycleTimeout: 30 * time.Minute, Started: started}
	if err := waitForStandaloneUninstallRecovery(opts); err != nil {
		t.Fatalf("the rerun did not go on after the recovery ended: %v", err)
	}
	if waited := time.Since(started); waited < 250*time.Millisecond {
		t.Fatalf("the rerun went on after %s, while the recovery still ran", waited)
	}
}

// A rerun whose wait ends with the recovery still running is the retryable
// 1618 lifecycle_busy before anything is staged or changed: it never arms a
// second recovery or starts the lifecycle child.
func TestStandaloneUninstallRerunDuringTheArmedRecoveryIsBusy(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the standalone Setup requires an elevated administrator token")
	}
	useTestRecoveryMutex(t)
	previousFlavor, previousPayload, previousArm, previousLimit :=
		enterpriseSetupStandaloneFlavor, enterpriseSetupPayloadLoader, enterpriseSetupArmUninstallRecovery, enterpriseSetupRecoveryWaitLimit
	t.Cleanup(func() {
		enterpriseSetupStandaloneFlavor, enterpriseSetupPayloadLoader, enterpriseSetupArmUninstallRecovery, enterpriseSetupRecoveryWaitLimit =
			previousFlavor, previousPayload, previousArm, previousLimit
	})
	enterpriseSetupStandaloneFlavor = func() bool { return true }
	payloadFS, _ := newEnterprisePayloadFixtureForFlavor(t, false, true)
	enterpriseSetupPayloadLoader = func() (enterprisePayload, error) { return loadEnterprisePayload(payloadFS) }
	armed := false
	enterpriseSetupArmUninstallRecovery = func() error {
		armed = true
		return errors.New("test: the uninstall went past the recovery wait")
	}
	enterpriseSetupRecoveryWaitLimit = 300 * time.Millisecond
	holdTestRecoveryMutex(t)

	var stdout, stderr bytes.Buffer
	code := runEnterpriseSetup([]string{"/uninstall", "JSON=1"}, &stdout, &stderr)
	var result struct {
		ExitCode int `json:"exit_code"`
		Errors   []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || armed ||
		code != enterpriseBusyExitCode || result.ExitCode != code || len(result.Errors) != 1 ||
		result.Errors[0].Code != "lifecycle_busy" || !strings.Contains(result.Errors[0].Message, "earlier Setup /uninstall") {
		t.Fatalf("rerun during the recovery: code=%d armed=%v stdout=%q stderr=%q parse=%v", code, armed, stdout.String(), stderr.String(), err)
	}
}
