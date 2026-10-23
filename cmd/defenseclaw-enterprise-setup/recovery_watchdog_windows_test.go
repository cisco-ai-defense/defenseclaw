// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// GAP-0726: the independent child waits until the uninstall parent has
// exited, then replays only a pending transaction. A successful uninstall
// leaves no pending record and must not be undone.
func TestStandaloneUninstallRecoveryWatcher(t *testing.T) {
	oldOpen, oldPending, oldReplay := setupRecoveryOpenParent, setupRecoveryPending, setupRecoveryReplay
	t.Cleanup(func() {
		setupRecoveryOpenParent, setupRecoveryPending, setupRecoveryReplay = oldOpen, oldPending, oldReplay
	})
	var events []string
	var output bytes.Buffer
	setupRecoveryOpenParent = func(pid int) (standaloneSetupParent, error) {
		events = append(events, "parent opened")
		return &fakeStandaloneSetupParent{wait: func() error {
			if !bytes.HasPrefix(output.Bytes(), []byte("READY\n")) {
				t.Error("watcher did not announce readiness before waiting for Setup to exit")
			}
			events = append(events, "parent exited")
			return nil
		}}, nil
	}
	setupRecoveryPending = func() (bool, error) { events = append(events, "pending checked"); return true, nil }
	setupRecoveryReplay = func() error { events = append(events, "replayed"); return nil }
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != 0 {
		t.Fatalf("pending uninstall recovery exit=%d: %s", code, output.String())
	}
	if want := []string{"parent opened", "parent exited", "pending checked", "replayed"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("recovery order=%v, want %v", events, want)
	}
	if !bytes.HasPrefix(output.Bytes(), []byte("READY\n")) {
		t.Fatalf("watcher did not announce readiness before replay: %q", output.String())
	}
	events = nil
	setupRecoveryPending = func() (bool, error) { events = append(events, "pending checked"); return false, nil }
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != 0 {
		t.Fatalf("committed uninstall recovery exit=%d: %s", code, output.String())
	}
	if want := []string{"parent opened", "parent exited", "pending checked"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("committed uninstall incorrectly replayed: %v", events)
	}
	events = nil
	setupRecoveryPending = func() (bool, error) { return true, nil }
	setupRecoveryReplay = func() error { return errors.New("recovery failed") }
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != enterpriseFailureExitCode {
		t.Fatalf("failed recovery exit=%d, want %d", code, enterpriseFailureExitCode)
	}
	setupRecoveryOpenParent = func(int) (standaloneSetupParent, error) { return nil, errors.New("parent handle inaccessible") }
	output.Reset()
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != enterpriseFailureExitCode ||
		bytes.Contains(output.Bytes(), []byte("READY\n")) {
		t.Fatalf("inaccessible parent announced readiness: exit=%d output=%q", code, output.String())
	}
}

type fakeStandaloneSetupParent struct{ wait func() error }

func (parent *fakeStandaloneSetupParent) Wait() error  { return parent.wait() }
func (parent *fakeStandaloneSetupParent) Close() error { return nil }

func TestStandaloneUninstallRecoveryRefusesUnbreakableJob(t *testing.T) {
	if _, err := standaloneSetupRecoveryFlagsForJob(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, nil); err == nil {
		t.Fatal("unbreakable kill-on-close job accepted; a killed Setup would kill its recovery child")
	}
	if flags, err := standaloneSetupRecoveryFlagsForJob(
		windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK, nil,
	); err != nil || flags&windows.CREATE_BREAKAWAY_FROM_JOB == 0 {
		t.Fatalf("breakaway-capable job flags=%#x error=%v", flags, err)
	}
	if _, err := standaloneSetupRecoveryFlagsForJob(0, windows.ERROR_ACCESS_DENIED); err == nil {
		t.Fatal("unknown job ownership accepted")
	}
}

func TestStandaloneUninstallRecoveryRefusesChildWithoutReadiness(t *testing.T) {
	oldFlags := setupRecoveryCreationFlags
	t.Cleanup(func() { setupRecoveryCreationFlags = oldFlags })
	setupRecoveryCreationFlags = func() (uint32, error) { return windows.DETACHED_PROCESS, nil }
	// The Go test binary has no Setup hidden recovery command. CreateProcess
	// succeeds, but the child exits without READY; the uninstall must refuse.
	if err := armStandaloneUninstallRecovery(); err == nil {
		t.Fatal("uninstall began with a child that could not run recovery")
	}
}

func TestStandaloneUninstallRecoveryRequiresRunningEnforcement(t *testing.T) {
	result := enterprisestatus.New("recover", "standalone", "windows", "1.0.4")
	result.OK = true
	result.Installed = true
	result.Services = []enterprisestatus.Service{
		{Kind: "gateway", State: "running", Required: true},
		{Kind: "guardian", State: "running", Required: true},
	}
	if err := proveStandaloneUninstallRecovery(*result); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*enterprisestatus.Result){
		func(r *enterprisestatus.Result) { r.TransactionPending = true },
		func(r *enterprisestatus.Result) { r.Installed = false },
		func(r *enterprisestatus.Result) { r.Services[0].State = "stopped" },
		func(r *enterprisestatus.Result) { r.Services[1].State = "stopped" },
	} {
		candidate := *result
		candidate.Services = append([]enterprisestatus.Service(nil), result.Services...)
		mutate(&candidate)
		if err := proveStandaloneUninstallRecovery(candidate); err == nil {
			t.Fatalf("unproven recovery accepted: %+v", candidate)
		}
	}
}
