// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The independent child waits until the uninstall parent has exited, then
// runs authenticated recovery even after pending.json was removed: hook
// finalization and state purge happen after that commit point.
func TestStandaloneUninstallRecoveryWatcher(t *testing.T) {
	oldOpen, oldNeeded, oldReplay := setupRecoveryOpenParent, setupRecoveryNeeded, setupRecoveryReplay
	t.Cleanup(func() {
		setupRecoveryOpenParent, setupRecoveryNeeded, setupRecoveryReplay = oldOpen, oldNeeded, oldReplay
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
	setupRecoveryNeeded = func() (bool, error) { events = append(events, "evidence checked"); return true, nil }
	setupRecoveryReplay = func() error { events = append(events, "replayed"); return nil }
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != 0 {
		t.Fatalf("pending uninstall recovery exit=%d: %s", code, output.String())
	}
	if want := []string{"parent opened", "parent exited", "evidence checked", "replayed"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("recovery order=%v, want %v", events, want)
	}
	if !bytes.HasPrefix(output.Bytes(), []byte("READY\n")) {
		t.Fatalf("watcher did not announce readiness before replay: %q", output.String())
	}
	events = nil
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != 0 {
		t.Fatalf("committed uninstall recovery exit=%d: %s", code, output.String())
	}
	if want := []string{"parent opened", "parent exited", "evidence checked", "replayed"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("committed uninstall skipped postcommit recovery: %v", events)
	}
	events = nil
	setupRecoveryNeeded = func() (bool, error) { events = append(events, "evidence checked"); return false, nil }
	if code := runEnterpriseSetup([]string{"--internal-recover-after-parent", "4321"}, &output, &output); code != 0 {
		t.Fatalf("settled uninstall recovery exit=%d: %s", code, output.String())
	}
	if want := []string{"parent opened", "parent exited", "evidence checked"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("settled uninstall ran unnecessary recovery: %v", events)
	}
	events = nil
	setupRecoveryNeeded = func() (bool, error) { return true, nil }
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

// Only a pending record or an unsettled tombstone starts recovery. A settled
// state-keeping uninstall keeps its tombstone; replaying it purged the state
// the administrator kept.
func TestStandaloneUninstallRecoveryNeedsPendingOrUnsettledTombstone(t *testing.T) {
	oldLayout, oldDeployment := setupRecoveryLayout, standaloneSetupDeployment
	t.Cleanup(func() { setupRecoveryLayout, standaloneSetupDeployment = oldLayout, oldDeployment })
	base := t.TempDir()
	layout := managed.StandaloneLayout{
		InstallRoot:  filepath.Join(base, "Program Files", "Cisco", "DefenseClaw"),
		LifecycleDir: filepath.Join(base, "ProgramData", "Cisco", "DefenseClaw", "install"),
	}
	if err := os.MkdirAll(layout.LifecycleDir, 0o700); err != nil {
		t.Fatal(err)
	}
	setupRecoveryLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	metadata := filepath.Join(layout.LifecycleDir, "deployment.json")
	for _, tc := range []struct {
		name   string
		state  winpath.EnterpriseDeploymentState
		record string
		root   bool
		need   bool
		err    bool
	}{
		{name: "absent", state: winpath.EnterpriseDeploymentAbsent},
		{name: "installed", state: winpath.EnterpriseDeploymentInstalled},
		{name: "settled state-keeping uninstall", state: winpath.EnterpriseDeploymentTombstone,
			record: `{"installed":false,"uninstall_purge_requested":false}`},
		{name: "settled pre-1.0.4 tombstone", state: winpath.EnterpriseDeploymentTombstone, record: `{"installed":false}`},
		{name: "state-keeping uninstall left its install root", state: winpath.EnterpriseDeploymentTombstone,
			record: `{"installed":false,"uninstall_purge_requested":false}`, root: true, need: true},
		{name: "unfinished purge", state: winpath.EnterpriseDeploymentTombstone,
			record: `{"installed":false,"uninstall_purge_requested":true}`, need: true},
		{name: "invalid recorded mode", state: winpath.EnterpriseDeploymentTombstone,
			record: `{"installed":false,"uninstall_purge_requested":"yes"}`, err: true},
		{name: "unknown", state: winpath.EnterpriseDeploymentUnknown, err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.RemoveAll(layout.InstallRoot); err != nil {
				t.Fatal(err)
			}
			if tc.root {
				if err := os.MkdirAll(layout.InstallRoot, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(metadata, []byte(tc.record), 0o600); err != nil {
				t.Fatal(err)
			}
			standaloneSetupDeployment = func() (winpath.EnterpriseDeployment, error) {
				return winpath.EnterpriseDeployment{State: tc.state, MetadataPath: metadata}, nil
			}
			needed, err := standaloneUninstallRecoveryNeeded()
			if needed != tc.need || (err != nil) != tc.err {
				t.Fatalf("recovery needed=%t error=%v, want needed=%t error=%t", needed, err, tc.need, tc.err)
			}
		})
	}
	pending := filepath.Join(layout.LifecycleDir, "pending.json")
	if err := os.WriteFile(pending, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	standaloneSetupDeployment = func() (winpath.EnterpriseDeployment, error) {
		t.Fatal("a pending record must start recovery before the deployment record is read")
		return winpath.EnterpriseDeployment{}, nil
	}
	if needed, err := standaloneUninstallRecoveryNeeded(); err == nil && !needed {
		t.Fatal("a pending transaction did not start recovery")
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
	uninstalled := *result
	uninstalled.Installed = false
	uninstalled.Services = []enterprisestatus.Service{
		{Kind: "gateway", State: "absent", Required: true},
		{Kind: "guardian", State: "absent", Required: true},
		{Kind: "enumerator", State: "absent", Required: true},
		{Kind: "sensor_helper", State: "absent", Required: true},
	}
	if err := proveStandaloneUninstallRecovery(uninstalled); err != nil {
		t.Fatalf("completed uninstall refused: %v", err)
	}
	uninstalled.Services = uninstalled.Services[:3]
	if err := proveStandaloneUninstallRecovery(uninstalled); err == nil {
		t.Fatal("uninstall without proof of absent sensor helper accepted")
	}
	uninstalled.Services = append(uninstalled.Services, enterprisestatus.Service{Kind: "sensor_helper", State: "absent", Required: true})
	uninstalled.Services[0].State = "stopped"
	if err := proveStandaloneUninstallRecovery(uninstalled); err == nil {
		t.Fatal("uninstall with a surviving gateway service accepted")
	}
}
