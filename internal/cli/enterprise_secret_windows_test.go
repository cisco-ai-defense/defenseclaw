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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/processutil"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func windowsSecretTestHarness(t *testing.T) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("the secret store is administrator-only; run elevated")
	}
	// An administrator-only directory at the root of the system drive stands
	// in for the deployment tree the gateway's credential reader trusts.
	root, err := os.MkdirTemp(os.Getenv("SystemDrive")+`\`, "dc-secret-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := applyWindowsSDDL(root, "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "secrets")
	previousAccount := windowsSecretGatewayAccount
	t.Cleanup(func() { windowsSecretGatewayAccount = previousAccount })
	// The change spool keeps its state in the lifecycle folder and its
	// events beside the config, as on an installed computer.
	layout := managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir, LifecycleDir: filepath.Join(root, "install"),
		ConfigDir: filepath.Join(root, "config"), DataDir: filepath.Join(root, "data")}
	for _, folder := range []string{layout.LifecycleDir, layout.ConfigDir, layout.DataDir} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stubWindowsSecretHost(t, layout)
	// A virtual service account that always exists stands in for the
	// gateway service.
	windowsSecretGatewayAccount = `NT SERVICE\TrustedInstaller`
	return dir
}

// windowsSecretLockEvents records what the stubbed locks and restart saw.
type windowsSecretLockEvents struct {
	events                  []string
	bundle                  time.Duration
	bundleErr, lifecycleErr error
}

type fakeWindowsSecretRecovery struct {
	armed, cancelled, recovered, finished bool
}

func (r *fakeWindowsSecretRecovery) arm() error { r.armed = true; return nil }
func (r *fakeWindowsSecretRecovery) finish(recoverGateway bool) error {
	r.finished = true
	r.cancelled = r.armed && !recoverGateway
	r.recovered = r.armed && recoverGateway
	return nil
}

func TestWindowsSecretNoopDisarmsGatewayRecovery(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	stubWindowsSecretHost(t, managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir, LifecycleDir: filepath.Join(filepath.Dir(dir), "install")})
	recovery := &fakeWindowsSecretRecovery{}
	windowsSecretSpawnRecovery = func() (windowsSecretRecoveryControl, error) { return recovery, nil }
	windowsSecretRestartGateway = func(func() error) (bool, error) { return false, nil }
	out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "absent-key", json: true}, "")
	if err != nil || !strings.Contains(out, `"gateway_restarted":false`) || !recovery.finished || recovery.armed || recovery.recovered {
		t.Fatalf("absent credential started or retained a gateway recovery: output=%q error=%v recovery=%+v", out, err, recovery)
	}
}

func TestWindowsSecretCompletedRestartCancelsGatewayRecovery(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	stubWindowsSecretHost(t, managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir, LifecycleDir: filepath.Join(filepath.Dir(dir), "install")})
	recovery := &fakeWindowsSecretRecovery{}
	windowsSecretSpawnRecovery = func() (windowsSecretRecoveryControl, error) { return recovery, nil }
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "example-key", fromStdin: true}, "test-value\n"); err != nil {
		t.Fatal(err)
	}
	if !recovery.armed || !recovery.cancelled || recovery.recovered {
		t.Fatalf("completed restart left recovery armed: %+v", recovery)
	}
	recovery = &fakeWindowsSecretRecovery{}
	windowsSecretSpawnRecovery = func() (windowsSecretRecoveryControl, error) { return recovery, nil }
	windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
		if err := beforeStop(); err != nil {
			return false, err
		}
		return false, fmt.Errorf("SCM stop: %w", errWindowsGatewayStopRefused)
	}
	if _, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "example-key"}, ""); err == nil {
		t.Fatal("SCM stop refusal was reported as a completed credential change")
	}
	if !recovery.cancelled || recovery.recovered {
		t.Fatalf("SCM stop refusal left recovery free to start an independently stopped gateway: %+v", recovery)
	}
}

// stubWindowsSecretHost points the secret verb at layout on an elevated,
// installed host whose locks and gateway restart are recorded, not taken.
func stubWindowsSecretHost(t *testing.T, layout managed.StandaloneLayout) *windowsSecretLockEvents {
	t.Helper()
	if layout.ConfigPath == "" {
		layout.ConfigPath = filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(layout.ConfigPath, []byte(standaloneGatewayCheckConfig), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	previousLayout, previousInstalled, previousElevated, previousRestart, previousRecovery, previousConfigTrusted, previousAbsentParentTrusted := windowsSecretLayout, windowsSecretDeploymentInstalled, windowsSecretIsElevated, windowsSecretRestartGateway, windowsSecretSpawnRecovery, windowsSecretConfigTrusted, windowsSecretAbsentConfigParentTrusted
	previousBundle, previousPath, previousLifecycle, previousWait, previousArgs := windowsSecretLockBundleStore, windowsSecretLifecycleLockPath, windowsSecretLifecycleLock, windowsSecretInstallerLockWait, secretRawArgs
	previousChangeSpool := windowsChangeSpool
	previousManaged := managedHostWindowsStandalone
	previousLive := windowsSecretGatewayLive
	t.Cleanup(func() {
		windowsSecretGatewayLive = previousLive
		windowsSecretLayout, windowsSecretDeploymentInstalled, windowsSecretIsElevated, windowsSecretRestartGateway, windowsSecretSpawnRecovery, windowsSecretConfigTrusted, windowsSecretAbsentConfigParentTrusted = previousLayout, previousInstalled, previousElevated, previousRestart, previousRecovery, previousConfigTrusted, previousAbsentParentTrusted
		windowsSecretLockBundleStore, windowsSecretLifecycleLockPath, windowsSecretLifecycleLock, windowsSecretInstallerLockWait, secretRawArgs = previousBundle, previousPath, previousLifecycle, previousWait, previousArgs
		windowsChangeSpool = previousChangeSpool
		managedHostWindowsStandalone = previousManaged
	})
	host := &windowsSecretLockEvents{}
	// Credential tests exercise real durable reservations while replacing
	// the installer's protected spool layout with a disposable test root.
	// A standalone command uses ConfigDir and LifecycleDir from the installed
	// deployment; most fixture layouts intentionally omit those directories.
	spoolRoot := t.TempDir()
	windowsChangeSpool = func(managed.StandaloneLayout) (enterprisestatus.ChangeSpool, error) {
		return enterprisestatus.ChangeSpool{
			Dir: filepath.Join(spoolRoot, "change-events"), StateDir: spoolRoot,
		}, nil
	}
	windowsSecretLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	windowsSecretDeploymentInstalled = func() (bool, error) { return true, nil }
	windowsSecretIsElevated = func() bool { return true }
	windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
		if err := beforeStop(); err != nil {
			return false, err
		}
		host.events = append(host.events, "restart")
		return true, nil
	}
	windowsSecretSpawnRecovery = func() (windowsSecretRecoveryControl, error) { return &fakeWindowsSecretRecovery{}, nil }
	windowsSecretGatewayLive = func() (bool, error) { return true, nil }
	windowsSecretConfigTrusted = func(string) error { return nil }
	windowsSecretAbsentConfigParentTrusted = func(string) error { return nil }
	windowsSecretLockBundleStore = func(_ context.Context, dir string, wait time.Duration) (func(), error) {
		if dir != layout.LifecycleDir {
			t.Errorf("bundle.lock taken in %q, want %q", dir, layout.LifecycleDir)
		}
		host.bundle = wait
		if host.bundleErr != nil {
			return nil, host.bundleErr
		}
		host.events = append(host.events, "lock bundle")
		return func() { host.events = append(host.events, "unlock bundle") }, nil
	}
	windowsSecretLifecycleLockPath = func() (string, error) { return `C:\stub\DefenseClaw-Lifecycle\lifecycle.lock`, nil }
	windowsSecretLifecycleLock = func(string) (func(), error) {
		if host.lifecycleErr != nil {
			return nil, host.lifecycleErr
		}
		host.events = append(host.events, "lock lifecycle")
		return func() { host.events = append(host.events, "unlock lifecycle") }, nil
	}
	secretRawArgs = func() []string { return nil }
	// The standalone marker of the computer the test runs on must not pick
	// the refusal class: a managed test host turned the unmanaged 1603
	// expectation into exit 5 (mgmt-agent-api GAP-0002). A test that wants
	// a managed computer stubs the marker itself.
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	return host
}

// GAP-0749: a restart helper must be armed before a credential is changed.
// A failed launch leaves the old value and service untouched.
func TestWindowsSecretArmsGatewayRecoveryBeforeChange(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	host := stubWindowsSecretHost(t, managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir, LifecycleDir: filepath.Join(filepath.Dir(dir), "install")})
	windowsSecretSpawnRecovery = func() (windowsSecretRecoveryControl, error) {
		host.events = append(host.events, "armed")
		return &fakeWindowsSecretRecovery{}, nil
	}
	windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
		if err := beforeStop(); err != nil {
			return false, err
		}
		host.events = append(host.events, "restart")
		if !windowsSecretStored(dir, "ai-defense-api-key") {
			t.Error("gateway restarted before the credential was stored")
		}
		return true, nil
	}
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true}, "previous-value\n"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(host.events, ","); got != "lock bundle,lock lifecycle,armed,restart,unlock lifecycle,unlock bundle" {
		t.Fatalf("recovery was not armed before restart: %s", got)
	}
	host.events = nil
	windowsSecretSpawnRecovery = func() (windowsSecretRecoveryControl, error) { return nil, errors.New("helper launch failed") }
	_, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true}, "replacement-value\n")
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("missing recovery helper did not refuse: %v", err)
	}
	if raw, readErr := os.ReadFile(filepath.Join(dir, "ai-defense-api-key")); readErr != nil || string(raw) != "previous-value" {
		t.Fatalf("failed helper launch changed credential: %q %v", raw, readErr)
	}
}

func TestWindowsSecretRecoveryRefusesUnreadyOrUnbreakableChild(t *testing.T) {
	oldStart, oldCommand := windowsSecretStartRecovery, windowsSecretRecoveryCommand
	t.Cleanup(func() { windowsSecretStartRecovery, windowsSecretRecoveryCommand = oldStart, oldCommand })
	// A job the child cannot leave: nothing starts, and the change refuses.
	started := false
	windowsSecretStartRecovery = func(*exec.Cmd) error {
		return fmt.Errorf("%w: the job kills its processes when it closes", processutil.ErrChildBoundToJob)
	}
	windowsSecretRecoveryCommand = func(executable string) *exec.Cmd {
		started = true
		return exec.Command(executable, "-test.run=^TestWindowsSecretRecoveryUnreadyHelper$")
	}
	if _, err := spawnWindowsSecretGatewayRecovery(); !errors.Is(err, processutil.ErrChildBoundToJob) || !started {
		t.Fatalf("a recovery child bound to the job was accepted: %v", err)
	}
	windowsSecretStartRecovery = func(child *exec.Cmd) error {
		child.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
		return child.Start()
	}
	windowsSecretRecoveryCommand = func(executable string) *exec.Cmd {
		child := exec.Command(executable, "-test.run=^TestWindowsSecretRecoveryUnreadyHelper$")
		child.Env = append(os.Environ(), "DC_WINDOWS_SECRET_UNREADY_HELPER=1")
		return child
	}
	// This child starts and exits without READY. The credential operation
	// must refuse even though CreateProcess succeeded.
	if _, err := spawnWindowsSecretGatewayRecovery(); err == nil {
		t.Fatal("credential change accepted an unready recovery child")
	}
}

// The finding of loop round 2: a LocalSystem caller whose process job
// cannot be inspected (a scheduled task) could not set or remove a
// credential at all. A gateway that is stopped or not installed needs no
// restart and so no recovery child: the change goes through without one. A
// gateway that starts after that check gets its child at the restart
// decision, before it is stopped; a child that cannot start there leaves the
// gateway running and the restart failed, never stopped without recovery.
func TestWindowsSecretChangeStartsRecoveryOnlyForARestart(t *testing.T) {
	for _, tc := range []struct {
		name         string
		live         bool
		liveErr      error
		raceStart    bool
		wantSpawned  bool
		wantErr      string
		wantRestart  bool
		wantValue    string
		wantArmed    bool
		spawnFailure error
	}{
		{name: "stopped gateway, unreadable job", live: false, spawnFailure: processutil.ErrChildBoundToJob, wantValue: "new-value"},
		{name: "stopped gateway", live: false, wantValue: "new-value"},
		{name: "gateway started after the check", live: false, raceStart: true, wantSpawned: true, wantRestart: true, wantArmed: true, wantValue: "new-value"},
		{name: "gateway started after the check, unreadable job", live: false, raceStart: true, spawnFailure: processutil.ErrChildBoundToJob,
			wantSpawned: true, wantErr: "restarting the gateway failed", wantValue: "new-value"},
		{name: "running gateway, unreadable job", live: true, spawnFailure: processutil.ErrChildBoundToJob, wantSpawned: true,
			wantErr: "nothing was changed", wantValue: "old-value"},
		{name: "unknown gateway state, unreadable job", liveErr: errors.New("SCM unavailable"), spawnFailure: processutil.ErrChildBoundToJob,
			wantSpawned: true, wantErr: "nothing was changed", wantValue: "old-value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := windowsSecretTestHarness(t)
			if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "example-key", fromStdin: true}, "old-value\n"); err != nil {
				t.Fatal(err)
			}
			spawned, stopped := false, false
			recovery := &fakeWindowsSecretRecovery{}
			windowsSecretGatewayLive = func() (bool, error) { return tc.live, tc.liveErr }
			windowsSecretSpawnRecovery = func() (windowsSecretRecoveryControl, error) {
				spawned = true
				if tc.spawnFailure != nil {
					return nil, tc.spawnFailure
				}
				return recovery, nil
			}
			windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
				if !tc.live && !tc.raceStart && tc.liveErr == nil {
					return false, nil // stopped: no restart decision
				}
				if err := beforeStop(); err != nil {
					return false, err
				}
				stopped = true
				return true, nil
			}
			_, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "example-key", fromStdin: true}, "new-value\n")
			if tc.wantErr == "" && err != nil || tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
			if spawned != tc.wantSpawned || stopped != tc.wantRestart || recovery.armed != tc.wantArmed {
				t.Fatalf("spawned=%v stopped=%v armed=%v, want %v %v %v", spawned, stopped, recovery.armed, tc.wantSpawned, tc.wantRestart, tc.wantArmed)
			}
			if tc.wantArmed && (!recovery.cancelled || recovery.recovered) {
				t.Fatalf("a completed restart left its recovery armed: %+v", recovery)
			}
			if raw, readErr := os.ReadFile(filepath.Join(dir, "example-key")); readErr != nil || string(raw) != tc.wantValue {
				t.Fatalf("credential = %q %v, want %q", raw, readErr, tc.wantValue)
			}
		})
	}
}

func TestWindowsSecretRecoveryUnreadyHelper(t *testing.T) {
	if os.Getenv("DC_WINDOWS_SECRET_UNREADY_HELPER") == "1" {
		os.Exit(0)
	}
}

// GAP-0750: a missing or malformed config is an unproven policy, not proof
// that no reference exists. Refuse before reserving an audit row or deleting
// the credential, and leave the gateway running on its previous value.
func TestWindowsSecretRemoveRefusesUnprovenInstalledConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		body *string
	}{
		{name: "missing"},
		{name: "malformed", body: func() *string { s := "guardrail: [\n"; return &s }()},
		{name: "untrusted", body: func() *string { s := standaloneGatewayCheckConfig; return &s }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := windowsSecretTestHarness(t)
			if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true}, "saved-value\n"); err != nil {
				t.Fatal(err)
			}
			layout, err := windowsSecretLayout()
			if err != nil {
				t.Fatal(err)
			}
			if tc.body == nil {
				if err := os.Remove(layout.ConfigPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(layout.ConfigPath, []byte(*tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if tc.name == "untrusted" {
				windowsSecretConfigTrusted = func(string) error { return errors.New("config ACL drift") }
			}
			restarted := false
			windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
				if err := beforeStop(); err != nil {
					return false, err
				}
				restarted = true
				return true, nil
			}
			out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key", json: true}, "")
			windowsSecretFailureDoc(t, out, err, "remove", "state_invalid")
			if !windowsSecretStored(dir, "ai-defense-api-key") || restarted {
				t.Fatalf("unproven config changed credential or gateway: stored=%t restarted=%t", windowsSecretStored(dir, "ai-defense-api-key"), restarted)
			}
		})
	}
}

// GAP-0750 (TST-30694): a config whose DACL denies the caller read is
// refused even when the caller's token has SeBackupPrivilege enabled, which
// let os.ReadFile read past the deny; the credential stays and the gateway is
// not restarted.
func TestWindowsSecretRemoveRefusesAConfigItsDACLDeniesEvenWithBackupPrivilege(t *testing.T) {
	restore, ok := enableWindowsTestProcessPrivilege(t, "SeBackupPrivilege")
	if !ok {
		t.Skip("the test token cannot enable SeBackupPrivilege (not elevated)")
	}
	defer restore()
	dir := windowsSecretTestHarness(t)
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true}, "saved-value\n"); err != nil {
		t.Fatal(err)
	}
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{user.User.Sid.String(), "S-1-5-32-544"} {
		if out, err := exec.Command("icacls", layout.ConfigPath, "/deny", "*"+sid+":(R)").CombinedOutput(); err != nil {
			t.Fatalf("icacls deny: %v: %s", err, out)
		}
	}
	t.Cleanup(func() { _ = exec.Command("icacls", layout.ConfigPath, "/reset").Run() })
	restarted := false
	windowsSecretRestartGateway = func(func() error) (bool, error) { restarted = true; return true, nil }
	out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key", json: true}, "")
	windowsSecretFailureDoc(t, out, err, "remove", "state_invalid")
	if !windowsSecretStored(dir, "ai-defense-api-key") || restarted {
		t.Fatalf("a config the caller cannot read changed the credential or the gateway: stored=%t restarted=%t", windowsSecretStored(dir, "ai-defense-api-key"), restarted)
	}
}

// GAP-0712, GAP-1690: an identical set and the removal of an absent
// credential restart the gateway only when it may hold another value: when
// it started before that credential last changed. Otherwise they are no-ops
// with no restart, and an absent removal says so.
func TestWindowsSecretUnchangedCredentialRestartsOnlyAGatewayThatMayHoldAnotherValue(t *testing.T) {
	for _, tc := range []struct {
		name         string
		action       string
		startedAfter bool
		wantRestart  bool
		wantText     string
		noStore      bool
	}{
		{name: "identical set, gateway loaded it", action: "set", startedAfter: true, wantText: "already holds this value; gateway restart not needed"},
		{name: "identical set, older gateway", action: "set", wantRestart: true},
		{name: "absent remove, gateway loaded the store", action: "remove", startedAfter: true, wantText: "was not stored; nothing to remove"},
		{name: "absent remove, older gateway", action: "remove", wantRestart: true, wantText: "was not stored; nothing to remove; gateway restarted: true"},
		// No credential was ever stored, so no store folder exists: the
		// folder that would hold it dates the last change (GAP-1690).
		{name: "absent remove, no store folder, gateway started after", action: "remove", noStore: true, startedAfter: true, wantText: "was not stored; nothing to remove"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			windowsSecretTestHarness(t)
			name := "absent-key"
			stored := "other-key" // the store exists, without the removed key
			if tc.action == "set" {
				name, stored = "ai-defense-api-key", "ai-defense-api-key"
			}
			if !tc.noStore {
				if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: stored, fromStdin: true}, "same-value\n"); err != nil {
					t.Fatal(err)
				}
			}
			saved := windowsSecretGatewayStartedAfter
			t.Cleanup(func() { windowsSecretGatewayStartedAfter = saved })
			var changedAt time.Time
			windowsSecretGatewayStartedAfter = func(at time.Time) bool { changedAt = at; return tc.startedAfter }
			restarted := false
			windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
				if err := beforeStop(); err != nil {
					return false, err
				}
				restarted = true
				return true, nil
			}
			stdin := ""
			opts := enterpriseSecretOptions{name: name}
			if tc.action == "set" {
				opts.fromStdin, stdin = true, "same-value\n"
			}
			out, err := runWindowsSecretCommand(t, tc.action, opts, stdin)
			if err != nil {
				t.Fatalf("%s: %v", tc.action, err)
			}
			if changedAt.IsZero() {
				t.Fatal("the last change of the credential was not read")
			}
			if restarted != tc.wantRestart || (tc.wantText != "" && !strings.Contains(out, tc.wantText)) {
				t.Fatalf("restarted=%t (want %t) output=%q (want %q)", restarted, tc.wantRestart, out, tc.wantText)
			}
		})
	}
}

// enableWindowsTestProcessPrivilege enables privilege on the test process
// token and returns the restore; false when the token does not hold it.
func enableWindowsTestProcessPrivilege(t *testing.T, privilege string) (func(), bool) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return nil, false
	}
	name, err := windows.UTF16PtrFromString(privilege)
	var luid windows.LUID
	if err == nil {
		err = windows.LookupPrivilegeValue(nil, name, &luid)
	}
	if err != nil {
		token.Close()
		return nil, false
	}
	state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
	var previous windows.Tokenprivileges
	var size uint32
	if err := windows.AdjustTokenPrivileges(token, false, &state, uint32(unsafe.Sizeof(previous)), &previous, &size); err != nil ||
		errors.Is(windows.GetLastError(), windows.ERROR_NOT_ALL_ASSIGNED) {
		token.Close()
		return nil, false
	}
	return func() {
		_ = windows.AdjustTokenPrivileges(token, false, &previous, 0, nil, nil)
		token.Close()
	}, true
}

func runWindowsSecretCommand(t *testing.T, action string, opts enterpriseSecretOptions, stdin string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader(stdin))
	err := runEnterpriseSecret(cmd, action, &opts)
	return out.String(), err
}

func TestWindowsSecretStoreUsesTheGatewayReaderDACL(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	const value = "aid-test-key-0123456789"
	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, value+"\r\n")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil || result["ok"] != true || result["gateway_restarted"] != true {
		t.Fatalf("set result %s (%v)", out, err)
	}

	path := filepath.Join(dir, "ai-defense-api-key")
	extended, _ := winpath.Extended(path)
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, _ := sd.Control()
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the credential DACL inherits from its parent")
	}
	dacl, _, _ := sd.DACL()
	gateway, _ := managed.WindowsServiceAccountSID(windowsSecretGatewayAccount)
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	seen := map[string]windows.ACCESS_MASK{}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		seen[sid.String()] = ace.Mask
	}
	if len(seen) != 3 || seen[system.String()] == 0 || seen[admins.String()] == 0 || seen[gateway.String()] == 0 {
		t.Fatalf("credential DACL principals %v", seen)
	}
	if seen[gateway.String()]&(windows.FILE_WRITE_DATA|windows.DELETE|windows.WRITE_DAC) != 0 {
		t.Fatalf("the gateway SID may modify the credential: %#x", seen[gateway.String()])
	}

	// The directory grants the gateway SID exactly what its trust walk
	// needs on the directory itself: READ_CONTROL, SYNCHRONIZE,
	// FILE_READ_ATTRIBUTES and FILE_TRAVERSE, not inherited by files.
	dirACEs := windowsSecretTestACEs(t, dir)
	if len(dirACEs) != 3 {
		t.Fatalf("secrets directory DACL principals %v", dirACEs)
	}
	for _, sid := range []*windows.SID{system, admins} {
		ace, ok := dirACEs[sid.String()]
		if !ok || ace.flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE {
			t.Fatalf("secrets directory ACE for %s = %+v, want an inherited full-control ACE", sid, ace)
		}
	}
	reader, ok := dirACEs[gateway.String()]
	if !ok {
		t.Fatalf("secrets directory DACL has no ACE for the gateway SID %s: the gateway cannot read the directory's security descriptor", gateway)
	}
	const wantReaderAccess = windows.READ_CONTROL | windows.SYNCHRONIZE | windows.FILE_READ_ATTRIBUTES | windows.FILE_TRAVERSE
	if reader.mask != wantReaderAccess || reader.flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE|windows.INHERIT_ONLY_ACE) != 0 {
		t.Fatalf("gateway directory ACE = mask %#x flags %#x, want mask %#x and no inheritance", uint32(reader.mask), reader.flags, uint32(wantReaderAccess))
	}

	t.Setenv(managed.WindowsServiceAccountEnv, windowsSecretGatewayAccount)
	got, source, err := managed.ResolveServiceCredential("ai-defense-api-key", dir)
	if err != nil || string(got) != value || source != managed.CredentialFromFile {
		t.Fatalf("the gateway reader rejected the stored credential: %q %s %v", got, source, err)
	}

	status, err := runWindowsSecretCommand(t, "status", enterpriseSecretOptions{json: true}, "")
	if err != nil || !strings.Contains(status, `"ai-defense-api-key"`) || strings.Contains(status, value) {
		t.Fatalf("status %s %v", status, err)
	}
	if _, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key"}, ""); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("credential still present: %v", err)
	}
}

// GAP-1507: remove deleted a credential and restarted the gateway when it
// could not read the installed config, which may still reference it.
func TestWindowsSecretRemoveRefusesAnUnreadableConfig(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true}, "remove-guard-value\n"); err != nil {
		t.Fatalf("set: %v", err)
	}
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	// A folder in the config's place cannot be read as the config.
	layout.ConfigPath = t.TempDir()
	windowsSecretLayout = func() (managed.StandaloneLayout, error) { return layout, nil }
	restarted := false
	windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
		if err := beforeStop(); err != nil {
			return false, err
		}
		restarted = true
		return true, nil
	}
	_, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key"}, "")
	if err == nil || !strings.Contains(err.Error(), "cannot read the installed config") || !strings.Contains(err.Error(), "nothing was removed") {
		t.Fatalf("remove with an unreadable config: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "ai-defense-api-key")); statErr != nil {
		t.Fatalf("credential removed despite the unreadable config: %v", statErr)
	}
	if restarted {
		t.Fatal("gateway restarted after a refused remove")
	}
	out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key", json: true}, "")
	windowsSecretFailureDoc(t, out, err, "remove", "state_invalid")
}

func TestWindowsSecretRefusals(t *testing.T) {
	windowsSecretTestHarness(t)
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "../escape", fromStdin: true}, "x"); err == nil || commandExitCode(err) != windowsSecretExitInvalid {
		t.Fatalf("an unsafe name must be refused with 1639, got %v", err)
	}
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ok-name", fromStdin: true}, "two\nlines"); err == nil {
		t.Fatal("a multi-line credential must be refused")
	}
	windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil }
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ok-name", fromStdin: true}, "x"); err == nil {
		t.Fatal("set without a standalone deployment must be refused")
	}
	windowsSecretIsElevated = func() bool { return false }
	// Without the standalone marker a standard account gets 1603
	// elevation_required (management-agent.md 4.7).
	if _, err := runWindowsSecretCommand(t, "status", enterpriseSecretOptions{}, ""); err == nil || commandExitCode(err) != windowsSecretExitFailure {
		t.Fatalf("a non-elevated token on a computer without the standalone marker must be refused with 1603, got %v (exit %d)", err, commandExitCode(err))
	}
	// GAP-0931: on a managed computer a standard account gets exit 5
	// elevation_required and the command to ask for, like every other
	// enterprise refusal there.
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, true }
	_, err := runWindowsSecretCommand(t, "status", enterpriseSecretOptions{}, "")
	var refusal *managedViewRefusal
	if err == nil || commandExitCode(err) != 5 || !errors.As(err, &refusal) || refusal.code != "elevation_required" ||
		!strings.Contains(err.Error(), "enterprise secret status") {
		t.Fatalf("a standard account on a managed computer: %v (exit %d)", err, commandExitCode(err))
	}
}

// windowsSecretFailureDoc decodes stdout as exactly one failure document of
// secret-result.schema.json and checks its shape against err.
func windowsSecretFailureDoc(t *testing.T, out string, err error, action, code string) secretFailureResult {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(out))
	dec.DisallowUnknownFields()
	var doc secretFailureResult
	if decodeErr := dec.Decode(&doc); decodeErr != nil {
		t.Fatalf("stdout is not one failure document: %v\n%s", decodeErr, out)
	}
	if dec.More() {
		t.Fatalf("stdout holds more than one document:\n%s", out)
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal([]byte(out), &keys)
	for key := range keys {
		switch key {
		case "schema_version", "ok", "action", "name", "gateway_restarted", "errors", "exit_code":
		default:
			t.Fatalf("failure document has %q: %s", key, out)
		}
	}
	allowed := map[string]bool{"elevation_required": true, "invalid_arguments": true, "not_installed": true, "lifecycle_busy": true,
		"credential_in_use": true, "credential_changed": true, "change_failed": true, "restart_failed": true, "state_invalid": true, "not_supported_secure_client": true,
		"rotation_confirmed": true, "confirmed_bundle_changed": true}
	exit := commandExitCode(err)
	if doc.SchemaVersion != 1 || doc.OK || doc.Action != action || doc.GatewayRestarted || len(doc.Errors) != 1 ||
		doc.Errors[0].Code != code || !allowed[doc.Errors[0].Code] || doc.Errors[0].Message == "" || doc.ExitCode != exit {
		t.Fatalf("failure document %+v for exit %d, want action %s code %s", doc, exit, action, code)
	}
	switch exit {
	case enterprisestatus.WindowsExitAccessDenied, windowsSecretExitFailure, enterprisestatus.WindowsExitBusy, windowsSecretExitInvalid:
	default:
		t.Fatalf("exit %d is not a Windows secret exit code", exit)
	}
	return doc
}

// A5: every set and remove failure before the write prints one document,
// with the matching exit code, and never the value.
func TestWindowsSecretFailuresPrintOneDocument(t *testing.T) {
	const value = "s3cr3t-value-never-printed"
	for _, tc := range []struct {
		name   string
		action string
		opts   enterpriseSecretOptions
		stdin  string
		setup  func(*windowsSecretLockEvents)
		code   string
		exit   int
	}{
		{name: "bad name", action: "set", opts: enterpriseSecretOptions{name: "../escape", fromStdin: true}, stdin: value, code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "no source", action: "set", opts: enterpriseSecretOptions{name: "ok-name"}, code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "two lines", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true}, stdin: value + "\nmore", code: "invalid_arguments", exit: windowsSecretExitInvalid},
		// mgmt-agent-api GAP-0031 parity: a stdin closed with no value (the
		// agent stopped) and a blank line are one invalid_arguments document.
		{name: "closed stdin, empty value", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true}, stdin: "", code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "blank line", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true}, stdin: " \r\n", code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "lock wait over 15m", action: "remove", opts: enterpriseSecretOptions{name: "ok-name", lockWait: 16 * time.Minute}, code: "invalid_arguments", exit: windowsSecretExitInvalid},
		{name: "not installed", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true}, stdin: value, code: "not_installed", exit: windowsSecretExitFailure,
			setup: func(*windowsSecretLockEvents) {
				windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil }
			}},
		{name: "bundle lock busy", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true, lockWait: time.Second}, stdin: value, code: "lifecycle_busy", exit: enterprisestatus.WindowsExitBusy,
			setup: func(h *windowsSecretLockEvents) { h.bundleErr = errWindowsBundleStoreBusy }},
		{name: "bundle lock broken", action: "remove", opts: enterpriseSecretOptions{name: "ok-name"}, code: "state_invalid", exit: windowsSecretExitFailure,
			setup: func(h *windowsSecretLockEvents) { h.bundleErr = errors.New("access denied") }},
		{name: "lifecycle lock busy", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true}, stdin: value, code: "lifecycle_busy", exit: enterprisestatus.WindowsExitBusy,
			setup: func(h *windowsSecretLockEvents) { h.lifecycleErr = windows.ERROR_SHARING_VIOLATION }},
		{name: "lifecycle lock missing", action: "remove", opts: enterpriseSecretOptions{name: "ok-name"}, code: "state_invalid", exit: windowsSecretExitFailure,
			setup: func(h *windowsSecretLockEvents) { h.lifecycleErr = errors.New("lifecycle lock is not a regular file") }},
		{name: "standard user, managed", action: "set", opts: enterpriseSecretOptions{name: "ok-name", fromStdin: true}, stdin: value, code: "elevation_required", exit: enterprisestatus.WindowsExitAccessDenied,
			setup: func(*windowsSecretLockEvents) {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, true }
			}},
		{name: "standard user, unmanaged", action: "remove", opts: enterpriseSecretOptions{name: "ok-name"}, code: "elevation_required", exit: windowsSecretExitFailure,
			setup: func(*windowsSecretLockEvents) {
				windowsSecretIsElevated = func() bool { return false }
				managedHostWindowsStandalone = func() (string, bool) { return "", false }
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secrets := filepath.Join(t.TempDir(), "secrets")
			host := stubWindowsSecretHost(t, managed.StandaloneLayout{GOOS: "windows", SecretsDir: secrets, LifecycleDir: t.TempDir()})
			restoreManaged, restoreWait := managedHostWindowsStandalone, windowsSecretInstallerLockWait
			t.Cleanup(func() { managedHostWindowsStandalone, windowsSecretInstallerLockWait = restoreManaged, restoreWait })
			windowsSecretInstallerLockWait = 50 * time.Millisecond
			if tc.setup != nil {
				tc.setup(host)
			}
			opts := tc.opts
			opts.json = true
			out, err := runWindowsSecretCommand(t, tc.action, opts, tc.stdin)
			if commandExitCode(err) != tc.exit {
				t.Fatalf("exit %d (%v), want %d", commandExitCode(err), err, tc.exit)
			}
			doc := windowsSecretFailureDoc(t, out, err, tc.action, tc.code)
			if doc.Name != tc.opts.name {
				t.Fatalf("name %q, want %q as given", doc.Name, tc.opts.name)
			}
			if strings.Contains(out, value) || strings.Contains(err.Error(), value) {
				t.Fatal("the credential value was printed")
			}
			if _, statErr := os.Stat(secrets); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("a refused %s touched the credential store: %v", tc.action, statErr)
			}
			for _, event := range host.events {
				if event == "restart" {
					t.Fatal("the gateway restarted after a refusal")
				}
			}
			// A lock taken before a refusal is released.
			if len(host.events)%2 != 0 {
				t.Fatalf("locks left held: %v", host.events)
			}
			// Text mode keeps the plain error and prints nothing on stdout.
			opts.json = false
			if tc.setup != nil {
				tc.setup(host)
			}
			if out, err := runWindowsSecretCommand(t, tc.action, opts, tc.stdin); out != "" || commandExitCode(err) != tc.exit {
				t.Fatalf("text mode: exit %d, stdout %q", commandExitCode(err), out)
			}
		})
	}
}

// A5: a flag error exits 1639 and, when the command line asks for --json
// anywhere, prints the failure document; cobra stops parsing at the bad flag.
func TestWindowsSecretFlagErrorsPrintTheFailureDocument(t *testing.T) {
	stubWindowsSecretHost(t, managed.StandaloneLayout{GOOS: "windows", SecretsDir: filepath.Join(t.TempDir(), "secrets"), LifecycleDir: t.TempDir()})
	for _, tc := range []struct {
		args []string
		json bool
	}{
		{args: []string{"--bogus", "--json"}, json: true},
		{args: []string{"--json", "--bogus"}, json: true},
		{args: []string{"--name", "ok-name", "--lock-wait", "soon", "--json"}, json: true},
		{args: []string{"--name", "ok-name", "--from-stdin", "--json", "extra"}, json: true},
		{args: []string{"--from-stdin", "--json"}, json: true},
		{args: []string{"--bogus", "--json=false"}},
		{args: []string{"--bogus"}},
		{args: []string{"--bogus", "--", "--json"}},
	} {
		cmd := newEnterpriseSecretCommand("set", "Store a protected credential and apply it")
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		cmd.SetIn(strings.NewReader(""))
		cmd.SetArgs(tc.args)
		secretRawArgs = func() []string { return tc.args }
		err := cmd.Execute()
		if commandExitCode(err) != windowsSecretExitInvalid {
			t.Fatalf("%v: exit %d (%v), want 1639", tc.args, commandExitCode(err), err)
		}
		if !tc.json {
			if out.Len() != 0 {
				t.Fatalf("%v printed %q without --json", tc.args, out.String())
			}
			continue
		}
		windowsSecretFailureDoc(t, out.String(), err, "set", "invalid_arguments")
	}
	if cmd := newEnterpriseSecretCommand("set", "x"); !strings.Contains(cmd.Flags().Lookup("lock-wait").Usage, "bundle.lock") {
		t.Fatalf("Windows --lock-wait help: %q", cmd.Flags().Lookup("lock-wait").Usage)
	}
}

// A5: set and remove take bundle.lock (with --lock-wait), then
// lifecycle.lock, and change the credential and restart the gateway under
// both. A byte-identical value is not rewritten, but a running gateway still
// restarts (nothing proves the value it loaded); with no running gateway it
// is a no-op.
func TestWindowsSecretChangesUnderBothLocks(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	host := stubWindowsSecretHost(t, layout)
	written := false
	windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
		if err := beforeStop(); err != nil {
			return false, err
		}
		_, statErr := os.Stat(filepath.Join(dir, "ai-defense-api-key"))
		written = statErr == nil
		host.events = append(host.events, "restart")
		return true, nil
	}
	want := []string{"lock bundle", "lock lifecycle", "restart", "unlock lifecycle", "unlock bundle"}
	storedPath := filepath.Join(dir, "ai-defense-api-key")
	// The repeat models an administrator who repaired the file ACL after
	// the gateway started without the credential: same bytes, an old
	// preserved timestamp. The running gateway must restart, and the file
	// must not be rewritten.
	preserved := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	for i := 0; i < 2; i++ {
		host.events = nil
		out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true, lockWait: 10 * time.Minute}, "same-value\n")
		if err != nil {
			t.Fatalf("set %d: %v", i, err)
		}
		if out != `{"action":"set","gateway_restarted":true,"name":"ai-defense-api-key","ok":true,"schema_version":1}`+"\n" {
			t.Fatalf("set %d: success document changed: %q", i, out)
		}
		if strings.Join(host.events, ",") != strings.Join(want, ",") || host.bundle != 10*time.Minute || !written {
			t.Fatalf("set %d: events %v, bundle wait %s, written before restart %v", i, host.events, host.bundle, written)
		}
		if i == 0 {
			if err := os.Chtimes(storedPath, preserved, preserved); err != nil {
				t.Fatal(err)
			}
		} else if info, err := os.Stat(storedPath); err != nil || !info.ModTime().Equal(preserved) {
			t.Fatalf("identical value was rewritten: %v, %v", info, err)
		}
	}
	// No running gateway (stopped or not installed): the identical value is
	// a no-op and the next start reads the stored file.
	host.events = nil
	windowsSecretRestartGateway = func(func() error) (bool, error) {
		host.events = append(host.events, "restart")
		return false, nil
	}
	if out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, "same-value\n"); err != nil ||
		out != `{"action":"set","gateway_restarted":false,"name":"ai-defense-api-key","ok":true,"schema_version":1}`+"\n" {
		t.Fatalf("stopped gateway identical set: %q, %v", out, err)
	}
	if info, err := os.Stat(storedPath); err != nil || !info.ModTime().Equal(preserved) {
		t.Fatalf("identical value was rewritten for a stopped gateway: %v, %v", info, err)
	}
	windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
		if err := beforeStop(); err != nil {
			return false, err
		}
		_, statErr := os.Stat(storedPath)
		written = statErr == nil
		host.events = append(host.events, "restart")
		return true, nil
	}
	// The gateway reader trims whitespace, but an on-disk byte difference
	// still rewrites the credential and restarts the service.
	if err := os.WriteFile(storedPath, []byte("same-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host.events = nil
	if out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, "same-value\n"); err != nil || !strings.Contains(out, `"gateway_restarted":true`) {
		t.Fatalf("byte-different set: %q, %v", out, err)
	}
	if data, err := os.ReadFile(storedPath); err != nil || string(data) != "same-value" || strings.Join(host.events, ",") != strings.Join(want, ",") {
		t.Fatalf("byte-different value was not rewritten and restarted: %v, %v", err, host.events)
	}
	host.events = nil
	if _, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key", json: true}, ""); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if strings.Join(host.events, ",") != strings.Join(want, ",") || host.bundle != 0 || written {
		t.Fatalf("remove: events %v, bundle wait %s, present at restart %v", host.events, host.bundle, written)
	}

	// The credential was stored, the restart failed: restart_failed, and
	// the value is not printed.
	windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
		if err := beforeStop(); err != nil {
			return false, err
		}
		return false, errors.New("service did not start")
	}
	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, "rotated-value")
	windowsSecretFailureDoc(t, out, err, "set", "restart_failed")
	if strings.Contains(out, "rotated-value") || !strings.Contains(err.Error(), "credential ai-defense-api-key stored") {
		t.Fatalf("restart failure: %v %s", err, out)
	}
}

// An uninstall that finishes while the change waits for lifecycle.lock
// leaves no deployment: the change refuses not_installed (1603) under both
// locks, writes nothing and restarts nothing.
func TestWindowsSecretRechecksTheDeploymentUnderTheLocks(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	host := stubWindowsSecretHost(t, layout)
	for _, action := range []string{"set", "remove"} {
		t.Run(action, func(t *testing.T) {
			host.events = nil
			windowsSecretDeploymentInstalled = func() (bool, error) { return true, nil }
			windowsSecretLifecycleLock = func(string) (func(), error) {
				// The uninstall held lifecycle.lock and finished.
				windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil }
				host.events = append(host.events, "lock lifecycle")
				return func() { host.events = append(host.events, "unlock lifecycle") }, nil
			}
			stored := filepath.Join(dir, "ai-defense-api-key")
			if action == "remove" {
				// The refused remove must leave a stored credential as it was.
				// The refused set before it created no secrets folder.
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(stored, []byte("kept-value"), 0o600); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Remove(stored) })
			}
			opts := enterpriseSecretOptions{name: "ai-defense-api-key", json: true, fromStdin: action == "set"}
			out, err := runWindowsSecretCommand(t, action, opts, "late-value")
			windowsSecretFailureDoc(t, out, err, action, "not_installed")
			kept, readErr := os.ReadFile(stored)
			if action == "set" && !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("stored after the deployment was removed: %v", readErr)
			}
			if action == "remove" && (readErr != nil || string(kept) != "kept-value") {
				t.Fatalf("remove changed the credential after the deployment was removed: %q, %v", kept, readErr)
			}
			if want := "lock bundle,lock lifecycle,unlock lifecycle,unlock bundle"; strings.Join(host.events, ",") != want {
				t.Fatalf("events %v, want %s (no restart)", host.events, want)
			}
		})
	}
}

// A5: bundle.lock held by another bundle run (a second handle in this
// process) is lifecycle_busy 1618 without --lock-wait, and waits with it.
func TestWindowsSecretWaitsForTheRealBundleLock(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	lifecycleDir := filepath.Join(filepath.Dir(dir), "install")
	stubWindowsSecretHost(t, managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir, LifecycleDir: lifecycleDir})
	savedEnsure, savedPublish := windowsBundleEnsurePrivateDirectory, windowsBundlePublishPrivateFile
	t.Cleanup(func() {
		windowsBundleEnsurePrivateDirectory, windowsBundlePublishPrivateFile = savedEnsure, savedPublish
	})
	windowsBundleEnsurePrivateDirectory = func(path string) error { return os.MkdirAll(path, 0o700) }
	windowsBundlePublishPrivateFile = func(string) error { return nil }
	windowsSecretLockBundleStore = lockWindowsBundleStoreWithin
	unlock, err := lockWindowsBundleStore(lifecycleDir)
	if err != nil {
		t.Fatal(err)
	}
	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, "held-value")
	windowsSecretFailureDoc(t, out, err, "set", "lifecycle_busy")
	if _, statErr := os.Stat(filepath.Join(dir, "ai-defense-api-key")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("stored while bundle.lock was held: %v", statErr)
	}
	go func() { time.Sleep(300 * time.Millisecond); unlock() }()
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true, lockWait: 30 * time.Second}, "held-value"); err != nil {
		t.Fatalf("--lock-wait 30s with bundle.lock freed after 300ms: %v", err)
	}
}

func TestWindowsArgsRequestJSON(t *testing.T) {
	for args, want := range map[string]bool{
		"--json": true, "--name x --json": true, "--json=true": true, "--json=1": true,
		"--json=false": false, "--json=maybe": false, "": false, "-- --json": false, "--jsonx": false,
	} {
		if got := secretArgsRequestJSON(strings.Fields(args)); got != want {
			t.Fatalf("%q: %v, want %v", args, got, want)
		}
	}
}

type windowsSecretTestACE struct {
	mask  windows.ACCESS_MASK
	flags uint8
}

// windowsSecretTestACEs returns the allow ACEs of path's DACL by SID.
func windowsSecretTestACEs(t *testing.T, path string) map[string]windowsSecretTestACE {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no DACL: %v", path, err)
	}
	aces := map[string]windowsSecretTestACE{}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("%s: unexpected ACE type %#x", path, ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		aces[sid.String()] = windowsSecretTestACE{mask: ace.Mask, flags: ace.Header.AceFlags}
	}
	return aces
}

// windowsSecretTestJunction makes link a junction to target.
func windowsSecretTestJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J %s %s: %v: %s", link, target, err, out)
	}
}

// GAP-1314, GAP-1315: with a junction or a file where the secrets folder
// belongs, set, remove and status each print one state_invalid document,
// exit 1603 and restart nothing, and the junction, its target and the
// credential the target holds stay as they were. Remove deleted that
// credential through the junction and reported success; set reported
// change_failed.
func TestWindowsSecretVerbsRefuseAStoreThatIsNotARealDirectory(t *testing.T) {
	const name, kept = "ai-defense-api-key", "kept-elsewhere"
	for _, kind := range []string{"junction", "file"} {
		for _, action := range []string{"set", "remove", "status"} {
			t.Run(kind+"_"+action, func(t *testing.T) {
				root := t.TempDir()
				dir, target := filepath.Join(root, "secrets"), filepath.Join(root, "elsewhere")
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, name), []byte(kept), 0o600); err != nil {
					t.Fatal(err)
				}
				if kind == "junction" {
					windowsSecretTestJunction(t, dir, target)
				} else if err := os.WriteFile(dir, []byte(kept), 0o600); err != nil {
					t.Fatal(err)
				}
				host := stubWindowsSecretHost(t, managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir, LifecycleDir: filepath.Join(root, "install")})
				opts := enterpriseSecretOptions{name: name, fromStdin: action == "set", json: true}
				if action == "status" {
					opts = enterpriseSecretOptions{json: true}
				}
				out, err := runWindowsSecretCommand(t, action, opts, "new-value\n")
				doc := windowsSecretFailureDoc(t, out, err, action, "state_invalid")
				if commandExitCode(err) != windowsSecretExitFailure || !strings.Contains(doc.Errors[0].Message, "is not a real directory") {
					t.Fatalf("exit %d, %+v; want 1603 and not a real directory", commandExitCode(err), doc)
				}
				if strings.Contains(out, "new-value") || strings.Contains(out, kept) {
					t.Fatalf("output carries a value: %s", out)
				}
				for _, event := range host.events {
					if event == "restart" {
						t.Fatal("gateway restarted after a refused change")
					}
				}
				if got, err := os.ReadFile(filepath.Join(target, name)); err != nil || string(got) != kept {
					t.Fatalf("the credential outside the store changed: %q %v", got, err)
				}
				if entries, err := os.ReadDir(target); err != nil || len(entries) != 1 {
					t.Fatalf("the junction target holds %v (%v), want only %s", entries, err, name)
				}
				if kind == "file" {
					if got, err := os.ReadFile(dir); err != nil || string(got) != kept {
						t.Fatalf("the file in the place of the store changed: %q %v", got, err)
					}
				} else if info, err := os.Lstat(dir); err != nil || info.Mode().Type() == os.ModeDir {
					t.Fatalf("the junction is gone or became a folder: %v %v", info, err)
				}
				if windowsSecretStored(dir, name) {
					t.Fatal("a credential behind a store that is not a real directory counts as stored")
				}
			})
		}
	}
}

// In a real folder remove deletes only the named credential, a link named
// like a credential is removed itself and never its target, a folder of that
// name is refused, and a credential that is not there is not an error.
func TestWindowsSecretRemoveStaysInsideTheRealFolder(t *testing.T) {
	root := t.TempDir()
	dir, target := filepath.Join(root, "secrets"), filepath.Join(root, "elsewhere")
	for _, folder := range []string{dir, target, filepath.Join(dir, "a-folder")} {
		if err := os.Mkdir(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for path, value := range map[string]string{
		filepath.Join(dir, "ai-defense-api-key"): "one",
		filepath.Join(dir, "other-key"):          "two",
		filepath.Join(target, "llm-key"):         "outside",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	windowsSecretTestJunction(t, filepath.Join(dir, "llm-key"), target)
	// The change spool keeps its state in the lifecycle folder and its
	// events beside the config, as on an installed computer.
	layout := managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir, LifecycleDir: filepath.Join(root, "install"),
		ConfigDir: filepath.Join(root, "config"), DataDir: filepath.Join(root, "data")}
	for _, folder := range []string{layout.LifecycleDir, layout.ConfigDir, layout.DataDir} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stubWindowsSecretHost(t, layout)
	for _, name := range []string{"ai-defense-api-key", "llm-key", "never-stored"} {
		out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: name, json: true}, "")
		if err != nil || !strings.Contains(out, `"ok":true`) {
			t.Fatalf("remove %s: %v %s", name, err, out)
		}
		if _, err := os.Lstat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s is still in the store: %v", name, err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(target, "llm-key")); err != nil || string(got) != "outside" {
		t.Fatalf("removing the link llm-key changed its target: %q %v", got, err)
	}
	out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "a-folder", json: true}, "")
	windowsSecretFailureDoc(t, out, err, "remove", "change_failed")
	if info, err := os.Lstat(filepath.Join(dir, "a-folder")); err != nil || !info.IsDir() {
		t.Fatalf("remove deleted a folder: %v %v", info, err)
	}
	out, err = runWindowsSecretCommand(t, "status", enterpriseSecretOptions{json: true}, "")
	if err != nil || !strings.Contains(out, `"other-key"`) || strings.Contains(out, `"ai-defense-api-key"`) {
		t.Fatalf("status after remove: %v %s", err, out)
	}
	if !windowsSecretStored(dir, "other-key") || windowsSecretStored(dir, "ai-defense-api-key") {
		t.Fatal("windowsSecretStored disagrees with the store")
	}
}

// An ACL edit that drops the gateway service SID's read ACEs from a stored
// credential and its folder leaves the bytes alone. An identical set is still
// a no-op (nothing rewritten), but it applies both descriptors again: the
// administrator's own read of the value succeeds without them, while the
// gateway's restricted token cannot load the credential.
func TestWindowsSecretIdenticalSetRepairsTheGatewayReadACEs(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	stubWindowsSecretHost(t, managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir, LifecycleDir: filepath.Join(filepath.Dir(dir), "install")})
	windowsSecretRestartGateway = func(func() error) (bool, error) { return false, nil }
	set := func() string {
		t.Helper()
		out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, "same-value\n")
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	set()
	path := filepath.Join(dir, "ai-defense-api-key")
	if err := applyWindowsSDDL(path, "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"); err != nil {
		t.Fatal(err)
	}
	if err := applyWindowsSDDL(dir, "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"); err != nil {
		t.Fatal(err)
	}
	preserved := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := os.Chtimes(path, preserved, preserved); err != nil {
		t.Fatal(err)
	}
	if out := set(); out != `{"action":"set","gateway_restarted":false,"name":"ai-defense-api-key","ok":true,"schema_version":1}`+"\n" {
		t.Fatalf("identical set after an ACL edit: %q", out)
	}
	if info, err := os.Stat(path); err != nil || !info.ModTime().Equal(preserved) {
		t.Fatalf("identical value was rewritten: %v, %v", info, err)
	}
	gateway, err := managed.WindowsServiceAccountSID(windowsSecretGatewayAccount)
	if err != nil {
		t.Fatal(err)
	}
	if ace, ok := windowsSecretTestACEs(t, path)[gateway.String()]; !ok || ace.mask != 0x120089 { // FR (FILE_GENERIC_READ)
		t.Fatalf("credential read ACE of the gateway not repaired: %+v, %v", ace, ok)
	}
	if ace, ok := windowsSecretTestACEs(t, dir)[gateway.String()]; !ok || ace.mask != 0x1200a0 { // windowsSecretDirectoryReaderAccess
		t.Fatalf("folder ACE of the gateway not repaired: %+v, %v", ace, ok)
	}
}

// The identical-value check reads the stored bytes only through the pinned
// folder and a handle that follows no reparse point, and never more than the
// credential limit: a link or junction named like the credential and an
// oversized file are refused before anything is read.
func TestWindowsSecretOpenCredentialRefusesLinksAndOversizedFiles(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	store, err := openWindowsSecretStore(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if err := os.WriteFile(filepath.Join(dir, "oversized"), bytes.Repeat([]byte("a"), managed.ServiceCredentialLimit+1), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("same-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	windowsSecretTestJunction(t, filepath.Join(dir, "junction"), outside)
	for _, name := range []string{"oversized", "linked", "junction"} {
		if entry, data, err := store.openCredential(name); err == nil {
			_ = windows.CloseHandle(entry)
			t.Fatalf("%s was read: %q", name, data)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "plain"), []byte("same-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	entry, data, err := store.openCredential("plain")
	if err != nil || string(data) != "same-value" {
		t.Fatalf("plain credential: %q, %v", data, err)
	}
	_ = windows.CloseHandle(entry)
}

// GAP-0335: Windows `secret set` stores a credential the confirmed bundle
// references only with the value that bundle signs. Another value is
// refused secret_ref_mismatch with exit 1603 under the change locks: nothing
// is written and the gateway is not restarted. The signed value is stored.
func TestWindowsSecretSetStoresOnlyTheValueTheConfirmedBundleSigns(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	e, store := credentialBundleEnv(t)
	confirmSignedBundle(t, store, e.signCredentialBundle(t, "5", "key-1", filepath.Join(e.dir, "key.pem")))
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	host := stubWindowsSecretHost(t, layout)
	credential := filepath.Join(dir, "ai-defense-api-key")

	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, "key-2\r\n")
	if err == nil || commandExitCode(err) != windowsSecretExitFailure {
		t.Fatalf("set of a value the bundle does not sign: %v (exit %d), want exit %d", err, commandExitCode(err), windowsSecretExitFailure)
	}
	var doc struct {
		OK     bool `json:"ok"`
		Errors []struct {
			Code string `json:"code"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.OK || len(doc.Errors) != 1 || doc.Errors[0].Code != "secret_ref_mismatch" {
		t.Fatalf("refusal document %s (%v), want one secret_ref_mismatch error", out, err)
	}
	if strings.Contains(out, "key-2") {
		t.Fatal("the refusal prints the value")
	}
	if _, statErr := os.Stat(credential); !os.IsNotExist(statErr) {
		t.Fatalf("a refused value was written: %v", statErr)
	}
	want := []string{"lock bundle", "lock lifecycle", "unlock lifecycle", "unlock bundle"}
	if strings.Join(host.events, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v, want the refusal under both locks and no restart: %v", host.events, want)
	}

	host.events = nil
	if out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, "key-1\r\n"); err != nil {
		t.Fatalf("set of the signed value: %v\n%s", err, out)
	}
	if data, err := os.ReadFile(credential); err != nil || strings.TrimSpace(string(data)) != "key-1" {
		t.Fatalf("stored credential %q, %v; want the signed value", data, err)
	}
	if !slices.Contains(host.events, "restart") {
		t.Fatalf("events %v, want a gateway restart after the change", host.events)
	}
}

// Loop round 2 (rc.7), finding 1: the MDM wrapper's put-back of a credential
// a failed rotation added to a config that references it with no value
// stored. secret remove refuses credential_in_use, which proves nothing
// about the rotation. remove --undo-rotation with the bundle confirmed
// before the rotation removes it; with another bundle confirmed since, it
// refuses rotation_confirmed and leaves it. A rotation guarded by a bundle
// that is no longer confirmed writes nothing.
func TestWindowsSecretUndoRotationRemovesWhatAFailedRotationAdded(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	cfg := strings.Replace(standaloneGatewayCheckConfig, "enterprise:\n  profile: standalone\n",
		"enterprise:\n  profile: standalone\n  inspection:\n    ai_defense:\n      enabled: true\n      credential: ai-defense-api-key\n", 1)
	if cfg == standaloneGatewayCheckConfig {
		t.Fatal("the test config has no enterprise profile line to extend")
	}
	if err := os.WriteFile(layout.ConfigPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	previous := bundleStore
	t.Cleanup(func() { bundleStore = previous })
	store := enterprisebundle.NewStore(filepath.Join(t.TempDir(), "bundles"), filepath.Join(t.TempDir(), "lifecycle"))
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	const name = "ai-defense-api-key"
	other := strings.Repeat("a", 64)
	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true, json: true, bundle: "unused.dcbundle", ifConfirmed: other}, "new-key\n")
	windowsSecretFailureDoc(t, out, err, "set", "confirmed_bundle_changed")
	if windowsSecretStored(dir, name) {
		t.Fatal("a rotation guarded by a bundle no longer confirmed stored the value")
	}
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true}, "new-key\n"); err != nil {
		t.Fatal(err)
	}
	out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: name, json: true}, "")
	windowsSecretFailureDoc(t, out, err, "remove", "credential_in_use")
	out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: name, json: true, undoRotation: other, ifStored: windowsTestSHA256("new-key")}, "")
	windowsSecretFailureDoc(t, out, err, "remove", "rotation_confirmed")
	if !windowsSecretStored(dir, name) {
		t.Fatal("a refused put-back removed the credential")
	}
	// Without the config from before the rotation (--undo-config), or with
	// another one, the reference stands (loop round 1, review at b97e9ab4).
	for _, undoConfig := range []string{"", "none", windowsTestSHA256(standaloneGatewayCheckConfig)} {
		out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: name, json: true, undoRotation: "none", undoConfig: undoConfig, ifStored: windowsTestSHA256("new-key")}, "")
		windowsSecretFailureDoc(t, out, err, "remove", "credential_in_use")
		if !windowsSecretStored(dir, name) {
			t.Fatalf("a put-back with --undo-config %q removed a credential the installed config references", undoConfig)
		}
	}
	out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: name, json: true, undoRotation: "none", undoConfig: windowsTestSHA256(cfg), ifStored: windowsTestSHA256("new-key")}, "")
	if err != nil {
		t.Fatalf("put-back: %v\n%s", err, out)
	}
	if windowsSecretStored(dir, name) {
		t.Fatal("the put-back left the credential the failed rotation added")
	}
}

func windowsTestSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// Loop round 1 (review at b97e9ab4): the wrapper journaled an absent
// credential and stored a new value with no bundle confirmed; before its
// lifecycle finished, another ensure installed a config that uses the
// value; the lifecycle then failed. The put-back (remove --undo-rotation
// none) skipped credential_in_use, deleted the credential that config needs
// and restarted the gateway. It now takes a referenced credential only while
// the config journaled before the rotation (--undo-config) is installed;
// otherwise credential_in_use, and the credential stays.
func TestWindowsSecretUndoRotationKeepsACredentialALaterConfigUses(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	previous := bundleStore
	t.Cleanup(func() { bundleStore = previous })
	store := enterprisebundle.NewStore(filepath.Join(t.TempDir(), "bundles"), filepath.Join(t.TempDir(), "lifecycle"))
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	const name = "ai-defense-api-key"
	unused := standaloneGatewayCheckConfig
	uses := strings.Replace(unused, "enterprise:\n  profile: standalone\n",
		"enterprise:\n  profile: standalone\n  inspection:\n    ai_defense:\n      enabled: true\n      credential: ai-defense-api-key\n", 1)
	if uses == unused {
		t.Fatal("the test config has no enterprise profile line to extend")
	}
	reapplied := uses + "# installed again by another ensure\n"
	for _, tc := range []struct {
		name, before, after string
		removed             bool
	}{
		{"a config installed since uses it", unused, uses, false},
		{"a config installed since still uses it", uses, reapplied, false},
		{"the config from before uses it", uses, uses, true},
		{"a config installed since does not use it", uses, unused, true},
		// A bundle confirmed since the rotation (here: the journaled one
		// is no longer confirmed) proves it committed: rotation_confirmed,
		// whatever config is installed now, so the wrapper retires its
		// entry instead of keeping it for good.
		{"a bundle confirmed since and a config installed since", unused, uses, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(layout.ConfigPath, []byte(tc.before), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true}, "new-key\n"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(layout.ConfigPath, []byte(tc.after), 0o600); err != nil {
				t.Fatal(err)
			}
			undoRotation, code := "none", "credential_in_use"
			if strings.HasPrefix(tc.name, "a bundle confirmed since") {
				undoRotation, code = strings.Repeat("a", 64), "rotation_confirmed"
			}
			out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: name, json: true, undoRotation: undoRotation, undoConfig: windowsTestSHA256(tc.before), ifStored: windowsTestSHA256("new-key")}, "")
			if tc.removed {
				if err != nil {
					t.Fatalf("put-back: %v\n%s", err, out)
				}
				if windowsSecretStored(dir, name) {
					t.Fatal("the put-back left the credential the failed rotation added")
				}
				return
			}
			windowsSecretFailureDoc(t, out, err, "remove", code)
			if code == "rotation_confirmed" {
				if !windowsSecretStored(dir, name) {
					t.Fatal("a put-back refused rotation_confirmed removed the credential")
				}
				return
			}
			if !strings.Contains(out, "not the config installed before the rotation") || strings.Contains(out, "new-key") {
				t.Fatalf("refusal does not say why, or prints the value:\n%s", out)
			}
			if !windowsSecretStored(dir, name) {
				t.Fatal("the put-back removed a credential a config installed since uses")
			}
		})
	}
}

// A journaled absent credential can be restored when no config.yaml existed
// before the rotation or at replay. The ordinary remove path still requires
// an inspectable config.
func TestWindowsSecretUndoRotationRemovesAnAddedCredentialWithoutConfig(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(layout.ConfigPath); err != nil {
		t.Fatal(err)
	}
	previous := bundleStore
	t.Cleanup(func() { bundleStore = previous })
	store := enterprisebundle.NewStore(filepath.Join(t.TempDir(), "bundles"), filepath.Join(t.TempDir(), "lifecycle"))
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	const name = "ai-defense-api-key"
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true}, "new-key\n"); err != nil {
		t.Fatal(err)
	}
	out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: name, json: true}, "")
	windowsSecretFailureDoc(t, out, err, "remove", "state_invalid")
	windowsSecretAbsentConfigParentTrusted = func(string) error { return errors.New("untrusted parent") }
	out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{
		name: name, json: true, undoRotation: "none", undoConfig: "none", ifStored: windowsTestSHA256("new-key"),
	}, "")
	windowsSecretFailureDoc(t, out, err, "remove", "state_invalid")
	if !windowsSecretStored(dir, name) {
		t.Fatal("the failed rotation's credential was removed through an untrusted config parent")
	}
	windowsSecretAbsentConfigParentTrusted = func(string) error { return nil }
	out, err = runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{
		name: name, json: true, undoRotation: "none", undoConfig: "none", ifStored: windowsTestSHA256("new-key"),
	}, "")
	if err != nil {
		t.Fatalf("undo absent-config rotation: %v\n%s", err, out)
	}
	if windowsSecretStored(dir, name) {
		t.Fatal("the failed rotation's added credential remains")
	}
}

// Both put-back forms compare the exact value the rotation wrote under the
// credential locks. A later direct administrator save must survive even if
// the config and confirmed bundle still match the journal's older identity.
func TestWindowsSecretUndoRotationKeepsALaterCredentialValue(t *testing.T) {
	for _, action := range []string{"set", "remove"} {
		t.Run(action, func(t *testing.T) {
			dir := windowsSecretTestHarness(t)
			layout, err := windowsSecretLayout()
			if err != nil {
				t.Fatal(err)
			}
			if action == "remove" {
				if err := os.Remove(layout.ConfigPath); err != nil {
					t.Fatal(err)
				}
			}
			previous := bundleStore
			t.Cleanup(func() { bundleStore = previous })
			store := enterprisebundle.NewStore(filepath.Join(t.TempDir(), "bundles"), filepath.Join(t.TempDir(), "lifecycle"))
			bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
			const name = "ai-defense-api-key"
			if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true}, "new-key\n"); err != nil {
				t.Fatal(err)
			}
			credential := filepath.Join(dir, name)
			if err := os.WriteFile(credential, []byte("admin-new-key"), 0o600); err != nil {
				t.Fatal(err)
			}
			opts := enterpriseSecretOptions{name: name, json: true, undoRotation: "none", ifStored: windowsTestSHA256("new-key"), undoConfig: "none"}
			input := ""
			if action == "set" {
				opts.fromStdin, input = true, "old-key\n"
			}
			out, err := runWindowsSecretCommand(t, action, opts, input)
			windowsSecretFailureDoc(t, out, err, action, "credential_changed")
			if raw, err := os.ReadFile(credential); err != nil || string(raw) != "admin-new-key" {
				t.Fatalf("administrator's value changed to %q: %v", raw, err)
			}
		})
	}
}

// The wrapper journals before secret set writes the delivered value. A
// refused launch or an interrupted run can therefore replay while the old
// value (or its absence) is still in the store. That replay is already done;
// it must not strand the entry behind --if-stored's digest of the new value.
func TestWindowsSecretUndoRotationAlreadyRestoredBeforeSet(t *testing.T) {
	for _, oldPresent := range []bool{true, false} {
		t.Run(fmt.Sprint("old-present=", oldPresent), func(t *testing.T) {
			dir := windowsSecretTestHarness(t)
			layout, err := windowsSecretLayout()
			if err != nil {
				t.Fatal(err)
			}
			previous := bundleStore
			t.Cleanup(func() { bundleStore = previous })
			store := enterprisebundle.NewStore(filepath.Join(t.TempDir(), "bundles"), filepath.Join(t.TempDir(), "lifecycle"))
			bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
			const name = "ai-defense-api-key"
			if oldPresent {
				if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true}, "old-key\n"); err != nil {
					t.Fatal(err)
				}
				// Older stores can retain source whitespace. The replay's
				// input is normalized, but the exact old bytes stay in place.
				if err := os.WriteFile(filepath.Join(dir, name), []byte(" old-key\r\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else {
				// Even a config installed since the journal cannot cause a
				// removal: there is still nothing stored to remove.
				cfg := strings.Replace(standaloneGatewayCheckConfig, "enterprise:\n  profile: standalone\n",
					"enterprise:\n  profile: standalone\n  inspection:\n    ai_defense:\n      enabled: true\n      credential: ai-defense-api-key\n", 1)
				if cfg == standaloneGatewayCheckConfig {
					t.Fatal("the later config did not gain a credential reference")
				}
				if err := os.WriteFile(layout.ConfigPath, []byte(cfg), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			windowsSecretGatewayLive = func() (bool, error) { return false, nil }
			windowsSecretRestartGateway = func(func() error) (bool, error) { return false, nil }
			opts := enterpriseSecretOptions{name: name, json: true, undoRotation: "none", ifStored: windowsTestSHA256("new-key")}
			action, input := "remove", ""
			if oldPresent {
				action, input, opts.fromStdin = "set", "old-key\n", true
			} else {
				opts.undoConfig = windowsTestSHA256(standaloneGatewayCheckConfig)
			}
			out, err := runWindowsSecretCommand(t, action, opts, input)
			if err != nil || !strings.Contains(out, `"gateway_restarted":false`) {
				t.Fatalf("already-undone replay: %v\n%s", err, out)
			}
			if oldPresent {
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || string(raw) != " old-key\r\n" {
					t.Fatalf("old credential changed to %q: %v", raw, err)
				}
			} else if windowsSecretStored(dir, name) {
				t.Fatal("replay created a credential that was absent before the rotation")
			}
		})
	}
}

func TestWindowsSecretUndoRotationAlreadyRestoredReloadsLiveGateway(t *testing.T) {
	for _, oldPresent := range []bool{true, false} {
		for _, restartFails := range []bool{true, false} {
			t.Run(fmt.Sprintf("old-present=%t/restart-fails=%t", oldPresent, restartFails), func(t *testing.T) {
				dir := windowsSecretTestHarness(t)
				previous := bundleStore
				t.Cleanup(func() { bundleStore = previous })
				store := enterprisebundle.NewStore(filepath.Join(t.TempDir(), "bundles"), filepath.Join(t.TempDir(), "lifecycle"))
				bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
				const name = "ai-defense-api-key"
				if oldPresent {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, name), []byte("old-key"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				restarts := 0
				windowsSecretRestartGateway = func(beforeStop func() error) (bool, error) {
					restarts++
					if restartFails {
						return false, errWindowsGatewayStopRefused
					}
					if err := beforeStop(); err != nil {
						return false, err
					}
					return true, nil
				}
				opts := enterpriseSecretOptions{name: name, json: true, undoRotation: "none", ifStored: windowsTestSHA256("new-key")}
				action, input := "remove", ""
				if oldPresent {
					action, input, opts.fromStdin = "set", "old-key\n", true
				} else {
					opts.undoConfig = "none"
				}
				out, err := runWindowsSecretCommand(t, action, opts, input)
				if restartFails {
					windowsSecretFailureDoc(t, out, err, action, "restart_failed")
				} else if err != nil || !strings.Contains(out, `"gateway_restarted":true`) {
					t.Fatalf("restored replay did not reload the gateway: %v\n%s", err, out)
				}
				if restarts != 1 {
					t.Fatalf("gateway restart calls = %d, want 1", restarts)
				}
				if oldPresent {
					raw, readErr := os.ReadFile(filepath.Join(dir, name))
					if readErr != nil || string(raw) != "old-key" {
						t.Fatalf("old value changed: %q, %v", raw, readErr)
					}
				} else if windowsSecretStored(dir, name) {
					t.Fatal("absent credential was created")
				}
			})
		}
	}
}

func TestWindowsSecretSetIfStoredProvesAbsence(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	const name = "ai-defense-api-key"
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte("administrator-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := enterpriseSecretOptions{name: name, fromStdin: true, json: true, ifStored: "none"}
	out, err := runWindowsSecretCommand(t, "set", opts, "delivered-value\n")
	windowsSecretFailureDoc(t, out, err, "set", "credential_changed")
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil || string(raw) != "administrator-value" {
		t.Fatalf("administrator value changed: %q, %v", raw, err)
	}
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if _, err := runWindowsSecretCommand(t, "set", opts, "delivered-value\n"); err != nil {
		t.Fatalf("proven absence refused: %v", err)
	}
}

// GAP-2430 (issue #1319): a set whose new value fails the gateway trust
// check after the write leaves the previous credential exactly as it was
// (bytes, owner and protected DACL), reports change_failed, restarts
// nothing and leaves no temporary or kept file. With nothing stored before,
// nothing is stored after.
func TestWindowsSecretFailedTrustCheckKeepsThePreviousCredential(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	layout, err := windowsSecretLayout()
	if err != nil {
		t.Fatal(err)
	}
	host := stubWindowsSecretHost(t, layout)
	const name = "ai-defense-api-key"
	credential := filepath.Join(dir, name)
	securityOf := func() string {
		t.Helper()
		extended, _ := winpath.Extended(credential)
		sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return sd.String()
	}
	onlyTheCredential := func(want []string) {
		t.Helper()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		if strings.Join(names, ",") != strings.Join(want, ",") {
			t.Fatalf("secrets folder holds %v, want %v", names, want)
		}
	}
	if out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true, json: true}, "first-value-0001\r\n"); err != nil {
		t.Fatalf("first set: %v\n%s", err, out)
	}
	before, err := os.ReadFile(credential)
	if err != nil {
		t.Fatal(err)
	}
	beforeSecurity := securityOf()

	previousCheck := windowsSecretTrustCheck
	t.Cleanup(func() { windowsSecretTrustCheck = previousCheck })
	checked := 0
	windowsSecretTrustCheck = func(n, d string) error {
		checked++
		if data, _ := os.ReadFile(filepath.Join(d, n)); strings.TrimSpace(string(data)) != "second-value-0002" {
			t.Errorf("the trust check read %q, want the new value in place", data)
		}
		return errors.New("principal S-1-5-32-545 may read the protected credential")
	}
	host.events = nil
	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true, json: true}, "second-value-0002\r\n")
	if err == nil || commandExitCode(err) != windowsSecretExitFailure || checked != 1 {
		t.Fatalf("set with a failing trust check: %v (exit %d, checks %d), want exit %d after one check", err, commandExitCode(err), checked, windowsSecretExitFailure)
	}
	var doc struct {
		OK     bool `json:"ok"`
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc.OK || len(doc.Errors) != 1 || doc.Errors[0].Code != "change_failed" ||
		!strings.Contains(doc.Errors[0].Message, "previous credential is kept unchanged") {
		t.Fatalf("failure document %s (%v), want one change_failed error that says the previous credential is kept", out, err)
	}
	if strings.Contains(out, "second-value-0002") || strings.Contains(out, "first-value-0001") {
		t.Fatal("the failure document prints a value")
	}
	after, err := os.ReadFile(credential)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatalf("stored credential after the failed set: %v (equal %v), want the previous bytes", err, bytes.Equal(after, before))
	}
	if got := securityOf(); got != beforeSecurity {
		t.Fatalf("credential security %s, want the previous %s", got, beforeSecurity)
	}
	onlyTheCredential([]string{name})
	if slices.Contains(host.events, "restart") {
		t.Fatalf("events %v: the gateway restarted after a failed set", host.events)
	}

	// Nothing stored before: nothing stored after, nothing left behind.
	windowsSecretTrustCheck = previousCheck
	if out, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: name, json: true}, ""); err != nil {
		t.Fatalf("remove: %v\n%s", err, out)
	}
	windowsSecretTrustCheck = func(string, string) error { return errors.New("refused") }
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: name, fromStdin: true, json: true}, "third-value-0003\r\n"); err == nil {
		t.Fatal("set with a failing trust check and nothing stored succeeded")
	}
	if _, err := os.Lstat(credential); !os.IsNotExist(err) {
		t.Fatalf("a value that failed the trust check is stored: %v", err)
	}
	if entries, err := os.ReadDir(dir); err == nil && len(entries) != 0 {
		t.Fatalf("secrets folder keeps %d entries after the failed set, want none", len(entries))
	}
}

// GAP-2430 live (dc-fc-r104-cap-ewin4): a concurrent process that holds the
// rejected new file open made the put-back fail with access denied, and the
// previous credential was dropped with it. The put-back waits out a short
// hold; a hold it cannot wait out leaves the previous value under its kept
// name.
func TestWindowsSecretPutBackWaitsOutAShortHoldOnTheRejectedFile(t *testing.T) {
	dir := t.TempDir()
	final := filepath.Join(dir, "ai-defense-api-key")
	kept := filepath.Join(dir, ".ai-defense-api-key.kept-0011223344556677")
	if err := os.WriteFile(final, []byte("new-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kept, []byte("previous-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	hold := func() windows.Handle {
		t.Helper()
		p, _ := windows.UTF16PtrFromString(final)
		h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	h := hold()
	released := make(chan struct{})
	go func() {
		time.Sleep(400 * time.Millisecond)
		_ = windows.CloseHandle(h)
		close(released)
	}()
	if err := restoreWindowsSecret(kept, final); err != nil {
		t.Fatalf("put-back after a 400 ms hold: %v", err)
	}
	<-released
	if data, err := os.ReadFile(final); err != nil || string(data) != "previous-value" {
		t.Fatalf("after the put-back %s holds %q (%v), want the previous value", final, data, err)
	}
	if _, err := os.Lstat(kept); !os.IsNotExist(err) {
		t.Fatalf("the kept name is still there: %v", err)
	}

	// A hold longer than the wait: the previous value stays under its kept name.
	if err := os.WriteFile(kept, []byte("previous-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	h = hold()
	defer windows.CloseHandle(h)
	if err := restoreWindowsSecret(kept, final); err == nil {
		t.Fatal("put-back over a file held for the whole wait succeeded")
	}
	if data, err := os.ReadFile(kept); err != nil || string(data) != "previous-value" {
		t.Fatalf("kept copy %q (%v), want the previous value", data, err)
	}
}
