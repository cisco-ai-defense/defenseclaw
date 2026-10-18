// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// hookTrafficServices models systemd under agent hook traffic: a hook call
// on a listening hook socket starts the gateway, and the gateway's
// Requires= starts both of its sockets. The live host saw exactly that
// (GAP-0112): the uninstall stopped the gateway, then its API socket, then
// its hook socket, one request each; a hook call between them started the
// gateway again, which started the API socket again, and the API socket
// stayed listening after the package removed its unit file.
type hookTrafficServices struct {
	*fakeServices
}

func (s hookTrafficServices) Stop(ctx context.Context, u Unit) error {
	err := s.fakeServices.Stop(ctx, u)
	if u.Name == unitAPISocket || u.Name == unitHookSocket {
		_ = s.fakeServices.Stop(ctx, Unit{Name: unitGateway}) // Requires= propagates the stop
	}
	if s.isActive(unitHookSocket) && !s.isActive(unitGateway) {
		s.mu.Lock()
		for _, name := range []string{unitGateway, unitAPISocket, unitHookSocket} {
			s.active[name] = true
		}
		s.mu.Unlock()
	}
	return err
}

func TestUninstallStopsTheGatewayAndItsSocketsTogetherUnderHookTraffic(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.Services = hookTrafficServices{h.services}
	r := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, r)
	for _, unit := range h.services.Units() {
		if h.services.isActive(unit.Name) {
			t.Fatalf("the purge left %s running under hook traffic", unit.Name)
		}
	}
}

// A unit that is still running after the grouped stop and two retries is
// an uninstall error naming it, not a silent leftover.
type stuckServices struct {
	*fakeServices
	stuck string
}

// Stop is the stop of one unit, as launchd does it on macOS.
func (s stuckServices) Stop(ctx context.Context, unit Unit) error {
	err := s.fakeServices.Stop(ctx, unit)
	if unit.Name == s.stuck {
		s.mu.Lock()
		s.active[unit.Name] = true
		s.mu.Unlock()
	}
	return err
}

func (s stuckServices) StopTogether(ctx context.Context, units []Unit) error {
	err := s.fakeServices.StopTogether(ctx, units)
	s.mu.Lock()
	for _, unit := range units {
		if unit.Name == s.stuck {
			s.active[unit.Name] = true
		}
	}
	s.mu.Unlock()
	return err
}

// The error names the command that stops the unit on the platform:
// systemctl stop on Linux, launchctl bootout system/<label> on macOS, where
// launchd stops each job on its own.
func TestUninstallReportsAUnitItCouldNotStop(t *testing.T) {
	for _, tc := range []struct{ goos, stuck, command, foreign string }{
		{"linux", unitAPISocket, "`systemctl stop " + unitAPISocket + "`", "launchctl"},
		{"darwin", labelGateway, "`launchctl bootout system/" + labelGateway + "`", "systemctl"},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			h := newTestHost(t, tc.goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.Services = stuckServices{fakeServices: h.services, stuck: tc.stuck}
			r := h.run(Options{Action: ActionUninstall})
			requireError(t, r, codeUninstall)
			got := messagesOf(r.Errors, codeUninstall)
			if !strings.Contains(got, "could not stop "+tc.stuck+"; stop them with "+tc.command+" and rerun `") {
				t.Fatalf("the error does not name the running unit and %s: %s", tc.command, got)
			}
			if strings.Contains(got, tc.foreign) {
				t.Fatalf("the %s error names %s: %s", tc.goos, tc.foreign, got)
			}
			if got := countCalls(h.services.calls, "stop "+tc.stuck); got < 3 {
				t.Fatalf("the stuck unit was stopped %d times, want 3", got)
			}
			if !exists(h.env.deploymentPath()) {
				t.Fatal("the failed uninstall removed the deployment record")
			}
		})
	}
}

// Several units on macOS: one bootout each.
func TestStopCommandsFollowThePlatform(t *testing.T) {
	units := []string{"a.socket", "b.service"}
	if got := (&Env{GOOS: "linux"}).stopCommands(units); got != "`systemctl stop a.socket b.service`" {
		t.Fatalf("linux: %s", got)
	}
	if got := (&Env{GOOS: "darwin"}).stopCommands(units); got != "`launchctl bootout system/a.socket`, `launchctl bootout system/b.service`" {
		t.Fatalf("darwin: %s", got)
	}
}

// A purge removes the lifecycle lock and its directory (GAP-0112), and on
// macOS the product directory around it (GAP-0101). The package removal's
// own uninstall, a no-op after the purge, does not leave them again.
func TestPurgeLeavesNoLifecycleLockOrProductDirectory(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			l := h.env.Layout
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
			gone := []string{l.LifecycleDir}
			if goos == "darwin" {
				gone = append(gone, l.InstallRoot, "/opt/cisco")
			}
			for _, dir := range gone {
				if exists(h.env.P(dir)) {
					t.Fatalf("the purge left %s", dir)
				}
			}
			again := h.run(Options{Action: ActionUninstall})
			requireOK(t, again)
			if !again.Noop {
				t.Fatalf("the second uninstall is not a no-op: %+v", again)
			}
			if exists(h.env.P(l.LifecycleDir)) {
				t.Fatalf("the no-op uninstall after the purge created %s again", l.LifecycleDir)
			}
		})
	}
}

// An uninstall that keeps state keeps the lock with it.
func TestUninstallKeepStateKeepsTheLock(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	requireOK(t, h.run(Options{Action: ActionUninstall, KeepState: true}))
	if !exists(h.env.P(filepath.Join(h.env.Layout.LifecycleDir, lockFileName))) {
		t.Fatal("an uninstall that kept state removed the lifecycle lock")
	}
}

// A run that waited on the lock while an uninstall removed it must not run
// on the removed inode next to a new run on a new file, and must not create
// the lifecycle directory again.
func TestLockWaiterStopsWhenTheUninstallRemovedTheLock(t *testing.T) {
	h := newTestHost(t, "linux")
	dir := h.env.P(h.env.Layout.LifecycleDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.env.LockTimeout = 5 * time.Second
	held, err := h.env.acquireLock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		lock, err := h.env.acquireLock(context.Background())
		lock.release()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond) // the waiter has the file open and polls
	if err := os.Remove(filepath.Join(dir, lockFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	held.release()
	if err := <-done; !errors.Is(err, errLockRemoved) {
		t.Fatalf("the waiter got %v, want errLockRemoved", err)
	}
	if exists(dir) {
		t.Fatal("the waiter created the lifecycle directory again")
	}
}

// When the directory stays and another run created a new lock file, the
// waiter takes the new file, so two runs never hold different inodes.
func TestLockWaiterMovesToTheNewLockFile(t *testing.T) {
	h := newTestHost(t, "linux")
	dir := h.env.P(h.env.Layout.LifecycleDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.env.LockTimeout = 5 * time.Second
	held, err := h.env.acquireLock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan *lifecycleLock, 1)
	go func() {
		lock, err := h.env.acquireLock(context.Background())
		if err != nil {
			t.Error(err)
		}
		got <- lock
	}()
	time.Sleep(50 * time.Millisecond)
	if err := os.Remove(filepath.Join(dir, lockFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, lockFileName), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	held.release()
	lock := <-got
	defer lock.release()
	if lock == nil {
		t.Fatal("the waiter got no lock")
	}
	held2, statErr := lock.file.Stat()
	named, err := os.Stat(filepath.Join(dir, lockFileName))
	if statErr != nil || err != nil || !os.SameFile(held2, named) {
		t.Fatalf("the waiter holds a removed inode: %v %v", statErr, err)
	}
	h.env.LockTimeout = 50 * time.Millisecond
	if _, err := h.env.acquireLock(t.Context()); !errors.Is(err, errLockBusy) {
		t.Fatalf("a third run got the lock beside the waiter: %v", err)
	}
}

// runWhileTheLockIsRemoved runs opts while another run holds the lifecycle
// lock, then removes the lock and its directory as an uninstall that leaves
// nothing behind does, and releases it.
func runWhileTheLockIsRemoved(t *testing.T, h *testHost, opts Options) *enterprisestatus.Result {
	t.Helper()
	dir := h.env.P(h.env.Layout.LifecycleDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	h.env.LockTimeout = 10 * time.Second
	held, err := h.env.acquireLock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan *enterprisestatus.Result, 1)
	go func() { done <- Run(context.Background(), h.env, opts) }()
	time.Sleep(300 * time.Millisecond) // the waiter has the lock file open and polls
	if err := os.Remove(filepath.Join(dir, lockFileName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	held.release()
	r := <-done
	if exists(dir) {
		t.Fatalf("%s created the lifecycle directory again", opts.Action)
	}
	return r
}

// The package removal's preremove runs `uninstall --lock-wait 8m`. When it
// waits for a concurrent MDM purge, the purge removes the deployment and the
// lock; the waiting uninstall then has nothing left to remove. It exits 0 as
// a not_installed no-op: a busy 75 made the preremove abort the rpm or deb
// removal after the purge had removed everything (GAP-0112).
func TestUninstallWaitingForAPurgeThatRemovedTheLockIsANoop(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, purge := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/purge=%v", goos, purge), func(t *testing.T) {
				h := newTestHost(t, goos)
				r := runWhileTheLockIsRemoved(t, h, Options{Action: ActionUninstall, Purge: purge})
				requireOK(t, r)
				if r.ExitCode != enterprisestatus.ExitOK || !r.Noop || r.NoopReason != "not_installed" || r.Installed {
					t.Fatalf("exit %d noop %v %q installed %v, want a not_installed no-op with exit 0: %+v",
						r.ExitCode, r.Noop, r.NoopReason, r.Installed, r.Errors)
				}
				if got := messagesOf(r.Warnings, codeNotInstalled); !strings.Contains(got, "uninstalled by the lifecycle run this uninstall waited for") {
					t.Fatalf("the no-op does not say why: %q", got)
				}
			})
		}
	}
}

// Any other action that waited while an uninstall removed the lock reports
// busy (75): what it was asked to change is gone with the deployment.
func TestOtherActionsWaitingWhileTheLockWasRemovedReportBusy(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, action := range []string{ActionEnsure, ActionRepair, ActionReconcile} {
			t.Run(goos+"/"+action, func(t *testing.T) {
				h := newTestHost(t, goos)
				opts := Options{Action: action}
				if action == ActionEnsure {
					opts.PayloadDir = h.payload("1.0.0")
				}
				r := runWhileTheLockIsRemoved(t, h, opts)
				requireError(t, r, codeBusy)
				if r.ExitCode != enterprisestatus.UnixExitBusy || r.Noop {
					t.Fatalf("exit %d noop %v, want busy %d", r.ExitCode, r.Noop, enterprisestatus.UnixExitBusy)
				}
				if got := messagesOf(r.Errors, codeBusy); !strings.Contains(got, "uninstalled while this run waited") {
					t.Fatalf("the busy error does not say the deployment was uninstalled: %q", got)
				}
			})
		}
	}
}
