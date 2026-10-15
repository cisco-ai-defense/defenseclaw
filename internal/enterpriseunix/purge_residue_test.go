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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		s.fakeServices.mu.Lock()
		for _, name := range []string{unitGateway, unitAPISocket, unitHookSocket} {
			s.fakeServices.active[name] = true
		}
		s.fakeServices.mu.Unlock()
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

func (s stuckServices) StopTogether(ctx context.Context, units []Unit) error {
	err := s.fakeServices.StopTogether(ctx, units)
	s.fakeServices.mu.Lock()
	for _, unit := range units {
		if unit.Name == s.stuck {
			s.fakeServices.active[unit.Name] = true
		}
	}
	s.fakeServices.mu.Unlock()
	return err
}

func TestUninstallReportsAUnitItCouldNotStop(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.Services = stuckServices{fakeServices: h.services, stuck: unitAPISocket}
	r := h.run(Options{Action: ActionUninstall})
	requireError(t, r, codeUninstall)
	if got := messagesOf(r.Errors, codeUninstall); !strings.Contains(got, "could not stop "+unitAPISocket) {
		t.Fatalf("the error does not name the running unit: %s", got)
	}
	if got := countCalls(h.services.calls, "stop "+unitAPISocket); got < 3 {
		t.Fatalf("the stuck unit was stopped %d times, want 3", got)
	}
	if !exists(h.env.deploymentPath()) {
		t.Fatal("the failed uninstall removed the deployment record")
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
