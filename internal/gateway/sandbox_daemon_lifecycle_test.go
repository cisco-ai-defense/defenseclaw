// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func refusingResolve(sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
	return sandboxrelay.ResolveResponse{V: 1, Refusal: &sandboxrelay.Refusal{Reason: sandboxrelay.ReasonNotAllowed, Message: "not for you"}}, nil
}

// A poll can adopt a running registration's looser floor during a create,
// after the new floor was chosen but before Manager.Create reads its config.
func TestSandboxDaemonPollCanAdoptDuringCreate(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	runPastRevalidate(t, f)
	yes := true
	if err := f.d.regs.put(daemonRegistration{ID: "reg-running", Sandbox: "running", Confirmed: true,
		Floor: config.OpenShellAdminConfig{MinProfile: "open", AllowYolo: &yes}, UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	f.relay.resolve = func(sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
		return sandboxrelay.ResolveResponse{V: 1, Registration: sandboxrelay.RegistrationView{ID: "reg-new"},
			Effective: json.RawMessage(`{"profile":"strict","floor":{"min_profile":"strict","allow_yolo":false}}`)}, nil
	}
	polled, sawStrict := false, false
	f.os.prepare = func(sandboxrelay.DaemonSettings) (bool, error) {
		admin := f.d.config().OpenShell.Admin
		sawStrict = admin.AllowYolo != nil && !*admin.AllowYolo
		f.d.adoptMu.Lock()
		polled = f.d.adoptRunningFloor(map[string]string{"running": "ready"})
		f.d.adoptMu.Unlock()
		return true, nil
	}
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	_, _ = ctl.Create(t.Context(), sandboxapi.CreateRequest{Harness: "claudecode", Project: t.TempDir(), Yolo: true})
	if !sawStrict || !polled || f.os.prepared.Load() == 0 {
		t.Fatal("the poll did not run between the floor change and Manager.Create")
	}
	admin := f.d.config().OpenShell.Admin
	if admin.AllowYolo == nil || !*admin.AllowYolo {
		t.Fatalf("the poll did not restore the running floor: %+v", admin)
	}
}

// GAP-0615: a floor change from Start or Create must wait for the policy
// poll's adoption. The channels put both operations at the adoption point.
func TestSandboxDaemonFloorChangesWaitForAdoption(t *testing.T) {
	t.Run("adoptFloor", func(t *testing.T) {
		f := newSandboxDaemonFixture(t)
		if err := f.d.regs.put(daemonRegistration{ID: "reg-a", Sandbox: "box", Confirmed: true,
			Floor: config.OpenShellAdminConfig{MinProfile: "strict"}, UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
		f.d.adoptMu.Lock()
		locked := true
		defer func() {
			if locked {
				f.d.adoptMu.Unlock()
			}
		}()
		started, done := make(chan struct{}), make(chan struct{})
		go func() { close(started); f.d.adoptFloor("box"); close(done) }()
		<-started
		select {
		case <-done:
			t.Fatal("adoptFloor passed the policy adoption lock")
		case <-time.After(100 * time.Millisecond):
		}
		f.d.adoptMu.Unlock()
		locked = false
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("adoptFloor did not finish after adoption")
		}
	})
	t.Run("create", func(t *testing.T) {
		f := newSandboxDaemonFixture(t)
		runPastRevalidate(t, f)
		resolved, prepared := make(chan struct{}), make(chan struct{})
		f.relay.resolve = func(sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
			close(resolved)
			return sandboxrelay.ResolveResponse{V: 1, Registration: sandboxrelay.RegistrationView{ID: "reg-new"},
				Effective: json.RawMessage(`{"profile":"strict","floor":{"min_profile":"strict","allow_yolo":false}}`)}, nil
		}
		f.os.prepare = func(sandboxrelay.DaemonSettings) (bool, error) {
			close(prepared)
			return true, nil
		}
		f.d.adoptMu.Lock()
		locked := true
		defer func() {
			if locked {
				f.d.adoptMu.Unlock()
			}
		}()
		ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
		done := make(chan struct{})
		project := t.TempDir()
		go func() {
			_, _ = ctl.Create(t.Context(), sandboxapi.CreateRequest{Harness: "claudecode", Project: project})
			close(done)
		}()
		select {
		case <-resolved:
		case <-time.After(5 * time.Second):
			t.Fatal("create did not resolve the floor")
		}
		select {
		case <-prepared:
			t.Fatal("Create passed the policy adoption lock")
		case <-time.After(100 * time.Millisecond):
		}
		f.d.adoptMu.Unlock()
		locked = false
		select {
		case <-prepared:
		case <-time.After(5 * time.Second):
			t.Fatal("create did not prepare after adoption")
		}
		<-done
	})
}

// A phase can move from stopped to ready after the poll's first list. The
// adoption must use a fresh list taken under adoptMu, not that stale view.
func TestSandboxDaemonPollRelistsPhasesAtAdoption(t *testing.T) {
	f := newFreshFixture(t)
	f.d.floorMu.Lock()
	f.d.floor = &config.OpenShellAdminConfig{MinProfile: "open"}
	f.d.floorMu.Unlock()
	f.set(sandboxrelay.CurrentPolicy{V: 1, Generation: 8, Digest: "sha256:v2",
		Floor: &config.OpenShellAdminConfig{MinProfile: "strict"}}, nil)
	listed, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	var lists atomic.Int32
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		if lists.Add(1) == 1 {
			close(listed)
			<-release
			return map[string]string{"dc-a": "stopped"}, true
		}
		return map[string]string{"dc-a": "ready"}, true
	}
	done := make(chan struct{})
	go func() { f.d.pollRegistrations(context.Background(), true); close(done) }()
	select {
	case <-listed:
	case <-time.After(5 * time.Second):
		t.Fatal("poll did not take its first phase snapshot")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("poll did not finish adoption")
	}
	if lists.Load() < 2 || f.d.config().OpenShell.Admin.MinProfile != "strict" {
		t.Fatalf("poll adopted the stale phase: lists %d, floor %+v", lists.Load(), f.d.config().OpenShell.Admin)
	}
}

func TestSandboxDaemonRevalidateWaitsForAdoption(t *testing.T) {
	f := newFreshFixture(t)
	listed := make(chan struct{})
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		select {
		case <-listed:
		default:
			close(listed)
		}
		return map[string]string{"dc-a": "ready"}, true
	}
	f.d.adoptMu.Lock()
	locked := true
	defer func() {
		if locked {
			f.d.adoptMu.Unlock()
		}
	}()
	done := make(chan struct{})
	go func() { f.d.revalidate(context.Background()); close(done) }()
	select {
	case <-listed:
	case <-time.After(5 * time.Second):
		t.Fatal("revalidate did not list phases")
	}
	select {
	case <-done:
		t.Fatal("revalidate passed the adoption lock")
	case <-time.After(100 * time.Millisecond):
	}
	f.d.adoptMu.Unlock()
	locked = false
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("revalidate did not finish after adoption")
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The supervision's release of the listeners and a create never overlap: a
// create that begins while the release counts the running sandboxes waits,
// then binds the listeners again before it resolves.
func TestSandboxDaemonReleaseNeverRacesACreate(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	var block atomic.Bool
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	f.d.opts.countRunning = func(context.Context) (int, error) {
		if block.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
		return 0, nil
	}
	var resolved atomic.Int64
	var listeningAtResolve atomic.Bool
	f.relay.resolve = func(r sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
		listeningAtResolve.Store(f.d.listening())
		resolved.Add(1)
		return refusingResolve(r)
	}
	f.run(t)
	ctx := context.Background()
	if err := f.d.ensureListeners(); err != nil {
		t.Fatal(err)
	}
	block.Store(true)
	checked := make(chan struct{})
	go func() { _, _ = f.d.check(ctx); close(checked) }()
	<-entered
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	created := make(chan error, 1)
	go func() {
		_, err := ctl.Create(ctx, sandboxapi.CreateRequest{Harness: "claudecode"})
		created <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if resolved.Load() != 0 {
		t.Fatal("a create ran while the release counted the running sandboxes")
	}
	block.Store(false)
	close(release)
	<-checked
	if err := <-created; !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) {
		t.Fatalf("create: %v", err)
	}
	if resolved.Load() != 1 || !listeningAtResolve.Load() {
		t.Fatal("the create resolved without its listeners")
	}
	if f.d.listening() {
		t.Fatal("a failed create with no sandbox running kept the ports")
	}

	// A create in progress keeps the listeners through a supervision pass.
	if err := f.d.ensureListeners(); err != nil {
		t.Fatal(err)
	}
	f.d.lifecycle <- struct{}{}
	if stop, _ := f.d.check(ctx); stop || !f.d.listening() {
		t.Fatal("the listeners were released during a create")
	}
	f.d.unlockLifecycle()
}

// Managed creates run one at a time, from the resolve through the
// registration: a second create never swaps the floor under the first.
func TestSandboxDaemonCreatesAreSerialized(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	gate := make(chan struct{})
	var calls atomic.Int64
	f.relay.resolve = func(r sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
		if calls.Add(1) == 1 {
			<-gate
		}
		return refusingResolve(r)
	}
	f.run(t)
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	done := make(chan error, 2)
	create := func() {
		_, err := ctl.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode"})
		done <- err
	}
	go create()
	waitFor(t, "the first resolve", func() bool { return calls.Load() == 1 })
	go create()
	time.Sleep(100 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("a second create resolved while the first was under way")
	}
	close(gate)
	for range 2 {
		if err := <-done; !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) {
			t.Fatalf("create: %v", err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("resolves = %d", calls.Load())
	}

	// A caller that gives up while another create holds the lifecycle is
	// answered, not left waiting.
	f.d.lifecycle <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := ctl.Create(ctx, sandboxapi.CreateRequest{Harness: "claudecode"}); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("create behind another: %v", err)
	}
	f.d.unlockLifecycle()
}

// Start revokes a registration only when the managed gateway ended it (404,
// 410, 409); the sandbox-policy budget's 429, the CSRF 403 and an outage
// leave it for the next start.
func TestSandboxDaemonStartRevokesOnlyEndedRegistrations(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	if err := f.d.regs.put(daemonRegistration{ID: "reg-a", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	var answer error
	f.relay.current = func(string) (sandboxrelay.CurrentPolicy, error) { return sandboxrelay.CurrentPolicy{}, answer }
	for _, transient := range []error{
		&sandboxrelay.Error{Status: http.StatusTooManyRequests, Reason: "enterprise_managed_rate_limited", RetryAfter: "1"},
		&sandboxrelay.Error{Status: http.StatusForbidden, Reason: "csrf"},
		&sandboxrelay.Error{Status: http.StatusServiceUnavailable, Reason: sandboxrelay.ReasonUnavailable},
		sandboxrelay.ErrGatewayUnreachable,
	} {
		answer = transient
		if _, err := ctl.Start(context.Background(), "dc-a", sandboxapi.StartRequest{}); err == nil {
			t.Fatalf("%v: start succeeded", transient)
		}
		if r, _ := f.d.regs.get("dc-a"); r.Revoked {
			t.Fatalf("%v revoked the registration", transient)
		}
		if _, gone := registrationGone(transient); gone {
			t.Fatalf("%v counts as an ended registration", transient)
		}
	}
	answer = &sandboxrelay.Error{Status: http.StatusTooManyRequests, Reason: "enterprise_managed_rate_limited"}
	if _, err := ctl.Start(context.Background(), "dc-a", sandboxapi.StartRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) {
		t.Fatalf("429 start: %v", err)
	}
	for _, status := range []int{http.StatusNotFound, http.StatusGone, http.StatusConflict} {
		if _, gone := registrationGone(&sandboxrelay.Error{Status: status}); !gone {
			t.Fatalf("%d does not end a registration", status)
		}
	}
	answer = &sandboxrelay.Error{Status: http.StatusGone, Reason: sandboxrelay.ReasonRegistrationRevoked}
	if _, err := ctl.Start(context.Background(), "dc-a", sandboxapi.StartRequest{}); err == nil {
		t.Fatal("a revoked registration started")
	}
	if r, _ := f.d.regs.get("dc-a"); !r.Revoked || r.RevokedReason != sandboxrelay.ReasonRegistrationRevoked {
		t.Fatalf("410 left the registration live: %+v", r)
	}
}

// A registration the file holds is adopted only after the managed gateway
// confirmed it: an edited or revoked one never sets the floor.
func TestSandboxDaemonRevalidatesPersistedRegistrations(t *testing.T) {
	loose := true
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		if err := os.MkdirAll(o.StateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		regs, err := loadDaemonRegistrations(filepath.Join(o.StateDir, sandboxDaemonRegistrationsFile))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range []daemonRegistration{
			{ID: "reg-edited", Sandbox: "dc-a", Floor: config.OpenShellAdminConfig{MinProfile: "open", AllowYolo: &loose}, UpdatedAt: time.Now()},
			{ID: "reg-ok", Sandbox: "dc-b", Floor: config.OpenShellAdminConfig{MinProfile: "balanced"}, UpdatedAt: time.Now().Add(-time.Hour)},
		} {
			if err := regs.put(r); err != nil {
				t.Fatal(err)
			}
		}
	})
	if admin := f.d.config().OpenShell.Admin; admin.MinProfile != "strict" {
		t.Fatalf("a persisted floor was adopted before the gateway confirmed it: %+v", admin)
	}
	unreachable := true
	f.relay.current = func(id string) (sandboxrelay.CurrentPolicy, error) {
		switch {
		case unreachable:
			return sandboxrelay.CurrentPolicy{}, sandboxrelay.ErrGatewayUnreachable
		case id == "reg-edited":
			return sandboxrelay.CurrentPolicy{}, &sandboxrelay.Error{Status: http.StatusNotFound, Reason: sandboxrelay.ReasonRegistrationUnknown}
		}
		return sandboxrelay.CurrentPolicy{V: 1, Generation: 4,
			Floor: &config.OpenShellAdminConfig{MinProfile: "balanced"}}, nil
	}
	if revoked := f.d.revalidate(context.Background()); len(revoked) != 0 || f.d.config().OpenShell.Admin.MinProfile != "strict" {
		t.Fatalf("an unreachable gateway confirmed something: %v %+v", revoked, f.d.config().OpenShell.Admin)
	}
	unreachable = false
	revoked := f.d.revalidate(context.Background())
	if len(revoked) != 1 || revoked[0].Sandbox != "dc-a" {
		t.Fatalf("revoked = %+v", revoked)
	}
	if admin := f.d.config().OpenShell.Admin; admin.MinProfile != "balanced" || (admin.AllowYolo != nil && *admin.AllowYolo) {
		t.Fatalf("floor after revalidation = %+v", admin)
	}
	if r, _ := f.d.regs.get("dc-a"); !r.Revoked {
		t.Fatal("the unknown registration stayed live")
	}
	if r, _ := f.d.regs.get("dc-b"); !r.Confirmed {
		t.Fatal("the answered registration is not confirmed")
	}
}

// A registrations file that could not be written whole is never renamed
// over the good one, and the failed registration is not kept in memory.
func TestDaemonRegistrationsSaveFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, sandboxDaemonRegistrationsFile)
	regs, err := loadDaemonRegistrations(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	restore := writeRegistrationsTemp
	t.Cleanup(func() { writeRegistrationsTemp = restore })
	writeRegistrationsTemp = func(f *os.File, data []byte) error {
		_, _ = f.Write(data[:len(data)/2])
		return syscall.ENOSPC
	}
	if err := regs.put(daemonRegistration{ID: "reg-2", Sandbox: "dc-b", UpdatedAt: time.Now()}); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("short write: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("a short write replaced the registrations file")
	}
	if _, ok := regs.get("dc-b"); ok {
		t.Fatal("an unsaved registration is kept in memory")
	}
	if reloaded, err := loadDaemonRegistrations(path); err != nil || len(reloaded.list()) != 1 {
		t.Fatalf("reload after a failed save: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			t.Fatalf("temporary file %s left behind", e.Name())
		}
	}
}

// A daemon that cannot run sandboxes now answers its own account with the
// reason, then exits by itself once nobody asks.
func TestSandboxDaemonServesWhyItCannotRun(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the peer check serves only the daemon's own uid")
	}
	dir, err := os.MkdirTemp("", "dsu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "run", "sandbox.sock")
	ln, err := BindSandboxDaemonSocket(socket)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	cause := &sandboxrelay.Error{Status: http.StatusForbidden, Reason: sandboxrelay.ReasonNotAllowed, Message: "Sandboxes are turned off for you."}
	go func() {
		done <- serveSandboxDaemonUnavailable(context.Background(), ln, cause, 200*time.Millisecond, 10*time.Second)
	}()
	client := sandboxapi.NewUnixClient(socket)
	if _, err := client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "turned off for you") {
		t.Fatalf("status: %v", err)
	}
	client.HTTP.Transport.(*http.Transport).CloseIdleConnections()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the unavailable daemon did not exit when idle")
	}
	if _, err := os.Lstat(socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket after exit: %v", err)
	}
}
