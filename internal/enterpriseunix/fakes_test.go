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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// fakeServices is an in-memory service manager.
type fakeServices struct {
	mu      sync.Mutex
	goos    string
	version int
	active  map[string]bool
	enabled map[string]bool
	// disabled units carry launchd's disabled override; Enable clears it.
	disabled  map[string]bool
	calls     []string
	failStart map[string]error
	// failed units report systemd's failed state.
	failed map[string]bool
	// restarting units are in systemd's restart delay after a run with this
	// Result ("success" for a planned restart, "exit-code" for a crash).
	// PlannedRestart reads it once, and the unit is active again after that.
	restarting map[string]string
	reloads    int
	inner      ServiceManager // definition paths and unit list
	env        *Env
}

func newFakeServices(env *Env) *fakeServices {
	inner := newServiceManager(env)
	return &fakeServices{goos: env.GOOS, version: 255, active: map[string]bool{}, enabled: map[string]bool{}, failStart: map[string]error{}, failed: map[string]bool{}, restarting: map[string]string{}, inner: inner, env: env}
}

func (f *fakeServices) Enabled(_ context.Context, u Unit) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.enabled[u.Name]
}

// FragmentPath follows systemd's search order for the two unit directories
// the lifecycle uses.
func (f *fakeServices) FragmentPath(_ context.Context, u Unit) string {
	if f.goos != "linux" {
		return ""
	}
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system"} {
		if path := filepath.Join(dir, u.Name); exists(f.env.P(path)) {
			return path
		}
	}
	return ""
}

func (f *fakeServices) record(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeServices) Check(context.Context) error            { return nil }
func (f *fakeServices) Version(context.Context) int            { return f.version }
func (f *fakeServices) Units() []Unit                          { return f.inner.Units() }
func (f *fakeServices) DefinitionPath(u Unit, c string) string { return f.inner.DefinitionPath(u, c) }
func (f *fakeServices) Reload(context.Context) error           { f.reloads++; f.record("reload"); return nil }

func (f *fakeServices) Start(_ context.Context, u Unit) error {
	f.record("start " + u.Name)
	if err := f.failStart[u.Name]; err != nil {
		return err
	}
	f.mu.Lock()
	f.active[u.Name] = true
	f.mu.Unlock()
	return nil
}

func (f *fakeServices) Restart(_ context.Context, u Unit) error {
	f.record("restart " + u.Name)
	if err := f.failStart[u.Name]; err != nil {
		return err
	}
	f.mu.Lock()
	f.active[u.Name] = true
	f.mu.Unlock()
	return nil
}

func (f *fakeServices) Stop(_ context.Context, u Unit) error {
	f.record("stop " + u.Name)
	f.mu.Lock()
	f.active[u.Name] = false
	f.mu.Unlock()
	return nil
}

func (f *fakeServices) Disabled(_ context.Context, u Unit) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disabled[u.Name]
}

func (f *fakeServices) Enable(_ context.Context, u Unit) error {
	f.record("enable " + u.Name)
	f.mu.Lock()
	f.enabled[u.Name] = true
	delete(f.disabled, u.Name)
	f.mu.Unlock()
	return nil
}

func (f *fakeServices) Disable(_ context.Context, u Unit) error {
	f.record("disable " + u.Name)
	f.mu.Lock()
	f.enabled[u.Name] = false
	f.mu.Unlock()
	return nil
}

func (f *fakeServices) Status(_ context.Context, u Unit) (enterprisestatus.Service, error) {
	state := "inactive"
	if f.isActive(u.Name) {
		state = "active"
	}
	f.mu.Lock()
	if f.failed[u.Name] {
		state = "failed/failed"
	}
	f.mu.Unlock()
	return enterprisestatus.Service{Name: u.Name, Kind: u.Kind, State: state, Required: u.Required}, nil
}

func (f *fakeServices) PlannedRestart(_ context.Context, u Unit) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	result, restarting := f.restarting[u.Name]
	if restarting {
		delete(f.restarting, u.Name)
		f.active[u.Name] = true
	}
	return result == "success"
}

func (f *fakeServices) Active(_ context.Context, u Unit) bool { return f.isActive(u.Name) }

func (f *fakeServices) isActive(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.active[name]
}

func (f *fakeServices) startOrder() []string {
	var out []string
	for _, call := range f.calls {
		if strings.HasPrefix(call, "start ") {
			out = append(out, strings.TrimPrefix(call, "start "))
		}
	}
	return out
}

// fakeAccounts is an in-memory account database.
type fakeAccounts struct {
	accounts map[string]Account
	nextID   int
}

func (a *fakeAccounts) Lookup(_ context.Context, name string) (Account, bool, error) {
	account, ok := a.accounts[name]
	return account, ok, nil
}

func (a *fakeAccounts) Ensure(ctx context.Context, name string) (Account, error) {
	if account, ok, _ := a.Lookup(ctx, name); ok {
		return account, nil
	}
	a.nextID++
	account := Account{Name: name, UID: 900 + a.nextID, GID: 900 + a.nextID}
	a.accounts[name] = account
	account.Created = true
	return account, nil
}

func (a *fakeAccounts) Remove(_ context.Context, name string) error {
	delete(a.accounts, name)
	return nil
}

// fakeRunner answers the few host commands the lifecycle runs directly.
type fakeRunner struct {
	mu       sync.Mutex
	versions map[string]string // gateway path -> version
	calls    []string
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.mu.Lock()
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	r.mu.Unlock()
	if len(args) == 1 && args[0] == "--version-json" {
		version, ok := r.versions[name]
		if !ok {
			// Installed copies answer with the version their bytes carry.
			data, err := os.ReadFile(name)
			fields := strings.Fields(string(data))
			if err != nil || len(fields) != 2 {
				return CommandResult{ExitCode: 1}, fmt.Errorf("unknown binary %s", name)
			}
			version = fields[1]
		}
		return CommandResult{Stdout: []byte(fmt.Sprintf(`{"schema_version":1,"name":"defenseclaw-gateway","version":%q}`, version))}, nil
	}
	switch name {
	case "dpkg", "rpm":
		return CommandResult{ExitCode: 1}, errors.New("not owned")
	case "restorecon":
		return CommandResult{ExitCode: -1}, fmt.Errorf("%s: %w", name, ErrCommandNotFound)
	}
	return CommandResult{}, nil
}

type testHost struct {
	t        *testing.T
	env      *Env
	services *fakeServices
	accounts *fakeAccounts
	runner   *fakeRunner
	healthy  bool
	owners   map[string][2]int
}

// publishLedger publishes ledger as the guardian's authorization ledger
// with a credential attestation of the same reconcile, for the targets.yaml
// on disk, that reports targets (by default one current row per target the
// manifest enables), as a guardian reconcile does.
func (h *testHost) publishLedger(ledger []byte, targets ...enterprisehooks.CredentialAttestationTarget) {
	h.t.Helper()
	dir := h.env.P(h.env.Layout.GuardianAuthDir)
	if err := os.WriteFile(filepath.Join(dir, managed.HookGuardianAuthorizationFile), ledger, 0o640); err != nil {
		h.t.Fatal(err)
	}
	manifest, manifestSHA256, err := enterprisehooks.LoadManifestWithSHA256(h.env.P(h.env.Layout.ManifestPath))
	if err != nil {
		manifestSHA256 = strings.Repeat("d", 64)
	}
	if len(targets) == 0 {
		for _, target := range manifest.Targets {
			if target.IsEnabled() {
				row := enterprisehooks.CredentialAttestationTarget{Connector: target.Connector, User: target.User, UserHome: target.UserHome, UID: -1, State: enterprisehooks.CredentialTargetCurrent}
				if target.UID != nil {
					row.UID = *target.UID
				}
				targets = append(targets, row)
			}
		}
	}
	sum := sha256.Sum256(ledger)
	data, _ := json.Marshal(enterprisehooks.CredentialAttestation{
		Version: enterprisehooks.CredentialAttestationVersion, ID: strings.Repeat("e", 32), UpdatedAt: "2026-09-29T00:00:00Z",
		ManifestSHA256: manifestSHA256, AuthorizationSHA256: hex.EncodeToString(sum[:]), Targets: append([]enterprisehooks.CredentialAttestationTarget{}, targets...),
	})
	if err := os.WriteFile(filepath.Join(dir, managed.HookGuardianCredentialAttestationFile), data, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func newTestHost(t *testing.T, goos string) *testHost {
	t.Helper()
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		t.Fatal(err)
	}
	h := &testHost{t: t, runner: &fakeRunner{versions: map[string]string{}}, healthy: true, owners: map[string][2]int{}}
	env := &Env{
		GOOS:           goos,
		Root:           t.TempDir(),
		Layout:         layout,
		Runner:         h.runner,
		Geteuid:        func() int { return 0 },
		Trust:          func(string, TrustKind) error { return nil },
		ProductVersion: "1.0.0",
		LockTimeout:    300 * time.Millisecond,
		ReadyTimeout:   200 * time.Millisecond,
		PollInterval:   10 * time.Millisecond,
		// No guardian runs in the fake host.
		GuardianReportTimeout: 50 * time.Millisecond,
	}
	env.Lchown = func(path string, uid, gid int) error {
		h.owners[stagedFinal(path)] = [2]int{uid, gid}
		return nil
	}
	env.OwnerOf = func(path string) (int, int, error) {
		if owner, ok := h.owners[path]; ok {
			return owner[0], owner[1], nil
		}
		uid, gid, _, err := statOwnerMode(path)
		return uid, gid, err
	}
	h.services = newFakeServices(env)
	env.Services = h.services
	h.accounts = &fakeAccounts{accounts: map[string]Account{}}
	env.Accounts = h.accounts
	// The real machine-policy writers run inside the temporary root; only
	// the root-ownership ancestor checks are off.
	env.MachinePolicy = &policyManager{env: env, skipTrust: true}
	gatewayName := unitGateway
	if goos == "darwin" {
		gatewayName = labelGateway
	}
	// The gateway's health document on its hook socket.
	env.HealthGet = func(context.Context) (int, []byte, error) {
		if h.healthy && h.services.isActive(gatewayName) {
			return 200, []byte(`{"api":{"state":"running"},"inspection":{"local":"active","ai_defense":"disabled"}}`), nil
		}
		return 0, nil, errors.New("connection refused")
	}
	// The TCP API is probed only for a gateway that refuses /health on its
	// socket; tests that model one replace this.
	env.APIHealthGet = func(context.Context) (int, []byte, error) {
		return 0, nil, errors.New("the TCP API must not be probed")
	}
	env.HookSocketPeer = func(context.Context) (peercred.Credentials, error) {
		// The gateway serves its hook socket when it is healthy.
		if h.healthy && h.services.isActive(gatewayName) {
			account := h.accounts.accounts[layout.ServiceUser]
			return peercred.Credentials{UID: account.UID, GID: account.GID}, nil
		}
		return peercred.Credentials{}, errors.New("connection refused")
	}
	env.fillDefaults()
	h.env = env
	return h
}

// payload writes a staged payload directory whose gateway reports version.
func (h *testHost) payload(version string) string {
	h.t.Helper()
	dir := h.t.TempDir()
	for _, name := range []string{binGateway, binHook, binSensorHelper, binACP} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name+" "+version+"\n"), 0o755); err != nil {
			h.t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, name), 0o755); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		h.t.Fatal(err)
	}
	h.runner.versions[filepath.Join(dir, binGateway)] = version
	return dir
}

func (h *testHost) run(opts Options) *enterprisestatus.Result {
	h.t.Helper()
	return Run(context.Background(), h.env, opts)
}

func (h *testHost) read(canonical string) string {
	h.t.Helper()
	data, err := os.ReadFile(h.env.P(canonical))
	if err != nil {
		h.t.Fatalf("read %s: %v", canonical, err)
	}
	return string(data)
}

func (h *testHost) mode(canonical string) os.FileMode {
	h.t.Helper()
	info, err := os.Lstat(h.env.P(canonical))
	if err != nil {
		h.t.Fatalf("stat %s: %v", canonical, err)
	}
	return info.Mode().Perm()
}

func requireOK(t *testing.T, r *enterprisestatus.Result) {
	t.Helper()
	if !r.OK || r.ExitCode != 0 {
		t.Fatalf("expected success, got exit=%d errors=%+v warnings=%+v", r.ExitCode, r.Errors, r.Warnings)
	}
}

func requireError(t *testing.T, r *enterprisestatus.Result, code string) {
	t.Helper()
	if r.OK {
		t.Fatalf("expected failure %s, got success", code)
	}
	for _, e := range r.Errors {
		if e.Code == code {
			return
		}
	}
	t.Fatalf("expected error %s, got %+v", code, r.Errors)
}

func hasWarning(r *enterprisestatus.Result, code string) bool {
	for _, w := range r.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

// stagedFinal maps a writeFileAtomic staging name back to its destination,
// so recorded ownership follows the rename.
func stagedFinal(path string) string {
	dir, base := filepath.Split(path)
	if strings.HasPrefix(base, ".") {
		if index := strings.LastIndex(base, ".dc-"); index > 0 {
			return filepath.Join(dir, base[1:index])
		}
	}
	return path
}
