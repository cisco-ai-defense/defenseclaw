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
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
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
	disabled map[string]bool
	// masked units (systemctl mask) refuse Enable until Unmask.
	masked    map[string]bool
	calls     []string
	failStart map[string]error
	// failed units report systemd's failed state.
	failed map[string]bool
	// keepActiveOnStop models a systemd stop that returns while a helper is
	// still active; a later start is then a successful no-op.
	keepActiveOnStop map[string]bool
	afterStart       func(Unit)
	afterRestart     func(Unit)
	// restarting units are in systemd's restart delay after a run with this
	// Result ("success" for a planned restart, "exit-code" for a crash).
	// PlannedRestart reads it once, and the unit is active again after that.
	restarting map[string]string
	// activating units are running a oneshot start (systemd "activating").
	activating map[string]bool
	// pids are the main process ids Status reports for active units.
	pids    map[string]int
	reloads int
	// failReloadOnce makes the next Reload fail (a failure before the services start).
	failReloadOnce bool
	inner          ServiceManager // definition paths and unit list
	env            *Env
	// observe, when set, sees every call as it is made.
	observe func(call string)
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

// DropInPaths lists the unit's drop-ins in /etc/systemd/system.
func (f *fakeServices) DropInPaths(_ context.Context, u Unit) []string {
	if f.goos != "linux" {
		return nil
	}
	dir := filepath.Join("/etc/systemd/system", u.Name+".d")
	entries, _ := os.ReadDir(f.env.P(dir))
	var out []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".conf") {
			out = append(out, filepath.Join(dir, entry.Name()))
		}
	}
	return out
}

func (f *fakeServices) record(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	observe := f.observe
	f.mu.Unlock()
	if observe != nil {
		observe(call)
	}
}

func (f *fakeServices) Check(context.Context) error            { return nil }
func (f *fakeServices) Version(context.Context) int            { return f.version }
func (f *fakeServices) Units() []Unit                          { return f.inner.Units() }
func (f *fakeServices) DefinitionPath(u Unit, c string) string { return f.inner.DefinitionPath(u, c) }
func (f *fakeServices) Reload(context.Context) error {
	f.reloads++
	f.record("reload")
	if f.failReloadOnce {
		f.failReloadOnce = false
		return errors.New("fake: daemon-reload failed")
	}
	return nil
}

func (f *fakeServices) Start(_ context.Context, u Unit) error {
	f.record("start " + u.Name)
	if err := f.failStart[u.Name]; err != nil {
		return err
	}
	f.mu.Lock()
	f.active[u.Name] = true
	f.mu.Unlock()
	if f.afterStart != nil {
		f.afterStart(u)
	}
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
	if f.afterRestart != nil {
		f.afterRestart(u)
	}
	return nil
}

func (f *fakeServices) Stop(_ context.Context, u Unit) error {
	f.record("stop " + u.Name)
	f.mu.Lock()
	if !f.keepActiveOnStop[u.Name] {
		f.active[u.Name] = false
	}
	f.mu.Unlock()
	return nil
}

// StopTogether stops the units in one request, as systemctl stop does
// with several names.
func (f *fakeServices) StopTogether(_ context.Context, units []Unit) error {
	for _, u := range units {
		f.record("stop " + u.Name)
	}
	f.mu.Lock()
	for _, u := range units {
		f.active[u.Name] = false
	}
	f.mu.Unlock()
	return nil
}

func (f *fakeServices) Disabled(_ context.Context, u Unit) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.disabled[u.Name]
}

func (f *fakeServices) ResetFailed(_ context.Context, u Unit) error {
	f.record("reset-failed " + u.Name)
	f.mu.Lock()
	delete(f.failed, u.Name)
	f.mu.Unlock()
	return nil
}

func (f *fakeServices) Masked(_ context.Context, u Unit) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.masked[u.Name]
}

func (f *fakeServices) Unmask(_ context.Context, u Unit) error {
	f.record("unmask " + u.Name)
	f.mu.Lock()
	delete(f.masked, u.Name)
	f.mu.Unlock()
	return nil
}

func (f *fakeServices) Enable(_ context.Context, u Unit) error {
	f.record("enable " + u.Name)
	if f.Masked(context.Background(), u) {
		return fmt.Errorf("systemctl enable %s: exit 1: Failed to enable unit: Unit file is masked", u.Name)
	}
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
	if f.activating[u.Name] {
		state = "activating/start"
	}
	pid := 0
	if f.active[u.Name] {
		pid = f.pids[u.Name]
	}
	f.mu.Unlock()
	return enterprisestatus.Service{Name: u.Name, Kind: u.Kind, State: state, PID: pid, Required: u.Required}, nil
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

const fakeAppliedPolicyDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// fakeRunner answers the few host commands the lifecycle runs directly.
type fakeRunner struct {
	mu       sync.Mutex
	versions map[string]string // gateway path -> version
	calls    []string
	ps       string // what ps -axo pid=,uid=,comm= prints (macOS)
	// A healthy installed gateway computes the generation the lifecycle
	// recorded. Tests of a rejected digest replace this answer explicitly.
	installedGateway string
	policyState      func() configwrite.GenerationState
	// replies answer a command by filepath.Base(name) and its joined args.
	replies map[string]fakeReply
	// acls are the macOS ACL entries of rooted paths, as ls -le prints them;
	// chmod -h -a# <index> removes one of them.
	acls map[string][]string
}

type fakeReply struct {
	result CommandResult
	err    error
}

func (r *fakeRunner) Run(_ context.Context, name string, args ...string) (CommandResult, error) {
	r.mu.Lock()
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	r.mu.Unlock()
	if reply, ok := r.replies[filepath.Base(name)+" "+strings.Join(args, " ")]; ok {
		return reply.result, reply.err
	}
	if name == r.installedGateway && strings.Join(args, " ") == "policy digest --json" && r.policyState != nil {
		state := r.policyState()
		return CommandResult{Stdout: []byte(fmt.Sprintf(`{"effective_digest":%q,"config_generation":%d}`,
			fakeAppliedPolicyDigest, state.Generation))}, nil
	}
	if strings.HasPrefix(strings.Join(args, " "), "enterprise hooks native-otlp-check ") {
		return CommandResult{Stdout: []byte(`{"ok":true,"accounts":0,"findings":[]}`)}, nil
	}
	if strings.HasPrefix(strings.Join(args, " "), "enterprise hooks remove-all ") {
		return CommandResult{Stdout: []byte(`{"ok":true,"removed":0}`)}, nil
	}
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
	case "ps":
		return CommandResult{Stdout: []byte(r.ps)}, nil
	case "ls":
		r.mu.Lock()
		defer r.mu.Unlock()
		var out strings.Builder
		for _, path := range args[2:] {
			fmt.Fprintf(&out, "-rw-r--r--+ 1 root  wheel  0 Oct  9 04:09 %s\n", path)
			for index, entry := range r.acls[path] {
				fmt.Fprintf(&out, " %d: %s\n", index, entry)
			}
		}
		return CommandResult{Stdout: []byte(out.String())}, nil
	case "chmod":
		r.mu.Lock()
		defer r.mu.Unlock()
		path := args[len(args)-1]
		if len(args) == 4 && args[0] == "-h" && args[1] == "-a#" {
			index, err := strconv.Atoi(args[2])
			if entries := r.acls[path]; err == nil && index >= 0 && index < len(entries) {
				r.acls[path] = slices.Delete(slices.Clone(entries), index, index+1)
				if len(r.acls[path]) == 0 {
					delete(r.acls, path)
				}
				return CommandResult{}, nil
			}
			return CommandResult{ExitCode: 1}, fmt.Errorf("chmod: no ACL entry %s on %s", args[2], path)
		}
		delete(r.acls, path)
		return CommandResult{}, nil
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
	if goos == "darwin" {
		// A fake macOS host never reads a real process's argv: the fake ps
		// lists made-up PIDs, and kern.procargs2 of a live PID with the same
		// number would decide the session instead of the ps line. Tests that
		// model argv replace this after newTestHost (setDarwinProcessArgv).
		previous := darwinProcessArgv
		darwinProcessArgv = func(int) ([]string, error) { return nil, errors.New("fake macOS host: no process argv") }
		t.Cleanup(func() { darwinProcessArgv = previous })
	}
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
	if goos == "darwin" {
		// Nor its executable: kern.procargs2 and proc_pidpath of a live PID
		// with a fake session's number named that process's image, so a
		// supported npm Claude was judged by whatever ran under that PID on
		// the macOS runner (TestManagedClaudeSupportedNPMScriptLaunchStaysCovered
		// failed whenever PID 7181 was alive). Tests that model images set
		// ProcessExecPath or ProcessImagePath after newTestHost.
		env.ProcessExecPath = func(int) (string, error) { return "", errors.New("fake macOS host: no process executable") }
		env.ProcessImagePath = func(int) (string, error) { return "", errors.New("fake macOS host: no process image") }
	}
	h.runner.installedGateway = filepath.Join(env.P(layout.BinDir), binGateway)
	h.runner.policyState = func() configwrite.GenerationState {
		state, _ := configwrite.ReadGenerationState(env.P(layout.ConfigPath))
		return state
	}
	env.Lchown = func(path string, uid, gid int) error {
		h.owners[stagedFinal(path)] = [2]int{uid, gid}
		return nil
	}
	env.Fchown = func(f *os.File, uid, gid int) error {
		h.owners[f.Name()] = [2]int{uid, gid}
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
			state := h.runner.policyState()
			return 200, []byte(fmt.Sprintf(`{"api":{"state":"running"},"policy":{"effective_digest":%q,"config_generation":%d,"bundle_id":%q,"bundle_version":%d},"inspection":{"local":"active","ai_defense":"disabled"}}`,
				fakeAppliedPolicyDigest, state.Generation, state.BundleID, state.BundleVersion)), nil
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
	// The fake host's Docker engine answers; tests that stop it replace this.
	env.DockerEngine = func(context.Context, string) error { return nil }
	env.fillDefaults()
	h.env = env
	if goos == "linux" {
		// An empty fake process table still has a boot-time record. Tests
		// that need an unavailable process scan remove this file explicitly.
		stat := env.P("/proc/stat")
		if err := os.MkdirAll(filepath.Dir(stat), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stat, []byte(fmt.Sprintf("btime %d\n", time.Now().Unix())), 0o644); err != nil {
			t.Fatal(err)
		}
		// Tests of unrelated lifecycle behavior need explicit, readable
		// kernel facts before status can claim complete security. Tests for
		// open or unavailable controls replace or remove these fake values.
		writeHostFile(t, h, sysctlMaxUserNamespaces, "0\n")
		writeHostFile(t, h, sysctlPtraceScope, "2\n")
	}
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
	result := Run(context.Background(), h.env, opts)
	if (opts.Action == ActionInstall || opts.Action == ActionEnsure) && result.OK && result.Installed {
		// The fake enumerator never publishes its first empty record. Real
		// status must wait for that record before claiming complete coverage.
		path := h.env.P(enterprisehooks.UnprotectedAgentsPath(h.env.Layout.ManifestPath))
		if _, err := os.Stat(path); err == nil {
			return result
		} else if !os.IsNotExist(err) {
			h.t.Fatal(err)
		}
		data, err := enterprisehooks.MarshalUnprotectedAgents(nil)
		if err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
	return result
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
