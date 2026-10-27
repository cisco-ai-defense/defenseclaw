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

//go:build unix

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

type fakeSandboxStopper struct {
	list    []sandboxapi.Sandbox
	listErr error
	stopped []string
	fail    string
}

func (f *fakeSandboxStopper) List(context.Context) ([]sandboxapi.Sandbox, error) {
	return f.list, f.listErr
}

func (f *fakeSandboxStopper) Stop(_ context.Context, name string) (*sandboxapi.Sandbox, error) {
	if name == f.fail {
		return nil, errors.New("gateway gone")
	}
	f.stopped = append(f.stopped, name)
	return &sandboxapi.Sandbox{Name: name}, nil
}

// ExecStop stops every sandbox that may run and leaves stopped ones alone;
// a daemon that is not running has nothing to stop.
func TestStopManagedSandboxes(t *testing.T) {
	f := &fakeSandboxStopper{list: []sandboxapi.Sandbox{
		{Name: "a", Phase: "ready"}, {Name: "b", Phase: "stopped"}, {Name: "c", Phase: "provisioning"},
		{Name: "d", Phase: "unknown"}, {Name: "e", Phase: "error"},
	}}
	var out bytes.Buffer
	if err := stopManagedSandboxes(context.Background(), f, &out); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.stopped, []string{"a", "c", "d"}) || !strings.Contains(out.String(), "stopped sandbox a") {
		t.Fatalf("stopped %v, out %q", f.stopped, out.String())
	}
	f = &fakeSandboxStopper{list: []sandboxapi.Sandbox{{Name: "a", Phase: "ready"}, {Name: "b", Phase: "ready"}}, fail: "a"}
	if err := stopManagedSandboxes(context.Background(), f, &out); err == nil || !slices.Equal(f.stopped, []string{"b"}) {
		t.Fatalf("a failed stop: %v, stopped %v", err, f.stopped)
	}
	f = &fakeSandboxStopper{listErr: &sandboxapi.Error{Code: sandboxapi.CodeUnavailable, Message: "not reachable"}}
	if err := stopManagedSandboxes(context.Background(), f, &out); err != nil {
		t.Fatalf("daemon not running: %v", err)
	}
}

// unsyncedStopper answers each stop of a name in unsynced with
// sandboxapi.CodeUnsynced (its MicroVM's disk could not be synced) as many
// times as it says, then stops it.
type unsyncedStopper struct {
	fakeSandboxStopper
	unsynced map[string]int
	tries    map[string]int
}

func (f *unsyncedStopper) Stop(ctx context.Context, name string) (*sandboxapi.Sandbox, error) {
	f.tries[name]++
	if sandboxapi.DiscardUnsynced(ctx) {
		return nil, errors.New("stop-sandboxes accepted the loss of what a MicroVM has not synced")
	}
	if f.unsynced[name] != 0 {
		f.unsynced[name]--
		return nil, &sandboxapi.Error{Code: sandboxapi.CodeUnsynced, Message: "sandbox " + name + " was not stopped: its MicroVM's disk could not be synced first"}
	}
	return f.fakeSandboxStopper.Stop(ctx, name)
}

// GAP-0998: at a sign-out the gateway unit's ExecStop asked the daemon to
// stop the account's sandboxes, the daemon refused the stop of a MicroVM
// whose disk it could not sync (it never stops one then), and systemd went
// on to stop the gateway, which ended the VM with no word of what was
// lost. stop-sandboxes now tries such a stop again (it syncs first) while
// the gateway unit's stop timeout leaves time, never accepting the loss
// itself, and names a MicroVM still unsynced with what it may lose.
func TestStopSandboxesTriesAnUnsyncedMicroVMAgainAndNamesWhatItMayLose(t *testing.T) {
	pause, budget := stopUnsyncedPause, stopUnsyncedBudget
	t.Cleanup(func() { stopUnsyncedPause, stopUnsyncedBudget = pause, budget })
	stopUnsyncedPause, stopUnsyncedBudget = time.Millisecond, time.Second
	list := []sandboxapi.Sandbox{{Name: "vm", Phase: "ready", Driver: "vm"}, {Name: "dk", Phase: "ready"}}

	f := &unsyncedStopper{fakeSandboxStopper: fakeSandboxStopper{list: list}, unsynced: map[string]int{"vm": 2}, tries: map[string]int{}}
	var out bytes.Buffer
	if err := stopManagedSandboxes(context.Background(), f, &out); err != nil {
		t.Fatalf("a MicroVM whose sync worked on a later try: %v", err)
	}
	if f.tries["vm"] != 3 || !slices.Equal(f.stopped, []string{"dk", "vm"}) || !strings.Contains(out.String(), "stopped sandbox vm") {
		t.Fatalf("tries %v, stopped %v, out %q", f.tries, f.stopped, out.String())
	}

	f = &unsyncedStopper{fakeSandboxStopper: fakeSandboxStopper{list: list}, unsynced: map[string]int{"vm": 1 << 30}, tries: map[string]int{}}
	out.Reset()
	err := stopManagedSandboxes(context.Background(), f, &out)
	if err == nil || !strings.Contains(err.Error(), "sandbox vm keeps running: its MicroVM's disk could not be synced, so DefenseClaw did not stop it") ||
		!strings.Contains(err.Error(), "what its guest wrote since its last sync may be lost") {
		t.Fatalf("a MicroVM that never syncs: %v", err)
	}
	if f.tries["vm"] < 2 || slices.Contains(f.stopped, "vm") || !slices.Equal(f.stopped, []string{"dk"}) {
		t.Fatalf("tries %v, stopped %v", f.tries, f.stopped)
	}
}

func TestSandboxDaemonExitedOnItsOwn(t *testing.T) {
	env := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	if !sandboxDaemonExitedOnItsOwn(env(map[string]string{"INVOCATION_ID": "x"})) {
		t.Fatal("an ExecStop after the daemon exited would activate it again")
	}
	if sandboxDaemonExitedOnItsOwn(env(map[string]string{"INVOCATION_ID": "x", "MAINPID": "42"})) ||
		sandboxDaemonExitedOnItsOwn(env(nil)) {
		t.Fatal("skipped stopping a running daemon's sandboxes")
	}
}

// The ExecStop of a restart of the daemon unit keeps the sandboxes (the
// next daemon binds their ports again); a stop job (logout, `systemctl
// --user stop`) or anything unreadable stops them (GAP-0534).
func TestSandboxDaemonRestartKeepsSandboxes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd user units are Linux's")
	}
	jobs := sandboxDaemonJobs
	t.Cleanup(func() { sandboxDaemonJobs = jobs })
	ctx := context.Background()
	t.Setenv("INVOCATION_ID", "x")
	for _, tc := range []struct {
		out     string
		err     error
		restart bool
	}{
		{"412 defenseclaw-sandbox.service restart running\n", nil, true},
		{"413 defenseclaw-sandbox.service stop running\n", nil, false},
		{"414 defenseclaw-openshell-gateway.service restart running\n", nil, false},
		{"", errors.New("Failed to connect to bus"), false},
	} {
		sandboxDaemonJobs = func(context.Context, string) (string, error) { return tc.out, tc.err }
		if got := sandboxDaemonRestarting(ctx); got != tc.restart {
			t.Errorf("jobs %q (%v): restarting = %v", tc.out, tc.err, got)
		}
	}
	sandboxDaemonJobs = func(context.Context, string) (string, error) {
		return "412 defenseclaw-sandbox.service restart running", nil
	}
	t.Setenv("INVOCATION_ID", "")
	if sandboxDaemonRestarting(ctx) {
		t.Fatal("a stop outside systemd read as a restart")
	}
}

func TestSandboxDaemonRefusesUnmanagedHosts(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the daemon refuses root before the host check")
	}
	restore := sandboxDaemonHost
	t.Cleanup(func() { sandboxDaemonHost = restore })
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, nil, managed.ErrNoRuntimeDescriptor
	}
	if err := runSandboxDaemon(context.Background(), &bytes.Buffer{}); !errors.Is(err, errNotStandaloneManaged) {
		t.Fatalf("unmanaged host: %v", err)
	}
	if _, err := planSandboxOpenShellExec(context.Background(), "linux", nil); !errors.Is(err, errNotStandaloneManaged) {
		t.Fatalf("shim on an unmanaged host: %v", err)
	}
	var coded *exitCodeError
	if err := runSandboxDaemon(context.Background(), &bytes.Buffer{}); !errors.As(err, &coded) || coded.ExitCode() != sandboxPrerequisiteExit {
		t.Fatalf("unmanaged host exit: %v", err)
	}
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, nil, errors.New("owned by a user")
	}
	if err := runSandboxDaemon(context.Background(), &bytes.Buffer{}); err == nil || errors.Is(err, errNotStandaloneManaged) ||
		!errors.As(err, &coded) || coded.ExitCode() != sandboxPrerequisiteExit {
		t.Fatalf("untrusted descriptor: %v", err)
	}
}

// A daemon whose managed gateway is not there answers its CLI socket with
// the reason and ends cleanly (exit 0): no restart loop.
func TestSandboxDaemonWithoutTheManagedGateway(t *testing.T) {
	if runtime.GOOS != "linux" || os.Getuid() == 0 {
		t.Skip("the socket lives under XDG_RUNTIME_DIR on Linux; the daemon refuses root")
	}
	runDir, err := os.MkdirTemp("", "dsr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })
	t.Setenv("XDG_RUNTIME_DIR", runDir)
	t.Setenv("LISTEN_FDS", "")
	t.Setenv("LISTEN_PID", "")
	restore := sandboxDaemonHost
	t.Cleanup(func() { sandboxDaemonHost = restore })
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{HookSocketPath: filepath.Join(runDir, "absent", "hook.sock")}, &managed.RuntimeDescriptor{}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var logs bytes.Buffer
	done := make(chan error, 1)
	go func() { done <- runSandboxDaemon(ctx, &logs) }()
	socket := filepath.Join(runDir, "defenseclaw", "sandbox.sock")
	client := sandboxapi.NewUnixClient(socket)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := client.Status(ctx)
		if err != nil && strings.Contains(err.Error(), "not reachable") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status of a daemon without its gateway: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("exit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon did not stop")
	}
}

// On a standalone managed computer the sandbox commands never read the
// user's config.yaml (the daemon holds the settings), and a descriptor that
// cannot be trusted refuses instead of falling back to it.
func TestSandboxPreRunOnAManagedComputer(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("sandbox commands run on Linux and macOS only")
	}
	prevCfg, prevHost := cfg, sandboxHostClient
	t.Cleanup(func() { cfg, sandboxHostClient = prevCfg, prevHost })
	home := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	if err := os.WriteFile(filepath.Join(home, "config.yaml"), []byte("version: [not yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, _, err := sandboxCmd.Find([]string{"list"})
	if err != nil {
		t.Fatal(err)
	}
	sandboxHostClient = func(string) (*sandboxapi.Client, error) {
		return sandboxapi.NewUnixClient("/nonexistent/sandbox.sock"), nil
	}
	cfg = nil
	if err := sandboxPreRun(list, nil); err != nil {
		t.Fatalf("managed computer: %v", err)
	}
	if cfg == nil || cfg.DeploymentMode != "managed_enterprise" || !cfg.OpenShell.Enabled {
		t.Fatalf("managed cfg = %+v", cfg)
	}
	untrusted := errors.New("sandboxapi: the managed runtime descriptor is not trusted: owner")
	sandboxHostClient = func(string) (*sandboxapi.Client, error) { return nil, untrusted }
	var coded *exitCodeError
	if err := sandboxPreRun(list, nil); !errors.Is(err, untrusted) || !errors.As(err, &coded) || coded.ExitCode() != 3 {
		t.Fatalf("untrusted descriptor: %v", err)
	}
	sandboxHostClient = func(string) (*sandboxapi.Client, error) { return nil, sandboxapi.ErrNotManagedHost }
	if err := sandboxPreRun(list, nil); err == nil {
		t.Fatal("off a managed computer the broken config.yaml was not read")
	}
}

// The shim execs the user's own openshell-gateway with the rendered config,
// the TLS directory, umask-independent env and a pinned PATH; on macOS the
// trusted e2fsprogs comes first.
func TestPlanSandboxOpenShellExec(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the shim refuses root")
	}
	// The administrator's e2fsprogs folder below must sit under ancestors
	// every account can traverse, or the access rule refuses it first.
	root := testenv.TraversableTempDir(t)
	home := filepath.Join(root, "home")
	configDir := filepath.Join(root, "etc")
	for _, dir := range []string{filepath.Join(home, ".local", "bin"), filepath.Join(configDir, "openshell")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(home, ".local", "bin", "openshell-gateway")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	restoreHost, restoreHome, restoreFile, restoreDir, restoreSettings, restoreAdmin := sandboxDaemonHost, openShellExecHome,
		openShellExecTrustedFile, openShellExecTrustedDir, openShellExecSettings, openShellExecAdminBinary
	t.Cleanup(func() {
		sandboxDaemonHost, openShellExecHome, openShellExecTrustedFile, openShellExecTrustedDir, openShellExecSettings, openShellExecAdminBinary =
			restoreHost, restoreHome, restoreFile, restoreDir, restoreSettings, restoreAdmin
	})
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{ConfigDir: configDir}, &managed.RuntimeDescriptor{}, nil
	}
	openShellExecHome = func() (string, error) { return home, nil }
	trustedConfig := true
	openShellExecTrustedFile = func(string, string) error {
		if !trustedConfig {
			return errors.New("owned by a user")
		}
		return nil
	}
	adminE2fs, install := "", config.EnterpriseOpenShellInstallSetup
	openShellExecSettings = func(context.Context) sandboxrelay.EnterpriseOpenShell {
		return sandboxrelay.EnterpriseOpenShell{Install: install, E2fsprogsDir: adminE2fs}
	}
	openShellExecTrustedDir = func(string, string) error { return nil }
	// The account's own XDG_STATE_HOME does not reach its gateway, which
	// keeps its state in ~/.local/state (openshell.DefaultStateHome): the
	// daemon looks for the gateway's files there.
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "xdg-state"))

	plan, err := planSandboxOpenShellExec(context.Background(), "linux", []string{"--log-level", "info"})
	if err != nil {
		t.Fatal(err)
	}
	if v := envValue(plan.env, "XDG_STATE_HOME"); v != "" {
		t.Fatalf("the gateway was given XDG_STATE_HOME=%s, where the daemon does not look for its state", v)
	}
	config := filepath.Join(configDir, "openshell", "gateway.toml")
	if plan.binary != binary || !slices.Equal(plan.argv, []string{binary, "--config", config, "--log-level", "info"}) {
		t.Fatalf("plan = %+v", plan)
	}
	for _, want := range []string{
		"OPENSHELL_GATEWAY_CONFIG=" + config,
		"OPENSHELL_LOCAL_TLS_DIR=" + filepath.Join(home, ".local", "state", "openshell", "tls"),
		"PATH=" + filepath.Join(home, ".local", "bin") + ":/usr/bin:/bin:/usr/sbin:/sbin",
		"HOME=" + home,
		// Every MicroVM runs as the account whose images are built for it.
		"OPENSHELL_VM_SANDBOX_UID=" + strconv.Itoa(os.Getuid()),
		"OPENSHELL_VM_SANDBOX_GID=" + strconv.Itoa(os.Getegid()),
	} {
		if !slices.Contains(plan.env, want) {
			t.Fatalf("env lacks %q: %v", want, plan.env)
		}
	}
	// The account's local PKI is generated before the gateway starts, as
	// the upstream unit's ExecStartPre does, into a 0700 directory.
	tlsDir := filepath.Join(home, ".local", "state", "openshell", "tls")
	if plan.tlsDir != tlsDir || !slices.Equal(plan.certs, []string{"generate-certs", "--output-dir", tlsDir, "--server-san", "host.openshell.internal"}) {
		t.Fatalf("certs = %q %v", plan.tlsDir, plan.certs)
	}
	restoreCerts := openShellGenerateCerts
	t.Cleanup(func() { openShellGenerateCerts = restoreCerts })
	var generated []string
	openShellGenerateCerts = func(p openShellExecPlan) error { generated = p.certs; return nil }
	if err := generateOpenShellCerts(plan); err != nil || len(generated) == 0 {
		t.Fatalf("generate certs: %v %v", err, generated)
	}
	if info, err := os.Stat(tlsDir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("tls dir: %v %v", info, err)
	}
	openShellGenerateCerts = func(openShellExecPlan) error { return errors.New("exit status 1") }
	if err := generateOpenShellCerts(plan); err == nil || !strings.Contains(err.Error(), "generate-certs") {
		t.Fatalf("failed generate-certs: %v", err)
	}

	// macOS: no trusted e2fsprogs refuses; the user's own build, then the
	// administrator's directory, goes first on PATH.
	if err := os.WriteFile(config, []byte("[openshell.gateway]\nbind_address = '127.0.0.1:17670'\ncompute_driver = 'vm'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := planSandboxOpenShellExec(context.Background(), "darwin", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) {
		t.Fatalf("macOS without e2fsprogs: %v", err)
	}
	userSbin := filepath.Join(home, ".local", "opt", "e2fsprogs", "sbin")
	if err := os.MkdirAll(userSbin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userSbin, "mke2fs"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userSbin, "debugfs"), nil, 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err = planSandboxOpenShellExec(context.Background(), "darwin", nil)
	if err != nil || !slices.Contains(plan.env, "PATH="+userSbin+":"+filepath.Join(home, ".local", "bin")+":/usr/bin:/bin:/usr/sbin:/sbin") {
		t.Fatalf("user e2fsprogs: %v %v", err, plan.env)
	}
	// The administrator's e2fsprogs_dir follows the rule ensure checks
	// (GAP-0506): its install prefix (tools in sbin) or the folder holding
	// the tools both put that folder first; a folder without both refuses.
	adminE2fs = filepath.Join(root, "e2fsprogs")
	adminSbin := filepath.Join(adminE2fs, "sbin")
	if err := os.MkdirAll(adminSbin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(adminSbin, "mke2fs"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := planSandboxOpenShellExec(context.Background(), "darwin", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) {
		t.Fatalf("admin e2fsprogs without debugfs: %v", err)
	}
	checkDoctor := func(admin string) openshell.Check {
		d := &openshell.Doctor{GOOS: "darwin", Managed: true, AdminE2fsprogsKnown: true,
			AdminE2fsprogsDir: admin, HomeDir: func() (string, error) { return home, nil },
			TrustedE2fsprogsDir: openShellExecTrustedDir, TrustedE2fsprogsFile: openShellExecTrustedFile}
		return d.ManagedE2fsprogsCheck()
	}
	if row := checkDoctor(adminE2fs); row.Status != openshell.StatusFail || !strings.Contains(row.Detail, adminE2fs) || row.Fix == nil || !strings.Contains(row.Fix.Summary, "install prefix or the folder") {
		t.Fatalf("doctor accepted the missing debugfs: %+v", row)
	}
	if err := os.WriteFile(filepath.Join(adminSbin, "debugfs"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, configured := range []string{adminE2fs, adminSbin} {
		adminE2fs = configured
		plan, err = planSandboxOpenShellExec(context.Background(), "darwin", nil)
		if err != nil || !strings.HasPrefix(envValue(plan.env, "PATH"), adminSbin+":") {
			t.Fatalf("admin e2fsprogs %s: %v %v", configured, err, plan.env)
		}
		if row := checkDoctor(configured); row.Status != openshell.StatusPass || !strings.Contains(row.Detail, adminSbin) {
			t.Fatalf("doctor and gateway disagree on %s: %+v", configured, row)
		}
	}
	if err := os.Chmod(adminSbin, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := planSandboxOpenShellExec(context.Background(), "darwin", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) {
		t.Fatalf("private admin tool folder: %v", err)
	}
	if row := checkDoctor(adminE2fs); row.Status != openshell.StatusFail || !strings.Contains(row.Detail, "cannot be traversed") || row.Fix == nil || !strings.Contains(row.Fix.Summary, "chmod o+x") {
		t.Fatalf("doctor accepted the private tool folder: %+v", row)
	}
	if err := os.Chmod(adminSbin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(adminSbin, "debugfs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := planSandboxOpenShellExec(context.Background(), "darwin", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) {
		t.Fatalf("non-executable admin tool: %v", err)
	}
	if row := checkDoctor(adminE2fs); row.Status != openshell.StatusFail || !strings.Contains(row.Detail, "cannot be executed") {
		t.Fatalf("doctor accepted the non-executable tool: %+v", row)
	}
	if err := os.Chmod(filepath.Join(adminSbin, "debugfs"), 0o755); err != nil {
		t.Fatal(err)
	}
	openShellExecTrustedDir = func(string, string) error { return errors.New("owned by dcm-sv1") }
	if _, err := planSandboxOpenShellExec(context.Background(), "darwin", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) {
		t.Fatalf("untrusted admin e2fsprogs: %v", err)
	}
	if row := checkDoctor(adminE2fs); row.Status != openshell.StatusFail || !strings.Contains(row.Detail, "not trusted") {
		t.Fatalf("doctor accepted the untrusted folder: %+v", row)
	}
	openShellExecTrustedDir = func(string, string) error { return nil }
	baseTrustedFile := openShellExecTrustedFile
	openShellExecTrustedFile = func(path, label string) error {
		if path == filepath.Join(adminSbin, "debugfs") {
			return errors.New("owned by a user")
		}
		return baseTrustedFile(path, label)
	}
	if _, err := planSandboxOpenShellExec(context.Background(), "darwin", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) {
		t.Fatalf("untrusted admin tool: %v", err)
	}
	if row := checkDoctor(adminE2fs); row.Status != openshell.StatusFail || !strings.Contains(row.Detail, "not trusted") {
		t.Fatalf("doctor accepted the untrusted tool: %+v", row)
	}
	openShellExecTrustedFile = baseTrustedFile

	// An untrusted rendered config or a binary another account can change
	// refuses.
	trustedConfig = false
	if _, err := planSandboxOpenShellExec(context.Background(), "linux", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) {
		t.Fatalf("untrusted config: %v", err)
	}
	trustedConfig = true
	if err := os.Chmod(binary, 0o772); err != nil {
		t.Fatal(err)
	}
	if _, err := planSandboxOpenShellExec(context.Background(), "linux", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) {
		t.Fatalf("group-writable gateway binary: %v", err)
	}
}

// Prerequisite mode (GAP-0186, GAP-0221, GAP-0377): the shim execs the
// administrator's openshell-gateway on the rendered configuration, whatever
// the account has in ~/.local/bin, and refuses an administrator's binary an
// account could have changed. An unreachable managed gateway falls back on
// what the account has.
func TestPlanSandboxOpenShellExecPrerequisite(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the shim refuses root")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	configDir := filepath.Join(root, "etc")
	adminDir := filepath.Join(root, "usr", "bin")
	for _, dir := range []string{filepath.Join(home, ".local", "bin"), filepath.Join(configDir, "openshell"), adminDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	admin := filepath.Join(adminDir, "openshell-gateway")
	if err := os.WriteFile(admin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	restoreHost, restoreHome, restoreFile, restoreSettings, restoreAdmin, restoreVMDriver := sandboxDaemonHost, openShellExecHome,
		openShellExecTrustedFile, openShellExecSettings, openShellExecAdminBinary, openShellExecRenderedVMDriver
	t.Cleanup(func() {
		sandboxDaemonHost, openShellExecHome, openShellExecTrustedFile, openShellExecSettings, openShellExecAdminBinary, openShellExecRenderedVMDriver =
			restoreHost, restoreHome, restoreFile, restoreSettings, restoreAdmin, restoreVMDriver
	})
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{ConfigDir: configDir}, &managed.RuntimeDescriptor{}, nil
	}
	openShellExecHome = func() (string, error) { return home, nil }
	var untrusted string
	openShellExecTrustedFile = func(path, _ string) error {
		if path == untrusted {
			return errors.New("owned by a user")
		}
		return nil
	}
	openShellExecAdminBinary = func(_, name string, trusted func(string) error) (string, error) {
		if name != "openshell-gateway" {
			t.Fatalf("looked up %q", name)
		}
		if err := trusted(admin); err != nil {
			return "", err
		}
		return admin, nil
	}
	install := config.EnterpriseOpenShellInstallPrerequisite
	openShellExecSettings = func(context.Context) sandboxrelay.EnterpriseOpenShell {
		return sandboxrelay.EnterpriseOpenShell{Install: install}
	}
	// A gateway the account has of its own is not what prerequisite mode runs.
	if err := os.WriteFile(filepath.Join(home, ".local", "bin", "openshell-gateway"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(configDir, "openshell", "gateway.toml")
	writeConfig := func(driver openshell.ComputeDriver, dir string) {
		t.Helper()
		data, err := (openshell.RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: driver, DriverDir: dir}).TOML()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfgPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeConfig(openshell.DriverDocker, "")

	plan, err := planSandboxOpenShellExec(context.Background(), "linux", nil)
	if err != nil {
		t.Fatal(err)
	}
	if plan.binary != admin || !slices.Equal(plan.argv, []string{admin, "--config", cfgPath}) {
		t.Fatalf("plan = %+v", plan)
	}
	if got, want := envValue(plan.env, "PATH"), adminDir+":/usr/bin:/bin:/usr/sbin:/sbin"; got != want {
		t.Fatalf("PATH = %q, want %q", got, want)
	}
	for _, want := range []string{"OPENSHELL_GATEWAY_CONFIG=" + cfgPath, "OPENSHELL_VM_SANDBOX_UID=" + strconv.Itoa(os.Getuid())} {
		if !slices.Contains(plan.env, want) {
			t.Fatalf("env lacks %q: %v", want, plan.env)
		}
	}
	if strings.Contains(envValue(plan.env, "PATH"), ".local") {
		t.Fatalf("PATH holds the account's folder: %s", envValue(plan.env, "PATH"))
	}

	// An older rendered VM path overrides OpenShell's conventional search.
	// The shim refuses it before the gateway would wait and exit, even when
	// the administrator has moved the trusted driver to another accepted dir.
	openShellExecRenderedVMDriver = func(_, dir string) (string, string) {
		if dir == "/usr/local/libexec/openshell" {
			return dir + "/openshell-driver-vm", ""
		}
		return "", "the rendered MicroVM driver_dir " + dir + " has no executable openshell-driver-vm"
	}
	writeConfig(openshell.DriverVM, "/usr/libexec/openshell")
	if _, err := planSandboxOpenShellExec(context.Background(), "linux", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) ||
		!strings.Contains(err.Error(), "/usr/libexec/openshell") {
		t.Fatalf("stale rendered driver_dir: %v", err)
	}
	writeConfig(openshell.DriverVM, "/usr/local/libexec/openshell")
	if _, err := planSandboxOpenShellExec(context.Background(), "linux", nil); err != nil {
		t.Fatalf("rendered driver_dir with the trusted driver: %v", err)
	}
	writeConfig(openshell.DriverDocker, "")

	// The administrator's binary an account could change is refused, with
	// what to do.
	untrusted = admin
	if _, err := planSandboxOpenShellExec(context.Background(), "linux", nil); !errors.Is(err, errOpenShellPrerequisiteMissing) ||
		!strings.Contains(err.Error(), "prerequisite") {
		t.Fatalf("untrusted administrator binary: %v", err)
	}
	untrusted = ""

	// No answer from the managed gateway: the account's own OpenShell is
	// setup mode's, none at all is the administrator's.
	install = ""
	if plan, err := planSandboxOpenShellExec(context.Background(), "linux", nil); err != nil || plan.binary == admin {
		t.Fatalf("unreachable with an own gateway: %+v %v", plan, err)
	}
	if err := os.Remove(filepath.Join(home, ".local", "bin", "openshell-gateway")); err != nil {
		t.Fatal(err)
	}
	if plan, err := planSandboxOpenShellExec(context.Background(), "linux", nil); err != nil || plan.binary != admin {
		t.Fatalf("unreachable without one: %+v %v", plan, err)
	}
}

// The units run the commands this binary has: the daemon socket is 0600
// and holds no TCP port, ExecStop stops the sandboxes, both services run
// with UMask 0022, and the LaunchAgents load in GUI and SSH sessions.
func TestSandboxDaemonUnitsMatchTheCommands(t *testing.T) {
	read := func(rel string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", rel))
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	socket := read("packaging/systemd/user/defenseclaw-sandbox.socket")
	for _, want := range []string{"ListenStream=%t/defenseclaw/sandbox.sock\n", "FileDescriptorName=sandbox\n", "SocketMode=0600\n", "DirectoryMode=0700\n"} {
		if !strings.Contains(socket, want) {
			t.Fatalf("socket unit lacks %q", want)
		}
	}
	if strings.Count(socket, "ListenStream=") != 1 {
		t.Fatal("the socket unit holds more than the CLI socket (D3)")
	}
	service := read("packaging/systemd/user/defenseclaw-sandbox.service")
	gatewaySvc := read("packaging/systemd/user/defenseclaw-openshell-gateway.service")
	for _, want := range []string{
		"ExecStart=/opt/defenseclaw/bin/defenseclaw-gateway " + sandboxDaemonCmd.Name() + "\n",
		"ExecStop=/opt/defenseclaw/bin/defenseclaw-gateway " + sandboxDaemonCmd.Name() + " " + sandboxDaemonStopCmd.Name() + "\n",
		"UMask=0022\n",
	} {
		if !strings.Contains(service, want) {
			t.Fatalf("daemon unit lacks %q", want)
		}
	}
	for _, want := range []string{
		"ExecStart=/opt/defenseclaw/bin/defenseclaw-gateway " + sandboxOpenShellExecCmd.Name() + "\n",
		// A stop or restart of the gateway stops the account's sandboxes
		// first, so no MicroVM is left in Error (GAP-0281).
		"ExecStop=-/opt/defenseclaw/bin/defenseclaw-gateway " + sandboxDaemonCmd.Name() + " " + sandboxDaemonStopCmd.Name() + "\n",
		"UMask=0022\n", "Restart=on-failure\n",
	} {
		if !strings.Contains(gatewaySvc, want) {
			t.Fatalf("OpenShell gateway unit lacks %q", want)
		}
	}
	// A missing prerequisite (an account without OpenShell) is never
	// restarted, any other failure only up to the start limit, and the
	// OpenShell gateway never starts at login: it would hold its port for
	// whichever account logs in first.
	for name, unit := range map[string]string{"daemon": service, "OpenShell gateway": gatewaySvc} {
		for _, want := range []string{"RestartPreventExitStatus=" + strconv.Itoa(sandboxPrerequisiteExit) + "\n", "StartLimitIntervalSec=", "StartLimitBurst="} {
			if !strings.Contains(unit, want) {
				t.Fatalf("%s unit lacks %q", name, want)
			}
		}
	}
	if strings.Contains(gatewaySvc, "\n[Install]") || strings.Contains(gatewaySvc, "\nWantedBy=") {
		t.Fatal("the OpenShell gateway unit starts at login")
	}
	for _, plist := range []struct{ file, command string }{
		{"packaging/launchd-standalone/agents/com.cisco.defenseclaw.sandbox.plist", sandboxDaemonCmd.Name()},
		{"packaging/launchd-standalone/agents/com.cisco.defenseclaw.openshell-gateway.plist", sandboxOpenShellExecCmd.Name()},
	} {
		body := read(plist.file)
		for _, want := range []string{"<string>" + plist.command + "</string>", "<string>Aqua</string>", "<string>Background</string>",
			"<key>Umask</key>\n\t<integer>18</integer>", "<key>ThrottleInterval</key>"} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s lacks %q", plist.file, want)
			}
		}
		// launchd loads /Library/LaunchAgents at every login; RunAtLoad or
		// KeepAlive (its SuccessfulExit implies RunAtLoad) would start the
		// agent for every account and restart it in a loop where it cannot
		// run. The launcher starts it on demand.
		for _, never := range []string{"<key>RunAtLoad</key>", "<key>KeepAlive</key>"} {
			if strings.Contains(body, never) {
				t.Fatalf("%s has %s", plist.file, never)
			}
		}
	}
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}
