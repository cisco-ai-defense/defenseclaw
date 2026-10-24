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
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// fakeSandboxOps is the account side of the sandbox lifecycle.
type fakeSandboxOps struct {
	mu        sync.Mutex
	accounts  []SandboxAccount
	loggedIn  []SandboxAccount
	status    map[int]SandboxStatus
	statusErr map[int]error
	groups    map[string][]string
	stops     []string
	teardowns []string
	reloads   []string
	stopErr   error
	// events is every Stop, StopSandboxes and Teardown in the order they ran.
	events      []string
	teardownErr error
	// running names, per uid, the sandboxes StopSandboxes stops.
	running          map[int][]string
	stopSandboxesErr error
	// onTeardown does to the account's home what the real teardown does.
	onTeardown func(SandboxAccount)
	// onDrain answers the account's drain (Drain): nil lets it hold the
	// gateway. order is every drain, its release and every Stop, in the
	// order they ran.
	onDrain func(SandboxAccount) error
	order   []string
	// onOp sees every Stop (as "stop <units>"), the drain before its check
	// ("drain") and once it holds ("drained"), and every release, as each
	// begins.
	onOp func(a SandboxAccount, op string)
}

func (f *fakeSandboxOps) op(a SandboxAccount, op string) {
	f.mu.Lock()
	hook := f.onOp
	f.mu.Unlock()
	if hook != nil {
		hook(a, op)
	}
}

func (f *fakeSandboxOps) Accounts(context.Context) []SandboxAccount { return f.accounts }
func (f *fakeSandboxOps) LoggedIn(context.Context) []SandboxAccount { return f.loggedIn }
func (f *fakeSandboxOps) Status(_ context.Context, a SandboxAccount) (SandboxStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status[a.UID], f.statusErr[a.UID]
}

func (f *fakeSandboxOps) Stop(_ context.Context, a SandboxAccount, scope StopScope) error {
	var parts []string
	for _, item := range []struct {
		scope StopScope
		name  string
	}{{StopKill, "kill"}, {StopDaemon, "daemon"}, {StopGateway, "gateway"}, {StopSocket, "socket"}} {
		if scope&item.scope != 0 {
			parts = append(parts, item.name)
		}
	}
	f.op(a, "stop "+strings.Join(parts, "+"))
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stops = append(f.stops, a.Name+":"+strings.Join(parts, "+"))
	f.events = append(f.events, "stop "+a.Name)
	f.order = append(f.order, "stop "+a.Name+":"+strings.Join(parts, "+"))
	return f.stopErr
}

func (f *fakeSandboxOps) Drain(_ context.Context, a SandboxAccount) (func() error, error) {
	f.op(a, "drain")
	f.mu.Lock()
	onDrain := f.onDrain
	f.mu.Unlock()
	if onDrain != nil {
		if err := onDrain(a); err != nil {
			f.mu.Lock()
			f.order = append(f.order, "drain refused "+a.Name)
			f.mu.Unlock()
			return nil, err
		}
	}
	f.op(a, "drained")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.order = append(f.order, "drain "+a.Name)
	return func() error {
		f.op(a, "release")
		f.mu.Lock()
		defer f.mu.Unlock()
		f.order = append(f.order, "release "+a.Name)
		return nil
	}, nil
}

func (f *fakeSandboxOps) Reload(_ context.Context, a SandboxAccount) error {
	f.reloads = append(f.reloads, a.Name)
	return nil
}

func (f *fakeSandboxOps) StopSandboxes(_ context.Context, a SandboxAccount) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, "stop-sandboxes "+a.Name)
	return f.running[a.UID], f.stopSandboxesErr
}

func (f *fakeSandboxOps) Teardown(_ context.Context, a SandboxAccount) error {
	f.teardowns = append(f.teardowns, a.Name)
	f.events = append(f.events, "teardown "+a.Name)
	if f.onTeardown != nil {
		f.onTeardown(a)
	}
	return f.teardownErr
}

func (f *fakeSandboxOps) Groups(_ context.Context, a SandboxAccount) ([]string, error) {
	return f.groups[a.Name], nil
}

func (f *fakeSandboxOps) stopped() []string { return append([]string(nil), f.stops...) }

// osHost is a test host with the sandbox subsystem faked: unit definitions
// and the account side.
type osHost struct {
	*testHost
	ops        *fakeSandboxOps
	alice      SandboxAccount
	payloadDir string
}

const fakeSocketUnit = "[Unit]\nDescription=fake\n[Socket]\nListenStream=%t/defenseclaw/sandbox.sock\n[Install]\nWantedBy=sockets.target\n"

func newOSHost(t *testing.T, goos string) *osHost {
	t.Helper()
	h := newTestHost(t, goos)
	requireNoHostInstall(t, h.env.Layout)
	h.env.UserUnitSource = func(name string) ([]byte, error) {
		switch {
		case name == userUnitSandboxSocket:
			return []byte(fakeSocketUnit), nil
		case strings.HasSuffix(name, ".plist"):
			return []byte("<?xml version=\"1.0\"?>\n<plist version=\"1.0\"><dict><key>Label</key><string>" + strings.TrimSuffix(name, ".plist") +
				"</string><key>EnvironmentVariables</key><dict></dict></dict></plist>\n"), nil
		}
		return []byte("[Unit]\nDescription=fake " + name + "\n[Service]\nExecStart=/opt/defenseclaw/bin/defenseclaw-gateway sandbox-daemon\n"), nil
	}
	home := "/home/alice"
	if goos == "darwin" {
		home = "/Users/alice"
	}
	alice := SandboxAccount{Name: "alice", UID: os.Getuid(), GID: os.Getgid(), Home: home}
	if err := os.MkdirAll(h.env.P(home), 0o755); err != nil {
		t.Fatal(err)
	}
	old := sandboxHostArch
	sandboxHostArch = "arm64"
	t.Cleanup(func() { sandboxHostArch = old })
	ops := &fakeSandboxOps{accounts: []SandboxAccount{alice}, status: map[int]SandboxStatus{}, statusErr: map[int]error{}, groups: map[string][]string{}}
	h.env.SandboxUsers = ops
	return &osHost{testHost: h, ops: ops, alice: alice}
}

// sandboxConfig is the published sample config with the sandbox subsystem
// on and enterprise.openshell set by mutate.
func sandboxConfig(t *testing.T, goos string, on bool, settings map[string]any) []byte {
	t.Helper()
	file := "linux-standalone.yaml"
	if goos == "darwin" {
		file = "macos-standalone.yaml"
	}
	var doc map[string]any
	if err := yaml.Unmarshal(readSampleConfig(t, file), &doc); err != nil {
		t.Fatal(err)
	}
	if on {
		doc["openshell"] = map[string]any{"enabled": true}
	}
	enterprise := doc["enterprise"].(map[string]any)
	if settings != nil {
		enterprise["openshell"] = settings
	}
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (h *osHost) ensure(cfg []byte) *enterprisestatus.Result {
	h.t.Helper()
	return h.run(Options{Action: ActionEnsure, PayloadDir: h.payloadOnce(), ConfigFile: writeTempConfig(h.t, cfg)})
}

// GAP-0754: a rejected candidate cannot publish its own prerequisite result.
// Users continue under the previously applied sandbox settings.
func TestRefusedOpenShellSetupPinKeepsAppliedPrerequisites(t *testing.T) {
	h := newOSHost(t, "darwin")
	h.writeExecutables(t, openshell.PackageE2fsprogsDir+"/sbin/mke2fs", openshell.PackageE2fsprogsDir+"/sbin/debugfs", "/usr/local/bin/docker")
	h.env.Trust = func(string, TrustKind) error { return nil }
	valid := sandboxConfig(t, "darwin", true, map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5"})
	requireOK(t, h.ensure(valid))
	before := h.read(h.env.prerequisitesPath())
	var record openshell.PrerequisitesRecord
	if err := json.Unmarshal([]byte(before), &record); err != nil || !record.Ready {
		t.Fatalf("applied prerequisites = %+v, %v", record, err)
	}
	r := h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "setup", "driver": "vm"}))
	if r.OK || !strings.Contains(fmt.Sprint(r.Errors), "enterprise.openshell.version") {
		t.Fatalf("missing pin was accepted: %+v", r)
	}
	if after := h.read(h.env.prerequisitesPath()); after != before {
		t.Errorf("refused ensure changed prerequisites.json:\nbefore: %s\nafter: %s", before, after)
	}
}

// Releases through 1.0.3 refused an enabled unpinned setup config, so no
// genuine deployment record can authorize one. Even a manually altered
// record must not make the missing install pin acceptable.
func TestUnpinnedSetupCannotUseMatchingDeploymentRecord(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newOSHost(t, goos)
			pinned := sandboxConfig(t, goos, true, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5"})
			requireOK(t, h.ensure(pinned))
			beforePrerequisites := h.read(h.env.prerequisitesPath())
			beforeApplied := h.env.loadOpenShellState().Applied
			if beforeApplied == nil || beforeApplied.Version != "0.1.5" {
				t.Fatalf("initial setup state = %+v", beforeApplied)
			}

			unpinned := sandboxConfig(t, goos, true, map[string]any{"install": "setup", "driver": "docker"})
			if err := os.WriteFile(h.env.P(h.env.Layout.ConfigPath), unpinned, 0o640); err != nil {
				t.Fatal(err)
			}
			record, err := h.env.loadDeployment()
			if err != nil {
				t.Fatal(err)
			}
			record.ConfigSHA256 = sha256Bytes(unpinned)
			if err := h.env.saveDeployment(record); err != nil {
				t.Fatal(err)
			}

			r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payloadOnce()})
			if r.OK || !strings.Contains(fmt.Sprint(r.Errors), "enterprise.openshell.version") {
				t.Fatalf("matched record bypassed setup pin refusal: errors %+v, warnings %+v", r.Errors, r.Warnings)
			}
			if got := h.read(h.env.Layout.ConfigPath); got != string(unpinned) {
				t.Errorf("refusal changed installed config")
			}
			if got := h.env.loadOpenShellState().Applied; got == nil || got.Version != beforeApplied.Version {
				t.Errorf("refusal changed applied setup: %+v", got)
			}
			if got := h.read(h.env.prerequisitesPath()); got != beforePrerequisites {
				t.Errorf("refusal changed prerequisites")
			}
		})
	}
}

// payloadOnce stages one payload per host, so repeated ensures see the same
// binaries.
func (h *osHost) payloadOnce() string {
	if h.payloadDir == "" {
		h.payloadDir = h.payload("1.0.0")
	}
	return h.payloadDir
}

func (h *osHost) exists(canonical string) bool {
	_, err := os.Lstat(h.env.P(canonical))
	return err == nil
}

func (h *osHost) link(canonical string) string {
	target, err := os.Readlink(h.env.P(canonical))
	if err != nil {
		return ""
	}
	return target
}

func rowState(r *enterprisestatus.Result, name string) (string, bool) {
	for _, s := range r.Services {
		if s.Name == name && s.Kind == sandboxRowKind {
			return s.State, true
		}
	}
	return "", false
}

func sha(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------

// Every install mode with every driver renders the gateway configuration,
// installs the user units, the enable link and the launcher, and a second
// ensure changes nothing.
func TestSandboxFilesForEachModeAndDriver(t *testing.T) {
	cases := []struct {
		name, goos string
		settings   map[string]any
		driver     string
		wantVM     bool
	}{
		{"linux prerequisite docker", "linux", map[string]any{"install": "prerequisite", "driver": "docker"}, "docker", false},
		{"linux prerequisite vm", "linux", map[string]any{"install": "prerequisite", "driver": "vm"}, "vm", true},
		{"linux setup vm", "linux", map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5", "gateway_port": 17700}, "vm", true},
		{"linux setup docker", "linux", map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5"}, "docker", false},
		{"macos prerequisite vm", "darwin", map[string]any{"install": "prerequisite"}, "vm", true},
		{"macos setup vm", "darwin", map[string]any{"install": "setup", "version": "0.1.5"}, "vm", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newOSHost(t, c.goos)
			cfg := sandboxConfig(t, c.goos, true, c.settings)
			requireOK(t, h.ensure(cfg))

			toml := h.read(h.env.renderedTOMLPath())
			wantPort := 17670
			if p, ok := c.settings["gateway_port"].(int); ok {
				wantPort = p
			}
			for _, want := range []string{fmt.Sprintf("bind_address = '127.0.0.1:%d'", wantPort), "compute_driver = '" + c.driver + "'"} {
				if !strings.Contains(toml, want) {
					t.Errorf("gateway.toml lacks %q:\n%s", want, toml)
				}
			}
			// The MicroVM driver's table is there, but names no uid or gid:
			// the file is the same for every account, whose own identity the
			// exec shim gives its gateway (GAP-0254).
			if c.wantVM != strings.Contains(toml, "[openshell.drivers.vm]") {
				t.Errorf("MicroVM driver table = %v, want %v:\n%s", !c.wantVM, c.wantVM, toml)
			}
			if strings.Contains(toml, "sandbox_uid") || strings.Contains(toml, "sandbox_gid") {
				t.Errorf("gateway.toml names a MicroVM identity for every account:\n%s", toml)
			}
			if got := h.mode(h.env.renderedTOMLPath()); got != 0o644 {
				t.Errorf("gateway.toml mode %04o", got)
			}
			if env := h.read(h.env.renderedEnvPath()); !strings.Contains(env, "OPENSHELL_TELEMETRY_ENABLED=false") {
				t.Errorf("gateway.env = %q", env)
			}
			for _, u := range h.env.userUnits() {
				path := h.env.userUnitPath(u, ChannelPayload)
				if !h.exists(path) || h.mode(path) != 0o644 {
					t.Errorf("%s is not installed with mode 0644", path)
				}
			}
			if got := h.link(h.env.launcherPath()); got != h.env.launcherTarget() {
				t.Errorf("launcher -> %q, want %q", got, h.env.launcherTarget())
			}
			if c.goos == "linux" {
				if got := h.link("/etc/systemd/user/sockets.target.wants/" + userUnitSandboxSocket); got != "/etc/systemd/user/"+userUnitSandboxSocket {
					t.Errorf("enable link -> %q", got)
				}
			}
			if _, ok := rowState(h.run(Options{Action: ActionStatus}), "sandbox openshell"); !ok {
				t.Error("status has no sandbox openshell row")
			}

			again := h.ensure(cfg)
			requireOK(t, again)
			if !again.Noop {
				t.Errorf("a second ensure applied %v", again.Changes)
			}
			h.publishLedger([]byte("ledger\n"))
			requireOK(t, h.run(Options{Action: ActionVerify}))
		})
	}
}

// With the subsystem off the lifecycle installs and renders nothing, and
// turning it off removes what it installed.
func TestSandboxOffInstallsNothingAndOffRemovesEverything(t *testing.T) {
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", false, nil)))
	for _, path := range []string{h.env.openshellDir(), h.env.launcherPath(), "/etc/systemd/user"} {
		if h.exists(path) {
			t.Errorf("%s exists although sandboxes are off", path)
		}
	}
	if _, ok := rowState(h.run(Options{Action: ActionStatus}), "sandbox openshell"); ok {
		t.Error("status reports a sandbox row although sandboxes are off")
	}
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, nil)))
	if !h.exists(h.env.launcherPath()) {
		t.Fatal("no launcher after turning sandboxes on")
	}
	r := h.ensure(sandboxConfig(t, "linux", false, nil))
	requireOK(t, r)
	for _, path := range []string{h.env.renderedTOMLPath(), h.env.launcherPath(), "/etc/systemd/user/sockets.target.wants/" + userUnitSandboxSocket,
		"/etc/systemd/user/" + userUnitSandboxService, h.env.openshellDir()} {
		if h.exists(path) {
			t.Errorf("%s stays after sandboxes were turned off", path)
		}
	}
	if got := strings.Join(h.ops.stopped(), ","); got != "alice:daemon+socket,alice:daemon+gateway+socket" {
		t.Errorf("accounts were stopped as %v", got)
	}
}

// The macOS pkg installs the launcher and the launch agents whatever
// openshell.enabled says, and nothing but uninstall removes them: an ensure
// from the package with sandboxes off keeps them (the postinstall removed the
// launcher as a stale link), and an uninstall leaves neither behind.
func TestMacOSPackageKeepsTheLauncherAndAgentsWithSandboxesOff(t *testing.T) {
	h := newOSHost(t, "darwin")
	agents := writeMacOSPackageFiles(t, h)
	present := func(when string) {
		t.Helper()
		if got := h.link(h.env.launcherPath()); got != h.env.launcherTarget() {
			t.Fatalf("%s: launcher points at %q, want %s", when, got, h.env.launcherTarget())
		}
		for _, path := range agents {
			if !h.exists(path) {
				t.Fatalf("%s: %s is gone", when, path)
			}
		}
	}
	ensure := func(cfg []byte) *enterprisestatus.Result {
		t.Helper()
		return ensureFromMacOSPackage(t, h, cfg)
	}
	off := sandboxConfig(t, "darwin", false, nil)
	requireOK(t, ensure(off))
	present("after the package install")
	if r := ensure(off); !r.Noop {
		t.Errorf("a second ensure changed %v", r.Changes)
	}
	// Sandboxes on and off again keep both.
	requireOK(t, ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite"})))
	requireOK(t, ensure(off))
	present("after sandboxes were on and off")
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	for _, path := range append([]string{h.env.launcherPath()}, agents...) {
		if h.exists(path) {
			t.Errorf("%s stays after uninstall", path)
		}
	}
}

// ensureFromMacOSPackage runs the macOS pkg postinstall's ensure with cfg.
func ensureFromMacOSPackage(t *testing.T, h *osHost, cfg []byte) *enterprisestatus.Result {
	t.Helper()
	return h.run(Options{Action: ActionEnsure, FromPackage: true, Reason: "package", ConfigFile: writeTempConfig(t, cfg)})
}

// writeMacOSPackageFiles writes what the macOS pkg payload installs before
// its postinstall runs: the binaries, both launch agents and the launcher
// link. It returns the agents' paths.
func writeMacOSPackageFiles(t *testing.T, h *osHost) []string {
	t.Helper()
	bin := h.env.P(h.env.Layout.BinDir)
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := h.payloadOnce()
	for _, name := range []string{binGateway, binHook, binSensorHelper} {
		if err := h.env.copyFileAtomic(filepath.Join(staged, name), filepath.Join(bin, name), 0o755, rootOwner()); err != nil {
			t.Fatal(err)
		}
	}
	var agents []string
	for _, u := range h.env.userUnits() {
		data, err := h.env.userUnitBytes(u)
		if err != nil {
			t.Fatal(err)
		}
		path := h.env.userUnitPath(u, ChannelPackage)
		agents = append(agents, path)
		writeHostFile(t, h.testHost, path, string(data))
	}
	launcher := h.env.P(h.env.launcherPath())
	if err := os.MkdirAll(filepath.Dir(launcher), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(h.env.launcherTarget(), launcher); err != nil {
		t.Fatal(err)
	}
	return agents
}

// A path that is not ours is never replaced by the launcher, and it does not
// fail the deployment: the link is skipped, the sandbox launcher row is
// missing and the warning names the file (openshell_launcher_conflict).
func TestSandboxForeignLauncherIsAWarningNotAFailure(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newOSHost(t, goos)
			if err := os.MkdirAll(filepath.Dir(h.env.P(h.env.launcherPath())), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(h.env.launcherPath()), []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			cfg := sandboxConfig(t, goos, true, nil)
			r := h.ensure(cfg)
			requireOK(t, r)
			if !hasWarning(r, codeLauncherConflict) {
				t.Fatalf("no launcher conflict warning: %+v", r.Warnings)
			}
			var message string
			for _, w := range r.Warnings {
				if w.Code == codeLauncherConflict {
					message = w.Message
				}
			}
			if !strings.Contains(message, h.env.launcherPath()) || !strings.Contains(message, "not a symlink") || !strings.Contains(message, "move") {
				t.Errorf("warning = %q", message)
			}
			if state, ok := rowState(r, "sandbox launcher"); !ok || !strings.HasPrefix(state, "missing:") {
				t.Errorf("launcher row = %q %v", state, ok)
			}
			if got := h.read(h.env.launcherPath()); got != "#!/bin/sh\n" {
				t.Errorf("the foreign launcher was replaced by %q", got)
			}
			// The rest of the subsystem is installed and the deployment is
			// healthy: units, rendered files, and verify passes.
			for _, u := range h.env.userUnits() {
				if !h.exists(h.env.userUnitPath(u, ChannelPayload)) {
					t.Errorf("%s was not installed", u.Name)
				}
			}
			if !h.exists(h.env.renderedTOMLPath()) {
				t.Error("gateway.toml was not rendered")
			}
			var record openshell.PrerequisitesRecord
			if err := json.Unmarshal([]byte(h.read(h.env.prerequisitesPath())), &record); err != nil || record.Ready {
				t.Errorf("prerequisites.json = %+v %v, want not ready", record, err)
			}
			h.publishLedger([]byte("ledger\n"))
			requireOK(t, h.run(Options{Action: ActionVerify}))
			if again := h.ensure(cfg); !again.Noop {
				t.Errorf("a second ensure applied %v", again.Changes)
			}
			// The administrator moves it aside: the next ensure links the
			// launcher and the row goes.
			if err := os.Remove(h.env.P(h.env.launcherPath())); err != nil {
				t.Fatal(err)
			}
			r = h.ensure(cfg)
			requireOK(t, r)
			if got := h.link(h.env.launcherPath()); got != h.env.launcherTarget() {
				t.Errorf("launcher -> %q after the file was moved", got)
			}
			if hasWarning(r, codeLauncherConflict) {
				t.Errorf("the conflict is still reported: %+v", r.Warnings)
			}
			// Uninstall never removes a file it did not link.
			if err := os.Remove(h.env.P(h.env.launcherPath())); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(h.env.launcherPath()), []byte("#!/bin/sh\n"), 0o755); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if got := h.read(h.env.launcherPath()); got != "#!/bin/sh\n" {
				t.Errorf("uninstall removed the foreign launcher: %q", got)
			}
		})
	}
}

// A failed activation puts the units, the rendered files and the links back.
func TestSandboxRollbackRestoresUnitsAndLinks(t *testing.T) {
	t.Run("a first enable that fails leaves nothing", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", false, nil)))
		h.healthy = false
		r := h.ensure(sandboxConfig(t, "linux", true, nil))
		requireError(t, r, codeActivate)
		for _, path := range []string{h.env.renderedTOMLPath(), h.env.launcherPath(), "/etc/systemd/user/sockets.target.wants/" + userUnitSandboxSocket,
			"/etc/systemd/user/" + userUnitSandboxService} {
			if h.exists(path) {
				t.Errorf("%s stays after the rollback", path)
			}
		}
		if state := h.env.loadOpenShellState(); state.Applied != nil {
			t.Errorf("a host that never ran sandboxes has a record of them: %+v", state.Applied)
		}
	})
	t.Run("turning off that fails puts everything back", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, nil)))
		want := map[string]string{
			h.env.renderedTOMLPath(): h.read(h.env.renderedTOMLPath()),
		}
		h.healthy = false
		r := h.ensure(sandboxConfig(t, "linux", false, nil))
		requireError(t, r, codeActivate)
		for path, content := range want {
			if got := h.read(path); got != content {
				t.Errorf("%s not restored", path)
			}
		}
		if got := h.link(h.env.launcherPath()); got != h.env.launcherTarget() {
			t.Errorf("launcher -> %q after the rollback", got)
		}
		if got := h.link("/etc/systemd/user/sockets.target.wants/" + userUnitSandboxSocket); got == "" {
			t.Error("the enable link was not restored")
		}
		if state := h.env.loadOpenShellState(); state.Applied == nil || !state.Applied.Enabled {
			t.Errorf("the applied state was lost: %+v", state.Applied)
		}
	})
}

// A user-manager-visible change of the units restarts an idle daemon and
// leaves one with sandboxes alone until they stop.
func TestSandboxDeferredRestartAndPending(t *testing.T) {
	h := newOSHost(t, "linux")
	cfg := sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker"})
	requireOK(t, h.ensure(cfg))
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 2}

	// A change of the rendered configuration (telemetry allowed) needs a
	// restart of the daemon, which two running sandboxes defer.
	allowed := sandboxConfigWithTelemetry(t, "linux")
	r := h.ensure(allowed)
	requireOK(t, r)
	if got := h.ops.stopped(); len(got) != 0 {
		t.Fatalf("a daemon with running sandboxes was stopped: %v", got)
	}
	if !hasWarning(r, codeSandboxPending) {
		t.Fatalf("no pending warning: %+v", r.Warnings)
	}
	state := h.env.loadOpenShellState()
	entry, ok := state.Pending[fmt.Sprint(h.alice.UID)]
	if !ok || entry.Kind != "restart" || entry.Sandboxes != 2 {
		t.Fatalf("pending = %+v", state.Pending)
	}
	if st, ok := rowState(r, "sandbox pending alice"); !ok || !strings.Contains(st, "2 sandboxes run") {
		t.Errorf("pending row = %q %v", st, ok)
	}
	// status and verify only read that record: the user's own command may
	// have restarted the idle daemon since, so they do not say a sandbox
	// runs now (GAP-0679).
	for _, action := range []string{ActionStatus, ActionVerify} {
		got := h.run(Options{Action: action})
		st, ok := rowState(got, "sandbox pending alice")
		warning := messagesOf(got.Warnings, codeSandboxPending)
		if !ok || strings.Contains(st, "sandboxes run") || !strings.Contains(st, "2 sandboxes ran when it was last tried") ||
			strings.Contains(warning, "sandboxes run") || !strings.Contains(warning, "until the next ensure") {
			t.Errorf("%s pending row = %q, warning = %q", action, st, warning)
		}
	}

	// Still busy: a run that applies nothing keeps waiting, and says so.
	r = h.ensure(allowed)
	requireOK(t, r)
	if !r.Noop || len(h.ops.stopped()) != 0 || !hasWarning(r, codeSandboxPending) {
		t.Fatalf("busy retry: noop=%v stops=%v warnings=%+v", r.Noop, h.ops.stopped(), r.Warnings)
	}

	// The sandboxes stop: the next run restarts the daemon.
	h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 0}
	r = h.ensure(allowed)
	requireOK(t, r)
	if got := h.ops.stopped(); len(got) != 1 || got[0] != "alice:daemon" {
		t.Fatalf("stops = %v", got)
	}
	if r.Noop || !containsLine(r.Changes, "restarted the sandbox daemon of alice") {
		t.Errorf("noop=%v changes=%v", r.Noop, r.Changes)
	}
	if len(h.env.loadOpenShellState().Pending) != 0 || hasWarning(r, codeSandboxPending) {
		t.Errorf("the pending change was not cleared: %+v", h.env.loadOpenShellState().Pending)
	}
}

func sandboxConfigWithTelemetry(t *testing.T, goos string) []byte {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(sandboxConfig(t, goos, true, map[string]any{"install": "prerequisite", "driver": "docker"}), &doc); err != nil {
		t.Fatal(err)
	}
	doc["openshell"] = map[string]any{"enabled": true, "admin": map[string]any{"allow_upstream_telemetry": true}}
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func containsLine(lines []string, prefix string) bool {
	for _, line := range lines {
		if strings.HasPrefix(line, prefix) {
			return true
		}
	}
	return false
}

// An unknown sandbox state is treated as running: nothing is stopped.
func TestSandboxUnknownStatusDefers(t *testing.T) {
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker"})))
	if err := os.MkdirAll(h.env.P(filepath.Join(h.alice.Home, h.env.daemonStateRel())), 0o700); err != nil {
		t.Fatal(err)
	}
	h.ops.statusErr[h.alice.UID] = errors.New("the daemon does not answer")
	// GAP-0490: an account where no daemon ever ran does not wait forever
	// on a status nobody can answer.
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, Home: "/home/bob"}
	h.ops.accounts = append(h.ops.accounts, bob)
	h.ops.statusErr[bob.UID] = errors.New("no user manager")
	r := h.ensure(sandboxConfigWithTelemetry(t, "linux"))
	requireOK(t, r)
	if len(h.ops.stopped()) != 0 || !hasWarning(r, codeSandboxPending) {
		t.Fatalf("stops=%v warnings=%+v", h.ops.stopped(), r.Warnings)
	}
	if _, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(bob.UID)]; waiting || strings.Contains(messagesOf(r.Warnings, codeSandboxPending), "bob") {
		t.Errorf("bob waits: %+v", r.Warnings)
	}
}

// Install-mode, driver and version transitions are per account, wait for
// sandboxes, remove only an OpenShell DefenseClaw installed, and never delete
// a sandbox.
func TestSandboxTransitions(t *testing.T) {
	prerequisiteDocker := map[string]any{"install": "prerequisite", "driver": "docker"}
	setupVM := map[string]any{"install": "setup", "driver": "vm", "version": "0.1.5"}

	t.Run("driver switch waits, then switches without deleting sandboxes", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, prerequisiteDocker)))
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
		vm := map[string]any{"install": "prerequisite", "driver": "vm"}
		r := h.ensure(sandboxConfig(t, "linux", true, vm))
		requireOK(t, r)
		if entry := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]; entry.Kind != "switch" || !strings.Contains(entry.Reason, "driver docker -> vm") {
			t.Fatalf("pending = %+v", entry)
		}
		if len(h.ops.stopped()) != 0 {
			t.Fatalf("stopped %v while a sandbox runs", h.ops.stopped())
		}
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 0}
		r = h.ensure(sandboxConfig(t, "linux", true, vm))
		requireOK(t, r)
		if got := strings.Join(h.ops.stopped(), ","); got != "alice:daemon+socket,alice:daemon+gateway" {
			t.Fatalf("stops = %v", got)
		}
		if len(h.ops.teardowns) != 0 {
			t.Errorf("a switch tore sandboxes down: %v", h.ops.teardowns)
		}
		if !containsLine(r.Changes, "switched the sandbox setup of alice") || !strings.Contains(strings.Join(r.Changes, "\n"), "OpenShell drops them a few minutes after the switch") {
			t.Errorf("changes = %v", r.Changes)
		}
		// GAP-0230, GAP-0244: the lifecycle runs as root and creates nothing in
		// the account's home.
		if h.exists(filepath.Join(h.alice.Home, ".local")) {
			t.Error("the switch created folders in the account's home")
		}
		if len(h.env.loadOpenShellState().Pending) != 0 {
			t.Error("the switch stays pending")
		}
	})

	t.Run("leaving setup mode removes the OpenShell DefenseClaw installed", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setupVM)))
		kept := h.installTarballFiles(t, h.alice, "0.1.5")
		// The user changed the gateway after the install.
		if err := os.WriteFile(h.env.P(filepath.Join(h.alice.Home, ".local/bin/openshell-gateway")), []byte("mine"), 0o755); err != nil {
			t.Fatal(err)
		}
		r := h.ensure(sandboxConfig(t, "linux", true, prerequisiteDocker))
		requireOK(t, r)
		for _, rel := range []string{".local/bin/openshell", ".local/libexec/openshell/openshell-driver-vm"} {
			if h.exists(filepath.Join(h.alice.Home, rel)) {
				t.Errorf("%s was not removed", rel)
			}
		}
		if !h.exists(filepath.Join(h.alice.Home, ".local/bin/openshell-gateway")) {
			t.Error("a binary the user changed was removed")
		}
		if !hasWarning(r, codeSandboxUserState) || !strings.Contains(fmt.Sprint(r.Warnings), "changed after DefenseClaw installed it") {
			t.Errorf("no warning for the kept file: %+v", r.Warnings)
		}
		if !h.exists(kept) {
			t.Error("the account's other files were touched")
		}
	})

	t.Run("an OpenShell the administrator installed is never removed", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, prerequisiteDocker)))
		mine := filepath.Join(h.alice.Home, ".local/bin/openshell")
		if err := os.MkdirAll(filepath.Dir(h.env.P(mine)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(h.env.P(mine), []byte("theirs"), 0o755); err != nil {
			t.Fatal(err)
		}
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, setupVM)))
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, prerequisiteDocker)))
		if got := h.read(mine); got != "theirs" {
			t.Errorf("an OpenShell DefenseClaw did not install was changed: %q", got)
		}
	})

	t.Run("an account whose daemon is not running switches at once", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, prerequisiteDocker)))
		r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"}))
		requireOK(t, r)
		if len(h.env.loadOpenShellState().Pending) != 0 || hasWarning(r, codeSandboxPending) {
			t.Errorf("an idle account waits: %+v", r.Warnings)
		}
	})
}

// GAP-0463, GAP-0455: a switch line names what changed, the fallback
// included, and a switch that supersedes a waiting one names the setup the
// account really runs.
func TestSandboxSwitchLinesNameTheRealChange(t *testing.T) {
	vm := map[string]any{"install": "prerequisite", "driver": "vm", "driver_fallback": "docker"}
	vmNoFallback := map[string]any{"install": "prerequisite", "driver": "vm", "driver_fallback": "none"}
	docker := map[string]any{"install": "prerequisite", "driver": "docker"}
	statePending := func(h *osHost) pending {
		return h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]
	}

	t.Run("a fallback-only change names the fallback", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, vm)))
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true}
		r := h.ensure(sandboxConfig(t, "linux", true, vmNoFallback))
		requireOK(t, r)
		changes := strings.Join(r.Changes, "\n")
		if !strings.Contains(changes, "of alice on the new fallback (driver_fallback docker -> none)") ||
			strings.Contains(changes, "()") || strings.Contains(changes, "OpenShell drops them") {
			t.Fatalf("changes = %v", r.Changes)
		}
	})

	t.Run("a switch back while the old sandbox runs is no switch", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, vm)))
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, docker)))
		if entry := statePending(h); entry.Kind != "switch" || entry.reasonBase() != "driver vm -> docker" {
			t.Fatalf("pending = %+v", entry)
		}
		r := h.ensure(sandboxConfig(t, "linux", true, vm))
		requireOK(t, r)
		if entry, waiting := h.env.loadOpenShellState().Pending[fmt.Sprint(h.alice.UID)]; waiting {
			t.Errorf("the account still waits: %+v", entry)
		}
		if containsLine(r.Changes, "switched the sandbox setup of alice") || hasWarning(r, codeSandboxPending) {
			t.Errorf("changes = %v, warnings = %+v", r.Changes, r.Warnings)
		}
	})

	t.Run("a daemon that restarted onto the waiting setup switches from it", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, vm)))
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true, Running: 1}
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, docker)))
		// The user's next command found the daemon idle and restarted it, so
		// it runs the docker setup now.
		h.ops.status[h.alice.UID] = SandboxStatus{Active: true, StartedAt: h.env.Now().Add(time.Hour)}
		r := h.ensure(sandboxConfig(t, "linux", true, vm))
		requireOK(t, r)
		changes := strings.Join(r.Changes, "\n")
		if !strings.Contains(changes, "switched the sandbox setup of alice (driver docker -> vm)") || strings.Contains(changes, "vm -> docker") {
			t.Fatalf("changes = %v", r.Changes)
		}
	})
}

// installTarballFiles stands in for the setup mode's install in an account's
// home: the three binaries and the record, and an unrelated file.
func (h *osHost) installTarballFiles(t *testing.T, a SandboxAccount, version string) (unrelated string) {
	t.Helper()
	var files []openshell.InstalledFile
	for _, rel := range tarballRels {
		path := filepath.Join(h.env.P(a.Home), rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		content := "binary " + rel
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
		files = append(files, openshell.InstalledFile{Path: filepath.Join(a.Home, rel), SHA256: sha(content)})
	}
	manifest, _ := json.Marshal(openshell.InstalledRelease{Version: version, Files: files})
	record := filepath.Join(h.env.P(a.Home), installStateRel, openshell.TarballManifestName)
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, manifest, 0o644); err != nil {
		t.Fatal(err)
	}
	unrelated = filepath.Join(a.Home, "notes.txt")
	if err := os.WriteFile(h.env.P(unrelated), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	return unrelated
}

// Uninstall stops every account's sandboxes and keeps them; purge tears them
// down and leaves nothing the subsystem created.
func TestSandboxUninstallAndPurge(t *testing.T) {
	populate := func(t *testing.T, h *osHost) {
		t.Helper()
		h.installTarballFiles(t, h.alice, "0.1.5")
		for _, rel := range []string{h.env.daemonStateRel(), openshellVMStateRel, openshellStateRel + "/tls", openshellShareRel + "/vm-runtime/0.1.5"} {
			dir := filepath.Join(h.env.P(h.alice.Home), rel)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "state.bin"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// The decision and registration stores of the account.
		for _, dir := range []string{"registrations", "decisions"} {
			path := filepath.Join(h.env.P(h.env.Layout.DataDir), "sandbox", dir)
			if err := os.MkdirAll(path, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, fmt.Sprint(h.alice.UID)+".json"), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(h.env.P(h.alice.Home), "keep.txt"), []byte("mine"), 0o644); err != nil {
			t.Fatal(err)
		}
		// The sandbox CLI's image records below ~/.defenseclaw (GAP-0490).
		images := filepath.Join(h.env.P(h.alice.Home), userSandboxDataRel)
		if err := os.MkdirAll(images, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(images, "images.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos+" purge", func(t *testing.T) {
			h := newOSHost(t, goos)
			setup := map[string]any{"install": "setup", "version": "0.1.5", "driver": "vm"}
			requireOK(t, h.ensure(sandboxConfig(t, goos, true, setup)))
			populate(t, h)
			r := h.run(Options{Action: ActionUninstall, Purge: true})
			requireOK(t, r)
			if got := h.ops.teardowns; len(got) != 1 || got[0] != "alice" {
				t.Errorf("teardowns = %v", got)
			}
			if !strings.Contains(strings.Join(h.ops.stopped(), ","), "alice:daemon+gateway+socket") {
				t.Errorf("stops = %v", h.ops.stopped())
			}
			// Nothing the sandbox subsystem created is left anywhere.
			var left []string
			_ = filepath.WalkDir(h.env.Root, func(path string, d fs.DirEntry, err error) error {
				rel, _ := filepath.Rel(h.env.Root, path)
				lower := strings.ToLower(rel)
				// The lifecycle's lock file outlives the deployment by design.
				if strings.Contains(lower, "lifecycle") || strings.Contains(lower, "defenseclaw-enterprise") || rel == "opt/cisco/defenseclaw" {
					return nil
				}
				for _, needle := range []string{"openshell", "sandbox", "defenseclaw"} {
					if strings.Contains(lower, needle) {
						left = append(left, rel)
						break
					}
				}
				return nil
			})
			if len(left) > 0 {
				t.Errorf("purge leaves %v", left)
			}
			if got := h.read(filepath.Join(h.alice.Home, "keep.txt")); got != "mine" {
				t.Errorf("an unrelated file of the account changed: %q", got)
			}
		})
	}
	t.Run("purge leaves an account the subsystem never served alone", func(t *testing.T) {
		// GAP-0490: an enrolled account whose home holds only a folder it
		// does not own (the empty root-owned one an older release left) has
		// nothing of the subsystem: no teardown, no removal, no warning.
		h := newOSHost(t, "darwin")
		bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, GID: h.alice.GID, Home: "/Users/bob"}
		h.ops.accounts = []SandboxAccount{bob}
		requireOK(t, h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite"})))
		state := filepath.Join(bob.Home, h.env.daemonStateRel())
		if err := os.MkdirAll(h.env.P(state), 0o755); err != nil {
			t.Fatal(err)
		}
		r := h.run(Options{Action: ActionUninstall, Purge: true})
		requireOK(t, r)
		if len(h.ops.teardowns) != 0 || containsLine(r.Changes, "removed local sandbox files of user bob") || hasWarning(r, codeSandboxUserState) {
			t.Errorf("teardowns = %v, changes = %v, warnings = %+v", h.ops.teardowns, r.Changes, r.Warnings)
		}
		if !h.exists(state) {
			t.Error("the purge removed a folder the account does not own")
		}
	})
	t.Run("uninstall without purge keeps the account's state", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "setup", "version": "0.1.5", "driver": "vm"})))
		populate(t, h)
		requireOK(t, h.run(Options{Action: ActionUninstall}))
		if got := h.ops.teardowns; len(got) != 0 {
			t.Errorf("teardowns = %v: a non-purge uninstall deletes the sandboxes (GAP-0598)", got)
		}
		if !h.exists(filepath.Join(h.alice.Home, h.env.daemonStateRel())) || !h.exists(filepath.Join(h.alice.Home, ".local/bin/openshell")) {
			t.Error("the account's sandbox state was removed without --purge")
		}
		for _, path := range []string{h.env.launcherPath(), h.env.openshellDir(), "/etc/systemd/user/" + userUnitSandboxService} {
			if h.exists(path) {
				t.Errorf("%s stays after uninstall", path)
			}
		}
	})
	t.Run("a removal does not follow a link in the account's home", func(t *testing.T) {
		h := newOSHost(t, "linux")
		requireOK(t, h.ensure(sandboxConfig(t, "linux", true, nil)))
		outside := t.TempDir()
		if err := os.WriteFile(filepath.Join(outside, "precious"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		state := filepath.Join(h.env.P(h.alice.Home), ".local", "state")
		if err := os.MkdirAll(state, 0o755); err != nil {
			t.Fatal(err)
		}
		// ~/.local/state/defenseclaw-sandbox is a link to a folder elsewhere.
		if err := os.Symlink(outside, filepath.Join(state, "defenseclaw-sandbox")); err != nil {
			t.Fatal(err)
		}
		requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
		if !exists(filepath.Join(outside, "precious")) {
			t.Error("purge followed a link out of the account's home")
		}
	})
}

// The install-mode verify rows say what is missing and what to run.
func TestSandboxPrerequisiteRows(t *testing.T) {
	t.Run("prerequisite mode on an empty host", func(t *testing.T) {
		h := newOSHost(t, "linux")
		r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "vm"}))
		requireOK(t, r)
		for _, row := range []string{"sandbox openshell cli", "sandbox openshell gateway", "sandbox microvm driver", "sandbox e2fsprogs", "sandbox kvm"} {
			if state, ok := rowState(r, row); !ok {
				t.Errorf("no row %q", row)
			} else if !strings.HasPrefix(state, "missing:") {
				t.Errorf("%s = %q, want missing", row, state)
			}
		}
		if _, ok := rowState(r, "sandbox docker"); ok {
			t.Error("the MicroVM driver on Linux asks for Docker")
		}
		if !hasWarning(r, codeOpenShellPrerequisite) {
			t.Fatalf("no prerequisite warning: %+v", r.Warnings)
		}
		var gotFix bool
		for _, w := range r.Warnings {
			if w.Code == codeOpenShellPrerequisite && strings.Contains(w.Message, "enterprise.openshell.install: setup") {
				gotFix = true
			}
		}
		if !gotFix {
			t.Errorf("no warning names the setup mode: %+v", r.Warnings)
		}
		var record openshell.PrerequisitesRecord
		if err := json.Unmarshal([]byte(h.read(h.env.prerequisitesPath())), &record); err != nil || record.Ready || len(record.Missing) == 0 || record.Install != "prerequisite" {
			t.Errorf("prerequisites.json = %+v %v", record, err)
		}
		if h.mode(h.env.prerequisitesPath()) != 0o644 {
			t.Error("prerequisites.json is not world-readable")
		}
		// status reads, never writes.
		_ = os.Remove(h.env.P(h.env.prerequisitesPath()))
		h.run(Options{Action: ActionStatus})
		if h.exists(h.env.prerequisitesPath()) {
			t.Error("status wrote prerequisites.json")
		}
	})
	t.Run("a package-installed OpenShell passes", func(t *testing.T) {
		h := newOSHost(t, "linux")
		for _, p := range []string{"/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/bin/docker", "/usr/sbin/mke2fs"} {
			if err := os.MkdirAll(filepath.Dir(h.env.P(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(p), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		h.runner.replies = map[string]fakeReply{"rpm -q --qf %{VERSION} openshell": {result: CommandResult{Stdout: []byte("0.1.5")}},
			"rpm -q --qf %{VERSION} openshell-gateway": {result: CommandResult{Stdout: []byte("0.1.5")}}}
		r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": ">=0.1.1 <0.2.0"}))
		requireOK(t, r)
		if state, _ := rowState(r, "sandbox openshell cli"); !strings.HasPrefix(state, "ok: 0.1.5") {
			t.Errorf("cli row = %q", state)
		}
		if hasWarning(r, codeOpenShellPrerequisite) {
			t.Errorf("warnings = %+v", r.Warnings)
		}
		// An exact pin that differs is named.
		r = h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": "0.1.2"}))
		requireOK(t, r)
		if state, _ := rowState(r, "sandbox openshell cli"); !strings.Contains(state, "pins 0.1.2") {
			t.Errorf("cli row = %q", state)
		}
	})
	// OpenShell before 0.1.5 runs no sandbox (its network broker could let a
	// sandbox's connections bypass the policy, NVIDIA/OpenShell#4494),
	// whatever the pin allows: the administrator's install is named, with
	// the pin to set.
	t.Run("a prerequisite OpenShell older than the release sandboxes need", func(t *testing.T) {
		h := newOSHost(t, "linux")
		for _, p := range []string{"/usr/bin/openshell", "/usr/bin/openshell-gateway", "/usr/bin/docker", "/usr/sbin/mke2fs"} {
			if err := os.MkdirAll(filepath.Dir(h.env.P(p)), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(p), []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		h.runner.replies = map[string]fakeReply{"rpm -q --qf %{VERSION} openshell": {result: CommandResult{Stdout: []byte("0.1.3")}},
			"rpm -q --qf %{VERSION} openshell-gateway": {result: CommandResult{Stdout: []byte("0.1.3")}}}
		for pin, fix := range map[string]string{
			">=0.1.1 <0.2.0": "install a release that satisfies enterprise.openshell.version version=>=0.1.1 <0.2.0",
			"0.1.3":          "set enterprise.openshell.version to " + openshell.InstallerVersion + " (or a range from " + openshell.SupportedMin + ") and install that release",
		} {
			r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "prerequisite", "driver": "docker", "version": pin}))
			requireOK(t, r)
			if state, _ := rowState(r, "sandbox openshell cli"); !strings.Contains(state, "OpenShell 0.1.3 runs no DefenseClaw sandbox") || strings.HasPrefix(state, "ok") {
				t.Errorf("%s: cli row = %q", pin, state)
			}
			if !strings.Contains(fmt.Sprint(r.Warnings), fix) {
				t.Errorf("%s: warnings = %+v", pin, r.Warnings)
			}
		}
	})
	// The hosts DefenseClaw 1.0.3 set up pin "0.1.3", which runs no sandbox:
	// setup mode installs 0.1.5 for it, and each account switches once none
	// of its sandboxes runs (the in-place migration).
	t.Run("the 1.0.3 setup pin moves to the release sandboxes need", func(t *testing.T) {
		h := newOSHost(t, "linux")
		old := map[string]any{"install": "setup", "driver": "docker", "version": "0.1.3"}
		r := h.ensure(sandboxConfig(t, "linux", true, old))
		requireOK(t, r)
		// status and verify describe what ensure applied, raised pin
		// included (GAP-0621).
		for _, r := range []*enterprisestatus.Result{r, h.run(Options{Action: ActionStatus}), h.run(Options{Action: ActionVerify})} {
			if state, _ := rowState(r, "sandbox openshell pin"); !strings.HasPrefix(state, "ok: "+openshell.InstallerVersion) ||
				!strings.Contains(state, "enterprise.openshell.version pins 0.1.3, which runs no sandbox") || !strings.HasSuffix(state, "set the pin to "+openshell.InstallerVersion) {
				t.Errorf("%s: pin row = %q", r.Action, state)
			}
		}
		if v := h.env.loadOpenShellState().Applied.Version; v != openshell.InstallerVersion {
			t.Fatalf("applied version = %q", v)
		}
		// As 1.0.3 left it: its record names 0.1.3, which alice runs.
		st := h.env.loadOpenShellState()
		st.Applied.Version = "0.1.3"
		if err := h.env.saveOpenShellState(st); err != nil {
			t.Fatal(err)
		}
		h.installTarballFiles(t, h.alice, "0.1.3")
		// The upgrade to this build: its ensure on the new payload.
		r = h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.4"), ConfigFile: writeTempConfig(t, sandboxConfig(t, "linux", true, old))})
		requireOK(t, r)
		if !containsLine(r.Changes, `switched the sandbox setup of alice (version "0.1.3" -> "`+openshell.InstallerVersion+`")`) {
			t.Errorf("changes = %v", r.Changes)
		}
		if v := h.env.loadOpenShellState().Applied.Version; v != openshell.InstallerVersion {
			t.Errorf("applied version after the migration = %q", v)
		}
	})
	t.Run("setup mode checks the pin, not the host's OpenShell", func(t *testing.T) {
		h := newOSHost(t, "linux")
		r := h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5"}))
		requireOK(t, r)
		if state, _ := rowState(r, "sandbox openshell pin"); !strings.HasPrefix(state, "ok: 0.1.5") {
			t.Errorf("pin row = %q", state)
		}
		if _, ok := rowState(r, "sandbox openshell cli"); ok {
			t.Error("setup mode checks the host's OpenShell")
		}
		h.installTarballFiles(t, h.alice, "0.1.5")
		r = h.run(Options{Action: ActionStatus})
		if state, ok := rowState(r, "sandbox user-installed"); !ok || !strings.Contains(state, "alice: OpenShell 0.1.5 (user-installed, unmanaged)") {
			t.Errorf("user-installed row = %q %v", state, ok)
		}
		// GAP-0236: ensure refuses a release this build has no digests for,
		// and applies nothing.
		before := h.read(h.env.renderedTOMLPath())
		r = h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "setup", "driver": "docker", "version": "9.9.9"}))
		if r.OK || !strings.Contains(fmt.Sprint(r.Errors, r.Warnings), `"9.9.9" is not a release this DefenseClaw build can install`) {
			t.Errorf("an unpinned release is accepted: %+v", r)
		}
		if h.read(h.env.renderedTOMLPath()) != before || h.env.loadOpenShellState().Applied.Version != "0.1.5" {
			t.Error("a refused pin changed the applied sandbox configuration")
		}
	})
	t.Run("macOS e2fsprogs must come from an administrator directory", func(t *testing.T) {
		h := newOSHost(t, "darwin")
		r := h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite"}))
		requireOK(t, r)
		if state, _ := rowState(r, "sandbox e2fsprogs"); !strings.Contains(state, "e2fsprogs_dir is not set") {
			t.Errorf("e2fsprogs row = %q", state)
		}
		dir := "/opt/cisco/e2fs"
		for _, tool := range []string{"sbin/mke2fs", "sbin/debugfs"} {
			p := h.env.P(filepath.Join(dir, tool))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x"), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if runtime.GOOS != "darwin" {
			// The config load validates enterprise.openshell for the running
			// OS and refuses e2fsprogs_dir off macOS, so the rest runs on a Mac.
			return
		}
		r = h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite", "e2fsprogs_dir": dir}))
		requireOK(t, r)
		// The row names the folder the gateway runs the driver with (GAP-0506).
		if state, _ := rowState(r, "sandbox e2fsprogs"); state != "ok: "+dir+"/sbin" {
			t.Errorf("e2fsprogs row = %q", state)
		}
		h.env.Trust = func(path string, kind TrustKind) error {
			if strings.HasSuffix(path, "e2fs") {
				return errors.New("owned by an administrator account")
			}
			return nil
		}
		r = h.ensure(sandboxConfig(t, "darwin", true, map[string]any{"install": "prerequisite", "e2fsprogs_dir": dir}))
		if state, _ := rowState(r, "sandbox e2fsprogs"); !strings.Contains(state, "not an administrator-controlled directory") {
			t.Errorf("an untrusted e2fsprogs directory passes: %q", state)
		}
	})
}

// The groups row names, in one line, the accounts that used sandboxes and
// lack the group the driver needs; enrolled accounts that never ran one
// (administrators, service accounts) are not named (GAP-0454).
func TestSandboxGroupsRow(t *testing.T) {
	h := newOSHost(t, "linux")
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, Home: "/home/bob"}
	admin := SandboxAccount{Name: "admin", UID: h.alice.UID + 2, Home: "/home/admin"}
	h.ops.accounts = append(h.ops.accounts, bob, admin)
	h.ops.groups["alice"] = []string{"alice", "docker"}
	h.ops.groups["bob"] = []string{"bob"}
	h.ops.groups["admin"] = []string{"admin", "wheel"}
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, map[string]any{"install": "setup", "driver": "docker", "version": "0.1.5"})))
	for _, a := range []SandboxAccount{h.alice, bob} {
		h.registerSandboxUser(t, a)
	}
	r := h.run(Options{Action: ActionStatus})
	state, ok := rowState(r, "sandbox groups docker")
	if !ok || !strings.HasPrefix(state, "missing:") || !strings.Contains(state, "1 of 2 accounts that used sandboxes are not in the docker group (bob)") {
		t.Fatalf("groups row = %q %v", state, ok)
	}
	message := messagesOf(r.Warnings, codeSandboxGroups)
	if strings.Contains(message, "usermod -aG docker bob") || !strings.Contains(message, "group (bob)") || !strings.Contains(message, "root-equivalent") {
		t.Errorf("warning = %q", message)
	}
	h.ops.groups["bob"] = []string{"bob", "docker"}
	r = h.run(Options{Action: ActionStatus})
	if state, _ := rowState(r, "sandbox groups docker"); !strings.HasPrefix(state, "ok:") {
		t.Errorf("groups row after the fix = %q", state)
	}
}

// With the MicroVM driver every account that used sandboxes needs the
// docker group, as its agent images are built in Docker (GAP-0511); a
// kvm-group /dev/kvm also needs the kvm group, and an open one does not
// (GAP-0454).
func TestSandboxGroupsRowMicroVM(t *testing.T) {
	h := newOSHost(t, "linux")
	bob := SandboxAccount{Name: "bob", UID: h.alice.UID + 1, Home: "/home/bob"}
	h.ops.accounts = append(h.ops.accounts, bob)
	h.ops.groups["alice"] = []string{"alice", "kvm", "docker"}
	h.ops.groups["bob"] = []string{"bob"}
	dev := h.env.P(kvmDevice)
	if err := os.MkdirAll(filepath.Dir(dev), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dev, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dev, 0o666); err != nil {
		t.Fatal(err)
	}
	vm := map[string]any{"install": "prerequisite", "driver": "vm", "driver_fallback": "docker"}
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, vm)))
	for _, a := range []SandboxAccount{h.alice, bob} {
		h.registerSandboxUser(t, a)
	}
	r := h.run(Options{Action: ActionStatus})
	if _, ok := rowState(r, "sandbox groups kvm"); ok {
		t.Error("an open /dev/kvm still asks for the kvm group")
	}
	if state, _ := rowState(r, "sandbox groups docker"); !strings.Contains(state, "1 of 2 accounts that used sandboxes are not in the docker group (bob), which MicroVM sandboxes need") {
		t.Errorf("groups docker row = %q", state)
	}
	if err := os.Chmod(dev, 0o660); err != nil {
		t.Fatal(err)
	}
	r = h.run(Options{Action: ActionStatus})
	if state, _ := rowState(r, "sandbox groups kvm"); !strings.Contains(state, "1 of 2 accounts that used sandboxes lack /dev/kvm read-write access (bob)") ||
		!strings.Contains(state, "they get the docker fallback") {
		t.Errorf("groups kvm row = %q", state)
	}
	h.ops.groups["bob"] = []string{"bob", "kvm", "docker"}
	r = h.run(Options{Action: ActionStatus})
	if hasWarning(r, codeSandboxGroups) {
		t.Fatalf("every account in both groups still warns: %+v", r.Warnings)
	}
}

// registerSandboxUser gives a the managed registration record of an account
// that ran a sandbox.
func (h *osHost) registerSandboxUser(t *testing.T, a SandboxAccount) {
	t.Helper()
	dir := filepath.Join(h.env.P(h.env.Layout.DataDir), "sandbox", "registrations")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(a.UID)+".json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The user unit definitions and the links are part of verify.
func TestSandboxVerifyFailsOnADriftedLauncherOrUnit(t *testing.T) {
	h := newOSHost(t, "linux")
	requireOK(t, h.ensure(sandboxConfig(t, "linux", true, nil)))
	h.publishLedger([]byte("ledger\n"))
	requireOK(t, h.run(Options{Action: ActionVerify}))
	launcher := h.env.P(h.env.launcherPath())
	if err := os.Remove(launcher); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/bin/sh", launcher); err != nil {
		t.Fatal(err)
	}
	r := h.run(Options{Action: ActionVerify})
	if r.OK || !strings.Contains(fmt.Sprint(r.Errors), "points at /bin/sh") {
		t.Fatalf("verify = %+v", r.Errors)
	}
	// repair puts it back.
	requireOK(t, h.run(Options{Action: ActionRepair}))
	if got := h.link(h.env.launcherPath()); got != h.env.launcherTarget() {
		t.Errorf("repair left the launcher -> %q", got)
	}
	if err := os.WriteFile(h.env.P("/etc/systemd/user/"+userUnitSandboxService), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	r = h.run(Options{Action: ActionVerify})
	if r.OK || !strings.Contains(fmt.Sprint(r.Errors), userUnitSandboxService+" was modified after install") {
		t.Fatalf("verify = %+v", r.Errors)
	}
}

// The administrator's proxy reaches the units, and a package install records
// the package's own units instead of writing them.
func TestSandboxProxyDropinAndPackageUnits(t *testing.T) {
	t.Run("proxy drop-ins", func(t *testing.T) {
		h := newOSHost(t, "linux")
		var doc map[string]any
		if err := yaml.Unmarshal(sandboxConfig(t, "linux", true, nil), &doc); err != nil {
			t.Fatal(err)
		}
		doc["enterprise"].(map[string]any)["network"] = map[string]any{"https_proxy": "http://proxy.example.test:3128", "no_proxy": "localhost"}
		out, _ := yaml.Marshal(doc)
		requireOK(t, h.ensure(out))
		for _, name := range []string{userUnitSandboxService, userUnitGatewayService} {
			drop := h.read("/etc/systemd/user/" + name + ".d/" + dropinNetwork)
			if !strings.Contains(drop, "HTTPS_PROXY=http://proxy.example.test:3128") || !strings.Contains(drop, "NO_PROXY=localhost") {
				t.Errorf("%s drop-in = %q", name, drop)
			}
		}
	})
	t.Run("package units are recorded, not written", func(t *testing.T) {
		h := newOSHost(t, "linux")
		h.env.UserUnitSource = func(name string) ([]byte, error) { return []byte("unit " + name + "\n"), nil }
		for _, u := range h.env.userUnits() {
			path := h.env.P(h.env.userUnitPath(u, ChannelPackage))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("unit "+u.Source+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		p := &plan{channel: ChannelPackage, config: &validatedConfig{}}
		op := &openshellPlan{}
		units, _, err := h.env.renderUserUnits(p, op)
		if err != nil {
			t.Fatal(err)
		}
		if len(op.files) != 0 {
			t.Errorf("a package install would write %d unit files the package owns", len(op.files))
		}
		for _, u := range h.env.userUnits() {
			path := h.env.userUnitPath(u, ChannelPackage)
			if p.packageUnits[path] != sha("unit "+u.Source+"\n") || units[path] != p.packageUnits[path] {
				t.Errorf("%s: recorded %q", path, p.packageUnits[path])
			}
		}
	})
}
