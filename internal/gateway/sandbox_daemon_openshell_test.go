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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// openShellRig is an accountOpenShell whose host the test plays.
type openShellRig struct {
	o        *accountOpenShell
	mu       sync.Mutex
	commands []string
	installs []string
	// holder answers the port holder: the uid, or 0 for a free port.
	holder func(call int) int
	calls  int
	// registered is the port the registration points at (0: none).
	registered int
	metadata   string
	// fail makes a command (by prefix) fail with its output.
	fail map[string]string
	// active makes the managed gateway unit report active.
	active bool
	// pid and args are the gateway port's listener and its command line.
	pid  int
	args string
}

func newOpenShellRig(t *testing.T, goos string) *openShellRig {
	t.Helper()
	home := t.TempDir()
	cfgDir := filepath.Join(home, ".config", "openshell")
	r := &openShellRig{fail: map[string]string{}, holder: func(int) int { return 0 }}
	r.metadata = filepath.Join(cfgDir, "gateways", "openshell", "metadata.json")
	r.o = newAccountOpenShell(goos, 5001, home, func(string, ...any) {})
	r.o.install = func(_ context.Context, version, h string) (*openshell.TarballResult, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.installs = append(r.installs, version+"@"+h)
		if msg := r.fail["install"]; msg != "" {
			return nil, errors.New(msg)
		}
		return &openshell.TarballResult{Version: version, Files: []openshell.InstalledFile{{Path: "x"}}}, nil
	}
	r.o.run = func(_ context.Context, name string, args, _ []string) (string, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		line := filepath.Base(name) + " " + strings.Join(args, " ")
		r.commands = append(r.commands, line)
		for prefix, out := range r.fail {
			if prefix != "install" && strings.HasPrefix(line, prefix) {
				return out, errors.New("exit status 1")
			}
		}
		if strings.HasPrefix(line, "openshell gateway add ") {
			r.registered = 17670
		}
		if r.active && strings.HasPrefix(line, "systemctl --user is-active ") {
			return "active", nil
		}
		return "", nil
	}
	r.o.portHolder = func(int) (int, bool) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls++
		uid := r.holder(r.calls)
		return uid, uid != 0
	}
	r.o.configDir = func() (string, error) { return cfgDir, nil }
	r.o.portPID = func(int) int { return r.pid }
	r.o.procArgs = func(context.Context, int) (string, error) { return r.args, nil }
	r.o.discover = func(openshell.DiscoverOptions) (*openshell.Registration, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.registered == 0 {
			return nil, errors.New("no registration")
		}
		return &openshell.Registration{Name: "openshell", Endpoint: "https://127.0.0.1:" + strconv.Itoa(r.registered)}, nil
	}
	return r
}

func (r *openShellRig) ran() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.commands...)
}

func setupSettings() sandboxrelay.DaemonSettings {
	return sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "setup", Driver: "vm", Version: "0.1.3", GatewayPort: 17670}}
}

func fastGatewayWaits(t *testing.T) {
	t.Helper()
	wait, poll := openShellGatewayStartWait, openShellGatewayPollEvery
	openShellGatewayStartWait, openShellGatewayPollEvery = 200*time.Millisecond, 5*time.Millisecond
	t.Cleanup(func() { openShellGatewayStartWait, openShellGatewayPollEvery = wait, poll })
}

// Setup mode, first use: the pinned release is installed into the
// account's home, the gateway unit started, and the gateway registered with
// the account's CLI once it listens as the account. The next run finds
// everything in place and runs nothing.
func TestAccountOpenShellSetupFirstUse(t *testing.T) {
	fastGatewayWaits(t)
	r := newOpenShellRig(t, "linux")
	r.holder = func(call int) int {
		if call < 3 {
			return 0
		}
		return 5001
	}
	started, err := r.o.Prepare(context.Background(), setupSettings())
	if err != nil || !started {
		t.Fatalf("prepare: started=%v err=%v", started, err)
	}
	if len(r.installs) != 1 || r.installs[0] != "0.1.3@"+r.o.home {
		t.Fatalf("installs = %v", r.installs)
	}
	got := strings.Join(r.ran(), "\n")
	for _, want := range []string{
		"systemctl --user start " + openShellGatewayUnit,
		"openshell gateway add https://127.0.0.1:17670 --local --name openshell",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("commands lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "gateway remove") {
		t.Fatalf("a missing registration was removed:\n%s", got)
	}

	before := len(r.ran())
	started, err = r.o.Prepare(context.Background(), setupSettings())
	if err != nil || started || len(r.installs) != 1 || len(r.ran()) != before {
		t.Fatalf("second prepare: started=%v err=%v installs=%v commands=%v", started, err, r.installs, r.ran()[before:])
	}

	// A gateway that stopped (the daemon exited idle) gets its install
	// checked again before it is started.
	r.mu.Lock()
	r.calls = 0
	r.mu.Unlock()
	if _, err := r.o.Prepare(context.Background(), setupSettings()); err != nil || len(r.installs) != 2 {
		t.Fatalf("restart: %v, installs %v", err, r.installs)
	}
}

// Another account's listener on the gateway port is the neutral
// account-busy refusal; nothing is started and nothing names the account.
func TestAccountOpenShellPortOfAnotherAccount(t *testing.T) {
	fastGatewayWaits(t)
	for _, holder := range []int{5002, -1} {
		r := newOpenShellRig(t, "linux")
		r.holder = func(int) int { return holder }
		_, err := r.o.Prepare(context.Background(), setupSettings())
		if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(err.Error(), SandboxAccountBusyReason) ||
			strings.Contains(err.Error(), "5002") {
			t.Fatalf("holder %d: %v", holder, err)
		}
		for _, c := range r.ran() {
			if strings.Contains(c, "start") {
				t.Fatalf("holder %d: started the unit: %v", holder, r.ran())
			}
		}
	}
}

// A release that cannot be installed (offline, a checksum that does not
// match the pin) refuses with openshell_prerequisite_missing and starts
// nothing; the next run tries again.
func TestAccountOpenShellInstallFailure(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.fail["install"] = "openshell: a release tarball does not match its checksum"
	_, err := r.o.Prepare(context.Background(), setupSettings())
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(err.Error(), openShellPrerequisiteReason) ||
		!strings.Contains(err.Error(), "checksum") || len(r.ran()) != 0 {
		t.Fatalf("prepare: %v, commands %v", err, r.ran())
	}
	delete(r.fail, "install")
	r.holder = func(int) int { return 5001 }
	r.registered = 17670
	if _, err := r.o.Prepare(context.Background(), setupSettings()); err != nil || len(r.installs) != 2 {
		t.Fatalf("retry: %v, installs %v", err, r.installs)
	}

	// No pin is no install at all.
	s := setupSettings()
	s.Enterprise.Version = ""
	if _, err := newOpenShellRig(t, "linux").o.Prepare(context.Background(), s); !strings.Contains(fmtErr(err), "exact release") {
		t.Fatalf("no pin: %v", err)
	}
}

func fmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// A gateway that never listens is a refusal that says what the unit did:
// exit 78 is the exec shim's missing prerequisite.
func TestAccountOpenShellGatewayNeverListens(t *testing.T) {
	fastGatewayWaits(t)
	r := newOpenShellRig(t, "linux")
	r.o.run = func(_ context.Context, name string, args, _ []string) (string, error) {
		if len(args) > 1 && args[1] == "show" {
			return "ActiveState=failed\nSubState=failed\nExecMainStatus=78", nil
		}
		return "", nil
	}
	started, err := r.o.Prepare(context.Background(), setupSettings())
	if !started || !strings.Contains(fmtErr(err), "exited 78") || !strings.Contains(fmtErr(err), openShellPrerequisiteReason) {
		t.Fatalf("prepare: started=%v err=%v", started, err)
	}
	r2 := newOpenShellRig(t, "linux")
	r2.fail["systemctl --user start"] = "Unit defenseclaw-openshell-gateway.service not found."
	run := r2.o.run
	r2.o.run = func(ctx context.Context, name string, args, env []string) (string, error) {
		if len(args) > 1 && args[1] == "show" {
			return "LoadState=not-found\nActiveState=inactive\nSubState=dead\nExecMainStatus=0", nil
		}
		return run(ctx, name, args, env)
	}
	// The unit's state in words, not systemctl's command line (#1202).
	if _, err := r2.o.Prepare(context.Background(), setupSettings()); !strings.Contains(fmtErr(err), "its service unit was not found") ||
		strings.Contains(fmtErr(err), "systemctl") {
		t.Fatalf("unit missing: %v", err)
	}
}

// On a Mac the agent is bootstrapped into the background domain of an ssh
// login when it is not loaded, then kickstarted; a stale registration of
// the name is replaced.
func TestAccountOpenShellMacAgentAndStaleRegistration(t *testing.T) {
	fastGatewayWaits(t)
	r := newOpenShellRig(t, "darwin")
	r.fail["launchctl print"] = "Could not find domain"
	r.holder = func(call int) int {
		if call < 3 {
			return 0
		}
		return 5001
	}
	if err := os.MkdirAll(filepath.Dir(r.metadata), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.metadata, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.registered = 17999
	if _, err := r.o.Prepare(context.Background(), setupSettings()); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	got := strings.Join(r.ran(), "\n")
	for _, want := range []string{
		"launchctl bootstrap user/5001 " + openShellGatewayPlist,
		"launchctl kickstart user/5001/" + openShellGatewayLabel,
		"openshell gateway remove openshell",
		"openshell gateway add https://127.0.0.1:17670 --local --name openshell",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("commands lack %q:\n%s", want, got)
		}
	}
	if strings.Index(got, "gateway remove") > strings.Index(got, "gateway add") {
		t.Fatalf("the stale registration was removed after the add:\n%s", got)
	}
}

// A gateway of the account's that its managed unit did not start is compared
// with the rendered configuration; setup mode, a gateway that is not running
// and the managed unit's own gateway have nothing to compare.
func TestAccountOpenShellDrift(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	// The account's own gateway listens on the port.
	r.holder = func(int) int { return 5001 }
	dir := t.TempDir()
	want := openshell.RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: openshell.DriverDocker}
	r.o.readRendered = func(tomlPath, envPath string) (openshell.RenderedGateway, string, error) {
		if tomlPath != filepath.Join(dir, "gateway.toml") || envPath != filepath.Join(dir, openshell.GatewayEnvFile) {
			t.Errorf("rendered paths %s %s", tomlPath, envPath)
		}
		return want, "sha256:x", nil
	}
	user := t.TempDir()
	r.o.readUser = func(goos string) (*openshell.GatewayConfigState, error) {
		return (&openshell.GatewayConfigurator{Dir: user, GOOS: goos}).Read()
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(user, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "prerequisite", Driver: "docker",
		GatewayConfigPath: filepath.Join(dir, "gateway.toml"), GatewayConfigDigest: "sha256:x"}}

	// The organization allows OpenShell's telemetry: an account that keeps
	// it off is no drift; the defaults match.
	want.TelemetryEnabled = true
	write(openshell.GatewayEnvFile, "OPENSHELL_TELEMETRY_ENABLED=false\n")
	// An own docker gateway in OpenShell's shared default namespace drifts
	// from the render (r102 GAP-0621); the managed namespace matches.
	if drift, err := r.o.Drift(s); err != nil || driftFields(drift) != "Docker sandbox namespace" {
		t.Fatalf("default namespace: %v %v", drift, err)
	}
	// So does one in the account's own namespace: a managed sandbox made
	// there is lost to the rendered gateway after its next start.
	write(openshell.GatewayTOMLFile, "[openshell]\nversion = 2\n[openshell.drivers.docker]\nsandbox_label = \""+openshell.AccountDockerNamespace(5001)+"\"\n")
	if drift, err := r.o.Drift(s); err != nil || driftFields(drift) != "Docker sandbox namespace" {
		t.Fatalf("own namespace: %v %v", drift, err)
	}
	managedNS := "[openshell.drivers.docker]\nsandbox_label = \"" + openshell.ManagedDockerNamespace + "\"\n"
	write(openshell.GatewayTOMLFile, "[openshell]\nversion = 2\n"+managedNS)
	if drift, err := r.o.Drift(s); err != nil || len(drift) != 0 {
		t.Fatalf("matching settings: %v %v", drift, err)
	}
	// It does not: telemetry on is drift. So is another listener.
	want.TelemetryEnabled = false
	write(openshell.GatewayEnvFile, "")
	write(openshell.GatewayTOMLFile, "[openshell]\nversion = 2\n[openshell.gateway]\nbind_address = \"0.0.0.0:17999\"\n"+managedNS)
	drift, err := r.o.Drift(s)
	if err != nil || driftFields(drift) != "gateway listener, OpenShell telemetry" {
		t.Fatalf("drift = %v, %v", drift, err)
	}
	if driftEventField(drift[0].Field) != "gateway_listener" || driftEventField(drift[1].Field) != "openshell_telemetry" {
		t.Fatalf("event fields %q %q", driftEventField(drift[0].Field), driftEventField(drift[1].Field))
	}
	// An untrusted render is an error, not a pass.
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{}, "", errors.New("not root-owned")
	}
	if _, err := r.o.Drift(s); err == nil {
		t.Fatal("an untrusted render passed")
	}
	// Setup mode and a host without a render compare nothing.
	s.Enterprise.Install = "setup"
	if drift, err := r.o.Drift(s); err != nil || drift != nil {
		t.Fatalf("setup mode: %v %v", drift, err)
	}
	s.Enterprise.Install, s.Enterprise.GatewayConfigPath = "prerequisite", ""
	if drift, err := r.o.Drift(s); err != nil || drift != nil {
		t.Fatalf("no render: %v %v", drift, err)
	}
	s.Enterprise.GatewayConfigPath = filepath.Join(dir, "gateway.toml")
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) { return want, "sha256:x", nil }
	// No gateway runs, or another account's: Prepare starts the managed
	// unit or refuses as busy; nothing of the account's own to compare.
	for _, holder := range []int{0, 5002} {
		r.holder = func(int) int { return holder }
		if drift, err := r.o.Drift(s); err != nil || drift != nil {
			t.Fatalf("holder %d: %v %v", holder, drift, err)
		}
	}
	// The managed unit runs the gateway: the render by construction, though
	// the account's own files say otherwise.
	r.holder = func(int) int { return 5001 }
	r.active = true
	if drift, err := r.o.Drift(s); err != nil || drift != nil {
		t.Fatalf("managed unit: %v %v", drift, err)
	}
}

// The MicroVM identity the render leaves open is the account's own: a foreign
// gateway at 1000:1000 drifts, one at the account's uid and gid does not
// (GAP-0254).
func TestAccountOpenShellDriftComparesTheAccountIdentity(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.holder = func(int) int { return 5001 }
	r.o.gid = 5101
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: openshell.DriverVM}, "sha256:x", nil
	}
	user := t.TempDir()
	r.o.readUser = func(goos string) (*openshell.GatewayConfigState, error) {
		return (&openshell.GatewayConfigurator{Dir: user, GOOS: goos}).Read()
	}
	s := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "prerequisite", Driver: "vm", GatewayConfigPath: "/etc/defenseclaw/openshell/gateway.toml"}}
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(user, openshell.GatewayTOMLFile), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(user, openshell.GatewayEnvFile), []byte("OPENSHELL_TELEMETRY_ENABLED=false\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("[openshell.gateway]\ncompute_driver = \"vm\"\n")
	drift, err := r.o.Drift(s)
	if err != nil || driftFields(drift) != "MicroVM workload identity" {
		t.Fatalf("default 1000:1000: %v %v", drift, err)
	}
	write("[openshell.gateway]\ncompute_driver = \"vm\"\n[openshell.drivers.vm]\nsandbox_uid = 5001\nsandbox_gid = 5101\n")
	if drift, err := r.o.Drift(s); err != nil || len(drift) != 0 {
		t.Fatalf("the account's identity: %v %v", drift, err)
	}
}

// Prerequisite mode (GAP-0186, GAP-0221, GAP-0377): no install, but the
// account's managed gateway unit is started, waited for and registered with
// the administrator's openshell CLI; the next run finds it in place.
func TestAccountOpenShellPrerequisiteFirstUse(t *testing.T) {
	fastGatewayWaits(t)
	r := newOpenShellRig(t, "linux")
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	r.holder = func(call int) int {
		if call < 2 {
			return 0
		}
		return 5001
	}
	s := prerequisiteSettings()
	started, err := r.o.Prepare(context.Background(), s)
	if err != nil || !started {
		t.Fatalf("prepare: started=%v err=%v", started, err)
	}
	if len(r.installs) != 0 {
		t.Fatalf("prerequisite mode installed %v", r.installs)
	}
	got := strings.Join(r.ran(), "\n")
	for _, want := range []string{
		"systemctl --user start " + openShellGatewayUnit,
		"openshell gateway add https://127.0.0.1:17670 --local --name openshell",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("commands lack %q:\n%s", want, got)
		}
	}
	before := len(r.ran())
	if started, err = r.o.Prepare(context.Background(), s); err != nil || started || len(r.ran()) != before {
		t.Fatalf("second prepare: started=%v err=%v commands=%v", started, err, r.ran()[before:])
	}

	// An OpenShell the administrator did not install, or one an account
	// could have changed, refuses before anything is started.
	q := newOpenShellRig(t, "linux")
	q.o.adminBinary = func(name string) (string, error) {
		return "", errors.New("openshell is in none of /usr/bin, /usr/local/bin")
	}
	if _, err := q.o.Prepare(context.Background(), s); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) ||
		!strings.Contains(err.Error(), openShellPrerequisiteReason) || !strings.Contains(err.Error(), "/usr/bin") || len(q.ran()) != 0 {
		t.Fatalf("no administrator OpenShell: %v, commands %v", err, q.ran())
	}
}

func prerequisiteSettings() sandboxrelay.DaemonSettings {
	return sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "prerequisite", Driver: "vm", GatewayPort: 17670}}
}

// Stop stops the managed gateway unit in both modes, and a prerequisite-mode
// gateway only when the managed unit runs it.
func TestAccountOpenShellStop(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.o.Stop(context.Background(), prerequisiteSettings())
	if got := r.ran(); len(got) != 1 || got[0] != "systemctl --user is-active "+openShellGatewayUnit {
		t.Fatalf("a gateway the managed unit does not run was stopped: %v", got)
	}
	r = newOpenShellRig(t, "linux")
	r.active = true
	r.o.Stop(context.Background(), prerequisiteSettings())
	if got := r.ran(); len(got) != 2 || got[1] != "systemctl --user stop "+openShellGatewayUnit {
		t.Fatalf("prerequisite stop: %v", got)
	}
	r = newOpenShellRig(t, "linux")
	r.o.Stop(context.Background(), setupSettings())
	if got := r.ran(); len(got) != 1 || got[0] != "systemctl --user stop "+openShellGatewayUnit {
		t.Fatalf("stop: %v", got)
	}
}

func floorResolve(sandboxrelay.ResolveRequest) (sandboxrelay.ResolveResponse, error) {
	return sandboxrelay.ResolveResponse{V: 1, Registration: sandboxrelay.RegistrationView{ID: "reg-7"},
		Effective: json.RawMessage(`{"profile":"balanced","floor":{"min_profile":"balanced"}}`)}, nil
}

// A create whose OpenShell settings drifted is paused with the drift notice,
// the drift is reported under the run's registration, which is then
// released; nothing is created. A create whose setup-mode OpenShell is not
// ready is refused the same way, with the reason.
func TestSandboxDaemonCreateReadiesOpenShell(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.relay.resolve = floorResolve
	f.os.drift = []openshell.SettingDrift{{Field: "gateway listener", Want: "127.0.0.1:17670", Have: "0.0.0.0:17999"}}
	f.run(t)
	client := sandboxapi.NewUnixClient(f.socket)
	_, err := client.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode"})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(err.Error(), sandboxapi.SettingsDrift("gateway listener")) {
		t.Fatalf("drifted create: %v", err)
	}
	if f.os.prepared.Load() != 0 || f.relay.deleted.Load() != 1 {
		t.Fatalf("prepared %d deleted %d", f.os.prepared.Load(), f.relay.deleted.Load())
	}
	f.relay.eventsMu.Lock()
	batches := append([]sandboxrelay.EventBatch(nil), f.relay.events...)
	f.relay.eventsMu.Unlock()
	if len(batches) != 1 || batches[0].Registration != "reg-7" || len(batches[0].Events) != 1 ||
		batches[0].Events[0].Kind != sandboxrelay.EventSettingsDrift || string(batches[0].Events[0].Payload) != `{"field":"gateway_listener"}` {
		t.Fatalf("drift events = %+v", batches)
	}

	f.os.drift = nil
	f.os.prepare = func(sandboxrelay.DaemonSettings) (bool, error) {
		return true, openShellPrerequisiteError("OpenShell 0.1.3 could not be installed into your ~/.local: offline")
	}
	_, err = client.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode"})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || !strings.Contains(err.Error(), openShellPrerequisiteReason) ||
		f.os.prepared.Load() != 1 || f.relay.deleted.Load() != 2 {
		t.Fatalf("unready create: %v (prepared %d deleted %d)", err, f.os.prepared.Load(), f.relay.deleted.Load())
	}
	if list := f.d.regs.list(); len(list) != 0 {
		t.Fatalf("registrations after refusals: %v", list)
	}
}

// A run's preflight readies the account's OpenShell before its create
// (POST ready): the daemon installs and starts it and answers the status; a
// failure is the run's refusal; settings that make sandboxes unavailable
// ready nothing (GAP-0437, GAP-0441).
func TestSandboxDaemonReadyBeforeFirstRun(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{Allowed: true}, nil
	}
	f.run(t)
	client := sandboxapi.NewUnixClient(f.socket)
	st, err := client.Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"})
	if err != nil || st == nil || st.Managed == nil || st.IngressAddr == "" || st.EgressAddr == "" ||
		f.d.rt.listenersReady() != nil || f.os.prepared.Load() != 1 {
		t.Fatalf("ready: %+v, %v (prepared %d)", st, err, f.os.prepared.Load())
	}
	f.os.prepare = func(sandboxrelay.DaemonSettings) (bool, error) {
		return false, openShellPrerequisiteError("OpenShell 0.1.3 could not be installed into your ~/.local: offline")
	}
	if _, err := client.Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"}); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) ||
		!strings.Contains(err.Error(), openShellPrerequisiteReason) {
		t.Fatalf("unready: %v", err)
	}
	if err := f.d.rt.listenersReady(); err != nil {
		t.Fatalf("refused Ready removed listeners it found: %v", err)
	}

	g := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.Settings.Available, o.Settings.Unavailable = false, "no OpenShell here"
	})
	g.run(t)
	if _, err := sandboxapi.NewUnixClient(g.socket).Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"}); !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) ||
		g.os.prepared.Load() != 0 {
		t.Fatalf("unavailable settings: %v (prepared %d)", err, g.os.prepared.Load())
	}
}

func TestSandboxDaemonReadyFailureReleasesNewListenersWithoutGatewayList(t *testing.T) {
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.countRunning = func(context.Context) (int, error) { return 0, errors.New("OpenShell gateway unavailable") }
	})
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{Allowed: true}, nil
	}
	f.os.prepare = func(sandboxrelay.DaemonSettings) (bool, error) {
		return false, openShellPrerequisiteError("OpenShell could not be prepared: offline")
	}
	f.run(t)
	_, err := sandboxapi.NewUnixClient(f.socket).Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || f.d.listening() {
		t.Fatalf("refused Ready kept newly bound listeners: %v (listening %t)", err, f.d.listening())
	}
}

func TestSandboxDaemonReadyRefusesBusyIngressBeforeInstall(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{Allowed: true}, nil
	}
	addr := "127.0.0.1:" + strconv.Itoa(f.d.currentSettings().Operational.IngressPort)
	squatter, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = squatter.Close() })
	f.run(t)
	_, err = sandboxapi.NewUnixClient(f.socket).Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"})
	if err == nil {
		t.Fatalf("busy ingress reported ready after preparing OpenShell %d times", f.os.prepared.Load())
	}
	if e := sandboxapi.AsError(err); e.Detail != SandboxAccountBusyReason || f.os.prepared.Load() != 0 {
		t.Fatalf("busy ingress changed account or reported ready: %v (prepared %d)", err, f.os.prepared.Load())
	}
}

// GAP-0534: Ready is callable directly, and must consult the current
// organization profile before setup mode installs anything for the account.
func TestSandboxDaemonReadyRefusesForbiddenAccountBeforeInstall(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{Profile: "no-sandboxes", Allowed: false}, nil
	}
	f.run(t)
	_, err := sandboxapi.NewUnixClient(f.socket).Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"})
	if !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) || f.os.prepared.Load() != 0 {
		t.Fatalf("forbidden account ready = %v (prepared %d)", err, f.os.prepared.Load())
	}
	// An unavailable policy answer cannot authorize an install either.
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{}, sandboxrelay.ErrGatewayUnreachable
	}
	_, err = sandboxapi.NewUnixClient(f.socket).Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) || f.os.prepared.Load() != 0 {
		t.Fatalf("unreadable policy ready = %v (prepared %d)", err, f.os.prepared.Load())
	}
}

// A create on a Mac whose Docker does not answer for the account is refused
// with the prerequisite and the contact before anything is resolved or
// registered (GAP-0443).
func TestSandboxDaemonMacCreateNeedsDocker(t *testing.T) {
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.goos = "darwin"
		o.Settings.Enterprise.Driver = "vm"
		o.dockerEngine = func(context.Context) error { return errors.New("Cannot connect to the Docker daemon") }
	})
	f.relay.resolve = floorResolve
	f.run(t)
	_, err := sandboxapi.NewUnixClient(f.socket).Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode"})
	if !sandboxapi.IsCode(err, sandboxapi.CodeUnavailable) ||
		!strings.Contains(err.Error(), "Docker does not answer for your account (Cannot connect to the Docker daemon)") ||
		!strings.Contains(err.Error(), "it-help@example.com") {
		t.Fatalf("create without Docker: %v", err)
	}
	if f.os.prepared.Load() != 0 || f.relay.deleted.Load() != 0 {
		t.Fatalf("prepared %d deleted %d", f.os.prepared.Load(), f.relay.deleted.Load())
	}
}

// Setup mode's manager runs the openshell CLI the daemon installed.

func TestSandboxDaemonSetupModeCLI(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	if f.d.home == "" {
		t.Skip("no home directory")
	}
	if got := f.d.config().OpenShell.EffectiveBinary(); got != filepath.Join(f.d.home, ".local", "bin", "openshell") {
		t.Fatalf("setup-mode binary = %q", got)
	}
	g := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		s := *o.Settings
		s.Enterprise.Install = "prerequisite"
		o.Settings = &s
	})
	restore := adminOpenShell
	t.Cleanup(func() { adminOpenShell = restore })
	adminOpenShell = func(string, string) (string, error) { return "", errors.New("not installed") }
	if got := g.d.buildConfig().OpenShell.EffectiveBinary(); got != "openshell" {
		t.Fatalf("prerequisite-mode binary without an administrator install = %q", got)
	}
	// The administrator's CLI by path: a macOS LaunchAgent's PATH holds no
	// /usr/local/bin.
	adminOpenShell = func(_, name string) (string, error) { return "/usr/local/bin/" + name, nil }
	if got := g.d.buildConfig().OpenShell.EffectiveBinary(); got != "/usr/local/bin/openshell" {
		t.Fatalf("prerequisite-mode binary = %q", got)
	}
}

// A run refused because another account uses the sandboxes is reported to
// the managed gateway without a registration, from the readiness a run asks
// for first and from a create, with the agent when the create knows it; the
// reports are paced, but a refusal inside the pace goes with the next batch
// and a batch the gateway did not take is sent again (GAP-0598, GAP-0660).
// A refusal that is not account-busy reports nothing.
func TestSandboxDaemonReportsAccountBusyRefusals(t *testing.T) {
	prevEvery, prevMax := accountBusyReportEvery, accountBusyRetryMax
	accountBusyReportEvery, accountBusyRetryMax = 200*time.Millisecond, 400*time.Millisecond
	t.Cleanup(func() { accountBusyReportEvery, accountBusyRetryMax = prevEvery, prevMax })
	f := newSandboxDaemonFixture(t)
	f.relay.resolve = floorResolve
	f.os.holder.Store(int64(f.d.uid) + 1)
	f.run(t)
	client := sandboxapi.NewUnixClient(f.socket)
	batches := func() []sandboxrelay.EventBatch {
		f.relay.eventsMu.Lock()
		defer f.relay.eventsMu.Unlock()
		return append([]sandboxrelay.EventBatch(nil), f.relay.events...)
	}
	_, err := client.Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"})
	if e := sandboxapi.AsError(err); e.Detail != SandboxAccountBusyReason || f.os.prepared.Load() != 0 {
		t.Fatalf("ready beside another account's gateway: %v (prepared %d)", err, f.os.prepared.Load())
	}
	got := batches()
	if len(got) != 1 || got[0].Registration != "" || len(got[0].Events) != 1 ||
		got[0].Events[0].Kind != sandboxrelay.EventAccountBusy || string(got[0].Events[0].Payload) != `{"harness":""}` {
		t.Fatalf("busy report = %+v", got)
	}
	// Two more inside the pace: not sent at once, both in the next batch.
	for range 2 {
		if _, err = client.Ready(context.Background(), sandboxapi.ReadyRequest{Harness: "claudecode"}); err == nil {
			t.Fatal("ready beside another account's gateway succeeded")
		}
	}
	if len(batches()) != 1 {
		t.Fatalf("a refusal inside the pace was sent at once: %d batches", len(batches()))
	}
	waitBatches := func(n int) []sandboxrelay.EventBatch {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if got := batches(); len(got) >= n {
				return got
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("%d batches, want %d", len(batches()), n)
		return nil
	}
	if got = waitBatches(2); len(got[1].Events) != 2 || got[1].Events[0].Kind != sandboxrelay.EventAccountBusy {
		t.Fatalf("the refusals inside the pace = %+v", got[1])
	}

	// The gateway does not take the next batch twice: it is sent again.
	f.relay.eventsFail.Store(2)
	f.os.holder.Store(0)
	f.os.prepare = func(sandboxrelay.DaemonSettings) (bool, error) { return true, accountBusyError() }
	time.Sleep(accountBusyReportEvery)
	if _, err = client.Create(context.Background(), sandboxapi.CreateRequest{Harness: "claudecode"}); sandboxapi.AsError(err).Detail != SandboxAccountBusyReason {
		t.Fatalf("create beside another account: %v", err)
	}
	got = waitBatches(3)
	if got[2].Registration != "" || len(got[2].Events) != 1 || got[2].Events[0].Kind != sandboxrelay.EventAccountBusy ||
		string(got[2].Events[0].Payload) != `{"harness":"claudecode"}` || f.relay.eventsFail.Load() != 0 {
		t.Fatalf("create busy report after failed sends = %+v", got)
	}

	f.d.reportAccountBusy(context.Background(), "claudecode", openShellPrerequisiteError("offline"))
	time.Sleep(2 * accountBusyReportEvery)
	if len(batches()) != 3 {
		t.Fatal("a prerequisite refusal was reported as account busy")
	}
}

// A daemon that exits with no sandbox running stops its setup-mode
// OpenShell gateway; one with a sandbox running leaves it.
func TestSandboxDaemonStopsIdleOpenShell(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.d.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if f.os.stopped.Load() != 1 {
		t.Fatalf("stopped %d", f.os.stopped.Load())
	}

	g := newSandboxDaemonFixture(t)
	g.running.Store(1)
	g.d.stopOpenShellIfIdle()
	if g.os.stopped.Load() != 0 {
		t.Fatal("stopped the gateway under a running sandbox")
	}
}

// A ready from a CLI of DefenseClaw 1.0.3 or older does not say which agent
// the run is for, and profiles match per connector. The first agent the
// organization runs being forbidden must not
// refuse a run of an agent whose profile allows sandboxes, configured or
// not: Ready readies (the create judges the run's own agent). Nor must an
// agent whose view is slow or unanswered: one view timing out, or every
// other one, does not refuse or hold up a ready another agent's profile
// allows (S2 review, loop round 2). It still refuses before any install when
// no agent's profile allows a run, or when the gateway answers none of them,
// and then only after asking every agent, the daemon's own included.
func TestSandboxDaemonReadyReadiesForAnyAllowedAgent(t *testing.T) {
	for _, tc := range []struct {
		name         string
		harnesses    []string
		allowed      map[string]bool
		down         map[string]bool
		slow         map[string]bool
		wantCode     string
		wantPrepared int64
	}{
		{"first agent forbidden, second allowed", []string{"claudecode", "codex"}, map[string]bool{"codex": true}, nil, nil, "", 1},
		{"configured agent forbidden, another allowed", []string{"claudecode"}, map[string]bool{"codex": true}, nil, nil, "", 1},
		{"first agent unanswered, another allowed", []string{"claudecode", "codex"}, map[string]bool{"codex": true},
			map[string]bool{"claudecode": true}, nil, "", 1},
		{"first agent's view times out, another allowed", []string{"claudecode", "codex"}, map[string]bool{"codex": true},
			nil, map[string]bool{"claudecode": true}, "", 1},
		{"configured agent's view times out, another allowed", []string{"claudecode"}, map[string]bool{"codex": true},
			nil, map[string]bool{"claudecode": true}, "", 1},
		{"every other agent's view times out, one allowed", []string{"claudecode", "codex"}, map[string]bool{"opencode": true},
			nil, map[string]bool{"*": true}, "", 1},
		{"every agent forbidden", []string{"claudecode", "codex"}, nil, nil, nil, sandboxapi.CodeAdminViolation, 0},
		{"first agent forbidden, others unanswered", []string{"claudecode", "codex"}, nil, map[string]bool{"*": true}, nil,
			sandboxapi.CodeUnavailable, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
				o.Settings.Operational.Harnesses = tc.harnesses
			})
			var mu sync.Mutex
			var asked []string
			f.relay.explainCtx = func(ctx context.Context, req sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
				mu.Lock()
				asked = append(asked, req.Connector)
				first := len(asked) == 1
				mu.Unlock()
				// slow holds an agent's own policy view (the one Ready asks
				// for each agent); the unclaimed view of the status Ready
				// answers with is not one.
				if req.Harness != "" && (tc.slow[req.Connector] || tc.slow["*"] && !tc.allowed[req.Connector]) {
					<-ctx.Done()
					return sandboxapi.ManagedExplain{}, ctx.Err()
				}
				if tc.down[req.Connector] || tc.down["*"] && !first {
					return sandboxapi.ManagedExplain{}, sandboxrelay.ErrGatewayUnreachable
				}
				return sandboxapi.ManagedExplain{Allowed: tc.allowed[req.Connector]}, nil
			}
			f.run(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err := sandboxapi.NewUnixClient(f.socket).Ready(ctx, sandboxapi.ReadyRequest{})
			mu.Lock()
			defer mu.Unlock()
			if tc.wantCode == "" && err != nil || tc.wantCode != "" && !sandboxapi.IsCode(err, tc.wantCode) ||
				f.os.prepared.Load() != tc.wantPrepared {
				t.Fatalf("ready = %v (prepared %d, asked %v); want code %q, prepared %d",
					err, f.os.prepared.Load(), asked, tc.wantCode, tc.wantPrepared)
			}
			if tc.wantCode != "" {
				for _, name := range harness.Names() {
					if !slices.Contains(asked, name) {
						t.Fatalf("refused after asking for %v, not every agent (%s missing)", asked, name)
					}
				}
			}
		})
	}
}

// Ready asks only the agent the run names, so no other agent's view can
// rate-limit, hold up or refuse its first run, and an agent no harness
// knows is refused before anything is asked. A ready that names none (a CLI
// of DefenseClaw 1.0.3 or older) asks every agent, but never more views at
// once than readyViewsInFlight, inside the managed gateway's per-account
// policy admission (sandboxBudgetPolicy.InFlight), so slow denied views
// cannot push the allowed agent's view into a 429. A view the gateway's
// admission refused is asked again before Ready refuses; one it keeps
// refusing fails the ready closed (S2 review, loop round 2).
func TestSandboxDaemonReadyStaysInsideThePolicyAdmission(t *testing.T) {
	admit := sandboxBudgetLimits[sandboxBudgetPolicy].InFlight
	if readyViewsInFlight >= admit {
		t.Fatalf("readyViewsInFlight %d leaves no room in the gateway's %d policy requests", readyViewsInFlight, admit)
	}
	const last = "<the older CLI's last agent>"
	for _, tc := range []struct {
		name      string
		harness   string
		allowed   string
		limited   int
		wantCode  string
		wantAsked []string
	}{
		{name: "named agent allowed, every other forbidden", harness: "codex", allowed: "codex", wantAsked: []string{"codex"}},
		{name: "named agent forbidden, another allowed", harness: "claudecode", allowed: "codex",
			wantCode: sandboxapi.CodeAdminViolation, wantAsked: []string{"claudecode"}},
		{name: "named agent rate-limited first", harness: "codex", allowed: "codex", limited: 2,
			wantAsked: []string{"codex", "codex", "codex"}},
		{name: "named agent always rate-limited", harness: "codex", allowed: "codex", limited: 1 << 20,
			wantCode: sandboxapi.CodeUnavailable},
		{name: "no such agent", harness: "nosuchagent", allowed: "codex", wantCode: sandboxapi.CodeInvalid, wantAsked: []string{}},
		{name: "older CLI, allowed agent asked last", allowed: last},
		{name: "older CLI, allowed agent rate-limited first", allowed: last, limited: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSandboxDaemonFixture(t)
			allowed := tc.allowed
			if allowed == last {
				order := f.d.olderCLIReadyHarnesses()
				allowed = order[len(order)-1]
			}
			var mu sync.Mutex
			asked := []string{}
			inFlight, maxInFlight, limited := 0, 0, tc.limited
			f.relay.explainCtx = func(ctx context.Context, req sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
				if req.Harness == "" {
					// The unclaimed view of the status Ready answers with.
					return sandboxapi.ManagedExplain{Allowed: true}, nil
				}
				mu.Lock()
				asked = append(asked, req.Connector)
				inFlight++
				maxInFlight = max(maxInFlight, inFlight)
				over := inFlight > admit
				rateLimited := !over && req.Connector == allowed && limited > 0
				if rateLimited {
					limited--
				}
				mu.Unlock()
				defer func() {
					mu.Lock()
					inFlight--
					mu.Unlock()
				}()
				if over || rateLimited {
					return sandboxapi.ManagedExplain{}, &sandboxrelay.Error{Status: http.StatusTooManyRequests, Reason: "rate_limited"}
				}
				if req.Connector != allowed {
					// A denied agent's view is slow, holding its admission.
					select {
					case <-ctx.Done():
						return sandboxapi.ManagedExplain{}, ctx.Err()
					case <-time.After(150 * time.Millisecond):
					}
					return sandboxapi.ManagedExplain{Allowed: false}, nil
				}
				return sandboxapi.ManagedExplain{Allowed: true}, nil
			}
			f.run(t)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, err := sandboxapi.NewUnixClient(f.socket).Ready(ctx, sandboxapi.ReadyRequest{Harness: tc.harness})
			mu.Lock()
			defer mu.Unlock()
			wantPrepared := int64(0)
			if tc.wantCode == "" {
				wantPrepared = 1
			}
			if tc.wantCode == "" && err != nil || tc.wantCode != "" && !sandboxapi.IsCode(err, tc.wantCode) ||
				f.os.prepared.Load() != wantPrepared {
				t.Fatalf("ready = %v (prepared %d, asked %v); want code %q, prepared %d",
					err, f.os.prepared.Load(), asked, tc.wantCode, wantPrepared)
			}
			if tc.wantAsked != nil && !slices.Equal(asked, tc.wantAsked) {
				t.Fatalf("asked %v, want %v", asked, tc.wantAsked)
			}
			if maxInFlight > readyViewsInFlight {
				t.Fatalf("%d policy views at once, past readyViewsInFlight %d (gateway admits %d)", maxInFlight, readyViewsInFlight, admit)
			}
		})
	}
}
