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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The account's gateway is stopped once no sandbox of the account runs and
// the linger after its last ready passed, so the next account gets the one
// gateway port at once, not when the daemon idles out (GAP-0465). A running
// sandbox keeps it, and another account's gateway is not this daemon's.
func TestSandboxDaemonStopsGatewayWhenNoSandboxRuns(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	f.os.holder.Store(int64(os.Getuid()))
	f.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())
	f.running.Store(1)
	if f.d.check(ctx); f.os.stopped.Load() != 0 {
		t.Fatal("stopped the gateway under a running sandbox")
	}
	f.running.Store(0)
	f.d.openShellUsed.Store(time.Now().UnixNano())
	if f.d.check(ctx); f.os.stopped.Load() != 0 {
		t.Fatal("stopped the gateway between a run's ready and its create")
	}
	f.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())
	if f.d.check(ctx); f.os.stopped.Load() != 1 {
		t.Fatalf("idle gateway: stopped %d", f.os.stopped.Load())
	}
	f.os.holder.Store(4242)
	if f.d.check(ctx); f.os.stopped.Load() != 1 {
		t.Fatal("stopped another account's gateway")
	}
}

// A completed stop or delete hands the shared port to the next account
// before returning, even if the last preflight was less than a minute ago.
func TestSandboxDaemonHandoverAfterLifecycle(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	f.os.holder.Store(int64(os.Getuid()))
	f.d.openShellUsed.Store(time.Now().UnixNano())
	f.d.stops.Store(1)
	f.running.Store(1)
	f.d.handoverOpenShell(context.Background())
	if n := f.os.stopped.Load(); n != 0 {
		t.Fatalf("stopped under a running sandbox: %d", n)
	}
	f.running.Store(0)
	f.d.handoverOpenShell(context.Background())
	if n := f.os.stopped.Load(); n != 1 {
		t.Fatalf("idle gateway was not handed over: %d", n)
	}
}

// GAP-0237: a foreign sandbox that foreign_sandboxes: alert leaves running
// keeps an idle gateway only while it runs: the daemon looks again soon and
// stops the gateway once it ended. A stop or delete of the account's last
// sandbox does not wait for it at all: the sweep records it and the gateway
// stops with it, within the sweep's bound, so the next account can start.
func TestSandboxDaemonForeignAlertSandboxDoesNotHoldTheHandover(t *testing.T) {
	prev := foreignRecheckEvery
	foreignRecheckEvery = 20 * time.Millisecond
	t.Cleanup(func() { foreignRecheckEvery = prev })
	var foreign atomic.Bool
	var sweeps atomic.Int32
	foreign.Store(true)
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.sweepForeign = func(context.Context) (bool, error) {
			sweeps.Add(1)
			return foreign.Load(), nil
		}
	})
	f.run(t)
	ctx := context.Background()
	f.os.holder.Store(int64(os.Getuid()))
	f.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())
	if f.d.check(ctx); f.os.stopped.Load() != 0 || sweeps.Load() == 0 {
		t.Fatalf("an idle check stopped the gateway of a running foreign sandbox: stopped %d, sweeps %d", f.os.stopped.Load(), sweeps.Load())
	}
	foreign.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for f.os.stopped.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.os.stopped.Load() != 1 {
		t.Fatal("the gateway stayed up after the foreign sandbox ended")
	}

	foreign.Store(true)
	f.os.holder.Store(int64(os.Getuid()))
	f.d.openShellUsed.Store(time.Now().UnixNano())
	f.d.stops.Store(1)
	start := time.Now()
	f.d.handoverOpenShell(ctx)
	if n := f.os.stopped.Load(); n != 2 {
		t.Fatalf("the hand-over kept the gateway for a foreign sandbox: stopped %d", n)
	}
	if took := time.Since(start); took > foreignSweepTimeout+15*time.Second {
		t.Fatalf("the hand-over took %s", took)
	}
	f.d.stops.Store(0)
}

// TestSandboxDaemonChecksAgainRightBeforeItStopsTheGateway: the idle stop
// of the account's gateway counted its sandboxes once, then swept the
// gateway, which reads OpenShell's sandboxes afresh, and stopped it: a
// sandbox another OpenShell client started between the count and the
// sweep went down with it, and so did every sandbox when the sweep could
// not read OpenShell at all. Now the count is made again after the sweep,
// under the same lifecycle, right before the stop, and a sweep that fails
// keeps the gateway; it stops once the gateway holds nothing.
func TestSandboxDaemonChecksAgainRightBeforeItStopsTheGateway(t *testing.T) {
	prev := foreignRecheckEvery
	foreignRecheckEvery = time.Hour
	t.Cleanup(func() { foreignRecheckEvery = prev })
	var fx *sandboxDaemonFixture
	var startedMeanwhile, sweepFails atomic.Bool
	fx = newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.sweepForeign = func(context.Context) (bool, error) {
			if sweepFails.Load() {
				return false, errors.New("openshell: list sandboxes: context deadline exceeded")
			}
			if startedMeanwhile.Load() {
				fx.running.Store(1)
			}
			return false, nil
		}
	})
	fx.run(t)
	ctx := context.Background()
	idle := func() {
		fx.os.holder.Store(int64(os.Getuid()))
		fx.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())
	}
	idle()
	startedMeanwhile.Store(true)
	if fx.d.check(ctx); fx.os.stopped.Load() != 0 {
		t.Fatal("stopped the gateway under a sandbox the sweep found started")
	}
	startedMeanwhile.Store(false)
	fx.running.Store(0)
	sweepFails.Store(true)
	idle()
	if fx.d.check(ctx); fx.os.stopped.Load() != 0 {
		t.Fatal("stopped the gateway when OpenShell's sandboxes could not be read")
	}
	sweepFails.Store(false)
	idle()
	if fx.d.check(ctx); fx.os.stopped.Load() != 1 {
		t.Fatalf("an idle gateway was not stopped: %d", fx.os.stopped.Load())
	}
	// One DefenseClaw cannot connect to (its registration or certificates
	// broke) may still run MicroVMs, which the stop would end with no
	// flush: it is stopped only once no MicroVM runs as the account, and
	// kept when they cannot be counted. The daemon's stop on exit holds
	// the same rule.
	var vms atomic.Int64
	var countFails atomic.Bool
	unreachable := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		o.countMicroVMs = func(context.Context) (int, error) {
			if countFails.Load() {
				return 0, errors.New("ps failed")
			}
			return int(vms.Load()), nil
		}
	})
	unreachable.run(t)
	gone := func() {
		unreachable.os.holder.Store(int64(os.Getuid()))
		unreachable.d.openShellUsed.Store(time.Now().Add(-2 * openShellGatewayLinger).UnixNano())
	}
	vms.Store(1)
	gone()
	if unreachable.d.check(ctx); unreachable.os.stopped.Load() != 0 {
		t.Fatal("stopped a gateway DefenseClaw cannot read under a live MicroVM")
	}
	if unreachable.d.stopOpenShellIfIdle(); unreachable.os.stopped.Load() != 0 {
		t.Fatal("the stop on exit ended a live MicroVM")
	}
	vms.Store(0)
	countFails.Store(true)
	gone()
	if unreachable.d.check(ctx); unreachable.os.stopped.Load() != 0 {
		t.Fatal("stopped a gateway DefenseClaw cannot read with its MicroVMs not counted")
	}
	countFails.Store(false)
	gone()
	if unreachable.d.check(ctx); unreachable.os.stopped.Load() != 1 {
		t.Fatalf("a gateway DefenseClaw cannot reach, with no MicroVM, was not stopped: %d", unreachable.os.stopped.Load())
	}
}

// A stop or delete of a kept sandbox starts the account's gateway the daemon
// stopped; one that listens is used as it is; another account's is refused
// with the one-account-at-a-time text (GAP-0492), except for a delete of a
// name the account has no sandbox of, which says so (GAP-0126). Status says that text too,
// not certificates and CAs, and shows no sandbox port the daemon does not
// hold (GAP-0461).
func TestSandboxDaemonGatewayForKeptSandboxes(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.run(t)
	ctx := context.Background()
	c := sandboxapi.NewUnixClient(f.socket)
	_, _ = c.Delete(ctx, "kept1", sandboxapi.DeleteRequest{})
	_, _ = c.Stop(ctx, "kept1")
	if n := f.os.prepared.Load(); n != 2 {
		t.Fatalf("readied %d times for a delete and a stop", n)
	}
	f.os.holder.Store(int64(os.Getuid()))
	if _, _ = c.Stop(ctx, "kept1"); f.os.prepared.Load() != 2 {
		t.Fatal("readied a gateway that listens")
	}
	f.os.holder.Store(4242)
	// kept1 is a name the account has no sandbox of: that is the answer,
	// whoever holds the port (GAP-0126).
	_, err := c.Delete(ctx, "kept1", sandboxapi.DeleteRequest{})
	if err == nil || !strings.Contains(err.Error(), "no DefenseClaw sandbox named") || f.os.prepared.Load() != 2 {
		t.Fatalf("delete of an absent name while another account holds the port: %v", err)
	}
	if _, err := c.Stop(ctx, "kept1"); err == nil || !strings.Contains(err.Error(), "one account at a time") {
		t.Fatalf("stop while another account holds the port: %v", err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.Available || st.GatewayElsewhere != "another account" || st.Reason != sandboxAccountBusyMessage ||
		st.IngressAddr != "" || st.EgressAddr != "" {
		t.Fatalf("status: %+v, %v", st, err)
	}
	if strings.Contains(st.Reason, "certificate") || strings.Contains(st.Reason, " CA") {
		t.Fatalf("status reason: %q", st.Reason)
	}
}

// A deleted sandbox with only a retained snapshot needs no gateway. A
// different account can hold the shared port while its record is removed.
func TestSandboxDaemonDeleteRetainedWhileOtherAccountHoldsGateway(t *testing.T) {
	f := newSandboxDaemonFixture(t, func(o *SandboxDaemonOptions) {
		seedSandboxRecord(t, o.StateDir, "retained", map[string]any{"retained": true})
	})
	f.run(t)
	f.os.holder.Store(4242)
	ctl := &managedSandboxController{Manager: f.d.rt.manager, d: f.d}
	resp, err := ctl.Delete(t.Context(), "retained", sandboxapi.DeleteRequest{})
	if err != nil || resp == nil || !resp.Deleted {
		t.Fatalf("delete retained with another account's gateway: %+v, %v", resp, err)
	}
	if f.os.prepared.Load() != 0 {
		t.Fatal("readied a gateway to delete only a retained snapshot")
	}
	if _, err := ctl.Manager.Get(t.Context(), "retained"); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("retained record survived: %v", err)
	}
	// A name with no sandbox at all says so, not that another account is
	// using the sandboxes (GAP-0126).
	if _, err := ctl.Delete(t.Context(), "never-made", sandboxapi.DeleteRequest{}); !sandboxapi.IsCode(err, sandboxapi.CodeNotFound) {
		t.Fatalf("delete of an absent name while another account holds the gateway: %v", err)
	}
}

// A second OpenShell gateway the account starts writes its own client
// certificates into the registration of the default name; the next ready
// registers the managed gateway again (GAP-0495).
func TestAccountOpenShellRepairsOverwrittenRegistration(t *testing.T) {
	fastGatewayWaits(t)
	r := newOpenShellRig(t, "linux")
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	r.holder = func(int) int { return 5001 }
	r.active = true
	tlsDir := filepath.Join(r.o.home, filepath.FromSlash(openShellTLSDirRel))
	mtls := filepath.Join(r.o.home, ".config", "openshell", "gateways", "openshell", "mtls")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range [][3]string{{"ca.crt", "ca.crt", "managed ca"}, {"client/tls.crt", "tls.crt", "managed cert"}, {"client/tls.key", "tls.key", "managed key"}} {
		write(filepath.Join(tlsDir, filepath.FromSlash(f[0])), f[2])
		write(filepath.Join(mtls, f[1]), f[2])
	}
	r.o.discover = func(openshell.DiscoverOptions) (*openshell.Registration, error) {
		return &openshell.Registration{Name: "openshell", Endpoint: "https://127.0.0.1:17670", AuthMode: openshell.AuthModeMTLS,
			TLS: &openshell.TLSFiles{CA: filepath.Join(mtls, "ca.crt"), Cert: filepath.Join(mtls, "tls.crt"), Key: filepath.Join(mtls, "tls.key")}}, nil
	}
	add := "openshell gateway add https://127.0.0.1:17670 --local --name openshell"
	if _, err := r.o.Prepare(context.Background(), prerequisiteSettings()); err != nil || strings.Contains(strings.Join(r.ran(), "\n"), add) {
		t.Fatalf("intact registration: %v, %v", err, r.ran())
	}
	write(filepath.Join(mtls, "tls.crt"), "another gateway's cert")
	if _, err := r.o.Prepare(context.Background(), prerequisiteSettings()); err != nil || !strings.Contains(strings.Join(r.ran(), "\n"), add) {
		t.Fatalf("overwritten registration: %v, %v", err, r.ran())
	}
}

// The managed unit's gateway runs the install mode's openshell-gateway with
// --config on the rendered file and nothing else; the account's own
// gateway.toml is not read by it, so the command line is what is compared:
// another configuration or an added flag is drift (GAP-0512).
func TestAccountOpenShellManagedGatewayCommandDrift(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.holder = func(int) int { return 5001 }
	r.active, r.pid = true, 77
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: openshell.DriverVM}, "", nil
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, openshell.GatewayTOMLFile)
	s := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "prerequisite", Driver: "vm", GatewayPort: 17670,
		GatewayConfigPath: cfg}}
	for _, tc := range []struct {
		args  string
		drift bool
	}{
		{"/usr/bin/openshell-gateway --config " + cfg, false},
		{"/usr/bin/openshell-gateway --config " + filepath.Join(dir, openshell.GatewayFallbackTOMLFile), false},
		// The 1.0.1 upgrade bridge's docker configuration (GAP-0587).
		{"/usr/bin/openshell-gateway --config " + filepath.Join(dir, openshell.GatewayDefaultNamespaceTOMLFile), false},
		{"/usr/bin/openshell-gateway --config " + filepath.Join(r.o.home, ".config", "openshell", "gateway.toml"), true},
		{"/usr/bin/openshell-gateway --config " + cfg + " --bind-address 0.0.0.0:17670", true},
		{filepath.Join(r.o.home, ".local", "bin", "openshell-gateway") + " --config " + cfg, true},
		{"/usr/libexec/openshell/openshell-driver-vm --serve", false},
	} {
		r.args = tc.args
		drift, err := r.o.Drift(s)
		if err != nil || (len(drift) > 0) != tc.drift || (tc.drift && driftEventField(drift[0].Field) != "gateway_command") {
			t.Errorf("%s: drift %v, %v", tc.args, drift, err)
		}
	}
	s.Enterprise.Install = "setup"
	r.args = filepath.Join(r.o.home, ".local", "bin", "openshell-gateway") + " --config " + cfg
	if drift, err := r.o.Drift(s); err != nil || len(drift) != 0 {
		t.Fatalf("setup mode, the account's install: %v %v", drift, err)
	}
	r.args = "/usr/bin/openshell-gateway --config " + cfg
	if drift, err := r.o.Drift(s); err != nil || len(drift) != 1 {
		t.Fatalf("setup mode, another install: %v %v", drift, err)
	}
}

func TestAccountOpenShellReportsChangedManagedRender(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.holder = func(int) int { return 5001 }
	r.active, r.pid = true, 77
	r.o.adminBinary = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	configPath := filepath.Join(t.TempDir(), openshell.GatewayTOMLFile)
	r.args = "/usr/bin/openshell-gateway --config " + configPath
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{BindAddress: "127.0.0.1:17671"}, "sha256:edited", nil
	}
	s := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{
		Install: "prerequisite", Driver: "docker", GatewayPort: 17670,
		GatewayConfigPath: configPath, GatewayConfigDigest: "sha256:installed",
	}}
	drift, err := r.o.Drift(s)
	if err != nil || len(drift) != 1 || driftEventField(drift[0].Field) != "gateway_configuration" {
		t.Fatalf("edited managed render drift = %v, %v", drift, err)
	}
	if !r.o.RenderedConfigDrift(s) {
		t.Fatal("status missed the edited render")
	}
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{}, "", errors.New("invalid edited render")
	}
	if !r.o.RenderedConfigDrift(s) {
		t.Fatal("status missed the malformed edited render")
	}
}

// GAP-0730: install setup (the managed default on these hosts) runs the
// administrator's rendered gateway.toml too, so the daemon reports its hand
// edit as drift (the settings_drift event and counter) as status does; it is
// no pause, and a render setup mode cannot read is no refusal.
func TestAccountOpenShellReportsChangedRenderInSetupMode(t *testing.T) {
	r := newOpenShellRig(t, "linux")
	r.holder = func(int) int { return 5001 }
	r.active, r.pid = true, 77
	configPath := filepath.Join(t.TempDir(), openshell.GatewayTOMLFile)
	r.args = filepath.Join(r.o.home, ".local", "bin", "openshell-gateway") + " --config " + configPath
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{BindAddress: "127.0.0.1:17671"}, "sha256:edited", nil
	}
	s := sandboxrelay.DaemonSettings{Enterprise: sandboxrelay.EnterpriseOpenShell{
		Install: "setup", Driver: "docker", GatewayPort: 17670,
		GatewayConfigPath: configPath, GatewayConfigDigest: "sha256:installed",
	}}
	drift, err := r.o.Drift(s)
	if err != nil || len(drift) != 1 || driftEventField(drift[0].Field) != "gateway_configuration" {
		t.Fatalf("setup mode, edited render: drift = %v, %v", drift, err)
	}
	if len(blockingOpenShellDrift(drift)) != 0 {
		t.Fatalf("the edited render pauses sandboxes: %v", drift)
	}
	r.o.readRendered = func(string, string) (openshell.RenderedGateway, string, error) {
		return openshell.RenderedGateway{}, "", errors.New("unreadable")
	}
	if drift, err := r.o.Drift(s); err != nil || len(drift) != 0 {
		t.Fatalf("setup mode, unreadable render: drift = %v, %v", drift, err)
	}
}
