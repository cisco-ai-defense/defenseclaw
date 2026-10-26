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

package openshell_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

var stopSync = &openshell.StopSync{Binary: "/home/u/.local/bin/defenseclaw-gateway", Gateway: "openshell"}

const wantExecStop = "ExecStop=-/home/u/.local/bin/defenseclaw-gateway sandbox-daemon sync-sandboxes --gateway openshell\n"

func (f *gatewayFixture) stopSyncDropIn() string {
	return filepath.Join(filepath.Dir(f.dropIn()), "zz-defenseclaw-stop-sync.conf")
}

// serviceCalls are the daemon-reload and restart calls, in order.
func (f *gatewayFixture) serviceCalls() []string {
	var order []string
	for _, c := range f.runner.Calls() {
		if a := strings.Join(c.Args, " "); a == "--user daemon-reload" || a == "--user restart openshell-gateway" {
			order = append(order, strings.TrimPrefix(a, "--user "))
		}
	}
	return order
}

// onDriver gives the fixture the stop sync and a gateway that runs name;
// it counts the syncs before a restart and the stop syncs a restart wrote.
func (f *gatewayFixture) onDriver(t *testing.T, name string) (synced *int, written *[]*openshell.GatewayApplyResult) {
	t.Helper()
	d, ok := openshell.LookupDriver(name)
	if !ok {
		t.Fatalf("no driver %s", name)
	}
	f.runner.On("systemctl --user daemon-reload", "", nil)
	f.cfg.StopSync = stopSync
	f.cfg.RunningDriver = func(context.Context) (openshell.Driver, error) { return d, nil }
	synced, written = new(int), new([]*openshell.GatewayApplyResult)
	f.cfg.SyncSandboxes = func(context.Context, io.Writer) error { *synced++; return nil }
	f.cfg.StopSyncWritten = func(res *openshell.GatewayApplyResult) { *written = append(*written, res) }
	return synced, written
}

func (f *gatewayFixture) hasStopSync(t *testing.T) bool {
	t.Helper()
	data, err := os.ReadFile(f.stopSyncDropIn())
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil || !strings.HasSuffix(string(data), "[Service]\n"+wantExecStop) {
		t.Fatalf("drop-in = %q, %v", data, err)
	}
	return true
}

// GAP-0380: a raw `openshell sandbox start` that lands after a restart's
// final check was ended by the restart with what its guest had not synced.
// The gateway service gets an ExecStop that syncs every ready MicroVM
// first, whoever started it and whoever stops the gateway. A daemon-reload
// applies it: it restarts and checks nothing.
func TestGatewayServiceSyncsItsMicroVMsBeforeItStops(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	f.onDriver(t, "vm")
	checks := f.flushes
	res, err := f.cfg.EnsureStopSync(ctx)
	if err != nil || res == nil || len(res.Files) != 1 || res.Files[0].Path != f.stopSyncDropIn() || res.Files[0].Backup != "" {
		t.Fatalf("EnsureStopSync = %+v, %v", res, err)
	}
	if got := f.serviceCalls(); !slices.Equal(got, []string{"daemon-reload"}) || f.flushes != checks {
		t.Fatalf("service calls %v, %d stopped checks: the stop sync restarted or checked", got, f.flushes-checks)
	}
	if !f.hasStopSync(t) {
		t.Fatal("no drop-in")
	}
	if again, err := f.cfg.EnsureStopSync(ctx); err != nil || again != nil {
		t.Fatalf("a second EnsureStopSync = %+v, %v", again, err)
	}
	for _, bad := range []openshell.StopSync{{Binary: "defenseclaw-gateway"}, {Binary: "/opt/my dir/defenseclaw-gateway"}, {Binary: "/x/%h"}, {Binary: "/x/g", Gateway: "a b"}} {
		f.cfg.StopSync = &bad
		if _, err := f.cfg.EnsureStopSync(ctx); err == nil {
			t.Errorf("%+v written", bad)
		}
	}
	// Homebrew's launchd service has no stop hook, and a managed host's
	// units are the administrator's.
	for _, edit := range []func(*openshell.GatewayConfigurator){
		func(c *openshell.GatewayConfigurator) { c.GOOS = "darwin" },
		func(c *openshell.GatewayConfigurator) { c.Managed = true },
	} {
		g := newGatewayFixture(t)
		g.onDriver(t, "vm")
		edit(g.cfg)
		if res, err := g.cfg.EnsureStopSync(ctx); err != nil || res != nil || g.hasStopSync(t) {
			t.Fatalf("EnsureStopSync = %+v, %v", res, err)
		}
	}
}

// GAP-1927: a gateway set up before the stop sync existed (an upgrade does
// not run setup again) had no ExecStop on DefenseClaw's other restarts:
// `doctor --fix`, the restart onto a new OpenShell release and teardown's
// rollback. Every restart now gives a MicroVM gateway's service the stop
// sync first, with a daemon-reload before the restart, and says so for the
// setup receipt; a docker gateway gets none.
func TestEveryRestartGivesAMicroVMGatewayTheStopSyncFirst(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	synced, written := f.onDriver(t, "vm")
	if err := f.cfg.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	if got := f.serviceCalls(); !slices.Equal(got, []string{"daemon-reload", "restart openshell-gateway"}) || !f.hasStopSync(t) {
		t.Fatalf("service calls %v: the stop sync was not in place before the restart", got)
	}
	if len(*written) != 1 || len((*written)[0].Files) != 1 || (*written)[0].Files[0].Path != f.stopSyncDropIn() || *synced != 0 {
		t.Fatalf("written %+v, %d syncs before the restart (the ExecStop syncs)", *written, *synced)
	}
	if err := f.cfg.Restart(ctx); err != nil || len(*written) != 1 || len(f.serviceCalls()) != 3 {
		t.Fatalf("a second restart: %v, written %d, calls %v", err, len(*written), f.serviceCalls())
	}

	// The restart of a failed Apply (the rollback's) has it too.
	g := newGatewayFixture(t)
	g.onDriver(t, "vm")
	g.runner.On("systemctl --user restart openshell-gateway", "", errors.New("exit status 1"))
	g.write(t, "gateway.toml", operatorTOML)
	if _, err := g.apply(g.plan(t, bindMounts)); err == nil {
		t.Fatal("apply succeeded with a restart that failed")
	}
	if g.read(t, "gateway.toml") != operatorTOML || !g.hasStopSync(t) {
		t.Fatal("the rollback did not restore gateway.toml, or dropped the stop sync")
	}

	// Teardown: its restart onto the restored files gets the stop sync,
	// which goes only after it, with what setup recorded.
	h := newGatewayFixture(t)
	h.runner.On("systemctl --user daemon-reload", "", nil)
	h.write(t, "gateway.toml", operatorTOML)
	res, err := h.apply(h.plan(t, bindMounts))
	if err != nil || !res.Restarted || h.hasStopSync(t) {
		t.Fatalf("apply before the stop sync = %+v, %v", res, err)
	}
	_, hw := h.onDriver(t, "vm")
	before := len(h.serviceCalls())
	if err := h.cfg.Rollback(ctx, res); err != nil {
		t.Fatalf("Rollback = %v", err)
	}
	// GAP-2004: the stop sync teardown's restart wrote went again right
	// after it, so teardown neither says it was added nor records it.
	if len(*hw) != 0 {
		t.Fatalf("teardown announced %d stop syncs it then removed", len(*hw))
	}
	if got := h.serviceCalls()[before:]; !slices.Equal(got, []string{"daemon-reload", "restart openshell-gateway", "daemon-reload"}) {
		t.Fatalf("teardown service calls = %v, want the stop sync, the restart, then the reload without it", got)
	}
	if h.hasStopSync(t) || h.read(t, "gateway.toml") != operatorTOML {
		t.Fatalf("after the teardown: stop sync kept, or gateway.toml %q", h.read(t, "gateway.toml"))
	}

	// A teardown whose restart fails keeps the stop sync it wrote: that one
	// is announced and recorded, so the next teardown removes it.
	k := newGatewayFixture(t)
	k.runner.On("systemctl --user daemon-reload", "", nil)
	k.write(t, "gateway.toml", operatorTOML)
	kres, err := k.apply(k.plan(t, bindMounts))
	if err != nil {
		t.Fatal(err)
	}
	_, kw := k.onDriver(t, "vm")
	k.runner.On("systemctl --user restart openshell-gateway", "", errors.New("exit status 1"))
	if err := k.cfg.Rollback(ctx, kres); err == nil {
		t.Fatal("Rollback succeeded with a restart that failed")
	}
	if !k.hasStopSync(t) || len(*kw) != 1 || (*kw)[0].Files[0].Path != k.stopSyncDropIn() {
		t.Fatalf("a failed teardown restart: stop sync kept %v, written %+v", k.hasStopSync(t), *kw)
	}

	// A docker gateway's stop keeps what a workload wrote: no drop-in.
	d := newGatewayFixture(t)
	d.onDriver(t, "docker")
	if err := d.cfg.Restart(ctx); err != nil || d.hasStopSync(t) || !slices.Equal(d.serviceCalls(), []string{"restart openshell-gateway"}) {
		t.Fatalf("docker restart: %v, calls %v", err, d.serviceCalls())
	}
}

// GAP-1928, GAP-2003: Homebrew's launchd service has no stop hook, so a
// restart of a macOS MicroVM gateway syncs each running MicroVM right
// before its stop. `brew services restart` spent seconds in Homebrew before
// it stopped the gateway, in which a raw-started MicroVM got ready and its
// guest wrote what no sync saw. Now launchd stops the gateway at once after
// the sync and `brew services start` starts it after. The fake models the
// window: a brew run on a running gateway lets a raw start get ready and
// write, and a stop with unsynced work loses it. A sync that fails does not
// refuse the restart (its check passed).
func TestAMacOSRestartStopsTheGatewayRightAfterTheSync(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())
	label := "homebrew.mxcl." + filepath.Base(openshell.GatewayFormula)
	for _, tc := range []struct {
		name, loadedIn string
		want           []string
	}{
		{"graphical session", "gui", []string{"sync", "bootout gui", "start"}},
		{"background session", "user", []string{"sync", "bootout gui", "bootout user", "start"}},
		{"no launchd job", "", []string{"sync", "bootout gui", "bootout user", "restart"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			f.onDriver(t, "vm")
			f.cfg.GOOS = "darwin"
			f.cfg.BrewFormulaInstalled = func() bool { return true }
			var order []string
			running, unsynced, lost := true, false, false
			stop := func() {
				lost = lost || unsynced
				running, unsynced = false, false
			}
			f.cfg.SyncSandboxes = func(_ context.Context, out io.Writer) error {
				order = append(order, "sync")
				unsynced = false
				_, _ = io.WriteString(out, "could not sync the disk of sandbox raw\n")
				return errors.New("raw: the supervisor does not answer")
			}
			var out bytes.Buffer
			f.cfg.Out = &out
			for _, domain := range []string{"gui", "user"} {
				f.runner.OnFunc("launchctl bootout "+domain+"/"+uid+"/"+label, func(context.Context, openshell.Command) ([]byte, error) {
					order = append(order, "bootout "+domain)
					if domain != tc.loadedIn {
						return []byte("Boot-out failed: 3: No such process"), errors.New("exit status 3")
					}
					stop()
					return nil, nil
				})
			}
			for _, verb := range []string{"restart", "start"} {
				f.runner.OnFunc("brew services "+verb+" "+openshell.GatewayFormula, func(context.Context, openshell.Command) ([]byte, error) {
					order = append(order, verb)
					if running {
						// Homebrew's seconds before its stop.
						unsynced = true
						stop()
					}
					running = true
					return nil, nil
				})
			}
			if err := f.cfg.Restart(context.Background()); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(order, tc.want) || f.hasStopSync(t) || !strings.Contains(out.String(), "could not sync the disk of sandbox raw") {
				t.Fatalf("order %v, want %v; out %q", order, tc.want, out.String())
			}
			if tc.loadedIn != "" && lost {
				t.Fatal("the restart stopped the gateway with work a raw-started MicroVM wrote after the sync")
			}
		})
	}
}

// The ExecStop's work: sync(1) in every MicroVM OpenShell lists ready (a
// raw-started one included), nothing in a stopped one, and nothing at all
// on a driver whose stop keeps what a workload wrote. A sync that fails is
// named, with what it may cost.
func TestSyncRunningSandboxesSyncsEachReadyMicroVM(t *testing.T) {
	ctx := context.Background()
	gateway := func(d openshell.ComputeDriver) (*openshelltest.Fake, openshell.Client) {
		f := openshelltest.New(openshelltest.WithDriver(d))
		c := f.Client(openshell.ClientOptions{})
		for name, phase := range map[string]openshell.SandboxPhase{"dc-a": openshell.PhaseReady, "raw": openshell.PhaseReady, "dc-b": openshell.PhaseStopped} {
			if _, err := c.CreateSandbox(ctx, name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := f.SetPhase(openshell.DefaultWorkspace, name, phase); err != nil {
				t.Fatal(err)
			}
		}
		return f, c
	}
	f, c := gateway(openshell.DriverVM)
	var out bytes.Buffer
	if err := openshell.SyncRunningSandboxes(ctx, c, &out); err != nil {
		t.Fatal(err)
	}
	var synced []string
	for _, call := range f.ExecCalls() {
		if strings.Join(call.Command, " ") == "/bin/sync" {
			synced = append(synced, call.Sandbox)
		}
	}
	slices.Sort(synced)
	if !slices.Equal(synced, []string{"dc-a", "raw"}) || len(f.ExecCalls()) != 2 || f.Calls(openshelltest.MethodStopSandbox) != 0 {
		t.Fatalf("synced %v (exec calls %+v, %d stops)", synced, f.ExecCalls(), f.Calls(openshelltest.MethodStopSandbox))
	}
	if !strings.Contains(out.String(), "synced the disk of sandbox raw before the OpenShell gateway stops") {
		t.Fatalf("out = %q", out.String())
	}
	d, dc := gateway(openshell.DriverDocker)
	if err := openshell.SyncRunningSandboxes(ctx, dc, &out); err != nil || len(d.ExecCalls()) != 0 {
		t.Fatalf("docker: %v, exec calls %+v", err, d.ExecCalls())
	}
	f, c = gateway(openshell.DriverVM)
	f.Intercept(func(method string) error {
		if method == openshelltest.MethodExec {
			return errors.New("the supervisor does not answer")
		}
		return nil
	})
	out.Reset()
	if err := openshell.SyncRunningSandboxes(ctx, c, &out); err == nil ||
		!strings.Contains(out.String(), "could not sync the disk of sandbox raw") || !strings.Contains(out.String(), "may come back empty") {
		t.Fatalf("failing sync: %v, out %q", err, out.String())
	}
}
