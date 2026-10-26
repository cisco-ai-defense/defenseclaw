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
	"os"
	"path/filepath"
	"slices"
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

// GAP-0380: a raw `openshell sandbox start` that lands after a restart's
// final check was ended by the restart with what its guest had not synced.
// The gateway service gets an ExecStop that syncs every ready MicroVM
// first, whoever started it and whoever stops the gateway. A daemon-reload
// applies it: on its own it restarts nothing.
func TestGatewayServiceSyncsItsMicroVMsBeforeItStops(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	f.runner.On("systemctl --user daemon-reload", "", nil)
	plan, err := f.cfg.Plan(ctx, openshell.GatewayChanges{StopSync: stopSync})
	if err != nil || len(plan.Files) != 1 || plan.Files[0].Path != f.stopSyncDropIn() || !plan.ReloadOnly() {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if s := plan.String(); !strings.Contains(s, "no restart: running sandboxes keep running") || strings.Contains(s, "then restart the gateway") {
		t.Fatalf("plan renders as:\n%s", s)
	}
	checks := f.flushes
	res, err := f.cfg.Apply(ctx, plan)
	if err != nil || res.Restarted || len(res.Files) != 1 {
		t.Fatalf("apply = %+v, %v", res, err)
	}
	if got := f.serviceCalls(); !slices.Equal(got, []string{"daemon-reload"}) || f.flushes != checks {
		t.Fatalf("service calls %v, %d stopped checks: a reload-only change restarted or checked", got, f.flushes-checks)
	}
	data, err := os.ReadFile(f.stopSyncDropIn())
	if err != nil || !strings.HasSuffix(string(data), "[Service]\n"+wantExecStop) {
		t.Fatalf("drop-in = %q, %v", data, err)
	}
	if again, err := f.cfg.Plan(ctx, openshell.GatewayChanges{StopSync: stopSync}); err != nil || !again.Empty() {
		t.Fatalf("a second plan = %+v, %v", again, err)
	}
	for _, bad := range []openshell.StopSync{{Binary: "defenseclaw-gateway"}, {Binary: "/opt/my dir/defenseclaw-gateway"}, {Binary: "/x/%h"}, {Binary: "/x/g", Gateway: "a b"}} {
		if _, err := f.cfg.Plan(ctx, openshell.GatewayChanges{StopSync: &bad}); err == nil {
			t.Errorf("%+v planned", bad)
		}
	}
}

// The restarts that follow, Apply's own and the rollback's after a failed
// restart (the gap's "final rollback check"), have the stop sync in place:
// it is written and read first, and a rollback of the rest of the plan
// keeps it. Teardown's Rollback removes it only after its restart.
func TestTheStopSyncCoversEveryRestartThatFollows(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	f.runner.On("systemctl --user daemon-reload", "", nil)
	f.write(t, "gateway.toml", operatorTOML)
	ch := bindMounts
	ch.StopSync = stopSync
	plan := f.plan(t, ch)
	res, err := f.apply(plan)
	if err != nil || !res.Restarted || len(res.Files) != 2 {
		t.Fatalf("apply = %+v, %v", res, err)
	}
	if got := f.serviceCalls(); !slices.Equal(got[:2], []string{"daemon-reload", "restart openshell-gateway"}) {
		t.Fatalf("service calls = %v: the stop sync was not read before the restart", got)
	}

	// The restart onto the new files fails: the rollback restores them and
	// restarts again, with the stop sync kept.
	g := newGatewayFixture(t)
	g.runner.On("systemctl --user daemon-reload", "", nil)
	g.runner.On("systemctl --user restart openshell-gateway", "", errors.New("exit status 1"))
	g.write(t, "gateway.toml", operatorTOML)
	if _, err := g.apply(g.plan(t, ch)); err == nil {
		t.Fatal("apply succeeded with a restart that failed")
	}
	if g.read(t, "gateway.toml") != operatorTOML {
		t.Fatal("the rollback did not restore gateway.toml")
	}
	if data, err := os.ReadFile(g.stopSyncDropIn()); err != nil || !strings.HasSuffix(string(data), wantExecStop) {
		t.Fatalf("the rollback removed the stop sync: %q, %v", data, err)
	}

	// Teardown: the restart onto the restored files comes first, then the
	// stop sync goes, read by the manager.
	before := len(f.serviceCalls())
	if err := f.cfg.Rollback(ctx, res); err != nil {
		t.Fatalf("Rollback = %v", err)
	}
	if got := f.serviceCalls()[before:]; !slices.Equal(got, []string{"restart openshell-gateway", "daemon-reload"}) {
		t.Fatalf("teardown service calls = %v, want the restart, then the reload without the stop sync", got)
	}
	if _, err := os.Stat(f.stopSyncDropIn()); !os.IsNotExist(err) || f.read(t, "gateway.toml") != operatorTOML {
		t.Fatalf("after the teardown: stop sync %v, gateway.toml %q", err, f.read(t, "gateway.toml"))
	}

	// A stop sync recorded alone is undone by a reload, with no restart.
	h := newGatewayFixture(t)
	h.runner.On("systemctl --user daemon-reload", "", nil)
	only, err := h.apply(h.plan(t, openshell.GatewayChanges{StopSync: stopSync}))
	if err != nil {
		t.Fatal(err)
	}
	restarts := h.restarts()
	if err := h.cfg.Rollback(ctx, only); err != nil || h.restarts() != restarts {
		t.Fatalf("Rollback = %v, %d restarts", err, h.restarts()-restarts)
	}
	if _, err := os.Stat(h.stopSyncDropIn()); !os.IsNotExist(err) {
		t.Fatalf("the stop sync stayed: %v", err)
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
