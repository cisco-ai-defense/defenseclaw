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

//go:build !windows

package manager

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// onDriver moves e to a connection whose gateway runs another compute
// driver (the gateway was switched), and returns that driver.
func onDriver(t *testing.T, e *harnessEnv, name openshell.ComputeDriver) openshell.Driver {
	t.Helper()
	d, ok := openshell.LookupDriver(string(name))
	if !ok {
		t.Fatalf("no driver %s", name)
	}
	next := *e.gw
	next.Driver = d
	switchGateway(t, e, &next)
	return d
}

// useOpenCode makes e's images OpenCode's, a harness without per-run files.
func useOpenCode(t *testing.T, e *harnessEnv) {
	t.Helper()
	res := connector.ResolveSandboxHookContract("opencode", "1.18.31")
	if res.Status != connector.HookCompatibilityKnown {
		t.Fatalf("opencode 1.18.31 has no known contract: %+v", res)
	}
	e.images.rec.HarnessVersion, e.images.rec.HookContract = "1.18.31", res.Contract.ContractID
}

// A live mount is for a driver that mounts host folders: a create that got
// one planned on a MicroVM gateway anyway writes no pins, mask files or
// snapshot on the host.
func TestMountPlanNeedsHostMounts(t *testing.T) {
	e := newVMEnv(t, nil)
	useOpenCode(t, e)
	spec, _ := harness.Get("opencode")
	eff, _, err := e.m.resolve(e.config(), runFlags{}.packs("opencode", e.project, gatewayFacts{Port: e.gw.Port}))
	must(t, err)
	if eff.Workspace.Mode != config.OpenShellWorkdirMount {
		t.Fatalf("mode = %s", eff.Workspace.Mode)
	}
	b, err := e.m.reserve("guardbox", e.project, eff.Workspace.Mode)
	must(t, err)
	rb := &rollback{}
	_, err = e.m.create(t.Context(), e.gw, b, createInput{name: "guardbox", project: e.project, harness: spec, eff: eff,
		mode: eff.Workspace.Mode, resources: &eff.Resources}, rb)
	rb.run(e.m, "guardbox")
	wantCode(t, err, sandboxapi.CodeInternal)
	if len(e.ws.planned) != 0 || len(e.ws.snapshots) != 0 || e.fake.Calls(openshelltest.MethodCreateSandbox) != 0 {
		t.Fatalf("planned %v, snapshots %v", e.ws.planned, e.ws.snapshots)
	}
}

// Policy explain names the driver as what runs a new sandbox on a copy, and
// explains an existing one with the driver it was created on.
func TestExplainNamesTheDriver(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "mounted"})
	onDriver(t, e, openshell.DriverVM)
	if _, err := e.m.gateway(t.Context()); err != nil {
		t.Fatal(err)
	}
	mode := func(req sandboxapi.ExplainRequest) sandboxapi.Setting {
		t.Helper()
		ex, err := e.m.Explain(t.Context(), req)
		must(t, err)
		for _, s := range ex.Settings {
			if s.Key == "workdir.mode" {
				return s
			}
		}
		t.Fatalf("no workdir.mode in %+v", ex.Settings)
		return sandboxapi.Setting{}
	}
	if s := mode(sandboxapi.ExplainRequest{Harness: "opencode", Project: e.project}); s.Value != "copy" || s.Source != string(packs.SourceGateway) ||
		s.Origin != packs.ConstraintComputeDriver || s.Requested != "mount" {
		t.Fatalf("new sandbox: %+v", s)
	}
	if s := mode(sandboxapi.ExplainRequest{Harness: "opencode", Project: e.project, Copy: true}); s.Value != "copy" || s.Source != string(packs.SourceFlag) {
		t.Fatalf("new sandbox with --copy: %+v", s)
	}
	if s := mode(sandboxapi.ExplainRequest{Sandbox: "mounted"}); s.Value != "mount" {
		t.Fatalf("the docker sandbox: %+v", s)
	}
}

// Every MicroVM gets the gateway-wide vcpus and mem_mib: --cpu and --memory
// are dropped with a warning, the record keeps what the sandbox gets, and
// an administrator's max_resources is judged against it, at the create and
// again at every start. Unknown values fail closed under a maximum.
func TestResourcesOnVM(t *testing.T) {
	shared := packs.Resources{CPU: "2", Memory: "2048Mi"}
	vmWith := func(t *testing.T, max config.OpenShellResourcesConfig, read bool) *harnessEnv {
		e := newVMEnv(t, func(c *config.Config) { c.OpenShell.Admin.MaxResources = max })
		useOpenCode(t, e)
		if read {
			e.m.opts.GatewayResources = func() (packs.Resources, error) { return shared, nil }
		}
		return e
	}

	e := vmWith(t, config.OpenShellResourcesConfig{}, true)
	sb := e.create(sandboxapi.CreateRequest{Name: "vmres", Harness: "opencode", Copy: true, CPU: "4", Memory: "8Gi"})
	if findWarning(sb.Warnings, "cpu/memory limits have no effect on the OpenShell vm driver: every MicroVM gets [openshell.drivers.vm] vcpus and mem_mib") == "" {
		t.Fatalf("warnings = %q", sb.Warnings)
	}
	got, _ := e.client.GetSandbox(t.Context(), "vmres")
	if got.Spec.Template.Resources != nil {
		t.Fatalf("template resources = %+v", got.Spec.Template.Resources)
	}
	if rec := e.boxOf("vmres").rec; rec.Resources == nil || *rec.Resources != shared {
		t.Fatalf("recorded resources = %+v", rec.Resources)
	}
	// Nothing asked for, nothing said.
	if sb := e.create(sandboxapi.CreateRequest{Name: "vmres2", Harness: "opencode", Copy: true, Project: e.otherProject("p2")}); len(sb.Warnings) != 0 {
		t.Fatalf("warnings = %q", sb.Warnings)
	}

	for _, tc := range []struct {
		name string
		max  config.OpenShellResourcesConfig
		read bool
		want string
	}{
		{"above the maximum", config.OpenShellResourcesConfig{CPU: "1"}, true,
			"caps sandbox cpu at 1, and every sandbox on the vm driver gets 2 ([openshell.drivers.vm] vcpus)"},
		{"memory above the maximum", config.OpenShellResourcesConfig{Memory: "1Gi"}, true, "([openshell.drivers.vm] mem_mib)"},
		{"unknown under a maximum", config.OpenShellResourcesConfig{CPU: "8"}, false, "cannot be read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := vmWith(t, tc.max, tc.read)
			_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "capped", Harness: "opencode", Copy: true})
			apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation)
			if !strings.Contains(apiErr.Message, tc.want) || !strings.Contains(apiErr.Detail, "`defenseclaw sandbox doctor --fix`") {
				t.Fatalf("refusal = %+v", apiErr)
			}
			if n := e.fake.Calls(openshelltest.MethodCreateSandbox); n != 0 {
				t.Fatalf("create calls = %d", n)
			}
			assertNothingLeft(t, e)
		})
	}

	// Within the maximum it runs, until the gateway-wide values outgrow it.
	e = vmWith(t, config.OpenShellResourcesConfig{CPU: "4", Memory: "4Gi"}, true)
	e.create(sandboxapi.CreateRequest{Name: "grows", Harness: "opencode", Copy: true})
	e.stopBox("grows")
	shared.CPU = "8"
	_, err := e.m.Start(t.Context(), "grows", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation); !strings.Contains(apiErr.Message, "gets 8") {
		t.Fatalf("start refusal = %+v", apiErr)
	}
	shared.CPU = "4"
	e.startBox("grows", sandboxapi.StartRequest{})
}

// The daemon reads what every MicroVM gets from its gateway's
// configuration: gateway.env over gateway.toml, and the driver's defaults
// for what neither sets. A configuration it cannot parse is an error, so
// an administrator's maximum refuses the create (TestResourcesOnVM).
func TestGatewayConfigResources(t *testing.T) {
	dir := t.TempDir()
	write := func(name, data string) {
		t.Helper()
		must(t, os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600))
	}
	read := GatewayConfigResources(dir)
	// Both files are in dir, so a Mac's Homebrew copies are never read.
	write(openshell.GatewayEnvFile, "")
	write(openshell.GatewayTOMLFile, "")
	if got, err := read(); err != nil || got != (packs.Resources{CPU: "2", Memory: "2048Mi"}) {
		t.Fatalf("defaults = %+v, %v", got, err)
	}
	write(openshell.GatewayTOMLFile, "[openshell.drivers.vm]\nvcpus = 6\nmem_mib = 8192\n")
	if got, err := read(); err != nil || got != (packs.Resources{CPU: "6", Memory: "8192Mi"}) {
		t.Fatalf("gateway.toml = %+v, %v", got, err)
	}
	write(openshell.GatewayEnvFile, "OPENSHELL_VM_DRIVER_VCPUS=3\n")
	if got, err := read(); err != nil || got != (packs.Resources{CPU: "3", Memory: "8192Mi"}) {
		t.Fatalf("gateway.env over gateway.toml = %+v, %v", got, err)
	}
	write(openshell.GatewayTOMLFile, "[openshell.drivers.vm\n")
	if got, err := read(); err == nil {
		t.Fatalf("an unparsable gateway.toml read as %+v", got)
	}
}

// One gateway runs one driver: a sandbox created on docker does not start
// once the gateway runs vm, whether the gateway still lists it or not, and
// the refusal says why before any other (not "the policy now runs this
// project in copy mode"). A live mount does not start on a driver without
// host mounts either.
func TestStartOnAnotherDriverIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "dockerbox"})
	e.create(sandboxapi.CreateRequest{Name: "gonebox", Copy: true})
	e.stopBox("dockerbox")
	e.stopBox("gonebox")
	_, err := e.client.DeleteSandbox(t.Context(), "gonebox")
	must(t, err)
	must(t, e.client.WaitDeleted(t.Context(), "gonebox"))
	onDriver(t, e, openshell.DriverVM)
	starts := e.fake.Calls(openshelltest.MethodStartSandbox)
	for _, name := range []string{"dockerbox", "gonebox"} {
		_, err := e.m.Start(t.Context(), name, sandboxapi.StartRequest{})
		apiErr := wantCode(t, err, sandboxapi.CodeConflict)
		for _, want := range []string{"sandbox " + name + " was created on the docker driver; this gateway now runs vm",
			"switch back with `defenseclaw sandbox setup`", "`defenseclaw sandbox delete " + name + "`"} {
			if !strings.Contains(apiErr.Message, want) {
				t.Fatalf("refusal = %q, want %q", apiErr.Message, want)
			}
		}
	}
	if e.fake.Calls(openshelltest.MethodStartSandbox) != starts {
		t.Fatal("the sandbox was started")
	}

	b := e.boxOf("dockerbox")
	e.m.mu.Lock()
	b.rec.Driver = "vm"
	e.m.mu.Unlock()
	_, err = e.m.Start(t.Context(), "dockerbox", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Message, "mounts its project live") {
		t.Fatalf("refusal = %+v", apiErr)
	}
}

// After a switch to vm the daemon never releases a sandbox created on
// docker, whether the gateway still lists it or not: its unpulled work is
// with the other driver. Deleting it releases DefenseClaw's side and names
// what may be left.
func TestReconcileKeepsSandboxesOfAnotherDriver(t *testing.T) {
	for _, listed := range []bool{false, true} {
		e := newEnv(t, nil)
		e.create(sandboxapi.CreateRequest{Name: "copybox", Copy: true})
		if !listed {
			_, err := e.client.DeleteSandbox(t.Context(), "copybox")
			must(t, err)
			must(t, e.client.WaitDeleted(t.Context(), "copybox"))
		}
		onDriver(t, e, openshell.DriverVM)
		must(t, e.m.Reconcile(t.Context()))
		must(t, e.m.Reconcile(t.Context()))
		if _, err := e.store.Lookup("copybox"); err != nil {
			t.Fatalf("listed %v: the binding was revoked: %v", listed, err)
		}
		got := e.get("copybox")
		if findWarning(got.Warnings, "this sandbox was created on the docker compute driver, which the gateway no longer runs") == "" {
			t.Fatalf("listed %v: sandbox = %+v", listed, got)
		}
		if !listed && got.Phase != "missing" {
			t.Fatalf("phase = %s", got.Phase)
		}

		resp, err := e.m.Delete(t.Context(), "copybox", sandboxapi.DeleteRequest{})
		must(t, err)
		if !slices.ContainsFunc(resp.Warnings, func(w string) bool {
			return strings.Contains(w, "created on the docker compute driver, and the gateway runs vm now") && strings.Contains(w, "`docker rm -f`")
		}) {
			t.Fatalf("listed %v: warnings = %q", listed, resp.Warnings)
		}
		if _, err := e.store.Lookup("copybox"); err == nil {
			t.Fatalf("listed %v: the binding was kept", listed)
		}
		assertNothingLeft(t, e)
	}
}

// A delete of another driver's sandbox releases DefenseClaw's side even when
// the gateway cannot answer for it.
func TestDeleteOfAnotherDriversSandboxWhenTheGatewayFails(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "stuckcopy", Copy: true})
	onDriver(t, e, openshell.DriverVM)
	e.fake.FailNext(openshelltest.MethodGetSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "no driver for this sandbox"})
	resp, err := e.m.Delete(t.Context(), "stuckcopy", sandboxapi.DeleteRequest{})
	must(t, err)
	if !resp.Deleted || findWarning(resp.Warnings, "sandbox stuckcopy was created on the docker compute driver") == "" {
		t.Fatalf("delete = %+v", resp)
	}
	if _, err := e.store.Lookup("stuckcopy"); err == nil {
		t.Fatal("the binding was kept")
	}
}

// On vm a stop flushes the sandbox's disk first, in the harness's exit
// exec, after the harness exited: a MicroVM's stop loses what was not
// synced. A stop the flush did not reach is reported. On docker the exec
// is what it always was.
func TestStopOnVMFlushesFirst(t *testing.T) {
	e := newVMEnv(t, nil)
	useOpenCode(t, e)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "flushbox", Harness: "opencode", Copy: true})
	e.watch.waitStarted(t, "flushbox")
	var mu sync.Mutex
	var order []string
	answer := "exited\nsynced\n"
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, "exec "+call.Command[0])
		return openshelltest.ExecResponse{Stdout: []byte(answer)}
	}))
	e.fake.Intercept(func(method string) error {
		if method == openshelltest.MethodStopSandbox {
			mu.Lock()
			order = append(order, "stop")
			mu.Unlock()
		}
		return nil
	})
	e.stopBox("flushbox")
	calls := e.fake.ExecCalls()
	last := calls[len(calls)-1]
	if len(order) != 2 || order[0] != "exec /bin/sh" || order[1] != "stop" ||
		!strings.HasPrefix(last.Command[2], flushTrap) || !strings.HasSuffix(last.Command[2], endHarnessScript) ||
		last.Timeout != harnessExitWait+3*time.Second+flushWait {
		t.Fatalf("order = %v, exec = %+v", order, last)
	}
	if got := e.events("flushbox", "", "stop_unflushed"); len(got) != 0 {
		t.Fatalf("a flushed stop was reported: %+v", got)
	}

	// The sandbox answers, but the flush did not finish.
	e.startBox("flushbox", sandboxapi.StartRequest{})
	answer = "exited\n"
	e.stopBox("flushbox")
	if got := e.events("flushbox", "", "stop_unflushed"); len(got) != 1 || !strings.Contains(got[0].Message, "may come back empty") {
		t.Fatalf("feed = %+v", got)
	}

	// The exec failed: the flush is tried once more, on its own.
	e.startBox("flushbox", sandboxapi.StartRequest{})
	e.fake.HandleExec(e.workloadChecks(nil, func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if call.Command[0] == "/bin/sync" {
			return openshelltest.ExecResponse{}
		}
		return openshelltest.ExecResponse{Err: errors.New("exec relay closed")}
	}))
	before := len(e.fake.ExecCalls())
	e.stopBox("flushbox")
	calls = e.fake.ExecCalls()[before:]
	if len(calls) != 2 || !slices.Equal(calls[1].Command, []string{"/bin/sync"}) {
		t.Fatalf("exec calls = %+v", calls)
	}
	if got := e.events("flushbox", "", "stop_unflushed"); len(got) != 1 {
		t.Fatalf("a flushed stop was reported: %+v", got)
	}

	// Docker's stop keeps its exec as it was: no flush.
	d := liveEnv(t, "dockerstop", nil)
	d.stopBox("dockerstop")
	dc := d.fake.ExecCalls()
	if len(dc) != 1 || dc[0].Command[2] != endHarnessScript || dc[0].Timeout != harnessExitWait+3*time.Second {
		t.Fatalf("docker exec = %+v", dc)
	}
}

// The flush runs as the script ends, whichever way it ends, and says so.
func TestEndHarnessScriptFlushes(t *testing.T) {
	out, err := exec.Command("/bin/sh", "-c", flushTrap+endHarnessScript, "defenseclaw-end-harness", "/nonexistent/harness", "1").Output()
	if err != nil || strings.Join(strings.Fields(string(out)), " ") != "none synced" {
		t.Fatalf("script = %q, %v", out, err)
	}
}
