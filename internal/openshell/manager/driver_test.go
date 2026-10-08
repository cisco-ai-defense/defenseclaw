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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// newVMEnv is newEnv on a gateway that runs OpenShell's MicroVM driver.
func newVMEnv(t *testing.T, edit func(*config.Config)) *harnessEnv {
	t.Helper()
	return newDaemonEnv(t, daemonOptions{driver: openshell.DriverVM}, edit)
}

// The connector reads the driver off the gateway, and a gateway that runs
// none DefenseClaw drives is refused with an error that names it.
func TestConnectedDriver(t *testing.T) {
	for _, tc := range []struct {
		name    string
		fake    *openshelltest.Fake
		want    openshell.ComputeDriver
		refusal string
	}{
		{"docker", openshelltest.New(), openshell.DriverDocker, ""},
		{"vm", openshelltest.New(openshelltest.WithDriver(openshell.DriverVM)), openshell.DriverVM, ""},
		{"podman", openshelltest.New(openshelltest.WithDriver("podman")), "", `"podman"`},
		{"two drivers", openshelltest.New(openshelltest.WithGatewayInfo(types.GatewayInfo{ComputeDrivers: []types.ComputeDriverInfo{
			{Name: "docker"}, {Name: "vm"}}})), "", "several"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := connectedDriver(t.Context(), tc.fake.Client(openshell.ClientOptions{}))
			if tc.refusal == "" {
				if err != nil || d.Name != tc.want {
					t.Fatalf("driver = %+v, %v; want %s", d, err, tc.want)
				}
				return
			}
			if !errors.Is(err, openshell.ErrUnsupportedDriver) || !strings.Contains(err.Error(), tc.refusal) {
				t.Fatalf("driver = %+v, %v; want a refusal naming %s", d, err, tc.refusal)
			}
		})
	}
	f := openshelltest.New()
	f.FailNext(openshelltest.MethodGatewayInfo, &types.StatusError{Code: types.ErrorUnavailable, Message: "down"})
	if _, err := connectedDriver(t.Context(), f.Client(openshell.ClientOptions{})); err == nil || !strings.Contains(err.Error(), "which compute driver") {
		t.Fatalf("driver of a gateway whose info fails = %v", err)
	}
}

// The status names the connected gateway's driver.
func TestStatusNamesTheDriver(t *testing.T) {
	for _, driver := range []openshell.ComputeDriver{openshell.DriverDocker, openshell.DriverVM} {
		e := newDaemonEnv(t, daemonOptions{driver: driver}, nil)
		st, err := e.m.Status(t.Context())
		if err != nil || st.Gateway == nil || st.Gateway.Driver != string(driver) {
			t.Fatalf("%s: status = %+v, %v", driver, st, err)
		}
		// When the counters started: a session that began before it knows
		// its counts cover only the time since (PR 1022 live retest N1).
		if st.StartedAt.IsZero() || !st.StartedAt.Equal(e.m.startedAt) {
			t.Fatalf("%s: status started_at = %v, want the manager's start %v", driver, st.StartedAt, e.m.startedAt)
		}
		data, _ := json.Marshal(st)
		if !strings.Contains(string(data), `"driver":"`+string(driver)+`"`) {
			t.Fatalf("%s: status JSON = %s", driver, data)
		}
		if got := e.m.gatewayDriver(); got.Name != driver {
			t.Fatalf("%s: gatewayDriver after connecting = %+v", driver, got)
		}
	}
	// Before any gateway answered, a pre-create Explain describes docker.
	e := newVMEnv(t, nil)
	if got := e.m.gatewayDriver(); got.Name != openshell.DriverDocker {
		t.Fatalf("gatewayDriver before connecting = %+v", got)
	}
}

// A connection outlives a restart of its gateway, and `sandbox setup` or
// `doctor --fix` restart it on another driver. A create and a start ask
// the gateway which driver it runs now, and the status asks again once
// the last answer is a few seconds old: a switch drops the connection,
// and the next one drives the new driver.
func TestTheDaemonFollowsADriverSwitch(t *testing.T) {
	e := newEnv(t, nil)
	_, advance := e.fakeClock(time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC))
	connects := 0
	e.m.opts.Connect = func(ctx context.Context) (*Gateway, error) {
		connects++
		d, err := connectedDriver(ctx, e.client)
		if err != nil {
			return nil, err
		}
		gw := *e.gw
		gw.Driver = d
		return &gw, nil
	}
	useOpenCode(t, e)
	e.fake.HandleExec(e.workloadChecks(nil, nil))
	if st, err := e.m.Status(t.Context()); err != nil || st.Gateway == nil || st.Gateway.Driver != "docker" {
		t.Fatalf("status = %+v, %v", st, err)
	}
	// The gateway restarts on MicroVMs under the connection.
	e.fake.SetDriver(openshell.DriverVM)
	if st, _ := e.m.Status(t.Context()); st.Gateway.Driver != "docker" || connects != 1 {
		t.Fatalf("status within the recheck = %+v (connects %d)", st.Gateway, connects)
	}
	advance(driverRecheck)
	if st, _ := e.m.Status(t.Context()); st.Gateway.Driver != "vm" || connects != 2 || e.m.gatewayDriver().Name != openshell.DriverVM {
		t.Fatalf("status after the recheck = %+v (connects %d)", st.Gateway, connects)
	}

	// Back on docker: the create does not wait for the status to notice.
	e.fake.SetDriver(openshell.DriverDocker)
	e.create(sandboxapi.CreateRequest{Name: "dk-open", Harness: "opencode", Copy: true})
	if rec := e.boxOf("dk-open").rec; rec.Driver != string(openshell.DriverDocker) || connects != 3 {
		t.Fatalf("record driver %q (connects %d)", rec.Driver, connects)
	}
	e.stopBox("dk-open")
	// On vm again, the start judges the record against the driver the
	// gateway runs now: a sandbox made on docker cannot start.
	e.fake.SetDriver(openshell.DriverVM)
	_, err := e.m.Start(t.Context(), "dk-open", sandboxapi.StartRequest{})
	if apiErr := wantCode(t, err, sandboxapi.CodeConflict); !strings.Contains(apiErr.Error(), "was created on the docker driver") || connects != 4 {
		t.Fatalf("start = %v (connects %d)", apiErr, connects)
	}
}

// Setup's in-place upgrade restarts the gateway on a newer release under
// the connection: the status asks again once its last answer is a few
// seconds old, and a new release drops the connection, whose replacement
// reports it (and checks it against the supported window).
func TestTheDaemonFollowsAnInPlaceUpgrade(t *testing.T) {
	e := newEnv(t, nil)
	_, advance := e.fakeClock(time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC))
	connects := 0
	e.m.opts.Connect = func(ctx context.Context) (*Gateway, error) {
		connects++
		h, err := e.client.Health(ctx)
		if err != nil {
			return nil, err
		}
		gw := *e.gw
		gw.Version = h.RawVersion
		return &gw, nil
	}
	if st, err := e.m.Status(t.Context()); err != nil || st.Gateway == nil || st.Gateway.Version != openshell.SupportedMin {
		t.Fatalf("status = %+v, %v", st, err)
	}
	e.fake.SetRelease(openshell.InstallerVersion)
	advance(driverRecheck)
	if st, _ := e.m.Status(t.Context()); st.Gateway.Version != openshell.InstallerVersion || connects != 2 {
		t.Fatalf("status after the recheck = %+v (connects %d)", st.Gateway, connects)
	}
	// The same release again keeps the connection.
	advance(driverRecheck)
	if st, _ := e.m.Status(t.Context()); st.Gateway.Version != openshell.InstallerVersion || connects != 2 {
		t.Fatalf("status = %+v (connects %d)", st.Gateway, connects)
	}
}

// A MicroVM cannot take a live mount of the project: a Claude Code create
// that staged no copy is told to (CodeNeedsCopy) before anything is made,
// on the host or on the gateway. (In copy mode its run files go into a run
// image, see TestCreateOnVMBakesRunFilesIntoARunImage.)
func TestCreateOnVMRefusesAMountBeforeAnySideEffect(t *testing.T) {
	e := newVMEnv(t, nil)
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-claude", LLM: anthropicLLM, Credentials: stripeCred})
	apiErr := wantCode(t, err, sandboxapi.CodeNeedsCopy)
	if !strings.Contains(apiErr.Message, "mounted live") || !strings.Contains(apiErr.Detail, "mounts no host folders") {
		t.Fatalf("refusal = %+v", apiErr)
	}
	for _, method := range []string{openshelltest.MethodCreateSandbox, openshelltest.MethodCreateProvider} {
		if n := e.fake.Calls(method); n != 0 {
			t.Fatalf("%s calls = %d", method, n)
		}
	}
	if len(e.ws.planned) != 0 || len(e.ws.snapshots) != 0 || len(e.importer.imported) != 0 || len(e.images.runCalls()) != 0 {
		t.Fatalf("planned %v, snapshots %v, imported profiles %v, run images %d", e.ws.planned, e.ws.snapshots, e.importer.imported, len(e.images.runCalls()))
	}
	if _, err := os.Stat(filepath.Join(e.dataDir, "sandboxes", "vm-claude")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host state was written: %v", err)
	}
	assertNothingLeft(t, e)
}

// A harness without per-run files runs on a MicroVM in copy mode: its
// template carries no driver_config (the vm driver refuses a docker one),
// and the record and telemetry name the driver. A create that staged no
// copy is told to (CodeNeedsCopy) before anything is made.
func TestCreateOnVMHooksOnlyHarness(t *testing.T) {
	e := newVMEnv(t, nil)
	useOpenCode(t, e)
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-mount", Harness: "opencode"})
	if apiErr := wantCode(t, err, sandboxapi.CodeNeedsCopy); !strings.Contains(apiErr.Error(), "--copy") ||
		!strings.Contains(apiErr.Detail, "cannot be mounted live: the OpenShell MicroVM (vm) driver mounts no host folders") {
		t.Fatalf("mount refusal = %+v", apiErr)
	}
	if len(e.ws.planned) != 0 || len(e.ws.snapshots) != 0 || e.fake.Calls(openshelltest.MethodCreateSandbox) != 0 {
		t.Fatalf("a refused mount planned %v, snapshots %v", e.ws.planned, e.ws.snapshots)
	}
	assertNothingLeft(t, e)

	sb := e.create(sandboxapi.CreateRequest{Name: "vm-copy", Harness: "opencode", Copy: true})
	if sb.WorkdirMode != "copy" || sb.Phase != "ready" {
		t.Fatalf("sandbox = %+v", sb)
	}
	got, err := e.client.GetSandbox(t.Context(), "vm-copy")
	must(t, err)
	if got.Spec.Template == nil || got.Spec.Template.DriverConfig != nil {
		t.Fatalf("template = %+v", got.Spec.Template)
	}
	data, err := os.ReadFile(filepath.Join(e.dataDir, "sandboxes", "manager", "vm-copy.json"))
	must(t, err)
	var rec record
	must(t, json.Unmarshal(data, &rec))
	if rec.Driver != "vm" {
		t.Fatalf("recorded driver = %q", rec.Driver)
	}
	if ready := where(&e.tel.mu, &e.tel.lifecycle, func(ev audit.SandboxLifecycleEvent) bool {
		return ev.Sandbox.Name == "vm-copy" && ev.Sandbox.Phase == audit.SandboxPhaseReady
	}); len(ready) != 1 || ready[0].Sandbox.Driver != audit.SandboxDriverVM {
		t.Fatalf("lifecycle = %+v", ready)
	}
}

// The docker path records its driver too, and a docker template keeps its
// bind mounts.
func TestCreateOnDockerRecordsTheDriver(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "dk-copy", Copy: true})
	data, err := os.ReadFile(filepath.Join(e.dataDir, "sandboxes", "manager", "dk-copy.json"))
	must(t, err)
	var rec record
	must(t, json.Unmarshal(data, &rec))
	if rec.Driver != "docker" {
		t.Fatalf("recorded driver = %q", rec.Driver)
	}
	got, _ := e.client.GetSandbox(t.Context(), "dk-copy")
	if got.Spec.Template.DriverConfig["docker"] == nil {
		t.Fatalf("docker template = %+v", got.Spec.Template)
	}
}

// Telemetry names the driver a sandbox was created on (docker for records
// from before it was kept) and the digest of the image that runs.
func TestIdentityNamesTheDriverAndTheImageThatRuns(t *testing.T) {
	e := newEnv(t, nil)
	base, run := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64)
	for _, tc := range []struct {
		rec                record
		driver, digest     string
		runImage, runImgID string
	}{
		{record{Name: "old", ImageID: base}, audit.SandboxDriverDocker, base, "", ""},
		{record{Name: "dk", Driver: "docker", ImageID: base}, audit.SandboxDriverDocker, base, "", ""},
		{record{Name: "vm", Driver: "vm", ImageID: base, RunImage: "defenseclaw.invalid/sandbox-run:x", RunImageID: run}, audit.SandboxDriverVM, run,
			"defenseclaw.invalid/sandbox-run:x", run},
		// A driver this build does not know is left out, not guessed.
		{record{Name: "future", Driver: "podman", ImageID: base}, "", base, "", ""},
	} {
		b := &box{rec: tc.rec}
		if id := b.identity(); id.Driver != tc.driver || id.ImageDigest != tc.digest {
			t.Fatalf("%s: identity = %+v", tc.rec.Name, id)
		}
		e.m.mu.Lock()
		v := e.m.view(b)
		e.m.mu.Unlock()
		if v.RunImage != tc.runImage || v.RunImageID != tc.runImgID {
			t.Fatalf("%s: view = %+v", tc.rec.Name, v)
		}
	}
}

// GAP-0219: a first start on a full Mac ended with OpenShell's
// ProvisioningTimedOut alone; on the vm driver the error says what to check.
func TestProvisioningTimeoutNamesTheDisk(t *testing.T) {
	vm, _ := openshell.LookupDriver("vm")
	docker, _ := openshell.LookupDriver("docker")
	timedOut := errors.New(`sandbox "x" is in error state; OpenShell says: ProvisioningTimedOut: Provisioning repair window expired after 300 seconds`)
	if err := provisioningFailure(vm, upstream("wait for sandbox x", timedOut)); !strings.Contains(err.Error(), "Disk space in `defenseclaw sandbox doctor`") ||
		!strings.Contains(err.Error(), "defenseclaw sandbox image prune") {
		t.Fatalf("vm: %v", err)
	}
	for _, err := range []error{provisioningFailure(docker, upstream("wait for sandbox x", timedOut)),
		provisioningFailure(vm, upstream("wait for sandbox x", errors.New("deadline exceeded")))} {
		if strings.Contains(err.Error(), "image prune") {
			t.Fatalf("hint on another failure: %v", err)
		}
	}
}

// A sandbox's policy is re-resolved with the driver it was created on, not
// the connected gateway's, and a new one with the connected gateway's.
func TestResolutionUsesTheRecordsDriver(t *testing.T) {
	e := newVMEnv(t, nil)
	if _, err := e.m.gateway(t.Context()); err != nil {
		t.Fatal(err)
	}
	vm, _ := openshell.LookupDriver("vm")
	for _, tc := range []struct {
		driver string
		want   string
	}{{"", ""}, {"docker", ""}, {"vm", vm.MountRefusal}} {
		rec := record{Name: "r", Harness: "claudecode", Project: e.project, Driver: tc.driver}
		if got := rec.Flags.packs(rec.Harness, rec.Project, e.m.recordFacts(rec)).MountUnsupported; got != tc.want {
			t.Fatalf("record driver %q: MountUnsupported = %q, want %q", tc.driver, got, tc.want)
		}
	}
	if got := e.m.gatewayDriver(); got.MountRefusal != vm.MountRefusal {
		t.Fatalf("gatewayDriver = %+v", got)
	}
}
