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
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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

// Claude Code's per-run managed files reach a sandbox as read-only bind
// mounts, which a MicroVM cannot take: the create fails closed before
// anything is made, on the host or on the gateway, in mount and copy mode.
func TestCreateOnVMRefusesRunFilesBeforeAnySideEffect(t *testing.T) {
	for _, copyMode := range []bool{false, true} {
		e := newVMEnv(t, nil)
		_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-claude", Copy: copyMode, LLM: anthropicLLM, Credentials: stripeCred})
		apiErr := wantCode(t, err, sandboxapi.CodeUnavailable)
		if !strings.Contains(apiErr.Message, "Claude Code") || !strings.Contains(apiErr.Detail, "mounts no host folders") {
			t.Fatalf("copy %v: refusal = %+v", copyMode, apiErr)
		}
		for _, method := range []string{openshelltest.MethodCreateSandbox, openshelltest.MethodCreateProvider} {
			if n := e.fake.Calls(method); n != 0 {
				t.Fatalf("copy %v: %s calls = %d", copyMode, method, n)
			}
		}
		if len(e.ws.planned) != 0 || len(e.ws.snapshots) != 0 || len(e.importer.imported) != 0 {
			t.Fatalf("copy %v: planned %v, snapshots %v, imported profiles %v", copyMode, e.ws.planned, e.ws.snapshots, e.importer.imported)
		}
		if _, err := os.Stat(filepath.Join(e.dataDir, "sandboxes", "vm-claude")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("copy %v: host state was written: %v", copyMode, err)
		}
		assertNothingLeft(t, e)
	}
}

// A harness without per-run files runs on a MicroVM in copy mode: its
// template carries no driver_config (the vm driver refuses a docker one),
// and the record and telemetry name the driver. A live mount is refused
// before anything is made.
func TestCreateOnVMHooksOnlyHarness(t *testing.T) {
	e := newVMEnv(t, nil)
	res := connector.ResolveSandboxHookContract("opencode", "1.18.31")
	if res.Status != connector.HookCompatibilityKnown {
		t.Fatalf("opencode 1.18.31 has no known contract: %+v", res)
	}
	e.images.rec.HarnessVersion, e.images.rec.HookContract = "1.18.31", res.Contract.ContractID
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "vm-mount", Harness: "opencode"})
	if apiErr := wantCode(t, err, sandboxapi.CodeUnavailable); !strings.Contains(apiErr.Error(), "--copy") {
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
