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

// OpenShell runs on Linux and macOS only; these tests check its POSIX host
// paths and files.

//go:build !windows

package openshell

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderGatewayTOML(t *testing.T) {
	vm := RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: DriverVM, VMSandboxUID: 1000, VMSandboxGID: 1000}
	got, err := vm.TOML()
	if err != nil {
		t.Fatal(err)
	}
	want := "# Written by the DefenseClaw enterprise lifecycle from enterprise.openshell. Do not edit.\n" +
		"[openshell]\nversion = 2\n\n[openshell.gateway]\nbind_address = '127.0.0.1:17670'\ncompute_driver = 'vm'\n\n" +
		"[openshell.drivers]\n\n[openshell.drivers.vm]\nsandbox_uid = 1000\nsandbox_gid = 1000\n"
	if squashTOML(string(got)) != squashTOML(want) {
		t.Errorf("vm gateway.toml =\n%s\nwant\n%s", got, want)
	}
	docker := RenderedGateway{BindAddress: "127.0.0.1:18000", ComputeDriver: DriverDocker}
	got, err = docker.TOML()
	if err != nil {
		t.Fatal(err)
	}
	// The docker driver honors DefenseClaw's read-only driver-config mounts
	// (GAP-0449) and keeps its Docker objects in the managed namespace
	// (GAP-0566).
	if !strings.Contains(squashTOML(string(got)), "compute_driver = 'docker' [openshell.drivers] [openshell.drivers.docker] allow_driver_config = true enable_bind_mounts = true sandbox_label = 'defenseclaw-managed' [openshell.drivers.docker.resource_admission] enabled = false") {
		t.Errorf("docker gateway.toml =\n%s", got)
	}
	vm.DriverDir = "/usr/libexec/openshell"
	got, _ = vm.TOML()
	if !strings.Contains(string(got), "driver_dir = '/usr/libexec/openshell'") {
		t.Errorf("driver_dir missing:\n%s", got)
	}
}

func squashTOML(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\"", "'")), " ")
}

func TestRenderedGatewayRefusesWhatMustNotBeRendered(t *testing.T) {
	cases := map[string]RenderedGateway{
		"a public listener":     {BindAddress: "0.0.0.0:17670", ComputeDriver: DriverDocker},
		"a hostname listener":   {BindAddress: "localhost:17670", ComputeDriver: DriverDocker},
		"a privileged port":     {BindAddress: "127.0.0.1:80", ComputeDriver: DriverDocker},
		"no port":               {BindAddress: "127.0.0.1", ComputeDriver: DriverDocker},
		"an unknown driver":     {BindAddress: "127.0.0.1:17670", ComputeDriver: "podman"},
		"root in the MicroVM":   {BindAddress: "127.0.0.1:17670", ComputeDriver: DriverVM, VMSandboxUID: 0, VMSandboxGID: 1000},
		"a relative driver dir": {BindAddress: "127.0.0.1:17670", ComputeDriver: DriverVM, VMSandboxUID: 1000, VMSandboxGID: 1000, DriverDir: "libexec"},
	}
	for name, r := range cases {
		if _, err := r.TOML(); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	if _, err := (RenderedGateway{BindAddress: "[::1]:17670", ComputeDriver: DriverDocker}).TOML(); err != nil {
		t.Errorf("an IPv6 loopback listener was refused: %v", err)
	}
}

// The rendered gateway.toml is one file for every account, so it cannot name
// the account's uid (above 90 million for a directory account, never the
// MicroVM driver's default 1000): it leaves the MicroVM identity open, the
// exec shim gives each account's gateway its own, and Read and Drift see it
// (GAP-0254).
func TestRenderedGatewayLeavesTheMicroVMIdentityToTheAccount(t *testing.T) {
	r := RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: DriverVM}
	data, err := r.TOML()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sandbox_uid") || strings.Contains(string(data), "sandbox_gid") {
		t.Fatalf("the host-wide file names an identity:\n%s", data)
	}
	back, err := ParseRenderedGateway(data, nil)
	if err != nil || back.VMSandboxUID != 0 || back.VMSandboxGID != 0 {
		t.Fatalf("parsed = %+v %v", back, err)
	}
	for name, bad := range map[string]RenderedGateway{
		"a uid without a gid": {BindAddress: "127.0.0.1:17670", ComputeDriver: DriverVM, VMSandboxUID: 1000},
		"a negative uid":      {BindAddress: "127.0.0.1:17670", ComputeDriver: DriverVM, VMSandboxUID: -1, VMSandboxGID: 1000},
	} {
		if _, err := bad.TOML(); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}

	const uid, gid = 94404077, 94400513
	want := r.ForAccount(uid, gid)
	if want.VMSandboxUID != uid || want.VMSandboxGID != gid {
		t.Fatalf("for the account = %+v", want)
	}
	if fixed := (RenderedGateway{VMSandboxUID: 1500, VMSandboxGID: 1600}).ForAccount(uid, gid); fixed.VMSandboxUID != 1500 {
		t.Fatalf("an identity the render names was replaced: %+v", fixed)
	}
	if env := AccountVMEnvironment(uid, gid); len(env) != 2 || env[0] != "OPENSHELL_VM_SANDBOX_UID=94404077" || env[1] != "OPENSHELL_VM_SANDBOX_GID=94400513" {
		t.Fatalf("environment = %v", env)
	}

	// A gateway at the driver's default 1000:1000 drifts from the account's
	// identity; one at the account's does not.
	old := renderedOwnerOK
	renderedOwnerOK = func(fs.FileInfo) bool { return true }
	defer func() { renderedOwnerOK = old }()
	paths := writeRendered(t, r)
	read := &GatewayConfigurator{Dir: t.TempDir(), GOOS: "linux", Rendered: &paths}
	st, err := read.Read()
	if err != nil {
		t.Fatal(err)
	}
	if id := st.VM.Identity(); id.UID != DefaultVMSandboxUID {
		t.Fatalf("without the account's identity the driver default shows: %v", id)
	}
	if drift := st.Drift(want); len(drift) != 1 || drift[0].Field != "MicroVM workload identity" {
		t.Fatalf("drift = %v", drift)
	}
	read.AccountVM = &VMIdentity{UID: uid, GID: gid}
	st, err = read.Read()
	if err != nil {
		t.Fatal(err)
	}
	if id := st.VM.Identity(); id.UID != uid || id.GID != gid {
		t.Fatalf("identity = %v", id)
	}
	if drift := st.Drift(want); len(drift) != 0 {
		t.Fatalf("the account's gateway drifts from the render: %v", drift)
	}
}

// On a managed computer the doctor reads the rendered configuration with the
// account's identity, not the account's own gateway files (GAP-0254).
func TestDoctorGatewayFollowsTheRenderedConfiguration(t *testing.T) {
	paths := RenderedPaths{TOML: "/etc/defenseclaw/openshell/gateway.toml", Env: "/etc/defenseclaw/openshell/gateway.env"}
	d := &Doctor{Rendered: &paths, Geteuid: func() int { return 94404077 }, Getegid: func() int { return 94400513 }}
	d.defaults()
	if d.Gateway.Rendered != &paths || d.Gateway.AccountVM == nil || *d.Gateway.AccountVM != (VMIdentity{UID: 94404077, GID: 94400513}) {
		t.Fatalf("gateway = %+v", d.Gateway)
	}
	own := &Doctor{}
	own.defaults()
	if own.Gateway.Rendered != nil || own.Gateway.AccountVM != nil {
		t.Fatalf("an unmanaged computer reads the rendered files: %+v", own.Gateway)
	}
}

func TestRenderedGatewayRoundTripAndDigest(t *testing.T) {
	r := RenderedGateway{BindAddress: "127.0.0.1:17999", ComputeDriver: DriverVM, VMSandboxUID: 1500, VMSandboxGID: 1600, DriverDir: "/opt/os", TelemetryEnabled: false}
	toml1, err := r.TOML()
	if err != nil {
		t.Fatal(err)
	}
	env := r.EnvFile()
	if !strings.Contains(string(env), "OPENSHELL_TELEMETRY_ENABLED=false") {
		t.Fatalf("env = %q", env)
	}
	back, err := ParseRenderedGateway(toml1, env)
	if err != nil || back != r {
		t.Fatalf("round trip = %+v %v, want %+v", back, err, r)
	}
	r.TelemetryEnabled = true
	if env := r.EnvFile(); env != nil {
		t.Errorf("telemetry allowed still renders %q", env)
	}
	first, again := RenderedDigest(toml1, nil), RenderedDigest(toml1, nil)
	if first == RenderedDigest(toml1, []byte("x")) || first != again {
		t.Error("digest does not follow the content")
	}
}

func writeRendered(t *testing.T, r RenderedGateway) RenderedPaths {
	t.Helper()
	dir := t.TempDir()
	paths := RenderedPaths{TOML: filepath.Join(dir, "gateway.toml"), Env: filepath.Join(dir, "gateway.env")}
	data, err := r.TOML()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.TOML, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if env := r.EnvFile(); env != nil {
		if err := os.WriteFile(paths.Env, env, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return paths
}

func TestRenderedModeReadsTheRootOwnedFilesAndRefusesChanges(t *testing.T) {
	r := RenderedGateway{BindAddress: "127.0.0.1:17888", ComputeDriver: DriverVM, VMSandboxUID: 1000, VMSandboxGID: 1000}
	paths := writeRendered(t, r)
	g := &GatewayConfigurator{Dir: t.TempDir(), GOOS: "linux", Rendered: &paths}

	// The files here are the test user's, not root's: refused.
	if _, err := g.Read(); err == nil || !strings.Contains(err.Error(), "root-owned") {
		t.Fatalf("Read of a file root does not own: err = %v", err)
	}
	old := renderedOwnerOK
	renderedOwnerOK = func(fs.FileInfo) bool { return true }
	defer func() { renderedOwnerOK = old }()

	st, err := g.Read()
	if err != nil {
		t.Fatal(err)
	}
	if st.TOMLPath != paths.TOML || st.ComputeDriver != DriverVM || st.TelemetryEnabled() {
		t.Fatalf("state = %+v", st)
	}
	if drift := st.Drift(r); drift != nil {
		t.Errorf("a gateway running the rendered file drifts: %v", drift)
	}
	if _, err := g.Plan(context.Background(), GatewayChanges{EnableBindMounts: true}); !errors.Is(err, ErrRenderedGateway) {
		t.Errorf("Plan err = %v", err)
	}
	if _, err := g.Apply(context.Background(), &GatewayPlan{}); !errors.Is(err, ErrRenderedGateway) {
		t.Errorf("Apply err = %v", err)
	}
	if _, err := g.Write(context.Background(), &GatewayPlan{}); !errors.Is(err, ErrRenderedGateway) {
		t.Errorf("Write err = %v", err)
	}

	// A symlink in place of the rendered file is not followed.
	link := filepath.Join(filepath.Dir(paths.TOML), "linked.toml")
	if err := os.Symlink(paths.TOML, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRenderedFile(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("symlink: err = %v", err)
	}
	// A missing env file is the defaults.
	if data, info, err := readRenderedFile(filepath.Join(filepath.Dir(paths.TOML), "absent.env")); data != nil || info != nil || err != nil {
		t.Errorf("absent file = %v %v %v", data, info, err)
	}
}

// ReadRenderedGateway reads the trusted render back with the digest the
// daemon's settings carry, and refuses an untrusted or missing one.
func TestReadRenderedGateway(t *testing.T) {
	r := RenderedGateway{BindAddress: "127.0.0.1:17888", ComputeDriver: DriverDocker}
	paths := writeRendered(t, r)
	if _, _, err := ReadRenderedGateway(paths.TOML, paths.Env); err == nil || !strings.Contains(err.Error(), "root-owned") {
		t.Fatalf("untrusted render: %v", err)
	}
	old := renderedOwnerOK
	renderedOwnerOK = func(fs.FileInfo) bool { return true }
	defer func() { renderedOwnerOK = old }()
	got, digest, err := ReadRenderedGateway(paths.TOML, paths.Env)
	tomlData, _ := os.ReadFile(paths.TOML)
	envData, _ := os.ReadFile(paths.Env)
	if err != nil || got.BindAddress != r.BindAddress || got.ComputeDriver != DriverDocker || got.TelemetryEnabled ||
		digest != RenderedDigest(tomlData, envData) {
		t.Fatalf("read = %+v %q %v", got, digest, err)
	}
	if _, _, err := ReadRenderedGateway(filepath.Join(filepath.Dir(paths.TOML), "absent.toml"), paths.Env); err == nil {
		t.Fatal("a missing render was read")
	}
}

// An account's own docker gateway in any namespace but the rendered one
// drifts from the render, which keeps the managed gateways' sandboxes in
// ManagedDockerNamespace (OpenShell's default under the 1.0.1 bridge): a
// gateway in the shared default namespace removes the supervisors of other
// accounts' sandboxes at each start, and the sandboxes made in another
// namespace are lost to the rendered gateway.
func TestGatewayDriftNamesTheSharedDockerNamespace(t *testing.T) {
	want := RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: DriverDocker, TelemetryEnabled: true}
	base := "[openshell]\nversion = 2\n[openshell.gateway]\nbind_address = \"127.0.0.1:17670\"\ncompute_driver = \"docker\"\n"
	for _, tc := range []struct {
		name, label string
		bridge      bool
		drift       bool
	}{
		{"unset label", "", false, true},
		{"default label", "default", false, true},
		{"managed label", ManagedDockerNamespace, false, false},
		// A per-user label: the daemon's managed sandboxes would be lost
		// to the rendered gateway after its next start.
		{"own label", AccountDockerNamespace(1500), false, true},
		{"1.0.1 bridge", "", true, false},
		{"1.0.1 bridge, default label", "default", true, false},
		{"1.0.1 bridge, managed label", ManagedDockerNamespace, true, true},
		{"1.0.1 bridge, own label", AccountDockerNamespace(1500), true, true},
	} {
		dir := t.TempDir()
		toml := base
		if tc.label != "" {
			toml += "[openshell.drivers.docker]\nsandbox_label = \"" + tc.label + "\"\n"
		}
		if err := os.WriteFile(filepath.Join(dir, GatewayTOMLFile), []byte(toml), 0o600); err != nil {
			t.Fatal(err)
		}
		st, err := (&GatewayConfigurator{Dir: dir, GOOS: "linux"}).Read()
		if err != nil {
			t.Fatal(err)
		}
		w := want
		w.DefaultDockerNamespaceBridge = tc.bridge
		got := false
		for _, d := range st.Drift(w) {
			if d.Field == "Docker sandbox namespace" {
				got = true
			}
		}
		if got != tc.drift {
			t.Errorf("%s: namespace drift = %t, want %t (%v)", tc.name, got, tc.drift, st.Drift(w))
		}
	}
	// The render read back says which namespace it keeps.
	for _, bridge := range []bool{false, true} {
		r := RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: DriverDocker, DefaultDockerNamespaceBridge: bridge}
		data, err := r.TOML()
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseRenderedGateway(data, nil)
		if err != nil || back.DefaultDockerNamespaceBridge != bridge {
			t.Fatalf("bridge %t read back as %+v, %v", bridge, back, err)
		}
	}
}

func TestGatewayDriftNamesEverySettingThatDiffers(t *testing.T) {
	want := RenderedGateway{BindAddress: "127.0.0.1:17670", ComputeDriver: DriverVM, VMSandboxUID: 1500, VMSandboxGID: 1500}
	dir := t.TempDir()
	toml := "[openshell]\nversion = 2\n[openshell.gateway]\nbind_address = \"0.0.0.0:17670\"\ncompute_driver = \"docker\"\n"
	if err := os.WriteFile(filepath.Join(dir, GatewayTOMLFile), []byte(toml), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &GatewayConfigurator{Dir: dir, GOOS: "linux"}
	st, err := g.Read()
	if err != nil {
		t.Fatal(err)
	}
	var fields []string
	for _, d := range st.Drift(want) {
		fields = append(fields, d.Field)
	}
	got := strings.Join(fields, ", ")
	for _, field := range []string{"compute driver", "gateway listener", "MicroVM workload identity", "OpenShell telemetry"} {
		if !strings.Contains(got, field) {
			t.Errorf("drift %q lacks %q", got, field)
		}
	}
	// gateway.env overrides gateway.toml, so the drift follows it.
	env := "OPENSHELL_COMPUTE_DRIVER=vm\nOPENSHELL_BIND_ADDRESS=127.0.0.1\nOPENSHELL_TELEMETRY_ENABLED=false\nOPENSHELL_VM_SANDBOX_UID=1500\nOPENSHELL_VM_SANDBOX_GID=1500\n"
	if err := os.WriteFile(filepath.Join(dir, GatewayEnvFile), []byte(env), 0o600); err != nil {
		t.Fatal(err)
	}
	want.TelemetryEnabled = false
	st, err = g.Read()
	if err != nil {
		t.Fatal(err)
	}
	if drift := st.Drift(want); drift != nil {
		t.Errorf("the environment settings match, drift = %v", drift)
	}
}
