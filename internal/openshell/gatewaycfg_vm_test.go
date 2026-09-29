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
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// homebrewTOML is the gateway.toml the nvidia/openshell formula leaves
// under the Homebrew prefix.
const homebrewTOML = "[openshell]\nversion = 2\n\n[openshell.gateway]\n"

// microVMs is what setup asks for on a Mac, for uid 501, gid 20.
var microVMs = openshell.GatewayChanges{ComputeDriver: openshell.DriverVM, VMIdentity: &openshell.VMIdentity{UID: 501, GID: 20},
	VMResources: &openshell.VMResources{VCPUs: 4, MemMiB: 4096, OverlayDiskMiB: 16384}}

// onHomebrew makes f a Mac whose Homebrew service's own gateway.toml is
// content (none when empty), and whose restarted gateway runs *running.
// It returns the prefix's var/openshell.
func (f *gatewayFixture) onHomebrew(t *testing.T, content string, running *openshell.ComputeDriver) string {
	t.Helper()
	f.cfg.GOOS = "darwin"
	f.runner.On("brew services restart nvidia/openshell/openshell", "", nil)
	f.cfg.RunningDriver = func(context.Context) (openshell.Driver, error) {
		d, _ := openshell.LookupDriver(string(*running))
		return d, nil
	}
	prefix := filepath.Join(f.cfg.BrewPrefix, "var", "openshell")
	if err := os.MkdirAll(prefix, 0o700); err != nil {
		t.Fatal(err)
	}
	if content != "" {
		writeFile(t, filepath.Join(prefix, "gateway.toml"), content, 0o600)
	}
	return prefix
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (f *gatewayFixture) brewRestarts() int {
	n := 0
	for _, c := range f.runner.Calls() {
		if openshelltest.Argv(c) == "brew services restart nvidia/openshell/openshell" {
			n++
		}
	}
	return n
}

// TestGatewayConfigReadsTheComputeDriver: the configured driver and the
// MicroVM driver's settings come from gateway.toml, and gateway.env's
// variables override them.
func TestGatewayConfigReadsTheComputeDriver(t *testing.T) {
	f := newGatewayFixture(t)
	st, err := f.cfg.Read()
	if d, known := st.Driver(); err != nil || st.ComputeDriver != "" || !known || d.Name != openshell.DriverDocker ||
		st.VM.Identity() != (openshell.VMIdentity{UID: 1000, GID: 1000}) || st.VM.Resources() != (openshell.VMResources{VCPUs: 2, MemMiB: 2048, OverlayDiskMiB: 4096}) {
		t.Fatalf("fresh state = %+v, %v", st, err)
	}
	f.write(t, "gateway.toml", homebrewTOML+"compute_driver = \"vm\"\n\n[openshell.drivers.vm]\nsandbox_uid = 501\nsandbox_gid = 20\nvcpus = 4\n"+
		"state_dir = \"/vm/state\"\ndriver_dir = \"/vm/libexec\"\n")
	st, err = f.cfg.Read()
	if d, _ := st.Driver(); err != nil || st.ComputeDriver != openshell.DriverVM || d.HostMounts || st.VM.Identity() != (openshell.VMIdentity{UID: 501, GID: 20}) ||
		st.VM.Resources() != (openshell.VMResources{VCPUs: 4, MemMiB: 2048, OverlayDiskMiB: 4096}) || st.VM.StateDir != "/vm/state" || st.VM.DriverDir != "/vm/libexec" {
		t.Fatalf("state = %+v (vm %+v), %v", st, st.VM, err)
	}
	// An empty variable counts as unset, as it does for the gateway.
	f.write(t, "gateway.env", "OPENSHELL_COMPUTE_DRIVER=docker\nOPENSHELL_VM_SANDBOX_GID=30\nOPENSHELL_VM_DRIVER_MEM_MIB=8192\n"+
		"OPENSHELL_VM_OVERLAY_DISK_MIB=\nOPENSHELL_VM_DRIVER_STATE_DIR=/elsewhere\n")
	st, err = f.cfg.Read()
	if err != nil || st.ComputeDriver != openshell.DriverDocker || st.VM.Identity() != (openshell.VMIdentity{UID: 501, GID: 30}) ||
		st.VM.Resources() != (openshell.VMResources{VCPUs: 4, MemMiB: 8192, OverlayDiskMiB: 4096}) || st.VM.StateDir != "/elsewhere" {
		t.Fatalf("state with gateway.env = %+v (vm %+v), %v", st, st.VM, err)
	}
}

// TestGatewayConfigFindsTheHomebrewFiles: on macOS the formula's wrapper
// sources Dir's gateway.env when it exists, else the Homebrew prefix's,
// and starts the gateway on the prefix's gateway.toml only when
// OPENSHELL_GATEWAY_CONFIG is unset and Dir has none (F10). DefenseClaw
// edits the file the service reads, and never creates an empty one in
// Dir that would hide the prefix's.
func TestGatewayConfigFindsTheHomebrewFiles(t *testing.T) {
	f := newGatewayFixture(t)
	var running openshell.ComputeDriver
	prefix := f.onHomebrew(t, "", &running)
	paths := func() (string, string) {
		t.Helper()
		env, err := f.cfg.EnvPath()
		if err != nil {
			t.Fatal(err)
		}
		toml, err := f.cfg.TOMLPath()
		if err != nil {
			t.Fatal(err)
		}
		return env, toml
	}
	dirEnv, dirTOML := filepath.Join(f.dir, "gateway.env"), filepath.Join(f.dir, "gateway.toml")
	if env, toml := paths(); env != dirEnv || toml != dirTOML {
		t.Fatalf("with neither: %s, %s", env, toml)
	}
	writeFile(t, filepath.Join(prefix, "gateway.toml"), homebrewTOML, 0o600)
	writeFile(t, filepath.Join(prefix, "gateway.env"), "OPENSHELL_TELEMETRY_ENABLED=false\n", 0o600)
	if env, toml := paths(); env != filepath.Join(prefix, "gateway.env") || toml != filepath.Join(prefix, "gateway.toml") {
		t.Fatalf("with the prefix's: %s, %s", env, toml)
	}
	other := filepath.Join(f.dir, "elsewhere.toml")
	writeFile(t, filepath.Join(prefix, "gateway.env"), "OPENSHELL_GATEWAY_CONFIG="+other+"\n", 0o600)
	if _, toml := paths(); toml != other {
		t.Fatalf("with OPENSHELL_GATEWAY_CONFIG in the prefix's gateway.env: %s", toml)
	}
	f.write(t, "gateway.env", "")
	f.write(t, "gateway.toml", homebrewTOML)
	if env, toml := paths(); env != dirEnv || toml != dirTOML {
		t.Fatalf("with Dir's: %s, %s", env, toml)
	}
	// Linux never reads a Homebrew prefix.
	g := newGatewayFixture(t)
	g.onHomebrew(t, homebrewTOML, &running)
	g.cfg.GOOS = "linux"
	if toml, err := g.cfg.TOMLPath(); err != nil || toml != filepath.Join(g.dir, "gateway.toml") {
		t.Fatalf("Linux TOMLPath = %s, %v", toml, err)
	}
}

// TestGatewayConfigSwitchesToMicroVMs: the plan edits the gateway.toml the
// service reads (here the Homebrew prefix's), writes the driver as a
// string and the settings as TOML integers, says what the switch strands,
// and after the restart checks that the gateway runs vm, undoing the
// switch when it does not.
func TestGatewayConfigSwitchesToMicroVMs(t *testing.T) {
	f := newGatewayFixture(t)
	running := openshell.DriverVM
	prefix := f.onHomebrew(t, homebrewTOML, &running)
	path := filepath.Join(prefix, "gateway.toml")
	plan := f.plan(t, microVMs)
	text := plan.String()
	for _, want := range []string{"edit " + path + " (a timestamped backup is kept)", `set [openshell.gateway] compute_driver = "vm"`,
		"set [openshell.drivers.vm] sandbox_uid = 501", "set [openshell.drivers.vm] overlay_disk_mib = 16384", `+ compute_driver = "vm"`, "+ sandbox_gid = 20",
		"then restart the gateway (brew services restart nvidia/openshell/openshell) on the vm compute driver; running sandboxes stop, and sandboxes " +
			"made on the docker driver cannot start again unless it is switched back (one gateway runs one driver)"} {
		if !strings.Contains(text, want) {
			t.Errorf("plan lacks %q:\n%s", want, text)
		}
	}
	if len(plan.Files) != 1 || plan.BindMounts || plan.ComputeDriver != openshell.DriverVM || plan.FromDriver != openshell.DriverDocker {
		t.Fatalf("plan = %+v", plan)
	}
	// A gateway.toml change is no longer taken for bind mounts: nothing
	// probes who can reach the gateway.
	if res, err := f.apply(plan); err != nil || !res.Restarted || f.brewRestarts() != 1 || f.probes != 0 {
		t.Fatalf("Apply = %+v, %v (restarts %d, probes %d)", res, err, f.brewRestarts(), f.probes)
	}
	st, err := f.cfg.Read()
	if err != nil || st.TOMLPath != path || st.ComputeDriver != openshell.DriverVM || st.VM.Identity() != *microVMs.VMIdentity ||
		st.VM.Resources() != *microVMs.VMResources {
		t.Fatalf("after Apply: %+v, %v", st, err)
	}
	if _, err := os.Lstat(filepath.Join(f.dir, "gateway.toml")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an XDG gateway.toml hides the prefix's: %v", err)
	}
	// Integer keys compare as TOML decodes them: the same change again
	// plans nothing.
	if again := f.plan(t, microVMs); !again.Empty() {
		t.Fatalf("an unchanged configuration plans:\n%s", again)
	}

	// A gateway that comes back on docker (an environment DefenseClaw does
	// not read selects it) gets its previous configuration back.
	g := newGatewayFixture(t)
	docker := openshell.DriverDocker
	prefix = g.onHomebrew(t, homebrewTOML, &docker)
	_, err = g.apply(g.plan(t, microVMs))
	if err == nil || !strings.Contains(err.Error(), "the restarted gateway runs the docker compute driver, not vm") ||
		!strings.Contains(err.Error(), "previous configuration was restored") || g.brewRestarts() != 2 {
		t.Fatalf("Apply = %v (restarts %d)", err, g.brewRestarts())
	}
	if got := readFile(t, filepath.Join(prefix, "gateway.toml")); got != homebrewTOML {
		t.Fatalf("gateway.toml not restored:\n%s", got)
	}
}

// TestGatewayConfigRefusesMicroVMUsersThatAreRoot: the identity is every
// sandbox's on the gateway; DefenseClaw never makes it root's.
func TestGatewayConfigRefusesMicroVMUsersThatAreRoot(t *testing.T) {
	f := newGatewayFixture(t)
	for _, id := range []openshell.VMIdentity{{UID: 0, GID: 20}, {UID: 501, GID: 0}} {
		if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{VMIdentity: &id}); err == nil || !strings.Contains(err.Error(), "never as root") {
			t.Fatalf("Plan(%v) = %v", id, err)
		}
	}
	if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{VMResources: &openshell.VMResources{MemMiB: -1}}); err == nil {
		t.Fatal("planned a negative memory size")
	}
}

// TestGatewayConfigRefusesBindMountsOnMicroVMs: bind mounts are the docker
// driver's; on a gateway configured for vm there is nothing to enable.
func TestGatewayConfigRefusesBindMountsOnMicroVMs(t *testing.T) {
	f := newGatewayFixture(t)
	vm := homebrewTOML + "compute_driver = \"vm\"\n"
	f.write(t, "gateway.toml", vm)
	for _, ch := range []openshell.GatewayChanges{bindMounts, {EnableBindMounts: true, ComputeDriver: openshell.DriverVM}} {
		if _, err := f.cfg.Plan(context.Background(), ch); !errors.Is(err, openshell.ErrBindMountsRefused) || !strings.Contains(err.Error(), "mounts no host folders") {
			t.Fatalf("Plan(%+v) = %v", ch, err)
		}
	}
	f.untouched(t, vm)
}

// TestGatewayConfigMatchesGatewayEnvToTheDriver: gateway.env overrides
// gateway.toml, so a variable there naming another driver or user is set
// to match, which the plan says; one that already agrees is left alone.
func TestGatewayConfigMatchesGatewayEnvToTheDriver(t *testing.T) {
	f := newGatewayFixture(t)
	f.write(t, "gateway.env", "OPENSHELL_COMPUTE_DRIVER=docker\nOPENSHELL_VM_SANDBOX_UID=501\nOTHER=1\n")
	plan := f.plan(t, openshell.GatewayChanges{ComputeDriver: openshell.DriverVM, VMIdentity: &openshell.VMIdentity{UID: 501, GID: 20}})
	if len(plan.Files) != 2 || plan.Files[1].Path != filepath.Join(f.dir, "gateway.env") {
		t.Fatalf("plan = %+v", plan.Files)
	}
	env := plan.Files[1]
	if strings.Join(env.Summary, "; ") != "OPENSHELL_COMPUTE_DRIVER=vm (it overrides gateway.toml)" ||
		string(env.After) != "OPENSHELL_COMPUTE_DRIVER=vm\nOPENSHELL_VM_SANDBOX_UID=501\nOTHER=1\n" {
		t.Fatalf("gateway.env change = %q:\n%s", env.Summary, env.After)
	}
	if _, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{ComputeDriver: openshell.DriverVM,
		Env: map[string]string{"OPENSHELL_COMPUTE_DRIVER": "docker"}}); err == nil {
		t.Fatal("planned a driver and a gateway.env change that contradict each other")
	}
}

// TestGatewayConfigSeedsASharedHomebrewPrefix: a gateway.toml under a
// Homebrew prefix another macOS user owns (sandbox_uid is per user) is
// never edited: the change goes to a copy in Dir, which the wrapper reads
// from then on, and the plan says so.
func TestGatewayConfigSeedsASharedHomebrewPrefix(t *testing.T) {
	f := newGatewayFixture(t)
	running := openshell.DriverVM
	theirs := homebrewTOML + "# theirs\n"
	prefix := f.onHomebrew(t, theirs, &running)
	path := filepath.Join(prefix, "gateway.toml")
	foreign, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	openshell.SetGatewayFileOwner(t, func(info fs.FileInfo) bool { return !os.SameFile(info, foreign) })
	if st, err := f.cfg.Read(); err != nil || st.TOMLPath != path {
		t.Fatalf("Read = %+v, %v", st, err)
	}
	plan := f.plan(t, microVMs)
	dirTOML := filepath.Join(f.dir, "gateway.toml")
	if len(plan.Files) != 1 || plan.Files[0].Path != dirTOML || plan.Files[0].SeededFrom != path ||
		!strings.Contains(plan.String(), "create "+dirTOML+" from "+path+", which another user owns and is left alone; the gateway reads the new file from then on") {
		t.Fatalf("plan = %+v:\n%s", plan.Files, plan)
	}
	// The other user's file changed since the plan: nothing is written.
	writeFile(t, path, theirs+"# again\n", 0o600)
	if _, err := f.apply(plan); !errors.Is(err, openshell.ErrConfigChanged) {
		t.Fatalf("Apply after the prefix's file changed = %v", err)
	}
	writeFile(t, path, theirs, 0o600)
	if foreign, err = os.Lstat(path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.apply(f.plan(t, microVMs)); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, dirTOML); !strings.Contains(got, "# theirs\n") || !strings.Contains(got, `compute_driver = "vm"`) {
		t.Fatalf("seeded gateway.toml:\n%s", got)
	}
	if got := readFile(t, path); got != theirs {
		t.Fatalf("the other user's file changed:\n%s", got)
	}
	if st, err := f.cfg.Read(); err != nil || st.TOMLPath != dirTOML || st.ComputeDriver != openshell.DriverVM {
		t.Fatalf("after Apply: %+v, %v", st, err)
	}
}
