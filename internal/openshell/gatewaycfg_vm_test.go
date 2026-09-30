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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

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

// TestGatewayConfigWaitsForTheRestartedDriver: a restarted gateway can be
// healthy before it says which driver it runs (its driver has not
// connected yet). Apply asks again within the restart wait instead of
// undoing the switch, and undoes it only for a gateway that never says.
func TestGatewayConfigWaitsForTheRestartedDriver(t *testing.T) {
	f := newGatewayFixture(t)
	running := openshell.DriverVM
	f.onHomebrew(t, homebrewTOML, &running)
	f.cfg.RestartWait = 5 * time.Second
	asked := 0
	f.cfg.RunningDriver = func(context.Context) (openshell.Driver, error) {
		if asked++; asked < 3 {
			return openshell.Driver{}, fmt.Errorf("%w; this gateway reports no compute driver", openshell.ErrUnsupportedDriver)
		}
		d, _ := openshell.LookupDriver(string(running))
		return d, nil
	}
	if res, err := f.apply(f.plan(t, microVMs)); err != nil || !res.Restarted || f.brewRestarts() != 1 || asked != 3 {
		t.Fatalf("Apply = %+v, %v (restarts %d, asked %d times)", res, err, f.brewRestarts(), asked)
	}

	g := newGatewayFixture(t)
	prefix := g.onHomebrew(t, homebrewTOML, &running)
	g.cfg.RestartWait = 50 * time.Millisecond
	g.cfg.RunningDriver = func(context.Context) (openshell.Driver, error) {
		return openshell.Driver{}, errors.New("openshell: gateway info: unavailable")
	}
	_, err := g.apply(g.plan(t, microVMs))
	if err == nil || !strings.Contains(err.Error(), "gateway info: unavailable") || g.brewRestarts() != 2 {
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

// TestFlushSandboxesBeforeARestart: a restart stops every sandbox on the
// gateway, and a MicroVM stopped without a flush brings back empty what
// it wrote since its last one (OpenShell 0.1.1). On the vm driver every
// ready sandbox runs sync(1) first, of every owner, and one that cannot
// be flushed refuses the restart; the docker driver's stop keeps what a
// container wrote. A gateway whose driver could not be read is flushed
// too, and only one that answers neither call is taken to be down.
func TestFlushSandboxesBeforeARestart(t *testing.T) {
	gateway := func(t *testing.T, d openshell.ComputeDriver, phases map[string]openshell.SandboxPhase) *openshelltest.Fake {
		t.Helper()
		f := openshelltest.New(openshelltest.WithDriver(d))
		c := f.Client(openshell.ClientOptions{})
		for name, phase := range phases {
			if _, err := c.CreateSandbox(context.Background(), name, &openshell.SandboxSpec{}, openshell.CreateSandboxOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := f.SetPhase(openshell.DefaultWorkspace, name, phase); err != nil {
				t.Fatal(err)
			}
		}
		return f
	}
	flushed := func(f *openshelltest.Fake) []string {
		var out []string
		for _, c := range f.ExecCalls() {
			if strings.Join(c.Command, " ") == "/bin/sync" {
				out = append(out, c.Sandbox)
			}
		}
		slices.Sort(out)
		return out
	}
	phases := map[string]openshell.SandboxPhase{"dc-a": openshell.PhaseReady, "dc-b": openshell.PhaseStopped, "theirs": openshell.PhaseReady}

	vm := gateway(t, openshell.DriverVM, phases)
	if err := openshell.FlushSandboxes(context.Background(), vm.Client(openshell.ClientOptions{})); err != nil {
		t.Fatal(err)
	}
	if got := flushed(vm); !slices.Equal(got, []string{"dc-a", "theirs"}) {
		t.Fatalf("flushed %v, want the ready ones", got)
	}

	docker := gateway(t, openshell.DriverDocker, phases)
	if err := openshell.FlushSandboxes(context.Background(), docker.Client(openshell.ClientOptions{})); err != nil || len(flushed(docker)) != 0 {
		t.Fatalf("docker: %v, flushed %v", err, flushed(docker))
	}

	stuck := gateway(t, openshell.DriverVM, phases)
	stuck.HandleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if call.Sandbox == "theirs" {
			return openshelltest.ExecResponse{ExitCode: 1}
		}
		return openshelltest.ExecResponse{}
	})
	err := openshell.FlushSandboxes(context.Background(), stuck.Client(openshell.ClientOptions{}))
	if !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "theirs: sync(1) exited with status 1") || strings.Contains(err.Error(), "dc-a:") {
		t.Fatalf("flush with a stuck sandbox = %v", err)
	}

	// A gateway whose driver could not be read is flushed all the same:
	// one failed GetGatewayInfo does not mean nothing runs on it.
	for _, infoErr := range []error{
		&v1.StatusError{Code: v1.ErrorDeadlineExceeded, Message: "context deadline exceeded"},
		&v1.StatusError{Code: v1.ErrorUnavailable, Message: "connection refused"},
		&v1.StatusError{Code: v1.ErrorUnimplemented, Message: "unknown method GetGatewayInfo"},
	} {
		busy := gateway(t, openshell.DriverVM, phases)
		busy.FailNext(openshelltest.MethodGatewayInfo, infoErr)
		if err := openshell.FlushSandboxes(context.Background(), busy.Client(openshell.ClientOptions{})); err != nil {
			t.Fatalf("GatewayInfo failed with %v: %v", infoErr, err)
		}
		if got := flushed(busy); !slices.Equal(got, []string{"dc-a", "theirs"}) {
			t.Fatalf("GatewayInfo failed with %v: flushed %v, want the ready ones", infoErr, got)
		}
	}

	// A gateway that refuses both calls has nothing a flush could reach.
	down := gateway(t, openshell.DriverVM, phases)
	down.FailNext(openshelltest.MethodGatewayInfo, &v1.StatusError{Code: v1.ErrorUnavailable, Message: "connection refused"})
	down.FailNext(openshelltest.MethodListSandboxes, &v1.StatusError{Code: v1.ErrorUnavailable, Message: "connection refused"})
	if err := openshell.FlushSandboxes(context.Background(), down.Client(openshell.ClientOptions{})); err != nil || len(flushed(down)) != 0 {
		t.Fatalf("gateway down: %v, flushed %v", err, flushed(down))
	}

	// One that answers the list with an error, or times out on it (a
	// busy host), is not down: the restart waits until its sandboxes can
	// be flushed.
	for _, listErr := range []error{
		&v1.StatusError{Code: v1.ErrorInternal, Message: "store locked"},
		&v1.StatusError{Code: v1.ErrorDeadlineExceeded, Message: "context deadline exceeded"},
	} {
		unlisted := gateway(t, openshell.DriverVM, phases)
		unlisted.FailNext(openshelltest.MethodGatewayInfo, &v1.StatusError{Code: v1.ErrorDeadlineExceeded, Message: "context deadline exceeded"})
		unlisted.FailNext(openshelltest.MethodListSandboxes, listErr)
		if err := openshell.FlushSandboxes(context.Background(), unlisted.Client(openshell.ClientOptions{})); !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), listErr.(*v1.StatusError).Message) {
			t.Fatalf("GatewayInfo and the list (%v) failed: %v, want ErrUnflushed", listErr, err)
		}
	}
	// Nor is one whose context ended.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ended := gateway(t, openshell.DriverVM, phases)
	ended.FailNext(openshelltest.MethodGatewayInfo, &v1.StatusError{Code: v1.ErrorUnavailable, Message: "connection refused"})
	ended.FailNext(openshelltest.MethodListSandboxes, &v1.StatusError{Code: v1.ErrorUnavailable, Message: "connection refused"})
	if err := openshell.FlushSandboxes(ctx, ended.Client(openshell.ClientOptions{})); !errors.Is(err, openshell.ErrUnflushed) {
		t.Fatalf("flush on an ended context: %v, want ErrUnflushed", err)
	}
}

// TestGatewayConfigFlushesBeforeTheRestart: every restart flushes first,
// and a sandbox that cannot be flushed refuses it: Apply leaves the
// previous configuration in place without restarting, and Restart and
// Rollback do not restart.
func TestGatewayConfigFlushesBeforeTheRestart(t *testing.T) {
	f := newGatewayFixture(t)
	running := openshell.DriverVM
	prefix := f.onHomebrew(t, homebrewTOML, &running)
	f.flush = fmt.Errorf("%w (dc-a: exec relay closed)", openshell.ErrUnflushed)
	_, err := f.apply(f.plan(t, microVMs))
	if !errors.Is(err, openshell.ErrUnflushed) || !strings.Contains(err.Error(), "previous configuration was restored") || f.brewRestarts() != 0 || f.flushes != 1 {
		t.Fatalf("Apply = %v (restarts %d, flushes %d)", err, f.brewRestarts(), f.flushes)
	}
	if got := readFile(t, filepath.Join(prefix, "gateway.toml")); got != homebrewTOML {
		t.Fatalf("gateway.toml not restored:\n%s", got)
	}
	if err := f.cfg.Restart(context.Background()); !errors.Is(err, openshell.ErrUnflushed) || f.brewRestarts() != 0 {
		t.Fatalf("Restart = %v (restarts %d)", err, f.brewRestarts())
	}

	f.flush = nil
	res, err := f.apply(f.plan(t, microVMs))
	if err != nil || f.brewRestarts() != 1 || f.flushes != 3 {
		t.Fatalf("Apply = %v (restarts %d, flushes %d)", err, f.brewRestarts(), f.flushes)
	}
	f.flush = fmt.Errorf("%w (dc-a: exec relay closed)", openshell.ErrUnflushed)
	if err := f.cfg.Rollback(context.Background(), res); !errors.Is(err, openshell.ErrUnflushed) || f.brewRestarts() != 1 {
		t.Fatalf("Rollback = %v (restarts %d)", err, f.brewRestarts())
	}
	if st, _ := f.cfg.Read(); st.ComputeDriver != openshell.DriverVM {
		t.Fatalf("a refused rollback changed the configuration: %+v", st)
	}
}
