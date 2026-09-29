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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

const enabledTOML = `[openshell]
version = 2

[openshell.drivers.docker]
allow_driver_config = true
enable_bind_mounts = true

[openshell.drivers.docker.resource_admission]
enabled = false
`

// disabledTOML is a gateway.toml without bind mounts.
const disabledTOML = "[openshell]\nversion = 2\n"

type doctorFixture struct {
	t        *testing.T
	dir      string
	regDir   string
	home     string
	runner   *openshelltest.Runner
	fake     *openshelltest.Fake
	doctor   *openshell.Doctor
	found    map[string]bool
	busy     map[string]bool
	started  time.Time
	verified int
	// diskFree answers DiskFree; diskProbed is the path it was asked about.
	diskFree   uint64
	diskErr    error
	diskProbed string
	// probe answers ProbeClientAuth; probes counts the calls.
	probe  error
	probes int
	// vmABI, vmKernel and vmErr answer VMLandlockABI (the Docker VM's
	// kernel, asked off Linux); vmProbes counts the calls.
	vmABI    int
	vmKernel string
	vmErr    error
	vmProbes int
	// brew is the Homebrew prefix of a Mac, e2fsprogs the directory the
	// MicroVM driver would find e2fsprogs in (empty until installed).
	brew, e2fsprogs string
	// restartedOn is the compute driver the gateway runs once a change
	// restarts it (empty: docker).
	restartedOn openshell.ComputeDriver
}

// unit renders the service as systemd reports it, started at f.started
// and reading f.dir's gateway.env.
func (f *doctorFixture) unit(active, fileState string) string {
	return systemdUnit(active, fileState, f.started, filepath.Join(f.dir, "gateway.env"))
}

func dockerInfoJSON(version, os string, extra map[string]any) string {
	m := map[string]any{"ServerVersion": version, "DockerRootDir": "/data/docker", "OperatingSystem": os,
		"SecurityOptions": []string{"name=apparmor", "name=seccomp,profile=builtin", "name=cgroupns"}}
	for k, v := range extra {
		m[k] = v
	}
	data, _ := json.Marshal(m)
	return string(data)
}

// newDoctorFixture describes a healthy Linux host: every check passes.
func newDoctorFixture(t *testing.T) *doctorFixture {
	t.Helper()
	skipOnWindows(t)
	f := &doctorFixture{
		t:        t,
		dir:      filepath.Join(t.TempDir(), "openshell"),
		home:     t.TempDir(),
		runner:   &openshelltest.Runner{},
		fake:     openshelltest.New(),
		found:    map[string]bool{"docker": true, "openshell": true},
		busy:     map[string]bool{},
		started:  time.Now().Add(-time.Hour).Truncate(time.Second),
		diskFree: 40 << 30,
		vmABI:    6,
		vmKernel: "6.12.65-linuxkit",
	}
	f.brew, f.e2fsprogs = filepath.Join(f.home, "homebrew"), filepath.Join(f.home, "homebrew", "opt", "e2fsprogs", "sbin")
	f.regDir = f.addRegistration("openshell", nil)
	f.writeTOML(enabledTOML, f.started.Add(-time.Minute))

	f.runner.On("docker info", dockerInfoJSON("29.4.0", "Ubuntu 24.04.4 LTS", nil), nil)
	f.runner.On("loginctl show-user dev", "yes\n", nil)
	f.runner.OnFunc("systemctl --user show openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) {
		return []byte(f.unit("active", "enabled")), nil
	})
	f.runner.On("systemctl --user show-environment", systemdManager(f.dir), nil)
	f.runner.On("/usr/bin/openshell --version", "openshell 0.1.1\n", nil)
	f.runner.On("systemctl --user restart openshell-gateway", "", nil)
	f.runner.On("systemctl --user enable --now openshell-gateway", "", nil)
	f.runner.On("openshell-gateway config preflight", "", nil)
	f.runner.On("/usr/bin/ssh -G sandbox", sshConfigSharing("false", ""), nil)
	f.runner.On(fakeShim.Path+" -G sandbox", sshConfigSharing("false", ""), nil)

	f.doctor = &openshell.Doctor{
		GOOS:     "linux",
		GOARCH:   "arm64",
		Runner:   f.runner,
		Discover: openshell.DiscoverOptions{ConfigDir: f.dir, SystemDir: filepath.Join(f.dir, "none")},
		LookPath: func(name string) (string, error) {
			if f.found[name] {
				return "/usr/bin/" + name, nil
			}
			return "", errors.New("not found")
		},
		Dial: func(*openshell.Registration) (openshell.Client, error) {
			return f.fake.Client(openshell.ClientOptions{}), nil
		},
		Gateway: &openshell.GatewayConfigurator{Dir: f.dir, GOOS: "linux", Runner: f.runner, BrewPrefix: f.brew,
			VerifyGateway:        func(context.Context) error { f.verified++; return nil },
			ProbeClientAuth:      func(context.Context, *openshell.Registration) error { f.probes++; return f.probe },
			BrewFormulaInstalled: func() bool { return true },
			RunningDriver: func(context.Context) (openshell.Driver, error) {
				d, _ := openshell.LookupDriver(string(f.restartedOn))
				return d, nil
			},
			FlushSandboxes: func(ctx context.Context) error {
				return openshell.FlushSandboxes(ctx, f.fake.Client(openshell.ClientOptions{}))
			}},
		Ports:               []openshell.PortRequirement{{Name: "ingress", Port: 18971}, {Name: "egress", Port: 18972}},
		LandlockABI:         func() (int, error) { return 6, nil },
		DockerVMLandlockABI: func(context.Context) (int, string, error) { f.vmProbes++; return f.vmABI, f.vmKernel, f.vmErr },
		E2fsprogsDirs:       []string{f.e2fsprogs},
		HostMemory:          func() uint64 { return 32 << 30 },
		DiskFree:            func(p string) (uint64, error) { f.diskProbed = p; return f.diskFree, f.diskErr },
		Listen:              f.listen,
		Geteuid:             func() int { return 1000 },
		Getegid:             func() int { return 1000 },
		Username:            func() (string, error) { return "dev", nil },
		HomeDir:             func() (string, error) { return f.home, nil },
		DockerDesktop:       func() (*openshell.DockerDesktop, error) { return nil, errors.New("not Docker Desktop") },
		DockerGroup:         func() (bool, bool, error) { return true, true, nil },
		SSHShim:             func() (*openshell.SSHShim, error) { return fakeShim, nil },
	}
	return f
}

// fakeShim stands for the ssh shim in doctor tests; Remove leaves it be.
var fakeShim = &openshell.SSHShim{Dir: "/shim", Path: "/shim/ssh", Real: "/usr/bin/ssh"}

// sshConfigSharing is `ssh -G sandbox` output with the given
// controlmaster and controlpath (none when empty).
func sshConfigSharing(master, path string) string {
	out := "user dev\nhostname sandbox\nport 22\ncontrolmaster " + master + "\n"
	if path != "" {
		out += "controlpath " + path + "\n"
	}
	return out + "controlpersist no\nproxycommand none\n"
}

// addRegistration writes a registration with the credential modes doctor
// accepts.
func (f *doctorFixture) addRegistration(name string, meta map[string]any) string {
	dir := writeRegistration(f.t, f.dir, name, meta, nil)
	for file, mode := range map[string]os.FileMode{"mtls": 0o700, "mtls/ca.crt": 0o644, "mtls/tls.crt": 0o644} {
		chmod(f.t, filepath.Join(dir, file), mode)
	}
	return dir
}

func (f *doctorFixture) listen(network, addr string) (net.Listener, error) {
	if f.busy[addr] {
		return nil, errors.New("bind: address already in use")
	}
	return net.Listen(network, "127.0.0.1:0")
}

func (f *doctorFixture) writeTOML(content string, mtime time.Time) {
	f.t.Helper()
	path := filepath.Join(f.dir, "gateway.toml")
	writeFile(f.t, path, content, 0o600)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		f.t.Fatal(err)
	}
}

// onBrew makes the host macOS with a running Homebrew service.
func (f *doctorFixture) onBrew() {
	f.doctor.GOOS, f.doctor.Gateway.GOOS = "darwin", "darwin"
	f.runner.On("brew services info nvidia/openshell/openshell --json", `[{"running":true,"loaded":true,"status":"started","file":"/x.plist"}]`, nil)
	f.runner.On("brew services restart nvidia/openshell/openshell", "", nil)
}

func (f *doctorFixture) run() *openshell.DoctorReport {
	f.t.Helper()
	return f.doctor.Run(context.Background())
}

func expectCheck(t *testing.T, r *openshell.DoctorReport, id string, status openshell.CheckStatus, detail string) *openshell.Check {
	t.Helper()
	c := r.Get(id)
	if c == nil {
		t.Fatalf("no %s check in:\n%s", id, r)
	}
	if c.Status != status || !strings.Contains(c.Detail, detail) {
		t.Fatalf("%s = %s %q, want %s containing %q\n%s", id, c.Status, c.Detail, status, detail, r)
	}
	return c
}

// applyFixes applies the automatic fixes of the given checks (all when
// none are named) and fails unless each one applied.
func applyFixes(t *testing.T, r *openshell.DoctorReport, ids ...string) {
	t.Helper()
	outcomes, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) {
		return len(ids) == 0 || slices.Contains(ids, c.ID), nil
	})
	if err != nil || len(outcomes) == 0 {
		t.Fatalf("ApplyFixes = %+v, %v", outcomes, err)
	}
	for _, o := range outcomes {
		if !o.Applied {
			t.Fatalf("fix not applied: %+v", o)
		}
	}
}

func expectMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != mode {
		t.Fatalf("%s: mode %v, %v; want %v", path, info.Mode().Perm(), err, mode)
	}
}

func TestDoctorHealthyHost(t *testing.T) {
	f := newDoctorFixture(t)
	r := f.run()
	var got []string
	for _, c := range r.Checks {
		got = append(got, c.ID)
		if c.Status != openshell.StatusPass && c.Status != openshell.StatusSkip {
			t.Errorf("%s = %s: %s", c.ID, c.Status, c.Detail)
		}
	}
	want := []string{"platform", "user", "landlock", "docker", "docker-host-network", "docker-file-sharing", "disk", "linger",
		"gateway-service", "openshell-cli", "ssh-connection-sharing", "gateway-registration", "mtls-permissions", "gateway-version", "gateway-driver",
		"global-policy", "bind-mounts", "telemetry", "port-ingress", "port-egress"}
	if !r.OK() || strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("checks = %v\nwant     %v\n%s", got, want, r)
	}
	expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusPass, "ABI 6")
	expectCheck(t, r, openshell.CheckIDSSHSharing, openshell.StatusPass,
		"off for the OpenShell sessions DefenseClaw runs (ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no); your ssh configuration shares none for host sandbox either")
	if f.vmProbes != 0 {
		t.Fatalf("a Linux host asked a Docker VM for Landlock %d times", f.vmProbes)
	}
	expectCheck(t, r, openshell.CheckIDDisk, openshell.StatusPass, "40.0 GiB free under /data/docker")
	if f.diskProbed != "/data/docker" || r.DockerVersion != "29.4.0" || r.CLIVersion != "0.1.1" || r.GatewayVersion != "0.1.1" || r.Registration.Name != "openshell" ||
		r.Service == nil || r.Service.Manager != "systemd" || !r.Service.Installed {
		t.Fatalf("facts = %+v (disk probed at %q)", r, f.diskProbed)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatalf("report does not marshal: %v", err)
	}
	f.runner.On("loginctl show-user dev", "no\n", nil)
	out := f.run().String()
	for _, want := range []string{"PASS  Platform", "WARN  systemd linger", "fix linger:", "sudo loginctl enable-linger dev"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}

func TestDoctorPlatforms(t *testing.T) {
	for _, tc := range []struct {
		goos, goarch string
		status       openshell.CheckStatus
		early        bool
	}{
		{"windows", "amd64", openshell.StatusFail, true},
		{"freebsd", "amd64", openshell.StatusFail, true},
		{"linux", "386", openshell.StatusFail, false},
		{"darwin", "amd64", openshell.StatusFail, false},
		{"darwin", "arm64", openshell.StatusWarn, false},
	} {
		t.Run(tc.goos+"/"+tc.goarch, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.doctor.GOOS, f.doctor.GOARCH, f.doctor.Gateway.GOOS = tc.goos, tc.goarch, tc.goos
			r := f.run()
			expectCheck(t, r, openshell.CheckIDPlatform, tc.status, tc.goos)
			if tc.early != (len(r.Checks) == 1) {
				t.Fatalf("early return = %v, checks %d", len(r.Checks) == 1, len(r.Checks))
			}
		})
	}
}

type checkWant struct {
	id     string
	status openshell.CheckStatus
	detail string
}

// fixWant describes the fix of a case's first check.
type fixWant struct {
	command string // the exact command, when set
	text    string // in the summary or the command, when set
	auto    bool   // an automatic fix
	manual  bool   // the operator must act: no Apply
	sudo    bool
}

// TestDoctorChecks runs each check against one broken host fact and, where
// the case says so, applies the fix it offers.
func TestDoctorChecks(t *testing.T) {
	const (
		pass, warn, fail, skip = openshell.StatusPass, openshell.StatusWarn, openshell.StatusFail, openshell.StatusSkip
		restart                = "systemctl --user restart openshell-gateway"
		start                  = "systemctl --user enable --now openshell-gateway"
		install                = "defenseclaw sandbox setup --install-openshell"
	)
	docker := func(out string, err error) func(*doctorFixture) {
		return func(f *doctorFixture) { f.runner.On("docker info", out, err) }
	}
	desktop := func(hostNetworking bool, shared func(f *doctorFixture) []string) func(*doctorFixture) {
		return func(f *doctorFixture) {
			f.runner.On("docker info", dockerInfoJSON("28.3.2", "Docker Desktop", nil), nil)
			f.doctor.DockerDesktop = func() (*openshell.DockerDesktop, error) {
				return &openshell.DockerDesktop{HostNetworking: &hostNetworking, FileSharing: shared(f)}, nil
			}
		}
	}
	service := func(show string, err error) func(*doctorFixture) {
		return func(f *doctorFixture) { f.runner.On("systemctl --user show openshell-gateway", show, err) }
	}
	unit := func(active, fileState string) func(*doctorFixture) {
		return func(f *doctorFixture) {
			f.runner.On("systemctl --user show openshell-gateway", f.unit(active, fileState), nil)
		}
	}
	cliVersion := func(out string) func(*doctorFixture) {
		return func(f *doctorFixture) { f.runner.On("/usr/bin/openshell --version", out, nil) }
	}
	health := func(err error) func(*doctorFixture) {
		return func(f *doctorFixture) { f.fake.FailNext(openshelltest.MethodHealth, err) }
	}
	landlock := func(abi int, err error) func(*doctorFixture) {
		return func(f *doctorFixture) { f.doctor.LandlockABI = func() (int, error) { return abi, err } }
	}
	disk := func(free uint64, err error) func(*doctorFixture) {
		return func(f *doctorFixture) { f.diskFree, f.diskErr = free, err }
	}
	mode := func(path func(f *doctorFixture) string, m os.FileMode) func(*doctorFixture) {
		return func(f *doctorFixture) { chmod(f.t, path(f), m) }
	}
	key := func(f *doctorFixture) string { return filepath.Join(f.regDir, "mtls", "tls.key") }
	metadata := func(f *doctorFixture) string { return filepath.Join(f.regDir, "metadata.json") }
	gatewayEnv := func(content string) func(*doctorFixture) {
		return func(f *doctorFixture) { writeFile(f.t, filepath.Join(f.dir, "gateway.env"), content, 0o600) }
	}
	probe := func(err error) func(*doctorFixture) {
		return func(f *doctorFixture) { f.probe = err }
	}
	noMounts := func(then func(*doctorFixture)) func(*doctorFixture) {
		return func(f *doctorFixture) {
			f.writeTOML(disabledTOML, f.started.Add(-time.Minute))
			if then != nil {
				then(f)
			}
		}
	}
	credsRefused := "openshell gateway remove openshell && openshell gateway add 'https://127.0.0.1:17670' --local --name openshell"
	exposed := "others can reach the gateway and mount any host path"
	noCertNeeded := fmt.Errorf("%w: accepted a TLS session", openshell.ErrGatewayExposed)

	cases := []struct {
		name  string
		setup func(f *doctorFixture)
		want  []checkWant
		fix   *fixWant
		// then runs after the checks, for fixes and other effects.
		then func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport)
	}{
		{name: "root user", setup: func(f *doctorFixture) { f.doctor.Geteuid = func() int { return 0 } },
			want: []checkWant{{"user", fail, "running as root"}}},
		{name: "daemon runs as another user", setup: func(f *doctorFixture) { uid := 998; f.doctor.DaemonUID = &uid },
			want: []checkWant{{"user", fail, "daemon runs as uid 998"}}},
		{name: "landlock ABI too old", setup: landlock(2, nil),
			want: []checkWant{{"landlock", fail, "ABI 2; OpenShell needs ABI 3"}}, fix: &fixWant{sudo: true, manual: true}},
		{name: "landlock disabled", setup: landlock(0, openshell.ErrLandlockDisabled),
			want: []checkWant{{"landlock", fail, "not enabled"}}, fix: &fixWant{sudo: true, manual: true}},
		{name: "landlock missing", setup: landlock(0, openshell.ErrLandlockMissing),
			want: []checkWant{{"landlock", fail, "no Landlock support"}}, fix: &fixWant{sudo: true, manual: true}},

		{name: "docker not installed", setup: func(f *doctorFixture) { f.found["docker"] = false },
			want: []checkWant{{"docker", fail, "not installed"}, {"docker-host-network", skip, ""}, {"docker-file-sharing", skip, ""}, {"disk", skip, ""}},
			fix:  &fixWant{text: "install Docker Engine 28"}},
		{name: "docker permission denied, not in the group", setup: func(f *doctorFixture) {
			docker("permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock", errors.New("exit status 1"))(f)
			f.doctor.DockerGroup = func() (bool, bool, error) { return false, false, nil }
		}, want: []checkWant{{"docker", fail, "permission denied"}}, fix: &fixWant{text: "sudo usermod -aG docker dev"}},
		{name: "docker permission denied, stale session", setup: func(f *doctorFixture) {
			docker(`{"ServerErrors":["permission denied while trying to connect to the Docker daemon socket"]}`, errors.New("exit status 1"))(f)
			f.doctor.DockerGroup = func() (bool, bool, error) { return true, false, nil }
		}, want: []checkWant{{"docker", fail, "permission denied"}}, fix: &fixWant{text: "newgrp docker"}},
		{name: "docker daemon down", setup: docker("Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", errors.New("exit status 1")),
			want: []checkWant{{"docker", fail, "Is the docker daemon running"}}, fix: &fixWant{text: "sudo systemctl enable --now docker"}},
		{name: "docker too old", setup: docker(dockerInfoJSON("27.5.1", "Ubuntu", nil), nil), want: []checkWant{{"docker", fail, "older than 28"}}},
		{name: "docker rootless", setup: docker(dockerInfoJSON("29.4.0", "Ubuntu", map[string]any{"SecurityOptions": []string{"name=seccomp,profile=builtin", "name=rootless"}}), nil),
			want: []checkWant{{"docker", fail, "rootless"}}},
		{name: "docker desktop with host networking and sharing", setup: desktop(true, func(f *doctorFixture) []string { return []string{filepath.Dir(f.home)} }),
			want: []checkWant{{"docker", pass, "Docker Desktop"}, {"docker-host-network", pass, "enabled"}, {"docker-file-sharing", pass, "is shared"}, {"disk", skip, "VM"}}},
		{name: "docker desktop without host networking or sharing", setup: desktop(false, func(*doctorFixture) []string { return []string{"/Volumes"} }),
			want: []checkWant{{"docker-host-network", fail, "host networking is off"}, {"docker-file-sharing", fail, "not shared"}}},
		{name: "docker desktop settings store on disk", setup: func(f *doctorFixture) {
			docker(dockerInfoJSON("28.3.2", "Docker Desktop", nil), nil)(f)
			f.doctor.DockerDesktop = nil
			store := filepath.Join(f.home, ".docker", "desktop", "settings-store.json")
			if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
				f.t.Fatal(err)
			}
			writeFile(f.t, store, fmt.Sprintf(`{"HostNetworkingEnabled": false, "filesharingDirectories": [%q]}`, f.home), 0o600)
		}, want: []checkWant{{"docker-host-network", fail, "host networking is off"}, {"docker-file-sharing", pass, "is shared"}}},
		{name: "docker desktop settings unreadable", setup: docker(dockerInfoJSON("28.3.2", "Docker Desktop", nil), nil),
			want: []checkWant{{"docker-host-network", warn, "could not read"}, {"docker-file-sharing", warn, "could not read"}}},

		// Low space names DefenseClaw's own prune, and warns about the
		// machine-wide one instead of suggesting it.
		{name: "disk too full", setup: disk(3<<30, nil), want: []checkWant{{"disk", fail, "at least 5.0 GiB"}},
			fix: &fixWant{command: "defenseclaw sandbox image prune", text: "rather than `docker system prune`, which also removes"}},
		{name: "disk low", setup: disk(7<<30, nil), want: []checkWant{{"disk", warn, "10.0 GiB or more"}},
			fix: &fixWant{command: "defenseclaw sandbox image prune", text: "rather than `docker system prune`, which also removes"}},
		{name: "disk unmeasured", setup: disk(0, errors.New("no such file")), want: []checkWant{{"disk", warn, "could not measure"}}},

		{name: "linger off", setup: func(f *doctorFixture) { f.runner.On("loginctl show-user dev", "no\n", nil) },
			want: []checkWant{{"linger", warn, "stop when you log out"}}, fix: &fixWant{command: "sudo loginctl enable-linger dev", sudo: true}},
		{name: "service failed", setup: service("LoadState=loaded\nActiveState=failed\nSubState=failed\nUnitFileState=enabled\n", nil),
			want: []checkWant{{"gateway-service", fail, "failed (failed)"}}, fix: &fixWant{auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDGatewayService)
				if !f.runner.Called(start) || f.verified != 1 {
					t.Fatalf("fix did not start and verify the gateway (verified %d)", f.verified)
				}
			}},
		{name: "service not installed", setup: service("LoadState=not-found\nActiveState=inactive\nSubState=dead\n", nil),
			want: []checkWant{{"gateway-service", fail, "not installed"}}, fix: &fixWant{command: install}},
		{name: "service not enabled", setup: service("LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=disabled\n", nil),
			want: []checkWant{{"gateway-service", warn, "does not start at login"}}},
		// `systemctl --user link` without enable: nothing starts it at login.
		{name: "service only linked", setup: unit("active", "linked"),
			want: []checkWant{{"gateway-service", warn, "does not start at login"}}, fix: &fixWant{command: start, auto: true}},
		{name: "no user bus", setup: service("Failed to connect to bus: No medium found", errors.New("exit status 1")),
			want: []checkWant{{"gateway-service", fail, "Failed to connect to bus"}}},
		{name: "macOS skips Linux-only checks", setup: func(f *doctorFixture) { f.onBrew() },
			want: []checkWant{{"landlock", pass, "ABI 6 in the Linux VM Docker runs in"}, {"linger", skip, ""},
				{"gateway-service", pass, "nvidia/openshell/openshell"},
				// The Homebrew service's wrapper sources gateway.env too (M8).
				{"telemetry", skip, "DefenseClaw changes it on Linux only; the Homebrew service reads OPENSHELL_TELEMETRY_ENABLED from /"}}},
		// No formula and no gateway answering (one that answers is
		// TestDoctorOnReleaseBinaries').
		{name: "macOS without OpenShell", setup: func(f *doctorFixture) {
			f.onBrew()
			f.doctor.Gateway.BrewFormulaInstalled = func() bool { return false }
			f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
		}, want: []checkWant{{"gateway-service", fail, "nvidia/openshell/openshell is not installed"}}, fix: &fixWant{command: install}},

		{name: "cli missing", setup: func(f *doctorFixture) { f.found["openshell"] = false }, want: []checkWant{{"openshell-cli", fail, "not on PATH"}}},
		{name: "cli 0.0.x", setup: cliVersion("openshell 0.0.16\n"), want: []checkWant{{"openshell-cli", fail, "predates 0.0.37"}}},
		{name: "cli 0.0.x that upgrades in place", setup: cliVersion("openshell 0.0.40\n"),
			want: []checkWant{{"openshell-cli", fail, "upgrade it in place"}}, fix: &fixWant{command: install}},
		{name: "cli and gateway differ", setup: func(f *doctorFixture) { f.fake.SetHealth(true, "0.1.2") },
			want: []checkWant{{"gateway-version", warn, "gateway 0.1.2 but CLI 0.1.1"}}},
		{name: "gateway outside the window", setup: func(f *doctorFixture) { f.fake.SetHealth(true, "0.2.0") },
			want: []checkWant{{"gateway-version", fail, "not supported"}}},
		{name: "gateway unhealthy", setup: func(f *doctorFixture) { f.fake.SetHealth(false, "0.1.1") },
			want: []checkWant{{"gateway-version", fail, "unhealthy"}, {"gateway-driver", skip, ""}, {"global-policy", skip, ""}}},
		{name: "gateway unreachable", setup: health(errors.New("connection refused")),
			want: []checkWant{{"gateway-version", fail, "connection refused"}}},
		// A running gateway that does not answer is restarted, since
		// starting it again does nothing; a stopped one is started.
		{name: "gateway running but hung", setup: health(&types.StatusError{Code: types.ErrorDeadlineExceeded, Message: "context deadline exceeded"}),
			want: []checkWant{{"gateway-version", fail, "not answering"}}, fix: &fixWant{command: restart, auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDGatewayVersion)
				if !f.runner.Called(restart) || f.runner.Called("systemctl --user enable") || f.verified != 1 {
					t.Fatalf("fix did not restart and verify the gateway (verified %d): %v", f.verified, f.runner.Calls())
				}
			}},
		{name: "gateway stopped", setup: func(f *doctorFixture) { unit("inactive", "enabled")(f); f.fake.SetHealth(false, "0.1.1") },
			want: []checkWant{{"gateway-version", fail, "unhealthy"}}, fix: &fixWant{command: start, auto: true}},
		// A gateway that refuses DefenseClaw's credentials is registered
		// again instead.
		{name: "credentials refused", setup: health(&types.StatusError{Code: types.ErrorUnauthenticated, Message: "client certificate not trusted"}),
			want: []checkWant{{"gateway-version", fail, "refused DefenseClaw's TLS credentials"}}, fix: &fixWant{command: credsRefused, manual: true}},
		{name: "certificate from an unknown authority", setup: health(&types.StatusError{Code: types.ErrorUnavailable,
			Message: `connection error: desc = "transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority"`}),
			want: []checkWant{{"gateway-version", fail, "refused DefenseClaw's TLS credentials"}}, fix: &fixWant{command: credsRefused, manual: true}},
		{name: "wrong compute driver", setup: func(f *doctorFixture) {
			f.fake = openshelltest.New(openshelltest.WithGatewayInfo(types.GatewayInfo{Version: "0.1.1",
				ComputeDrivers: []types.ComputeDriverInfo{{Name: "podman", DriverName: "podman"}}}))
		}, want: []checkWant{{"gateway-driver", fail, `this gateway runs "podman"`}}},
		{name: "global policy", setup: func(f *doctorFixture) { f.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1}) },
			want: []checkWant{{"global-policy", warn, "approvals are disabled"}}},

		{name: "no registration", setup: func(f *doctorFixture) {
			if err := os.RemoveAll(filepath.Join(f.dir, "gateways")); err != nil {
				f.t.Fatal(err)
			}
		}, want: []checkWant{{"gateway-registration", fail, "no gateway registration"}, {"mtls-permissions", skip, ""}, {"gateway-version", skip, ""}}},
		{name: "remote gateway", setup: func(f *doctorFixture) {
			writeRegistration(f.t, f.dir, "openshell", map[string]any{"gateway_endpoint": "https://gw.example.com:443", "auth_mode": "mtls", "is_remote": true}, nil)
		}, want: []checkWant{{"gateway-registration", fail, "remote gateways are not supported"}}},
		{name: "readable key is fixed", setup: mode(key, 0o644),
			want: []checkWant{{"mtls-permissions", fail, "private key is accessible to other users"}, {"gateway-version", skip, ""}},
			fix:  &fixWant{text: "chmod 600 ", auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r)
				expectMode(t, key(f), 0o600)
				if again := f.run(); !again.OK() {
					t.Fatalf("still failing after the fix:\n%s", again)
				}
			}},
		{name: "bind mounts already on a plaintext gateway", setup: func(f *doctorFixture) {
			writeRegistration(f.t, f.dir, "openshell", map[string]any{"gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "none"}, nil)
		}, want: []checkWant{{"bind-mounts", fail, "any local user can mount host paths"}}},
		{name: "stock registration files inside private directories", setup: func(f *doctorFixture) {
			writeFile(f.t, filepath.Join(f.dir, "active_gateway"), "openshell\n", 0o664)
		}, want: []checkWant{{"gateway-registration", pass, "openshell at"}}},
		{name: "group-writable registration is fixed", setup: func(f *doctorFixture) {
			chmod(f.t, metadata(f), 0o664)
			for _, d := range []string{f.dir, filepath.Join(f.dir, "gateways"), f.regDir} {
				chmod(f.t, d, 0o750)
			}
		}, want: []checkWant{{"gateway-registration", warn, "metadata.json is group-writable"}, {"mtls-permissions", pass, "owner-only"}},
			fix: &fixWant{text: "chmod go-w ", auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDRegistration)
				expectMode(t, metadata(f), 0o644)
				// The first run closed the fake gateway client; only the
				// registration matters here.
				if again := f.run(); again.Get(openshell.CheckIDRegistration).Status != pass {
					t.Fatalf("still warning after the fix:\n%s", again)
				}
			}},
		{name: "world-writable registration is fixed", setup: mode(func(f *doctorFixture) string { return f.regDir }, 0o777),
			want: []checkWant{{"gateway-registration", fail, "is writable by every user"}, {"mtls-permissions", skip, ""}, {"gateway-version", skip, ""}, {"bind-mounts", pass, ""}},
			fix:  &fixWant{auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r)
				expectMode(t, f.regDir, 0o755)
				if again := f.run(); !again.OK() {
					t.Fatalf("still failing after the fix:\n%s", again)
				}
			}},
		{name: "group-writable certificates are fixed", setup: mode(func(f *doctorFixture) string { return filepath.Join(f.regDir, "mtls", "ca.crt") }, 0o664),
			want: []checkWant{{"mtls-permissions", warn, "group-writable"}},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDMTLS)
				expectMode(t, filepath.Join(f.regDir, "mtls", "ca.crt"), 0o644)
			}},

		{name: "bind mounts disabled are fixable", setup: noMounts(nil),
			want: []checkWant{{"bind-mounts", fail, "only --copy sandboxes work"}}, fix: &fixWant{auto: true},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDBindMounts)
				if st, _ := f.doctor.Gateway.Read(); !st.BindMounts.Enabled() || !f.runner.Called(restart) {
					t.Fatalf("fix did not enable mounts and restart: %+v", st.BindMounts)
				}
			}},
		{name: "copy-only mode", setup: noMounts(func(f *doctorFixture) { f.doctor.BindMountsOptional = true }),
			want: []checkWant{{"bind-mounts", warn, "disabled"}}},
		{name: "restart pending", setup: func(f *doctorFixture) { f.writeTOML(enabledTOML, f.started.Add(time.Minute)) },
			want: []checkWant{{"bind-mounts", warn, "has not been restarted"}}, fix: &fixWant{command: restart, auto: true}},
		{name: "telemetry differs from config", setup: func(f *doctorFixture) { off := false; f.doctor.WantTelemetry = &off },
			want: []checkWant{{"telemetry", warn, "telemetry is on but openshell.upstream_telemetry is false"}},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				applyFixes(t, r, openshell.CheckIDTelemetry)
				if st, _ := f.doctor.Gateway.Read(); st.TelemetryEnabled() {
					t.Fatal("telemetry still on after the fix")
				}
			}},
		// Doctor, and its bind-mount fix, follow a config directory a
		// dotfile manager links elsewhere, with active_gateway choosing
		// between two registrations.
		{name: "symlinked config directory", setup: noMounts(func(f *doctorFixture) {
			f.addRegistration("dev", nil)
			writeFile(f.t, filepath.Join(f.dir, "active_gateway"), "dev\n", 0o644)
			link := filepath.Join(f.t.TempDir(), "openshell")
			if err := os.Symlink(f.dir, link); err != nil {
				f.t.Fatal(err)
			}
			f.doctor.Discover.ConfigDir, f.doctor.Gateway.Dir = link, link
		}), want: []checkWant{{"bind-mounts", fail, "only --copy sandboxes work"}},
			then: func(t *testing.T, f *doctorFixture, r *openshell.DoctorReport) {
				if r.Registration == nil || r.Registration.Name != "dev" {
					t.Fatalf("registration = %+v", r.Registration)
				}
				applyFixes(t, r, openshell.CheckIDBindMounts)
				if st, err := f.doctor.Gateway.Read(); err != nil || !st.BindMounts.Enabled() {
					t.Fatalf("state = %+v, %v", st, err)
				}
			}},

		// Bind mounts are judged by the gateway the service runs, not only
		// by the CLI's registration files.
		{name: "enabled: TLS disabled in gateway.env", setup: gatewayEnv("OPENSHELL_DISABLE_TLS=true\n"),
			want: []checkWant{{"bind-mounts", fail, exposed}}, fix: &fixWant{manual: true}},
		{name: "enabled: mTLS auth off", setup: gatewayEnv("OPENSHELL_ENABLE_MTLS_AUTH=false\nOPENSHELL_BIND_ADDRESS=0.0.0.0\n"),
			want: []checkWant{{"bind-mounts", fail, exposed}}, fix: &fixWant{manual: true}},
		{name: "enabled: probe gets in without a certificate", setup: probe(noCertNeeded),
			want: []checkWant{{"bind-mounts", fail, exposed}}, fix: &fixWant{manual: true}},
		{name: "disabled: TLS disabled in gateway.env", setup: noMounts(gatewayEnv("OPENSHELL_DISABLE_TLS=true\n")),
			want: []checkWant{{"bind-mounts", fail, "disabled"}}, fix: &fixWant{manual: true, text: "reachable by you alone"}},
		{name: "disabled: mTLS auth off", setup: noMounts(gatewayEnv("OPENSHELL_ENABLE_MTLS_AUTH=false\n")),
			want: []checkWant{{"bind-mounts", fail, "disabled"}}, fix: &fixWant{manual: true, text: "reachable by you alone"}},
		{name: "disabled: probe gets in without a certificate", setup: noMounts(probe(noCertNeeded)),
			want: []checkWant{{"bind-mounts", fail, "disabled"}}, fix: &fixWant{manual: true, text: "reachable by you alone"}},
		{name: "registration reaches another gateway", setup: func(f *doctorFixture) {
			f.addRegistration("dev", map[string]any{"gateway_endpoint": "https://127.0.0.1:18080", "auth_mode": "mtls"})
			writeFile(f.t, filepath.Join(f.dir, "active_gateway"), "dev\n", 0o600)
		}, want: []checkWant{{"bind-mounts", fail, "reaches https://127.0.0.1:18080, but the openshell-gateway service listens on port 17670"}}},
		{name: "service reads another configuration", setup: func(f *doctorFixture) { f.runner.On("systemctl --user show-environment", "HOME=/home/dev\n", nil) },
			want: []checkWant{{"bind-mounts", fail, "home/dev/.config/openshell/gateway.toml, not"}, {"telemetry", warn, "does not match"}}},
		{name: "probe inconclusive", setup: probe(errors.New("could not confirm that the gateway requires a client certificate: i/o timeout")),
			want: []checkWant{{"bind-mounts", warn, "could not confirm"}}},
		{name: "gateway not answering is not probed", setup: health(errors.New("connection refused")),
			want: []checkWant{{"bind-mounts", pass, "enabled"}},
			then: func(t *testing.T, f *doctorFixture, _ *openshell.DoctorReport) {
				if f.probes != 0 {
					t.Fatalf("probed a gateway that is not answering %d times", f.probes)
				}
			}},

		{name: "ports", setup: func(f *doctorFixture) {
			f.busy["127.0.0.1:18971"], f.busy["127.0.0.1:18972"] = true, true
			f.doctor.Ports = []openshell.PortRequirement{{Name: "ingress", Port: 18971}, {Name: "egress", Port: 18972, ServedByDaemon: true},
				{Name: "extra", Port: 17670}, {Name: "bad", Port: 0}}
		}, want: []checkWant{{"port-ingress", fail, "in use by another process"}, {"port-egress", pass, "served by the DefenseClaw daemon"},
			{"port-extra", fail, "OpenShell gateway's port"}, {"port-bad", fail, "invalid port"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			tc.setup(f)
			r := f.run()
			var first *openshell.Check
			for i, w := range tc.want {
				if c := expectCheck(t, r, w.id, w.status, w.detail); i == 0 {
					first = c
				}
			}
			if w := tc.fix; w != nil {
				c := first.Fix
				if c == nil || (w.command != "" && c.Command != w.command) || !strings.Contains(c.Summary+" "+c.Command, w.text) ||
					(w.auto && (!c.Automatic || c.Apply == nil)) || (w.manual && (c.Automatic || c.Apply != nil)) || (w.sudo && !c.Sudo) {
					t.Fatalf("%s fix = %+v, want %+v", first.ID, c, *w)
				}
			}
			if tc.then != nil {
				tc.then(t, f, r)
			}
		})
	}
}

// TestDoctorChecksLandlockInTheDockerVM: on macOS sandboxes run on the
// kernel of Docker Desktop's Linux VM, which doctor said enforced Landlock
// without asking it; Docker Desktop 29.1.5's runs only capability and bpf,
// so no sandbox could start (manual test M12). Doctor asks that kernel,
// fails with the way on when it has no Landlock, and says the check did
// not run, with how to run it, when no image to ask in is local.
func TestDoctorChecksLandlockInTheDockerVM(t *testing.T) {
	const (
		pass, warn, fail, skip = openshell.StatusPass, openshell.StatusWarn, openshell.StatusFail, openshell.StatusSkip
		vm                     = "Docker Desktop's Linux VM (kernel 6.12.65-linuxkit)"
		today                  = "macOS sandboxes cannot run on Docker Desktop's kernel: run them in OpenShell MicroVMs"
	)
	for _, tc := range []struct {
		name   string
		abi    int
		err    error
		status openshell.CheckStatus
		detail string
		fix    string
	}{
		{name: "no Landlock", err: openshell.ErrLandlockMissing, status: fail, detail: vm + " has no Landlock, and OpenShell sandboxes need it", fix: today},
		{name: "Landlock off", err: openshell.ErrLandlockDisabled, status: fail, detail: vm + " has Landlock turned off, and OpenShell sandboxes need it", fix: today},
		{name: "ABI too old", abi: 2, status: fail, detail: vm + " has Landlock ABI 2; OpenShell needs ABI 3 or newer", fix: today},
		{name: "Landlock", abi: 6, status: pass, detail: "ABI 6 in Docker Desktop's Linux VM"},
		{name: "no image to check in", err: openshell.ErrNoProbeImage, status: warn,
			detail: "not checked: sandboxes run on the kernel of Docker Desktop's Linux VM, which DefenseClaw checks in the OpenShell base image, and that image is not on this machine yet",
			fix:    "download the OpenShell base image"},
		{name: "probe failed", err: errors.New("the probe container failed"), status: warn, detail: "could not check " + vm + ": the probe container failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.onBrew()
			f.runner.On("docker info", dockerInfoJSON("29.1.5", "Docker Desktop", nil), nil)
			f.vmABI, f.vmErr = tc.abi, tc.err
			r := f.run()
			c := expectCheck(t, r, openshell.CheckIDLandlock, tc.status, tc.detail)
			if c.Detail != tc.detail {
				t.Fatalf("detail = %q, want %q", c.Detail, tc.detail)
			}
			// The check keeps its place, before Docker's, though it runs after.
			if r.Checks[2].ID != openshell.CheckIDLandlock || r.Checks[3].ID != openshell.CheckIDDocker {
				t.Fatalf("checks out of order:\n%s", r)
			}
			switch {
			case tc.fix == "" && c.Fix != nil:
				t.Fatalf("fix = %+v, want none", c.Fix)
			case tc.fix != "" && (c.Fix == nil || !strings.Contains(c.Fix.Summary, tc.fix)):
				t.Fatalf("fix = %+v, want one saying %q", c.Fix, tc.fix)
			case tc.status == fail && (c.Fix.Command != openshell.TroubleshootingURL || c.Fix.Apply != nil):
				t.Fatalf("fix = %+v, want the guide and nothing to apply", c.Fix)
			}
		})
	}

	t.Run("pulls the base image only when asked", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.onBrew()
		f.vmErr = openshell.ErrNoProbeImage
		pull := "docker pull " + openshell.DefaultBaseImage
		f.runner.On(pull, "", nil)
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDLandlock, warn, "not checked")
		if f.runner.Called("docker pull") {
			t.Fatal("doctor pulled an image by itself")
		}
		if c.Fix.Command != pull || !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
		applyFixes(t, r, openshell.CheckIDLandlock)
		if !f.runner.Called(pull) {
			t.Fatalf("the fix did not pull the base image: %v", f.runner.Calls())
		}
	})

	t.Run("not asked without Docker", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.onBrew()
		f.found["docker"] = false
		expectCheck(t, f.run(), openshell.CheckIDLandlock, skip, "the Docker daemon is not available")
		if f.vmProbes != 0 {
			t.Fatalf("asked the Docker VM %d times without Docker", f.vmProbes)
		}
	})
}

// TestDoctorAsksTheDockerVMKernel runs the real probe against scripted
// docker commands: it runs in the first local image, never pulls one, and
// reads the kernel's answer.
func TestDoctorAsksTheDockerVMKernel(t *testing.T) {
	const overlay = "defenseclaw/sandbox:claudecode-1a2b"
	run := "docker run --rm --pull never --network none --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges --read-only " +
		"--entrypoint /usr/bin/python3 " + overlay + " -I -S -c"
	for _, tc := range []struct {
		name, out string
		err       error
		status    openshell.CheckStatus
		detail    string
	}{
		{name: "ENOSYS", out: "kernel 6.12.65-linuxkit\nerrno 38 ENOSYS\n", status: openshell.StatusFail, detail: "(kernel 6.12.65-linuxkit) has no Landlock"},
		{name: "EOPNOTSUPP", out: "kernel 6.12.65-linuxkit\nerrno 95 EOPNOTSUPP\n", status: openshell.StatusFail, detail: "has Landlock turned off"},
		{name: "ABI", out: "kernel 6.12.65-linuxkit\nlandlock 6\n", status: openshell.StatusPass, detail: "ABI 6 in"},
		// A seccomp profile refusing the call says nothing about the kernel.
		{name: "EPERM", out: "kernel 6.12.65-linuxkit\nerrno 1 EPERM\n", status: openshell.StatusWarn, detail: "failed with errno 1 EPERM"},
		{name: "no python", out: "exec: \"/usr/bin/python3\": no such file", err: errors.New("exit status 127"), status: openshell.StatusWarn,
			detail: "the probe container failed: exit status 127: exec: \"/usr/bin/python3\": no such file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.onBrew()
			f.doctor.DockerVMLandlockABI = nil
			f.doctor.ProbeImages = []string{"", overlay}
			f.runner.On("docker image inspect --format {{.Id}} "+overlay, "sha256:1a2b\n", nil)
			f.runner.On(run, tc.out, tc.err)
			expectCheck(t, f.run(), openshell.CheckIDLandlock, tc.status, tc.detail)
			if !f.runner.Called("docker image inspect --format {{.Id}} "+openshell.DefaultBaseImage) || !f.runner.Called(run) {
				t.Fatalf("calls = %v", f.runner.Calls())
			}
		})
	}
	t.Run("no local image", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.onBrew()
		f.doctor.DockerVMLandlockABI = nil
		f.doctor.ProbeImages = []string{overlay}
		expectCheck(t, f.run(), openshell.CheckIDLandlock, openshell.StatusWarn, "not checked")
		if f.runner.Called("docker run") || f.runner.Called("docker pull") {
			t.Fatalf("ran or pulled an image: %v", f.runner.Calls())
		}
	})
}

// TestDoctorPlaintextGateway covers a registration that lets any local
// user in: doctor never dials it, and never offers to enable bind mounts
// on it.
func TestDoctorPlaintextGateway(t *testing.T) {
	f := newDoctorFixture(t)
	writeRegistration(t, f.dir, "openshell", map[string]any{"gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "plaintext"}, nil)
	f.writeTOML(disabledTOML, f.started.Add(-time.Minute))
	dialed := false
	f.doctor.Dial = func(*openshell.Registration) (openshell.Client, error) {
		dialed = true
		return f.fake.Client(openshell.ClientOptions{}), nil
	}
	r := f.run()
	if c := expectCheck(t, r, openshell.CheckIDRegistration, openshell.StatusFail, "accepts unauthenticated calls"); c.Fix == nil || c.Fix.Automatic || !strings.Contains(c.Fix.Summary, "mTLS") {
		t.Fatalf("registration fix = %+v", c.Fix)
	}
	expectCheck(t, r, openshell.CheckIDMTLS, openshell.StatusSkip, "")
	expectCheck(t, r, openshell.CheckIDGatewayVersion, openshell.StatusSkip, "")
	if mounts := expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusFail, "disabled"); mounts.Fix == nil || mounts.Fix.Automatic || mounts.Fix.Apply != nil {
		t.Fatalf("bind mounts offered an automatic fix on a plaintext gateway: %+v", mounts.Fix)
	}
	if dialed {
		t.Fatal("doctor dialed a plaintext gateway")
	}
}

func TestDoctorPendingRestart(t *testing.T) {
	t.Run("written earlier in the second the gateway started", func(t *testing.T) {
		// systemd reports the start to the microsecond, so a file written
		// 600ms before the start is not mistaken for a later change.
		f := newDoctorFixture(t)
		second := f.started
		f.started = second.Add(900 * time.Millisecond)
		f.writeTOML(enabledTOML, second.Add(300*time.Millisecond))
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusPass, "enabled")
		f.writeTOML(enabledTOML, second.Add(950*time.Millisecond))
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusWarn, "has not been restarted")
	})
	t.Run("pending restart mark", func(t *testing.T) {
		mark := func(f *doctorFixture, at time.Time) {
			path := filepath.Join(f.dir, ".defenseclaw-restart-pending")
			writeFile(t, path, at.UTC().Format(time.RFC3339Nano)+"\n", 0o600)
			if err := os.Chtimes(path, at, at); err != nil {
				t.Fatal(err)
			}
		}
		// Homebrew reports no start time; the mark DefenseClaw left
		// before a restart of its own that never happened still shows, as
		// a reminder: the gateway may have been restarted by hand since
		// (manual test M11).
		f := newDoctorFixture(t)
		f.onBrew()
		mark(f, f.started.Add(-time.Minute))
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusWarn,
			"/openshell/gateway.toml; restart the gateway if you have not since gateway.toml changed")
		if strings.Contains(c.Detail, "has not been restarted") || c.Fix.Command != "brew services restart nvidia/openshell/openshell" {
			t.Fatalf("check = %+v, fix %+v", c, c.Fix)
		}
		applyFixes(t, r, openshell.CheckIDBindMounts)
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusPass, "enabled")

		// On systemd a mark from before the last start is stale.
		f = newDoctorFixture(t)
		mark(f, f.started.Add(-time.Second))
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusPass, "enabled")
		mark(f, f.started.Add(time.Second))
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusWarn, "has not been restarted")
	})
}

func TestDoctorApplyFixesConsent(t *testing.T) {
	f := newDoctorFixture(t)
	f.writeTOML(disabledTOML, f.started.Add(-time.Minute))
	f.runner.On("systemctl --user show openshell-gateway", f.unit("inactive", "enabled"), nil)
	f.runner.On("systemctl --user enable --now openshell-gateway", "Job failed", errors.New("exit status 1"))
	r := f.run()
	var asked []string
	outcomes, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) {
		asked = append(asked, c.ID)
		return c.ID == openshell.CheckIDGatewayService, nil
	})
	if err != nil || strings.Join(asked, ",") != "gateway-service,bind-mounts" {
		t.Fatalf("asked about %v, %v", asked, err)
	}
	if len(outcomes) != 1 || outcomes[0].Applied || !strings.Contains(outcomes[0].Error, "Job failed") {
		t.Fatalf("outcomes = %+v", outcomes)
	}
	if st, _ := f.doctor.Gateway.Read(); st.BindMounts.Enabled() {
		t.Fatal("a declined fix was applied")
	}
	stop := errors.New("stop")
	if _, err := r.ApplyFixes(context.Background(), func(openshell.Check) (bool, error) { return false, stop }); !errors.Is(err, stop) {
		t.Fatalf("consent error = %v", err)
	}
}

// The ssh check proves, with `ssh -G sandbox` through the shim, that the
// OpenShell sessions DefenseClaw runs share no ssh connections, and warns
// when the user's own ssh configuration would share them for `openshell`
// commands run outside DefenseClaw.
func TestDoctorSSHConnectionSharing(t *testing.T) {
	const pass, warn, fail = openshell.StatusPass, openshell.StatusWarn, openshell.StatusFail
	shimErr := errors.New(`ssh shim: DefenseClaw found no directory for an ssh with connection sharing off that the OpenShell CLI would run (/tmp/x is writable by other users (mode 0777): ` +
		`another user could replace the ssh DefenseClaw gives the OpenShell CLI there); set TMPDIR to a directory only you can write, on a filesystem not mounted noexec`)
	for _, tc := range []struct {
		name   string
		setup  func(f *doctorFixture)
		status openshell.CheckStatus
		detail string
		fix    string
	}{
		{name: "the user's config shares connections for every host", setup: func(f *doctorFixture) {
			f.runner.On("/usr/bin/ssh -G sandbox", sshConfigSharing("auto", "/home/dev/.ssh/cm-eed2ca1b"), nil)
		}, status: warn, detail: `your ssh configuration shares connections for host "sandbox", the name OpenShell gives every sandbox (ControlMaster auto, ControlPath /home/dev/.ssh/cm-eed2ca1b). ` +
			"DefenseClaw turns that off for the OpenShell sessions it runs. An `openshell sandbox connect`, `upload`, `download` or `forward` that you run yourself " +
			"can still reach another sandbox than the one you name, through the connection an earlier one left open",
			fix: "above any `Host *`: `Host sandbox` with `ControlMaster no` and `ControlPath none`"},
		{name: "a control path alone rides a master someone else opened", setup: func(f *doctorFixture) {
			f.runner.On("/usr/bin/ssh -G sandbox", sshConfigSharing("false", "/home/dev/.ssh/cm-eed2ca1b"), nil)
		}, status: warn, detail: "(ControlMaster false, ControlPath /home/dev/.ssh/cm-eed2ca1b)"},
		{name: "the user's config cannot be read", setup: func(f *doctorFixture) {
			f.runner.On("/usr/bin/ssh -G sandbox", "", errors.New("exit status 255"))
		}, status: pass, detail: "off for the OpenShell sessions DefenseClaw runs (ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no); could not read your own ssh configuration: ssh -G sandbox: exit status 255"},
		{name: "no shim can be made safely", setup: func(f *doctorFixture) {
			f.doctor.SSHShim = func() (*openshell.SSHShim, error) { return nil, shimErr }
		}, status: fail, detail: "DefenseClaw cannot give the OpenShell CLI an ssh with connection sharing off, so it refuses to start sandbox sessions: " + shimErr.Error(),
			fix: "set TMPDIR to a directory only you can write"},
		{name: "the shim is under the data directory", setup: func(f *doctorFixture) {
			shim := &openshell.SSHShim{Dir: "/home/dev/.defenseclaw/openshell-ssh/defenseclaw-ssh-1", Path: "/home/dev/.defenseclaw/openshell-ssh/defenseclaw-ssh-1/ssh", Real: fakeShim.Real,
				Fallback: "/tmp is on a filesystem mounted noexec"}
			f.doctor.SSHShim = func() (*openshell.SSHShim, error) { return shim, nil }
			f.runner.On(shim.Path+" -G sandbox", sshConfigSharing("false", ""), nil)
		}, status: pass, detail: "(ssh -o ControlMaster=no -o ControlPath=none -o ControlPersist=no); " +
			"its ssh is under /home/dev/.defenseclaw/openshell-ssh, not the temporary directory: /tmp is on a filesystem mounted noexec; your ssh configuration"},
		{name: "no ssh on PATH", setup: func(f *doctorFixture) {
			f.doctor.SSHShim = func() (*openshell.SSHShim, error) { return nil, nil }
		}, status: warn, detail: "no ssh on PATH: the OpenShell CLI needs one for sandbox connect, file transfers and port forwards", fix: "install the OpenSSH client"},
		{name: "the shim's ssh still shares", setup: func(f *doctorFixture) {
			f.runner.On(fakeShim.Path+" -G sandbox", sshConfigSharing("auto", "/home/dev/.ssh/cm-eed2ca1b"), nil)
		}, status: fail, detail: "/usr/bin/ssh, the first ssh on PATH, does not keep connection sharing off when run with -o ControlMaster=no -o ControlPath=none -o ControlPersist=no first " +
			"(`ssh -G sandbox` through DefenseClaw's shim reports ControlMaster auto, ControlPath /home/dev/.ssh/cm-eed2ca1b), so one sandbox's session could reach another sandbox",
			fix: "make /usr/bin/ssh pass its arguments on to OpenSSH's ssh without ControlMaster, ControlPath or ControlPersist options, -S or -M of its own"},
		{name: "the shim's ssh opens a master", setup: func(f *doctorFixture) {
			f.runner.On(fakeShim.Path+" -G sandbox", sshConfigSharing("true", ""), nil)
		}, status: fail, detail: "reports ControlMaster true, ControlPath none)"},
		{name: "the shim's ssh cannot be asked", setup: func(f *doctorFixture) {
			f.runner.On(fakeShim.Path+" -G sandbox", "/home/dev/.ssh/config line 3: Bad configuration option: controlmastr\n", errors.New("exit status 255"))
		}, status: warn, detail: "could not confirm that the ssh DefenseClaw runs the OpenShell CLI with shares no connections: ssh -G sandbox: exit status 255: /home/dev/.ssh/config line 3: Bad configuration option: controlmastr"},
		{name: "the shim's ssh prints no setting", setup: func(f *doctorFixture) {
			f.runner.On(fakeShim.Path+" -G sandbox", "Pseudo-terminal will not be allocated because stdin is not a terminal.\n", nil)
		}, status: warn, detail: "/shim/ssh -G sandbox printed no controlmaster setting"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			tc.setup(f)
			r := f.run()
			c := expectCheck(t, r, openshell.CheckIDSSHSharing, tc.status, tc.detail)
			if tc.fix != "" && (c.Fix == nil || c.Fix.Automatic || c.Fix.Apply != nil || !strings.Contains(c.Fix.Summary, tc.fix)) {
				t.Fatalf("fix = %+v, want a manual one containing %q", c.Fix, tc.fix)
			}
			if r.OK() != (tc.status != fail) {
				t.Fatalf("OK = %v with the ssh check %s", r.OK(), tc.status)
			}
		})
	}
}

// An ssh wrapper first on PATH that turns connection sharing back on fails
// the check, naming the wrapper and the ssh to put first, since DefenseClaw
// refuses sandbox sessions through it; it used to only warn.
func TestDoctorFailsWhenAnSSHWrapperShares(t *testing.T) {
	skipOnWindows(t)
	root := t.TempDir()
	realDir, wrapperDir := filepath.Join(root, "usr-bin"), filepath.Join(root, "home-bin")
	realSSH := recordingSSH(t, realDir)
	wrapper := sharingWrapper(t, wrapperDir, realSSH, "-o ControlMaster=auto -o "+shq("ControlPath="+filepath.Join(root, "cm-%C")))
	openshell.SetSSHShimBase(t, realTempDir(t))
	f := newDoctorFixture(t)
	f.doctor.SSHShim = func() (*openshell.SSHShim, error) {
		return openshell.NewSSHShim(wrapperDir + string(os.PathListSeparator) + realDir)
	}
	r := f.run()
	c := expectCheck(t, r, openshell.CheckIDSSHSharing, openshell.StatusFail,
		"DefenseClaw refuses to start sandbox sessions: "+wrapper+", the first ssh on PATH, does not keep connection sharing off when run with "+
			"-o ControlMaster=no -o ControlPath=none -o ControlPersist=no first (`ssh -G sandbox` through DefenseClaw's shim reports ControlMaster auto, ControlPath "+
			filepath.Join(root, "cm-%C")+")")
	if want := "make " + wrapper + " pass its arguments on to OpenSSH's ssh without ControlMaster, ControlPath or ControlPersist options, -S or -M of its own, " +
		"or put " + realDir + " before " + wrapperDir + " on PATH, so the OpenShell CLI runs " + realSSH; c.Fix == nil || c.Fix.Summary != want {
		t.Fatalf("fix = %+v, want %q", c.Fix, want)
	}
	if r.OK() {
		t.Fatal("the report is OK with an ssh that shares connections")
	}
}

// A shim a PATH search would pass over (here one the system will not run,
// as on a filesystem mounted noexec) fails the check, since DefenseClaw
// refuses sandbox sessions without one; it used to pass NewSSHShim and
// only warn when `ssh -G` through it was refused.
func TestDoctorFailsWhenTheSSHShimCannotRun(t *testing.T) {
	skipOnWindows(t)
	bin := filepath.Join(t.TempDir(), "bin")
	recordingSSH(t, bin)
	openshell.SetSSHShimBase(t, realTempDir(t))
	openshell.SetSSHShimMode(t, 0o600)
	f := newDoctorFixture(t)
	f.doctor.SSHShim = func() (*openshell.SSHShim, error) { return openshell.NewSSHShim(bin) }
	r := f.run()
	c := expectCheck(t, r, openshell.CheckIDSSHSharing, openshell.StatusFail,
		"DefenseClaw cannot give the OpenShell CLI an ssh with connection sharing off, so it refuses to start sandbox sessions: ssh shim: ")
	if !strings.Contains(c.Detail, ", which it cannot execute, and finds "+filepath.Join(bin, "ssh")) ||
		c.Fix == nil || !strings.Contains(c.Fix.Summary, "on a filesystem not mounted noexec") {
		t.Fatalf("check = %+v, fix %+v", c, c.Fix)
	}
	if r.OK() {
		t.Fatal("the report is OK without an ssh shim that runs")
	}
}
