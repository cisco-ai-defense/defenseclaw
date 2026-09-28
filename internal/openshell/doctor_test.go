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
	// probe answers ProbeClientAuth; probes counts the calls.
	probe  error
	probes int
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
		t:       t,
		dir:     filepath.Join(t.TempDir(), "openshell"),
		home:    t.TempDir(),
		runner:  &openshelltest.Runner{},
		fake:    openshelltest.New(),
		found:   map[string]bool{"docker": true, "openshell": true},
		busy:    map[string]bool{},
		started: time.Now().Add(-time.Hour).Truncate(time.Second),
	}
	f.regDir = writeRegistration(t, f.dir, "openshell", nil, nil)
	for file, mode := range map[string]os.FileMode{"mtls": 0o700, "mtls/ca.crt": 0o644, "mtls/tls.crt": 0o644} {
		if err := os.Chmod(filepath.Join(f.regDir, file), mode); err != nil {
			t.Fatal(err)
		}
	}
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
		Gateway: &openshell.GatewayConfigurator{Dir: f.dir, GOOS: "linux", Runner: f.runner,
			VerifyGateway:   func(context.Context) error { f.verified++; return nil },
			ProbeClientAuth: func(context.Context, *openshell.Registration) error { f.probes++; return f.probe }},
		Ports:         []openshell.PortRequirement{{Name: "ingress", Port: 18971}, {Name: "egress", Port: 18972}},
		LandlockABI:   func() (int, error) { return 6, nil },
		DiskFree:      func(string) (uint64, error) { return 40 << 30, nil },
		Listen:        f.listen,
		Geteuid:       func() int { return 1000 },
		Username:      func() (string, error) { return "dev", nil },
		HomeDir:       func() (string, error) { return f.home, nil },
		DockerDesktop: func() (*openshell.DockerDesktop, error) { return nil, errors.New("not Docker Desktop") },
		DockerGroup:   func() (bool, bool, error) { return true, true, nil },
	}
	return f
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
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		f.t.Fatal(err)
	}
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

func TestDoctorHealthyHost(t *testing.T) {
	f := newDoctorFixture(t)
	r := f.run()
	if !r.OK() {
		t.Fatalf("healthy host failed:\n%s", r)
	}
	for _, c := range r.Checks {
		if c.Status != openshell.StatusPass && c.Status != openshell.StatusSkip {
			t.Errorf("%s = %s: %s", c.ID, c.Status, c.Detail)
		}
	}
	want := []string{"platform", "user", "landlock", "docker", "docker-host-network", "docker-file-sharing", "disk", "linger",
		"gateway-service", "openshell-cli", "gateway-registration", "mtls-permissions", "gateway-version", "gateway-driver",
		"global-policy", "bind-mounts", "telemetry", "port-ingress", "port-egress"}
	var got []string
	for _, c := range r.Checks {
		got = append(got, c.ID)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("checks = %v\nwant     %v", got, want)
	}
	expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusPass, "ABI 6")
	expectCheck(t, r, openshell.CheckIDDisk, openshell.StatusPass, "40.0 GiB free under /data/docker")
	if r.DockerVersion != "29.4.0" || r.CLIVersion != "0.1.1" || r.GatewayVersion != "0.1.1" || r.Registration.Name != "openshell" {
		t.Fatalf("facts = %+v", r)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatalf("report does not marshal: %v", err)
	}
}

func TestDoctorPlatforms(t *testing.T) {
	cases := []struct {
		goos, goarch string
		status       openshell.CheckStatus
		early        bool
	}{
		{"windows", "amd64", openshell.StatusFail, true},
		{"freebsd", "amd64", openshell.StatusFail, true},
		{"linux", "386", openshell.StatusFail, false},
		{"darwin", "amd64", openshell.StatusFail, false},
		{"darwin", "arm64", openshell.StatusWarn, false},
	}
	for _, tc := range cases {
		t.Run(tc.goos+"/"+tc.goarch, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.doctor.GOOS, f.doctor.GOARCH = tc.goos, tc.goarch
			f.doctor.Gateway.GOOS = tc.goos
			r := f.run()
			expectCheck(t, r, openshell.CheckIDPlatform, tc.status, tc.goos)
			if tc.early != (len(r.Checks) == 1) {
				t.Fatalf("early return = %v, checks %d", len(r.Checks) == 1, len(r.Checks))
			}
		})
	}
	t.Run("macOS skips Linux-only checks", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.doctor.GOOS, f.doctor.Gateway.GOOS = "darwin", "darwin"
		f.runner.On("brew services info nvidia/openshell/openshell --json", `[{"running":true,"loaded":true,"status":"started","file":"/x.plist"}]`, nil)
		r := f.run()
		expectCheck(t, r, openshell.CheckIDLandlock, openshell.StatusSkip, "Docker Desktop")
		expectCheck(t, r, openshell.CheckIDLinger, openshell.StatusSkip, "")
		expectCheck(t, r, openshell.CheckIDGatewayService, openshell.StatusPass, "nvidia/openshell/openshell")
		expectCheck(t, r, openshell.CheckIDTelemetry, openshell.StatusSkip, "")
	})
}

func TestDoctorUser(t *testing.T) {
	f := newDoctorFixture(t)
	f.doctor.Geteuid = func() int { return 0 }
	expectCheck(t, f.run(), openshell.CheckIDUser, openshell.StatusFail, "running as root")

	f = newDoctorFixture(t)
	uid := 998
	f.doctor.DaemonUID = &uid
	expectCheck(t, f.run(), openshell.CheckIDUser, openshell.StatusFail, "daemon runs as uid 998")
}

func TestDoctorLandlock(t *testing.T) {
	cases := []struct {
		abi    int
		err    error
		detail string
	}{
		{2, nil, "ABI 2; OpenShell needs ABI 3"},
		{0, openshell.ErrLandlockDisabled, "not enabled"},
		{0, openshell.ErrLandlockMissing, "no Landlock support"},
	}
	for _, tc := range cases {
		f := newDoctorFixture(t)
		f.doctor.LandlockABI = func() (int, error) { return tc.abi, tc.err }
		c := expectCheck(t, f.run(), openshell.CheckIDLandlock, openshell.StatusFail, tc.detail)
		if c.Fix == nil || !c.Fix.Sudo || c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
	}
}

func TestDoctorDocker(t *testing.T) {
	type result struct {
		id     string
		status openshell.CheckStatus
		detail string
	}
	cases := []struct {
		name  string
		setup func(f *doctorFixture)
		want  []result
		fix   string
	}{
		{
			name:  "not installed",
			setup: func(f *doctorFixture) { f.found["docker"] = false },
			want: []result{{"docker", openshell.StatusFail, "not installed"}, {"docker-host-network", openshell.StatusSkip, ""},
				{"docker-file-sharing", openshell.StatusSkip, ""}, {"disk", openshell.StatusSkip, ""}},
			fix: "install Docker Engine 28",
		},
		{
			name: "permission denied, not in the group",
			setup: func(f *doctorFixture) {
				f.runner.On("docker info", "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock", errors.New("exit status 1"))
				f.doctor.DockerGroup = func() (bool, bool, error) { return false, false, nil }
			},
			want: []result{{"docker", openshell.StatusFail, "permission denied"}},
			fix:  "sudo usermod -aG docker dev",
		},
		{
			name: "permission denied, stale session",
			setup: func(f *doctorFixture) {
				f.runner.On("docker info", `{"ServerErrors":["permission denied while trying to connect to the Docker daemon socket"]}`, errors.New("exit status 1"))
				f.doctor.DockerGroup = func() (bool, bool, error) { return true, false, nil }
			},
			want: []result{{"docker", openshell.StatusFail, "permission denied"}},
			fix:  "newgrp docker",
		},
		{
			name: "daemon down",
			setup: func(f *doctorFixture) {
				f.runner.On("docker info", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?", errors.New("exit status 1"))
			},
			want: []result{{"docker", openshell.StatusFail, "Is the docker daemon running"}},
			fix:  "sudo systemctl enable --now docker",
		},
		{
			name:  "too old",
			setup: func(f *doctorFixture) { f.runner.On("docker info", dockerInfoJSON("27.5.1", "Ubuntu", nil), nil) },
			want:  []result{{"docker", openshell.StatusFail, "older than 28"}},
		},
		{
			name: "rootless",
			setup: func(f *doctorFixture) {
				f.runner.On("docker info", dockerInfoJSON("29.4.0", "Ubuntu", map[string]any{"SecurityOptions": []string{"name=seccomp,profile=builtin", "name=rootless"}}), nil)
			},
			want: []result{{"docker", openshell.StatusFail, "rootless"}},
		},
		{
			name: "desktop with host networking and sharing",
			setup: func(f *doctorFixture) {
				f.runner.On("docker info", dockerInfoJSON("28.3.2", "Docker Desktop", nil), nil)
				on := true
				f.doctor.DockerDesktop = func() (*openshell.DockerDesktop, error) {
					return &openshell.DockerDesktop{HostNetworking: &on, FileSharing: []string{filepath.Dir(f.home)}}, nil
				}
			},
			want: []result{{"docker", openshell.StatusPass, "Docker Desktop"}, {"docker-host-network", openshell.StatusPass, "enabled"},
				{"docker-file-sharing", openshell.StatusPass, "is shared"}, {"disk", openshell.StatusSkip, "VM"}},
		},
		{
			name: "desktop without host networking or sharing",
			setup: func(f *doctorFixture) {
				f.runner.On("docker info", dockerInfoJSON("28.3.2", "Docker Desktop", nil), nil)
				off := false
				f.doctor.DockerDesktop = func() (*openshell.DockerDesktop, error) {
					return &openshell.DockerDesktop{HostNetworking: &off, FileSharing: []string{"/Volumes"}}, nil
				}
			},
			want: []result{{"docker-host-network", openshell.StatusFail, "host networking is off"}, {"docker-file-sharing", openshell.StatusFail, "not shared"}},
		},
		{
			name: "desktop settings store on disk",
			setup: func(f *doctorFixture) {
				f.runner.On("docker info", dockerInfoJSON("28.3.2", "Docker Desktop", nil), nil)
				f.doctor.DockerDesktop = nil
				store := filepath.Join(f.home, ".docker", "desktop", "settings-store.json")
				if err := os.MkdirAll(filepath.Dir(store), 0o700); err != nil {
					f.t.Fatal(err)
				}
				data := fmt.Sprintf(`{"HostNetworkingEnabled": false, "filesharingDirectories": [%q]}`, f.home)
				if err := os.WriteFile(store, []byte(data), 0o600); err != nil {
					f.t.Fatal(err)
				}
			},
			want: []result{{"docker-host-network", openshell.StatusFail, "host networking is off"}, {"docker-file-sharing", openshell.StatusPass, "is shared"}},
		},
		{
			name: "desktop settings unreadable",
			setup: func(f *doctorFixture) {
				f.runner.On("docker info", dockerInfoJSON("28.3.2", "Docker Desktop", nil), nil)
			},
			want: []result{{"docker-host-network", openshell.StatusWarn, "could not read"}, {"docker-file-sharing", openshell.StatusWarn, "could not read"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			tc.setup(f)
			r := f.run()
			for _, w := range tc.want {
				c := expectCheck(t, r, w.id, w.status, w.detail)
				if w.id == "docker" && tc.fix != "" && (c.Fix == nil || !strings.Contains(c.Fix.Summary+" "+c.Fix.Command, tc.fix)) {
					t.Fatalf("docker fix = %+v, want %q", c.Fix, tc.fix)
				}
			}
		})
	}
}

func TestDoctorDisk(t *testing.T) {
	for _, tc := range []struct {
		free   uint64
		err    error
		status openshell.CheckStatus
		detail string
	}{
		{3 << 30, nil, openshell.StatusFail, "at least 5.0 GiB"},
		{7 << 30, nil, openshell.StatusWarn, "10.0 GiB or more"},
		{0, errors.New("no such file"), openshell.StatusWarn, "could not measure"},
	} {
		f := newDoctorFixture(t)
		var probed string
		f.doctor.DiskFree = func(p string) (uint64, error) { probed = p; return tc.free, tc.err }
		c := expectCheck(t, f.run(), openshell.CheckIDDisk, tc.status, tc.detail)
		if probed != "/data/docker" {
			t.Fatalf("probed %q, want the Docker root", probed)
		}
		// Low space names DefenseClaw's own prune, and warns about the
		// machine-wide one instead of suggesting it.
		if tc.err == nil {
			if c.Fix == nil || c.Fix.Command != "defenseclaw sandbox image prune" ||
				!strings.Contains(c.Fix.Summary, "rather than `docker system prune`, which also removes") {
				t.Fatalf("disk fix = %+v", c.Fix)
			}
		}
	}
}

func TestDoctorLingerAndService(t *testing.T) {
	t.Run("linger off", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("loginctl show-user dev", "no\n", nil)
		c := expectCheck(t, f.run(), openshell.CheckIDLinger, openshell.StatusWarn, "stop when you log out")
		if c.Fix.Command != "sudo loginctl enable-linger dev" || !c.Fix.Sudo {
			t.Fatalf("fix = %+v", c.Fix)
		}
	})
	t.Run("service stopped is fixable", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", "LoadState=loaded\nActiveState=failed\nSubState=failed\nUnitFileState=enabled\n", nil)
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDGatewayService, openshell.StatusFail, "failed (failed)")
		if !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
		outcomes, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDGatewayService, nil })
		if err != nil || len(outcomes) != 1 || !outcomes[0].Applied {
			t.Fatalf("outcomes = %+v, %v", outcomes, err)
		}
		if !f.runner.Called("systemctl --user enable --now openshell-gateway") || f.verified != 1 {
			t.Fatalf("fix did not start and verify the gateway (verified %d)", f.verified)
		}
	})
	t.Run("service not installed", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", "LoadState=not-found\nActiveState=inactive\nSubState=dead\n", nil)
		c := expectCheck(t, f.run(), openshell.CheckIDGatewayService, openshell.StatusFail, "not installed")
		if c.Fix.Command != "defenseclaw sandbox setup --install-openshell" {
			t.Fatalf("fix = %+v", c.Fix)
		}
	})
	t.Run("service not enabled", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=disabled\n", nil)
		expectCheck(t, f.run(), openshell.CheckIDGatewayService, openshell.StatusWarn, "does not start at login")
	})
	t.Run("service only linked", func(t *testing.T) {
		// `systemctl --user link` without enable: nothing starts it at login.
		f := newDoctorFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", f.unit("active", "linked"), nil)
		c := expectCheck(t, f.run(), openshell.CheckIDGatewayService, openshell.StatusWarn, "does not start at login")
		if c.Fix.Command != "systemctl --user enable --now openshell-gateway" || !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
	})
	t.Run("no user bus", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", "Failed to connect to bus: No medium found", errors.New("exit status 1"))
		expectCheck(t, f.run(), openshell.CheckIDGatewayService, openshell.StatusFail, "Failed to connect to bus")
	})
}

func TestDoctorVersions(t *testing.T) {
	t.Run("cli missing", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.found["openshell"] = false
		expectCheck(t, f.run(), openshell.CheckIDCLI, openshell.StatusFail, "not on PATH")
	})
	t.Run("cli 0.0.x", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("/usr/bin/openshell --version", "openshell 0.0.16\n", nil)
		expectCheck(t, f.run(), openshell.CheckIDCLI, openshell.StatusFail, "predates 0.0.37")
	})
	t.Run("cli 0.0.x that upgrades in place", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("/usr/bin/openshell --version", "openshell 0.0.40\n", nil)
		c := expectCheck(t, f.run(), openshell.CheckIDCLI, openshell.StatusFail, "upgrade it in place")
		if c.Fix.Command != "defenseclaw sandbox setup --install-openshell" {
			t.Fatalf("fix = %+v", c.Fix)
		}
	})
	t.Run("cli and gateway differ", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.fake.SetHealth(true, "0.1.2")
		expectCheck(t, f.run(), openshell.CheckIDGatewayVersion, openshell.StatusWarn, "gateway 0.1.2 but CLI 0.1.1")
	})
	t.Run("gateway outside the window", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.fake.SetHealth(true, "0.2.0")
		expectCheck(t, f.run(), openshell.CheckIDGatewayVersion, openshell.StatusFail, "not supported")
	})
	t.Run("gateway unhealthy", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.fake.SetHealth(false, "0.1.1")
		r := f.run()
		expectCheck(t, r, openshell.CheckIDGatewayVersion, openshell.StatusFail, "unhealthy")
		expectCheck(t, r, openshell.CheckIDGatewayDriver, openshell.StatusSkip, "")
		expectCheck(t, r, openshell.CheckIDGlobalPolicy, openshell.StatusSkip, "")
	})
	t.Run("gateway unreachable", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
		expectCheck(t, f.run(), openshell.CheckIDGatewayVersion, openshell.StatusFail, "connection refused")
	})
}

// TestDoctorGatewayRecovery covers the fix for a gateway that does not
// answer: a running (hung) gateway is restarted, since starting it again
// does nothing, a stopped one is started, and one that refuses
// DefenseClaw's credentials is registered again instead.
func TestDoctorGatewayRecovery(t *testing.T) {
	t.Run("running but hung is restarted", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.fake.FailNext(openshelltest.MethodHealth, &types.StatusError{Code: types.ErrorDeadlineExceeded, Message: "context deadline exceeded"})
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDGatewayVersion, openshell.StatusFail, "not answering")
		if c.Fix.Command != "systemctl --user restart openshell-gateway" || !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
		if _, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDGatewayVersion, nil }); err != nil {
			t.Fatal(err)
		}
		if !f.runner.Called("systemctl --user restart openshell-gateway") || f.runner.Called("systemctl --user enable") || f.verified != 1 {
			t.Fatalf("fix did not restart and verify the gateway (verified %d): %v", f.verified, f.runner.Calls())
		}
	})
	t.Run("stopped is started", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", f.unit("inactive", "enabled"), nil)
		f.fake.SetHealth(false, "0.1.1")
		c := expectCheck(t, f.run(), openshell.CheckIDGatewayVersion, openshell.StatusFail, "unhealthy")
		if c.Fix.Command != "systemctl --user enable --now openshell-gateway" || !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
	})
	t.Run("credentials refused", func(t *testing.T) {
		for _, err := range []error{
			&types.StatusError{Code: types.ErrorUnauthenticated, Message: "client certificate not trusted"},
			&types.StatusError{Code: types.ErrorUnavailable, Message: "connection error: desc = \"transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority\""},
		} {
			f := newDoctorFixture(t)
			f.fake.FailNext(openshelltest.MethodHealth, err)
			c := expectCheck(t, f.run(), openshell.CheckIDGatewayVersion, openshell.StatusFail, "refused DefenseClaw's TLS credentials")
			if c.Fix.Automatic || c.Fix.Command != "openshell gateway remove openshell && openshell gateway add 'https://127.0.0.1:17670' --local --name openshell" {
				t.Fatalf("fix = %+v", c.Fix)
			}
		}
	})
}

func TestDoctorGatewayFeatures(t *testing.T) {
	t.Run("wrong compute driver", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.fake = openshelltest.New(openshelltest.WithGatewayInfo(types.GatewayInfo{Version: "0.1.1",
			ComputeDrivers: []types.ComputeDriverInfo{{Name: "podman", DriverName: "podman"}}}))
		expectCheck(t, f.run(), openshell.CheckIDGatewayDriver, openshell.StatusFail, "runs podman")
	})
	t.Run("global policy", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.fake.SetGlobalPolicy(&openshell.SandboxPolicy{Version: 1})
		expectCheck(t, f.run(), openshell.CheckIDGlobalPolicy, openshell.StatusWarn, "approvals are disabled")
	})
}

func TestDoctorRegistrationAndMTLS(t *testing.T) {
	t.Run("no registration", func(t *testing.T) {
		f := newDoctorFixture(t)
		if err := os.RemoveAll(filepath.Join(f.dir, "gateways")); err != nil {
			t.Fatal(err)
		}
		r := f.run()
		expectCheck(t, r, openshell.CheckIDRegistration, openshell.StatusFail, "no gateway registration")
		expectCheck(t, r, openshell.CheckIDMTLS, openshell.StatusSkip, "")
		expectCheck(t, r, openshell.CheckIDGatewayVersion, openshell.StatusSkip, "")
	})
	t.Run("remote gateway", func(t *testing.T) {
		f := newDoctorFixture(t)
		writeRegistration(t, f.dir, "openshell", map[string]any{"name": "openshell", "gateway_endpoint": "https://gw.example.com:443", "auth_mode": "mtls", "is_remote": true}, nil)
		expectCheck(t, f.run(), openshell.CheckIDRegistration, openshell.StatusFail, "remote gateways are not supported")
	})
	t.Run("readable key is fixed", func(t *testing.T) {
		f := newDoctorFixture(t)
		key := filepath.Join(f.regDir, "mtls", "tls.key")
		if err := os.Chmod(key, 0o644); err != nil {
			t.Fatal(err)
		}
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDMTLS, openshell.StatusFail, "private key is accessible to other users")
		expectCheck(t, r, openshell.CheckIDGatewayVersion, openshell.StatusSkip, "")
		if !c.Fix.Automatic || !strings.HasPrefix(c.Fix.Command, "chmod 600 ") {
			t.Fatalf("fix = %+v", c.Fix)
		}
		if _, err := r.ApplyFixes(context.Background(), func(openshell.Check) (bool, error) { return true, nil }); err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Stat(key); info.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %v after fix", info.Mode())
		}
		if again := f.run(); !again.OK() {
			t.Fatalf("still failing after the fix:\n%s", again)
		}
	})
	t.Run("plaintext gateway fails and gets no bind mounts", func(t *testing.T) {
		f := newDoctorFixture(t)
		writeRegistration(t, f.dir, "openshell", map[string]any{"name": "openshell", "gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "plaintext"}, nil)
		f.writeTOML("[openshell]\nversion = 2\n", f.started.Add(-time.Minute))
		dialed := false
		f.doctor.Dial = func(*openshell.Registration) (openshell.Client, error) {
			dialed = true
			return f.fake.Client(openshell.ClientOptions{}), nil
		}
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDRegistration, openshell.StatusFail, "accepts unauthenticated calls")
		if c.Fix == nil || c.Fix.Automatic || !strings.Contains(c.Fix.Summary, "mTLS") {
			t.Fatalf("registration fix = %+v", c.Fix)
		}
		expectCheck(t, r, openshell.CheckIDMTLS, openshell.StatusSkip, "")
		expectCheck(t, r, openshell.CheckIDGatewayVersion, openshell.StatusSkip, "")
		mounts := expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusFail, "disabled")
		if mounts.Fix == nil || mounts.Fix.Automatic || mounts.Fix.Apply != nil {
			t.Fatalf("bind mounts offered an automatic fix on a plaintext gateway: %+v", mounts.Fix)
		}
		if dialed {
			t.Fatal("doctor dialed a plaintext gateway")
		}
		// The bind-mount edit itself refuses too.
		if _, err := f.doctor.Gateway.Plan(context.Background(), openshell.GatewayChanges{EnableBindMounts: true}); !errors.Is(err, openshell.ErrBindMountsRefused) || !errors.Is(err, openshell.ErrUnauthenticatedGateway) {
			t.Fatalf("Plan = %v", err)
		}
	})
	t.Run("bind mounts already on a plaintext gateway fail", func(t *testing.T) {
		f := newDoctorFixture(t)
		writeRegistration(t, f.dir, "openshell", map[string]any{"name": "openshell", "gateway_endpoint": "http://127.0.0.1:17670", "auth_mode": "none"}, nil)
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusFail, "any local user can mount host paths")
	})
	t.Run("stock registration files inside private directories pass", func(t *testing.T) {
		f := newDoctorFixture(t)
		writeFile(t, filepath.Join(f.dir, "active_gateway"), "openshell\n", 0o664)
		expectCheck(t, f.run(), openshell.CheckIDRegistration, openshell.StatusPass, "openshell at")
	})
	t.Run("group-writable registration warns and is fixed", func(t *testing.T) {
		f := newDoctorFixture(t)
		meta := filepath.Join(f.regDir, "metadata.json")
		chmod(t, meta, 0o664)
		for _, d := range []string{f.dir, filepath.Join(f.dir, "gateways"), f.regDir} {
			chmod(t, d, 0o750)
		}
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDRegistration, openshell.StatusWarn, "metadata.json is group-writable")
		if !c.Fix.Automatic || !strings.HasPrefix(c.Fix.Command, "chmod go-w ") {
			t.Fatalf("fix = %+v", c.Fix)
		}
		expectCheck(t, r, openshell.CheckIDMTLS, openshell.StatusPass, "owner-only")
		if _, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDRegistration, nil }); err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Stat(meta); info.Mode().Perm() != 0o644 {
			t.Fatalf("metadata mode %v after fix", info.Mode())
		}
		// The first run closed the fake gateway client; only the
		// registration matters here.
		if again := f.run(); again.Get(openshell.CheckIDRegistration).Status != openshell.StatusPass {
			t.Fatalf("still warning after the fix:\n%s", again)
		}
	})
	t.Run("world-writable registration fails and is fixed", func(t *testing.T) {
		f := newDoctorFixture(t)
		chmod(t, f.regDir, 0o777)
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDRegistration, openshell.StatusFail, "is writable by every user")
		expectCheck(t, r, openshell.CheckIDMTLS, openshell.StatusSkip, "")
		expectCheck(t, r, openshell.CheckIDGatewayVersion, openshell.StatusSkip, "")
		if c.Fix == nil || !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
		if mounts := r.Get(openshell.CheckIDBindMounts); mounts.Status != openshell.StatusPass {
			t.Fatalf("bind mounts = %+v", mounts)
		}
		if _, err := r.ApplyFixes(context.Background(), func(openshell.Check) (bool, error) { return true, nil }); err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Stat(f.regDir); info.Mode().Perm() != 0o755 {
			t.Fatalf("registration mode %v after fix", info.Mode())
		}
		if again := f.run(); !again.OK() {
			t.Fatalf("still failing after the fix:\n%s", again)
		}
	})
	t.Run("group-writable certificates warn and are fixed", func(t *testing.T) {
		f := newDoctorFixture(t)
		ca := filepath.Join(f.regDir, "mtls", "ca.crt")
		if err := os.Chmod(ca, 0o664); err != nil {
			t.Fatal(err)
		}
		r := f.run()
		expectCheck(t, r, openshell.CheckIDMTLS, openshell.StatusWarn, "group-writable")
		if _, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDMTLS, nil }); err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Stat(ca); info.Mode().Perm() != 0o644 {
			t.Fatalf("ca mode %v after fix", info.Mode())
		}
	})
}

func TestDoctorGatewayConfig(t *testing.T) {
	t.Run("bind mounts disabled are fixable", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.writeTOML("[openshell]\nversion = 2\n", f.started.Add(-time.Minute))
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusFail, "only --copy sandboxes work")
		if !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
		outcomes, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDBindMounts, nil })
		if err != nil || len(outcomes) != 1 || !outcomes[0].Applied {
			t.Fatalf("outcomes = %+v, %v", outcomes, err)
		}
		st, _ := f.doctor.Gateway.Read()
		if !st.BindMounts.Enabled() || !f.runner.Called("systemctl --user restart openshell-gateway") {
			t.Fatalf("fix did not enable mounts and restart: %+v", st.BindMounts)
		}
	})
	t.Run("copy-only mode warns", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.writeTOML("[openshell]\nversion = 2\n", f.started.Add(-time.Minute))
		f.doctor.BindMountsOptional = true
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusWarn, "disabled")
	})
	t.Run("restart pending", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.writeTOML(enabledTOML, f.started.Add(time.Minute))
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusWarn, "has not been restarted")
		if c.Fix.Command != "systemctl --user restart openshell-gateway" || !c.Fix.Automatic {
			t.Fatalf("fix = %+v", c.Fix)
		}
	})
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
		// before a restart that never happened still shows.
		f := newDoctorFixture(t)
		f.doctor.GOOS, f.doctor.Gateway.GOOS = "darwin", "darwin"
		f.runner.On("brew services info nvidia/openshell/openshell --json", `[{"running":true,"loaded":true,"status":"started","file":"/x.plist"}]`, nil)
		f.runner.On("brew services restart nvidia/openshell/openshell", "", nil)
		mark(f, f.started.Add(-time.Minute))
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusWarn, "has not been restarted")
		if c.Fix.Command != "brew services restart nvidia/openshell/openshell" {
			t.Fatalf("fix = %+v", c.Fix)
		}
		if _, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDBindMounts, nil }); err != nil {
			t.Fatal(err)
		}
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusPass, "enabled")

		// On systemd a mark from before the last start is stale.
		f = newDoctorFixture(t)
		mark(f, f.started.Add(-time.Second))
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusPass, "enabled")
		mark(f, f.started.Add(time.Second))
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusWarn, "has not been restarted")
	})
	t.Run("telemetry differs from config", func(t *testing.T) {
		f := newDoctorFixture(t)
		off := false
		f.doctor.WantTelemetry = &off
		r := f.run()
		expectCheck(t, r, openshell.CheckIDTelemetry, openshell.StatusWarn, "telemetry is on but openshell.upstream_telemetry is false")
		if _, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDTelemetry, nil }); err != nil {
			t.Fatal(err)
		}
		st, _ := f.doctor.Gateway.Read()
		if st.TelemetryEnabled() {
			t.Fatal("telemetry still on after the fix")
		}
	})
}

// TestDoctorBindMountsNeedAPrivateGateway covers bind mounts judged by
// the gateway the service runs, not only by the CLI's registration files.
func TestDoctorBindMountsNeedAPrivateGateway(t *testing.T) {
	exposedCases := []struct {
		name  string
		setup func(f *doctorFixture)
	}{
		{"TLS disabled in gateway.env", func(f *doctorFixture) {
			writeFile(t, filepath.Join(f.dir, "gateway.env"), "OPENSHELL_DISABLE_TLS=true\n", 0o600)
		}},
		{"mTLS auth off", func(f *doctorFixture) {
			writeFile(t, filepath.Join(f.dir, "gateway.env"), "OPENSHELL_ENABLE_MTLS_AUTH=false\nOPENSHELL_BIND_ADDRESS=0.0.0.0\n", 0o600)
		}},
		{"probe gets in without a certificate", func(f *doctorFixture) {
			f.probe = fmt.Errorf("%w: accepted a TLS session", openshell.ErrGatewayExposed)
		}},
	}
	for _, tc := range exposedCases {
		t.Run("enabled: "+tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			tc.setup(f)
			c := expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusFail, "others can reach the gateway and mount any host path")
			if c.Fix == nil || c.Fix.Automatic {
				t.Fatalf("fix = %+v", c.Fix)
			}
		})
		t.Run("disabled: "+tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.writeTOML("[openshell]\nversion = 2\n", f.started.Add(-time.Minute))
			tc.setup(f)
			c := expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusFail, "disabled")
			if c.Fix == nil || c.Fix.Automatic || c.Fix.Apply != nil || !strings.Contains(c.Fix.Summary, "reachable by you alone") {
				t.Fatalf("bind mounts offered an automatic fix on an exposed gateway: %+v", c.Fix)
			}
		})
	}
	t.Run("registration reaches another gateway", func(t *testing.T) {
		f := newDoctorFixture(t)
		dev := writeRegistration(t, f.dir, "dev", map[string]any{"gateway_endpoint": "https://127.0.0.1:18080", "auth_mode": "mtls"}, nil)
		for file, mode := range map[string]os.FileMode{"mtls": 0o700, "mtls/ca.crt": 0o644, "mtls/tls.crt": 0o644} {
			chmod(t, filepath.Join(dev, file), mode)
		}
		writeFile(t, filepath.Join(f.dir, "active_gateway"), "dev\n", 0o600)
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusFail, "reaches https://127.0.0.1:18080, but the openshell-gateway service listens on port 17670")
	})
	t.Run("service reads another configuration", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.runner.On("systemctl --user show-environment", "HOME=/home/dev\n", nil)
		r := f.run()
		expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusFail, "home/dev/.config/openshell/gateway.toml, not")
		expectCheck(t, r, openshell.CheckIDTelemetry, openshell.StatusWarn, "does not match")
	})
	t.Run("probe inconclusive", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.probe = errors.New("could not confirm that the gateway requires a client certificate: i/o timeout")
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusWarn, "could not confirm")
	})
	t.Run("gateway not answering is not probed", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
		expectCheck(t, f.run(), openshell.CheckIDBindMounts, openshell.StatusPass, "enabled")
		if f.probes != 0 {
			t.Fatalf("probed a gateway that is not answering %d times", f.probes)
		}
	})
}

// TestDoctorFollowsSymlinkedConfigDir runs doctor, and its bind-mount
// fix, on a config directory a dotfile manager links elsewhere, with
// active_gateway choosing between two registrations.
func TestDoctorFollowsSymlinkedConfigDir(t *testing.T) {
	f := newDoctorFixture(t)
	f.writeTOML("[openshell]\nversion = 2\n", f.started.Add(-time.Minute))
	dev := writeRegistration(t, f.dir, "dev", nil, nil)
	for file, mode := range map[string]os.FileMode{"mtls": 0o700, "mtls/ca.crt": 0o644, "mtls/tls.crt": 0o644} {
		chmod(t, filepath.Join(dev, file), mode)
	}
	writeFile(t, filepath.Join(f.dir, "active_gateway"), "dev\n", 0o644)
	link := filepath.Join(t.TempDir(), "openshell")
	if err := os.Symlink(f.dir, link); err != nil {
		t.Fatal(err)
	}
	f.doctor.Discover.ConfigDir = link
	f.doctor.Gateway.Dir = link
	r := f.run()
	if r.Registration == nil || r.Registration.Name != "dev" {
		t.Fatalf("registration = %+v\n%s", r.Registration, r)
	}
	expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusFail, "only --copy sandboxes work")
	outcomes, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) { return c.ID == openshell.CheckIDBindMounts, nil })
	if err != nil || len(outcomes) != 1 || !outcomes[0].Applied {
		t.Fatalf("outcomes = %+v, %v", outcomes, err)
	}
	if st, err := f.doctor.Gateway.Read(); err != nil || !st.BindMounts.Enabled() {
		t.Fatalf("state = %+v, %v", st, err)
	}
}

func TestDoctorPorts(t *testing.T) {
	f := newDoctorFixture(t)
	f.busy["127.0.0.1:18971"] = true
	f.busy["127.0.0.1:18972"] = true
	f.doctor.Ports = []openshell.PortRequirement{
		{Name: "ingress", Port: 18971},
		{Name: "egress", Port: 18972, ServedByDaemon: true},
		{Name: "extra", Port: 17670},
		{Name: "bad", Port: 0},
	}
	r := f.run()
	expectCheck(t, r, "port-ingress", openshell.StatusFail, "in use by another process")
	expectCheck(t, r, "port-egress", openshell.StatusPass, "served by the DefenseClaw daemon")
	expectCheck(t, r, "port-extra", openshell.StatusFail, "OpenShell gateway's port")
	expectCheck(t, r, "port-bad", openshell.StatusFail, "invalid port")
}

func TestDoctorApplyFixesConsent(t *testing.T) {
	f := newDoctorFixture(t)
	f.writeTOML("[openshell]\nversion = 2\n", f.started.Add(-time.Minute))
	f.runner.On("systemctl --user show openshell-gateway", f.unit("inactive", "enabled"), nil)
	f.runner.On("systemctl --user enable --now openshell-gateway", "Job failed", errors.New("exit status 1"))
	r := f.run()
	var asked []string
	outcomes, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) {
		asked = append(asked, c.ID)
		return c.ID == openshell.CheckIDGatewayService, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(asked, ",") != "gateway-service,bind-mounts" {
		t.Fatalf("asked about %v", asked)
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

func TestDoctorReportString(t *testing.T) {
	f := newDoctorFixture(t)
	f.runner.On("loginctl show-user dev", "no\n", nil)
	out := f.run().String()
	for _, want := range []string{"PASS  Platform", "WARN  systemd linger", "fix linger:", "sudo loginctl enable-linger dev"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
}
