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

package sandboxcli

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// TestSetupInstallsNothingWhileAnotherAccountHoldsTheGatewayPort
// (GAP-0390): a second account on a Mac whose own Homebrew (~/homebrew) has
// no nvidia/openshell formula, while another account's gateway holds
// 127.0.0.1:17670. The doctor said only "not installed", so setup went past
// the machine checks and installed OpenShell, whose service could never
// bind the port. With the real host checks, setup stops at the other
// account's gateway, with the way on, and runs neither the installer nor
// Homebrew.
func TestSetupInstallsNothingWhileAnotherAccountHoldsTheGatewayPort(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.IO.TTY = false
	ta.GOOS = "darwin"
	brew := filepath.Join(ta.home, "homebrew")
	runner := &openshelltest.Runner{}
	runner.On("docker info", `{"ServerVersion":"29.1.5","OperatingSystem":"Docker Desktop","DockerRootDir":"/var/lib/docker",`+
		`"SecurityOptions":["name=seccomp,profile=builtin","name=cgroupns"]}`, nil)
	runner.On("docker buildx version", "github.com/docker/buildx v0.30.1 c6f062d0eef6a18ae703d0433e2c8a4dd34d4513\n", nil)
	runner.OnFunc("brew", func(_ context.Context, c openshell.Command) ([]byte, error) {
		t.Errorf("ran brew %v", c.Args)
		return []byte("Error: Formula `openshell` is not installed."), errors.New("exit status 1")
	})
	lookPath := func(name string) (string, error) {
		if name == "docker" {
			return "/usr/local/bin/docker", nil
		}
		return "", errors.New("not found")
	}
	ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		openshellDir := filepath.Join(ta.home, ".config", "openshell")
		d.GOOS, d.GOARCH, d.Runner, d.LookPath = "darwin", "arm64", runner, lookPath
		d.Discover = openshell.DiscoverOptions{ConfigDir: openshellDir, SystemDir: filepath.Join(ta.home, "none")}
		d.Dial = func(*openshell.Registration) (openshell.Client, error) { return nil, errors.New("connection refused") }
		d.Gateway = &openshell.GatewayConfigurator{Dir: openshellDir, GOOS: "darwin", Runner: runner, LookPath: lookPath, BrewPrefix: brew,
			BrewFormulaInstalled: func() bool { return false }}
		d.Listen = func(network, addr string) (net.Listener, error) {
			if addr == "127.0.0.1:17670" {
				return nil, errors.New("listen tcp 127.0.0.1:17670: bind: address already in use")
			}
			return net.Listen(network, "127.0.0.1:0")
		}
		// lsof lists this account's processes only.
		d.PortHolder = func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{UID: -1}, daemon.ErrNoListener }
		d.Geteuid, d.Getegid = func() int { return 502 }, func() int { return 20 }
		d.Username = func() (string, error) { return "dcm-std1", nil }
		d.HomeDir = func() (string, error) { return ta.home, nil }
		d.DockerDesktop = func() (*openshell.DockerDesktop, error) { return &openshell.DockerDesktop{}, nil }
		d.LandlockABI = func() (int, error) { return 0, errors.New("not Linux") }
		d.DockerVMLandlockABI = func(context.Context) (int, string, error) { return 6, "6.12.65-linuxkit", nil }
		d.E2fsprogsDirs = []string{filepath.Join(brew, "opt", "e2fsprogs", "sbin")}
		d.OpenKVM = func() error { return os.ErrNotExist }
		d.HostMemory = func() uint64 { return 32 << 30 }
		d.DiskFree = func(string) (uint64, error) { return 100 << 30, nil }
		d.TempDir = t.TempDir
		d.DockerGroup = func() (bool, bool, error) { return true, true, nil }
		d.ServiceDockerGroupMissing = func() bool { return false }
		d.SSHShim = func() (*openshell.SSHShim, error) {
			return &openshell.SSHShim{Dir: "/shim", Path: "/shim/ssh", Real: "/usr/bin/ssh"}, nil
		}
		d.Getenv = func(string) string { return "" }
		return d.Run(ctx)
	}
	inst := &fakeInstaller{}
	ta.Installer = func(consent func(*openshell.InstallPlan) (bool, error)) Installer {
		inst.consent = consent
		return inst
	}
	err := ta.Setup(bg, SetupOptions{Yes: true, InstallOpenShell: true, SkipImages: true, NoWrappers: true})
	var silent *Silent
	if !errors.As(err, &silent) || inst.ran || inst.e2fsprogs != 0 || ta.gateway.applied != 0 {
		t.Fatalf("Setup = %v, installer ran %v (e2fsprogs %d), gateway applied %d\n%s", err, inst.ran, inst.e2fsprogs, ta.gateway.applied, ta.output())
	}
	has(t, ta.output(), "Gateway service: nvidia/openshell/openshell is not installed; 127.0.0.1:17670, the gateway's port, is held by a process of another account",
		"→ one OpenShell gateway runs on a machine, under the account that started it, and this account's would not get its port: run sandboxes from that account, "+
			"or have it hand its gateway over (`brew services stop nvidia/openshell/openshell` as that account), then install OpenShell in this account: "+
			"defenseclaw sandbox setup --install-openshell")
	lacks(t, ta.output(), "Install OpenShell", "Run sandboxes in OpenShell MicroVMs?")
}
