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
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestSetupMacMicroVMQuestionFollowsTheOpenShellRelease (GAP-1775): with
// OpenShell 0.1.9 MicroVM sandboxes start on a Mac, but the setup question told
// every Mac they do not. The text follows the release the host runs: from
// 0.1.9 it drops that claim and offers vm as a choice that works; 0.1.6 to
// 0.1.8, which the guest-root check still refuses, keep it. The default does
// not move (GAP-1704): docker unless the user says yes, and --yes never writes
// vm, so a gateway on vm is moved to docker.
func TestSetupMacMicroVMQuestionFollowsTheOpenShellRelease(t *testing.T) {
	const stale = "MicroVMs do not start"
	for _, tc := range []struct {
		name    string
		version string
		driver  openshell.ComputeDriver
		input   string
		yes     bool
		stales  bool                    // the question says they do not start
		want    openshell.ComputeDriver // "": the gateway stays on docker, which plans no driver change
	}{
		{"0.1.9 vm default", "0.1.9", openshell.DriverVM, "\ny\n", false, false, openshell.DriverDocker},
		{"0.1.9 vm --yes", "0.1.9", openshell.DriverVM, "", true, false, openshell.DriverDocker},
		{"0.1.9 vm yes", "0.1.9", openshell.DriverVM, "y\ny\n", false, false, openshell.DriverVM},
		{"0.1.10 vm default", "0.1.10", openshell.DriverVM, "\ny\n", false, false, openshell.DriverDocker},
		{"0.1.9 docker default", "0.1.9", openshell.DriverDocker, "\ny\n", false, false, ""},
		{"0.1.9 docker --yes", "0.1.9", openshell.DriverDocker, "", true, false, ""},
		{"0.1.9 docker yes", "0.1.9", openshell.DriverDocker, "y\ny\n", false, false, openshell.DriverVM},
		{"0.1.8 vm default", "0.1.8", openshell.DriverVM, "\ny\n", false, true, openshell.DriverDocker},
		{"0.1.8 vm --yes", "0.1.8", openshell.DriverVM, "", true, true, openshell.DriverDocker},
		{"0.1.8 vm yes", "0.1.8", openshell.DriverVM, "y\ny\n", false, true, openshell.DriverVM},
		{"0.1.8 docker default", "0.1.8", openshell.DriverDocker, "\ny\n", false, true, ""},
		{"0.1.6 docker yes", "0.1.6", openshell.DriverDocker, "y\ny\n", false, true, openshell.DriverVM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := setupApp(t, tc.input, "", false)
			if tc.yes {
				ta.IO.TTY, ta.IO.InTTY = false, false
			}
			ta.GOOS = "darwin"
			ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
			ta.gateway.state.TOMLPath = filepath.Join(ta.home, ".config", "openshell", "gateway.toml")
			ta.HostDoctor = macReport(tc.driver, func(r *openshell.DoctorReport) { r.CLIVersion = tc.version })
			ta.gateway.applyRes = &openshell.GatewayApplyResult{}
			_, _ = useGateway(ta)
			_ = ta.Setup(bg, SetupOptions{Yes: tc.yes, SkipImages: true, NoWrappers: true})
			out := ta.output()
			if !tc.yes {
				has(t, out, "Run sandboxes in OpenShell MicroVMs? ", "[y/N]")
			}
			if tc.stales {
				if !tc.yes {
					has(t, out, stale)
				}
			} else {
				lacks(t, out, stale, "no sandbox starts on a Mac", "do not start until OpenShell fixes")
			}
			p := ta.gateway.planned
			if len(p) != 1 || p[0].ComputeDriver != tc.want {
				t.Fatalf("gateway plans = %+v, want compute_driver %q:\n%s", p, tc.want, out)
			}
		})
	}
}

// TestSetupSaysNothingOfAMacMicroVMGatewayNotStartingOnZeroOneNine (GAP-1775):
// a gateway on vm that the user moves to docker on OpenShell 0.1.9, while a
// sandbox runs on it, waits for the restart: it is not "where no sandbox starts
// on a Mac" then; before 0.1.9 it is.
func TestSetupSaysNothingOfAMacMicroVMGatewayNotStartingOnZeroOneNine(t *testing.T) {
	for _, tc := range []struct {
		version string
		stale   bool
	}{{"0.1.9", false}, {"0.1.8", true}} {
		t.Run(tc.version, func(t *testing.T) {
			ta := setupApp(t, "n\ny\nn\nn\n", "", false)
			ta.GOOS = "darwin"
			ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
			ta.HostDoctor = macReport(openshell.DriverVM, func(r *openshell.DoctorReport) { r.CLIVersion = tc.version })
			ta.gateway.applyRes = &openshell.GatewayApplyResult{}
			runningOn(t, ta, 1)
			_ = ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true})
			has(t, ta.output(), "the gateway still runs the MicroVM driver")
			if tc.stale {
				has(t, ta.output(), "where no sandbox starts on a Mac")
				return
			}
			lacks(t, ta.output(), "where no sandbox starts on a Mac")
		})
	}
}
