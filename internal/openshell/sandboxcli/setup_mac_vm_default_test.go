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

// TestSetupMovesAMacGatewayOffTheVMDriver (GAP-1704): a Mac whose OpenShell
// gateway already runs the vm driver (the upstream default of a fresh
// OpenShell) was never asked the MicroVM question, and setup, --yes
// included, wrote compute_driver = "vm", on which no sandbox starts on a
// Mac. It is asked like any Mac: the default, no, and --yes plan the
// docker driver in the same plan and restart; only a yes keeps vm.
func TestSetupMovesAMacGatewayOffTheVMDriver(t *testing.T) {
	const question = `Run sandboxes in OpenShell MicroVMs? This gateway runs the MicroVM driver, but on a Mac MicroVMs do not start until OpenShell fixes it; ` +
		`no switches it to the docker driver, which runs sandboxes on Docker Desktop 29.8 or newer (the run-time Landlock check decides) ` +
		`(sets compute_driver = "docker" in ~/.config/openshell/gateway.toml and restarts the gateway; sandboxes made on the MicroVM driver cannot start after the switch) [y/N]`
	for _, tc := range []struct {
		name  string
		input string
		yes   bool
		want  openshell.ComputeDriver
	}{
		{"no", "n\ny\n", false, openshell.DriverDocker},
		{"default", "\ny\n", false, openshell.DriverDocker},
		{"--yes", "", true, openshell.DriverDocker},
		{"yes", "y\n", false, openshell.DriverVM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta := setupApp(t, tc.input, "", false)
			if tc.yes {
				ta.IO.TTY, ta.IO.InTTY = false, false
			}
			ta.GOOS = "darwin"
			ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
			ta.gateway.state.TOMLPath = filepath.Join(ta.home, ".config", "openshell", "gateway.toml")
			ta.HostDoctor = macReport(openshell.DriverVM, nil)
			ta.gateway.applyRes = &openshell.GatewayApplyResult{}
			_, _ = useGateway(ta)
			ta.ok(t, ta.Setup(bg, SetupOptions{Yes: tc.yes, SkipImages: true, NoWrappers: true}))
			p := ta.gateway.planned
			if len(p) != 1 || p[0].ComputeDriver != tc.want || ta.gateway.applied != 1 {
				t.Fatalf("gateway plans = %+v, applied %d, want compute_driver %q:\n%s", p, ta.gateway.applied, tc.want, ta.output())
			}
			if !tc.yes {
				has(t, ta.output(), question)
			}
			if tc.want == openshell.DriverDocker {
				if p[0].VMIdentity != nil || p[0].VMResources != nil {
					t.Fatalf("docker plan carries MicroVM settings: %+v", p[0])
				}
				has(t, ta.output(), "✓ gateway configured and restarted", "Done →")
				lacks(t, ta.output(), `compute_driver = "vm"`, "it runs sandboxes in OpenShell MicroVMs", "every run works on a copy (the MicroVM driver")
				return
			}
			has(t, ta.output(), "✓ gateway configured and restarted: it runs sandboxes in OpenShell MicroVMs")
		})
	}
}

// TestSetupSaysAMacGatewayLeftOnTheVMDriverIsNotReady (GAP-1704): the
// switch to docker restarts the gateway, which --yes does not give while a
// sandbox is on it. Setup then names the MicroVM sandboxes the switch
// strands, applies nothing, and ends not ready rather than done.
func TestSetupSaysAMacGatewayLeftOnTheVMDriverIsNotReady(t *testing.T) {
	ta := setupApp(t, "", "", false)
	ta.IO.TTY, ta.IO.InTTY = false, false
	ta.GOOS = "darwin"
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	ta.HostDoctor = macReport(openshell.DriverVM, nil)
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	runningOn(t, ta, 1)
	wantExit(t, ta.Setup(bg, SetupOptions{Yes: true, SkipImages: true, NoWrappers: true}), 1)
	if p := ta.gateway.planned; len(p) != 1 || p[0].ComputeDriver != openshell.DriverDocker || ta.gateway.applied != 0 || ta.gateway.restarts != 0 {
		t.Fatalf("plans %+v, applied %d, restarts %d", p, ta.gateway.applied, ta.gateway.restarts)
	}
	has(t, ta.output(), "applying this restarts the OpenShell gateway on the docker driver: the 1 sandbox on it (dc-claude-theirs-a) were made on the MicroVM driver",
		"the gateway still runs the MicroVM driver, where no sandbox starts on a Mac; it runs sandboxes on the docker driver once it restarts on them",
		"not ready for sandboxes yet: the gateway still runs the MicroVM driver, where no sandbox starts on a Mac; restart it on the docker driver (`defenseclaw sandbox setup --restart-gateway`)")
	lacks(t, ta.output(), "Done →")
}
