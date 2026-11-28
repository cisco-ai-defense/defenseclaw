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

// rel-1-0-10:GAP-1786: a Mac on OpenShell 0.1.6 to 0.1.8 that setup
// upgrades in the same run was asked the MicroVM question with only the
// claim that MicroVMs do not start, though the upgrade setup offers next
// installs a release that starts them. Setup says so before it asks.
func TestGAP1786MacMicroVMQuestionNamesTheUpgradeThatStartsThem(t *testing.T) {
	ta := setupApp(t, "\nn\n", "", false)
	ta.GOOS = "darwin"
	ta.gateway.state.Env = map[string]string{openshell.EnvTelemetryEnabled: "false"}
	ta.gateway.state.TOMLPath = filepath.Join(ta.home, ".config", "openshell", "gateway.toml")
	ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) {
		r.CLIVersion = "0.1.8"
		c := r.Get(openshell.CheckIDCLI)
		c.Status, c.Detail = openshell.StatusWarn, "OpenShell 0.1.8; setup upgrades it to "+openshell.InstallerVersion
	})
	ta.gateway.applyRes = &openshell.GatewayApplyResult{}
	_, _ = useGateway(ta)
	_ = ta.Setup(bg, SetupOptions{SkipImages: true, NoWrappers: true})
	has(t, ta.output(), "OpenShell "+openshell.InstallerVersion+" starts MicroVM sandboxes on a Mac: setup offers the upgrade from 0.1.8 after this question",
		"Run sandboxes in OpenShell MicroVMs? ")
}
