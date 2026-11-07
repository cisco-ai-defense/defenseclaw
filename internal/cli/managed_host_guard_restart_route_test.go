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

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0718: on a managed Windows computer the per-user gateway stop, start
// and restart refusal names the restart route, not only the status command.
// GAP-0095: the route is the installed CLI's repair by its full path. Setup
// is not installed on a managed computer, so the refusal named a file the
// administrator did not have.
func TestManagedWindowsGatewayRefusalNamesTheRestartRoute(t *testing.T) {
	previous := managedHostWindowsStandalone
	t.Cleanup(func() { managedHostWindowsStandalone = previous })
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	t.Setenv(managed.DeploymentModeEnv, "")
	err := refusePerUserGatewayOnManagedHost()
	if err == nil {
		t.Fatal("managed Windows computer: per-user gateway not refused")
	}
	for _, want := range []string{
		"enterprise windows status --profile standalone",
		"and restart or repair the managed gateway with " + windowsEnterpriseAdminCommand("repair") + " from the same prompt",
		"from an elevated PowerShell prompt",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "DefenseClawSetup") || strings.Contains(err.Error(), "/repair JSON=1") {
		t.Errorf("refusal %q still sends the administrator to a Setup that is not installed", err)
	}
	if problems := managedWindowsCommandProblems(err.Error()); len(problems) != 0 {
		t.Errorf("refusal names commands that do not run as typed %q", problems)
	}
}
