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
// and restart refusal names the restart route (Setup /repair), not only the
// status command.
func TestManagedWindowsGatewayRefusalNamesTheRestartRoute(t *testing.T) {
	previous := managedHostWindowsStandalone
	t.Cleanup(func() { managedHostWindowsStandalone = previous })
	managedHostWindowsStandalone = func() (string, bool) { return `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise`, true }
	t.Setenv(managed.DeploymentModeEnv, "")
	err := refusePerUserGatewayOnManagedHost()
	if err == nil {
		t.Fatal("managed Windows computer: per-user gateway not refused")
	}
	for _, want := range []string{"enterprise windows status --profile standalone", "DefenseClawSetup-Enterprise-Standalone-x64.exe /repair JSON=1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
}
