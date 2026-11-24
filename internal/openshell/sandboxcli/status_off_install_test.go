// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-2024: `sandbox run` reads the same precedence as `sandbox status` and
// `sandbox doctor`. An allowed account on a computer whose OpenShell release
// runs no sandbox is told that, whether or not another account's gateway
// holds the ports: the retry hint cannot help while the install is old.
func TestRunNamesTheInstallReasonBeforeAnotherAccount(t *testing.T) {
	for _, tc := range []struct {
		name, managed string
		want          string
		lack          []string
	}{
		{"release runs no sandbox", prerequisiteJSON, "OpenShell 0.1.3 runs no DefenseClaw sandbox", []string{busyWords, "Try again when"}},
		{"OpenShell not installed", notInstalledJSON, "OpenShell is not installed", []string{busyWords, "Try again when"}},
		{"another account only", elsewhereJSON, busyWords, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withManagedHost(t)
			ta := newTestApp(t, "")
			ta.daemon.status.Enabled, ta.daemon.status.Available = true, false
			ta.daemon.status.GatewayElsewhere = "another account"
			ta.daemon.status.Reason = sandboxapi.AccountBusyMessage + " (one account at a time). Try again when that account has no sandbox running."
			ta.daemon.status.Managed = managedFromJSON(t, tc.managed)
			err := ta.Run(bg, RunOptions{Harness: "claude"})
			if err == nil {
				t.Fatal("run succeeded")
			}
			has(t, err.Error(), tc.want)
			lacks(t, err.Error(), tc.lack...)
		})
	}
}

// GAP-2023: while the organization has turned sandboxes off, the doctor's
// Sandbox driver row says so like every other row. The organization renders
// no OpenShell gateway configuration then, so a "not trusted" failure would
// send the user to an administrator step that cannot help.
func TestDoctorDriverRowSaysTheOrganizationTurnedSandboxesOff(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "gateway.toml")
	prevPaths, prevAdmin := managedRenderedGateway, managedAdminVMDriver
	t.Cleanup(func() { managedRenderedGateway, managedAdminVMDriver = prevPaths, prevAdmin })
	managedRenderedGateway = func() *openshell.RenderedPaths { return &openshell.RenderedPaths{TOML: missing} }
	managedAdminVMDriver = func(string) (string, []string) { return "/usr/local/libexec/openshell/openshell-driver-vm", nil }
	for _, tc := range []struct {
		name         string
		enabled      bool
		unavailable  string
		wantStatus   openshell.CheckStatus
		want, lack   string
		wantNoFixRow bool
	}{
		{"organization off", false, sandboxapi.OrganizationOffReason, openshell.StatusSkip, "turned off by your organization", "not trusted", true},
		// The same render in a computer the organization runs sandboxes on
		// still fails the row: the check is untouched.
		{"organization on", true, "", openshell.StatusFail, "not trusted", "turned off by your organization", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withManagedHost(t)
			ta, _ := launchAgentDoctorFixture(t, "", errors.New("exit status 113"))
			ta.daemon.status.Enabled, ta.daemon.status.Available = tc.enabled, tc.enabled
			m := vmPrerequisiteStatus("none")
			m.Unavailable = tc.unavailable
			ta.daemon.status.Managed = m
			row := ta.runDoctor(bg).Get("managed-driver")
			if row == nil || row.Status != tc.wantStatus || (tc.wantNoFixRow && row.Fix != nil) {
				t.Fatalf("Sandbox driver row = %+v", row)
			}
			if !strings.Contains(row.Detail, tc.want) || strings.Contains(row.Detail, tc.lack) {
				t.Fatalf("Sandbox driver detail = %q, want %q and not %q", row.Detail, tc.want, tc.lack)
			}
		})
	}
}
