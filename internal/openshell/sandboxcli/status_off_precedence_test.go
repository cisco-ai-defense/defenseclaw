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
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// One precedence decides why sandboxes are off or refused for a caller on a
// managed computer, for `sandbox status`, `sandbox doctor` and `sandbox run`:
// the organization's switch, then the caller's profile, then the install
// itself (OpenShell missing, or a release that runs no sandbox), then another
// account's gateway. Another account's use of the ports is only ever the
// reason when nothing before it is.

const (
	orgOffJSON = `{"profile":"b18-deny","allowed":false,"account_denied":true,"denied_harnesses":["claudecode"],` +
		`"request_access":"it-security@example.com","unavailable":"sandboxes are turned off by your organization"}`
	deniedJSON       = `{"profile":"b18-deny","allowed":false,"account_denied":true,"denied_harnesses":["claudecode"],"request_access":"it-security@example.com"}`
	deniedDockerJSON = `{"profile":"b18-deny","allowed":false,"account_denied":true,"denied_harnesses":["claudecode"],` +
		`"unavailable":"your account is not in the docker group"}`
	notInstalledJSON = `{"profile":"staff","allowed":true,"request_access":"it-security@example.com","unavailable":"OpenShell is not installed"}`
	prerequisiteJSON = `{"profile":"staff","allowed":true,"request_access":"it-security@example.com","openshell_version":"0.1.6","installed_openshell_version":"0.1.3",` +
		`"unavailable":"OpenShell 0.1.3 runs no DefenseClaw sandbox: OpenShell 0.1.6 or later is required"}`
	elsewhereJSON = `{"profile":"staff","allowed":true,"request_access":"it-security@example.com"}`
)

// busyWords are in every text that blames another account's sandboxes.
const busyWords = "another account is using"

// statusOutput is `sandbox status` of a managed computer whose daemon says
// enabled, with another account's gateway on the ports.
func statusOutput(t *testing.T, enabled bool, elsewhere, managed string) string {
	t.Helper()
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Enabled, ta.daemon.status.Available = enabled, false
	ta.daemon.status.GatewayElsewhere = elsewhere
	ta.daemon.status.Managed = managedFromJSON(t, managed)
	ta.printStatus(&ta.daemon.status)
	return ta.output()
}

func TestStatusOpenShellRowNamesTheRealReasonNotAnotherAccount(t *testing.T) {
	for _, tc := range []struct {
		name, managed string
		want, lack    []string
	}{
		{"account denied", deniedJSON,
			[]string{"Sandboxes       off for your account: your organization doesn't allow sandboxes for your account (profile b18-deny)"},
			[]string{busyWords, "clears when that account"}},
		// The profile outranks every install reason: a denied account is
		// not told about its docker group, or any other prerequisite.
		{"account denied and a prerequisite missing", deniedDockerJSON,
			[]string{"Sandboxes       off for your account"},
			[]string{busyWords, "docker group", "OpenShell       "}},
		{"OpenShell not installed", notInstalledJSON,
			[]string{"OpenShell       ", "OpenShell is not installed"},
			[]string{busyWords, "clears when that account"}},
		{"prerequisite release runs no sandbox", prerequisiteJSON,
			[]string{"OpenShell       ", "OpenShell 0.1.3 runs no DefenseClaw sandbox"},
			[]string{busyWords, "clears when that account"}},
		// Nothing before another account's gateway applies: it stays the reason.
		{"another account only", elsewhereJSON,
			[]string{"OpenShell       not available for your account right now: another account is using sandboxes"},
			nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := statusOutput(t, true, "another account", tc.managed)
			has(t, out, tc.want...)
			lacks(t, out, tc.lack...)
		})
	}
}

func TestStatusSaysTheOrganizationTurnedSandboxesOffBeforeEveryOtherReason(t *testing.T) {
	// Organization off together with a profile that denies sandboxes and
	// another account's gateway.
	out := statusOutput(t, false, "another account", orgOffJSON)
	has(t, out, "turned off by your organization")
	lacks(t, out, busyWords, "doesn't allow sandboxes for your account")
}

func TestDoctorDockerRowUnderEveryOffReasonNamesIt(t *testing.T) {
	for _, tc := range []struct {
		name               string
		enabled            bool
		elsewhere, managed string
		want               []string
		lack               []string
	}{
		{"organization off, another account and a denied profile", false, "another account", orgOffJSON,
			[]string{"turned off by your organization"}, []string{busyWords}},
		{"organization off alone", false, "", orgOffJSON,
			[]string{"turned off by your organization"}, []string{busyWords}},
		{"account denied, another account", true, "another account", deniedJSON,
			[]string{"doesn't allow sandboxes for your account"}, []string{busyWords}},
		{"OpenShell not installed, another account", true, "another account", notInstalledJSON,
			[]string{"see Sandbox runtime"}, []string{busyWords}},
		{"another account only", true, "another account", elsewhereJSON,
			[]string{busyWords}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta, _ := launchAgentDoctorFixture(t, "", errors.New("exit status 113"))
			ta.daemon.status.Enabled, ta.daemon.status.Available = tc.enabled, false
			ta.daemon.status.GatewayElsewhere = tc.elsewhere
			ta.daemon.status.Managed = managedFromJSON(t, tc.managed)
			ta.DockerEngine = func(context.Context) (string, error) { return "", errors.New("Cannot connect to the Docker daemon") }
			row := ta.runDoctor(bg).Get("managed-docker")
			if row == nil || row.Status != openshell.StatusSkip || row.Fix != nil {
				t.Fatalf("Docker row = %+v", row)
			}
			has(t, row.Detail, tc.want...)
			lacks(t, row.Detail, tc.lack...)
		})
	}
}

func TestDoctorDaemonRowNamesTheRealReasonNotAnotherAccount(t *testing.T) {
	for _, tc := range []struct {
		name, managed, want string
	}{
		{"account denied", deniedJSON, "doesn't allow sandboxes for your account"},
		{"OpenShell not installed", notInstalledJSON, "see Sandbox runtime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ta, _ := launchAgentDoctorFixture(t, "", errors.New("exit status 113"))
			ta.daemon.status.Enabled, ta.daemon.status.Available = true, false
			ta.daemon.status.GatewayElsewhere = "another account"
			ta.daemon.status.Managed = managedFromJSON(t, tc.managed)
			var detail string
			for _, c := range ta.runDoctor(bg).Checks {
				if strings.HasPrefix(c.Detail, "running") && strings.Contains(c.Title, "daemon") {
					detail = c.Detail
				}
			}
			has(t, detail, tc.want)
			lacks(t, detail, busyWords)
		})
	}
}
