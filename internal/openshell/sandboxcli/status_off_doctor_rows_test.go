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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The doctor's Organization policy and Sandbox runtime rows read the one
// precedence of sandboxapi.Status.ManagedOff, as the Sandboxes row of status,
// the daemon row and the refusal of `sandbox run` do: the organization's
// switch first, then the profile, then the install, then another account.

// deniedPrerequisiteJSON is a profile that denies sandboxes on an install
// that also runs none (a prerequisite release): the profile is the reason.
const deniedPrerequisiteJSON = `{"profile":"b18-deny","allowed":false,"account_denied":true,"denied_harnesses":["claudecode"],` +
	`"request_access":"it-security@example.com","openshell_version":"0.1.6","installed_openshell_version":"0.1.3",` +
	`"unavailable":"OpenShell 0.1.3 runs no DefenseClaw sandbox: OpenShell 0.1.6 or later is required"}`

func doctorRowsFor(t *testing.T, enabled bool, elsewhere, managed string) (admin, runtime *openshell.Check) {
	t.Helper()
	ta, _ := launchAgentDoctorFixture(t, "", errors.New("exit status 113"))
	ta.daemon.status.Enabled, ta.daemon.status.Available = enabled, false
	ta.daemon.status.GatewayElsewhere = elsewhere
	ta.daemon.status.Managed = managedFromJSON(t, managed)
	rep := ta.runDoctor(bg)
	admin, runtime = rep.Get(CheckIDAdmin), rep.Get(CheckIDManagedRuntime)
	if admin == nil || runtime == nil {
		t.Fatalf("doctor rows: Organization policy = %+v, Sandbox runtime = %+v", admin, runtime)
	}
	return admin, runtime
}

// GAP-2019: a denied account's Sandbox runtime row names the profile, not
// the docker group or the install reason.
func TestDoctorRuntimeRowOfADeniedAccountNamesTheProfile(t *testing.T) {
	for _, tc := range []struct{ name, managed string }{
		{"denied and not in the docker group", deniedDockerJSON},
		{"denied on a prerequisite release", deniedPrerequisiteJSON},
		{"denied only", deniedJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			admin, runtime := doctorRowsFor(t, true, "", tc.managed)
			if runtime.Status == openshell.StatusFail || runtime.Fix != nil {
				t.Fatalf("Sandbox runtime row = %+v, want no failure for a denied account", runtime)
			}
			has(t, runtime.Detail, "doesn't allow sandboxes for your account", "profile b18-deny")
			lacks(t, runtime.Detail, "docker group", "OpenShell 0.1.3 runs no", busyWords)
			// The denial is failed once, by the policy row.
			if admin.Status != openshell.StatusFail {
				t.Fatalf("Organization policy row = %+v, want the one failure", admin)
			}
			has(t, admin.Detail, "doesn't allow sandboxes")
		})
	}
}

// GAP-2020: with the organization's switch off, a denying profile is not
// named by the Organization policy row; the organization-off sentence is.
func TestDoctorPolicyRowUnderOrganizationOffDefersToTheOrganization(t *testing.T) {
	for _, elsewhere := range []string{"", "another account"} {
		admin, runtime := doctorRowsFor(t, false, elsewhere, orgOffJSON)
		if admin.Status == openshell.StatusFail {
			t.Fatalf("Organization policy row = %+v, want no failure under organization off", admin)
		}
		has(t, admin.Detail, "turned off by your organization")
		lacks(t, admin.Detail, "doesn't allow sandboxes", busyWords)
		// The Sandbox runtime row carries the organization's sentence and
		// the contact, once.
		if runtime.Status != openshell.StatusFail {
			t.Fatalf("Sandbox runtime row = %+v", runtime)
		}
		has(t, runtime.Detail, "turned off by your organization")
	}
}

// With nothing before it, a profile that denies sandboxes is still failed by
// the Organization policy row.
func TestDoctorPolicyRowStillNamesTheProfileDenial(t *testing.T) {
	admin, _ := doctorRowsFor(t, true, "another account", deniedJSON)
	if admin.Status != openshell.StatusFail {
		t.Fatalf("Organization policy row = %+v", admin)
	}
	has(t, admin.Detail, "organization profile b18-deny", "doesn't allow sandboxes for claudecode")
}

// An install reason still fails the Sandbox runtime row when the profile
// allows sandboxes.
func TestDoctorRuntimeRowStillNamesTheInstallReason(t *testing.T) {
	_, runtime := doctorRowsFor(t, true, "another account", prerequisiteJSON)
	if runtime.Status != openshell.StatusFail {
		t.Fatalf("Sandbox runtime row = %+v", runtime)
	}
	has(t, runtime.Detail, "OpenShell 0.1.3 runs no DefenseClaw sandbox")
}
