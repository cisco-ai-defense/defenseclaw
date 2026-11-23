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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Every row `sandbox status`, `sandbox doctor`, `sandbox run` and `sandbox
// delete` print about why sandboxes are off names only the reason that
// sandboxapi.Status.ManagedOff allows for the caller: the organization's
// switch, then the profile, then the install, then another account. One
// table, every kind and every row (GAP-2029 after GAP-2010, 2011, 2019, 2020,
// 2023, 2024: each live run found one more row that skipped it).

// The phrases that identify a reason in a row, and the ones that say what
// sandboxes need or will do.
const (
	orgPhrase     = "turned off by your organization"
	profilePhrase = "doesn't allow sandboxes for your account"
	busyPhrase    = "another account"
	installPhrase = "runs no DefenseClaw sandbox"
)

// needPhrases tell an account what its sandboxes need or what a run does: false
// for an account whose sandboxes are closed.
var needPhrases = []string{
	"which sandboxes on this computer need", "nothing to change for your sandboxes",
	"the first run builds it", "your agent images are built in it", "the administrator has turned sandboxes off",
	"no longer run sandboxes on this computer",
}

func TestEveryOffRowNamesOnlyTheReasonItsKindAllows(t *testing.T) {
	withManagedHost(t)
	for _, tc := range []struct {
		kind      sandboxapi.ManagedOffKind
		name      string
		enabled   bool
		elsewhere string
		managed   string
		// reasons that may appear; every other reason phrase is forbidden.
		allow []string
		// closed kinds are told nothing about what sandboxes need.
		closed bool
	}{
		{sandboxapi.ManagedOffNone, "none", true, "", elsewhereJSON, nil, false},
		{sandboxapi.ManagedOffOrganization, "organization", false, "another account", orgOffJSON, []string{orgPhrase}, true},
		{sandboxapi.ManagedOffProfile, "profile", true, "another account", deniedPrerequisiteJSON, []string{profilePhrase}, true},
		{sandboxapi.ManagedOffUnavailable, "install", true, "another account", prerequisiteJSON, []string{installPhrase}, false},
		{sandboxapi.ManagedOffElsewhere, "elsewhere", true, "another account", elsewhereJSON, []string{busyPhrase}, false},
		{sandboxapi.ManagedOffSetting, "setting", false, "", elsewhereJSON, nil, true},
	} {
		for _, goos := range []string{"linux", "darwin"} {
			t.Run(tc.name+"/"+goos, func(t *testing.T) {
				ta, _ := launchAgentDoctorFixture(t, "", nil)
				ta.GOOS = goos
				ta.daemon.status.Enabled, ta.daemon.status.Available = tc.enabled, false
				ta.daemon.status.GatewayElsewhere = tc.elsewhere
				ta.daemon.status.Managed = managedFromJSON(t, tc.managed)
				if got := ta.daemon.status.ManagedOff(); got != tc.kind {
					t.Fatalf("the fixture is kind %d, want %d", got, tc.kind)
				}
				ta.DockerEngine = func(context.Context) (string, error) { return "Docker Desktop", nil }
				ta.HostDoctor = func(_ context.Context, d *openshell.Doctor) *openshell.DoctorReport {
					d.DockerGroup = func() (bool, bool, error) { return true, true, nil }
					return hostReport(nil)(bg, d)
				}
				rows := map[string]string{}
				ta.printStatus(&ta.daemon.status)
				rows["status"] = ta.output()
				for _, c := range ta.runDoctor(bg).Checks {
					text := c.Detail
					if c.Fix != nil {
						text += " " + c.Fix.Summary
					}
					rows["doctor: "+c.Title] = text
				}
				if tc.kind != sandboxapi.ManagedOffNone {
					err := ta.Run(bg, RunOptions{Harness: "claude"})
					if err == nil {
						t.Fatal("run: not refused")
					}
					rows["run"] = err.Error()
				}
				if !tc.enabled {
					// `sandbox delete` of a kept sandbox needs the account gateway.
					err := ta.Delete(bg, DeleteOptions{Names: []string{"kept"}, Yes: true})
					if err == nil {
						t.Fatal("delete: not refused")
					}
					rows["delete"] = err.Error()
				}
				for row, text := range rows {
					for _, reason := range []string{orgPhrase, profilePhrase, busyPhrase, installPhrase} {
						allowed := false
						for _, a := range tc.allow {
							allowed = allowed || a == reason
						}
						if !allowed && strings.Contains(text, reason) {
							t.Errorf("%s names %q while the reason is %s:\n%s", row, reason, tc.name, text)
						}
					}
					if tc.closed {
						for _, need := range needPhrases {
							if strings.Contains(text, need) {
								t.Errorf("%s says %q while sandboxes are closed for the account (%s):\n%s", row, need, tc.name, text)
							}
						}
					}
				}
			})
		}
	}
}
