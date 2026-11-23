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
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// Every row `sandbox status`, `sandbox doctor`, `sandbox run`, `sandbox
// delete` and `sandbox activity -f` print about why sandboxes are off names
// only the reason that sandboxapi.Status.ManagedOff allows for the caller: the
// organization's switch, then the profile, then the install, then another
// account. One table, every kind and every row (GAP-2029 after GAP-2010, 2011,
// 2019, 2020, 2023, 2024: each live run found one more row that skipped it),
// and for each kind the status of the rows that read the kind, the doctor's
// exit code and verdict line, and its json ready flag (GAP-2036, GAP-2037).

// The phrases that identify a reason in a row, and the ones that say what
// sandboxes need or will do.
const (
	orgPhrase     = "turned off by your organization"
	profilePhrase = "doesn't allow sandboxes for your account"
	busyPhrase    = "another account"
	installPhrase = "runs no DefenseClaw sandbox"
	settingPhrase = "your organization manages this setting"
)

// needPhrases tell an account what its sandboxes need or what a run does: false
// for an account whose sandboxes are closed.
var needPhrases = []string{
	"which sandboxes on this computer need", "nothing to change for your sandboxes",
	"the first run builds it", "your agent images are built in it", "the administrator has turned sandboxes off",
	"no longer run sandboxes on this computer",
}

// offCase is one way sandboxes are off (or on) for a managed account.
type offCase struct {
	kind    sandboxapi.ManagedOffKind
	name    string
	enabled bool
	// elsewhere is the other account's gateway; port a port another program holds.
	elsewhere string
	managed   string
	port      bool
	// allow are the reasons that may appear; every other reason phrase is
	// forbidden.
	allow []string
	// closed kinds are told nothing about what sandboxes need.
	closed bool
	// daemonStatus is the DefenseClaw daemon row's status ("": not asserted),
	// daemonHas a phrase its detail has, daemonNot one it must not have.
	daemonStatus openshell.CheckStatus
	daemonHas    string
	daemonNot    string
}

var offCases = []offCase{
	{kind: sandboxapi.ManagedOffNone, name: "none", enabled: true, elsewhere: "", managed: elsewhereJSON},
	{kind: sandboxapi.ManagedOffOrganization, name: "organization", enabled: false, elsewhere: "another account", managed: orgOffJSON,
		allow: []string{orgPhrase}, closed: true, daemonStatus: openshell.StatusSkip, daemonHas: orgPhrase},
	// The organization off with openshell.enabled still true (S1, D1).
	{kind: sandboxapi.ManagedOffOrganization, name: "organization-enabled", enabled: true, elsewhere: "another account", managed: orgOffJSON,
		allow: []string{orgPhrase}, closed: true, daemonStatus: openshell.StatusSkip, daemonHas: orgPhrase},
	{kind: sandboxapi.ManagedOffProfile, name: "profile", enabled: true, elsewhere: "another account", managed: deniedPrerequisiteJSON,
		allow: []string{profilePhrase}, closed: true, daemonStatus: openshell.StatusSkip, daemonHas: profilePhrase},
	{kind: sandboxapi.ManagedOffUnavailable, name: "install", enabled: true, elsewhere: "another account", managed: prerequisiteJSON,
		allow: []string{installPhrase}, daemonStatus: openshell.StatusSkip, daemonHas: "see Sandbox runtime"},
	// An install reason outranks a port another program holds (D1).
	{kind: sandboxapi.ManagedOffUnavailable, name: "install-port", enabled: true, managed: prerequisiteJSON, port: true,
		allow: []string{installPhrase}, daemonStatus: openshell.StatusSkip, daemonHas: "see Sandbox runtime", daemonNot: "occupied"},
	{kind: sandboxapi.ManagedOffElsewhere, name: "elsewhere", enabled: true, elsewhere: "another account", managed: elsewhereJSON,
		allow: []string{busyPhrase}, daemonStatus: openshell.StatusWarn, daemonHas: busyPhrase},
	{kind: sandboxapi.ManagedOffSetting, name: "setting", enabled: false, managed: elsewhereJSON,
		closed: true, daemonStatus: openshell.StatusSkip, daemonHas: settingPhrase},
}

// offFixture is a managed account of kind tc on goos. dockerDown makes the
// Docker engine answer an error; driverFail makes the account's MicroVM driver
// the administrator installs missing.
func offFixture(t *testing.T, tc offCase, goos string, dockerDown, driverFail bool) *testApp {
	t.Helper()
	ta, _ := launchAgentDoctorFixture(t, "", nil)
	ta.GOOS = goos
	ta.daemon.status.Enabled, ta.daemon.status.Available = tc.enabled, false
	ta.daemon.status.GatewayElsewhere = tc.elsewhere
	ta.daemon.status.Managed = managedFromJSON(t, tc.managed)
	if tc.port {
		ta.daemon.status.PortConflict = &sandboxapi.PortConflict{Name: "ingress"}
	}
	if driverFail {
		ta.daemon.status.Managed.Driver, ta.daemon.status.Managed.InstallMode = "vm", "prerequisite"
		withAdminVMDriverAt(t, "")
	}
	if got := ta.daemon.status.ManagedOff(); got != tc.kind {
		t.Fatalf("the fixture is kind %d, want %d", got, tc.kind)
	}
	ta.DockerEngine = func(context.Context) (string, error) {
		if dockerDown {
			return "", errors.New("docker down")
		}
		return "Docker Desktop", nil
	}
	ta.HostDoctor = func(_ context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		d.DockerGroup = func() (bool, bool, error) { return true, true, nil }
		return hostReport(nil)(bg, d)
	}
	return ta
}

// doctorJSON runs `sandbox doctor --json`: its exit error, and what a script
// reads (ok, ready) with the status of every row by title.
func doctorJSON(t *testing.T, ta *testApp) (ok, ready bool, rows map[string]openshell.CheckStatus, err error) {
	t.Helper()
	ta.out.Reset()
	err = ta.RunDoctor(bg, DoctorOptions{Output: OutputJSON})
	var doc struct {
		OK     bool `json:"ok"`
		Ready  bool `json:"ready"`
		Checks []struct {
			Title  string                `json:"title"`
			Status openshell.CheckStatus `json:"status"`
		} `json:"checks"`
	}
	if jerr := json.Unmarshal(ta.out.Bytes(), &doc); jerr != nil {
		t.Fatalf("doctor --json is not json: %v\n%s", jerr, ta.output())
	}
	rows = map[string]openshell.CheckStatus{}
	for _, c := range doc.Checks {
		rows[c.Title] = c.Status
	}
	return doc.OK, doc.Ready, rows, err
}

// doctorVerdict runs `sandbox doctor` and returns its exit error and the last
// line it prints.
func doctorVerdict(ta *testApp) (string, error) {
	ta.out.Reset()
	err := ta.RunDoctor(bg, DoctorOptions{})
	lines := strings.Split(strings.TrimSpace(ta.output()), "\n")
	return lines[len(lines)-1], err
}

func TestEveryOffRowNamesOnlyTheReasonItsKindAllows(t *testing.T) {
	withManagedHost(t)
	for _, tc := range offCases {
		for _, goos := range []string{"linux", "darwin"} {
			t.Run(tc.name+"/"+goos, func(t *testing.T) {
				ta := offFixture(t, tc, goos, false, false)
				rows := map[string]string{}
				ta.printStatus(&ta.daemon.status)
				rows["status"] = ta.output()
				// The Sandboxes row never says "on" for an account the organization,
				// its profile or a setting closed (S1: the organization's switch off
				// with enabled=true said on); an install reason or another account's
				// gateway can clear, and the OpenShell row says what is wrong.
				for _, line := range strings.Split(rows["status"], "\n") {
					if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Sandboxes"); ok {
						if on := strings.TrimSpace(rest) == "on"; on == tc.closed {
							t.Errorf("status Sandboxes row %q while the kind is %s", strings.TrimSpace(line), tc.name)
						}
					}
				}
				for _, c := range ta.runDoctor(bg).Checks {
					text := c.Detail
					if c.Fix != nil {
						text += " " + c.Fix.Summary
					}
					rows["doctor: "+c.Title] = text
					if c.Title != "DefenseClaw daemon" {
						continue
					}
					if tc.daemonStatus != "" && c.Status != tc.daemonStatus {
						t.Errorf("daemon row is %s (%s), want %s", c.Status, c.Detail, tc.daemonStatus)
					}
					if tc.daemonHas != "" && !strings.Contains(c.Detail, tc.daemonHas) {
						t.Errorf("daemon row %q does not say %q", c.Detail, tc.daemonHas)
					}
					if tc.daemonNot != "" && strings.Contains(c.Detail, tc.daemonNot) {
						t.Errorf("daemon row %q says %q", c.Detail, tc.daemonNot)
					}
				}
				if tc.kind != sandboxapi.ManagedOffNone {
					err := ta.Run(bg, RunOptions{Harness: "claude"})
					if err == nil {
						t.Fatal("run: not refused")
					}
					rows["run"] = err.Error()
					// `sandbox activity -f` after the daemon went away names the
					// one reason `sandbox status` does.
					err = ta.awaitDaemon(bg, ta.API)
					if err == nil {
						t.Fatal("activity -f: the feed did not stop")
					}
					rows["activity -f"] = err.Error()
					if want := strings.TrimRight(ta.daemon.status.OffMessage(), ". "); !strings.Contains(err.Error(), want) {
						t.Errorf("activity -f says %q, want the reason %q", err, want)
					}
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

// While sandboxes are off for the account by any reason ManagedOff names,
// `sandbox run` refuses; the doctor then never says ready, exits 1 and names
// that reason in its verdict, whichever rows it skipped as not needed: not with
// Docker down, not with a failing driver, not for a setting the organization
// manages (GAP-2036). The rows that are not needed say so; rows that can clear
// (the install, another account's gateway) keep their own status.
func TestDoctorIsNeverReadyWhileSandboxesAreOffForTheAccount(t *testing.T) {
	withManagedHost(t)
	for _, tc := range offCases {
		if tc.kind == sandboxapi.ManagedOffNone {
			continue
		}
		for _, goos := range []string{"linux", "darwin"} {
			for _, dockerDown := range []bool{false, true} {
				for _, driverFail := range []bool{false, true} {
					name := tc.name + "/" + goos
					if dockerDown {
						name += "/docker-down"
					}
					if driverFail {
						name += "/driver-fails"
					}
					t.Run(name, func(t *testing.T) {
						ta := offFixture(t, tc, goos, dockerDown, driverFail)
						reason := ta.daemon.status.OffMessage()
						verdict, err := doctorVerdict(ta)
						wantExit(t, err, 1)
						if want := "✗ not ready for sandboxes: " + reason; !strings.HasSuffix(verdict, want) {
							t.Errorf("verdict = %q, want it to end %q", verdict, want)
						}
						ok, ready, rows, err := doctorJSON(t, ta)
						wantExit(t, err, 1)
						if ok || ready {
							t.Errorf("json ok=%v ready=%v, want both false (the exit status is 1)", ok, ready)
						}
						if tc.closed {
							// Not needed: neither Docker nor a driver is the blocker.
							titles := []string{"Sandbox driver", "Harness images"}
							if goos == "darwin" {
								// The Mac's Docker row; on Linux "Docker" is the host's own check.
								titles = append(titles, "Docker")
							}
							for _, title := range titles {
								if st, found := rows[title]; found && st != openshell.StatusSkip {
									t.Errorf("row %q is %s while sandboxes are closed for the account, want skip", title, st)
								}
							}
						}
						if driverFail && !tc.closed {
							if rows["Sandbox driver"] != openshell.StatusFail {
								t.Errorf("row Sandbox driver is %s, want fail: nothing closes sandboxes for the account yet, so the missing driver stays", rows["Sandbox driver"])
							}
						}
					})
				}
			}
		}
	}
}
