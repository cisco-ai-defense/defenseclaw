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
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// managedFromJSON decodes a managed status the way the CLI reads the daemon's
// answer, so a field the daemon sends is exercised through the wire.
func managedFromJSON(t *testing.T, doc string) *sandboxapi.ManagedStatus {
	t.Helper()
	m := &sandboxapi.ManagedStatus{}
	if err := json.Unmarshal([]byte(doc), m); err != nil {
		t.Fatal(err)
	}
	return m
}

// GAP-1987: openshell.enabled false is the organization's switch. It holds
// for every account, so status and run say so even while another account's
// gateway holds the port.
func TestStatusAndRunSayTheOrganizationTurnedSandboxesOffBeforeAnotherAccount(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Enabled = false
	ta.daemon.status.GatewayElsewhere = "another account"
	ta.daemon.status.Managed = managedFromJSON(t, `{"profile":"contractors","allowed":true,"request_access":"it-security@example.com","unavailable":"sandboxes are turned off by your organization"}`)
	ta.printStatus(&ta.daemon.status)
	out := ta.output()
	has(t, out, "turned off by your organization")
	lacks(t, out, "another account is using")

	ta.fresh()
	err := ta.Run(bg, RunOptions{Harness: "claude"})
	if err == nil || !strings.Contains(err.Error(), "turned off by your organization") || strings.Contains(err.Error(), "another account is using") {
		t.Fatalf("run with sandboxes turned off and another account's gateway = %v", err)
	}
}

// GAP-1985: a profile with sandbox.allowed false is refused by `sandbox run`;
// status must not say "on" for that account, and names the profile.
func TestStatusSaysSandboxesAreNotAllowedForAProfileThatRefusesThem(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Enabled, ta.daemon.status.Available = true, true
	ta.daemon.status.Managed = managedFromJSON(t, `{"profile":"no-sandbox","allowed":false,"account_denied":true,"denied_harnesses":["claudecode"],"request_access":"it-security@example.com"}`)
	ta.printStatus(&ta.daemon.status)
	out := ta.output()
	has(t, out, "your organization doesn't allow sandboxes for your account", "no-sandbox")
	lacks(t, out, "Sandboxes       on")
}

// An account that the profile allows, or whose policy could not be read, is
// still "on".
func TestStatusStaysOnWhenNoProfileRefusesTheAccount(t *testing.T) {
	withManagedHost(t)
	for name, doc := range map[string]string{
		"allowed":       `{"profile":"staff","allowed":true}`,
		"policy unread": `{"profile":"","allowed":false,"policy_unread":"the managed gateway did not answer"}`,
	} {
		ta := newTestApp(t, "")
		ta.daemon.status.Enabled, ta.daemon.status.Available = true, true
		ta.daemon.status.Managed = managedFromJSON(t, doc)
		ta.printStatus(&ta.daemon.status)
		has(t, ta.output(), "Sandboxes       on")
		_ = name
	}
}

// GAP-1993: the Runtime row names the installed OpenShell, and the required
// release apart from it when they differ.
func TestStatusRuntimeRowNamesInstalledAndRequiredOpenShell(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.daemon.status.Managed = managedFromJSON(t, `{"profile":"staff","allowed":true,"install_mode":"prerequisite","openshell_version":"0.1.6","installed_openshell_version":"0.1.3"}`)
	ta.printStatus(&ta.daemon.status)
	has(t, ta.output(), "OpenShell 0.1.3 installed, 0.1.6 required, prerequisite install")
	lacks(t, ta.output(), "OpenShell 0.1.6, prerequisite")

	// Same release, or no installed one known: the single form.
	for doc, want := range map[string]string{
		`{"profile":"staff","allowed":true,"openshell_version":"0.1.3","installed_openshell_version":"0.1.3"}`: "Runtime         OpenShell 0.1.3",
		`{"profile":"staff","allowed":true,"openshell_version":"0.1.3"}`:                                       "Runtime         OpenShell 0.1.3",
	} {
		ta := newTestApp(t, "")
		ta.daemon.status.Managed = managedFromJSON(t, doc)
		ta.printStatus(&ta.daemon.status)
		has(t, ta.output(), want)
		lacks(t, ta.output(), "installed,")
	}
}
