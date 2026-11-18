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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
	"github.com/defenseclaw/defenseclaw/internal/substrate/fleet"
)

// fleetWithAdminList is the healthy fake cluster, with the real
// policy_conflict reader against a fake admin listener whose list of
// actors answers with conflictActors(); everyone says whether it marks the
// answer as every person's ("all": true, an administrator's all=1).
func fleetWithAdminList(t *testing.T, everyone bool) *fakeAdmin {
	t.Helper()
	real := substrateFleetEveryone
	fakeKubectl(t, nil)
	substrateFleetEveryone = real
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": func(w http.ResponseWriter, r *http.Request) {
		body := conflictActors()
		if everyone && r.URL.Query().Get("all") == "1" {
			body["all"] = true
		}
		jsonReply(body)(w, r)
	}}}
	useFakeAdmin(t, f)
	return f
}

// GAP-0398 (runbook J24): verify --json and status --cluster --json list
// each atespace with its agents in policy_conflict, read with the
// administrator's sign-in; the policy_conflict check fails and names the
// agent and the reset.
func TestSubstrateVerifyAndStatusCountPolicyConflicts(t *testing.T) {
	f := fleetWithAdminList(t, true)
	install := writeInstall(t, fleetInstallOK)
	out, _, err := runSubstrate(t, newSubstrateVerifyCmd(), "--install-file", install, "--json")
	if err == nil || cliusage.ExitCode(err) != 1 {
		t.Fatalf("verify with an agent in policy_conflict: exit %d (%v)\n%s", cliusage.ExitCode(err), err, out)
	}
	var doc fleet.VerifyDocument
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	pc := doc.PolicyConflicts
	if !pc.Read || pc.Agents == nil || *pc.Agents != 1 || len(pc.Atespaces) != 1 || pc.Atespaces[0] != (fleet.AtespaceConflicts{Atespace: "eng-web", Conflicts: 1}) {
		t.Fatalf("verify policy_conflicts = %+v\n%s", pc, out)
	}
	if !strings.Contains(out, `"conflicts": 1`) {
		t.Errorf("verify --json lacks conflicts: 1:\n%s", out)
	}
	var check fleet.Check
	for _, c := range doc.Checks {
		if c.ID == fleet.CheckPolicyConflicts {
			check = c
		}
	}
	if check.Status != fleet.Fail || !strings.Contains(check.Message, "eng-web/fix-tests-1 (3 foreign change(s)") ||
		!strings.Contains(check.Message, "defenseclaw substrate policy reset eng-web/fix-tests-1") {
		t.Errorf("policy_conflict check = %+v", check)
	}
	if !strings.Contains(strings.Join(f.calls, "\n"), "GET actors?all=1") {
		t.Errorf("the count did not list every person's agents: %v", f.calls)
	}

	out, _, err = runSubstrate(t, newSubstrateStatusCmd(), "--cluster", "--install-file", install, "--json")
	if err != nil {
		t.Fatalf("status --cluster: %v\n%s", err, out)
	}
	var st fleet.StatusDocument
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Atespaces) != 1 || st.Atespaces[0].Conflicts == nil || *st.Atespaces[0].Conflicts != 1 ||
		st.PolicyConflicts.Agents == nil || *st.PolicyConflicts.Agents != 1 {
		t.Fatalf("status atespaces %+v, policy_conflicts %+v\n%s", st.Atespaces, st.PolicyConflicts, out)
	}
	text, _, err := runSubstrate(t, newSubstrateStatusCmd(), "--cluster", "--install-file", install)
	if err != nil || !strings.Contains(text, "1 in policy_conflict") || !strings.Contains(text, "fail  policy_conflict") {
		t.Errorf("status --cluster text (%v):\n%s", err, text)
	}
}

// GAP-0398: a person's list is not the cluster's. Without an administrator's
// sign-in the count is unknown (null, no per-atespace number, the reason)
// and the check warns with how to sign in; verify does not fail on it.
func TestSubstrateVerifyPolicyConflictsUnknownWithoutAnAdministrator(t *testing.T) {
	fleetWithAdminList(t, false)
	install := writeInstall(t, fleetInstallOK)
	check := func(t *testing.T, reason, words string) {
		t.Helper()
		out, _, err := runSubstrate(t, newSubstrateVerifyCmd(), "--install-file", install, "--json")
		if err != nil {
			t.Fatalf("verify: %v\n%s", err, out)
		}
		var doc struct {
			PolicyConflicts map[string]any `json:"policy_conflicts"`
			Checks          []fleet.Check  `json:"checks"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatal(err)
		}
		pc := doc.PolicyConflicts
		if pc["read"] != false || pc["reason"] != reason || pc["agents"] != nil {
			t.Errorf("policy_conflicts = %v, want unknown (%s)", pc, reason)
		}
		if a, _ := pc["atespaces"].([]any); len(a) != 0 {
			t.Errorf("an unknown count lists atespaces: %v", pc)
		}
		for _, c := range doc.Checks {
			if c.ID == fleet.CheckPolicyConflicts && (c.Status != fleet.Warn || !strings.Contains(c.Message, words)) {
				t.Errorf("policy_conflict check = %+v, want warn %q", c, words)
			}
		}
		out, _, err = runSubstrate(t, newSubstrateStatusCmd(), "--cluster", "--install-file", install, "--json")
		if err != nil || strings.Contains(out, `"conflicts"`) {
			t.Errorf("status --cluster prints a count it did not read (%v):\n%s", err, out)
		}
	}
	check(t, fleet.ConflictsNotAdministrator, "you are not signed in as an administrator")

	old := substrateOpen
	substrateOpen = func(*cobra.Command, *substrateCommon) (*substrateSession, error) {
		return nil, errors.New("no cluster is configured")
	}
	t.Cleanup(func() { substrateOpen = old })
	check(t, fleet.ConflictsNoSignIn, "defenseclaw substrate login")
}

// doctor --install-file runs the fleet checks next to its own
// policy_conflict row: the row is there once (GAP-0398).
func TestSubstrateDoctorKubeChecksLeavePolicyConflictToDoctor(t *testing.T) {
	fakeKubectl(t, nil)
	f := &substrateClusterFlags{installFile: writeInstall(t, fleetInstallOK), namespace: "defenseclaw-system",
		substrateNS: "ate-system", timeout: 10 * time.Second}
	for _, c := range doctorKubeChecks(context.Background(), f) {
		if c.ID == fleet.CheckPolicyConflicts {
			t.Errorf("doctor --install-file has a second policy_conflict row: %+v", c)
		}
	}
}

// GAP-0398: doctor --cluster as a person does not report the cluster as
// free of conflicts from the person's own agents: it warns that the
// cluster's agents were not read.
func TestSubstrateDoctorClusterAsAPersonSaysTheClusterWasNotRead(t *testing.T) {
	f := newSubAdminFake(t)
	c := f.context()
	subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, c), nil }, nil)
	out, _, err := runSubAdmin(newSubstrateDoctorCmd(), "--cluster")
	if err != nil {
		t.Fatalf("doctor --cluster: %v\n%s", err, out)
	}
	if !strings.Contains(out, "warn  policy_conflict") || !strings.Contains(out, "you are not signed in as an administrator") ||
		strings.Contains(out, "no agent in the cluster is in policy_conflict") {
		t.Errorf("doctor --cluster as a person:\n%s", out)
	}
}
