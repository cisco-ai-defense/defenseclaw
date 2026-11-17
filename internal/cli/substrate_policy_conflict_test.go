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
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// conflictActors is a list answer with one agent in policy_conflict, as the
// gateway sends it (GAP-0398).
func conflictActors() map[string]any {
	return map[string]any{"actors": []map[string]any{
		{"atespace": "eng-web", "name": "fix-tests-1", "uid": "u1", "profile": "eng", "connector": "claudecode", "state": "running",
			"created_at": time.Now().Add(-5 * time.Minute),
			"policy_conflict": map[string]any{"since": "2026-11-17T15:40:00Z", "reverts": 3,
				"fix": "defenseclaw substrate policy reset eng-web/fix-tests-1"}},
		{"atespace": "eng-web", "name": "calm-1", "uid": "u2", "profile": "eng", "connector": "codex", "state": "running",
			"created_at": time.Now().Add(-5 * time.Minute)},
	}}
}

// GAP-0398: list, list --json and status NAME show policy_conflict and the
// reset that clears it; an agent that is not in conflict shows nothing.
func TestSubstrateListAndStatusShowPolicyConflict(t *testing.T) {
	f := &fakeAdmin{h: map[string]func(http.ResponseWriter, *http.Request){"GET actors": jsonReply(conflictActors())}}
	useFakeAdmin(t, f)
	out, _, err := runSubstrate(t, newSubstrateListCmd())
	if err != nil {
		t.Fatal(err)
	}
	var conflictRow, calmRow string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.Contains(line, "eng-web/fix-tests-1"):
			conflictRow = line
		case strings.Contains(line, "eng-web/calm-1"):
			calmRow = line
		}
	}
	if !strings.Contains(conflictRow, "running, policy_conflict") {
		t.Errorf("list row of the agent in conflict = %q\n%s", conflictRow, out)
	}
	if calmRow == "" || strings.Contains(calmRow, "policy_conflict") {
		t.Errorf("list row of the calm agent = %q\n%s", calmRow, out)
	}

	jsonOut, _, err := runSubstrate(t, newSubstrateListCmd(), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Actors []map[string]any `json:"actors"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &doc); err != nil || len(doc.Actors) != 2 {
		t.Fatalf("list --json = %v\n%s", err, jsonOut)
	}
	pc, _ := doc.Actors[0]["policy_conflict"].(map[string]any)
	if pc == nil || pc["reverts"] != float64(3) {
		t.Errorf("list --json policy_conflict = %v\n%s", doc.Actors[0], jsonOut)
	}
	if _, has := doc.Actors[1]["policy_conflict"]; has {
		t.Errorf("list --json shows a conflict on the calm agent:\n%s", jsonOut)
	}

	out, _, err = runSubstrate(t, newSubstrateStatusCmd(), "fix-tests-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Policy:    policy_conflict since 2026-11-17T15:40:00Z", "3 foreign change(s)",
		"defenseclaw substrate policy reset eng-web/fix-tests-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	out, _, err = runSubstrate(t, newSubstrateStatusCmd(), "calm-1")
	if err != nil || strings.Contains(out, "policy_conflict") {
		t.Errorf("status of the calm agent = %q, %v", out, err)
	}
}

// GAP-0398: doctor --cluster fails for an agent in policy_conflict, names the
// number of foreign changes and the reset; without --cluster it warns.
func TestSubstrateDoctorNamesPolicyConflict(t *testing.T) {
	f := newSubAdminFake(t)
	f.actorsBody = `{"actors":[{"atespace":"a1","name":"n1","state":"running",` +
		`"policy_conflict":{"since":"2026-11-17T15:40:00Z","reverts":3,"fix":"defenseclaw substrate policy reset a1/n1"}}]}`
	c := f.context()
	subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, c), nil }, nil)

	out, _, err := runSubAdmin(newSubstrateDoctorCmd(), "--cluster")
	if err == nil || cliusage.ExitCode(err) != 1 {
		t.Fatalf("doctor --cluster exit %d (err %v), want 1\n%s", cliusage.ExitCode(err), err, out)
	}
	for _, want := range []string{"fail  policy_conflict", "a1/n1 (3 foreign change(s)", "policy_conflict: stop whatever else writes",
		"defenseclaw substrate policy reset a1/n1", "not ready"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor --cluster lacks %q:\n%s", want, out)
		}
	}

	out, _, err = runSubAdmin(newSubstrateDoctorCmd())
	if err != nil {
		t.Fatalf("doctor: %v\n%s", err, out)
	}
	if !strings.Contains(out, "warn  policy_conflict") || !strings.Contains(out, "defenseclaw substrate policy reset a1/n1") {
		t.Errorf("doctor does not warn of the conflict:\n%s", out)
	}
}
