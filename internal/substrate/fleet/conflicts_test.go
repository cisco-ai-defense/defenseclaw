// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// GAP-0398: verify and status --cluster list each atespace with its agents
// in policy_conflict, and the policy_conflict check fails while one is
// there, naming the agent, the reverted changes and the reset.
func TestPolicyConflictsAreCountedPerAtespace(t *testing.T) {
	s := compile(t)
	o := healthyCluster()
	o.Conflicts = &Conflicts{Agents: []ConflictAgent{{Atespace: "eng-web", Name: "j24a", Reverts: 3}, {Atespace: "other", Name: "x1", Reverts: 4}}}

	v := BuildVerify(o, "1.0.10", time.Unix(1, 0))
	got := s.ValidateValue(t, "substrate-verify.schema.json", v)
	if v.OK || v.ExitCode() != 1 {
		t.Errorf("verify with an agent in policy_conflict is ok: %+v", v)
	}
	pc := v.PolicyConflicts
	if !pc.Read || pc.Agents == nil || *pc.Agents != 2 {
		t.Fatalf("policy_conflicts = %+v", pc)
	}
	want := []AtespaceConflicts{{"data-team", 0}, {"eng-web", 1}, {"other", 1}}
	if len(pc.Atespaces) != len(want) {
		t.Fatalf("atespaces = %+v, want %+v", pc.Atespaces, want)
	}
	for i := range want {
		if pc.Atespaces[i] != want[i] {
			t.Errorf("atespace %d = %+v, want %+v", i, pc.Atespaces[i], want[i])
		}
	}
	raw, _ := json.Marshal(got["policy_conflicts"])
	if !strings.Contains(string(raw), `{"atespace":"eng-web","conflicts":1}`) {
		t.Errorf("verify --json policy_conflicts = %s", raw)
	}
	expect(t, CheckPolicyConflict(o), Fail, "2 agent(s) in policy_conflict")
	expect(t, CheckPolicyConflict(o), Fail, "eng-web/j24a (3 foreign change(s) to its network policy reverted)")
	expect(t, CheckPolicyConflict(o), Fail, "defenseclaw substrate policy reset eng-web/j24a; defenseclaw substrate policy reset other/x1")

	st := BuildStatus(o, healthyReport())
	s.ValidateValue(t, "substrate-status.schema.json", st)
	for _, a := range st.Atespaces {
		n := map[string]int{"data-team": 0, "eng-web": 1, "empty": 0}[a.Name]
		if a.Conflicts == nil || *a.Conflicts != n {
			t.Errorf("status atespace %s conflicts = %v, want %d", a.Name, a.Conflicts, n)
		}
	}
	if st.Health.State != Degraded {
		t.Errorf("health with an agent in policy_conflict = %s", st.Health.State)
	}

	o.Conflicts.Agents = nil
	expect(t, CheckPolicyConflict(o), Pass, "no agent is in policy_conflict")
	if pc := BuildVerify(o, "1.0.10", time.Unix(1, 0)).PolicyConflicts; pc.Agents == nil || *pc.Agents != 0 || len(pc.Atespaces) != 2 {
		t.Errorf("no conflicts: %+v", pc)
	}
}

// GAP-0398: without an administrator's sign-in the count is unknown, never
// 0: no number per atespace, the reason, and a warning that says how to
// sign in.
func TestPolicyConflictsUnknownWithoutAnAdministrator(t *testing.T) {
	s := compile(t)
	for reason, words := range map[string]string{
		ConflictsNotAdministrator: "you are not signed in as an administrator",
		ConflictsNoSignIn:         "no DefenseClaw sign-in is configured here",
		ConflictsSignedOut:        "sign in again as an administrator",
		ConflictsUnreachable:      "did not answer",
	} {
		o := healthyCluster()
		o.Conflicts = &Conflicts{Reason: reason}
		expect(t, CheckPolicyConflict(o), Warn, words)
		v := BuildVerify(o, "1.0.10", time.Unix(1, 0))
		got := s.ValidateValue(t, "substrate-verify.schema.json", v)
		if !v.OK || v.PolicyConflicts.Read || v.PolicyConflicts.Reason != reason || v.PolicyConflicts.Agents != nil ||
			len(v.PolicyConflicts.Atespaces) != 0 {
			t.Errorf("%s: verify %+v", reason, v.PolicyConflicts)
		}
		if pc, _ := got["policy_conflicts"].(map[string]any); pc == nil || pc["agents"] != nil {
			t.Errorf("%s: policy_conflicts.agents must be null: %v", reason, got["policy_conflicts"])
		}
		st := BuildStatus(o, healthyReport())
		s.ValidateValue(t, "substrate-status.schema.json", st)
		for _, a := range st.Atespaces {
			if a.Conflicts != nil {
				t.Errorf("%s: atespace %s has a count %d", reason, a.Name, *a.Conflicts)
			}
		}
		raw, _ := json.Marshal(st.Atespaces)
		if strings.Contains(string(raw), "conflicts") {
			t.Errorf("%s: an unknown count is printed: %s", reason, raw)
		}
	}
	o := healthyCluster()
	o.Conflicts = nil
	expect(t, CheckPolicyConflict(o), Warn, "doctor --cluster")
}
