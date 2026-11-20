// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package fleet

import (
	"fmt"
	"slices"
	"strings"
)

// CheckPolicyConflicts is the check id of the agents in policy_conflict.
const CheckPolicyConflicts = "policy_conflict"

// Why the agents in policy_conflict were not counted (PolicyConflicts.Reason).
const (
	// ConflictsNoSignIn: no DefenseClaw context is configured here.
	ConflictsNoSignIn = "no_sign_in"
	// ConflictsSignedOut: the sign-in expired or was refused.
	ConflictsSignedOut = "signed_out"
	// ConflictsNotAdministrator: the gateway listed only the caller's own
	// agents (it gives every person's only to an administrator).
	ConflictsNotAdministrator = "not_administrator"
	// ConflictsUnreachable: the admin listener could not be reached.
	ConflictsUnreachable = "unreachable"
	// ConflictsNotRead: the command does not read them (doctor has its own
	// policy_conflict row).
	ConflictsNotRead = "not_read"
)

// Conflicts is what the CLI read of the agents in policy_conflict
// (GAP-0398): the controller marks an agent there after repeated foreign
// changes to its network policy and keeps it on the DefenseClaw rule only
// (deny-only) until an administrator resets it. The mark lives on the
// leader's registrations, so it is read with the administrator's own
// DefenseClaw sign-in (every person's agents), not with kubectl. Reason is
// "" when they were read, else why not (Conflicts*).
type Conflicts struct {
	Reason string
	Agents []ConflictAgent
}

// ConflictAgent is one agent in policy_conflict and the foreign changes the
// controller reverted before it marked it.
type ConflictAgent struct {
	Atespace, Name string
	Reverts        int
}

// PolicyConflicts is the documents' policy_conflicts member. Agents is
// null and Atespaces empty when they were not counted (Reason says why):
// an unknown count is never a 0.
type PolicyConflicts struct {
	Read      bool                `json:"read"`
	Reason    string              `json:"reason,omitempty"`
	Agents    *int                `json:"agents"`
	Atespaces []AtespaceConflicts `json:"atespaces"`
}

// AtespaceConflicts is one atespace and its agents in policy_conflict.
type AtespaceConflicts struct {
	Atespace  string `json:"atespace"`
	Conflicts int    `json:"conflicts"`
}

// conflictsRead reports whether o holds a count.
func conflictsRead(o Observed) bool {
	return o.Conflicts != nil && o.Conflicts.Reason == ""
}

// conflictCounts is the agents in policy_conflict per atespace.
func conflictCounts(o Observed) map[string]int {
	n := map[string]int{}
	for _, a := range o.Conflicts.Agents {
		n[a.Atespace]++
	}
	return n
}

// policyConflicts builds the member: every launcher and managed atespace,
// and every other one with an agent in conflict, sorted by name.
func policyConflicts(o Observed) *PolicyConflicts {
	if !conflictsRead(o) {
		reason := ConflictsNotRead
		if o.Conflicts != nil {
			reason = o.Conflicts.Reason
		}
		return &PolicyConflicts{Reason: reason, Atespaces: []AtespaceConflicts{}}
	}
	counts := conflictCounts(o)
	names := append([]string{}, o.WritableAtespaces...)
	for a := range counts {
		names = append(names, a)
	}
	slices.Sort(names)
	names = slices.Compact(names)
	total := len(o.Conflicts.Agents)
	out := &PolicyConflicts{Read: true, Agents: &total, Atespaces: make([]AtespaceConflicts, 0, len(names))}
	for _, a := range names {
		out.Atespaces = append(out.Atespaces, AtespaceConflicts{Atespace: a, Conflicts: counts[a]})
	}
	return out
}

// conflictReasonWords says a Reason in words, with what to do.
func conflictReasonWords(reason string) string {
	switch reason {
	case ConflictsNoSignIn:
		return "no DefenseClaw sign-in is configured here; sign in as an administrator (defenseclaw substrate login) and run again"
	case ConflictsSignedOut:
		return "your DefenseClaw sign-in expired or was refused; sign in again as an administrator (defenseclaw substrate login) and run again"
	case ConflictsNotAdministrator:
		return "you are not signed in as an administrator, so the cluster lists only your own agents; sign in as an administrator " +
			"(defenseclaw substrate login) and run again, with --context NAME when that is not the cluster you signed in to last"
	case ConflictsUnreachable:
		return "the DefenseClaw admin address did not answer; check it with defenseclaw substrate doctor and run again"
	}
	return "run defenseclaw substrate doctor --cluster as an administrator"
}

// CheckPolicyConflict: no agent is in policy_conflict. One is reachable only
// to DefenseClaw until something else stops writing its egress policy and an
// administrator resets it, and only the controller's log said so (GAP-0398).
func CheckPolicyConflict(o Observed) Check {
	if !conflictsRead(o) {
		reason := ConflictsNotRead
		if o.Conflicts != nil {
			reason = o.Conflicts.Reason
		}
		return result(CheckPolicyConflicts, Warn, "", "the agents in policy_conflict were not counted: %s", conflictReasonWords(reason))
	}
	if len(o.Conflicts.Agents) == 0 {
		return result(CheckPolicyConflicts, Pass, "", "no agent is in policy_conflict")
	}
	agents := slices.Clone(o.Conflicts.Agents)
	slices.SortFunc(agents, func(a, b ConflictAgent) int {
		return strings.Compare(a.Atespace+"/"+a.Name, b.Atespace+"/"+b.Name)
	})
	var names, resets []string
	for _, a := range agents {
		ref := a.Atespace + "/" + a.Name
		names = append(names, fmt.Sprintf("%s (%d foreign change(s) to its network policy reverted)", ref, a.Reverts))
		resets = append(resets, "defenseclaw substrate policy reset "+ref)
	}
	return result(CheckPolicyConflicts, Fail, "", "%d agent(s) in policy_conflict reach only DefenseClaw (deny-only): %s. Stop "+
		"whatever else writes the agent's egress policy, then run: %s", len(agents), strings.Join(names, "; "), strings.Join(resets, "; "))
}
