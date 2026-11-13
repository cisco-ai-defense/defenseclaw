// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"reflect"
	"strings"
	"testing"
)

var editors = []string{"system:serviceaccount:dc:defenseclaw-gateway", "system:serviceaccount:dc:defenseclaw-controller"}

func TestLauncherPolicyOnlyDefenseClawEdits(t *testing.T) {
	current := &AccessPolicy{UID: "u1", Version: 3, Bindings: []Binding{
		{Role: RoleOwner, Members: []string{"user:alice"}},
		{Role: RoleEditor, Members: []string{"user:bob", Member(editors[0])}},
		{Role: RoleViewer, Members: []string{"user:carol"}},
	}}
	next, changes := LauncherPolicy("eng-web", current, editors)
	want := []Binding{
		{Role: RoleEditor, Members: []string{Member(editors[1]), Member(editors[0])}},
	}
	for i := range want {
		sortStrings(want[i].Members)
	}
	if !reflect.DeepEqual(next.Bindings, want) {
		t.Errorf("bindings = %+v, want %+v", next.Bindings, want)
	}
	if next.UID != "u1" || next.Version != 3 || next.Atespace != "eng-web" {
		t.Errorf("preconditions lost: %+v", next)
	}
	var revoked, granted int
	for _, c := range changes {
		if c.Removed {
			revoked++
		} else {
			granted++
		}
	}
	// alice (owner), bob (editor) and carol (viewer, GAP-0084: own data only).
	if revoked != 3 || granted != 1 {
		t.Errorf("changes = %+v", changes)
	}
	if current.Bindings[1].Members[0] != "user:bob" {
		t.Error("the current policy was modified")
	}
	// Idempotent.
	if _, again := LauncherPolicy("eng-web", &next, editors); len(again) != 0 {
		t.Errorf("second pass changed %+v", again)
	}
}

func TestGrantAndRevokePolicy(t *testing.T) {
	current := &AccessPolicy{Bindings: []Binding{{Role: RoleViewer, Members: []string{"user:carol"}}, {Role: RoleOwner, Members: []string{"user:root"}}}}
	next, changes := GrantPolicy("", current, RoleViewer, editors)
	if len(changes) != 2 || len(next.Members(RoleViewer)) != 3 || len(next.Members(RoleOwner)) != 1 {
		t.Fatalf("grant: %+v %+v", next, changes)
	}
	if _, again := GrantPolicy("", &next, RoleViewer, editors); len(again) != 0 {
		t.Errorf("not idempotent: %+v", again)
	}
	back, removed := RevokePolicy(next, RoleViewer, editors)
	if len(removed) != 2 || !reflect.DeepEqual(back.Members(RoleViewer), []string{"user:carol"}) {
		t.Errorf("revoke: %+v %+v", back, removed)
	}
	fresh, _ := GrantPolicy("team", nil, RoleEditor, editors[:1])
	if fresh.Atespace != "team" || len(fresh.Bindings) != 1 {
		t.Errorf("fresh grant: %+v", fresh)
	}
}

func TestPrintAccessPolicies(t *testing.T) {
	plan := testPlan()
	out, err := PrintAccessPolicies(plan)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "access-policies.txt", []byte(out))
	for _, want := range []string{"kubectl ate create access-policy -a eng-web", "name: default", "role: editor", "Managed atespace data-team"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "role: owner") {
		t.Error("a launcher policy grants owner")
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
