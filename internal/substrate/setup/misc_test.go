// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNamespaceGrantRoundTrip(t *testing.T) {
	in := "policies:\n- atespace: team-a\n  allowedNamespaces: [ns1]\n  note: kept\nextra: yes\n"
	out, changes, err := GrantNamespace(in, []string{"team-a", "eng"}, "dc-secrets")
	if err != nil || len(changes) != 2 {
		t.Fatalf("%v %v", changes, err)
	}
	if !strings.Contains(out, "note: kept") || !strings.Contains(out, "extra:") {
		t.Errorf("unknown members dropped:\n%s", out)
	}
	same, none, err := GrantNamespace(out, []string{"team-a", "eng"}, "dc-secrets")
	if err != nil || len(none) != 0 || same != out {
		t.Errorf("not idempotent: %v", none)
	}
	back, removed, err := RevokeNamespaceExcept(out, nil, "dc-secrets")
	if err != nil || len(removed) != 2 {
		t.Fatalf("%v %v", removed, err)
	}
	if strings.Contains(back, "dc-secrets") || strings.Contains(back, "atespace: eng\n") || !strings.Contains(back, "ns1") {
		t.Errorf("revoke:\n%s", back)
	}
	if _, _, err := GrantNamespace("policies: {", nil, "x"); err == nil {
		t.Error("bad yaml accepted")
	}
	empty, ch, err := GrantNamespace("", []string{"eng"}, "dc-secrets")
	if err != nil || len(ch) != 1 || !strings.Contains(empty, "allowedNamespaces:") {
		t.Errorf("empty policy: %q %v", empty, err)
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		v, rng string
		want   bool
	}{
		{"1.0.0", ">=1.0.0 <1.1.0", true},
		{"v1.0.7", ">=1.0.0 <1.1.0", true},
		{"1.1.0", ">=1.0.0 <1.1.0", false},
		{"1.1.0-rc.1", ">=1.0.0 <1.1.0", true},
		{"1.0.0-rc.1", ">=1.0.0 <1.1.0", false},
		{"0.9.9", ">=1.0.0", false},
		{"1.0.0", "1.0.0", true},
	} {
		got, err := InRange(c.v, c.rng)
		if err != nil || got != c.want {
			t.Errorf("InRange(%s, %s) = %v, %v", c.v, c.rng, got, err)
		}
	}
	for _, bad := range []string{"", "~1.0", ">=x"} {
		if _, err := InRange("1.0.0", bad); err == nil {
			t.Errorf("range %q accepted", bad)
		}
	}
	if _, err := ParseVersion("1.0"); err == nil {
		t.Error("1.0 accepted")
	}
	for _, c := range []struct {
		from, to string
		ok       bool
	}{
		{"1.0.9", "1.0.10", true}, {"1.0.10", "1.1.0", true}, {"1.0.10", "1.2.0", false},
		{"1.0.10", "1.0.9", false}, {"1.9.3", "2.0.0", true}, {"1.9.3", "2.1.0", false}, {"", "1.0.10", true},
	} {
		if err := CheckUpgrade(c.from, c.to); (err == nil) != c.ok {
			t.Errorf("CheckUpgrade(%s, %s) = %v", c.from, c.to, err)
		}
	}
}

func TestStoreState(t *testing.T) {
	st, err := ParseStoreState(nil)
	if st != nil || err != nil {
		t.Fatal("nil data")
	}
	if _, err := ParseStoreState(map[string]string{StoreStateSchemaKey: "x"}); err == nil {
		t.Error("bad schema accepted")
	}
	in := StoreState{SchemaVersion: 3, Backup: "b.db", WrittenByVersion: "1.0.10", UpdatedAt: "t"}
	out, err := ParseStoreState(in.Data())
	if err != nil || *out != in {
		t.Errorf("%+v %v", out, err)
	}
	if err := CheckRollback(3, out); err != nil {
		t.Error(err)
	}
	err = CheckRollback(1, &StoreState{SchemaVersion: 2})
	if err == nil || !strings.Contains(err.Error(), "No backup") {
		t.Errorf("%v", err)
	}
}

func TestParsePlan(t *testing.T) {
	good, _ := json.Marshal(testPlan())
	if _, err := ParsePlan(good); err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePlan([]byte(`{"schema":1,"surprise":true}`)); err == nil {
		t.Error("unknown member accepted")
	}
	p := testPlan()
	p.CredentialProvider.SecretsNamespace = p.Namespace
	b, _ := json.Marshal(p)
	if _, err := ParsePlan(b); err == nil || !strings.Contains(err.Error(), "D14") {
		t.Errorf("secrets in the DefenseClaw namespace: %v", err)
	}
	p = testPlan()
	p.LauncherAtespaces = []string{"Bad_Name"}
	b, _ = json.Marshal(p)
	if _, err := ParsePlan(b); err == nil {
		t.Error("bad atespace accepted")
	}
}

func TestReadSource(t *testing.T) {
	t.Setenv("A8_TEST_PLAN", "{}")
	if b, err := ReadSource("env:A8_TEST_PLAN"); err != nil || string(b) != "{}" {
		t.Errorf("%q %v", b, err)
	}
	if _, err := ReadSource("env:A8_TEST_UNSET"); err == nil {
		t.Error("unset env accepted")
	}
}
