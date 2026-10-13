// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// GAP-0690: the policy age a user's explain and policy/current show is the
// registration's last policy change, not its create or bind. A re-match
// that changes the floor (here request_access) moves it to the re-match;
// a re-match under the same policy in a new process keeps it.
func TestSandboxAuthorityPolicyAgeFollowsTheLastChange(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.publishFirstGeneration()
	resp := f.live(sbxAlice, 1)
	id := resp.Registration.ID
	ages := func(g *sandboxFixture) (time.Time, time.Time) {
		t.Helper()
		rec := g.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyExplain, sandboxrelay.ExplainRequest{V: 1, Registration: id}, nil)
		var me sandboxapi.ManagedExplain
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &me) != nil {
			t.Fatalf("explain: %d %s", rec.Code, rec.Body.String())
		}
		code, cur := g.current(sbxAlice, id)
		if code != http.StatusOK {
			t.Fatalf("current: %d", code)
		}
		return me.UpdatedAt, cur.UpdatedAt
	}
	auth, _ := f.api.sandboxAuth()
	reg, _, _ := auth.store.Get(sbxAlice.UID, id)
	if explained, current := ages(f); !explained.Equal(reg.CreatedAt) || !current.Equal(reg.CreatedAt) {
		t.Fatalf("age before any change: explain %v current %v, want the resolve %v", explained, current, reg.CreatedAt)
	}

	changedAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	contact := "sandbox-help@example.com"
	moved := newSandboxFixtureOn(t, f)
	moved.cfg.OpenShell.Admin.RequestAccess = contact
	moved.publishFirstGeneration()
	movedAuth, _ := moved.api.sandboxAuth()
	movedAuth.now = func() time.Time { return changedAt }
	if explained, current := ages(moved); !explained.Equal(changedAt) || !current.Equal(changedAt) {
		t.Fatalf("age after request_access changed: explain %v current %v, want %v", explained, current, changedAt)
	}

	same := newSandboxFixtureOn(t, moved)
	same.cfg.OpenShell.Admin.RequestAccess = contact
	same.publishFirstGeneration()
	sameAuth, _ := same.api.sandboxAuth()
	sameAuth.now = func() time.Time { return changedAt.Add(time.Hour) }
	if explained, current := ages(same); !explained.Equal(changedAt) || !current.Equal(changedAt) {
		t.Fatalf("an unchanged policy moved the age: explain %v current %v, want %v", explained, current, changedAt)
	}
}

// GAP-0690: the daemon's status age is the managed gateway's policy time,
// also when only a field that is not live changed; the time alone is not a
// change the floor adopts.
func TestSandboxDaemonStatusAgeIsThePolicyTime(t *testing.T) {
	regs, err := loadDaemonRegistrations(filepath.Join(t.TempDir(), "registrations.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", Digest: "sha256:a", UpdatedAt: time.Now().UTC(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	policyAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	if regs.applyLive("dc-a", sandboxrelay.CurrentPolicy{Digest: "sha256:a", UpdatedAt: policyAt}) {
		t.Fatal("a new policy time alone was reported as a floor change")
	}
	if got, _ := regs.get("dc-a"); !got.UpdatedAt.Equal(policyAt) {
		t.Fatalf("status age %v, want the policy time %v", got.UpdatedAt, policyAt)
	}
	again, err := loadDaemonRegistrations(regs.path)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := again.get("dc-a"); !got.UpdatedAt.Equal(policyAt) {
		t.Fatalf("policy time not kept across a restart: %v", got.UpdatedAt)
	}
}
