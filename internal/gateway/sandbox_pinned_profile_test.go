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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// A sandbox created under the strict profile keeps its floor after its
// group moved to the loose profile. The refusal of an unblock, the policy
// answer the daemon's status shows and the explain name the strict profile
// as pinned when the sandbox was created, and the loose one as the
// assignment now, so a help-desk quote points at the rule's profile
// (GAP-0285). A sandbox whose floor is its current profile's alone is
// named as before.
func TestPinnedFloorIsNamedByTheProfileItWasCreatedUnder(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-devs")
	pinnedFloorProfiles(f, "")
	strict := f.live(sbxAlice, 1)
	loose := f.live(sbxBob, 2)

	moved := newSandboxFixtureOn(t, f)
	pinnedFloorProfiles(moved, "engineering")

	code, cur := moved.current(sbxAlice, strict.Registration.ID)
	if code != http.StatusOK || cur.Profile != "engineering" || cur.PinnedProfile != "contractors" {
		t.Fatalf("policy/current of the strict-created sandbox: %d profile %q pinned %q", code, cur.Profile, cur.PinnedProfile)
	}
	rec := moved.do(sbxAlice, http.MethodPost, sandboxrelay.PathDecisions, sandboxrelay.DecisionRequest{
		V: 1, Registration: strict.Registration.ID, Kind: sandboxrelay.DecisionUnblock, Host: "github.com", Scope: sandboxrelay.DecisionScopeAlways,
	}, nil)
	body := rec.Body.String()
	if rec.Code != http.StatusForbidden ||
		!strings.Contains(body, "profile contractors, pinned when this sandbox was created") ||
		!strings.Contains(body, "you are now assigned engineering") ||
		!strings.Contains(body, "Quote: profile contractors, ") {
		t.Fatalf("unblock refusal: %d %s", rec.Code, body)
	}
	rec = moved.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyExplain, sandboxrelay.ExplainRequest{V: 1, Registration: strict.Registration.ID}, nil)
	var ex sandboxapi.ManagedExplain
	if err := json.Unmarshal(rec.Body.Bytes(), &ex); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("explain: %d %v", rec.Code, err)
	}
	if ex.Profile != "engineering" || ex.PinnedProfile != "contractors" || ex.Description != "Contractors" {
		t.Fatalf("explain of the strict-created sandbox: profile %q pinned %q description %q", ex.Profile, ex.PinnedProfile, ex.Description)
	}

	// The loose-created sandbox moved to the same loose profile: no pin.
	if code, cur := moved.current(sbxBob, loose.Registration.ID); code != http.StatusOK || cur.PinnedProfile != "" {
		t.Fatalf("policy/current of the loose-created sandbox: %d pinned %q", code, cur.PinnedProfile)
	}
	// A move to the strict profile tightens the loose one; its floor is the
	// strict profile's alone, so it names that profile only.
	toStrict := newSandboxFixtureOn(t, moved)
	pinnedFloorProfiles(toStrict, "contractors")
	if code, cur := toStrict.current(sbxBob, loose.Registration.ID); code != http.StatusOK || cur.Profile != "contractors" || cur.PinnedProfile != "" {
		t.Fatalf("a loose-created sandbox under the strict profile: %d profile %q pinned %q", code, cur.Profile, cur.PinnedProfile)
	}
}
