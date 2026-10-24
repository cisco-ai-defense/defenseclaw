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
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A person who only runs raw OpenShell sandboxes or plain containers has
// no registration: the events route takes their foreign sandbox and
// container records without one, stamped with the verified peer alone
// (GAP-0235, GAP-0263, GAP-0318). Any other kind still needs one, an
// account the gateway can't name is refused, and so is a peer the
// authorizer allows no sandbox harness.
func TestSandboxEventsWithoutRegistration(t *testing.T) {
	var mu sync.Mutex
	var got []sandboxreg.Registration
	prev := sandboxEmitEvent
	sandboxEmitEvent = func(_ context.Context, _ *APIServer, _ managedHookPeer, reg sandboxreg.Registration, _ sandboxrelay.Event) {
		mu.Lock()
		got = append(got, reg)
		mu.Unlock()
	}
	t.Cleanup(func() { sandboxEmitEvent = prev })
	emitted := func() []sandboxreg.Registration {
		mu.Lock()
		defer mu.Unlock()
		return append([]sandboxreg.Registration(nil), got...)
	}
	post := func(f *sandboxFixture, peer managedHookPeer, kinds ...string) int {
		t.Helper()
		batch := sandboxrelay.EventBatch{V: sandboxrelay.WireVersion}
		for _, k := range kinds {
			batch.Events = append(batch.Events, sandboxrelay.Event{Kind: k, Payload: json.RawMessage(`{"sandbox":"raw-mac","action":"stop"}`)})
		}
		return f.do(peer, http.MethodPost, sandboxrelay.PathEvents, batch, nil).Code
	}

	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	if code := post(f, sbxAlice, sandboxrelay.EventForeignSandbox, sandboxrelay.EventForeignContainer, sandboxrelay.EventAccountBusy); code != http.StatusAccepted {
		t.Fatalf("foreign records without a registration: %d", code)
	}
	auth, err := f.api.sandboxAuth()
	if err != nil {
		t.Fatal(err)
	}
	regs := emitted()
	if len(regs) != 3 || regs[0].ID != "" || regs[0].UID != sbxAlice.UID || regs[0].UserName != sbxAlice.Name ||
		regs[0].SubjectKey != sandboxSubjectKey(auth.key, sbxAlice.UID, sbxAlice.Name, "") {
		t.Fatalf("emitted under %+v", regs)
	}
	for _, kind := range []string{sandboxrelay.EventSettingsDrift, sandboxrelay.EventForeignRule} {
		if code := post(f, sbxAlice, sandboxrelay.EventForeignSandbox, kind); code != http.StatusBadRequest {
			t.Errorf("%s without a registration: %d, want 400", kind, code)
		}
	}
	many := make([]string, sandboxrelay.MaxUnregisteredEventRecords+1)
	for i := range many {
		many[i] = sandboxrelay.EventForeignContainer
	}
	if code := post(f, sbxAlice, many...); code != http.StatusBadRequest {
		t.Errorf("%d records without a registration: %d, want 400", len(many), code)
	}
	if code := post(f, managedHookPeer{UID: sbxAlice.UID}, sandboxrelay.EventForeignSandbox); code != http.StatusServiceUnavailable {
		t.Errorf("an account without a name: %d, want 503", code)
	}
	strict := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{UnenrolledUsers: config.EnterpriseUnenrolledDeny}, &managedHookLedger{})
	strict.setGroups(sbxAlice, "dc-sbx-contractors")
	if code := post(strict, sbxAlice, sandboxrelay.EventForeignSandbox); code != http.StatusForbidden {
		t.Errorf("an unenrolled account: %d, want 403", code)
	}
	if n := len(emitted()); n != 3 {
		t.Fatalf("%d records emitted, want only the first batch's 3", n)
	}
}

// A foreign container or sandbox record names the item itself, the
// connector of the harness the daemon found in it (never the connector of
// the registration the batch came under, GAP-0434), and the caller's own
// guardrail profile match with the subject key, with or without a
// registration (GAP-0444).
func TestSandboxForeignRecordsCarryTheCallersProfile(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	key := "hmac-sha256:" + strings.Repeat("a", 64)
	batch := sandboxreg.Registration{ID: "reg-abcdefghijklmnopqrstuvwxyz", UID: sbxAlice.UID, UserName: sbxAlice.Name,
		SubjectKey: key, Connector: "claudecode", Profile: "contractors", SandboxName: "mine"}
	none := sandboxreg.Registration{UID: sbxAlice.UID, UserName: sbxAlice.Name, SubjectKey: key}
	for _, reg := range []sandboxreg.Registration{batch, none} {
		for harnessName, want := range map[string]string{"codex": "codex", "claudecode": "claudecode", "not-a-harness": "", "": ""} {
			got := f.api.sandboxForeignIdentity(context.Background(), reg, "f3a4232d055b", "plain", harnessName, "")
			m := got.Managed
			if got.ID != "f3a4232d055b" || got.Name != "plain" || got.Connector != want || m.RegistrationID != "" ||
				m.GuardrailProfile != "contractors" || m.ProfileMatch != "group" || m.MatchedGroup != "dc-sbx-contractors" ||
				!strings.HasPrefix(m.ProfileDigest, "sha256:") || m.SubjectKey != key || m.Provisional == nil || *m.Provisional {
				t.Fatalf("registration %q harness %q: identity %+v", reg.ID, harnessName, got)
			}
		}
	}
	// Another person's groups give another profile: the stamp is the caller's.
	f.setGroups(sbxBob, "dc-sbx-devs")
	bob := sandboxreg.Registration{UID: sbxBob.UID, UserName: sbxBob.Name, SubjectKey: key}
	if got := f.api.sandboxForeignIdentity(context.Background(), bob, "c1", "plain", "claudecode", ""); got.Managed.GuardrailProfile != "engineering" {
		t.Fatalf("bob's foreign container profile %q", got.Managed.GuardrailProfile)
	}
}

// A foreign record of a caller whose groups are unknown, when an assignment
// needs them, is refused: its stamp carries no candidate profile, digest or
// matched group, which may be another account's (decision 4 of the 1.0.4
// identity design).
func TestSandboxForeignRecordOfARefusedDecisionNamesNoCandidateProfile(t *testing.T) {
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	// bob-only and contractors block, so a decision that may give them is
	// refused; one among profiles that only observe is observed and records
	// no candidate either (TestSandboxAuthorityColdCacheAmongObserveProfilesIsProvisional).
	f.cfg.Guardrail.Profiles["bob-only"] = config.GuardrailProfile{Description: "Bob private profile", Mode: "action"}
	f.cfg.Guardrail.Profiles["contractors"] = strictTier(t, f.cfg, config.GuardrailProfile{Description: "Contractors"}, "strict")
	f.cfg.Guardrail.ProfileAssignments = append([]config.ProfileAssignment{
		{Profile: "bob-only", Match: config.ProfileMatch{Groups: []string{"dc-sbx-bob-team"}}},
	}, f.cfg.Guardrail.ProfileAssignments...)
	f.publishFirstGeneration()
	// sandboxMatchPeer and sandboxForeignIdentity below run without a
	// pinned generation: they read the server's own profile set.
	set, err := newGuardrailProfileSet(f.cfg, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	f.api.guardrailProfiles.set.Store(set)
	f.mu.Lock()
	f.facts[sbxAlice.UID] = useridentity.DirectoryFacts{
		Principal: sbxAlice.Name + "@DCLAB.TEST", Domain: "dclab.test", Directory: useridentity.DirectoryActiveDirectory,
		Source: "sssd", GroupsPartial: true, ResolvedAt: time.Now(),
	}
	f.mu.Unlock()
	reg := sandboxreg.Registration{UID: sbxAlice.UID, UserName: sbxAlice.Name, SubjectKey: "hmac-sha256:" + strings.Repeat("a", 64)}
	d := f.api.sandboxMatchPeer(context.Background(), managedHookPeer{UID: reg.UID, Name: reg.UserName}, "claudecode", 0).decision
	if d.Refused == "" || d.Name == "" {
		t.Fatalf("decision %+v; want a refusal that names a candidate profile", d)
	}
	m := f.api.sandboxForeignIdentity(context.Background(), reg, "c1", "plain", "claudecode", "").Managed
	if m.GuardrailProfile != "" || m.ProfileDigest != "" || m.MatchedGroup != "" || m.SubjectKey != reg.SubjectKey {
		t.Fatalf("foreign record of a refused decision: %+v; want no candidate profile, digest or matched group", m)
	}
}
