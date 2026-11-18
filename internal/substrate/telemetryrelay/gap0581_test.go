// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetryrelay

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// fakeRegs is a registry.Store over a map keyed atespace/uid.
type fakeRegs map[string]registry.Registration

func (f fakeRegs) Get(_ context.Context, atespace, uid string) (registry.Registration, bool, error) {
	r, ok := f[atespace+"/"+uid]
	return r, ok, nil
}
func (f fakeRegs) Put(context.Context, registry.Registration) error { return nil }
func (f fakeRegs) List(context.Context, registry.Filter) ([]registry.Registration, error) {
	return nil, nil
}

// GAP-0581: the leader exported an egress record's atespace, actor, UID and
// profile as the callout sent them, so a faulty or compromised callout
// could write egress records for any actor. The leader now names the actor
// from its registration (by atespace and UID). A UID no registration of the
// atespace has is stripped with the profile, so the record can't name
// another actor's registration.
func TestGAP0581EgressRecordsNameTheActorFromItsRegistration(t *testing.T) {
	s := &Store{Registrations: fakeRegs{
		"eng-web/uid-alice": {Atespace: "eng-web", Name: "alice-1", UID: "uid-alice", Profile: "eng"},
	}}
	_, _ = s.PostEgress(context.Background(), PostRequest{Records: []Record{
		{Kind: KindEgress, Atespace: "eng-web", UID: "uid-alice", Actor: "bob-1", Host: "pypi.org", Decision: "allow", Unregistered: true},
		{Kind: KindEgress, Atespace: "eng-web", UID: "uid-alice", Actor: "alice-1", Profile: "eng-default-policy", Host: "files.example.org", Decision: "allow"},
		{Kind: KindEgress, Atespace: "eng-web", UID: "uid-unknown", Actor: "carol-1", Profile: "admin", Host: "evil.example.com", Decision: "allow"},
		{Kind: KindEgress, Atespace: "other", UID: "uid-alice", Actor: "alice-1", Profile: "eng", Host: "evil.example.com", Decision: "allow"},
	}})
	out, _ := s.Take(context.Background(), TakeRequest{})
	if len(out.Records) != 4 {
		t.Fatalf("kept %d records, want 4: %+v", len(out.Records), out.Records)
	}
	// The registered actor: its name from the registration, the profile
	// from the registration when the callout named no deciding policy, and
	// the callout's deciding policy when it named one.
	if r := out.Records[0]; r.Atespace != "eng-web" || r.UID != "uid-alice" || r.Actor != "alice-1" || r.Profile != "eng" || r.Unregistered {
		t.Errorf("record %+v: the actor fields are not the registration's", r)
	}
	if r := out.Records[1]; r.Actor != "alice-1" || r.UID != "uid-alice" || r.Profile != "eng-default-policy" || r.Unregistered {
		t.Errorf("record %+v: the deciding policy the callout named is lost", r)
	}
	// A UID no registration of the atespace has: no UID, no profile, marked.
	for _, r := range out.Records[2:] {
		if r.UID != "" || r.Profile != "" || !r.Unregistered {
			t.Errorf("record %+v: a UID with no registration kept its UID or profile, or is not marked unregistered", r)
		}
	}
}

// GAP-0581 (review 2): the callout leaves the UID empty on real refusals: a
// deleted actor (ErrActorNotLive is answered before the UID is set), a
// registration lookup outage past the stale window, and an actor
// DefenseClaw never registered. The leader dropped every record without a
// UID, so those blocks never reached log.egress.blocked. They are kept with
// the atespace and actor name, without UID or profile, marked Unregistered.
func TestGAP0581RefusalsOfUnregisteredActorsKeepTheirRecord(t *testing.T) {
	s := &Store{Registrations: fakeRegs{
		"eng-web/uid-alice": {Atespace: "eng-web", Name: "alice-1", UID: "uid-alice", Profile: "eng"},
	}}
	_, _ = s.PostEgress(context.Background(), PostRequest{Records: []Record{
		// The shapes extproc.Engine.Finish writes for these refusals
		// (TestGAP0581CalloutRefusalsWithoutUIDNameTheActor).
		{Kind: KindEgress, Atespace: "eng-web", Actor: "deleted-1", Host: "example.com", Decision: "block",
			Category: "actor_not_live", Reason: "DefenseClaw's registrations say this actor was deleted."},
		{Kind: KindEgress, Atespace: "eng-web", Actor: "outage-1", Profile: "default", Host: "example.com", Decision: "block",
			Category: "chain_unchecked", Alert: true},
		{Kind: KindEgress, Atespace: "ci-runs", Actor: "job-1", Profile: "default", Host: "pastebin.com", Decision: "block",
			Category: "paste_site"},
		// No actor at all: nothing to name, dropped.
		{Kind: KindEgress, Atespace: "eng-web", Host: "example.com", Decision: "block"},
	}})
	out, _ := s.Take(context.Background(), TakeRequest{})
	want := map[string]string{"deleted-1": "eng-web", "outage-1": "eng-web", "job-1": "ci-runs"}
	if len(out.Records) != len(want) {
		t.Fatalf("kept %d records, want the 3 refusals of actors without a registration: %+v", len(out.Records), out.Records)
	}
	for _, r := range out.Records {
		if want[r.Actor] != r.Atespace || r.Decision != "block" || r.UID != "" || r.Profile != "" || !r.Unregistered {
			t.Errorf("record %+v: want the atespace and actor kept, no UID or profile, marked unregistered", r)
		}
	}
}
