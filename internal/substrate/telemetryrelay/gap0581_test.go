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
// from its registration (by atespace and UID) and drops records of actors
// it has no registration for.
func TestGAP0581EgressRecordsNameTheActorFromItsRegistration(t *testing.T) {
	s := &Store{Registrations: fakeRegs{
		"eng-web/uid-alice": {Atespace: "eng-web", Name: "alice-1", UID: "uid-alice", Profile: "eng"},
	}}
	_, _ = s.PostEgress(context.Background(), PostRequest{Records: []Record{
		{Kind: KindEgress, Atespace: "eng-web", UID: "uid-alice", Actor: "bob-1", Profile: "admin", Host: "pypi.org", Decision: "allow"},
		{Kind: KindEgress, Atespace: "eng-web", UID: "uid-unknown", Actor: "carol-1", Host: "evil.example.com", Decision: "allow"},
		{Kind: KindEgress, Atespace: "other", UID: "uid-alice", Actor: "alice-1", Host: "evil.example.com", Decision: "allow"},
		{Kind: KindEgress, Atespace: "eng-web", Actor: "alice-1", Host: "evil.example.com", Decision: "allow"},
	}})
	out, _ := s.Take(context.Background(), TakeRequest{})
	if len(out.Records) != 1 {
		t.Fatalf("kept %d records, want only the registered actor's: %+v", len(out.Records), out.Records)
	}
	r := out.Records[0]
	if r.Atespace != "eng-web" || r.UID != "uid-alice" || r.Actor != "alice-1" || r.Profile != "eng" || r.Host != "pypi.org" {
		t.Fatalf("record %+v: the actor fields are not the registration's", r)
	}
}
