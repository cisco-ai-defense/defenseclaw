// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// TestSubstrateUsageTelemetryKeepsSubject: only the usage owner of an actor
// call takes its person key; the model.usage log user.id stays the verified
// subject its hook and llm events carry (RV2 P2-2, T6 ruling 11-22).
func TestSubstrateUsageTelemetryKeepsSubject(t *testing.T) {
	prev := identityFactsEnabled.Load()
	t.Cleanup(func() { setIdentityFactsEnabled(prev) })
	setIdentityFactsEnabled(true)

	p := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice", Principal: "alice@example.com"}
	ctx := substrateActorCallContext(t, p, "fix-login", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a")
	s, ok := verifiedSubjectFromContext(ctx)
	if !ok || s.UserID == "" {
		t.Fatal("an actor call with a bound person must carry a verified subject")
	}
	var f modelusage.CallFacts
	usageIdentity(ctx, &f)
	if f.Subject != s.UserID || f.SubjectKind != s.Source {
		t.Fatalf("usage subject %q/%q, want the hook subject %q/%q", f.Subject, f.SubjectKind, s.UserID, s.Source)
	}
	in := buildModelUsageLogInput(observability.FamilyEnvelopeInput{}, modelusage.Record{Facts: f})
	if in.UserID != hookModelV8OptionalID(s.UserID) {
		t.Fatalf("model.usage user.id %+v, want the hook subject %q", in.UserID, s.UserID)
	}
	owner := modelusage.OwnerID(f)
	if !strings.HasPrefix(owner, substrateUsageOwnerKind+":p:") {
		t.Fatalf("usage owner %q, want %s:p:<key>", owner, substrateUsageOwnerKind)
	}
	// The writer and the usage API reader agree (RV2 P3-2).
	if want := substrateUsageOwner(ownerOf(p)); owner != want {
		t.Fatalf("usage owner %q written, %q read", owner, want)
	}
}

type fakeSubstrateUsage struct{ owners []string }

func (f *fakeSubstrateUsage) Usage(_ context.Context, q SubstrateUsageQuery) (SubstrateUsageAnswer, error) {
	f.owners = append(f.owners, q.Owner)
	return SubstrateUsageAnswer{By: q.By}, nil
}

// TestSubstrateUsageNoPersonForbidden: "" is every owner, so a caller with
// no person, or no caller on the request, is refused, and only an admin
// with all=1 reads every owner (RV2 P3-1).
func TestSubstrateUsageNoPersonForbidden(t *testing.T) {
	cases := []struct {
		name   string
		ctx    context.Context
		query  string
		status int
		owner  string
	}{
		{"no caller", context.Background(), "", http.StatusForbidden, "-"},
		{"non-admin empty person", withSubstratePerson(context.Background(), identity.Person{}, false), "", http.StatusForbidden, "-"},
		{"non-admin empty person all=1", withSubstratePerson(context.Background(), identity.Person{}, false), "all=1", http.StatusForbidden, "-"},
		{"admin empty person", withSubstratePerson(context.Background(), identity.Person{}, true), "", http.StatusForbidden, "-"},
		{"admin all=1", withSubstratePerson(context.Background(), identity.Person{}, true), "all=1", http.StatusOK, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fu := &fakeSubstrateUsage{}
			st := &substrateState{cfg: SubstrateConfig{Usage: fu}}
			r := httptest.NewRequest(http.MethodGet, "/api/v1/substrate/usage?"+tc.query, nil).WithContext(tc.ctx)
			w := httptest.NewRecorder()
			(&APIServer{}).substrateUsage(st)(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d (%s)", w.Code, tc.status, strings.TrimSpace(w.Body.String()))
			}
			if tc.owner == "-" && len(fu.owners) != 0 {
				t.Fatalf("usage read for owners %q, want no read", fu.owners)
			}
			if tc.owner != "-" && (len(fu.owners) != 1 || fu.owners[0] != tc.owner) {
				t.Fatalf("usage read for owners %q, want [%q]", fu.owners, tc.owner)
			}
		})
	}
	// A person reads only their own owner.
	p := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice"}
	fu := &fakeSubstrateUsage{}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/substrate/usage", nil).WithContext(withSubstratePerson(context.Background(), p, false))
	w := httptest.NewRecorder()
	(&APIServer{}).substrateUsage(&substrateState{cfg: SubstrateConfig{Usage: fu}})(w, r)
	if w.Code != http.StatusOK || len(fu.owners) != 1 || fu.owners[0] != substrateUsageOwner(ownerOf(p)) {
		t.Fatalf("own read: status %d owners %q", w.Code, fu.owners)
	}
}
