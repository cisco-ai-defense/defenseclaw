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
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

func usageReq(ctx context.Context, query string) (*http.Request, *httptest.ResponseRecorder) {
	return httptest.NewRequest(http.MethodGet, "/api/v1/substrate/usage?"+query, nil).WithContext(ctx), httptest.NewRecorder()
}

// TestSubstrateUsageOwnOnly: a person's read is scoped to their own usage
// owner and carries by/since/batch to the reader; the request cannot name
// another owner.
func TestSubstrateUsageOwnOnly(t *testing.T) {
	p := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice"}
	var got SubstrateUsageQuery
	fu := usageFunc(func(_ context.Context, q SubstrateUsageQuery) (SubstrateUsageAnswer, error) {
		got = q
		return SubstrateUsageAnswer{By: q.By}, nil
	})
	r, w := usageReq(withSubstratePerson(context.Background(), p, false), "by=actor&since=7d&batch=b1&owner=someone-else&limit=5")
	(&APIServer{}).substrateUsage(&substrateState{cfg: SubstrateConfig{Usage: fu}})(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	if got.Owner != substrateUsageOwner(ownerOf(p)) || got.All || got.By != "actor" || got.Since != 7*24*time.Hour || got.Batch != "b1" || got.Limit != 5 {
		t.Fatalf("query %+v", got)
	}
}

type usageFunc func(context.Context, SubstrateUsageQuery) (SubstrateUsageAnswer, error)

func (f usageFunc) Usage(ctx context.Context, q SubstrateUsageQuery) (SubstrateUsageAnswer, error) {
	return f(ctx, q)
}

// TestSubstrateUsageAdminAllAudited: an administrator's all=1 read sees every
// owner and is audited; a non-administrator's all=1 is their own read.
func TestSubstrateUsageAdminAllAudited(t *testing.T) {
	var all []bool
	fu := usageFunc(func(_ context.Context, q SubstrateUsageQuery) (SubstrateUsageAnswer, error) {
		all = append(all, q.All)
		if q.By == "person" && !q.All {
			return SubstrateUsageAnswer{}, errSubstrateUsageAdminOnly
		}
		return SubstrateUsageAnswer{By: q.By}, nil
	})
	st := &substrateState{cfg: SubstrateConfig{Usage: fu}}
	p := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice"}
	r, w := usageReq(withSubstratePerson(context.Background(), p, true), "all=1&by=person")
	(&APIServer{}).substrateUsage(st)(w, r)
	if w.Code != http.StatusOK || len(all) != 1 || !all[0] {
		t.Fatalf("admin all=1: status %d all=%v", w.Code, all)
	}
	r, w = usageReq(withSubstratePerson(context.Background(), p, false), "all=1&by=person")
	(&APIServer{}).substrateUsage(st)(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "usage_forbidden") {
		t.Fatalf("non-admin per-person view: status %d %s", w.Code, w.Body.String())
	}
}

// TestSubstrateUsageUsersSeeNone: routing.admin.visibility.users_see: none
// hides a person's own usage; an administrator still reads.
func TestSubstrateUsageUsersSeeNone(t *testing.T) {
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Visibility: &config.RoutingVisibility{UsersSee: config.RoutingUsersSeeNone}}
	a := &APIServer{configSnapshot: func() *config.Config { return cfg }}
	fu := usageFunc(func(context.Context, SubstrateUsageQuery) (SubstrateUsageAnswer, error) {
		return SubstrateUsageAnswer{}, nil
	})
	st := &substrateState{cfg: SubstrateConfig{Usage: fu}}
	p := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice"}
	r, w := usageReq(withSubstratePerson(context.Background(), p, false), "")
	a.substrateUsage(st)(w, r)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "usage_hidden") {
		t.Fatalf("user read: status %d %s", w.Code, w.Body.String())
	}
	r, w = usageReq(withSubstratePerson(context.Background(), p, true), "")
	a.substrateUsage(st)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("admin own read: status %d", w.Code)
	}
}

// TestSubstrateUsageDisabled: substrate.usage.enabled false answers 501
// usage_disabled, a missing reader usage_unavailable, bad parameters 400.
func TestSubstrateUsageDisabled(t *testing.T) {
	p := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice"}
	ctx := withSubstratePerson(context.Background(), p, false)
	for _, tc := range []struct {
		name  string
		cfg   SubstrateConfig
		query string
		code  int
		body  string
	}{
		{"disabled", SubstrateConfig{UsageDisabled: true, Usage: usageFunc(nil)}, "", 501, "usage_disabled"},
		{"unavailable", SubstrateConfig{}, "", 501, "usage_unavailable"},
		{"bad since", SubstrateConfig{Usage: usageFunc(nil)}, "since=soon", 400, "usage_bad_since"},
		{"bad by", SubstrateConfig{Usage: usageFunc(func(context.Context, SubstrateUsageQuery) (SubstrateUsageAnswer, error) {
			return SubstrateUsageAnswer{}, errSubstrateUsageBy
		})}, "by=zodiac", 400, "usage_bad_by"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, w := usageReq(ctx, tc.query)
			(&APIServer{}).substrateUsage(&substrateState{cfg: tc.cfg})(w, r)
			if w.Code != tc.code || !strings.Contains(w.Body.String(), tc.body) {
				t.Fatalf("status %d %s, want %d %s", w.Code, w.Body.String(), tc.code, tc.body)
			}
		})
	}
}

// TestSubstrateUsageOffCostsNothing: with no spend leader (usage disabled or
// not a cluster replica) startSubstrateSpend adds no sink and starts no
// goroutine, so a request pays nothing.
func TestSubstrateUsageOffCostsNothing(t *testing.T) {
	s := &Sidecar{}
	if s.startSubstrateSpend(context.Background(), SubstrateConfig{}, time.Second) {
		t.Fatal("started without a leader")
	}
	if s.modelUsageRT.Load() != nil {
		t.Fatal("the usage engine was created with usage off")
	}
}

type fakePushLeader struct {
	SubstrateSpendLeader
	mu   sync.Mutex
	rows []modelusage.RemoteRow
}

func (f *fakePushLeader) UsagePush(_ context.Context, _ string, rows []modelusage.RemoteRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rows = append(f.rows, rows...)
	return nil
}

// TestSubstrateUsagePushesAtShutdown: pending usage goes to the leader on the
// final push when the sidecar stops, and an acknowledged bucket is not sent
// again.
func TestSubstrateUsagePushesAtShutdown(t *testing.T) {
	sink := modelusage.NewLeaderSink("e1")
	usd := 0.5
	sink.Emit(context.Background(), modelusage.Record{
		Facts:   modelusage.CallFacts{Actor: "a1", Atespace: "ns", OwnerKey: "p:aa", OwnerKind: substrateUsageOwnerKind, SelectedModel: "m1"},
		Cost:    modelusage.Cost{USD: &usd},
		EndedAt: time.Now(),
	})
	l := &fakePushLeader{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { substratePushUsage(ctx, l, sink, time.Hour); close(done) }()
	cancel()
	<-done
	if len(l.rows) != 1 || l.rows[0].Actor != "a1" {
		t.Fatalf("pushed %+v, want the actor bucket once", l.rows)
	}
	if len(sink.Pending()) != 0 {
		t.Fatal("an acked bucket stays pending")
	}
}

// TestSubstrateUsageActorFactsRoundTrip: the facts usageIdentity sets from an
// actor's registration (person owner, actor, batch, atespace) go through the
// leader sink and the remote table, and the reader finds the row under the
// owner the usage API computes from the verified person (GAP-0103, RV2 P3-2).
func TestSubstrateUsageActorFactsRoundTrip(t *testing.T) {
	prev := identityFactsEnabled.Load()
	t.Cleanup(func() { setIdentityFactsEnabled(prev) })
	setIdentityFactsEnabled(true)

	p := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice"}
	ctx := substrateActorCallContext(t, p, "fix-login", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a")
	reg, _ := substrateRegistrationFrom(ctx)
	reg.BatchID = "nightly-7"
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)

	var f modelusage.CallFacts
	usageIdentity(ctx, &f)
	if f.Actor != "fix-login" || f.BatchID != "nightly-7" || f.Atespace != "eng-web" {
		t.Fatalf("usage facts actor/batch/atespace %q/%q/%q", f.Actor, f.BatchID, f.Atespace)
	}
	usd := 0.25
	sink := modelusage.NewLeaderSink("e1")
	f.SelectedModel, f.SelectedProvider, f.Connector = "m1", "anthropic", "claudecode"
	sink.Emit(context.Background(), modelusage.Record{Facts: f, Cost: modelusage.Cost{USD: &usd}, EndedAt: time.Now()})

	st := modelusage.NewStore(filepath.Join(t.TempDir(), "model_usage", "model_usage.db"))
	if err := st.Configure(true, 30); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Configure(false, 30) })
	if err := st.ApplyRemote(sink.Epoch(), modelusage.Rows(sink.Pending())); err != nil {
		t.Fatal(err)
	}
	owner := substrateUsageOwner(ownerOf(p))
	rows, err := st.Run(context.Background(), modelusage.Query{By: "actor", Owner: owner})
	if err != nil || len(rows) != 1 || rows[0].Key != "fix-login" {
		t.Fatalf("actor rows %+v err %v for owner %q", rows, err, owner)
	}
	rows, err = st.Run(context.Background(), modelusage.Query{By: "actor", Owner: owner, Batch: "other"})
	if err != nil || len(rows) != 0 {
		t.Fatalf("batch filter: %+v err %v", rows, err)
	}
	other := substrateUsageOwner(registry.Person{Issuer: "https://idp-b.example", Subject: "alice"})
	if rows, _ = st.Run(context.Background(), modelusage.Query{By: "actor", Owner: other}); len(rows) != 0 {
		t.Fatalf("another issuer's alice reads %+v", rows)
	}
}
