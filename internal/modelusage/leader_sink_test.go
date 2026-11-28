// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func actorRec(owner, actor, batch, atespace, model string, usd float64, at time.Time) Record {
	r := rec(owner, nil, model, &usd, at)
	r.Facts.Actor, r.Facts.BatchID, r.Facts.Atespace = actor, batch, atespace
	r.Facts.OwnerKey, r.Facts.OwnerKind = owner, "substrate_person"
	return r
}

// TestUsageLeaderSinkNoPromptText: nothing outside the bounded dimension keys
// and the counts reaches the push.
func TestUsageLeaderSinkNoPromptText(t *testing.T) {
	s := NewLeaderSink("epoch-a")
	const marker = "PROMPTMARK-ignore-previous-instructions"
	r := actorRec("p:1111111111111111", "ctr-1", "", "main", "claude-sonnet", 0.01, time.Now())
	f := &r.Facts
	f.RequestID, f.TraceID, f.SessionID, f.TurnID, f.AgentID = marker, marker, marker, marker, marker
	f.ModelRequestID, f.ModelResponseID, f.SubjectName = marker, marker, marker+"@example.com"
	f.Groups = []string{marker}
	f.Route.RuleID, f.Route.Category, f.Route.FallbackReason = marker, marker, marker
	f.ChargeKeys = []string{marker}
	r.ErrorType = marker
	r.Labels = []Label{{Key: "k", Value: marker}}
	s.Emit(context.Background(), r)
	body, err := json.Marshal(Rows(s.Pending()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "PROMPTMARK") || strings.Contains(string(body), "example.com") {
		t.Fatalf("a non-dimension field reached the push: %s", body)
	}
	if !strings.Contains(string(body), `"actor":"ctr-1"`) || !strings.Contains(string(body), "p:1111111111111111") {
		t.Fatalf("dimensions missing: %s", body)
	}
}

func TestLeaderSinkAckAndBound(t *testing.T) {
	s := NewLeaderSink("e1")
	at := time.Now()
	s.Emit(context.Background(), actorRec("p:aa", "a1", "", "ns", "m1", 1, at))
	p := s.Pending()
	if len(p) != 1 {
		t.Fatalf("pending %d", len(p))
	}
	s.Emit(context.Background(), actorRec("p:aa", "a1", "", "ns", "m1", 1, at)) // changes after the snapshot
	s.Acked(p)
	p2 := s.Pending()
	if len(p2) != 1 || p2[0].Calls != 2 {
		t.Fatalf("the bucket that changed after the read must stay pending with the absolute total: %+v", p2)
	}
	s.Acked(p2)
	if len(s.Pending()) != 0 {
		t.Fatal("acked buckets stay quiet")
	}
	// an old hour that is fully stored leaves memory
	s.now = func() time.Time { return at.Add(24 * time.Hour) }
	s.Acked(nil)
	if len(s.entries) != 0 {
		t.Fatalf("old stored buckets must be dropped, have %d", len(s.entries))
	}
}

func TestLeaderUsageRoundTripSumsEpochs(t *testing.T) {
	st := openStore(t)
	now := time.Now()
	a := NewLeaderSink("epoch-a")
	b := NewLeaderSink("epoch-b")
	alice, bob := "substrate_person:p:aaaa", "substrate_person:p:bbbb"
	a.Emit(context.Background(), actorRec("p:aaaa", "act-1", "", "ns1", "m1", 0.5, now))
	a.Emit(context.Background(), actorRec("p:aaaa", "act-2", "", "ns1", "m1", 0.25, now))
	b.Emit(context.Background(), actorRec("p:aaaa", "act-1", "", "ns1", "m1", 1, now))
	b.Emit(context.Background(), actorRec("p:bbbb", "act-9", "", "ns2", "m1", 7, now))
	push := func(s *LeaderSink) {
		t.Helper()
		if err := st.ApplyRemote(s.Epoch(), Rows(s.Pending())); err != nil {
			t.Fatal(err)
		}
	}
	push(a)
	push(a) // a retry changes nothing
	push(b)
	ctx := context.Background()
	rows, err := st.Run(ctx, Query{By: "actor", Owner: alice})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, r := range rows {
		got[r.Key] = *r.CostUSD
	}
	if len(got) != 2 || got["act-1"] != 1.5 || got["act-2"] != 0.25 {
		t.Fatalf("alice by actor (own rows, epochs summed once): %+v", got)
	}
	if rows, _ = st.Run(ctx, Query{By: "user", AllOwners: true}); len(rows) != 2 {
		t.Fatalf("admin by user: %+v", rows)
	}
	if rows, _ = st.Run(ctx, Query{By: "atespace", Owner: bob}); len(rows) != 1 || rows[0].Key != "ns2" || *rows[0].CostUSD != 7 {
		t.Fatalf("bob by atespace: %+v", rows)
	}
	if rows, _ = st.Run(ctx, Query{By: "day", Owner: alice}); len(rows) != 1 || *rows[0].CostUSD != 1.75 {
		t.Fatalf("alice by day: %+v", rows)
	}
	// a later push of the same epoch replaces its earlier totals
	a.Emit(context.Background(), actorRec("p:aaaa", "act-2", "", "ns1", "m1", 0.25, now))
	push(a)
	if rows, _ = st.Run(ctx, Query{By: "actor", Owner: alice}); len(rows) != 2 {
		t.Fatalf("%+v", rows)
	}
	for _, r := range rows {
		if r.Key == "act-2" && (*r.CostUSD != 0.5 || r.Calls != 2) {
			t.Fatalf("act-2 after the second push: %+v", r)
		}
	}
	// a person never reads another's rows, and a caller without an owner reads none
	if _, err := st.Run(ctx, Query{By: "actor"}); err != ErrAdminOnly {
		t.Fatalf("no owner: %v", err)
	}
}

func TestApplyRemoteRefusesBadRows(t *testing.T) {
	st := openStore(t)
	good := RemoteRow{Hour: time.Now().Truncate(time.Hour).Unix(), Owner: "o", Connector: "c", Provider: "p", Model: "m", Route: "r", Role: "x", Profile: "p", Family: "f", Basis: "b", Calls: 1}
	neg := good
	neg.Calls = -5
	neg.Model = "neg"
	if err := st.ApplyRemote("e", []RemoteRow{good, neg}); err != nil {
		t.Fatal(err)
	}
	rows, _ := st.Run(context.Background(), Query{By: "model", AllOwners: true})
	if len(rows) != 1 || rows[0].Key != "m" || rows[0].Calls != 1 {
		t.Fatalf("a negative row must be skipped: %+v", rows)
	}
	if st.ApplyRemote("", []RemoteRow{good}) == nil || st.ApplyRemote("e", make([]RemoteRow, RemoteBatchMax+1)) == nil {
		t.Fatal("no epoch and an oversized push are refused")
	}
}
