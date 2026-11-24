// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package spendleader

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

func startLeader(t *testing.T, dir string) (*Client, func()) {
	t.Helper()
	us := modelusage.NewStore(filepath.Join(dir, "usage", "usage.db"))
	if err := us.Configure(true, 30); err != nil {
		t.Fatal(err)
	}
	svc := &Service{Counter: routingadmin.NewLocalCounter(dir), Usage: us}
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, svc)
	hs := httptest.NewServer(srv)
	c := &Client{Leader: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: 300 * time.Millisecond}}
	return c, func() {
		hs.Close()
		_ = svc.Counter.Close()
		_ = us.Configure(false, 30)
	}
}

// TestLeaderSpendSurvivesLeaderRestart: spend pushed to the leader is on the
// store volume, so a new leader process reads it back and adds the replicas.
func TestLeaderSpendSurvivesLeaderRestart(t *testing.T) {
	dir := t.TempDir()
	day := time.Now().UTC().Format(time.DateOnly)
	since := time.Now().AddDate(0, 0, -2)
	ctx := context.Background()
	c, stop := startLeader(t, dir)
	if err := c.SpendPush(ctx, "epoch-aaaa", []routingadmin.SeedRow{{Day: day, Key: "user:d:p:1", USD: 1.25}}); err != nil {
		t.Fatal(err)
	}
	if err := c.SpendPush(ctx, "epoch-bbbb", []routingadmin.SeedRow{{Day: day, Key: "user:d:p:1", USD: 0.75}}); err != nil {
		t.Fatal(err)
	}
	stop()

	c2, stop2 := startLeader(t, dir) // the leader pod restarted on the same volume
	defer stop2()
	rows, err := c2.SpendTotals(ctx, "epoch-cccc", since, nil)
	if err != nil || len(rows) != 1 || rows[0].USD != 2 {
		t.Fatalf("both replicas' spend must survive: %+v %v", rows, err)
	}
	// a replica never reads its own epoch twice
	rows, _ = c2.SpendTotals(ctx, "epoch-aaaa", since, nil)
	if len(rows) != 1 || rows[0].USD != 0.75 {
		t.Fatalf("own epoch left out: %+v", rows)
	}
	// the counter plugs into the evaluator's sync as a SpendCounter
	var _ routingadmin.SpendCounter = routingadmin.NewLeaderCounter(c2)
}

func TestLeaderUsagePushAndQueryOverTheWire(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	sink := modelusage.NewLeaderSink("epoch-usage1")
	for _, who := range []string{"p:aaaa", "p:bbbb"} {
		r := modelusage.Record{
			Facts: modelusage.CallFacts{Connector: "claudecode", Subject: who, IdentityVerified: true, OwnerKey: who, OwnerKind: "substrate_person",
				Actor: "act-" + who, Atespace: "ns", CallRole: modelusage.RoleAgent, APIFamily: modelusage.FamilyMessages},
			Usage: modelusage.Usage{Input: 10, Output: 5, Has: modelusage.HasInput | modelusage.HasOutput}, Outcome: "completed",
			EndedAt: time.Now(), ModelKey: "m1", ProviderKey: "anthropic",
		}
		usd := 0.5
		r.Cost.USD, r.Cost.Basis = &usd, modelusage.BasisComputed
		sink.Emit(ctx, r)
	}
	p := sink.Pending()
	if err := c.UsagePush(ctx, sink.Epoch(), modelusage.Rows(p)); err != nil {
		t.Fatal(err)
	}
	sink.Acked(p)
	own := modelusage.OwnerID(modelusage.CallFacts{Subject: "p:aaaa", IdentityVerified: true, OwnerKey: "p:aaaa", OwnerKind: "substrate_person"})
	rows, err := c.UsageQuery(ctx, modelusage.Query{By: "actor", Owner: own})
	if err != nil || len(rows) != 1 || rows[0].Key != "act-p:aaaa" {
		t.Fatalf("own rows only: %+v %v", rows, err)
	}
	rows, err = c.UsageQuery(ctx, modelusage.Query{By: "user", AllOwners: true})
	if err != nil || len(rows) != 2 {
		t.Fatalf("admin all: %+v %v", rows, err)
	}
	if _, err = c.UsageQuery(ctx, modelusage.Query{By: "actor"}); err == nil {
		t.Fatal("a query without an owner or all_owners is refused")
	}
}

// TestUsageOffRegistersNothing: a nil service (substrate.usage.enabled: false)
// leaves the methods unknown.
func TestUsageOffRegistersNothing(t *testing.T) {
	srv := &leader.Server{IsLeader: func() bool { return true }}
	Serve(srv, nil)
	hs := httptest.NewServer(srv)
	defer hs.Close()
	c := &Client{Leader: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: 100 * time.Millisecond}}
	if err := c.SpendPush(context.Background(), "epoch-aaaa", nil); err == nil {
		t.Fatal("methods must not exist while usage is off")
	}
}
