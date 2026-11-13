// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"testing"
	"time"
)

type writerFleet struct {
	recordingFleet
	id     string
	epochs []string
}

func (f *writerFleet) WriterID() string { return f.id }

func (f *writerFleet) Push(ctx context.Context, epoch string, rows []SeedRow) error {
	f.epochs = append(f.epochs, epoch)
	return f.recordingFleet.Push(ctx, epoch, rows)
}

// A new device credential is a new writer: the spend charged before the swap
// stays with the old writer and is never pushed under the new device id.
func TestNewCredentialStartsANewWriter(t *testing.T) {
	rt := NewRuntime()
	rt.For(adapterConfig(nil, dailyBudget()))
	local := &fakeCounter{}
	oldFleet, newFleet := &writerFleet{id: "d-old"}, &writerFleet{id: "d-new"}
	rt.mu.Lock()
	rt.local = local // no ctx: no sync loop races the test
	rt.mu.Unlock()
	rt.SetFleet(oldFleet, nil)
	rt.Ledger().ApplyRemote([]string{"d"}, nil, time.Now()) // seeded, as after a first sync
	rt.Charge([]string{"user:d:*:1001"}, 3, time.Now())
	rt.push(context.Background())
	before := rt.epoch
	rt.SetFleet(oldFleet, nil) // same writer: nothing changes
	if rt.epoch != before {
		t.Fatal("the same credential keeps the epoch")
	}
	rt.SetFleet(newFleet, nil)
	if rt.epoch == before {
		t.Fatal("a new credential starts a new epoch")
	}
	if len(rt.Ledger().LocalRows()) != 0 {
		t.Fatal("no local spend is carried to the new writer")
	}
	if got, _ := rt.Ledger().Spend("user:d:*:1001", "day", time.Now()); got != 3 {
		t.Fatalf("the spend keeps counting until the next sync: %v", got)
	}
	if rows := local.pushed[before]; len(rows) != 1 || rows[0].USD != 3 {
		t.Fatalf("the old writer's spend is stored on this device: %+v", local.pushed)
	}
	rt.Charge([]string{"user:d:*:1001"}, 1, time.Now())
	rt.push(context.Background())
	if len(newFleet.pushed) != 1 || newFleet.pushed[0].USD != 1 || newFleet.epochs[0] == before {
		t.Fatalf("the new writer sends only spend after the swap: %+v %v", newFleet.pushed, newFleet.epochs)
	}
}
