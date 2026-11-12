// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// When more writes queue than one batch takes, the durable ones go first,
// but the head of the queue still leads its batch: every caller gets its own
// result and no write is left without a leader (S8 review 3 blocker).
func TestWriteGroupDurableFirstKeepsTheLeader(t *testing.T) {
	g := &writeGroup{}
	hold := make(chan struct{})
	calls := 0
	exec := func(batch []*groupedWrite) {
		calls++
		if calls == 1 {
			<-hold
		}
		for _, it := range batch {
			it.err = it.data.(error)
		}
	}
	mk := func(name string, durable bool) *groupedWrite {
		return &groupedWrite{ctx: context.Background(), data: errors.New(name), durable: durable}
	}
	type res struct {
		name string
		err  error
	}
	out := make(chan res, 100)
	start := func(w *groupedWrite) { go func() { out <- res{w.data.(error).Error(), g.do(w, exec)} }() }
	waitPending := func(n int) {
		for {
			g.mu.Lock()
			got := len(g.pending)
			active := g.active
			g.mu.Unlock()
			if active && got == n {
				return
			}
			time.Sleep(50 * time.Microsecond)
		}
	}
	start(mk("A", false))
	waitPending(0)
	for i := 0; i < writeGroupMax+1; i++ {
		start(mk(fmt.Sprintf("W%d", i), false))
	}
	waitPending(writeGroupMax + 1)
	start(mk("D", true))
	waitPending(writeGroupMax + 2)
	close(hold)
	deadline := time.After(5 * time.Second)
	for got := 0; got < writeGroupMax+3; got++ {
		select {
		case r := <-out:
			if r.err == nil || r.err.Error() != r.name {
				t.Fatalf("caller %s got %v", r.name, r.err)
			}
		case <-deadline:
			t.Fatalf("only %d of %d callers returned", got, writeGroupMax+3)
		}
	}
}

// The two-class baton serves an urgent waiter before an older ordinary one,
// alternates the classes while both wait, and passes the baton on when a
// waiter gives up as it is handed over.
func TestWriteBatonUrgentFirstThenAlternates(t *testing.T) {
	var b writeBaton
	release, err := b.acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var order []string
	var wg sync.WaitGroup
	queue := func(name string, urgent bool) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			acquire := b.acquire
			if urgent {
				acquire = b.acquireUrgent
			}
			rel, err := acquire(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			order = append(order, name)
			mu.Unlock()
			rel()
		}()
		for {
			b.mu.Lock()
			n := len(b.urgent) + len(b.normal)
			b.mu.Unlock()
			if n > 0 && waiting(&b, name, urgent) {
				return
			}
			time.Sleep(50 * time.Microsecond)
		}
	}
	queue("n1", false)
	queue("n2", false)
	queue("u1", true)
	queue("u2", true)
	release()
	wg.Wait()
	want := []string{"u1", "n1", "u2", "n2"}
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("baton order %v, want %v", order, want)
	}
	// A waiter whose context ends as it is handed the baton passes it on.
	release, _ = b.acquire(t.Context())
	ctx, cancel := context.WithCancel(context.Background())
	gotErr := make(chan error, 1)
	go func() { _, err := b.acquireUrgent(ctx); gotErr <- err }()
	for !waiting(&b, "", true) {
		time.Sleep(50 * time.Microsecond)
	}
	cancel()
	release()
	if err := <-gotErr; err == nil {
		// It got the baton before the cancel was seen: give it back.
		t.Log("waiter won the race with its cancel")
	}
	again, err := b.acquire(t.Context())
	if err != nil {
		t.Fatalf("baton lost after a cancelled hand-over: %v", err)
	}
	again()
}

func waiting(b *writeBaton, _ string, urgent bool) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if urgent {
		return len(b.urgent) > 0
	}
	return len(b.normal) > 0
}

// Close finishes while durable writes and journal deletions are queued in
// the hook-call group (no nested lifecycle read lock under a waiting Close).
func TestCloseWhileDurableWritesQueueDoesNotHang(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_ = store.JournalHookDelivery(ctx, fmt.Sprintf("c-%d", i), "p", []byte(`{}`), journalRows(1000))
		}(i)
		go func(i int) {
			defer wg.Done()
			_ = store.ForgetHookDelivery(ctx, fmt.Sprintf("c-%d", i))
		}(i)
	}
	closed := make(chan error, 1)
	go func() { closed <- store.Close() }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-closed:
	case <-time.After(20 * time.Second):
		t.Fatal("Close hung behind queued durable writes")
	}
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("durable writers hung after Close")
	}
}
