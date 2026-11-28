// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// countedAsks counts the launcher's reads of the pending list.
type countedAsks struct {
	fakeAsks
	reads atomic.Int32
}

func (c *countedAsks) Pending(ctx context.Context, t Target) ([]Ask, error) {
	c.reads.Add(1)
	return c.fakeAsks.Pending(ctx, t)
}

// TestAskRowShowsWithinTwoSecondsGAP0483: an ask raised right after the
// launcher read the pending list is on the row well within 2 s. The callout
// holds the request for about 1.5 s, so the row is the person's cue; with a
// 2 s poll it came at up to 2 s plus the round trip.
func TestAskRowShowsWithinTwoSecondsGAP0483(t *testing.T) {
	src := &countedAsks{}
	size := func() relay.Resize { return relay.Resize{Cols: testCols, Rows: testRows} }
	scr := newScreen(&writes{}, size)
	scr.reserve = true
	scr.begin()
	u := newAskUI(src, testTarget, scr, size, newFakeClock().now, func() {})
	r := &uiRig{u: u, scr: scr, src: &src.fakeAsks}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u.start(ctx)
	defer u.stop()
	for start := time.Now(); src.reads.Load() == 0; time.Sleep(5 * time.Millisecond) {
		if time.Since(start) > 5*time.Second {
			t.Fatal("the launcher never read the pending list")
		}
	}
	src.mu.Lock()
	src.pending = []Ask{myAsk("k1")}
	src.mu.Unlock()
	raised := time.Now()
	for r.curID() != "k1" {
		if time.Since(raised) > 1500*time.Millisecond {
			t.Fatalf("no ask row %s after the ask was raised (the launcher reads every %s)", time.Since(raised).Round(time.Millisecond), askPollEvery)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if row := r.row(); !strings.HasPrefix(row, "DefenseClaw ask k1 from "+myActor+": ") {
		t.Fatalf("ask row %q", row)
	}
}
