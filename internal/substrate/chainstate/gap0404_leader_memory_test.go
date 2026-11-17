// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// leaderRSS is the process's resident memory (Linux), or -1.
func leaderRSS() int64 {
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return -1
	}
	f := strings.Fields(string(raw))
	if len(f) < 2 {
		return -1
	}
	pages, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return -1
	}
	return pages * int64(os.Getpagesize())
}

func settledRSS() int64 {
	runtime.GC()
	debug.FreeOSMemory()
	return leaderRSS()
}

// GAP-0404: the leader's memory grew about 90 KiB per audited tool call
// (+215 MiB after 2,434 calls of 8 actors on E1) and kept most of it after
// the actors were deleted. Two things grew with the calls:
//   - each actor's write-ahead log: audit stores run with SQLite's own
//     checkpoints off and the leader never copied the chain stores' logs, so
//     each grew by about 300 KiB per hook call (81 MB after 270 calls), on
//     the volume and in the page cache the pod is charged for;
//   - each store's SQLite page cache: the gateway's 20 MB per connection, on
//     the writer and a 4-connection read pool, outside the Go heap.
//
// The leader's Run loop now checkpoints the open stores (guardWALs) and the
// stores open WithSmallFootprint.
//
// The bound: resident growth over N calls of 8 actors at most N x 2 KiB
// (the E1 cell's per-call bound) plus the open stores' capped page caches
// and 16 MiB, once the stores are open; and every actor's log stays at most
// a few passes of writes (16 MiB here).
func TestGAP0404LeaderMemoryStaysBoundedPerToolCall(t *testing.T) {
	if leaderRSS() < 0 {
		t.Skip("resident memory is read from /proc/self/statm (Linux)")
	}
	h := newHarness(t, t.TempDir(), Options{})
	ctx := context.Background()
	// The leader runs the service's loop (substrate_serve.go).
	runCtx, stop := context.WithCancel(ctx)
	ran := make(chan struct{})
	go func() { defer close(ran); _ = h.svc.Run(runCtx) }()
	defer func() { stop(); <-ran }()
	actors := make([]Actor, 8)
	for i := range actors {
		actors[i] = Actor{Atespace: "dc-eng", UID: fmt.Sprintf("25a1da0f-1c9b-4ef7-8248-c276138c7f%02d", i)}
	}
	// A benign Bash call (echo): no chain step, as in the E1 replay.
	benign := guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete}
	n := 0
	call := func(a Actor) {
		n++
		sum := sha256.Sum256([]byte(fmt.Sprintf("gap0404-inv-%d", n)))
		inv := hex.EncodeToString(sum[:])
		session := "sess-" + a.UID
		for _, scope := range []Scope{ScopeSession, ScopeActor} {
			id, fp := eventID(t)
			b, err := h.client.Bind(a, scope, "claudecode", session, "PreToolUse")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.PreparePending(ctx, audit.ToolChainPreparePendingInput{ToolInvocationDigest: inv, PreSemanticEventID: id,
				PreInputFingerprint: fp, RulesetFingerprint: ruleset, Projection: benign}); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := h.svc.IntentPut(ctx, IntentRequest{Actor: a, Op: IntentAppend, Key: session, Tool: "Bash",
			Args: fmt.Sprintf(`{"command":"echo call %d"}`, n)}); err != nil {
			t.Fatal(err)
		}
		for _, scope := range []Scope{ScopeSession, ScopeActor} {
			id, fp := eventID(t)
			b, err := h.client.Bind(a, scope, "claudecode", session, "PostToolUse")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := b.ResolvePending(ctx, audit.ToolChainResolvePendingInput{ToolInvocationDigest: inv,
				Outcome: audit.ToolChainPendingOutcomeSuccess, RulesetFingerprint: ruleset,
				TerminalSemanticEventID: id, TerminalInputFingerprint: fp}); err != nil {
				t.Fatal(err)
			}
		}
		h.advance(50 * time.Millisecond)
	}
	// Open every actor's store first: what an open store costs is bounded
	// by MaxOpenStores, not by the calls.
	for range 10 {
		for _, a := range actors {
			call(a)
		}
	}
	before := settledRSS()
	const perActor = 150
	for range perActor {
		for _, a := range actors {
			call(a)
		}
	}
	calls := int64(perActor * len(actors))
	grew := settledRSS() - before
	// 2 KiB per call (the call memory, about 1 KiB, and the replay cache),
	// what the 8 open stores' page caches hold at most (2 connections of
	// 512 KiB each), and 16 MiB for the runtime.
	bound := calls*2<<10 + 8*2*512<<10 + 16<<20
	t.Logf("%d calls: leader memory +%d KiB (%d B per call), bound %d KiB", calls, grew>>10, grew/calls, bound>>10)
	var largest int64
	for _, a := range actors {
		if info, err := os.Stat(h.svc.dbPath(a) + "-wal"); err == nil && info.Size() > largest {
			largest = info.Size()
		}
	}
	t.Logf("largest actor write-ahead log: %d KiB", largest>>10)
	if largest > 16<<20 {
		t.Fatalf("an actor's write-ahead log is %d KiB after %d calls of its actor: nothing copies it into the store", largest>>10, perActor+10)
	}
	if grew > bound {
		t.Fatalf("leader memory grew %d KiB over %d calls (%d B per call), over the bound of %d KiB",
			grew>>10, calls, grew/calls, bound>>10)
	}
}
