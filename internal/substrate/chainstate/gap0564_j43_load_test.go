// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// j43Load collects the leader calls of a J43-shaped run.
type j43Load struct {
	mu        sync.Mutex
	lat       map[string][]time.Duration
	failed    map[string]int
	refused   map[string]bool
	resends   map[audit.ToolChainPendingStatus]int
	firstErrs []string
}

func (l *j43Load) took(kind string, d time.Duration, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lat[kind] = append(l.lat[kind], d)
	if err != nil {
		l.failed[kind]++
		if len(l.firstErrs) < 4 {
			l.firstErrs = append(l.firstErrs, kind+": "+err.Error())
		}
	}
}

func (l *j43Load) report(t *testing.T) {
	t.Helper()
	kinds := make([]string, 0, len(l.lat))
	for k := range l.lat {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		v := append([]time.Duration(nil), l.lat[k]...)
		sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
		at := func(q float64) time.Duration { return v[min(len(v)-1, int(float64(len(v))*q))] }
		t.Logf("J43 %-16s n=%5d failed=%d p50=%7.2fms p95=%7.2fms p99=%7.2fms max=%7.2fms", k, len(v), l.failed[k],
			ms(at(.5)), ms(at(.95)), ms(at(.99)), ms(v[len(v)-1]))
	}
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func j43Env(t *testing.T, name string, def int) int {
	t.Helper()
	if v := os.Getenv(name); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("%s=%q is not a positive number", name, v)
		}
		return n
	}
	return def
}

func j43Digest(parts ...any) string {
	sum := sha256.Sum256([]byte(fmt.Sprint(parts...)))
	return hex.EncodeToString(sum[:])
}

// TestSubstrateGAP0564J43ShapeOnARealLeader replays CERT-110 cell J43 on E5 (two
// gateway replicas, one leader, 50 headless Claude Code actors) against a
// real leader over the leader transport. The 50 actors start at once. Each
// actor's first tool call (Claude Code running the load script) is a
// PreToolUse prepare in the session and actor windows that is posted twice:
// the second time through the other replica, with its own semantic event id
// and the same hook body, as the kit resends a hook that ran past its answer
// budget while the leader created 50 new actor stores. Its PostToolUse
// resolves it. Then each actor posts the J43 steady step (a PreToolUse
// without a tool call id: an observe in both windows) every 0.5 s and checks
// one egress every 2 s, as the callout does. A leader call that fails is
// handled as the gateway handles it: the actor is marked unrecorded, and the
// callout refuses its egress.
//
// substrate-1 GAP-0564: before the fix the resend read as a reused tool call
// id, the leader dropped the proposal and answered "internal", and every
// later egress of the actor was refused (16 of the 50 on E5, all of them
// here, where every first call is resent). The bar is J43's: no refused
// egress and no failed leader call. DEFENSECLAW_J43_ACTORS and
// DEFENSECLAW_J43_SECS size the run; the percentiles go to the test log.
func TestSubstrateGAP0564J43ShapeOnARealLeader(t *testing.T) {
	actors := j43Env(t, "DEFENSECLAW_J43_ACTORS", 50)
	secs := j43Env(t, "DEFENSECLAW_J43_SECS", 4)
	svc, err := New(Options{Dir: t.TempDir(), Warn: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	ls := &leader.Server{IsLeader: func() bool { return true }}
	svc.Register(ls)
	srv := httptest.NewServer(ls)
	t.Cleanup(func() { srv.Close(); _ = svc.Close() })
	var replicas [2]*Client
	for i := range replicas {
		replicas[i] = &Client{Leader: &leader.Client{BaseURL: srv.URL, HTTP: srv.Client(), Retry: time.Second}}
	}
	load := &j43Load{lat: map[string][]time.Duration{}, failed: map[string]int{},
		refused: map[string]bool{}, resends: map[audit.ToolChainPendingStatus]int{}}
	steady := projection(t, reverseShell, 1)
	ctx := context.Background()

	start := time.Now().Add(50 * time.Millisecond)
	// The steady phase starts when every actor's first call is done, as
	// J43's load script waited for its start time.
	var started sync.WaitGroup
	started.Add(actors)
	var end time.Time
	steadyAt := make(chan struct{})
	go func() {
		started.Wait()
		end = time.Now().Add(time.Duration(secs) * time.Second)
		close(steadyAt)
	}()
	var wg sync.WaitGroup
	for i := range actors {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := Actor{Atespace: "dc-eng", UID: fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i)}
			session := "claude-" + strconv.Itoa(i)
			home, other := replicas[i%2], replicas[1-i%2]
			bind := func(c *Client, scope Scope, event string) *Binding {
				b, err := c.Bind(a, scope, "claudecode", session, event)
				if err != nil {
					t.Error(err)
				}
				return b
			}
			// The gateway's answer to a failed actor-window step.
			missed := func(c *Client, scope Scope, err error) {
				if err != nil && scope == ScopeActor {
					_ = c.Unrecorded(ctx, a, "the leader did not take the step: "+err.Error())
				}
			}
			time.Sleep(time.Until(start))
			inv, body := j43Digest("call", i), j43Digest("body", i)
			first := time.Now()
			for n, c := range []*Client{home, other} {
				for _, scope := range []Scope{ScopeSession, ScopeActor} {
					id, _ := eventID(t)
					t0 := time.Now()
					r, err := bind(c, scope, "PreToolUse").PreparePending(ctx, audit.ToolChainPreparePendingInput{
						ToolInvocationDigest: inv, PreSemanticEventID: id, PreInputFingerprint: body,
						RulesetFingerprint: ruleset, Projection: steady})
					kind := "prepare"
					if n == 1 {
						kind = "prepare-resend"
						load.mu.Lock()
						load.resends[r.Status]++
						load.mu.Unlock()
					}
					load.took(kind, time.Since(t0), err)
					missed(c, scope, err)
				}
				if n == 0 {
					load.took("first-call", time.Since(first), nil)
				}
			}
			for _, scope := range []Scope{ScopeSession, ScopeActor} {
				id, fp := eventID(t)
				t0 := time.Now()
				_, err := bind(home, scope, "PostToolUse").ResolvePending(ctx, audit.ToolChainResolvePendingInput{
					ToolInvocationDigest: inv, Outcome: audit.ToolChainPendingOutcomeSuccess, RulesetFingerprint: ruleset,
					TerminalSemanticEventID: id, TerminalInputFingerprint: fp})
				load.took("resolve", time.Since(t0), err)
				missed(home, scope, err)
			}
			started.Done()
			<-steadyAt
			nextEgress := time.Now()
			for step := 0; time.Now().Before(end); step++ {
				t0 := time.Now()
				c := replicas[(i+step)%2]
				for _, scope := range []Scope{ScopeSession, ScopeActor} {
					id, fp := eventID(t)
					s0 := time.Now()
					_, err := bind(c, scope, "PreToolUse").Observe(ctx, audit.ToolChainObserveInput{
						SemanticEventID: id, InputFingerprint: fp, RulesetFingerprint: ruleset,
						Projection: steady, DenyEligible: true})
					load.took("observe", time.Since(s0), err)
					missed(c, scope, err)
				}
				load.took("hook-step", time.Since(t0), nil)
				if !t0.Before(nextEgress) {
					nextEgress = t0.Add(2 * time.Second)
					e0 := time.Now()
					v, err := c.CheckEgress(ctx, EgressRequest{Actor: a, Host: "t-sink.t.svc", Method: "GET"})
					load.took("egress", time.Since(e0), err)
					if err != nil || v.Deny || v.Unrecorded != "" {
						load.mu.Lock()
						load.refused[a.UID] = true
						load.mu.Unlock()
					}
				}
				time.Sleep(time.Until(t0.Add(500 * time.Millisecond)))
			}
		}()
	}
	wg.Wait()
	load.report(t)
	t.Logf("J43 actors=%d secs=%d resend answers=%v refused actors=%d", actors, secs, load.resends, len(load.refused))
	failed := 0
	for _, n := range load.failed {
		failed += n
	}
	if failed != 0 || len(load.refused) != 0 {
		t.Fatalf("%d of %d actors had their egress refused and %d leader calls failed (first: %v); "+
			"J43 wants none (GAP-0564)", len(load.refused), actors, failed, load.firstErrs)
	}
	if load.resends[audit.ToolChainPendingReplay] != 2*actors {
		t.Fatalf("resent first calls answered %v, want %d replays", load.resends, 2*actors)
	}
}
