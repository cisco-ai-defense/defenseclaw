// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The 1.0.4 guard review (proof renewal while the gateway answers): a
// gateway whose process runs but that does not answer the hooks renews no
// proof, so the hooks decide in outage mode and no earlier allow passes
// past its lifetime. Before, the renewal ran on its own ticker for 15
// minutes after the session's last exchange, whatever the hooks got. Each
// way the gateway can fail to answer: a listener that takes connections
// but never answers (wedged, out of handler capacity), a listener that
// takes none, and an exchange that waits on the gateway past the hook's
// budget (alice's own: the wait of an exchange counts against its
// account). Once the gateway answers again, the proof is renewed again.
func TestForeignHookSessionProofIsRenewedOnlyWhileTheGatewayAnswers(t *testing.T) {
	for _, tc := range []struct {
		name string
		// stall makes the gateway not answer and returns what ends it.
		stall func(t *testing.T, server *foreignHookPublishTestServer) (resume func())
	}{
		{name: "a listener takes connections but never answers", stall: func(t *testing.T, server *foreignHookPublishTestServer) func() {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			server.api.serveForeignHooks(ln)
			return func() { foreignHookServeForTest(t, ln) }
		}},
		{name: "a listener takes no connection", stall: func(t *testing.T, server *foreignHookPublishTestServer) func() {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			server.api.serveForeignHooks(ln)
			_ = ln.Close()
			return func() { foreignHookForgetListenersForTest(server, ln.Addr()) }
		}},
		{name: "an exchange waits on the gateway past the hook's budget", stall: func(t *testing.T, server *foreignHookPublishTestServer) func() {
			blocked, release := make(chan struct{}), make(chan struct{})
			previous := foreignHookSessionKey
			foreignHookSessionKey = func(root, identity string) (enterprisepolicy.SessionRecordKey, error) {
				if identity == server.alice {
					close(blocked)
					<-release
				}
				return previous(root, identity)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				server.exchange(server.aliceToken, foreignHookTestCall("s-1", runtime.GOOS+":b:1:500", false))
			}()
			<-blocked
			foreignHookSessionKey = previous
			time.Sleep(foreignHookAnswerWithin + 500*time.Millisecond)
			return func() {
				close(release)
				<-done
				// The late answer keeps the account unanswered until a
				// later exchange is answered in time.
				server.call(server.aliceToken, foreignHookTestCall("s-1", runtime.GOOS+":b:1:500", false))
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newForeignHookRealPublishTestServer(t)
			previousWithin, previousHold := foreignHookAnswerWithin, foreignHookExchangeHold
			foreignHookAnswerWithin, foreignHookExchangeHold = foreignHookTestAnswerWithin, 2*foreignHookTestAnswerWithin
			t.Cleanup(func() { foreignHookAnswerWithin, foreignHookExchangeHold = previousWithin, previousHold })
			writes := countForeignHookAllowWrites(t)
			key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: runtime.GOOS + ":b:1:500"}
			if got := server.call(server.aliceToken, foreignHookTestCall("s-1", key.Process, true)); got.Deny {
				t.Fatalf("alice's clean session start: %+v", got)
			}
			before := writes.of(server.alice)
			server.api.renewForeignHookSessionProofsOnce()
			if writes.of(server.alice) != before+1 {
				t.Fatalf("a gateway that answers renews the proof: %d writes, want %d", writes.of(server.alice), before+1)
			}

			resume := tc.stall(t, server)
			stalled := writes.of(server.alice)
			for range 3 {
				server.api.renewForeignHookSessionProofsOnce()
			}
			if writes.of(server.alice) != stalled {
				t.Fatalf("a gateway that does not answer renewed the proof: %d writes, want %d", writes.of(server.alice), stalled)
			}
			if err := foreignHookOutageAfter(server, server.alice, key, foreignHookProofExpired); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
				t.Fatalf("the earlier allow 90 s after its last renewal: %v, want ErrPublishedSessionUnavailable", err)
			}

			resume()
			resumed := writes.of(server.alice)
			server.api.renewForeignHookSessionProofsOnce()
			if writes.of(server.alice) != resumed+1 {
				t.Fatalf("the gateway answers again and renews the proof: %d writes, want %d", writes.of(server.alice), resumed+1)
			}
			if err := foreignHookOutageAfter(server, server.alice, key, 0); err != nil {
				t.Fatalf("the renewed allow: %v", err)
			}
		})
	}
}

// foreignHookTestAnswerWithin is the answer budget of these tests: short
// enough to wait out, long enough that an ordinary exchange and a /health
// probe under -race on a loaded host answer within it. The tests hold an
// allow open for twice that (foreignHookExchangeHold), so an exchange
// answered just past the budget, and a renewal on a loaded host, still
// answer allow rather than revoke the account's key.
const foreignHookTestAnswerWithin = 3 * time.Second

// foreignHookServeForTest answers on ln as the hook listener does. It reads
// each request before it answers: a reply written over an unread request
// can reach the client as a reset instead of the answer.
func foreignHookServeForTest(t *testing.T, ln net.Listener) {
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(ln) }()
}

// foreignHookForgetListenersForTest stops probing addr (a listener that
// was closed for good).
func foreignHookForgetListenersForTest(server *foreignHookPublishTestServer, addr net.Addr) {
	s := &server.api.foreignHookServing
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.listeners[:0]
	for _, listener := range s.listeners {
		if listener.String() != addr.String() {
			kept = append(kept, listener)
		}
	}
	s.listeners = kept
}

// The 1.0.4 guard review (round 6, P2): whether the gateway answered a hook
// is kept, not sampled at the renewal. An exchange that got no answer within
// the hook's budget, counted from its arrival, stops the renewal of its
// account's proofs until a later exchange of the account is answered in
// time, also when it waited outside the handler (for the caller's run slot)
// or ended before the renewal looked (the hook gave up). Before, only an
// exchange still being decided at the renewal, counted from after its body
// was read, stopped it, so a dropped exchange left the proofs renewed for
// 15 minutes. Another account's proofs are still renewed.
func TestForeignHookSessionProofIsNotRenewedAfterAnExchangeWentUnanswered(t *testing.T) {
	for _, tc := range []struct {
		name string
		// drop makes one exchange of alice go unanswered within the budget.
		drop func(t *testing.T, server *foreignHookPublishTestServer, budget time.Duration)
	}{
		{name: "the exchange waits for the caller's run slot until the hook gives up", drop: func(t *testing.T, server *foreignHookPublishTestServer, budget time.Duration) {
			release, run, refusal, _ := server.api.hookCallerLimits.acquire(server.alice)
			if refusal != "" {
				t.Fatalf("holding alice's run slot: %s", refusal)
			}
			run <- struct{}{}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			if _, body := server.exchangeCtx(ctx, server.aliceToken, foreignHookTestCall("s-1", runtime.GOOS+":b:1:500", false)); len(body) != 0 {
				t.Fatalf("an exchange that never got a run slot was answered: %s", body)
			}
			<-run
			release()
		}},
		{name: "the exchange is answered after the hook's budget", drop: func(t *testing.T, server *foreignHookPublishTestServer, budget time.Duration) {
			previous := foreignHookSessionKey
			foreignHookSessionKey = func(root, identity string) (enterprisepolicy.SessionRecordKey, error) {
				time.Sleep(budget + 500*time.Millisecond)
				return previous(root, identity)
			}
			defer func() { foreignHookSessionKey = previous }()
			server.call(server.aliceToken, foreignHookTestCall("s-1", runtime.GOOS+":b:1:500", false))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newForeignHookRealPublishTestServer(t)
			server.api.hookCallerLimits.running = 1
			previousWithin, previousHold := foreignHookAnswerWithin, foreignHookExchangeHold
			foreignHookAnswerWithin, foreignHookExchangeHold = foreignHookTestAnswerWithin, 2*foreignHookTestAnswerWithin
			t.Cleanup(func() { foreignHookAnswerWithin, foreignHookExchangeHold = previousWithin, previousHold })
			writes := countForeignHookAllowWrites(t)
			key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: runtime.GOOS + ":b:1:500"}
			for _, token := range []string{server.aliceToken, server.bobToken} {
				if got := server.call(token, foreignHookTestCall("s-1", key.Process, true)); got.Deny {
					t.Fatalf("a clean session start: %+v", got)
				}
			}

			tc.drop(t, server, foreignHookAnswerWithin)
			alice, bob := writes.of(server.alice), writes.of(server.bob)
			for range 3 {
				server.api.renewForeignHookSessionProofsOnce()
			}
			if writes.of(server.alice) != alice {
				t.Fatalf("the proof of an account whose exchange went unanswered was renewed: %d writes, want %d", writes.of(server.alice), alice)
			}
			if writes.of(server.bob) != bob+3 {
				t.Fatalf("another account's proof: %d writes, want %d", writes.of(server.bob), bob+3)
			}
			if err := foreignHookOutageAfter(server, server.alice, key, foreignHookProofExpired); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
				t.Fatalf("the earlier allow 90 s after its last renewal: %v, want ErrPublishedSessionUnavailable", err)
			}

			if got := server.call(server.aliceToken, foreignHookTestCall("s-1", key.Process, false)); got.Deny {
				t.Fatalf("alice's next call: %+v", got)
			}
			answered := writes.of(server.alice)
			server.api.renewForeignHookSessionProofsOnce()
			if writes.of(server.alice) != answered+1 {
				t.Fatalf("a later exchange answered in time renews the proof again: %d writes, want %d", writes.of(server.alice), answered+1)
			}
		})
	}
}

// A refusal and a decision for another session cannot answer the guarded
// session whose call the gateway dropped. The account's missed-call mark
// applies to each proof until that session itself gets a timely decision.
func TestForeignHookSessionProofNeedsItsOwnDecidedAnswerAfterAMissedCall(t *testing.T) {
	for _, tc := range []struct {
		name string
		try  func(*testing.T, *foreignHookPublishTestServer)
	}{
		{name: "invalid update", try: func(t *testing.T, server *foreignHookPublishTestServer) {
			code, _ := server.exchange(server.aliceToken, map[string]any{"key": "invalid"})
			if code != http.StatusBadRequest {
				t.Fatalf("invalid update: status %d, want 400", code)
			}
		}},
		{name: "scope mismatch", try: func(t *testing.T, server *foreignHookPublishTestServer) {
			update := foreignHookTestCall("s-1", runtime.GOOS+":b:1:500", false)
			update["key"].(map[string]any)["connector"] = "codex"
			code, _ := server.exchange(server.aliceToken, update)
			if code != http.StatusForbidden {
				t.Fatalf("scope mismatch: status %d, want 403", code)
			}
		}},
		{name: "rate limit refusal", try: func(t *testing.T, server *foreignHookPublishTestServer) {
			server.api.hookCallerLimits.inFlight = 1
			release, _, refusal, _ := server.api.hookCallerLimits.acquire(server.alice)
			if refusal != "" {
				t.Fatalf("holding alice's request budget: %s", refusal)
			}
			defer release()
			code, _ := server.exchange(server.aliceToken, foreignHookTestCall("s-1", runtime.GOOS+":b:1:500", false))
			if code != http.StatusTooManyRequests {
				t.Fatalf("rate limit refusal: status %d, want 429", code)
			}
		}},
		{name: "another session is allowed", try: func(t *testing.T, server *foreignHookPublishTestServer) {
			if got := server.call(server.aliceToken, foreignHookTestCall("s-2", runtime.GOOS+":b:2:600", true)); got.Deny {
				t.Fatalf("s-2's decision: %+v", got)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := newForeignHookRealPublishTestServer(t)
			server.api.hookCallerLimits.running = 1
			previousWithin, previousHold := foreignHookAnswerWithin, foreignHookExchangeHold
			foreignHookAnswerWithin, foreignHookExchangeHold = foreignHookTestAnswerWithin, 2*foreignHookTestAnswerWithin
			t.Cleanup(func() { foreignHookAnswerWithin, foreignHookExchangeHold = previousWithin, previousHold })
			writes := countForeignHookAllowWrites(t)
			key := enterprisepolicy.SessionKey{Connector: "claudecode", Session: "s-1", Process: runtime.GOOS + ":b:1:500"}
			if got := server.call(server.aliceToken, foreignHookTestCall(key.Session, key.Process, true)); got.Deny {
				t.Fatalf("s-1's clean start: %+v", got)
			}

			release, run, refusal, _ := server.api.hookCallerLimits.acquire(server.alice)
			if refusal != "" {
				t.Fatalf("holding alice's run slot: %s", refusal)
			}
			run <- struct{}{}
			ctx, cancel := context.WithTimeout(context.Background(), foreignHookAnswerWithin)
			defer cancel()
			if _, body := server.exchangeCtx(ctx, server.aliceToken, foreignHookTestCall(key.Session, key.Process, false)); len(body) != 0 {
				t.Fatalf("dropped s-1 exchange was answered: %s", body)
			}
			<-run
			release()

			tc.try(t, server)
			s1 := writes.ofSession(server.alice, key)
			for range 3 {
				server.api.renewForeignHookSessionProofsOnce()
			}
			if got := writes.ofSession(server.alice, key); got != s1 {
				t.Fatalf("s-1 renewed after %s: %d writes, want %d", tc.name, got, s1)
			}
			if err := foreignHookOutageAfter(server, server.alice, key, foreignHookProofExpired); !errors.Is(err, enterprisepolicy.ErrPublishedSessionUnavailable) {
				t.Fatalf("s-1 at 92 seconds: %v, want ErrPublishedSessionUnavailable", err)
			}

			if got := server.call(server.aliceToken, foreignHookTestCall(key.Session, key.Process, false)); got.Deny {
				t.Fatalf("s-1's next decision: %+v", got)
			}
			answered := writes.ofSession(server.alice, key)
			server.api.renewForeignHookSessionProofsOnce()
			if got := writes.ofSession(server.alice, key); got != answered+1 {
				t.Fatalf("s-1 did not resume after its own decision: %d writes, want %d", got, answered+1)
			}
		})
	}
}
