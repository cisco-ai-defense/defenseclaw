// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// The outage proof (1.0.4 guard: fail closed by class).
//
// The hook cannot learn of a revocation the gateway failed to write, so an
// allow must not outlive its proof. The protected allow records of a
// session are that proof: the hook accepts one during an outage for at most
// enterprisepolicy.PublishedSessionProofLifetime after the gateway last
// wrote it. So:
//
//   - every exchange that answers allow with the account's key keeps the
//     session's proof (keepForeignHookSessionProof), and this gateway renews
//     it every foreignHookSessionRenewEvery while it runs, as an exchange
//     would: under the account's locks, with the key and the guardian's
//     removals read again, from the private store's record of the session
//     (enterprisepolicy.ForeignHookSessionRenewable);
//   - a denial of the session stops its renewal at once
//     (dropForeignHookSessionProof); so do a revocation of the account that
//     is owed, a session the store no longer allows, and an agent that made
//     no exchange for foreignHookSessionProofIdle; a read that fails and a
//     closed account renew nothing until they are resolved;
//   - a gateway that does not answer the hooks renews nothing: before each
//     round it asks every listener the hooks call (the hook socket and the
//     TCP API it serves) for /health, and renews only when each answers
//     within foreignHookAnswerWithin. Every exchange is timed from its
//     arrival at the listener (answerForeignHooks): an account with one
//     waiting longer than that, or with one that went unanswered (answered
//     late, refused, or its hook gave up first, also while it waited for the
//     caller's run slot), has each proof renewed again only once that
//     session has a later, in-time guard decision. A gateway that stops, crashes,
//     hangs, is wedged or has run out of connections therefore renews
//     nothing, whether or not its process still runs.
//
// Whatever write failed, an earlier allow therefore ends by itself at most
// the proof lifetime after its last renewal. A denial whose revocation
// writes fail also closes the account (foreignHookDenialRevocation), and
// reports the denial as FAILED, with the time the last allow ends, when
// that fails too.

// foreignHookSessionRenewEvery is how often the proofs are renewed, and
// foreignHookSessionProofIdle how long after its last exchange a session's
// proof is still renewed (replaceable in tests).
var (
	foreignHookSessionRenewEvery = enterprisepolicy.PublishedSessionRenewEvery
	foreignHookSessionProofIdle  = 15 * time.Minute
)

// foreignHookAnswerWithin is how long the gateway may take to answer a
// hook before it counts as not answering: the hook gives a session exchange
// at most 5 seconds (hookForeignGuardMaxScan in internal/cli), and then
// decides as in an outage (replaceable in tests).
var foreignHookAnswerWithin = 5 * time.Second

// foreignHookServing is what tells whether this gateway answers the hooks:
// the listeners the hooks call, the exchanges it has not answered yet, and
// the accounts whose last exchange went unanswered.
type foreignHookServing struct {
	mu        sync.Mutex
	listeners []net.Addr
	next      uint64
	pending   map[uint64]*foreignHookExchangeTiming
	// unanswered is, per account, when an exchange of it last went
	// unanswered ("" for one that ended late before its account was known).
	// It is an epoch: each session needs its own later decided answer.
	unanswered map[string]time.Time
}

// foreignHookExchangeTiming is one session exchange from its arrival at the
// listener: the account it came from, once known.
type foreignHookExchangeTiming struct {
	arrived       time.Time
	identity      string
	answer        *foreignHookAnswerWriter
	decidedInTime bool // handleForeignHookSession completed a 200 guard decision in time
}

type foreignHookExchangeTimingContextKey struct{}

// serveForeignHooks records a listener the hooks call; the proofs are
// renewed only while each of them answers.
func (a *APIServer) serveForeignHooks(ln net.Listener) {
	s := &a.foreignHookServing
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listeners = append(s.listeners, ln.Addr())
}

// answerForeignHooks times every session exchange next serves from the
// moment it arrives, before admission, authentication and the body: one
// whose 200 guard decision was not written within foreignHookAnswerWithin
// of its arrival, while its hook still waited, went unanswered. Each
// session's proof is renewed again only after its own later decided answer.
func (a *APIServer) answerForeignHooks(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, enterprisepolicy.ForeignHookSessionPathPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		s := &a.foreignHookServing
		timing := &foreignHookExchangeTiming{arrived: time.Now()}
		s.mu.Lock()
		if s.pending == nil {
			s.pending = map[uint64]*foreignHookExchangeTiming{}
		}
		s.next++
		id := s.next
		s.pending[id] = timing
		s.mu.Unlock()
		answer := &foreignHookAnswerWriter{ResponseWriter: w, ctx: r.Context(), within: timing.arrived.Add(foreignHookAnswerWithin)}
		timing.answer = answer
		defer func() {
			late := time.Since(timing.arrived) > foreignHookAnswerWithin
			s.mu.Lock()
			defer s.mu.Unlock()
			delete(s.pending, id)
			switch {
			case timing.decidedInTime:
				// A decision for one session never clears another session's miss.
			case timing.identity != "" || late:
				if s.unanswered == nil {
					s.unanswered = map[string]time.Time{}
				}
				s.unanswered[timing.identity] = time.Now()
			}
			// A hook that left in time before naming its account was owed
			// no answer.
		}()
		next.ServeHTTP(answer, r.WithContext(context.WithValue(r.Context(), foreignHookExchangeTimingContextKey{}, timing)))
	})
}

// foreignHookAnswerWriter notes whether the answer of an exchange began
// before its deadline while its hook still waited.
type foreignHookAnswerWriter struct {
	http.ResponseWriter
	ctx     context.Context
	within  time.Time
	written bool
	inTime  bool
	code    int
}

func (w *foreignHookAnswerWriter) answer(code int) {
	if !w.written {
		w.written = true
		w.code = code
		w.inTime = w.ctx.Err() == nil && !time.Now().After(w.within)
	}
}

func (w *foreignHookAnswerWriter) WriteHeader(code int) {
	w.answer(code)
	w.ResponseWriter.WriteHeader(code)
}

func (w *foreignHookAnswerWriter) Write(data []byte) (int, error) {
	w.answer(http.StatusOK)
	return w.ResponseWriter.Write(data)
}

// Unwrap lets http.ResponseController reach the connection (the fenced
// allow bounds and flushes its write).
func (w *foreignHookAnswerWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// noteForeignHookSessionDecision is called only after the handler wrote a
// complete 200 guard decision. Refusals and middleware answers do not count.
func noteForeignHookSessionDecision(ctx context.Context) {
	if timing, ok := ctx.Value(foreignHookExchangeTimingContextKey{}).(*foreignHookExchangeTiming); ok {
		answer := timing.answer
		timing.decidedInTime = answer != nil && answer.inTime && answer.code == http.StatusOK &&
			ctx.Err() == nil && !time.Now().After(answer.within)
	}
}

// foreignHookDecidedInTime returns the arrival of this session's own
// decided exchange, or zero if it was late, refused or not fully written.
func foreignHookDecidedInTime(ctx context.Context) time.Time {
	timing, ok := ctx.Value(foreignHookExchangeTimingContextKey{}).(*foreignHookExchangeTiming)
	if !ok || !timing.decidedInTime {
		return time.Time{}
	}
	return timing.arrived
}

// noteForeignHookExchangeAccount names the account of the session exchange
// on ctx, if any, as soon as the caller is verified.
func (a *APIServer) noteForeignHookExchangeAccount(ctx context.Context, identity string) {
	timing, ok := ctx.Value(foreignHookExchangeTimingContextKey{}).(*foreignHookExchangeTiming)
	if !ok {
		return
	}
	s := &a.foreignHookServing
	s.mu.Lock()
	defer s.mu.Unlock()
	timing.identity = identity
}

// foreignHookGatewayAnswering is nil only while this gateway answers the
// hooks: it serves at least one listener, no exchange whose account is not
// known yet has waited longer than foreignHookAnswerWithin, and every
// listener answers /health within it. Completed misses are checked for
// each session by foreignHookAccountAnswered.
func (a *APIServer) foreignHookGatewayAnswering() error {
	s := &a.foreignHookServing
	s.mu.Lock()
	listeners := append([]net.Addr(nil), s.listeners...)
	waited := s.waitedLongest("")
	s.mu.Unlock()
	if len(listeners) == 0 {
		return errors.New("no listener serves the hooks")
	}
	if waited > foreignHookAnswerWithin {
		return fmt.Errorf("an exchange has waited %s for its answer", waited.Round(time.Second))
	}
	for _, addr := range listeners {
		ctx, cancel := context.WithTimeout(context.Background(), foreignHookAnswerWithin)
		err := probeForeignHookListener(ctx, addr)
		cancel()
		if err != nil {
			return fmt.Errorf("the %s listener does not answer: %w", addr.Network(), err)
		}
	}
	return nil
}

// foreignHookAccountAnswered is nil only while the gateway answers the
// account's hooks and this session itself has a timely decision after the
// account's (or unknown account's) latest unanswered exchange.
func (a *APIServer) foreignHookAccountAnswered(proof foreignHookSessionProof) error {
	s := &a.foreignHookServing
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, identity := range []string{"", proof.identity} {
		if at, ok := s.unanswered[identity]; ok && !proof.lastDecided.After(at) {
			return errors.New("the session has no in-time guard decision after an exchange went unanswered")
		}
	}
	if waited := s.waitedLongest(proof.identity); waited > foreignHookAnswerWithin {
		return fmt.Errorf("an exchange of the account has waited %s for its answer", waited.Round(time.Second))
	}
	return nil
}

// waitedLongest is how long the oldest pending exchange of identity has
// waited ("" for those whose account is not known yet); s.mu is held.
func (s *foreignHookServing) waitedLongest(identity string) time.Duration {
	var waited time.Duration
	for _, timing := range s.pending {
		if timing.identity == identity {
			waited = max(waited, time.Since(timing.arrived))
		}
	}
	return waited
}

// probeForeignHookListener asks the listener at addr for /health over a new
// connection, as a hook would connect; any HTTP answer is one.
func probeForeignHookListener(ctx context.Context, addr net.Addr) error {
	network, address := addr.Network(), addr.String()
	if tcp, ok := addr.(*net.TCPAddr); ok && (tcp.IP == nil || tcp.IP.IsUnspecified()) {
		address = net.JoinHostPort("127.0.0.1", fmt.Sprint(tcp.Port))
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/health", nil)
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// foreignHookSessionProof is one session whose proof this gateway renews:
// the account, the session key and when an exchange last allowed it.
type foreignHookSessionProof struct {
	identity    string
	key         enterprisepolicy.SessionKey
	seen        time.Time
	lastDecided time.Time
}

// foreignHookSessionProofs are the proofs this gateway process renews.
type foreignHookSessionProofs struct {
	mu     sync.Mutex
	proofs map[string]foreignHookSessionProof
}

func foreignHookSessionProofID(identity string, key enterprisepolicy.SessionKey) string {
	return strings.Join([]string{identity, key.Connector, key.Session, key.Process}, "\x00")
}

// keepForeignHookSessionProof renews the proof of key from now on (the
// caller answered it allow with the account's key).
func (a *APIServer) keepForeignHookSessionProof(ctx context.Context, identity string, key enterprisepolicy.SessionKey) {
	p := &a.foreignHookProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.proofs == nil {
		p.proofs = map[string]foreignHookSessionProof{}
	}
	p.proofs[foreignHookSessionProofID(identity, key)] = foreignHookSessionProof{identity: identity, key: key, seen: time.Now(), lastDecided: foreignHookDecidedInTime(ctx)}
}

// dropForeignHookSessionProof stops renewing every proof of identity's
// connector that shares the session or the agent process of key (the
// caller denied it).
func (a *APIServer) dropForeignHookSessionProof(identity string, key enterprisepolicy.SessionKey) {
	p := &a.foreignHookProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	for id, proof := range p.proofs {
		if proof.identity != identity || proof.key.Connector != key.Connector {
			continue
		}
		if (key.Session != "" && proof.key.Session == key.Session) || (key.Process != "" && proof.key.Process == key.Process) {
			delete(p.proofs, id)
		}
	}
}

// foreignHookSessionProofKept reports a proof still renewed, and forgets
// one whose agent made no exchange for foreignHookSessionProofIdle.
func (a *APIServer) foreignHookSessionProofKept(proof foreignHookSessionProof) (foreignHookSessionProof, bool) {
	p := &a.foreignHookProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	id := foreignHookSessionProofID(proof.identity, proof.key)
	current, ok := p.proofs[id]
	if ok && time.Since(current.seen) > foreignHookSessionProofIdle {
		delete(p.proofs, id)
		return foreignHookSessionProof{}, false
	}
	return current, ok
}

// foreignHookSessionProofList is every proof renewed now.
func (a *APIServer) foreignHookSessionProofList() []foreignHookSessionProof {
	p := &a.foreignHookProofs
	p.mu.Lock()
	defer p.mu.Unlock()
	list := make([]foreignHookSessionProof, 0, len(p.proofs))
	for _, proof := range p.proofs {
		list = append(list, proof)
	}
	return list
}

// currentForeignHookSessionPlaces are the places of the gateway's data
// directory, and false where it publishes no records.
func (a *APIServer) currentForeignHookSessionPlaces() (foreignHookSessionPlaces, bool) {
	dataDir := strings.TrimSpace(a.configDataDir())
	if !filepath.IsAbs(dataDir) {
		return foreignHookSessionPlaces{}, false
	}
	places := a.foreignHookSessionPlaces(dataDir)
	return places, places.recordRoot != ""
}

// renewForeignHookSessionProofs renews every proof every interval until ctx
// ends.
func (a *APIServer) renewForeignHookSessionProofs(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.renewForeignHookSessionProofsOnce()
		}
	}
}

// renewForeignHookSessionProofsOnce renews every proof once.
func (a *APIServer) renewForeignHookSessionProofsOnce() {
	places, ok := a.currentForeignHookSessionPlaces()
	if !ok {
		return
	}
	proofs := a.foreignHookSessionProofList()
	if len(proofs) == 0 {
		return
	}
	if err := a.foreignHookGatewayAnswering(); err != nil {
		fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the gateway does not answer the hooks, so the outage proofs of %d sessions were not renewed and end within %s: %v\n",
			len(proofs), enterprisepolicy.PublishedSessionProofLifetime, err)
		return
	}
	for _, proof := range proofs {
		if err := a.foreignHookAccountAnswered(proof); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the gateway did not answer a hook of the account, so the outage proof of a %s session was not renewed and ends within %s: %v\n",
				clipForeignHookAuditField(proof.key.Connector, 64), enterprisepolicy.PublishedSessionProofLifetime, err)
			continue
		}
		if err := a.renewForeignHookSessionProof(places, proof); err != nil {
			fmt.Fprintf(os.Stderr, "[gateway] foreign-hook session: the outage proof of a %s session was not renewed, so it ends within %s: %v\n",
				clipForeignHookAuditField(proof.key.Connector, 64), enterprisepolicy.PublishedSessionProofLifetime, err)
		}
	}
}

// errForeignHookProofNotRenewable is a proof the gateway stops renewing
// for good: the session is no longer allowed, or its account owes a
// revocation.
var errForeignHookProofNotRenewable = errors.New("the session's proof is no longer renewed")

// renewForeignHookSessionProof writes the allow records of one session
// again, as an exchange would answer it: under the account's exchange lock
// of this process and its removal lock, with the account's key read first,
// then the guardian's removals and the private store, while the account is
// not closed, and only within
// foreignHookExchangeHold of asking for the removal lock. Any doubt renews
// nothing. A proof a denial dropped meanwhile is not renewed.
func (a *APIServer) renewForeignHookSessionProof(places foreignHookSessionPlaces, proof foreignHookSessionProof) error {
	stateDir := enterprisepolicy.ForeignHookSessionStoreDir(places.dataDir, proof.identity)
	unlock := a.foreignHookSessionLocks.lock(stateDir)
	defer unlock()
	current, kept := a.foreignHookSessionProofKept(proof)
	if !kept {
		return nil
	}
	proof = current
	answerBy := time.Now().Add(foreignHookExchangeHold)
	ctx, cancel := context.WithTimeout(context.Background(), foreignHookExchangeWait)
	release, err := foreignHookAccountExchangeLock(ctx, places.dataDir, proof.identity)
	cancel()
	if err != nil {
		return fmt.Errorf("the account's removal lock: %w", err)
	}
	defer release()
	if a.foreignHookRevocationOwed(places, proof.identity) {
		a.dropForeignHookSessionProof(proof.identity, proof.key)
		return fmt.Errorf("%w: a revocation of the account is owed", errForeignHookProofNotRenewable)
	}
	if err := enterprisepolicy.PublishedSessionAccountClosed(places.recordRoot, proof.identity); err != nil {
		// Renewed again once the account is open (a revocation took).
		return err
	}
	recordKey, err := foreignHookSessionKey(places.recordRoot, proof.identity)
	if err != nil {
		return fmt.Errorf("the account's record key: %w", err)
	}
	removals, ledgerErr := a.foreignHookRemovals.forIdentity(places.removalsDir, proof.identity)
	if err := enterprisepolicy.ForeignHookSessionRenewable(stateDir, proof.key, removals, ledgerErr, time.Now()); err != nil {
		a.dropForeignHookSessionProof(proof.identity, proof.key)
		return fmt.Errorf("%w: %v", errForeignHookProofNotRenewable, err)
	}
	if !time.Now().Before(answerBy) {
		return errForeignHookExchangeExpired
	}
	if err := a.foreignHookAccountAnswered(proof); err != nil {
		return err
	}
	return foreignHookSessionPublish(places.recordRoot, proof.identity, proof.key, enterprisepolicy.GuardDecision{}, recordKey, time.Now())
}
