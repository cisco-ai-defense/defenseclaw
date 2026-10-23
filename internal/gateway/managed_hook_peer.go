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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Stable diagnostics returned to a standalone hook caller the gateway
// refuses. They name the policy, never another user's state.
const (
	managedHookReasonPeerUnverified    = "enterprise_managed_peer_unverified"
	managedHookReasonUIDUnregistered   = "enterprise_managed_uid_unregistered"
	managedHookReasonRootDenied        = "enterprise_managed_root_denied"
	managedHookReasonLedgerUnavailable = "enterprise_managed_ledger_unavailable"
	managedHookReasonConnectorUnknown  = "enterprise_managed_connector_unknown"
	managedHookReasonSurfaceUnverified = "enterprise_managed_surface_unverified"
	managedHookReasonGuardianOnly      = "enterprise_managed_guardian_only"
)

// managedHookPeer is the kernel-verified identity of a caller on the
// standalone hook socket. It comes from SO_PEERCRED / LOCAL_PEERCRED, never
// from anything the caller sent.
type managedHookPeer struct {
	UID  int
	GID  int
	PID  int
	Name string
	// Home is the caller's home directory from the account database, used
	// to resolve "~" in the caller's commands. Empty when it could not be
	// resolved; it is never the gateway service account's home.
	Home string
}

type managedHookPeerContextKey struct{}

func withManagedHookPeer(ctx context.Context, peer managedHookPeer) context.Context {
	return context.WithValue(ctx, managedHookPeerContextKey{}, peer)
}

func managedHookPeerFromContext(ctx context.Context) (managedHookPeer, bool) {
	if ctx == nil {
		return managedHookPeer{}, false
	}
	peer, ok := ctx.Value(managedHookPeerContextKey{}).(managedHookPeer)
	return peer, ok
}

// managedHookConnPeer carries one hook-socket connection's caller from the
// accept loop to its requests. The accept loop records only the kernel
// credentials; the account lookups run once, on the connection's first
// request, in that connection's goroutine.
type managedHookConnPeer struct {
	once    sync.Once
	resolve func() managedHookPeer
	peer    managedHookPeer
}

type managedHookConnPeerContextKey struct{}

func withManagedHookConnPeer(ctx context.Context, resolve func() managedHookPeer) context.Context {
	return context.WithValue(ctx, managedHookConnPeerContextKey{}, &managedHookConnPeer{resolve: resolve})
}

func (c *managedHookConnPeer) identity() managedHookPeer {
	c.once.Do(func() {
		c.peer = c.resolve()
		c.resolve = nil
	})
	return c.peer
}

// managedHookRequestPeer is the verified caller of a hook-socket request:
// the identity already bound to the request, or the connection's caller,
// resolved on first use.
func managedHookRequestPeer(ctx context.Context) (managedHookPeer, bool) {
	if peer, ok := managedHookPeerFromContext(ctx); ok {
		return peer, true
	}
	if ctx == nil {
		return managedHookPeer{}, false
	}
	conn, ok := ctx.Value(managedHookConnPeerContextKey{}).(*managedHookConnPeer)
	if !ok || conn == nil {
		return managedHookPeer{}, false
	}
	return conn.identity(), true
}

// managedHookLedgerTarget is one row of the guardian authorization ledger as
// the hook socket and the per-user credentials need it. UID is optional: the
// guardian names users, and a ledger that also records the numeric uid lets
// directory users match without a name lookup. SID is set only by the
// Windows guardian; the hook socket never consults it.
type managedHookLedgerTarget struct {
	User      string `json:"user,omitempty"`
	UID       *int   `json:"uid,omitempty"`
	SID       string `json:"sid,omitempty"`
	Connector string `json:"connector"`
	OK        bool   `json:"ok"`
}

type managedHookLedger struct {
	Targets []managedHookLedgerTarget `json:"protected_targets"`
	// Refused is read from the enumerator's refused-surfaces file: users
	// whose only installs of a machine-policy connector are app or
	// extension surfaces refused under unverified_versions: refuse.
	Refused []managedHookLedgerTarget `json:"refused_surfaces,omitempty"`
}

// refused reports whether peer's connector installs are refused surfaces.
func (l managedHookLedger) refused(peer managedHookPeer, connector string) bool {
	for _, target := range l.Refused {
		if !strings.EqualFold(strings.TrimSpace(target.Connector), connector) {
			continue
		}
		if (target.UID != nil && *target.UID == peer.UID) || (target.UID == nil && peer.Name != "" && target.User == peer.Name) {
			return true
		}
	}
	return false
}

func (l managedHookLedger) matches(peer managedHookPeer, target managedHookLedgerTarget) bool {
	if !target.OK {
		return false
	}
	if target.UID != nil {
		return *target.UID == peer.UID
	}
	return peer.Name != "" && target.User == peer.Name
}

// enrolled reports whether peer holds a successfully protected target for
// connector.
func (l managedHookLedger) enrolled(peer managedHookPeer, connector string) bool {
	for _, target := range l.Targets {
		if strings.EqualFold(strings.TrimSpace(target.Connector), connector) && l.matches(peer, target) {
			return true
		}
	}
	return false
}

// enrolledAny reports whether peer holds any protected target.
func (l managedHookLedger) enrolledAny(peer managedHookPeer) bool {
	for _, target := range l.Targets {
		if l.matches(peer, target) {
			return true
		}
	}
	return false
}

// managedHookDecision is the socket-level authorization result.
type managedHookDecision struct {
	Allow  bool
	Status int
	Reason string
	Exempt bool
}

func allowManagedHook() managedHookDecision {
	return managedHookDecision{Allow: true, Status: http.StatusOK}
}

func denyManagedHook(status int, reason string) managedHookDecision {
	return managedHookDecision{Status: status, Reason: reason}
}

// managedHookAuthorizer decides, per request, whether a kernel-verified
// caller may use a connector's hook route on the standalone hook socket.
//
//   - Connectors whose DefenseClaw hooks are published through vendor
//     machine policy inspect every local user: the policy runs the hook for
//     all of them, so refusing an unenrolled user would only block their
//     agent. enrollment.unenrolled_users=deny restores strict enrollment.
//   - Per-user connectors require that uid to hold a protected target for
//     that connector in the guardian's root-owned authorization ledger
//     (W-28 parity: an unregistered caller never reaches inspection).
//   - uid 0 follows enrollment.root.
//   - enrollment.exempt_users are authorized without enrollment; they are
//     still inspected under their guardrail profile, which blocks as for
//     anyone (GAP-0328), and every call is logged.
type managedHookAuthorizer struct {
	enrollment    config.EnterpriseEnrollmentConfig
	machinePolicy map[string]bool
	loadLedger    func() (managedHookLedger, error)
	// loadRefused reads the refused surfaces; nil means none.
	loadRefused func() (managedHookLedger, error)
}

func newManagedHookAuthorizer(
	enrollment config.EnterpriseEnrollmentConfig,
	machinePolicyConnectors []string,
	loadLedger func() (managedHookLedger, error),
) *managedHookAuthorizer {
	machine := make(map[string]bool, len(machinePolicyConnectors))
	for _, name := range machinePolicyConnectors {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			machine[name] = true
		}
	}
	return &managedHookAuthorizer{enrollment: enrollment, machinePolicy: machine, loadLedger: loadLedger}
}

// exempt reports whether enterprise.enrollment.exempt_users names the
// caller: by its uid or its account name as the account database gives it,
// or as a guardrail users entry selects the account (userEntryMatches) from
// its verified directory facts. A bare ent-alice then exempts the SSSD
// account ent-alice@dclab.test, as users: [ent-alice] selects it, and
// DCLAB\ent-alice or the UPN do too where the facts confirm them; it
// exempted nobody on a host with fully qualified names (GAP-0494). A local
// namesake is still exempted only by its own exact name or uid (GAP-0305).
func (z *managedHookAuthorizer) exempt(peer managedHookPeer) bool {
	uid := strconv.Itoa(peer.UID)
	named := false
	for _, entry := range z.enrollment.ExemptUsers {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == uid || (peer.Name != "" && entry == peer.Name) {
			return true
		}
		named = named || useridentity.KindForID(entry) == ""
	}
	if !named || peer.Name == "" || !identityFactsEnabled.Load() {
		return false
	}
	matches := func(facts useridentity.DirectoryFacts) bool {
		if facts.ResolvedAt.IsZero() {
			return false
		}
		subject := profileSubjectFromVerified(VerifiedSubject{
			UserID: uid, IDKind: useridentity.KindPOSIXUID, UserName: peer.Name, Directory: facts,
		}, false)
		return anyMatches(z.enrollment.ExemptUsers, func(entry string) bool { return userEntryMatches(&subject, entry) })
	}
	// Current facts the cache holds for the account that holds the uid (within
	// their lifetime and settled) decide without waiting, either way. Entries
	// select by account names (userEntryMatches), never by group, so they
	// need none of the fresh Open Directory answer a managed Mac waits for
	// on every group decision; the cache's other bounds (maxAge, the account
	// holding the uid now, the guardian's record) still apply. Settled facts
	// past their lifetime that match no entry reject the caller without
	// waiting (the refresh they started serves a later hook), so an enrolled
	// caller is not held on every expiry. Every other case waits for the
	// current answer, within identityDirectoryBudget (exemptIdentityDirectory):
	// missing facts, unsettled ones (a UPN or domain not given yet, which may
	// also still give one the directory has since dropped), invalidated facts
	// whatever they match (a profile reload or a guardian record with news
	// may stand for a UPN the directory now gives, listed in exempt_users;
	// rejecting on the old facts denied the exemption the release waited for,
	// continuation 3, loop round 3), and expired facts that match an entry,
	// since the directory may have removed that name since; a refresh that
	// fails or does not finish in time exempts no one (loop round 3). A name the facts gave
	// before therefore never exempts a caller after the directory dropped it
	// (review of r104 Q-identity, continuation 2, loop round 2), and waiting
	// on every hook, which held every caller or denied a named exemption on a
	// slow healthy directory, stays limited to the hooks that need a current
	// answer (loop rounds 1 and 2).
	cached, state := managedHookExemptFacts(peer.UID, true)
	switch {
	case state == exemptFactsCurrent:
		return matches(cached)
	case state == exemptFactsExpired && !matches(cached):
		return false
	}
	facts, state := managedHookExemptFacts(peer.UID, false)
	return state != exemptFactsNone && matches(facts)
}

// exemptFactsState is how far the directory facts managedHookExemptFacts
// returns decide an exemption.
type exemptFactsState int

const (
	// exemptFactsNone: no facts, unsettled ones that may lack a name a
	// current answer gives, or ones fetched before an invalidation (a
	// profile assignment change, a guardian record with news), which may
	// lack a name the change gave; a current answer decides.
	exemptFactsNone exemptFactsState = iota
	// exemptFactsExpired: settled facts past their lifetime. A name they
	// give may be one the directory has since dropped, so a match waits for
	// a current answer; a nonmatch rejects.
	exemptFactsExpired
	// exemptFactsCurrent: facts within their lifetime, fetched after the
	// last invalidation and settled, or a current answer; they decide.
	exemptFactsCurrent
)

// hostRunExempt reports whether the caller is exempt from enrollment as decide
// marks a hook call exempt (managedHookDecision.Exempt), so the
// require-sandbox gate allows its host runs: exempt_users names it and it is
// not root, which enterprise.enrollment.root governs and exempt_users never
// exempts. The policy views ask the same question (GAP-0555).
func (z *managedHookAuthorizer) hostRunExempt(peer managedHookPeer) bool {
	return peer.UID != 0 && z.exempt(peer)
}

// managedHookExemptFacts are the verified directory facts exempt matches a
// caller's names with, from the cache the caller's hook requests use; tests
// replace it. cached returns the facts the cache holds now, without waiting,
// and how far they decide (exemptFactsState); otherwise they are a current
// answer (exemptIdentityDirectory; on Windows, what a blocking hook read
// gets), so the first hook after a restart can use a UPN or DOMAIN\name
// exemption.
var managedHookExemptFacts = exemptIdentityDirectory

// decide authorizes one hook call. surface is the caller's
// hookexec.AgentSurfaceHeader: under unverified_versions: refuse a call
// from an app or extension surface that is not live-verified is refused
// (surface_unverified) whatever the user's enrollment, so an unverified
// surface is refused next to the same user's enrolled CLI. A user whose
// only installs are refused surfaces is in the refused list and is refused
// for the connector.
func (z *managedHookAuthorizer) decide(peer managedHookPeer, connectorName, surface string) managedHookDecision {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	if connectorName == "" {
		return denyManagedHook(http.StatusForbidden, managedHookReasonConnectorUnknown)
	}
	if peer.UID == 0 {
		if strings.EqualFold(strings.TrimSpace(z.enrollment.Root), config.EnterpriseRootDeny) {
			return denyManagedHook(http.StatusForbidden, managedHookReasonRootDenied)
		}
		return allowManagedHook()
	}
	refuse := z.enrollment.UnverifiedVersionsFor(connectorName) == config.EnterpriseUnverifiedRefuse
	if refuse && connector.SurfaceRefused(connectorName, surface, config.EnterpriseUnverifiedRefuse) {
		return denyManagedHook(http.StatusForbidden, managedHookReasonSurfaceUnverified)
	}
	if refuse && z.loadRefused != nil {
		refused, err := z.loadRefused()
		if err != nil {
			return denyManagedHook(http.StatusServiceUnavailable, managedHookReasonLedgerUnavailable)
		}
		if refused.refused(peer, connectorName) {
			return denyManagedHook(http.StatusForbidden, managedHookReasonSurfaceUnverified)
		}
	}
	if z.hostRunExempt(peer) {
		decision := allowManagedHook()
		decision.Exempt = true
		return decision
	}
	machine := z.machinePolicy[connectorName]
	strict := strings.EqualFold(strings.TrimSpace(z.enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny)
	if machine && !strict {
		return allowManagedHook()
	}
	if z.loadLedger == nil {
		return denyManagedHook(http.StatusServiceUnavailable, managedHookReasonLedgerUnavailable)
	}
	ledger, err := z.loadLedger()
	if err != nil {
		return denyManagedHook(http.StatusServiceUnavailable, managedHookReasonLedgerUnavailable)
	}
	if machine {
		if ledger.enrolledAny(peer) {
			return allowManagedHook()
		}
		return denyManagedHook(http.StatusForbidden, managedHookReasonUIDUnregistered)
	}
	if ledger.enrolled(peer, connectorName) {
		return allowManagedHook()
	}
	return denyManagedHook(http.StatusForbidden, managedHookReasonUIDUnregistered)
}

// managedHookLedgerLoader reads the root-owned authorization ledger with
// the same trust checks readiness uses, caching the parsed rows briefly so a
// busy agent does not re-read a multi-megabyte ledger per tool call.
type managedHookLedgerLoader struct {
	path string
	ttl  time.Duration
	now  func() time.Time
	read func(string) (managedHookLedger, error)

	mu       sync.Mutex
	loadedAt time.Time
	modTime  time.Time
	size     int64
	ledger   managedHookLedger
	err      error
	// generation increases on every re-read, so a consumer that derives
	// state from the ledger can tell a cached answer from a new one.
	generation uint64
}

func newManagedHookLedgerLoader(path string) *managedHookLedgerLoader {
	return &managedHookLedgerLoader{path: path, ttl: 2 * time.Second, now: time.Now, read: readManagedHookLedger}
}

// newManagedHookRefusedLoader caches the refused-surfaces file like the
// ledger.
func newManagedHookRefusedLoader(path string) *managedHookLedgerLoader {
	return &managedHookLedgerLoader{path: path, ttl: 2 * time.Second, now: time.Now, read: readManagedHookRefusedSurfaces}
}

func (l *managedHookLedgerLoader) Load() (managedHookLedger, error) {
	ledger, _, err := l.LoadGeneration()
	return ledger, err
}

// LoadGeneration is Load plus the generation of the answer.
func (l *managedHookLedgerLoader) LoadGeneration() (managedHookLedger, uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	info, statErr := os.Stat(l.path)
	now := l.now()
	if statErr == nil && !l.loadedAt.IsZero() && now.Sub(l.loadedAt) < l.ttl &&
		info.ModTime().Equal(l.modTime) && info.Size() == l.size {
		return l.ledger, l.generation, l.err
	}
	l.loadedAt = now
	if statErr == nil {
		l.modTime, l.size = info.ModTime(), info.Size()
	}
	read := l.read
	if read == nil {
		read = readManagedHookLedger
	}
	l.ledger, l.err = read(l.path)
	l.generation++
	return l.ledger, l.generation, l.err
}

// readManagedHookRefusedSurfaces reads the refused-surfaces file; a missing
// file means nothing is refused.
func readManagedHookRefusedSurfaces(path string) (managedHookLedger, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return managedHookLedger{}, nil
	}
	return readManagedHookLedger(path)
}

func readManagedHookLedger(path string) (managedHookLedger, error) {
	if err := validateManagedGuardianAuthorization(path, "hook guardian authorization"); err != nil {
		return managedHookLedger{}, err
	}
	file, err := os.Open(path)
	if err != nil {
		return managedHookLedger{}, fmt.Errorf("open hook guardian authorization: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, managedGuardianAuthorizationMaxBytes+1))
	if err != nil {
		return managedHookLedger{}, fmt.Errorf("read hook guardian authorization: %w", err)
	}
	if int64(len(data)) > managedGuardianAuthorizationMaxBytes {
		return managedHookLedger{}, errors.New("hook guardian authorization exceeds the size limit")
	}
	var ledger managedHookLedger
	if err := json.Unmarshal(data, &ledger); err != nil {
		return managedHookLedger{}, fmt.Errorf("decode hook guardian authorization: %w", err)
	}
	return ledger, nil
}

// managedHookIdentityHeaders are the caller-supplied identity headers the
// hook socket replaces with the kernel-verified identity.
var managedHookIdentityHeaders = []string{
	llmEventUserIDHeader, llmEventUserNameHeader,
	"X-User-Id", "X-User-ID", "X-User", "X-User-Name", "X-Username",
}

// managedHookCredentialHeaders are never meaningful on the hook socket: the
// peer is authenticated by the kernel, so a bearer a caller presents could
// only be an attempt to borrow another authority.
var managedHookCredentialHeaders = []string{"Authorization", "X-DefenseClaw-Token", "X-DC-Auth"}

// managedHookPeerIdentityMiddleware is the outermost handler on the hook
// socket. It rewrites the request so every downstream layer sees one
// trustworthy identity: RemoteAddr becomes loopback (the socket is
// host-local, and loopback-only handlers and the loopback-exempt rate
// limiter must treat it as such), caller-supplied identity and credential
// headers are removed, and the kernel-verified uid and account name are set
// as the trusted user identity the correlation layer already honors. The
// caller's account name and home are resolved here, once per connection.
func managedHookPeerIdentityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := managedHookRequestPeer(r.Context())
		if !ok {
			writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonPeerUnverified)
			return
		}
		r = r.WithContext(withManagedHookPeer(r.Context(), peer))
		r.RemoteAddr = "127.0.0.1:0"
		for _, header := range managedHookIdentityHeaders {
			r.Header.Del(header)
		}
		for _, header := range managedHookCredentialHeaders {
			r.Header.Del(header)
		}
		r.Header.Set(llmEventUserIDHeader, strconv.Itoa(peer.UID))
		if peer.Name != "" {
			r.Header.Set(llmEventUserNameHeader, peer.Name)
		}
		next.ServeHTTP(w, r)
	})
}

// managedHookRouteScope maps a hook-socket request to the connector whose
// authority it uses and the context marker the handlers expect.
func (a *APIServer) managedHookRouteScope(r *http.Request) (connectorName string, inspect bool) {
	if strings.HasPrefix(r.URL.Path, "/api/v1/inspect/") {
		name := strings.ToLower(strings.TrimSpace(r.Header.Get("X-DefenseClaw-Connector")))
		if name == "" || a.connectorRegistry == nil {
			return "", true
		}
		if _, registered := a.connectorRegistry.Get(name); !registered {
			return "", true
		}
		return name, true
	}
	if scope, ok := a.hookTokenScopeForPath(r.URL.Path); ok {
		return scope, false
	}
	return "", false
}

// managedHookPeerAuth replaces bearer-token authentication on the hook
// socket with kernel-verified peer authorization.
func (a *APIServer) managedHookPeerAuth(authorizer *managedHookAuthorizer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, ok := managedHookPeerFromContext(r.Context())
		if !ok || authorizer == nil {
			writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonPeerUnverified)
			return
		}
		route := r.Pattern
		if route == "" {
			route = sanitizeRouteForTelemetry(r.URL.Path)
		}
		if strings.HasPrefix(r.URL.Path, sandboxrelay.PathPrefix) {
			// The managed sandbox routes refuse uid 0 outright, take their
			// class's budget, and decide once the registration or the
			// connector claim names the connector (sandbox_authority.go).
			a.serveSandboxRoute(authorizer, peer, route, w, r, next)
			return
		}
		r, release := a.admitHookCaller(w, r, strconv.Itoa(peer.UID), route)
		if release == nil {
			return
		}
		defer release()
		if r.URL.Path == managedRefusalAuditPath {
			// Any kernel-verified local account may report its own refused
			// policy write; the route has no connector to enroll for.
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == managedGuardianRepairAuditPath {
			// The guardian runs as root and reports repairs over the same
			// kernel-verified socket; user hooks cannot create audit rows.
			if peer.UID != 0 {
				writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonGuardianOnly)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get(hookexec.ClientRefusalHeader) == hookexec.ManagedUserNamespaceReason {
			// A hook in a private user namespace refused its agent before it
			// could check the runtime state; the refusal left no audit row or
			// log line, unlike a refused unenrolled account (GAP-0923).
			connectorName, _ := a.managedHookRouteScope(r)
			fmt.Fprintf(os.Stderr,
				"[sidecar-api] hook socket refused uid=%d connector=%q route=%s reason=%s: the agent runs in a private user namespace\n",
				peer.UID, connectorName, route, hookexec.ManagedUserNamespaceReason)
			a.emitHTTPAuthFailureForConnector(r.Context(), r, route, gatewaylog.ErrCodeAuthInvalidToken, hookexec.ManagedUserNamespaceReason, connectorName)
			writeManagedHookRefusal(w, http.StatusForbidden, hookexec.ManagedUserNamespaceReason)
			return
		}
		connectorName, inspect := a.managedHookRouteScope(r)
		decision := authorizer.decide(peer, connectorName, r.Header.Get(hookexec.AgentSurfaceHeader))
		if !decision.Allow {
			fmt.Fprintf(os.Stderr,
				"[sidecar-api] hook socket refused uid=%d connector=%q route=%s reason=%s\n",
				peer.UID, connectorName, route, decision.Reason)
			a.emitHTTPAuthFailureForConnector(r.Context(), r, route, gatewaylog.ErrCodeAuthInvalidToken, decision.Reason, connectorName)
			writeManagedHookRefusal(w, decision.Status, decision.Reason)
			return
		}
		if decision.Exempt {
			fmt.Fprintf(os.Stderr,
				"[sidecar-api] enterprise_exempt_user uid=%d user=%q connector=%q route=%s\n",
				peer.UID, peer.Name, connectorName, route)
		}
		ctx := PromoteSessionIfAuthenticated(r.Context())
		ctx = attachVerifiedSubject(ctx, a.observabilityV8RuntimeEmitter(), strconv.Itoa(peer.UID), peer.Name, subjectSourcePeerCredentials)
		if inspect {
			ctx = withAuthenticatedInspectConnector(ctx, connectorName)
		} else {
			ctx = withAuthenticatedHookConnector(ctx, connectorName)
		}
		if decision.Exempt {
			a.serveEnterpriseExemptHookCall(w, r.WithContext(withEnterpriseExemptUser(ctx)), next, peer, connectorName, route, inspect)
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// serveEnterpriseExemptHookCall serves an exempt account's hook call, then
// writes its enterprise-exempt-user row when the handler answered it (2xx)
// on a route that inspects the call: a call the handler refused, a
// malformed one for example, was not inspected and writes none (GAP-1285).
// Neither does a Codex notification or a foreign hook session report, which
// the handler records without inspecting: the row would also start the
// account's audit interval and hide its next inspected call.
func (a *APIServer) serveEnterpriseExemptHookCall(
	w http.ResponseWriter, r *http.Request, next http.Handler,
	peer managedHookPeer, connectorName, route string, inspect bool,
) {
	if !inspect && !exemptAuditedHookPath(r.URL.Path) {
		next.ServeHTTP(w, r)
		return
	}
	sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	next.ServeHTTP(sw, r)
	if sw.status >= 200 && sw.status < 300 {
		a.auditEnterpriseExemptUser(r.Context(), peer, connectorName, route, time.Now())
	}
}

// exemptAuditedHookPath reports whether a hook socket route that is not an
// inspect endpoint inspects the call: every connector hook route does; the
// Codex notifier and the foreign hook session report do not.
func exemptAuditedHookPath(path string) bool {
	return path != "/api/v1/codex/notify" && !strings.HasPrefix(path, enterprisepolicy.ForeignHookSessionPathPrefix)
}

// refuseUnverifiedSurface refuses, on the standalone profile, a hook call
// authenticated by a user-scoped credential (the TCP hook route Windows
// uses) from a surface refused under unverified_versions: refuse, as
// managedHookAuthorizer.decide does on the hook socket. It reports whether
// it answered.
func (a *APIServer) refuseUnverifiedSurface(w http.ResponseWriter, r *http.Request, route, connectorName string) bool {
	if !a.userScopedCredentialsRequired() {
		return false
	}
	policy := a.scannerCfg.Enterprise.Enrollment.UnverifiedVersionsFor(connectorName)
	if !connector.SurfaceRefused(connectorName, r.Header.Get(hookexec.AgentSurfaceHeader), policy) {
		return false
	}
	a.emitHTTPAuthFailureForConnector(r.Context(), r, route, gatewaylog.ErrCodeAuthInvalidToken, managedHookReasonSurfaceUnverified, connectorName)
	writeManagedHookRefusal(w, http.StatusForbidden, managedHookReasonSurfaceUnverified)
	return true
}

func writeManagedHookRefusal(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "forbidden", "reason": reason})
}

// managedHookSocketEnabled reports whether this gateway serves the
// standalone hook socket.
func managedHookSocketEnabled(cfg *config.Config) bool {
	return cfg != nil && cfg.StandaloneEnterprise()
}

// loadStandaloneRuntimeDescriptor reads the lifecycle-written descriptor for
// the host OS. A missing descriptor is not an error for the gateway itself:
// the hook socket can still serve per-user connectors from the ledger.
var loadStandaloneRuntimeDescriptor = func(goos string) (*managed.RuntimeDescriptor, error) {
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		return nil, err
	}
	return managed.LoadRuntimeDescriptor(layout.DescriptorPath)
}

// managedHookSocketMux registers only the agent-facing routes on the hook
// socket: connector hook endpoints, the inspect endpoints, the Codex
// notifier, the refused-write report of a standard user CLI, the root
// guardian's repair report and the managed sandbox authority routes a user's
// sandbox daemon calls. Management, status, configuration, policy and scan
// routes are not reachable through it at all.
func (a *APIServer) managedHookSocketMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(enterprisepolicy.ForeignHookSessionPathPrefix+"{connector}", a.handleForeignHookSession)
	limiter := perIPRateLimiter(20, 40)
	inspectMux := http.NewServeMux()
	inspectMux.HandleFunc("/api/v1/inspect/tool", a.handleInspectTool)
	inspectMux.HandleFunc("/api/v1/inspect/request", a.handleInspectRequest)
	inspectMux.HandleFunc("/api/v1/inspect/response", a.handleInspectResponse)
	inspectMux.HandleFunc("/api/v1/inspect/tool-response", a.handleInspectToolResponse)
	mux.Handle("/api/v1/inspect/", limiter(a.guardrailProfileInspectMiddleware(inspectMux)))
	a.registerConnectorHookRoutes(mux, limiter)
	mux.HandleFunc("/api/v1/codex/notify", a.handleCodexNotify)
	mux.HandleFunc(managedRefusalAuditPath, a.handleManagedRefusalAudit)
	mux.HandleFunc(managedGuardianRepairAuditPath, a.handleManagedGuardianRepairAudit)
	a.registerSandboxAuthorityRoutes(mux)
	a.registerSandboxRelayRoutes(mux)
	handler := bodyLimitMiddleware(mux, func(r *http.Request) int64 {
		if limit := sandboxRouteBodyLimit(r.URL.Path); limit > 0 {
			return limit
		}
		if isOTLPEndpointPath(r.URL.Path) {
			return otlpRequestBodyMaxBytes
		}
		return apiRequestBodyMaxBytes
	})
	return a.apiCSRFProtect(handler)
}

// enterpriseExemptUserContextKey marks a request from an account
// enterprise.enrollment.exempt_users lists.
type enterpriseExemptUserContextKey struct{}

func withEnterpriseExemptUser(ctx context.Context) context.Context {
	return context.WithValue(ctx, enterpriseExemptUserContextKey{}, true)
}

// enterpriseEnrollmentV8 is defenseclaw.user.enrollment for a record emitted
// under ctx: exempt for an exempt_users account, absent otherwise, so the
// hook_decision rows of exempt accounts are found in the audit store and a
// SIEM, not only in the gateway log (GAP-0832).
func enterpriseEnrollmentV8(ctx context.Context) observability.Optional[string] {
	if exempt, _ := ctx.Value(enterpriseExemptUserContextKey{}).(bool); exempt {
		return observability.Present("exempt")
	}
	return observability.Absent[string]()
}

// enterpriseExemptAuditInterval bounds the enterprise-exempt-user audit rows:
// one per account and connector in each interval.
const (
	enterpriseExemptAuditInterval = 10 * time.Minute
	enterpriseExemptAuditMaxKeys  = 4096
)

// auditEnterpriseExemptUser writes the enterprise-exempt-user audit row for
// an exempt account's answered hook call, at most once per account and
// connector in each enterpriseExemptAuditInterval. The interval starts at a
// row the audit store took: after a failed write the next call tries again.
// It reports whether it wrote one.
func (a *APIServer) auditEnterpriseExemptUser(ctx context.Context, peer managedHookPeer, connectorName, route string, now time.Time) bool {
	if a == nil || a.logger == nil {
		return false
	}
	key := strconv.Itoa(peer.UID) + "/" + connectorName
	a.exemptAuditMu.Lock()
	if last, seen := a.exemptAuditAt[key]; seen && now.Sub(last) < enterpriseExemptAuditInterval {
		a.exemptAuditMu.Unlock()
		return false
	}
	a.exemptAuditMu.Unlock()
	details := fmt.Sprintf("uid=%d user=%s connector=%s route=%s; allowed and inspected, not enrolled (enterprise.enrollment.exempt_users)",
		peer.UID, sanitizeLLMEventUser(peer.Name), connectorName, route)
	if err := a.logger.LogActionSeverityConnector(string(audit.ActionEnterpriseExemptUser), "uid:"+strconv.Itoa(peer.UID), details, "INFO", connectorName); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] enterprise-exempt-user audit row for uid=%d: %v\n", peer.UID, err)
		return false
	}
	a.exemptAuditMu.Lock()
	if a.exemptAuditAt == nil || len(a.exemptAuditAt) >= enterpriseExemptAuditMaxKeys {
		a.exemptAuditAt = make(map[string]time.Time)
	}
	a.exemptAuditAt[key] = now
	a.exemptAuditMu.Unlock()
	return true
}
