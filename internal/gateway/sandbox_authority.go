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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// The managed gateway as the policy authority of a managed host's
// sandboxes.
//
// A user's sandbox daemon reaches these routes only on the standalone hook
// socket, where the kernel names the caller (SO_PEERCRED / LOCAL_PEERCRED);
// they are never served on the TCP API. For every route:
//
//   - uid 0 is refused, whatever enrollment.root says: sandboxes run as the
//     user, never as root.
//   - The route class's own budget applies (sandbox_authority_limits.go).
//   - decide(peer, connector, "sandbox") runs with the connector the
//     registration pins, or for settings, resolve and an unregistered
//     explain the connector claim: unenrolled_users: deny keeps an
//     unenrolled user from creating a sandbox. The "sandbox" surface is no
//     host surface, so unverified_versions: refuse is applied to the
//     harness version explicitly (sandboxCheckHarness) instead.
//   - Registrations are looked up among the caller's own only, so another
//     uid's registration id is an unknown one.
//
// A registration binds a sandbox to the account (its subject key: the uid
// and the account name the account database gave, never directory facts)
// and records the profile match the policy came from. Directory facts that
// change (a regroup, a cold cache warming up) re-match the registration
// (sandbox_rematch.go); only a different account behind the same uid
// revokes it.

// Refusal texts the sandbox routes answer with. They name only the
// caller's own state.
const (
	sandboxTextRootDenied        = "Sandboxes don't run as root. Run them from your own account."
	sandboxTextRegistrationGone  = "This sandbox is no longer registered with your organization's policy. Start it again."
	sandboxTextRegistrationUnkn  = "This sandbox is not registered for your account."
	sandboxTextNotBound          = "This sandbox's registration is not bound to a sandbox yet."
	sandboxTextStopped           = "This sandbox is not running. Start it again with defenseclaw sandbox start."
	sandboxTextConnectorMismatch = "This sandbox is registered for another agent."
	sandboxTextSubjectChanged    = "This sandbox was registered by another account. Start it again from your own account."
	sandboxTextFilesUnsupported  = "File content is not relayed on managed computers; sandboxes use copy mode."
	sandboxTextUnloadable        = "Your organization's sandbox policy can't be loaded right now. Try again later or contact your IT help desk."
	sandboxTextUnavailable       = "Sandboxes aren't available on this computer."
	sandboxTextBadRequest        = "The sandbox request is malformed."
	sandboxTextDaemonOutdated    = "Your sandbox service runs an older DefenseClaw version than this computer and can't apply " +
		"your organization's complete sandbox policy, so it can't start sandboxes or take policy updates. " +
		"Stop your running sandboxes with defenseclaw sandbox stop so it restarts on the new version, or sign out and back in."
	sandboxTextAccountUnknown    = sandboxapi.AccountUnknownText
	sandboxRequestAccessFallback = "contact your IT help desk"
)

// sandboxRouteSurface is the agent surface decide sees for a sandbox
// route: no host surface, so a host app or extension refusal never
// applies to a sandbox.
const sandboxRouteSurface = "sandbox"

// sandboxAuthority holds the managed gateway's sandbox state: the
// registration and decision stores and the HMAC key of subject keys and
// facts digests. Everything a re-match needs (the run inputs, the policy
// key and floor of the last match, a pending stop) is in the registration
// store's run records, so a restarted gateway has it too.
type sandboxAuthority struct {
	store     sandboxRegistrationStore
	decisions sandboxreg.DecisionStore
	key       []byte
	now       func() time.Time

	// rematch serializes re-matches per registration id.
	rematch keyedMutex
	// records is each account's sandbox telemetry records budget, and
	// eventRecords the budget of the records of its daemon's other events.
	records, eventRecords sandboxRecordBudget
	eventReplay           sandboxEventReplay
	guestSignals          sandboxGuestSignals
}

// sandboxRegistrationStore is the registration store with the run record
// of each pending or live registration (sandboxreg.FileStore).
type sandboxRegistrationStore interface {
	sandboxreg.GuestStore
	CreateRun(uid int, r sandboxreg.Registration, run *sandboxreg.Run) error
	Run(uid int, id string) (sandboxreg.Run, bool, error)
	// GetWithRun reads a registration and its run record as one write
	// stored them.
	GetWithRun(uid int, id string) (sandboxreg.Registration, bool, sandboxreg.Run, bool, error)
	UpdateRun(uid int, r sandboxreg.Registration, run *sandboxreg.Run) error
	// Report records whether the daemon sees the registration's sandbox
	// running; RevokeSandbox revokes the registrations bound to a sandbox
	// the daemon reported foreign.
	Report(uid int, id string, running bool) (sandboxreg.Registration, error)
	RevokeSandbox(uid int, sandboxID, sandboxName, reason string) ([]sandboxreg.Registration, error)
}

func (s *sandboxAuthority) clock() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

// stopText is the text of the stop a re-match revoked uid's registration id
// with ("" for none), which its daemon is told when it polls.
func (s *sandboxAuthority) stopText(uid int, id string) string {
	run, ok, err := s.store.Run(uid, id)
	if err != nil || !ok {
		return ""
	}
	return run.StopText
}

// sandboxAuthorityHolder creates an API server's authority once it can:
// a failure (an unusable data directory, a key that can't be loaded yet)
// is retried on the next call instead of answering 503 until a restart.
type sandboxAuthorityHolder struct {
	ready atomic.Pointer[sandboxAuthority]
	mu    sync.Mutex
}

// sandboxAuthorityKey loads the HMAC key of subject keys and facts
// digests: the gateway's correlation key, which also keys the redaction
// identifiers. Tests replace it.
var sandboxAuthorityKey = func(dataDir string) ([]byte, error) {
	key, err := redaction.LoadOrCreateCorrelationKey(dataDir)
	if err != nil {
		return nil, err
	}
	material, ok := key.Material()
	if !ok {
		return nil, errors.New("correlation key unavailable")
	}
	return material[:], nil
}

// sandboxAuth returns the API server's sandbox authority, or an error when
// its data directory or key is unusable (the routes then answer 503 and
// the next call tries again).
func (a *APIServer) sandboxAuth() (*sandboxAuthority, error) {
	if a == nil {
		return nil, errors.New("no API server")
	}
	holder := &a.sandboxAuthority
	if auth := holder.ready.Load(); auth != nil {
		return auth, nil
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	if auth := holder.ready.Load(); auth != nil {
		return auth, nil
	}
	dataDir := strings.TrimSpace(a.configDataDir())
	if dataDir == "" {
		return nil, errors.New("the gateway has no data directory")
	}
	key, err := sandboxAuthorityKey(dataDir)
	if err != nil {
		return nil, fmt.Errorf("sandbox authority key: %w", err)
	}
	store := sandboxreg.NewFileStore(sandboxreg.RegistrationsDir(dataDir))
	// A registration revoked, removed or evicted by any path ends its
	// sandbox's tracked phase (P2-A of the telemetry relay review).
	store.OnGone = a.sandboxRegistrationGone
	auth := &sandboxAuthority{
		store:        store,
		decisions:    sandboxreg.NewFileDecisionStore(sandboxreg.DecisionsDir(dataDir)),
		key:          key,
		eventRecords: sandboxRecordBudget{perSecond: sandboxEventRecordRate, burst: sandboxEventRecordBurst},
	}
	holder.ready.Store(auth)
	return auth, nil
}

// sandboxSubjectKey is a registration's subject key: DigestPrefix and the
// HMAC of "v1|uid|account|sid", the kernel uid, the lowercased account
// name the account database gives for it at peer auth and the account SID
// where the OS gives one without a directory round trip ("" on Linux and
// macOS). Principal, directory and tenant are left out: they arrive late on
// a cold cache and would otherwise turn a provisional create into a
// subject change once the cache warms (GAP-0022).
func sandboxSubjectKey(key []byte, uid int, account, sid string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "%s|%d|%s|%s", sandboxreg.SubjectKeyVersion, uid,
		strings.ToLower(strings.TrimSpace(account)), strings.ToUpper(strings.TrimSpace(sid)))
	return sandboxreg.DigestPrefix + hex.EncodeToString(mac.Sum(nil))
}

// sandboxSubjectMatches reports whether peer, whose account name the
// account database gave, is the account that created reg. Resolve never
// registers without an account name, so a registration without one proves
// no account and never matches.
func sandboxSubjectMatches(key []byte, reg sandboxreg.Registration, peer managedHookPeer) bool {
	if strings.TrimSpace(reg.UserName) == "" || strings.TrimSpace(peer.Name) == "" {
		return false
	}
	return hmac.Equal([]byte(reg.SubjectKey), []byte(sandboxSubjectKey(key, peer.UID, peer.Name, "")))
}

// sandboxFactsDigest is a registration's facts digest: DigestPrefix and
// the HMAC of the directory facts a profile match uses (principal, UPN,
// domain, directory, tenant, sorted groups) and whether they resolved. A
// change re-matches the registration without revoking it. Requests whose
// assignments need the unresolved fact are refused until it is confirmed.
func sandboxFactsDigest(key []byte, facts useridentity.DirectoryFacts, resolved bool) string {
	groups := slices.Clone(facts.Groups)
	for i := range groups {
		groups[i] = strings.ToLower(groups[i])
	}
	slices.Sort(groups)
	mac := hmac.New(sha256.New, key)
	for _, part := range append([]string{"v1", strings.ToLower(facts.Principal), strings.ToLower(facts.UPN),
		strings.ToLower(facts.Domain), string(facts.Directory), strings.ToLower(facts.TenantID),
		strconv.FormatBool(resolved)}, groups...) {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return sandboxreg.DigestPrefix + hex.EncodeToString(mac.Sum(nil))
}

// sandboxPrincipalHash is a decision actor's principal_hash: keyed like the
// subject key, never the principal itself.
func sandboxPrincipalHash(key []byte, principal string) string {
	principal = strings.ToLower(strings.TrimSpace(principal))
	if principal == "" {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(mac, "v1|principal|%s", principal)
	return sandboxreg.DigestPrefix + hex.EncodeToString(mac.Sum(nil))
}

// The relay-verified marker: a relayed hook, notify or inspect call whose
// registration sandboxRelayAdmit checked against the kernel peer. Only it
// gives a sandbox request the peer's verified subject
// (profileRequestSubject).
type sandboxRelayRegistrationKey struct{}

func withSandboxRelayRegistration(ctx context.Context, reg sandboxreg.Registration) context.Context {
	return context.WithValue(ctx, sandboxRelayRegistrationKey{}, reg)
}

// sandboxRelayRegistrationFrom returns the registration of a relayed call.
func sandboxRelayRegistrationFrom(ctx context.Context) (sandboxreg.Registration, bool) {
	if ctx == nil {
		return sandboxreg.Registration{}, false
	}
	reg, ok := ctx.Value(sandboxRelayRegistrationKey{}).(sandboxreg.Registration)
	return reg, ok && reg.ID != ""
}

// isRelayVerifiedSandboxRequest reports a relayed call admitted by
// sandboxRelayAdmit whose registration belongs to the request's
// kernel-verified peer.
func isRelayVerifiedSandboxRequest(ctx context.Context) bool {
	reg, ok := sandboxRelayRegistrationFrom(ctx)
	if !ok || reg.State != sandboxreg.StateLive {
		return false
	}
	peer, ok := managedHookPeerFromContext(ctx)
	return ok && peer.UID == reg.UID && peer.UID != 0
}

// sandboxRouteAuthorizerKey carries the hook socket's authorizer from
// managedHookPeerAuth to the sandbox route handlers, which decide once
// they know the connector.
type sandboxRouteAuthorizerKey struct{}

// serveSandboxRoute is managedHookPeerAuth for the managed sandbox routes:
// it requires the CSRF client header on every method (GET included; the
// relay always sends it), refuses uid 0, applies the route class's budget
// and attaches the peer's verified subject. decide runs in the handler,
// once the registration or the connector claim names the connector; the
// budget comes first so a refused caller still spends only its own.
func (a *APIServer) serveSandboxRoute(authorizer *managedHookAuthorizer, peer managedHookPeer, route string, w http.ResponseWriter, r *http.Request, next http.Handler) {
	if r.Header.Get(sandboxrelay.ClientHeader) == "" {
		a.emitHTTPAuthFailure(r.Context(), r, route, gatewaylog.ErrCodeAuthCSRFMismatch, "csrf_mismatch")
		http.Error(w, `{"error":"missing X-DefenseClaw-Client header"}`, http.StatusForbidden)
		return
	}
	if peer.UID == 0 {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] refused uid=0 route=%s reason=%s\n", route, managedHookReasonRootDenied)
		a.emitHTTPAuthFailureForConnector(r.Context(), r, route, gatewaylog.ErrCodeAuthInvalidToken, managedHookReasonRootDenied, "")
		writeSandboxRefusal(w, http.StatusForbidden, managedHookReasonRootDenied, sandboxTextRootDenied)
		return
	}
	r, release := a.admitHookCaller(w, r, strconv.Itoa(peer.UID), route)
	if release == nil {
		return
	}
	defer release()
	if sandboxDaemonOutdated(r) && !sandboxOutdatedDaemonRoute(r.URL.Path) {
		refuseOutdatedSandboxDaemon(w, peer, route)
		return
	}
	ctx := attachVerifiedSubject(r.Context(), a.observabilityV8RuntimeEmitter(), strconv.Itoa(peer.UID), peer.Name, subjectSourcePeerCredentials)
	ctx = context.WithValue(ctx, sandboxRouteAuthorizerKey{}, authorizer)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// sandboxDaemonOutdated reports a call from a daemon below the floor
// contract (sandboxrelay.DaemonContract): it would mark a partial floor
// confirmed (GAP-0182). A package upgrade leaves the account's old daemon
// running until its sandboxes stop.
func sandboxDaemonOutdated(r *http.Request) bool {
	contract, err := strconv.Atoi(strings.TrimSpace(r.Header.Get(sandboxrelay.DaemonContractHeader)))
	return err != nil || contract < sandboxrelay.DaemonContract
}

// sandboxOutdatedDaemonRoute reports a sandbox route a daemon below the
// floor contract still reaches; every other one is refused before its
// handler. Settings and the sandbox events (the audit of what the daemon
// does) are answered as usual, and a deletion is recorded. Resolve
// records its refusal (GAP-0148), and policy/current and the state report
// pass a revocation and a stopped sandbox through but never confirm a
// floor or renew a running one (serveSandboxCurrent).
func sandboxOutdatedDaemonRoute(path string) bool {
	switch path {
	case sandboxrelay.PathSettings, sandboxrelay.PathEvents, sandboxrelay.PathPolicyResolve, sandboxrelay.PathPolicyCurrent:
		return true
	}
	if id, ok := strings.CutPrefix(path, sandboxrelay.PathRegistrations); ok {
		return strings.HasSuffix(id, sandboxrelay.RegistrationStateSub) || strings.HasSuffix(id, sandboxrelay.RegistrationDelSub)
	}
	return false
}

// sandboxOutdatedDaemonLogged holds the uids whose outdated daemon this
// gateway already logged, so a running sandbox's hooks log it once.
var sandboxOutdatedDaemonLogged sync.Map

// refuseOutdatedSandboxDaemon answers a daemon below the floor contract
// with ReasonDaemonOutdated.
func refuseOutdatedSandboxDaemon(w http.ResponseWriter, peer managedHookPeer, route string) {
	logOutdatedSandboxDaemon(peer, route)
	writeSandboxReason(w, sandboxrelay.ReasonDaemonOutdated, sandboxTextDaemonOutdated)
}

// logOutdatedSandboxDaemon logs the first refusal of peer's outdated daemon.
func logOutdatedSandboxDaemon(peer managedHookPeer, route string) {
	if _, logged := sandboxOutdatedDaemonLogged.LoadOrStore(peer.UID, true); !logged {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] uid=%d route=%s reason=%s: the account's sandbox daemon does not state contract %d; "+
			"new sandboxes and policy confirmations are refused until it restarts on this version\n",
			peer.UID, route, sandboxrelay.ReasonDaemonOutdated, sandboxrelay.DaemonContract)
	}
}

// sandboxDecide runs decide(peer, connectorName, "sandbox") for a sandbox
// route and answers the refusal. It reports whether the call may go on.
func (a *APIServer) sandboxDecide(w http.ResponseWriter, r *http.Request, peer managedHookPeer, connectorName string) bool {
	authorizer, _ := r.Context().Value(sandboxRouteAuthorizerKey{}).(*managedHookAuthorizer)
	if authorizer == nil {
		writeSandboxRefusal(w, http.StatusForbidden, managedHookReasonPeerUnverified, "")
		return false
	}
	decision := authorizer.decide(peer, connectorName, sandboxRouteSurface)
	if decision.Allow {
		return true
	}
	a.sandboxRefuseDecision(w, r, peer, connectorName, decision)
	return false
}

// sandboxDecideAny runs decide for a route that names no connector
// (settings without a claim): the call may go on when the peer is allowed
// for any sandbox harness, so unenrolled_users: deny keeps an account
// enrolled for none of them out. The first refusal is answered otherwise.
func (a *APIServer) sandboxDecideAny(w http.ResponseWriter, r *http.Request, peer managedHookPeer) bool {
	authorizer, _ := r.Context().Value(sandboxRouteAuthorizerKey{}).(*managedHookAuthorizer)
	if authorizer == nil {
		writeSandboxRefusal(w, http.StatusForbidden, managedHookReasonPeerUnverified, "")
		return false
	}
	refusal := denyManagedHook(http.StatusForbidden, managedHookReasonConnectorUnknown)
	refused := false
	for _, name := range harness.Names() {
		connectorName := sandboxConnectorClaim(name)
		if connectorName == "" {
			continue
		}
		decision := authorizer.decide(peer, connectorName, sandboxRouteSurface)
		if decision.Allow {
			return true
		}
		if !refused {
			refusal, refused = decision, true
		}
	}
	a.sandboxRefuseDecision(w, r, peer, "", refusal)
	return false
}

// sandboxRefuseDecision logs, records and answers a decide refusal.
func (a *APIServer) sandboxRefuseDecision(w http.ResponseWriter, r *http.Request, peer managedHookPeer, connectorName string, decision managedHookDecision) {
	route := sanitizeRouteForTelemetry(r.URL.Path)
	fmt.Fprintf(os.Stderr, "[sandbox-authority] refused uid=%d connector=%q route=%s reason=%s\n",
		peer.UID, connectorName, route, decision.Reason)
	a.emitHTTPAuthFailureForConnector(r.Context(), r, route, gatewaylog.ErrCodeAuthInvalidToken, decision.Reason, connectorName)
	writeSandboxRefusal(w, decision.Status, decision.Reason, "")
}

// writeSandboxRefusal answers a sandbox route's refusal. The body is
// sandboxrelay.ErrorBody, with the hook socket's "reason" key kept for
// callers that read the managed refusals.
func writeSandboxRefusal(w http.ResponseWriter, status int, reason, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		sandboxrelay.ErrorBody
		Reason string `json:"reason"`
	}{sandboxrelay.ErrorBody{Error: reason, Message: message}, reason})
}

// writeSandboxReason answers a sandboxrelay reason with its status.
func writeSandboxReason(w http.ResponseWriter, reason, message string) {
	status := sandboxrelay.ReasonStatus(reason)
	if status == 0 {
		status = http.StatusForbidden
	}
	writeSandboxRefusal(w, status, reason, message)
}

// sandboxPeer returns the request's kernel-verified peer or answers 403.
func sandboxPeer(w http.ResponseWriter, r *http.Request) (managedHookPeer, bool) {
	peer, ok := managedHookPeerFromContext(r.Context())
	if !ok || peer.UID == 0 {
		writeSandboxRefusal(w, http.StatusForbidden, managedHookReasonPeerUnverified, "")
		return managedHookPeer{}, false
	}
	return peer, true
}

// sandboxRegistrationFor looks up the caller's registration id and answers
// the refusal when it is unknown (another uid's included), revoked or
// expired. allowPending admits an unexpired pending registration and
// allowRevoked a tombstone (policy/current reports revocation in its body).
func (a *APIServer) sandboxRegistrationFor(w http.ResponseWriter, auth *sandboxAuthority, peer managedHookPeer, id string, allowPending, allowRevoked bool) (sandboxreg.Registration, bool) {
	reg, ok, err := auth.store.Get(peer.UID, strings.TrimSpace(id))
	switch {
	case err != nil:
		fmt.Fprintf(os.Stderr, "[sandbox-authority] registration store uid=%d: %v\n", peer.UID, err)
		writeSandboxReason(w, sandboxrelay.ReasonPolicyUnloadable, sandboxTextUnloadable)
		return reg, false
	case !ok:
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationUnknown, sandboxTextRegistrationUnkn)
		return reg, false
	case reg.State == sandboxreg.StateRevoked && !allowRevoked:
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationRevoked, sandboxTextRegistrationGone)
		return reg, false
	case reg.State == sandboxreg.StatePending && sandboxreg.PendingExpired(reg, auth.clock()):
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationExpired, sandboxTextRegistrationGone)
		return reg, false
	case reg.State == sandboxreg.StatePending && !allowPending:
		writeSandboxReason(w, sandboxrelay.ReasonNotAllowed, sandboxTextNotBound)
		return reg, false
	}
	return reg, true
}

// sandboxStandInName is the account name a new registration binds for peer:
// the account database's, else, while it gives none (a directory outage), the
// name the uid last resolved to, which a managed gateway keeps across
// restarts, so the run is not refused with "your account can't be looked
// up" (GAP-0507). The run is still refused, naming the missing fact, when an
// assignment needs a fact the outage withholds; otherwise the proven or
// default profile applies. sandboxCheckSubject applies the same stand-in to
// the calls that follow, and revokes the registration if the directory later
// names another account. "" when neither is known.
func sandboxStandInName(peer managedHookPeer) string {
	if name := strings.TrimSpace(peer.Name); name != "" {
		return name
	}
	return strings.TrimSpace(managedHookPeerLastName(peer.UID))
}

// sandboxCheckSubject revokes reg and answers 409 when the account behind
// the uid is not the one that registered it (a recycled uid, a renamed
// account). While the account database gives no name for the uid (a
// directory outage), the name the uid last resolved to stands in for it, so
// a running sandbox keeps its last proven profile until the facts resolve
// instead of every hook failing (GAP-0506); a call whose assignments need
// the missing fact is refused, naming it. A recycled uid resolves through
// the account database that now holds it. A peer with neither, or whose last
// name is not the registration's, can't be told apart from another account:
// the call is refused (503) and the registration kept.
func (a *APIServer) sandboxCheckSubject(w http.ResponseWriter, auth *sandboxAuthority, peer managedHookPeer, reg sandboxreg.Registration) bool {
	if strings.TrimSpace(peer.Name) == "" {
		last := peer
		last.Name = managedHookPeerLastName(peer.UID)
		if strings.TrimSpace(last.Name) != "" && sandboxSubjectMatches(auth.key, reg, last) {
			return true
		}
		writeSandboxReason(w, sandboxrelay.ReasonUnavailable, sandboxTextAccountUnknown)
		return false
	}
	if sandboxSubjectMatches(auth.key, reg, peer) {
		return true
	}
	if err := auth.store.Revoke(peer.UID, reg.ID, sandboxrelay.ReasonSubjectChanged); err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] revoke uid=%d registration=%s: %v\n", peer.UID, reg.ID, err)
	}
	fmt.Fprintf(os.Stderr, "[sandbox-authority] revoked uid=%d registration=%s reason=%s\n", peer.UID, reg.ID, sandboxrelay.ReasonSubjectChanged)
	writeSandboxReason(w, sandboxrelay.ReasonSubjectChanged, sandboxTextSubjectChanged)
	return false
}

// sandboxRelayAdmit runs the managed gateway's checks of a relayed hook,
// notify or inspect call, in order: the caller's own registration (an
// unknown or another uid's id answers 404), live (revoked or expired 410,
// pending 403), routeConnector equal to the registration's ("" for the
// inspect routes, which take the registration's), decide for it, the
// subject key (a different account revokes and answers 409), the harness
// version under unverified_versions: refuse (403), no
// FilesHeader (400, copy-only), then a due re-match, which may revoke a
// sandbox that outlived its stop, then the sandbox running (a stopped
// registration, or one past its LiveLease, answers 403
// sandbox_registration_stopped). On success it sets the profile and
// generation response headers and returns the request context carrying
// the relay-verified registration; it answered the refusal otherwise.
func (a *APIServer) sandboxRelayAdmit(w http.ResponseWriter, r *http.Request, routeConnector string) (context.Context, sandboxreg.Registration, bool) {
	// One generation decides the admission, the re-match and the relayed
	// handler's answer.
	r = a.pinRequestGeneration(r)
	peer, ok := sandboxPeer(w, r)
	if !ok {
		return nil, sandboxreg.Registration{}, false
	}
	auth, err := a.sandboxAuth()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] unavailable: %v\n", err)
		writeSandboxReason(w, sandboxrelay.ReasonUnavailable, sandboxTextUnavailable)
		return nil, sandboxreg.Registration{}, false
	}
	reg, ok := a.sandboxRegistrationFor(w, auth, peer, r.Header.Get(sandboxrelay.RegistrationHeader), false, false)
	if !ok {
		return nil, reg, false
	}
	if routeConnector != "" && config.NormalizeConnectorName(routeConnector) != reg.Connector {
		writeSandboxReason(w, sandboxrelay.ReasonConnectorMismatch, sandboxTextConnectorMismatch)
		return nil, reg, false
	}
	if !a.sandboxDecide(w, r, peer, reg.Connector) || !a.sandboxCheckSubject(w, auth, peer, reg) {
		return nil, reg, false
	}
	cfg := a.liveBaseConfig(r.Context())
	// unverified_versions: refuse set after the sandbox was created still
	// binds its harness version.
	if _, why := sandboxCheckHarness(cfg, reg.Harness, reg.Connector, reg.HarnessVersion, reg.HookContract); why != "" {
		writeSandboxReason(w, sandboxrelay.ReasonNotAllowed, why)
		return nil, reg, false
	}
	if _, present := r.Header[http.CanonicalHeaderKey(sandboxrelay.FilesHeader)]; present {
		writeSandboxReason(w, sandboxrelay.ReasonRelayFilesUnsupported, sandboxTextFilesUnsupported)
		return nil, reg, false
	}
	reg = a.sandboxRematchIfDue(r.Context(), auth, peer, reg)
	if !sandboxAdmitsCalls(w, auth, reg) {
		return nil, reg, false
	}
	a.sandboxGuestSignal(r.Context(), auth, reg, audit.SandboxGuestRelayWithoutGuest)
	w.Header().Set(sandboxrelay.ProfileHeader, reg.Profile)
	w.Header().Set(sandboxrelay.GenerationHeader, strconv.FormatUint(a.sandboxViewGeneration(cfg, reg), 10))
	return withSandboxRelayRegistration(r.Context(), reg), reg, true
}

// sandboxAdmitsCalls answers the refusal of a registration, as a re-match
// left it, that admits no call: revoked (410), or stopped (403) because its
// daemon reports its sandbox stopped or no longer reports it running, which
// runs nothing that could make the call (GAP-0505, GAP-0446).
func sandboxAdmitsCalls(w http.ResponseWriter, auth *sandboxAuthority, reg sandboxreg.Registration) bool {
	switch {
	case reg.State == sandboxreg.StateRevoked:
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationRevoked, sandboxTextRegistrationGone)
	case sandboxreg.EffectiveState(reg, auth.clock()) == sandboxreg.StateStopped:
		writeSandboxReason(w, sandboxrelay.ReasonRegistrationStopped, sandboxTextStopped)
	default:
		return true
	}
	return false
}

// sandboxGenerationOf is the generation ctx pinned, else the live one.
func (a *APIServer) sandboxGenerationOf(ctx context.Context) *Generation {
	if g := pinnedGeneration(ctx); g != nil {
		return g
	}
	return a.generation()
}

// sandboxHostGeneration is the in-process generation counter of the
// configuration ctx's policy came from, which a registration records for
// administrators (users see sandboxViewGeneration). It restarts at 1 with
// every gateway process, so it never decides a re-match: sandboxPolicyKey
// does.
func (a *APIServer) sandboxHostGeneration(ctx context.Context) uint64 {
	if g := a.sandboxGenerationOf(ctx); g != nil {
		return g.N
	}
	return 0
}

// sandboxPolicyKey is the content key of the sandbox policy cfg (the
// configuration ctx's policy came from) gives: its generation's effective
// policy digest (the configuration, asset and profile digests) and a
// digest of what a sandbox match and resolve read (openshell, the
// guardrail profiles, their assignments and default, enrollment). It is
// the same in every gateway process for the same policy and differs when
// any of those inputs does; a registration matched under another key is
// re-matched. "" (inputs that can't be encoded) re-matches every time.
func (a *APIServer) sandboxPolicyKey(ctx context.Context, cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	inputs := sandboxDigestOf(struct {
		OpenShell           config.OpenShellConfig
		EnterpriseOpenShell config.EnterpriseOpenShellConfig
		Profiles            map[string]config.GuardrailProfile
		Assignments         []config.ProfileAssignment
		DefaultProfile      string
		Enrollment          config.EnterpriseEnrollmentConfig
	}{cfg.OpenShell, cfg.Enterprise.OpenShell, cfg.Guardrail.Profiles, cfg.Guardrail.ProfileAssignments,
		cfg.Guardrail.DefaultProfile, cfg.Enterprise.Enrollment})
	if inputs == "" {
		return ""
	}
	generation := ""
	if g := a.sandboxGenerationOf(ctx); g != nil {
		generation = g.Digest
	}
	return sandboxDigestOf([]string{"v1", generation, inputs})
}

// sandboxViewGeneration is the generation a user's daemon sees: it moves
// when that user's own policy or the host's sandbox settings change, and
// never with another group's profile, which the host generation would
// reveal. The daemon compares it for equality only.
func (a *APIServer) sandboxViewGeneration(cfg *config.Config, reg sandboxreg.Registration) uint64 {
	floor, floorDigest, err := sandboxRegistrationFloor(cfg, reg)
	if err != nil {
		floorDigest = "unloadable"
	}
	sum := sha256.New()
	for _, part := range []string{reg.Profile, reg.ProfileDigest, reg.EffectiveDigest, floorDigest,
		sandboxSettingsDigest(cfg, floor), strconv.FormatBool(reg.Provisional)} {
		sum.Write([]byte(part))
		sum.Write([]byte{0})
	}
	return binary.BigEndian.Uint64(sum.Sum(nil)[:8]) >> 1
}

// sandboxFloorFor is the floor F for profile ("" = openshell.admin alone)
// and its digest: openshell.admin tightened by the profile's sandbox
// section (config.SandboxFloor). An error fails closed: the routes answer
// sandbox_policy_unloadable.
var sandboxFloorFor = func(cfg *config.Config, profile string) (config.OpenShellAdminConfig, string, error) {
	return cfg.SandboxManagedFloor(profile)
}

// sandboxRegistrationFloor is the floor F of a registered sandbox and its
// digest: the floor of the profile it is matched to now, tightened by the
// floor of the profile it was created under when a profile-assignment
// change has since moved it (Registration.CreateProfile). Floors are pinned
// at create per sandbox: a re-match may tighten a running sandbox, never
// loosen it, and the person's next sandbox takes the new profile alone
// (GAP-0242). An administrator's edit of a profile's own settings applies
// to both floors, so it still reaches a running sandbox. Floors that do not
// combine (a contradiction, or a create profile no longer defined) fail
// closed like any floor that does not load.
func sandboxRegistrationFloor(cfg *config.Config, reg sandboxreg.Registration) (config.OpenShellAdminConfig, string, error) {
	floor, digest, err := sandboxFloorFor(cfg, reg.Profile)
	if err != nil || reg.CreateProfile == nil || *reg.CreateProfile == reg.Profile {
		return floor, digest, err
	}
	created, createdDigest, err := sandboxFloorFor(cfg, *reg.CreateProfile)
	if err != nil {
		return config.OpenShellAdminConfig{}, "", fmt.Errorf("the floor of profile %q the sandbox was created under: %w", *reg.CreateProfile, err)
	}
	pinned, err := config.TightenOpenShellAdmin(floor, &created)
	if err != nil {
		return config.OpenShellAdminConfig{}, "", err
	}
	if access := strings.TrimSpace(floor.RequestAccess); access != "" {
		// The contact of the profile the person is assigned to now.
		pinned.RequestAccess = floor.RequestAccess
	}
	return pinned, sandboxDigestOf([]string{"create-pinned-v1", digest, createdDigest}), nil
}

// sandboxDigestOf is "sha256:" and the hex SHA-256 of v's JSON.
func sandboxDigestOf(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// sandboxRequestAccess is the request-access contact of floor F.
func sandboxRequestAccess(f config.OpenShellAdminConfig) string {
	if text := strings.TrimSpace(f.RequestAccess); text != "" {
		return text
	}
	return sandboxRequestAccessFallback
}

// sandboxMatch is a peer's profile match for a sandbox.
type sandboxMatch struct {
	decision profileDecision
	// resolved says the peer's directory facts resolved; provisional that
	// the match fell back to default_lookup_failed.
	resolved    bool
	provisional bool
	facts       useridentity.DirectoryFacts
}

// sandboxPeerDirectory returns uid's directory facts, waiting up to wait
// for a lookup that has not resolved (0: only what is cached). Tests
// replace it.
var sandboxPeerDirectory = func(ctx context.Context, uid int, wait time.Duration) (useridentity.DirectoryFacts, bool) {
	id := strconv.Itoa(uid)
	deadline := time.Now().Add(wait)
	for {
		facts, ok := verifiedIdentityDirectory(id, wait > 0)
		if ok && !facts.ResolvedAt.IsZero() {
			return facts, true
		}
		remaining := time.Until(deadline)
		if wait <= 0 || remaining <= 0 {
			return facts, false
		}
		select {
		case <-ctx.Done():
			return facts, false
		case <-time.After(min(remaining, 250*time.Millisecond)):
		}
	}
}

// sandboxMatchPeer matches peer's profile for a sandbox of connectorName:
// the #1085 assignments with the peer's verified facts, agents ignored
// (an agent id is no stable sandbox identity). wait bounds the identity
// lookup (ResolveIdentityWait at create; 0 on later calls).
func (a *APIServer) sandboxMatchPeer(ctx context.Context, peer managedHookPeer, connectorName string, wait time.Duration) sandboxMatch {
	set := a.guardrailProfileSet()
	if g := pinnedGeneration(ctx); g.published() {
		set = g.Profiles
	}
	var facts useridentity.DirectoryFacts
	resolved := false
	lookup := identityFactsEnabled.Load() && identityLookupBlocking.Load()
	if identityFactsEnabled.Load() {
		if !lookup {
			wait = 0
		}
		facts, resolved = sandboxPeerDirectory(ctx, peer.UID, wait)
	}
	if set == nil {
		return sandboxMatch{decision: profileDecision{Match: sandboxreg.MatchNone}, resolved: resolved, facts: facts}
	}
	id := strconv.Itoa(peer.UID)
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: id, IDKind: useridentity.KindForID(id), UserName: verifiedAccountName(id, peer.Name),
		Directory: facts, Source: subjectSourcePeerCredentials,
	}, lookup)
	connectorName = config.NormalizeConnectorName(connectorName)
	scans := set.requestScanScopes(ctx, connectorName)
	decision := set.matchResolved(&subject, resolveIdentity(&subject, nil), profileSubjectVerified, connectorName, scans, profilePathAny, "")
	return sandboxMatch{
		decision: decision, resolved: resolved, facts: facts,
		provisional: decision.Match == profileMatchDefaultLookupFailed,
	}
}

// sandboxProfileDescription is the description of the caller's own
// profile, for the banner and explain.
func sandboxProfileDescription(cfg *config.Config, profile string) string {
	if cfg == nil || profile == "" {
		return ""
	}
	if p, ok := cfg.Guardrail.Profiles[profile]; ok {
		return strings.TrimSpace(p.Description)
	}
	return ""
}

// sandboxHarnessFacts are what the gateway trusts of a harness: its tamper
// tier from the harness registry and the hook contract its version
// resolves to.
type sandboxHarnessFacts struct {
	Contract   string
	TamperTier string
}

// sandboxCheckHarness judges the harness a resolve names. The harness must
// be one DefenseClaw runs in sandboxes and its connector the same name;
// under unverified_versions: refuse the version must resolve to a reviewed
// sandbox hook contract (the "sandbox" surface never trips decide's surface
// check, so this is the explicit version check); a claimed contract must
// be the one the version resolves to. The tamper tier is the registry's,
// never the claim.
func sandboxCheckHarness(cfg *config.Config, harnessName, connectorName, version, contract string) (sandboxHarnessFacts, string) {
	spec, ok := harness.Get(harnessName)
	if !ok || config.NormalizeConnectorName(connectorName) != spec.Name {
		return sandboxHarnessFacts{}, "This agent can't run in a sandbox."
	}
	version = strings.TrimSpace(version)
	if version == "" || len(version) > 128 || !sandboxPrintable(version) {
		return sandboxHarnessFacts{}, "The sandbox image does not name a valid agent version."
	}
	resolution := connector.ResolveSandboxHookContract(spec.Name, version)
	known := resolution.Status == connector.HookCompatibilityKnown
	refuse := cfg != nil && cfg.Enterprise.Enrollment.UnverifiedVersionsFor(spec.Name) == config.EnterpriseUnverifiedRefuse
	if refuse && !known {
		return sandboxHarnessFacts{}, fmt.Sprintf("%s %s is not a version your organization has verified for sandboxes.", spec.DisplayName, version)
	}
	contract = strings.TrimSpace(contract)
	if known {
		if contract != "" && contract != resolution.Contract.ContractID {
			return sandboxHarnessFacts{}, "The sandbox image's hook contract does not match its agent version."
		}
		contract = resolution.Contract.ContractID
	} else if len(contract) > 128 || !sandboxPrintable(contract) {
		return sandboxHarnessFacts{}, "The sandbox image's hook contract is malformed."
	}
	return sandboxHarnessFacts{Contract: contract, TamperTier: spec.TamperTier}, ""
}

func sandboxPrintable(s string) bool {
	for _, c := range s {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// sandboxRecordResolved and sandboxRecordRematched record a registration
// and a re-match for the administrator (log.sandbox.policy.resolved and
// log.sandbox.policy.rematched with the sandbox.policy.rematched audit
// action; sandbox_managed_telemetry.go). A re-match that changed nothing
// but the state (a revocation) is recorded as one too. Tests replace them.
var (
	sandboxRecordResolved = func(a *APIServer, reg sandboxreg.Registration) {
		emitSandboxPolicyResolved(a, reg)
	}
	// sandboxRecordResolveRefused records a refused resolution (attempt is
	// the caller and profile it was judged under; reason the refusal).
	sandboxRecordResolveRefused = func(a *APIServer, attempt sandboxreg.Registration, reason string) {
		emitSandboxPolicyResolveRefused(a, attempt, reason)
	}
	sandboxRecordRematched = func(a *APIServer, before, after sandboxreg.Registration, changed []string, action string) {
		fmt.Fprintf(os.Stderr, "[sandbox-authority] rematched uid=%d registration=%s profile=%q->%q match=%s->%s changed=%s action=%s\n",
			after.UID, after.ID, before.Profile, after.Profile, before.ProfileMatch, after.ProfileMatch, strings.Join(changed, ","), action)
		emitSandboxPolicyRematched(a, before, after)
	}
)
