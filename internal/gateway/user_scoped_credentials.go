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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Per-user connector credentials on the loopback TCP API (standalone profile).
//
// The guardian gives each protected user credentials derived from a
// per-machine key and bound to that user's uid (Unix) or SID (Windows); see
// connector.UserScopedHookAPIToken. The gateway derives the same credentials
// for every protected target in the guardian's root-owned authorization
// ledger. A request that presents one is attributed to the identity it is
// bound to, and a request whose identity headers name anyone else is
// refused, so user A cannot post an event attributed to user B. The
// connector-wide credentials of other profiles are not accepted here:
// before per-user credentials existed every user of a connector held the
// same one.

// A credential rotation (the standalone Unix lifecycle's
// rotate-credentials) stages the next key beside the committed one. While
// the staged key exists the index holds the credentials of both keys, so a
// user whose hooks the guardian has already moved to the new key and a user
// it has not reached yet both authenticate; committing the rotation renames
// the staged key over the committed one and the old key's credentials stop
// authenticating on the next refresh. A rotation that rolls back first
// moves the staged key aside as the retiring key, which still authenticates
// but which the guardian no longer renders from, so users it had already
// moved are not refused while the guardian moves them back. A staged or
// retiring key that fails its trust checks, or that is older than
// connector.RotationKeyMaxAge, is ignored. Windows does not stage keys.

// userScopedCredentialRefreshInterval bounds how often the key and ledger
// are revalidated on the request path.
const userScopedCredentialRefreshInterval = time.Second

const userScopedIdentityMismatchReason = "user_scoped_identity_mismatch"

type userScopedCredential struct {
	kind     string
	scope    string
	identity string
	// key indexes the store's keys: the key the credential derives from.
	key int
}

// userScopedCredentialStore caches the credential index derived from the
// key and the ledger. The index is keyed by the SHA-256 of each credential,
// so a lookup never compares a presented value against a secret.
type userScopedCredentialStore struct {
	dataDir func() string
	loadKey func(dataDir string) (string, error)
	// loadPendingKey reads the key a rotation staged; nil where keys are
	// never staged.
	loadPendingKey func(dataDir string) (string, error)
	// loadRetiringKey reads the key a rolling-back rotation retires; nil
	// where keys are never staged.
	loadRetiringKey func(dataDir string) (string, error)
	newLedger       func(path string) func() (managedHookLedger, uint64, error)
	now             func() time.Time

	mu        sync.Mutex
	checkedAt time.Time
	dir       string
	ledger    func() (managedHookLedger, uint64, error)
	// keys are the committed key and, during a rotation, the staged one.
	keys       []string
	generation uint64
	built      bool
	index      map[[sha256.Size]byte]userScopedCredential
}

func newUserScopedCredentialStore(dataDir func() string) *userScopedCredentialStore {
	store := &userScopedCredentialStore{
		dataDir: dataDir,
		loadKey: connector.LoadUserScopedTokenKey,
		newLedger: func(path string) func() (managedHookLedger, uint64, error) {
			return newManagedHookLedgerLoader(path).LoadGeneration
		},
		now: time.Now,
	}
	if runtime.GOOS != "windows" {
		store.loadPendingKey = connector.LoadPendingUserScopedTokenKey
		store.loadRetiringKey = connector.LoadRetiringUserScopedTokenKey
	}
	return store
}

// lookup returns the identity presented is bound to for kind and scope.
func (s *userScopedCredentialStore) lookup(kind, scope, presented string) (string, bool) {
	presented = strings.TrimSpace(presented)
	scope = strings.ToLower(strings.TrimSpace(scope))
	if s == nil || presented == "" || scope == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	credential, ok := s.index[sha256.Sum256([]byte(presented))]
	if !ok || credential.kind != kind || credential.scope != scope {
		return "", false
	}
	return credential.identity, true
}

// hookCredentialForKeyID returns the per-user hook credential for scope
// whose key ID (connector.UserScopedCredentialKeyID) is keyID, re-derived
// from the key, for answering a listener proof. The index is keyed by that
// same digest, so the credential is found without the caller presenting it.
func (s *userScopedCredentialStore) hookCredentialForKeyID(scope, keyID string) (string, bool) {
	scope = strings.ToLower(strings.TrimSpace(scope))
	keyID = strings.TrimSpace(keyID)
	if s == nil || scope == "" || len(keyID) != 2*sha256.Size || strings.ToLower(keyID) != keyID {
		return "", false
	}
	raw, err := hex.DecodeString(keyID)
	if err != nil {
		return "", false
	}
	var digest [sha256.Size]byte
	copy(digest[:], raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	credential, ok := s.index[digest]
	if !ok || credential.kind != connector.UserScopedHookCredential || credential.scope != scope {
		return "", false
	}
	if credential.key < 0 || credential.key >= len(s.keys) {
		return "", false
	}
	token, err := connector.UserScopedHookAPIToken(s.keys[credential.key], scope, credential.identity)
	if err != nil || sha256.Sum256([]byte(token)) != digest {
		return "", false
	}
	return token, true
}

func (s *userScopedCredentialStore) refreshLocked() {
	now := s.now()
	dir := strings.TrimSpace(s.dataDir())
	if dir == s.dir && !s.checkedAt.IsZero() && now.Sub(s.checkedAt) < userScopedCredentialRefreshInterval {
		return
	}
	s.checkedAt = now
	if dir != s.dir || s.ledger == nil {
		s.dir = dir
		s.ledger = nil
		s.built = false
		if dir != "" {
			s.ledger = s.newLedger(managed.HookGuardianAuthorizationPath(dir))
		}
	}
	fail := func() {
		s.index, s.keys, s.built = nil, nil, false
	}
	if dir == "" || s.ledger == nil {
		fail()
		return
	}
	key, err := s.loadKey(dir)
	if err != nil || key == "" {
		// No key, or one that fails its trust checks: no per-user
		// credential authenticates.
		fail()
		return
	}
	keys := []string{key}
	// The staged key is read before the retiring one: a rollback renames the
	// first to the second, so this order sees it under one name or the other.
	for _, load := range []func(string) (string, error){s.loadPendingKey, s.loadRetiringKey} {
		if load == nil {
			continue
		}
		if extra, err := load(dir); err == nil && extra != "" && !slices.Contains(keys, extra) {
			keys = append(keys, extra)
		}
	}
	ledger, generation, err := s.ledger()
	if err != nil {
		fail()
		return
	}
	if s.built && slices.Equal(keys, s.keys) && generation == s.generation {
		return
	}
	s.index = buildUserScopedCredentialIndex(keys, ledger)
	s.keys, s.generation, s.built = keys, generation, true
}

// keyFingerprints names the keys whose credentials authenticate right now:
// the committed key, then a staged or retiring one. The standalone lifecycle reads them
// from /health to prove a rotation's key is live before any user is moved
// to it, and that the old key is retired after the commit.
func (s *userScopedCredentialStore) keyFingerprints() []string {
	fingerprints := []string{}
	if s == nil {
		return fingerprints
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	for _, key := range s.keys {
		fingerprints = append(fingerprints, connector.UserScopedTokenKeyFingerprint(key))
	}
	return fingerprints
}

func buildUserScopedCredentialIndex(keys []string, ledger managedHookLedger) map[[sha256.Size]byte]userScopedCredential {
	index := map[[sha256.Size]byte]userScopedCredential{}
	add := func(kind, scope, identity, token string, key int) {
		index[sha256.Sum256([]byte(token))] = userScopedCredential{kind: kind, scope: scope, identity: identity, key: key}
	}
	for _, target := range ledger.Targets {
		if !target.OK {
			continue
		}
		identity, ok := userScopedLedgerIdentity(target)
		if !ok {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(target.Connector))
		otlpScope, hasOTLP := connector.OTLPPathTokenScopeForConnector(name)
		for keyIndex, key := range keys {
			if token, err := connector.UserScopedHookAPIToken(key, name, identity); err == nil {
				add(connector.UserScopedHookCredential, name, identity, token, keyIndex)
			}
			if hasOTLP {
				if token, err := connector.UserScopedOTLPPathToken(key, otlpScope, identity); err == nil {
					add(connector.UserScopedOTLPCredential, string(otlpScope), identity, token, keyIndex)
				}
			}
		}
	}
	return index
}

// userScopedLedgerIdentity is the OS identity a protected target's
// credentials are bound to: its SID on Windows, its uid on Unix. The Unix
// guardian omits uid 0 from the ledger, so a row without one resolves its
// account name through the local account database.
func userScopedLedgerIdentity(target managedHookLedgerTarget) (string, bool) {
	if sid := strings.TrimSpace(target.SID); sid != "" {
		return connector.CanonicalUserScopedIdentity(sid)
	}
	if target.UID != nil {
		return connector.CanonicalUserScopedIdentity(strconv.Itoa(*target.UID))
	}
	name := strings.TrimSpace(target.User)
	if name == "" {
		return "", false
	}
	account, err := userScopedLookupAccount(name)
	if err != nil || account == nil {
		return "", false
	}
	return connector.CanonicalUserScopedIdentity(account.Uid)
}

var userScopedLookupAccount = user.Lookup

// userScopedIdentityIDHeaders and userScopedIdentityNameHeaders are the
// caller-supplied identity headers checked against a per-user credential.
var (
	userScopedIdentityIDHeaders   = []string{llmEventUserIDHeader, "X-User-Id", "X-User"}
	userScopedIdentityNameHeaders = []string{llmEventUserNameHeader, "X-User-Name", "X-Username"}
)

// bindUserScopedIdentity makes identity the only user identity downstream
// layers see. It refuses the request (false) when an identity header names
// another uid or SID, or the name of another account. A name no account has
// now is the name the account had when its user signed in: a renamed account
// (Rename-LocalUser) is the same SID, so it is served, not refused until its
// user signs out (GAP-0907). Header values are never trusted beyond that:
// they are replaced by the bound identity and its current account name,
// which records then carry (GAP-0702).
func bindUserScopedIdentity(r *http.Request, identity string) (*http.Request, bool) {
	for _, header := range userScopedIdentityIDHeaders {
		for _, value := range r.Header.Values(header) {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			canonical, ok := connector.CanonicalUserScopedIdentity(value)
			if !ok || canonical != identity {
				return r, false
			}
		}
	}
	name := sanitizeLLMEventUser(userScopedIdentityName(identity))
	for _, header := range userScopedIdentityNameHeaders {
		for _, value := range r.Header.Values(header) {
			value = strings.TrimSpace(value)
			if value == "" || name == "" {
				continue
			}
			if userScopedNamesEqual(identity, value, name) {
				continue
			}
			if other, known := userScopedIdentityForName(value); !known || other != identity {
				if known {
					return r, false
				}
				noteRenamedUserScopedAccount(identity, value, name)
			}
		}
	}
	for _, header := range managedHookIdentityHeaders {
		r.Header.Del(header)
	}
	r.Header.Set(llmEventUserIDHeader, identity)
	if name != "" {
		r.Header.Set(llmEventUserNameHeader, name)
	}
	ctx := r.Context()
	id := AgentIdentityFromContext(ctx)
	id.UserID = identity
	id.UserIDKind = useridentity.KindForID(identity)
	id.UserName = name
	return r.WithContext(ContextWithAgentIdentity(ctx, id)), true
}

// userScopedNamesEqual compares an account name the way the platform does:
// Windows account names are case-insensitive, POSIX names are not. Both
// sides compare by their bare account, because the host may name a
// directory account qualified (alice@realm, CORP\alice) while the caller
// sends the bare name (GAP-0290).
func userScopedNamesEqual(identity, presented, resolved string) bool {
	presented = useridentity.BareAccountName(presented)
	resolved = useridentity.BareAccountName(resolved)
	if useridentity.KindForID(identity) == useridentity.KindWindowsSID {
		return strings.EqualFold(presented, resolved)
	}
	return presented == resolved
}

// renamedUserScopedAccounts remembers the renamed accounts already logged,
// so their hooks leave one gateway log line, not one per call.
var renamedUserScopedAccounts = &boundedNameSet{max: 256}

// noteRenamedUserScopedAccount logs, once per identity and old name, that a
// caller still sends a name the account no longer has.
func noteRenamedUserScopedAccount(identity, presented, current string) {
	key := identity + "/" + sanitizeLLMEventUser(useridentity.BareAccountName(presented))
	if slices.Contains(renamedUserScopedAccounts.list(), key) {
		return
	}
	renamedUserScopedAccounts.add(key)
	fmt.Fprintf(os.Stderr, "[sidecar-api] per-user credential identity=%s sends the account name %q, which no account has "+
		"now (renamed to %q?); served by its identity under the current name until its user signs in again\n",
		identity, sanitizeLLMEventUser(presented), current)
}

// userScopedCredentialsRequired reports whether connector credentials on the
// TCP API must be per-user: the standalone profile, on every OS.
func (a *APIServer) userScopedCredentialsRequired() bool {
	return a != nil && a.scannerCfg != nil && a.scannerCfg.StandaloneEnterprise()
}

func (a *APIServer) userScopedCredentialStore() *userScopedCredentialStore {
	a.userScopedCredentialsOnce.Do(func() {
		if a.userScopedCredentials == nil {
			a.userScopedCredentials = newUserScopedCredentialStore(a.configDataDir)
		}
	})
	return a.userScopedCredentials
}

// lookupUserScopedCredential returns the identity a per-user credential is
// bound to, or false outside the standalone profile.
func (a *APIServer) lookupUserScopedCredential(kind, scope, presented string) (string, bool) {
	if !a.userScopedCredentialsRequired() {
		return "", false
	}
	return a.userScopedCredentialStore().lookup(kind, scope, presented)
}

// serveUserScoped runs next for a request authenticated by a per-user
// credential bound to identity, after binding that identity to the request.
func (a *APIServer) serveUserScoped(
	w http.ResponseWriter,
	r *http.Request,
	route, identity string,
	next http.Handler,
	mark func(context.Context) context.Context,
) {
	r, release := a.admitHookCaller(w, r, identity, route)
	if release == nil {
		return
	}
	defer release()
	ctx := PromoteSessionIfAuthenticated(r.Context())
	ctx = context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, identity)
	ctx = attachVerifiedSubject(ctx, a.observabilityV8RuntimeEmitter(), identity, sanitizeLLMEventUser(userScopedIdentityName(identity)), subjectSourceUserCredential)
	if mark != nil {
		ctx = mark(ctx)
	}
	bound, ok := bindUserScopedIdentity(r.WithContext(ctx), identity)
	if !ok {
		fmt.Fprintf(os.Stderr,
			"[sidecar-api] per-user credential refused identity=%s route=%s reason=%s\n",
			identity, route, userScopedIdentityMismatchReason)
		a.emitHTTPAuthFailure(ctx, r, route, gatewaylog.ErrCodeAuthInvalidToken, userScopedIdentityMismatchReason)
		writeManagedHookRefusal(w, http.StatusForbidden, userScopedIdentityMismatchReason)
		return
	}
	next.ServeHTTP(w, bound)
}
