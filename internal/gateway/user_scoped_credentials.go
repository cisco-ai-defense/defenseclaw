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

// userScopedCredentialRefreshInterval bounds how often the key and ledger
// are revalidated on the request path.
const userScopedCredentialRefreshInterval = time.Second

const userScopedIdentityMismatchReason = "user_scoped_identity_mismatch"

type userScopedCredential struct {
	kind     string
	scope    string
	identity string
}

// userScopedCredentialStore caches the credential index derived from the
// key and the ledger. The index is keyed by the SHA-256 of each credential,
// so a lookup never compares a presented value against a secret.
type userScopedCredentialStore struct {
	dataDir   func() string
	loadKey   func(dataDir string) (string, error)
	newLedger func(path string) func() (managedHookLedger, uint64, error)
	now       func() time.Time

	mu         sync.Mutex
	checkedAt  time.Time
	dir        string
	ledger     func() (managedHookLedger, uint64, error)
	key        string
	generation uint64
	built      bool
	index      map[[sha256.Size]byte]userScopedCredential
}

func newUserScopedCredentialStore(dataDir func() string) *userScopedCredentialStore {
	return &userScopedCredentialStore{
		dataDir: dataDir,
		loadKey: connector.LoadUserScopedTokenKey,
		newLedger: func(path string) func() (managedHookLedger, uint64, error) {
			return newManagedHookLedgerLoader(path).LoadGeneration
		},
		now: time.Now,
	}
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
	token, err := connector.UserScopedHookAPIToken(s.key, scope, credential.identity)
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
		s.index, s.key, s.built = nil, "", false
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
	ledger, generation, err := s.ledger()
	if err != nil {
		fail()
		return
	}
	if s.built && key == s.key && generation == s.generation {
		return
	}
	s.index = buildUserScopedCredentialIndex(key, ledger)
	s.key, s.generation, s.built = key, generation, true
}

func buildUserScopedCredentialIndex(key string, ledger managedHookLedger) map[[sha256.Size]byte]userScopedCredential {
	index := map[[sha256.Size]byte]userScopedCredential{}
	add := func(kind, scope, identity, token string) {
		index[sha256.Sum256([]byte(token))] = userScopedCredential{kind: kind, scope: scope, identity: identity}
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
		if token, err := connector.UserScopedHookAPIToken(key, name, identity); err == nil {
			add(connector.UserScopedHookCredential, name, identity, token)
		}
		if scope, ok := connector.OTLPPathTokenScopeForConnector(name); ok {
			if token, err := connector.UserScopedOTLPPathToken(key, scope, identity); err == nil {
				add(connector.UserScopedOTLPCredential, string(scope), identity, token)
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
// another uid or SID, or another account name than the one the identity
// resolves to. Header values are never trusted beyond that comparison: they
// are replaced by the bound identity and its resolved account name.
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
			if !userScopedNamesEqual(identity, value, name) {
				return r, false
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
// Windows account names are case-insensitive, POSIX names are not.
func userScopedNamesEqual(identity, presented, resolved string) bool {
	if useridentity.KindForID(identity) == useridentity.KindWindowsSID {
		return strings.EqualFold(presented, resolved)
	}
	return presented == resolved
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
