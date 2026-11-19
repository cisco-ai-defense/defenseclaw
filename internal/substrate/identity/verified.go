// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/sha256"
	"time"
)

// An actor sends the same token on every request until the egress gateway
// injects a new one, and a flooding actor's requests were each verified
// again (signature, claims) before its rate-limit bucket refused them:
// about 100 µs of CPU per refused request, which slowed the other actors
// on the same gateway replica (substrate-1 GAP-0565). The verifier now
// keeps what it checked of a token's bytes, by their SHA-256: the actor,
// and the times, which are checked again on every use, with the live-UID
// check. An entry counts only while the key-set fetch that verified it is
// the one in use and fresh, so a key removed from the pool stops verifying
// within DefaultKeyMaxAge, as before.

// maxVerifiedTokens bounds the verified-token cache; past it, the cache is
// dropped (it refills as tokens are used).
const maxVerifiedTokens = 4096

type verifiedToken struct {
	actor         Actor
	exp, iat, nbf int64
	hasNbf        bool
	gen           uint64 // the key-set fetch that verified it
}

func tokenKey(token string) [sha256.Size]byte { return sha256.Sum256([]byte(token)) }

// verified returns the cached checks of a token, when the key-set fetch
// that verified it is still the fresh one in use.
func (v *ActorVerifier) verified(key [sha256.Size]byte) (verifiedToken, bool) {
	gen, fresh := v.keys.generation()
	if !fresh {
		return verifiedToken{}, false
	}
	v.tokMu.Lock()
	defer v.tokMu.Unlock()
	e, ok := v.tokens[key]
	if !ok || e.gen != gen {
		return verifiedToken{}, false
	}
	return e, true
}

func (v *ActorVerifier) rememberToken(key [sha256.Size]byte, e verifiedToken) {
	v.tokMu.Lock()
	defer v.tokMu.Unlock()
	if v.tokens == nil || len(v.tokens) >= maxVerifiedTokens {
		v.tokens = make(map[[sha256.Size]byte]verifiedToken)
	}
	v.tokens[key] = e
}

func (v *ActorVerifier) forgetToken(key [sha256.Size]byte) {
	v.tokMu.Lock()
	defer v.tokMu.Unlock()
	delete(v.tokens, key)
}

// times re-checks the token's times now.
func (e verifiedToken) times(now time.Time, skew time.Duration) error {
	exp, iat := e.exp, e.iat
	var nbf *int64
	if e.hasNbf {
		n := e.nbf
		nbf = &n
	}
	return checkTimes(now, skew, &exp, nbf, &iat, MaxActorTokenLifetime)
}

// generation is the number of the key-set fetch in use, and whether it is
// fresh (younger than MaxAge).
func (ks *KeySet) generation() (uint64, bool) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.gen, !ks.fetched.IsZero() && ks.now().Sub(ks.fetched) < ks.maxAge
}
