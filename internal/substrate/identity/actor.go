// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Actor token rules (Agent Substrate v1.0.0 docs/guides/actor-jwts.md).
const (
	// ActorSubjectPrefix starts every actor token subject.
	ActorSubjectPrefix = "actor/"
	// WorkerSubjectPrefix starts the subjects of worker-for-actor tokens,
	// which the same keys sign and a relying party must reject.
	WorkerSubjectPrefix = "worker-for-actor/"
	// ActorClaim and WorkerClaim are the private claim objects.
	ActorClaim  = "actor.ate.dev"
	WorkerClaim = "worker-for-actor.ate.dev"
	// DefaultAudience is the audience DefenseClaw asks egress to mint.
	DefaultAudience = "defenseclaw"
	// DefaultSkew is the clock skew allowed on exp and nbf.
	DefaultSkew = 60 * time.Second
	// MaxActorTokenLifetime is upstream's longest expiration_seconds.
	MaxActorTokenLifetime = time.Hour
	// DefaultLiveTTL is how long a live-UID answer is cached.
	// It is short because only the replica that served a DefenseClaw
	// delete invalidates its own cache: every other replica sees a deleted
	// or recreated actor within this time (GAP-0060).
	DefaultLiveTTL = 10 * time.Second
	// DefaultLiveGrace is how long the last good answer serves while the
	// control API cannot answer (PLAN 5.5: 60 s, then refuse).
	DefaultLiveGrace = 60 * time.Second
	// liveRecheck is the least time between two forced re-checks of one
	// actor whose token names a UID the cache does not hold.
	liveRecheck = time.Second
)

// Atespace and actor names are DNS labels of up to 63 characters.
var nameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// ActorState is the lifecycle state the control API reports.
type ActorState string

const (
	ActorRunning  ActorState = "RUNNING"
	ActorResuming ActorState = "RESUMING"
)

// LiveActor is the control API's view of an actor.
type LiveActor struct {
	UID   string
	State ActorState
}

// ActorLookup reads an actor from the Substrate control API. It returns
// ErrActorNotFound for an actor that does not exist; any other error means
// the API could not answer.
type ActorLookup interface {
	LookupActor(ctx context.Context, atespace, name string) (LiveActor, error)
}

// ActorLookupFunc adapts a function to ActorLookup.
type ActorLookupFunc func(ctx context.Context, atespace, name string) (LiveActor, error)

// LookupActor implements ActorLookup.
func (f ActorLookupFunc) LookupActor(ctx context.Context, atespace, name string) (LiveActor, error) {
	return f(ctx, atespace, name)
}

// ErrActorNotFound is what an ActorLookup returns for a missing actor.
var ErrActorNotFound = errors.New("actor not found")

// Actor is a verified actor token: the caller of an actor-listener
// request.
type Actor struct {
	Issuer   string
	Subject  string
	Atespace string
	Name     string
	UID      string
	TokenID  string
	Expires  time.Time
	IssuedAt time.Time
}

// Ref is atespace/name.
func (a Actor) Ref() string { return a.Atespace + "/" + a.Name }

// ActorVerifierOptions configures an ActorVerifier.
type ActorVerifierOptions struct {
	KeySet *KeySet
	// Audience defaults to DefaultAudience.
	Audience string
	// Skew defaults to DefaultSkew.
	Skew time.Duration
	// Lookup checks that the token's actor UID is live. Required: an actor
	// token names an actor, not one incarnation (a recreated same-name
	// actor gets the same sub), and upstream #2208 lets egress inject a
	// token of the old incarnation for a while.
	Lookup ActorLookup
	// LiveTTL defaults to DefaultLiveTTL.
	LiveTTL time.Duration
	Now     func() time.Time
}

// ActorVerifier verifies actor tokens. It is safe for concurrent use.
type ActorVerifier struct {
	keys     *KeySet
	audience string
	skew     time.Duration
	lookup   ActorLookup
	liveTTL  time.Duration
	now      func() time.Time

	mu   sync.Mutex
	live map[string]liveEntry
}

type liveEntry struct {
	actor   LiveActor
	found   bool
	at      time.Time
	recheck time.Time
}

// maxLiveEntries bounds the live-UID cache; past it, expired entries go
// first and then the whole cache is dropped (it refills from the API).
const maxLiveEntries = 65536

// NewActorVerifier validates opts.
func NewActorVerifier(opts ActorVerifierOptions) (*ActorVerifier, error) {
	if opts.KeySet == nil {
		return nil, errors.New("identity: actor verifier needs a key set")
	}
	if opts.Lookup == nil {
		return nil, errors.New("identity: actor verifier needs the control API lookup (live actor UID)")
	}
	v := &ActorVerifier{
		keys: opts.KeySet, audience: opts.Audience, skew: opts.Skew,
		lookup: opts.Lookup, liveTTL: opts.LiveTTL, now: opts.Now,
		live: make(map[string]liveEntry),
	}
	if v.audience == "" {
		v.audience = DefaultAudience
	}
	if v.skew <= 0 {
		v.skew = DefaultSkew
	}
	if v.liveTTL <= 0 {
		v.liveTTL = DefaultLiveTTL
	}
	if v.now == nil {
		v.now = time.Now
	}
	return v, nil
}

type actorClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  audience        `json:"aud"`
	Expiry    *int64          `json:"exp"`
	NotBefore *int64          `json:"nbf"`
	IssuedAt  *int64          `json:"iat"`
	ID        string          `json:"jti"`
	Actor     *actorObject    `json:"actor.ate.dev"`
	Worker    json.RawMessage `json:"worker-for-actor.ate.dev"`
}

type actorObject struct {
	Atespace string `json:"atespace"`
	Name     string `json:"actorName"`
	UID      string `json:"actorUID"`
}

// Verify checks token as actor-jwts.md requires, then that its actor UID
// is live (RESUMING or RUNNING). It returns the verified actor, or an
// *Error whose Reason says why not.
func (v *ActorVerifier) Verify(ctx context.Context, token string) (Actor, error) {
	t, err := parseJWS(token)
	if err != nil {
		return Actor{}, err
	}
	if t.header.Typ != "" && !strings.EqualFold(t.header.Typ, "JWT") {
		// Session tokens (dcrelay+jwt) and other typed tokens are never
		// actor tokens, whoever signed them.
		return Actor{}, reasonf(ReasonType, "token typ is not JWT")
	}
	if err := v.keys.verify(ctx, t); err != nil {
		return Actor{}, err
	}
	var c actorClaims
	if err := strictJSON(t.claims, &c); err != nil {
		return Actor{}, reasonf(ReasonMalformed, "token claims are not a JSON object")
	}
	if c.Issuer != v.keys.Issuer() {
		return Actor{}, reasonf(ReasonIssuer, "token issuer is not trusted")
	}
	if !c.Audience.contains(v.audience) {
		return Actor{}, reasonf(ReasonAudience, "token audience does not contain %s", v.audience)
	}
	if err := checkTimes(v.now(), v.skew, c.Expiry, c.NotBefore, c.IssuedAt, MaxActorTokenLifetime); err != nil {
		return Actor{}, err
	}
	if strings.HasPrefix(c.Subject, WorkerSubjectPrefix) || len(c.Worker) > 0 {
		return Actor{}, reasonf(ReasonWorkerToken, "a worker-for-actor token is not an actor token")
	}
	if !strings.HasPrefix(c.Subject, ActorSubjectPrefix) {
		return Actor{}, reasonf(ReasonSubject, "token subject is not an actor")
	}
	if c.Actor == nil || !nameRE.MatchString(c.Actor.Atespace) || !nameRE.MatchString(c.Actor.Name) ||
		!validUID(c.Actor.UID) {
		return Actor{}, reasonf(ReasonClaims, "token has no valid %s claim", ActorClaim)
	}
	if c.Subject != ActorSubjectPrefix+c.Actor.Atespace+"/"+c.Actor.Name {
		return Actor{}, reasonf(ReasonSubject, "token subject does not name its actor claim")
	}
	a := Actor{
		Issuer: c.Issuer, Subject: c.Subject,
		Atespace: c.Actor.Atespace, Name: c.Actor.Name, UID: c.Actor.UID, TokenID: c.ID,
		Expires: time.Unix(*c.Expiry, 0), IssuedAt: time.Unix(*c.IssuedAt, 0),
	}
	if err := v.checkLive(ctx, a); err != nil {
		return Actor{}, err
	}
	return a, nil
}

func validUID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

// checkTimes applies exp, nbf and iat with skew, and caps the lifetime.
func checkTimes(now time.Time, skew time.Duration, exp, nbf, iat *int64, maxLife time.Duration) error {
	if exp == nil || iat == nil {
		return reasonf(ReasonClaims, "token has no exp or iat")
	}
	e, i := time.Unix(*exp, 0), time.Unix(*iat, 0)
	if now.After(e.Add(skew)) {
		return reasonf(ReasonExpired, "token expired")
	}
	if nbf != nil && now.Add(skew).Before(time.Unix(*nbf, 0)) {
		return reasonf(ReasonNotYetValid, "token is not valid yet")
	}
	if now.Add(skew).Before(i) {
		return reasonf(ReasonNotYetValid, "token was issued in the future")
	}
	if e.Sub(i) > maxLife+skew || !e.After(i) {
		return reasonf(ReasonLifetime, "token lifetime is out of range")
	}
	return nil
}

// checkLive compares the token's UID with the control API's, through a
// cache of LiveTTL. A UID the cache does not hold forces one re-check (at
// most every second per actor), so a new incarnation's first call is not
// refused for the old one's cache entry; a stale token of a recreated actor
// still fails against the fresh answer.
func (v *ActorVerifier) checkLive(ctx context.Context, a Actor) error {
	key := a.Ref()
	now := v.now()
	v.mu.Lock()
	e, ok := v.live[key]
	v.mu.Unlock()
	fresh := ok && now.Sub(e.at) < v.liveTTL
	if fresh && e.found && e.actor.UID == a.UID && liveState(e.actor) == nil {
		return nil
	}
	if fresh && now.Before(e.recheck) {
		// A refusal from the cache; it is re-checked at most every second,
		// so a resumed or recreated actor is not refused for long.
		if e.found && e.actor.UID == a.UID {
			return liveState(e.actor)
		}
		return liveMismatch(e)
	}
	got, err := v.lookup.LookupActor(ctx, a.Atespace, a.Name)
	switch {
	case errors.Is(err, ErrActorNotFound):
		e = liveEntry{found: false, at: now, recheck: now.Add(liveRecheck)}
	case err != nil:
		// The control API is down: the last good answer for this UID
		// serves for DefaultLiveGrace (PLAN 5.5), then the call is refused.
		if ok && e.found && e.actor.UID == a.UID && now.Sub(e.at) < DefaultLiveGrace {
			return liveState(e.actor)
		}
		return reasonf(ReasonUnavailable, "control API: actor lookup failed")
	default:
		e = liveEntry{actor: got, found: true, at: now, recheck: now.Add(liveRecheck)}
	}
	v.store(key, e)
	if e.found && e.actor.UID == a.UID {
		return liveState(e.actor)
	}
	return liveMismatch(e)
}

func liveState(a LiveActor) error {
	switch a.State {
	case ActorRunning, ActorResuming:
		return nil
	}
	return reasonf(ReasonActorState, "actor is not running")
}

func liveMismatch(e liveEntry) error {
	if !e.found {
		return reasonf(ReasonActorGone, "actor no longer exists")
	}
	return reasonf(ReasonActorUID, "token names another incarnation of the actor")
}

func (v *ActorVerifier) store(key string, e liveEntry) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.live) >= maxLiveEntries {
		now := v.now()
		for k, old := range v.live {
			if now.Sub(old.at) >= v.liveTTL {
				delete(v.live, k)
			}
		}
		if len(v.live) >= maxLiveEntries {
			v.live = make(map[string]liveEntry)
		}
	}
	v.live[key] = e
}

// Invalidate drops the cached live state of atespace/name. The controller
// calls it on lifecycle events (suspend, delete, fork, recreate).
func (v *ActorVerifier) Invalidate(atespace, name string) {
	v.mu.Lock()
	delete(v.live, atespace+"/"+name)
	v.mu.Unlock()
}
