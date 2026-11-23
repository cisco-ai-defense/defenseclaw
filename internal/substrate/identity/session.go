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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Relay session tokens (the format lane A5's relay verifies,
// internal/substrate/relay/auth.go): a compact JWS with typ dcrelay+jwt,
// ES256, that names one person and one actor incarnation. The admin
// listener issues them to a signed-in person who may attach to that actor;
// the relay accepts nothing else (E2).
const (
	SessionTokenType = "dcrelay+jwt"
	// SessionAudience is the aud the relay expects.
	SessionAudience = "dcrelay"
	// SessionClaim holds the actor a session token is for.
	SessionClaim = "dc.actor"
	// SessionTaskClaim holds the SHA-256 (hex) of the task the actor was
	// registered for; the relay starts a task only when its text has this
	// digest (GAP-0071, GAP-0162).
	SessionTaskClaim = "dc.task_sha256"
	// DefaultSessionLifetime and MaxSessionLifetime bound a token's life.
	DefaultSessionLifetime = 15 * time.Minute
	MaxSessionLifetime     = time.Hour
)

// SessionActor is the actor incarnation a session token is for.
type SessionActor struct {
	Atespace string `json:"atespace"`
	Name     string `json:"actorName"`
	UID      string `json:"actorUID"`
	// TaskDigest is the registration task digest ("" for an interactive
	// run). It travels as the top-level SessionTaskClaim, not in dc.actor.
	TaskDigest string `json:"-"`
	// Scope limits the token to one relay stream (B3 dc.scope: "port:N"
	// or "mcp:NAME"); "" is a terminal, task or file token. It travels as
	// the top-level dc.scope claim.
	Scope string `json:"-"`
}

// scopeRE is the shape of a stream scope: a port forward or an MCP bridge.
var scopeRE = regexp.MustCompile(`^(port:[1-9][0-9]{0,4}|mcp:[a-z0-9][a-z0-9_-]{0,31})$`)

// ValidScope reports an empty scope or one stream scope.
func ValidScope(s string) bool { return s == "" || scopeRE.MatchString(s) }

// Session is a verified relay session token.
type Session struct {
	Person   string       `json:"person"`
	Actor    SessionActor `json:"-"`
	ActorRef string       `json:"actor"`
	ActorUID string       `json:"actor_uid"`
	TokenID  string       `json:"jti,omitempty"`
	Expires  time.Time    `json:"expires"`
	// IssuedAt is the token's iat: a person-wide revocation after it ends
	// the session (B5.1).
	IssuedAt time.Time `json:"-"`
	// TaskDigest is the SessionTaskClaim ("" when the token has none).
	TaskDigest string `json:"task_digest,omitempty"`
	// SignInIssuedAt and SignInKey are the issue time and token key of the
	// sign-in the session was handed out for (zero and "" in a session a
	// released 1.0.10 gateway minted, which lives at most MaxSessionLifetime;
	// Issue never writes one).
	// Relay verify checks that sign-in too, so a session of an ended
	// sign-in is refused (GAP-0744).
	SignInIssuedAt time.Time `json:"-"`
	SignInKey      string    `json:"-"`
	// Scope is the dc.scope claim ("" when the token has none).
	Scope string `json:"scope,omitempty"`
}

// SessionSignIn is the sign-in a session token is handed out for.
type SessionSignIn struct {
	// Person is the person's ID (issuer#subject).
	Person string
	// IssuedAt is the sign-in token's iat, zero when it has none (a
	// static Kubernetes token).
	IssuedAt time.Time
	// TokenKey is the sign-in token's revocation key (Person.TokenKey).
	TokenKey string
}

// SignInOf is the sign-in of a verified person.
func SignInOf(p Person) SessionSignIn {
	return SessionSignIn{Person: p.ID(), IssuedAt: p.IssuedAt, TokenKey: p.TokenKey}
}

type sessionClaims struct {
	Issuer    string        `json:"iss"`
	Subject   string        `json:"sub"`
	Audience  audience      `json:"aud"`
	Expiry    *int64        `json:"exp"`
	NotBefore *int64        `json:"nbf"`
	IssuedAt  *int64        `json:"iat"`
	ID        string        `json:"jti"`
	Actor     *SessionActor `json:"dc.actor"`
	Task      string        `json:"dc.task_sha256,omitempty"`
	SignInIAT *int64        `json:"dc.signin_iat,omitempty"`
	SignInKey string        `json:"dc.signin_key,omitempty"`
	Scope     string        `json:"dc.scope,omitempty"`
}

// validTaskDigest reports an empty digest or 64 lowercase hex digits.
func validTaskDigest(d string) bool {
	if d == "" {
		return true
	}
	if len(d) != 64 {
		return false
	}
	for _, c := range d {
		if (c < 0x30 || c > 0x39) && (c < 0x61 || c > 0x66) {
			return false
		}
	}
	return true
}

// SessionSigner issues and verifies relay session tokens with one P-256
// key. The private key lives in a defenseclaw-system Secret (D14); the
// public key is what relays get.
type SessionSigner struct {
	key    *ecdsa.PrivateKey
	kid    string
	issuer string
	now    func() time.Time
}

// LoadSessionSigner reads a PEM EC private key (SEC 1 or PKCS #8, P-256).
func LoadSessionSigner(path, issuer string) (*SessionSigner, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("identity: session key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("identity: session key: no PEM block")
	}
	var key *ecdsa.PrivateKey
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		key = k
	} else if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("identity: session key is not an EC key")
		}
		key = ek
	} else {
		return nil, errors.New("identity: session key is not a PEM EC private key")
	}
	return NewSessionSigner(key, issuer)
}

// NewSessionSigner wraps a P-256 key.
func NewSessionSigner(key *ecdsa.PrivateKey, issuer string) (*SessionSigner, error) {
	if key == nil || key.Curve != elliptic.P256() {
		return nil, errors.New("identity: session key must be P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return &SessionSigner{key: key, kid: base64.RawURLEncoding.EncodeToString(sum[:]), issuer: issuer, now: time.Now}, nil
}

// KeyID is the base64url SHA-256 of the public key's PKIX encoding (the
// same rule ate-idp-server uses), so the relay's key map is keyed alike.
func (s *SessionSigner) KeyID() string { return s.kid }

// Issuer is the iss the signer writes ("" for none).
func (s *SessionSigner) Issuer() string { return s.issuer }

// PublicKeyPEM is the public key for relays (PKIX PEM).
func (s *SessionSigner) PublicKeyPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// SetClock replaces the clock (tests).
func (s *SessionSigner) SetClock(now func() time.Time) { s.now = now }

// Issue signs a token for the person of signIn to attach to actor for ttl
// (default DefaultSessionLifetime, at most MaxSessionLifetime). The token
// names the sign-in, so ending that sign-in ends the session (GAP-0744).
func (s *SessionSigner) Issue(signIn SessionSignIn, actor SessionActor, ttl time.Duration) (string, time.Time, error) {
	return s.IssueUntil(signIn, actor, ttl, time.Time{})
}

// ErrSessionBound refuses a session token whose bound has passed: the
// caller's own sign-in ends before the token could start (GAP-0588).
var ErrSessionBound = errors.New("identity: the sign-in ends before a session token could start")

// IssueUntil is Issue for a token that also ends no later than notAfter,
// the end of the caller's own bearer (Person.SessionBound; zero: no
// bound). A session token never outlives the sign-in it came from
// (GAP-0588): the relay ends an attachment at its token's exp, and the
// launcher reconnects with a fresh sign-in.
func (s *SessionSigner) IssueUntil(signIn SessionSignIn, actor SessionActor, ttl time.Duration, notAfter time.Time) (string, time.Time, error) {
	person := strings.TrimSpace(signIn.Person)
	if person == "" || strings.HasPrefix(person, ActorSubjectPrefix) || strings.HasPrefix(person, WorkerSubjectPrefix) {
		return "", time.Time{}, errors.New("identity: a session token names a person")
	}
	// A session with no sign-in key would pass relay verify as one a 1.0.10
	// gateway minted, unchecked against its sign-in (RV4-03).
	if strings.TrimSpace(signIn.TokenKey) == "" {
		return "", time.Time{}, errors.New("identity: a session token names the sign-in it is handed out for")
	}
	if !nameRE.MatchString(actor.Atespace) || !nameRE.MatchString(actor.Name) || !validUID(actor.UID) {
		return "", time.Time{}, errors.New("identity: a session token names one actor incarnation")
	}
	if !validTaskDigest(actor.TaskDigest) {
		return "", time.Time{}, errors.New("identity: a task digest is the SHA-256 of the task in hex")
	}
	if !ValidScope(actor.Scope) {
		return "", time.Time{}, errors.New("identity: a session scope is port:N or mcp:NAME")
	}
	if ttl <= 0 {
		ttl = DefaultSessionLifetime
	}
	if ttl > MaxSessionLifetime {
		ttl = MaxSessionLifetime
	}
	now := s.now().Truncate(time.Second)
	exp := now.Add(ttl)
	if !notAfter.IsZero() {
		// exp is a whole second (a NumericDate): the bound rounds down, so
		// the token ends at or before it.
		if b := notAfter.Truncate(time.Second); b.Before(exp) {
			exp = b
		}
		if !exp.After(now) {
			return "", time.Time{}, ErrSessionBound
		}
	}
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}
	iat, nbf, ex := now.Unix(), now.Unix(), exp.Unix()
	claims := sessionClaims{
		Issuer: s.issuer, Subject: person, Audience: audience{SessionAudience},
		Expiry: &ex, NotBefore: &nbf, IssuedAt: &iat,
		ID: base64.RawURLEncoding.EncodeToString(jti), Actor: &actor, Task: actor.TaskDigest, Scope: actor.Scope,
		SignInKey: signIn.TokenKey,
	}
	if !signIn.IssuedAt.IsZero() {
		at := signIn.IssuedAt.Unix()
		claims.SignInIAT = &at
	}
	hb, _ := json.Marshal(jwsHeader{Alg: "ES256", Kid: s.kid, Typ: SessionTokenType})
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}
	signed := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	d := sha256.Sum256([]byte(signed))
	r, ss, err := ecdsa.Sign(rand.Reader, s.key, d[:])
	if err != nil {
		return "", time.Time{}, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	ss.FillBytes(sig[32:])
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), exp, nil
}

// Verify checks a session token this signer issued.
func (s *SessionSigner) Verify(token string) (Session, error) {
	t, err := parseJWS(token)
	if err != nil {
		return Session{}, err
	}
	if t.header.Typ != SessionTokenType {
		return Session{}, reasonf(ReasonType, "token typ is not %s", SessionTokenType)
	}
	if t.header.Kid != s.kid {
		return Session{}, reasonf(ReasonUnknownKey, "session token key is not this gateway's")
	}
	if t.header.Alg != "ES256" {
		return Session{}, reasonf(ReasonAlgorithm, "session token alg is not ES256")
	}
	if err := verifySignature("ES256", crypto.PublicKey(&s.key.PublicKey), t.signed, t.signature); err != nil {
		return Session{}, err
	}
	var c sessionClaims
	if err := strictJSON(t.claims, &c); err != nil {
		return Session{}, reasonf(ReasonMalformed, "session token claims are not a JSON object")
	}
	if c.Issuer != s.issuer {
		return Session{}, reasonf(ReasonIssuer, "session token issuer is not this gateway")
	}
	if !c.Audience.contains(SessionAudience) {
		return Session{}, reasonf(ReasonAudience, "session token audience is not the relay")
	}
	if err := checkTimes(s.now(), DefaultSkew, c.Expiry, c.NotBefore, c.IssuedAt, MaxSessionLifetime); err != nil {
		return Session{}, err
	}
	if c.Subject == "" || strings.HasPrefix(c.Subject, ActorSubjectPrefix) || strings.HasPrefix(c.Subject, WorkerSubjectPrefix) {
		return Session{}, reasonf(ReasonSubject, "session token subject is not a person")
	}
	if c.Actor == nil || c.Actor.Atespace == "" || c.Actor.Name == "" || c.Actor.UID == "" {
		return Session{}, reasonf(ReasonClaims, "session token names no actor")
	}
	if !validTaskDigest(c.Task) {
		return Session{}, reasonf(ReasonClaims, "session token task digest is not a SHA-256")
	}
	if c.SignInIAT != nil && (c.SignInKey == "" || *c.SignInIAT <= 0) {
		return Session{}, reasonf(ReasonClaims, "session token names its sign-in in the wrong form")
	}
	actor := *c.Actor
	if !ValidScope(c.Scope) {
		return Session{}, reasonf(ReasonClaims, "session token scope is not a stream scope")
	}
	actor.TaskDigest, actor.Scope = c.Task, c.Scope
	out := Session{
		Person: c.Subject, Actor: actor, ActorRef: c.Actor.Atespace + "/" + c.Actor.Name, ActorUID: c.Actor.UID,
		TokenID: c.ID, Expires: time.Unix(*c.Expiry, 0), IssuedAt: time.Unix(*c.IssuedAt, 0), TaskDigest: c.Task, Scope: c.Scope,
		SignInKey: c.SignInKey,
	}
	if c.SignInIAT != nil {
		out.SignInIssuedAt = time.Unix(*c.SignInIAT, 0)
	}
	return out, nil
}
