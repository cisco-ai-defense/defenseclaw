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
	// DefaultSessionLifetime and MaxSessionLifetime bound a token's life.
	DefaultSessionLifetime = 15 * time.Minute
	MaxSessionLifetime     = time.Hour
)

// SessionActor is the actor incarnation a session token is for.
type SessionActor struct {
	Atespace string `json:"atespace"`
	Name     string `json:"actorName"`
	UID      string `json:"actorUID"`
}

// Session is a verified relay session token.
type Session struct {
	Person   string       `json:"person"`
	Actor    SessionActor `json:"-"`
	ActorRef string       `json:"actor"`
	ActorUID string       `json:"actor_uid"`
	TokenID  string       `json:"jti,omitempty"`
	Expires  time.Time    `json:"expires"`
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

// Issue signs a token for person to attach to actor for ttl (default
// DefaultSessionLifetime, at most MaxSessionLifetime).
func (s *SessionSigner) Issue(person string, actor SessionActor, ttl time.Duration) (string, time.Time, error) {
	person = strings.TrimSpace(person)
	if person == "" || strings.HasPrefix(person, ActorSubjectPrefix) || strings.HasPrefix(person, WorkerSubjectPrefix) {
		return "", time.Time{}, errors.New("identity: a session token names a person")
	}
	if !nameRE.MatchString(actor.Atespace) || !nameRE.MatchString(actor.Name) || !validUID(actor.UID) {
		return "", time.Time{}, errors.New("identity: a session token names one actor incarnation")
	}
	if ttl <= 0 {
		ttl = DefaultSessionLifetime
	}
	if ttl > MaxSessionLifetime {
		ttl = MaxSessionLifetime
	}
	now := s.now().Truncate(time.Second)
	exp := now.Add(ttl)
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", time.Time{}, err
	}
	iat, nbf, ex := now.Unix(), now.Unix(), exp.Unix()
	claims := sessionClaims{
		Issuer: s.issuer, Subject: person, Audience: audience{SessionAudience},
		Expiry: &ex, NotBefore: &nbf, IssuedAt: &iat,
		ID: base64.RawURLEncoding.EncodeToString(jti), Actor: &actor,
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
	return Session{
		Person: c.Subject, Actor: *c.Actor, ActorRef: c.Actor.Atespace + "/" + c.Actor.Name, ActorUID: c.Actor.UID,
		TokenID: c.ID, Expires: time.Unix(*c.Expiry, 0),
	}, nil
}
