// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// A launcher session token is a compact JWS (typ "dcrelay+jwt", ES256 or
// EdDSA) that the gateway's admin listener issues to a signed-in person for
// one actor (A2). The relay accepts nothing else (E2): not the actor's own
// JWT, not a Substrate worker token, not an unsigned or expired token, and
// not a token for another actor, so `kubectl ate proxy` by someone else
// reaches no terminal.

// TokenType is the JWS typ of a session token.
const TokenType = "dcrelay+jwt"

// Session is a verified attachment's identity.
type Session struct {
	// Person is the token subject (the OIDC principal or workload).
	Person string `json:"person"`
	// Actor is atespace/name.
	Actor    string    `json:"actor"`
	ActorUID string    `json:"actor_uid"`
	TokenID  string    `json:"jti,omitempty"`
	Expires  time.Time `json:"expires"`
	// TaskDigest is the SHA-256 (hex) of the --task text the actor was
	// registered for; empty for an interactive session (GAP-0071).
	TaskDigest string `json:"task_digest,omitempty"`
}

// Verifier checks the credential of an incoming request.
type Verifier interface {
	Verify(ctx context.Context, r *http.Request) (Session, error)
}

// ErrNoToken means the request carried no session token.
var ErrNoToken = errors.New("no launcher session token")

// TokenFrom returns the session token of r: Authorization: Bearer, or a
// WebSocket subprotocol "dcrelay.token.<token>".
func TokenFrom(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if strings.HasPrefix(p, TokenProtocol) {
				return strings.TrimPrefix(p, TokenProtocol)
			}
		}
	}
	return ""
}

// Identity is this actor's identity as Substrate projects it (systemInfo
// actorMetadata, rewritten on every run and restore).
type Identity struct {
	Atespace, Name, UID string
}

// IdentityFiles reads the actor identity from dir/{atespace,name,uid} each
// time it is called: a fork or a restore elsewhere changes it, and nothing
// may be cached from before the first resume (E5).
func IdentityFiles(dir string) func() (Identity, error) {
	return func() (Identity, error) {
		read := func(name string) (string, error) {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(string(b)), nil
		}
		var id Identity
		var err error
		if id.Atespace, err = read("atespace"); err != nil {
			return id, fmt.Errorf("actor identity: %w", err)
		}
		if id.Name, err = read("name"); err != nil {
			return id, fmt.Errorf("actor identity: %w", err)
		}
		if id.UID, err = read("uid"); err != nil {
			return id, fmt.Errorf("actor identity: %w", err)
		}
		if id.Atespace == "" || id.Name == "" || id.UID == "" {
			return id, errors.New("actor identity: empty field")
		}
		return id, nil
	}
}

// KeyVerifier verifies session tokens against public keys. It holds no
// secret (D14).
type KeyVerifier struct {
	// Keys maps a kid to an *ecdsa.PublicKey (P-256) or ed25519.PublicKey.
	Keys     map[string]crypto.PublicKey
	Audience string
	// Issuer must equal iss (GAP-0073).
	Issuer string
	// Self returns this actor's identity; a token must name it.
	Self        func() (Identity, error)
	Now         func() time.Time
	Skew        time.Duration
	MaxLifetime time.Duration
}

type tokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// Claims are a session token's claims.
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  audience `json:"aud"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	ID        string   `json:"jti"`
	Actor     struct {
		Atespace string `json:"atespace"`
		Name     string `json:"actorName"`
		UID      string `json:"actorUID"`
	} `json:"dc.actor"`
	// TaskDigest is the registered task's digest (dc.task_sha256).
	TaskDigest string `json:"dc.task_sha256"`
}

// Verify implements Verifier.
func (v *KeyVerifier) Verify(_ context.Context, r *http.Request) (Session, error) {
	tok := TokenFrom(r)
	if tok == "" {
		return Session{}, ErrNoToken
	}
	return v.VerifyToken(tok)
}

func b64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

// VerifyToken checks one token.
func (v *KeyVerifier) VerifyToken(tok string) (Session, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || len(tok) > 8192 {
		return Session{}, errors.New("session token is not a compact JWS")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return Session{}, errors.New("session token header is not base64url")
	}
	var h tokenHeader
	if err := json.Unmarshal(hb, &h); err != nil {
		return Session{}, errors.New("session token header is not JSON")
	}
	if h.Typ != TokenType {
		return Session{}, fmt.Errorf("session token typ %q is not %s", h.Typ, TokenType)
	}
	key, ok := v.Keys[h.Kid]
	if !ok {
		return Session{}, fmt.Errorf("session token key %q is unknown", h.Kid)
	}
	sig, err := b64(parts[2])
	if err != nil {
		return Session{}, errors.New("session token signature is not base64url")
	}
	signed := []byte(parts[0] + "." + parts[1])
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		if h.Alg != "ES256" || len(sig) != 64 {
			return Session{}, errors.New("session token alg does not match its key")
		}
		d := sha256.Sum256(signed)
		rr, ss := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(k, d[:], rr, ss) {
			return Session{}, errors.New("session token signature is invalid")
		}
	case ed25519.PublicKey:
		if h.Alg != "EdDSA" || !ed25519.Verify(k, signed, sig) {
			return Session{}, errors.New("session token signature is invalid")
		}
	default:
		return Session{}, errors.New("session token key type is not supported")
	}
	cb, err := b64(parts[1])
	if err != nil {
		return Session{}, errors.New("session token claims are not base64url")
	}
	var c Claims
	dec := json.NewDecoder(bytes.NewReader(cb))
	if err := dec.Decode(&c); err != nil {
		return Session{}, errors.New("session token claims are not JSON")
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	skew := v.Skew
	if skew == 0 {
		skew = 60 * time.Second
	}
	maxLife := v.MaxLifetime
	if maxLife == 0 {
		maxLife = time.Hour
	}
	t := now()
	exp, nbf, iat := time.Unix(c.Expiry, 0), time.Unix(c.NotBefore, 0), time.Unix(c.IssuedAt, 0)
	switch {
	case c.Expiry == 0 || t.After(exp.Add(skew)):
		return Session{}, errors.New("session token expired")
	case c.NotBefore != 0 && t.Add(skew).Before(nbf):
		return Session{}, errors.New("session token not valid yet")
	case c.IssuedAt == 0 || exp.Sub(iat) > maxLife:
		return Session{}, errors.New("session token lifetime too long")
	case v.Issuer == "" || c.Issuer != v.Issuer:
		return Session{}, errors.New("session token issuer is not accepted")
	}
	audOK := false
	for _, a := range c.Audience {
		audOK = audOK || a == v.Audience
	}
	if !audOK {
		return Session{}, errors.New("session token audience is not this relay")
	}
	sub := strings.TrimSpace(c.Subject)
	if sub == "" || strings.HasPrefix(sub, "actor/") || strings.HasPrefix(sub, "worker-for-actor/") {
		// A session token names a person; an actor or worker identity is
		// never one.
		return Session{}, errors.New("session token subject is not a person")
	}
	if c.Actor.Atespace == "" || c.Actor.Name == "" || c.Actor.UID == "" {
		return Session{}, errors.New("session token names no actor")
	}
	if v.Self == nil {
		return Session{}, errors.New("relay does not know its own actor identity")
	}
	self, err := v.Self()
	if err != nil {
		return Session{}, err
	}
	if self.Atespace != c.Actor.Atespace || self.Name != c.Actor.Name || self.UID != c.Actor.UID {
		return Session{}, errors.New("session token is for another actor")
	}
	return Session{Person: sub, Actor: c.Actor.Atespace + "/" + c.Actor.Name, ActorUID: c.Actor.UID, TokenID: c.ID, Expires: exp,
		TaskDigest: c.TaskDigest}, nil
}

// LoadPublicKey reads a PEM public key (PKIX: P-256 ECDSA or Ed25519).
func LoadPublicKey(path string) (crypto.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch kk := k.(type) {
	case *ecdsa.PublicKey:
		if kk.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("%s: ECDSA key is not P-256", path)
		}
	case ed25519.PublicKey:
	default:
		return nil, fmt.Errorf("%s: key type is not supported", path)
	}
	return k, nil
}

// GatewayVerifier asks the gateway whether a token is bound to this actor
// and its person. The relay posts through Substrate egress with the
// x-defenseclaw-actor placeholder, so the gateway learns the calling actor
// from its verified JWT, not from anything the relay says. The gateway
// route is A2's: POST /api/v1/substrate/relay/verify {"token": ...} ->
// 200 Session (with task_digest from the registration for a --task actor),
// any other status refuses.
type GatewayVerifier struct {
	URL    string
	Client *http.Client
}

// Verify implements Verifier.
func (g *GatewayVerifier) Verify(ctx context.Context, r *http.Request) (Session, error) {
	tok := TokenFrom(r)
	if tok == "" {
		return Session{}, ErrNoToken
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.URL, bytes.NewReader(body))
	if err != nil {
		return Session{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(kit.PlaceholderHeader, kit.PlaceholderValue)
	req.Header.Set("X-DefenseClaw-Client", "actor-relay/"+kit.Version)
	resp, err := g.Client.Do(req)
	if err != nil {
		return Session{}, fmt.Errorf("session token check: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return Session{}, fmt.Errorf("session token refused by the gateway (status %d)", resp.StatusCode)
	}
	var s Session
	if err := json.Unmarshal(raw, &s); err != nil || s.Person == "" {
		return Session{}, errors.New("session token check: bad gateway answer")
	}
	return s, nil
}
