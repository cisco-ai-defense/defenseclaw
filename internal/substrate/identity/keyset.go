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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Key-set fetch bounds. A discovery document or key set is a few KiB.
const (
	maxDocumentBytes = 256 << 10
	maxKeys          = 64
	// DefaultRefetchInterval is the least time between two key-set fetches
	// an unknown kid may cause (actor-jwts.md: rate-limit refetches so
	// invalid tokens cannot overload ate-idp-server).
	DefaultRefetchInterval = 10 * time.Second
	// DefaultKeyMaxAge is how long a fetched key set is used before the
	// next verification refreshes it. A key removed from the pool (a
	// compromised key) stops verifying within this time.
	DefaultKeyMaxAge = 5 * time.Minute
	// DefaultFetchTimeout bounds one discovery plus key-set fetch.
	DefaultFetchTimeout = 5 * time.Second
)

// KeySetOptions configures a key set read through OIDC discovery.
type KeySetOptions struct {
	// Issuer is the trusted issuer: https:// and a host, an optional port,
	// and an optional path for a person issuer (actor issuers have none).
	Issuer string
	// CAFile is a PEM trust bundle for the issuer (the projected
	// ClusterTrustBundle in cluster). Empty uses the system roots.
	CAFile string
	// HTTPClient replaces the client (tests). It must verify TLS itself.
	HTTPClient *http.Client
	// RefetchInterval and MaxAge default to DefaultRefetchInterval and
	// DefaultKeyMaxAge.
	RefetchInterval time.Duration
	MaxAge          time.Duration
	Now             func() time.Time
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type publicKey struct {
	key crypto.PublicKey
	alg string // the JWK alg, or "" when the JWK names none
}

// KeySet holds an issuer's verification keys, fetched through its OIDC
// discovery document. It is safe for concurrent use.
type KeySet struct {
	issuer   string
	client   *http.Client
	refetch  time.Duration
	maxAge   time.Duration
	now      func() time.Time
	fetchMu  sync.Mutex // one fetch at a time
	mu       sync.RWMutex
	keys     map[string]publicKey
	fetched  time.Time // last successful fetch
	tried    time.Time // last fetch attempt
	fetches  int
	lastErr  error
	jwksHost string
}

// NewKeySet validates opts and returns a key set that fetches lazily.
func NewKeySet(opts KeySetOptions) (*KeySet, error) {
	iss, err := validIssuer(opts.Issuer)
	if err != nil {
		return nil, err
	}
	client := opts.HTTPClient
	if client == nil {
		client, err = tlsClient(opts.CAFile)
		if err != nil {
			return nil, err
		}
	}
	ks := &KeySet{
		issuer: iss, client: client,
		refetch: opts.RefetchInterval, maxAge: opts.MaxAge, now: opts.Now,
	}
	if ks.refetch <= 0 {
		ks.refetch = DefaultRefetchInterval
	}
	if ks.maxAge <= 0 {
		ks.maxAge = DefaultKeyMaxAge
	}
	if ks.now == nil {
		ks.now = time.Now
	}
	return ks, nil
}

// validIssuer requires https, a host, and no query, fragment or user info.
func validIssuer(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		strings.HasSuffix(raw, "/") {
		return "", fmt.Errorf("identity: issuer %q must be https://host[:port][/path] with no trailing slash, query or fragment", raw)
	}
	return raw, nil
}

func tlsClient(caFile string) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("identity: read trust bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("identity: trust bundle holds no certificate")
		}
		cfg.RootCAs = pool
	}
	tr := &http.Transport{
		TLSClientConfig:     cfg,
		Proxy:               nil, // the issuer is reached directly, never through a proxy
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   DefaultFetchTimeout,
		// Discovery and the key set are fetched from fixed URLs; a redirect
		// could point the verifier at keys someone else controls.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// Issuer returns the trusted issuer.
func (ks *KeySet) Issuer() string { return ks.issuer }

// Fetches returns how many key-set fetches were attempted (tests, metrics).
func (ks *KeySet) Fetches() int {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.fetches
}

// key returns the key for kid. An unknown kid, or a key set older than
// MaxAge, causes at most one fetch per RefetchInterval; concurrent callers
// share it.
func (ks *KeySet) key(ctx context.Context, kid string) (publicKey, error) {
	if kid == "" {
		return publicKey{}, reasonf(ReasonMalformed, "token header has no kid")
	}
	ks.mu.RLock()
	k, ok := ks.keys[kid]
	fresh := !ks.fetched.IsZero() && ks.now().Sub(ks.fetched) < ks.maxAge
	ks.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	ferr := ks.refresh(ctx)
	ks.mu.RLock()
	k, ok = ks.keys[kid]
	haveKeys := ks.keys != nil
	ks.mu.RUnlock()
	if ok {
		// A failed refresh keeps the keys of the last good fetch: an
		// ate-idp-server outage must not stop tokens it already signed.
		return k, nil
	}
	if !haveKeys && ferr != nil {
		return publicKey{}, ferr
	}
	return publicKey{}, reasonf(ReasonUnknownKey, "kid is not in the issuer's key set")
}

// refresh fetches the key set unless a fetch ran within RefetchInterval.
func (ks *KeySet) refresh(ctx context.Context) error {
	ks.fetchMu.Lock()
	defer ks.fetchMu.Unlock()
	ks.mu.RLock()
	recent := !ks.tried.IsZero() && ks.now().Sub(ks.tried) < ks.refetch
	lastErr := ks.lastErr
	ks.mu.RUnlock()
	if recent {
		return lastErr
	}
	ks.mu.Lock()
	ks.tried = ks.now()
	ks.fetches++
	ks.mu.Unlock()
	keys, host, err := ks.fetch(ctx)
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if err != nil {
		ks.lastErr = reasonf(ReasonKeysetFailed, "%v", err)
		return ks.lastErr
	}
	ks.keys, ks.fetched, ks.lastErr, ks.jwksHost = keys, ks.now(), nil, host
	return nil
}

type discovery struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

func (ks *KeySet) fetch(ctx context.Context) (map[string]publicKey, string, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultFetchTimeout)
	defer cancel()
	var doc discovery
	if err := ks.getJSON(ctx, ks.issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, "", fmt.Errorf("discovery: %w", err)
	}
	if doc.Issuer != ks.issuer {
		return nil, "", errors.New("discovery: the document names another issuer")
	}
	ju, err := url.Parse(doc.JWKSURI)
	if err != nil || ju.Scheme != "https" || ju.Host == "" {
		return nil, "", errors.New("discovery: jwks_uri is not an https URL")
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := ks.getJSON(ctx, doc.JWKSURI, &set); err != nil {
		return nil, "", fmt.Errorf("key set: %w", err)
	}
	if len(set.Keys) == 0 || len(set.Keys) > maxKeys {
		return nil, "", fmt.Errorf("key set: %d keys", len(set.Keys))
	}
	keys := make(map[string]publicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kid == "" || (k.Use != "" && k.Use != "sig") {
			continue
		}
		pk, err := k.public()
		if err != nil {
			continue // a key type this verifier does not use; others still verify
		}
		keys[k.Kid] = publicKey{key: pk, alg: k.Alg}
	}
	if len(keys) == 0 {
		return nil, "", errors.New("key set: no usable signing key")
	}
	return keys, ju.Host, nil
}

func (ks *KeySet) getJSON(ctx context.Context, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := ks.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil {
		return err
	}
	if len(b) > maxDocumentBytes {
		return errors.New("document too large")
	}
	return json.Unmarshal(b, v)
}

func (k jwk) public() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		if k.Crv != "P-256" {
			return nil, errors.New("curve")
		}
		x, err1 := b64url(k.X)
		y, err2 := b64url(k.Y)
		if err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("coordinates")
		}
		pub, perr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{0x04}, x...), y...))
		if perr != nil {
			return nil, errors.New("point is not on the curve")
		}
		return pub, nil
	case "RSA":
		n, err1 := b64url(k.N)
		e, err2 := b64url(k.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("modulus or exponent")
		}
		exp := 0
		for _, c := range e {
			exp = exp<<8 | int(c)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
		if pub.N.BitLen() < 2048 || exp < 3 || exp%2 == 0 {
			return nil, errors.New("weak RSA key")
		}
		return pub, nil
	}
	return nil, errors.New("key type")
}

// verify checks the signature of t against the key its kid names.
func (ks *KeySet) verify(ctx context.Context, t parsedJWS) error {
	switch t.header.Alg {
	case "ES256", "RS256":
	default:
		return reasonf(ReasonAlgorithm, "alg %q is not accepted", t.header.Alg)
	}
	k, err := ks.key(ctx, t.header.Kid)
	if err != nil {
		return err
	}
	if k.alg != "" && k.alg != t.header.Alg {
		return reasonf(ReasonAlgorithm, "token alg does not match its key")
	}
	return verifySignature(t.header.Alg, k.key, t.signed, t.signature)
}
