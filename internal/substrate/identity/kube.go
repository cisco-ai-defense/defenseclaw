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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PersonKube is a person known by their Kubernetes credentials: an open
// source cluster without an OIDC provider (STEER 11-12 22:55Z). The
// launcher sends the bearer token of the user's kubeconfig; the gateway
// asks the API server who it is (TokenReview), and the person is that
// Kubernetes user (id_kind k8s_user). Managed installs require OIDC.
const PersonKube = "k8s_user"

// KubeTokenAudience is the audience of the ServiceAccount token the
// launcher mints with TokenRequest for a person whose kubeconfig signs in
// with a client certificate (GAP-0192). The gateway accepts a
// ServiceAccount only when the API server authenticates its token for this
// audience: a pod's mounted token (the API server's audience) is refused.
const KubeTokenAudience = "defenseclaw-substrate"

// KubeIssuer is the Issuer of a Kubernetes person: the cluster's API
// server, the one authority for the name.
const KubeIssuer = "kubernetes"

const (
	kubeReviewTTL     = 30 * time.Second
	kubeReviewMaxKeys = 4096
)

// KubeTokenVerifier verifies a person's Kubernetes bearer token with a
// TokenReview (the gateway's ServiceAccount needs create on
// tokenreviews, the system:auth-delegator role).
type KubeTokenVerifier struct {
	// Server is https://<API server>; TokenFile the gateway's own token.
	Server    string
	TokenFile string
	HTTP      *http.Client
	Now       func() time.Time

	mu    sync.Mutex
	cache map[string]kubeReview
}

type kubeReview struct {
	p Person
	// until is when the answer stops serving: the review time plus
	// kubeReviewTTL, or the token's exp when that comes first (GAP-0569).
	until time.Time
}

func (k *KubeTokenVerifier) now() time.Time {
	if k.Now != nil {
		return k.Now()
	}
	return time.Now()
}

// Verify implements the admin listener's person check.
func (k *KubeTokenVerifier) Verify(ctx context.Context, token string) (Person, error) {
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 16<<10 {
		return Person{}, reasonf(ReasonMissing, "no Kubernetes token")
	}
	sum := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(sum[:])
	now := k.now()
	// A JWT (a ServiceAccount token, or an OIDC token in a kubeconfig) is
	// refused from the second it expires, without a review: the API server
	// allows its own leeway past exp (GAP-0569). A JWT whose exp cannot be
	// read is refused too, so no exp form skips the check (GAP-0587).
	exp, isJWT, hasExp := kubeTokenExpiry(token)
	if isJWT && !hasExp {
		return Person{}, reasonf(ReasonClaims, "the Kubernetes token has no readable exp")
	}
	if hasExp && !now.Before(exp) {
		return Person{}, reasonf(ReasonExpired, "the Kubernetes token expired")
	}
	k.mu.Lock()
	if c, ok := k.cache[key]; ok && now.Before(c.until) {
		k.mu.Unlock()
		return c.p, nil
	}
	k.mu.Unlock()
	u, ok, err := k.review(ctx, token, nil)
	if err != nil {
		return Person{}, err
	}
	switch {
	case !ok:
		// Not a token of the API server's own audience: it counts only as a
		// ServiceAccount token minted for DefenseClaw (GAP-0192).
		u, ok, err = k.review(ctx, token, []string{KubeTokenAudience})
		if err != nil {
			return Person{}, err
		}
		if !ok {
			return Person{}, reasonf(ReasonSignature, "the Kubernetes API does not know the token")
		}
		if !strings.HasPrefix(u.Username, "system:serviceaccount:") {
			return Person{}, reasonf(ReasonSubject, "only a ServiceAccount token may carry the DefenseClaw audience")
		}
	case strings.HasPrefix(u.Username, "system:serviceaccount:"):
		// A pod's own token: the ServiceAccount of a workload is not a
		// person, and an actor has no Kubernetes identity (D15).
		return Person{}, reasonf(ReasonSubject, "a ServiceAccount token must be minted for DefenseClaw (audience %s); sign in with defenseclaw substrate login --kube", KubeTokenAudience)
	}
	if strings.HasPrefix(u.Username, "system:node:") {
		return Person{}, reasonf(ReasonSubject, "a node token is not a person")
	}
	until := now.Add(kubeReviewTTL)
	if hasExp && exp.Before(until) {
		until = exp
	}
	// The token key and issue time let logout, logout --all and admin
	// revoke end a Kubernetes sign-in like an OIDC one (RV1-01). A JWT is
	// keyed by its jti, else by its claims, never by its text: the API
	// server accepts other encodings of the same token (RV2-01).
	iat, jti := kubeClaims(token, now)
	p := Person{Kind: PersonKube, Issuer: KubeIssuer, Subject: u.Username, Principal: u.Username,
		Expires: until, IssuedAt: iat, TokenID: jti, TokenKey: TokenKey(KubeIssuer, jti, token)}
	if hasExp {
		p.TokenExpires = exp
	}
	for _, g := range u.Groups {
		if g = strings.TrimSpace(g); g != "" && len(p.Groups) < 512 {
			p.Groups = append(p.Groups, g)
		}
	}
	k.mu.Lock()
	if k.cache == nil || len(k.cache) >= kubeReviewMaxKeys {
		k.cache = map[string]kubeReview{}
	}
	k.cache[key] = kubeReview{p: p, until: until}
	k.mu.Unlock()
	return p, nil
}

// kubeTokenExpiry reads the exp claim of a bearer token that is a JWT,
// without verifying it: the TokenReview authenticates the token, and exp
// only shortens how long the answer is used, never lengthens it
// (GAP-0569). The claims are decoded with jwtClaims, the decoder of the
// token key and issue time, which reads every encoding the API server's
// go-jose accepts ('=' padding, spare bits, Unicode white space, the
// standard alphabet), so a re-encoded copy of a JWT is never taken for an
// opaque token that skips the exp rule (GAP-1032). isJWT is false for a
// token whose middle part is not a base64 JSON object (a static or
// provider token): it has no exp to read. For a JWT, ok is false when exp
// is missing, is not a finite JSON number (RFC 7519 NumericDate: an
// integer or a decimal such as 1799999990.0 or 1.79999999e9), or the
// claims repeat a member; the caller refuses it (GAP-0587).
func kubeTokenExpiry(token string) (exp time.Time, isJWT, ok bool) {
	cb, isJWT := jwtClaims(token)
	if !isJWT {
		return time.Time{}, false, false
	}
	var c map[string]json.RawMessage
	if err := json.Unmarshal(cb, &c); err != nil || c == nil || checkDuplicateKeys(cb) != nil {
		return time.Time{}, true, false
	}
	raw := bytes.TrimSpace(c["exp"])
	if len(raw) == 0 || (raw[0] != '-' && (raw[0] < '0' || raw[0] > '9')) {
		return time.Time{}, true, false // missing, null, a string, an object
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return time.Time{}, true, false
	}
	// Beyond 1e15 s (about 30 million years) either way only the side of
	// now matters; the bound keeps the int64 conversion defined.
	const far = 1e15
	f = max(min(f, far), -far)
	sec := math.Floor(f)
	return time.Unix(int64(sec), int64((f-sec)*1e9)), true, true
}

// kubeClaims reads the iat and jti of a Kubernetes token that is a JWT (a
// bound ServiceAccount token, or an OIDC token the API server accepts). It
// is called only after the TokenReview authenticated the whole token, so
// the claims are the issuer's. iat is zero when the token is opaque (a
// static token), has no iat (a legacy Secret-based ServiceAccount token),
// or names a time more than DefaultSkew ahead: such a sign-in can be ended
// one token at a time, not by time. jti is "" when the token has none.
func kubeClaims(token string, now time.Time) (time.Time, string) {
	raw, ok := jwtClaims(token)
	if !ok {
		return time.Time{}, ""
	}
	var c struct {
		IssuedAt *int64 `json:"iat"`
		TokenID  any    `json:"jti"`
	}
	if json.Unmarshal(raw, &c) != nil {
		return time.Time{}, ""
	}
	jti, _ := c.TokenID.(string)
	if c.IssuedAt == nil || *c.IssuedAt <= 0 {
		return time.Time{}, jti
	}
	iat := time.Unix(*c.IssuedAt, 0)
	if iat.After(now.Add(DefaultSkew)) {
		return time.Time{}, jti
	}
	return iat, jti
}

// kubeUser is the user of an authenticated TokenReview.
type kubeUser struct {
	Username string   `json:"username"`
	UID      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

// review asks the API server who token is, for audiences (nil: the API
// server's own). ok is false when the token is not authenticated for one of
// them; a ServiceAccount token reviewed for its own audience must also be
// answered with that audience.
func (k *KubeTokenVerifier) review(ctx context.Context, token string, audiences []string) (kubeUser, bool, error) {
	own, err := os.ReadFile(k.TokenFile)
	if err != nil {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "the gateway has no Kubernetes token")
	}
	spec := map[string]any{"token": token}
	if len(audiences) > 0 {
		spec["audiences"] = audiences
	}
	body, _ := json.Marshal(map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": spec})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.Server+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "token review request")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(own)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "the Kubernetes API did not answer")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "token review: HTTP %d", resp.StatusCode)
	}
	var tr struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			User          kubeUser `json:"user"`
			Audiences     []string `json:"audiences"`
		} `json:"status"`
	}
	if json.Unmarshal(raw, &tr) != nil {
		return kubeUser{}, false, reasonf(ReasonUnavailable, "token review answer is unreadable")
	}
	u := tr.Status.User
	if !tr.Status.Authenticated || strings.TrimSpace(u.Username) == "" {
		return kubeUser{}, false, nil
	}
	for _, want := range audiences {
		found := false
		for _, got := range tr.Status.Audiences {
			found = found || got == want
		}
		if !found {
			return kubeUser{}, false, nil
		}
	}
	return u, true, nil
}

// PersonVerifiers tries OIDC first and a Kubernetes token second: a token
// that is not from a configured issuer (a kubeconfig token, which may also
// be a JWT of the cluster's own issuer) goes to the TokenReview.
type PersonVerifiers struct {
	OIDC interface {
		Verify(ctx context.Context, token string) (Person, error)
		// Trusts reports a configured OIDC issuer.
		Trusts(issuer string) bool
	}
	Kube *KubeTokenVerifier
}

// Verify implements the admin listener's person check.
func (v PersonVerifiers) Verify(ctx context.Context, token string) (Person, error) {
	if v.OIDC != nil {
		p, err := v.OIDC.Verify(ctx, token)
		if err == nil || v.Kube == nil {
			return p, err
		}
		var ie *Error
		if !errors.As(err, &ie) || (ie.Reason != ReasonIssuer && ie.Reason != ReasonMalformed) {
			return p, err
		}
		// A token whose claims name a configured issuer is that issuer's,
		// however it is written. The strict parse refuses a copy with '='
		// padding, spare bits, line breaks or spaces; the API server
		// decodes leniently and could take the same copy as another person,
		// with another token key and under no end (RV3-01, GAP-0787).
		if iss := tokenIssuer(token); iss != "" && v.OIDC.Trusts(iss) {
			return p, err
		}
	}
	if v.Kube == nil {
		return Person{}, reasonf(ReasonIssuer, "no sign-in is configured")
	}
	return v.Kube.Verify(ctx, token)
}
