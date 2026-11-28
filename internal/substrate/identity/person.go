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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Person kinds.
const (
	PersonHuman    = "person"
	PersonWorkload = "workload"
)

// MaxPersonTokenLifetime bounds an accepted person token (ID tokens and
// device-flow access tokens are minutes to an hour; a day covers slow
// issuers without accepting long-lived credentials).
const MaxPersonTokenLifetime = 24 * time.Hour

// MaxPersonSignInAge is how long after it was issued (iat) the admin
// listener accepts a person's sign-in token, whatever its exp says
// (GAP-0409): the gateway cannot revoke a sign-in, so after `defenseclaw
// substrate logout` a copied token works for at most this long, not for
// an issuer's 60 to 90 minute access-token lifetime. The launcher refreshes
// its stored token before it is this old. Workload (CI) tokens keep their
// own exp.
const MaxPersonSignInAge = 15 * time.Minute

// Person is a verified admin-listener caller: a person signed in with the
// configured OIDC issuer (the launcher's device flow), or a CI workload
// (workload_oidc).
type Person struct {
	Kind    string
	Issuer  string
	Subject string
	// Principal is the cross-device join key (email, UPN or preferred
	// username), "" when the token carries none. An email the issuer marks
	// unverified (email_verified false) is never the principal.
	Principal string
	// EmailUnverified is set when the token carried an email the issuer
	// marked unverified (email_verified false): the sign-in is lower
	// assurance, and policy explain and the audit rows say so (GAP-0640).
	EmailUnverified bool
	Groups          []string
	// Expires is when the admin listener stops accepting the token: its
	// exp, or for a person sign-in iat plus MaxPersonSignInAge when that
	// comes first. For a Kubernetes caller it is when the gateway asks the
	// API server again (the review cache), not the end of the token: that
	// is TokenExpires.
	Expires time.Time
	// IssuedAt is the token's iat, TokenID its jti ("" when it has none)
	// and TokenKey the deny-list key of this one token (TokenKey). They
	// say which sign-in a request came with, for revocation (B5.1); they
	// are never stored with a registration.
	IssuedAt time.Time `json:"-"`
	TokenID  string    `json:"-"`
	TokenKey string    `json:"-"`
	// TokenExpires is a Kubernetes caller's own token exp, zero for a
	// token that carries none (a static or provider token). Only the
	// Kubernetes verifier sets it (GAP-0588).
	TokenExpires time.Time
}

// SessionBound is the latest a token the gateway derives from this
// caller's bearer (a relay session token) may live: the end of the bearer
// itself. For a person sign-in that is also the sign-in age bound of
// GAP-0409, so a session token never outlives a logout by more than
// MaxPersonSignInAge. Zero means the end is unknown (an opaque Kubernetes
// token): the derived token keeps its own cap (GAP-0588).
func (p Person) SessionBound() time.Time {
	if p.Kind == PersonKube {
		// Expires is the review cache here; never cap a session at the
		// cache time.
		return p.TokenExpires
	}
	return p.Expires
}

// TokenKey is the revocation key of one person token, token as it was
// presented. A deny list holds only this, never a token or a raw id:
//   - "jti:" a hash of the issuer and the token's jti;
//   - "clm:" a token with no jti that is a JWT: a hash of the issuer and
//     its decoded claims. These are the signed bytes, the same for every
//     encoding of one signed token a verifier accepts (spare base64 bits,
//     '=' padding, line breaks, an ES256 (r, n-s) signature), so a copy
//     that is re-encoded is still the token that was ended (RV2-01,
//     GAP-0759);
//   - "tok:" a hash of the whole token, only for an opaque token (a static
//     Kubernetes token), which its server compares as it is.
//
// The "clm:" prefix is new in the build that keys by claims, so a raw-text
// key an earlier build of the same release wrote can never be read as one;
// no released version wrote a deny list before it.
func TokenKey(issuer, jti, token string) string {
	if jti != "" {
		return claimsTokenKey(issuer, jti, nil)
	}
	if claims, ok := jwtClaims(token); ok {
		return claimsTokenKey(issuer, "", claims)
	}
	s := sha256.Sum256([]byte(token))
	return "tok:" + hex.EncodeToString(s[:16])
}

// claimsTokenKey is the key of a JWT: "jti:" when it has a jti, else
// "clm:" over claims. The OIDC verifier passes the claims bytes it
// verified, so the key never depends on how the token text is re-read
// (RV3-02, GAP-0789).
func claimsTokenKey(issuer, jti string, claims []byte) string {
	if jti != "" {
		s := sha256.Sum256([]byte(issuer + "\x00" + jti))
		return "jti:" + hex.EncodeToString(s[:16])
	}
	s := sha256.Sum256([]byte(issuer + "\x00" + string(claims)))
	return "clm:" + hex.EncodeToString(s[:16])
}

// jwtClaims is the decoded claims of a token shaped like a compact JWS, ok
// false when it is not one. It decodes at least as leniently as any
// verifier in front of DefenseClaw (go-jose, which the kube-apiserver
// uses, trims '=', ignores spare bits and strips every Unicode white-space
// rune; this also drops '=' anywhere and reads the standard alphabet), so
// every encoding such a verifier accepts gives the same bytes (RV4-02). It checks no signature: callers
// key only a token a verifier or a TokenReview has already accepted, or
// read only its issuer (tokenIssuer).
func jwtClaims(token string) ([]byte, bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		return nil, false
	}
	part := strings.Map(func(r rune) rune {
		switch {
		case r == '=' || unicode.IsSpace(r):
			return -1
		case r == '+':
			return '-'
		case r == '/':
			return '_'
		}
		return r
	}, parts[1])
	b, err := base64.RawURLEncoding.DecodeString(part)
	// JSON white space may come before the object (RV3-02, GAP-0789).
	if t := bytes.TrimLeft(b, " \t\r\n"); err != nil || len(t) == 0 || t[0] != '{' || !json.Valid(b) {
		return nil, false
	}
	return b, true
}

// tokenIssuer is the iss a token shaped like a compact JWS names, decoded
// leniently (jwtClaims), "" when it names none. It checks no signature: it
// only says which verifier a token belongs to (RV3-01, GAP-0787).
func tokenIssuer(token string) string {
	b, ok := jwtClaims(token)
	if !ok {
		return ""
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if json.Unmarshal(b, &c) != nil {
		return ""
	}
	return c.Issuer
}

// ID is the stable owner key of a person: issuer and subject.
func (p Person) ID() string { return p.Issuer + "#" + p.Subject }

// PersonIssuer is one trusted OIDC issuer of person or workload tokens.
type PersonIssuer struct {
	KeySet *KeySet
	// Audience the token must carry (aud) or name as azp: the launcher's
	// client_id, or the workload audience.
	Audience string
	// GroupsClaim is the claim holding group names or IDs ("groups").
	GroupsClaim string
	// Kind is PersonHuman or PersonWorkload.
	Kind string
	// APIAudience, when set, is DefenseClaw's own audience
	// (substrate.identity.audience): an access token whose aud names it and
	// whose azp is the client (Audience) is accepted too, the shape a
	// Keycloak device-flow token with an audience mapper has.
	APIAudience string
	// Binding is what a workload token must also carry (Kind
	// PersonWorkload); a workload issuer without one is refused.
	Binding WorkloadBinding
}

// WorkloadBinding names the workloads of an issuer DefenseClaw trusts.
type WorkloadBinding struct {
	// Subject is the token subject, exact, or a prefix when it ends in
	// ":*" or "/*" (for example "repo:acme/web:*"): the wildcard matches
	// whole segments only, so "repo:acme/web*" (which trusted
	// repo:acme/web-evil), a bare "*" and a wildcard right after the first
	// segment ("repo:*", every repository) are refused (GAP-0043).
	Subject string
	// Claims are top-level string claims the token must carry exactly
	// (for example repository: acme/web).
	Claims map[string]string
}

// WorkloadSubjectPattern is the subject rule (GAP-0043): exact, or a
// prefix ending in ":*" or "/*" that already holds a separator before the
// last one, so a wildcard cannot sit right after the issuer's first segment:
// repo:acme/* and repo:acme/web:* pass, repo:* and project_path:* are
// refused (they trust every workload of a CI issuer, as a bare * does).
var WorkloadSubjectPattern = regexp.MustCompile(`^(?:[^*]+|[^*]*[:/][^*]+[:/]\*)$`)

// Empty reports a binding that names nothing, or names its subject in a
// form that is refused (a raw prefix, a bare "*"): such a binding trusts
// no workload.
func (b WorkloadBinding) Empty() bool {
	sub := strings.TrimSpace(b.Subject)
	if sub != "" && !WorkloadSubjectPattern.MatchString(sub) {
		return true
	}
	return sub == "" && len(b.Claims) == 0
}

func (b WorkloadBinding) matches(sub string, raw map[string]json.RawMessage) bool {
	if b.Empty() {
		return false
	}
	if want := strings.TrimSpace(b.Subject); want != "" {
		if prefix, ok := strings.CutSuffix(want, "*"); ok {
			// prefix ends in ':' or '/', so the match stops on a boundary.
			if !strings.HasPrefix(sub, prefix) {
				return false
			}
		} else if sub != want {
			return false
		}
	}
	for k, want := range b.Claims {
		var got string
		v, ok := raw[k]
		if !ok || json.Unmarshal(v, &got) != nil || got != want {
			return false
		}
	}
	return true
}

// audienceOK is the audience rule (GAP-0059): aud names the client or
// workload audience, or aud names DefenseClaw's API audience and azp is the
// client. azp alone, with aud naming another API, is refused.
func (is PersonIssuer) audienceOK(aud audience, azp string) bool {
	if aud.contains(is.Audience) {
		return azp == "" || azp == is.Audience || is.Kind == PersonWorkload
	}
	return is.APIAudience != "" && aud.contains(is.APIAudience) && azp == is.Audience
}

// PersonVerifier verifies person tokens against a list of issuers.
type PersonVerifier struct {
	issuers map[string][]PersonIssuer
	skew    time.Duration
	now     func() time.Time
}

// NewPersonVerifier validates the issuers. Several workload entries may
// share an issuer (one per trusted workload); a person issuer is listed
// once, and a workload entry needs a binding.
func NewPersonVerifier(issuers []PersonIssuer, now func() time.Time) (*PersonVerifier, error) {
	if len(issuers) == 0 {
		return nil, errors.New("identity: no person issuer is configured")
	}
	v := &PersonVerifier{issuers: map[string][]PersonIssuer{}, skew: DefaultSkew, now: now}
	if v.now == nil {
		v.now = time.Now
	}
	for _, is := range issuers {
		if is.KeySet == nil || strings.TrimSpace(is.Audience) == "" {
			return nil, errors.New("identity: a person issuer needs its key set and audience")
		}
		if is.Kind == "" {
			is.Kind = PersonHuman
		}
		if is.GroupsClaim == "" {
			is.GroupsClaim = "groups"
		}
		if is.Kind == PersonWorkload && is.Binding.Empty() {
			return nil, errors.New("identity: a workload issuer needs a subject or claims binding")
		}
		iss := is.KeySet.Issuer()
		for _, old := range v.issuers[iss] {
			if old.Kind == PersonHuman && is.Kind == PersonHuman {
				return nil, errors.New("identity: person issuer listed twice")
			}
		}
		v.issuers[iss] = append(v.issuers[iss], is)
	}
	return v, nil
}

// Verify checks a bearer token from a person or workload.
func (v *PersonVerifier) Verify(ctx context.Context, token string) (Person, error) {
	t, err := parseJWS(token)
	if err != nil {
		return Person{}, err
	}
	if strings.EqualFold(t.header.Typ, SessionTokenType) {
		return Person{}, reasonf(ReasonType, "a relay session token is not a sign-in")
	}
	// The issuer is read before the signature check only to pick its key
	// set; every claim is checked again after verification.
	var peek struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(t.claims, &peek); err != nil {
		return Person{}, reasonf(ReasonMalformed, "token claims are not a JSON object")
	}
	cands, ok := v.issuers[peek.Issuer]
	if !ok || len(cands) == 0 {
		return Person{}, reasonf(ReasonIssuer, "token issuer is not trusted")
	}
	if err := cands[0].KeySet.verify(ctx, t); err != nil {
		return Person{}, err
	}
	var raw map[string]json.RawMessage
	if err := strictJSON(t.claims, &raw); err != nil {
		return Person{}, reasonf(ReasonMalformed, "token claims are not a JSON object")
	}
	var c struct {
		Issuer    string   `json:"iss"`
		Subject   string   `json:"sub"`
		Audience  audience `json:"aud"`
		AZP       string   `json:"azp"`
		Expiry    *int64   `json:"exp"`
		NotBefore *int64   `json:"nbf"`
		IssuedAt  *int64   `json:"iat"`
		TokenID   string   `json:"jti"`
		Email     string   `json:"email"`
		UPN       string   `json:"upn"`
		Preferred string   `json:"preferred_username"`
	}
	if err := json.Unmarshal(t.claims, &c); err != nil {
		return Person{}, reasonf(ReasonMalformed, "token claims have the wrong types")
	}
	if c.Issuer != cands[0].KeySet.Issuer() {
		return Person{}, reasonf(ReasonIssuer, "token issuer is not trusted")
	}
	// The first entry whose audience and workload binding the token meets
	// decides its kind (GAP-0043: a CI issuer such as GitHub Actions signs
	// tokens for every repository, so issuer and audience alone trust any
	// workflow that picks the audience).
	var is PersonIssuer
	matched, audOK := false, false
	for _, cand := range cands {
		if !cand.audienceOK(c.Audience, c.AZP) {
			continue
		}
		audOK = true
		if cand.Kind == PersonWorkload && !cand.Binding.matches(c.Subject, raw) {
			continue
		}
		is, matched = cand, true
		break
	}
	switch {
	case !audOK:
		return Person{}, reasonf(ReasonAudience, "token is not for DefenseClaw")
	case !matched:
		return Person{}, reasonf(ReasonSubject, "token is from a workload this install does not trust")
	}
	now := v.now()
	if err := checkTimes(now, v.skew, c.Expiry, c.NotBefore, c.IssuedAt, MaxPersonTokenLifetime); err != nil {
		return Person{}, err
	}
	expires := time.Unix(*c.Expiry, 0)
	if is.Kind == PersonHuman {
		// checkTimes has refused a token without iat.
		limit := time.Unix(*c.IssuedAt, 0).Add(MaxPersonSignInAge)
		// The sign-in age ends like exp: at the limit, with no skew
		// grace (GAP-0569).
		if !now.Before(limit) {
			return Person{}, reasonf(ReasonExpired, "sign-in is older than %d minutes; sign in again", int(MaxPersonSignInAge/time.Minute))
		}
		if limit.Before(expires) {
			expires = limit
		}
	}
	sub := strings.TrimSpace(c.Subject)
	if sub == "" || len(sub) > 255 || strings.HasPrefix(sub, ActorSubjectPrefix) || strings.HasPrefix(sub, WorkerSubjectPrefix) {
		return Person{}, reasonf(ReasonSubject, "token subject is not a person")
	}
	p := Person{Kind: is.Kind, Issuer: c.Issuer, Subject: sub, Expires: expires,
		IssuedAt: time.Unix(*c.IssuedAt, 0), TokenID: c.TokenID, TokenKey: claimsTokenKey(c.Issuer, c.TokenID, t.claims)}
	email := c.Email
	if emailUnverified(raw["email_verified"]) {
		// The issuer says it has not checked the address (a local user
		// typed it in): it is not a join key a profile or an audit row may
		// trust, so the UPN or user name stands in (GAP-0390).
		p.EmailUnverified = strings.TrimSpace(email) != ""
		email = ""
	}
	for _, cand := range []string{email, c.UPN, c.Preferred} {
		if cand = strings.TrimSpace(cand); cand != "" && len(cand) <= 320 {
			p.Principal = cand
			break
		}
	}
	if g, ok := raw[is.GroupsClaim]; ok {
		var groups []string
		if json.Unmarshal(g, &groups) == nil {
			for _, name := range groups {
				if name = strings.TrimSpace(name); name != "" && len(name) <= 256 && len(p.Groups) < 512 {
					p.Groups = append(p.Groups, name)
				}
			}
		}
	}
	return p, nil
}

// emailUnverified reports an email_verified claim that says no: false, or
// "false" from issuers that send the claim as a string. An absent claim is
// not a no (Entra ID and many CI issuers never send it).
func emailUnverified(v json.RawMessage) bool {
	var b bool
	if json.Unmarshal(v, &b) == nil {
		return !b
	}
	var str string
	return json.Unmarshal(v, &str) == nil && strings.EqualFold(strings.TrimSpace(str), "false")
}

// Trusts reports whether issuer is a configured person or workload issuer.
func (v *PersonVerifier) Trusts(issuer string) bool {
	return v != nil && len(v.issuers[issuer]) > 0
}

// SignInKeySet is the key set of the first person issuer (the OIDC issuer
// people sign in with), nil when there is none: workload issuers are not a
// sign-in server (GAP-0262).
func (v *PersonVerifier) SignInKeySet() *KeySet {
	if v == nil {
		return nil
	}
	for _, list := range v.issuers {
		for _, i := range list {
			if i.Kind == PersonHuman && i.KeySet != nil {
				return i.KeySet
			}
		}
	}
	return nil
}
