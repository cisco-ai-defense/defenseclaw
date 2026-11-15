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

package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// refreshSkew: a token that expires within this window is refreshed.
const refreshSkew = 60 * time.Second

// Token is one sign-in. Issuer, Subject, Principal and Groups are read
// from the JWT payload WITHOUT verification, for display only; the admin
// listener verifies the token.
type Token struct {
	AccessToken  string    `json:"access_token,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
	Kind         string    `json:"kind"`
	Issuer       string    `json:"issuer,omitempty"`
	Subject      string    `json:"subject,omitempty"`
	Principal    string    `json:"principal,omitempty"`
	Groups       []string  `json:"groups,omitempty"`
}

// String never shows a token value (it also covers %v and %+v).
func (t Token) String() string {
	return fmt.Sprintf("Token{kind=%s principal=%q issuer=%q expiry=%s access=%t id=%t refresh=%t}",
		t.Kind, t.Principal, t.Issuer, t.Expiry.UTC().Format(time.RFC3339),
		t.AccessToken != "", t.IDToken != "", t.RefreshToken != "")
}

// GoString keeps %#v free of token values too.
func (t Token) GoString() string { return t.String() }

// pick returns the bearer: the ID token when present and valid for more
// than refreshSkew, else the access token. ok is false when neither is.
func (t *Token) pick(now time.Time) (string, bool) {
	if t.IDToken != "" {
		exp := jwtExpiry(t.IDToken)
		if exp.IsZero() {
			exp = t.Expiry
		}
		if !exp.IsZero() && exp.After(now.Add(refreshSkew)) {
			return t.IDToken, true
		}
	}
	if t.AccessToken != "" {
		exp := t.Expiry
		if exp.IsZero() {
			exp = jwtExpiry(t.AccessToken)
		}
		// An opaque access token with no stated expiry is taken as valid.
		if exp.IsZero() || exp.After(now.Add(refreshSkew)) {
			return t.AccessToken, true
		}
	}
	return "", false
}

// stale reports whether the preferred token (ID, else access) is gone or
// within refreshSkew of expiry, so a refresh is due.
func (t *Token) stale(now time.Time) bool {
	if t.IDToken != "" {
		exp := jwtExpiry(t.IDToken)
		if exp.IsZero() {
			exp = t.Expiry
		}
		return exp.IsZero() || !exp.After(now.Add(refreshSkew))
	}
	_, ok := t.pick(now)
	return !ok
}

// flexInt accepts a JSON number or a numeric string.
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("not a number")
	}
	*f = flexInt(v)
	return nil
}

// tokenResponse is an RFC 6749 token response.
type tokenResponse struct {
	AccessToken  string  `json:"access_token"`
	IDToken      string  `json:"id_token"`
	RefreshToken string  `json:"refresh_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    flexInt `json:"expires_in"`
}

// toToken builds a person Token; prev supplies the refresh token a
// refresh response may leave out. An old ID token is not carried over:
// without a new one the access token is the bearer.
func (r tokenResponse) toToken(now time.Time, prev *Token) *Token {
	t := &Token{AccessToken: r.AccessToken, IDToken: r.IDToken, RefreshToken: r.RefreshToken, Kind: KindPerson}
	if prev != nil && t.RefreshToken == "" {
		t.RefreshToken = prev.RefreshToken
	}
	if r.ExpiresIn > 0 {
		t.Expiry = now.Add(time.Duration(r.ExpiresIn) * time.Second)
	} else {
		t.Expiry = jwtExpiry(t.AccessToken)
	}
	t.fillClaims()
	return t
}

// claims is the unverified JWT payload we display or check before
// sending a workload token.
type claims struct {
	Iss               string          `json:"iss"`
	Sub               string          `json:"sub"`
	Aud               json.RawMessage `json:"aud"`
	PreferredUsername string          `json:"preferred_username"`
	Email             string          `json:"email"`
	Exp               any             `json:"exp"`
	Groups            json.RawMessage `json:"groups"`
}

// decodeClaims reads a JWT payload without verifying it. Failures give
// zero claims.
func decodeClaims(jwt string) claims {
	c, _ := parseClaims(jwt)
	return c
}

// parseClaims reads a JWT payload without verifying it; ok is false when
// there is no payload or it is not base64url-encoded JSON.
func parseClaims(jwt string) (claims, bool) {
	var c claims
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return c, false
	}
	p := strings.TrimRight(parts[1], "=")
	raw, err := base64.RawURLEncoding.DecodeString(p)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(p); err != nil {
			return c, false
		}
	}
	if json.Unmarshal(raw, &c) != nil {
		return claims{}, false
	}
	return c, true
}

func (c claims) expiry() time.Time {
	var sec float64
	switch v := c.Exp.(type) {
	case float64:
		sec = v
	case string:
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return time.Time{}
		}
		sec = f
	default:
		return time.Time{}
	}
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(sec), 0)
}

// stringOrList reads a claim that is a string or a list of strings.
func stringOrList(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return list
	}
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}
	}
	return nil
}

func (c claims) groups() []string { return stringOrList(c.Groups) }

// audiences is the aud claim (RFC 7519: a string or a list of strings),
// without empty entries.
func (c claims) audiences() []string {
	var out []string
	for _, a := range stringOrList(c.Aud) {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func (c claims) principal() string {
	for _, v := range []string{c.PreferredUsername, c.Email, c.Sub} {
		if v != "" {
			return v
		}
	}
	return ""
}

func jwtExpiry(jwt string) time.Time { return decodeClaims(jwt).expiry() }

// fillClaims sets Issuer, Subject, Principal and Groups from the ID token,
// then from the access token for whatever is still empty.
func (t *Token) fillClaims() {
	t.Issuer, t.Subject, t.Principal, t.Groups = "", "", "", nil
	for _, raw := range []string{t.IDToken, t.AccessToken} {
		if raw == "" {
			continue
		}
		c := decodeClaims(raw)
		if t.Issuer == "" {
			t.Issuer = c.Iss
		}
		if t.Subject == "" {
			t.Subject = c.Sub
		}
		if t.Principal == "" {
			t.Principal = c.principal()
		}
		if t.Groups == nil {
			t.Groups = c.groups()
		}
	}
}
