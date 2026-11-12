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
	"strings"
	"time"
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

// Person is a verified admin-listener caller: a person signed in with the
// configured OIDC issuer (the launcher's device flow), or a CI workload
// (workload_oidc).
type Person struct {
	Kind    string
	Issuer  string
	Subject string
	// Principal is the cross-device join key (email, UPN or preferred
	// username), "" when the token carries none.
	Principal string
	Groups    []string
	Expires   time.Time
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
}

// PersonVerifier verifies person tokens against a list of issuers.
type PersonVerifier struct {
	issuers map[string]PersonIssuer
	skew    time.Duration
	now     func() time.Time
}

// NewPersonVerifier validates the issuers. Two entries may not share an
// issuer.
func NewPersonVerifier(issuers []PersonIssuer, now func() time.Time) (*PersonVerifier, error) {
	if len(issuers) == 0 {
		return nil, errors.New("identity: no person issuer is configured")
	}
	v := &PersonVerifier{issuers: map[string]PersonIssuer{}, skew: DefaultSkew, now: now}
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
		if _, dup := v.issuers[is.KeySet.Issuer()]; dup {
			return nil, errors.New("identity: person issuer listed twice")
		}
		v.issuers[is.KeySet.Issuer()] = is
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
	is, ok := v.issuers[peek.Issuer]
	if !ok {
		return Person{}, reasonf(ReasonIssuer, "token issuer is not trusted")
	}
	if err := is.KeySet.verify(ctx, t); err != nil {
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
		Email     string   `json:"email"`
		UPN       string   `json:"upn"`
		Preferred string   `json:"preferred_username"`
	}
	if err := json.Unmarshal(t.claims, &c); err != nil {
		return Person{}, reasonf(ReasonMalformed, "token claims have the wrong types")
	}
	if c.Issuer != is.KeySet.Issuer() {
		return Person{}, reasonf(ReasonIssuer, "token issuer is not trusted")
	}
	if !c.Audience.contains(is.Audience) && c.AZP != is.Audience {
		return Person{}, reasonf(ReasonAudience, "token is not for DefenseClaw")
	}
	if err := checkTimes(v.now(), v.skew, c.Expiry, c.NotBefore, c.IssuedAt, MaxPersonTokenLifetime); err != nil {
		return Person{}, err
	}
	sub := strings.TrimSpace(c.Subject)
	if sub == "" || len(sub) > 255 || strings.HasPrefix(sub, ActorSubjectPrefix) || strings.HasPrefix(sub, WorkerSubjectPrefix) {
		return Person{}, reasonf(ReasonSubject, "token subject is not a person")
	}
	p := Person{Kind: is.Kind, Issuer: c.Issuer, Subject: sub, Expires: time.Unix(*c.Expiry, 0)}
	for _, cand := range []string{c.Email, c.UPN, c.Preferred} {
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
