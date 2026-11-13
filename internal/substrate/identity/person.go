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
	// repo:acme/web-evil) and a bare "*" are refused (GAP-0043).
	Subject string
	// Claims are top-level string claims the token must carry exactly
	// (for example repository: acme/web).
	Claims map[string]string
}

// WorkloadSubjectPattern is the subject rule (GAP-0043): exact, or a
// prefix ending in ":*" or "/*" with something before the separator.
var WorkloadSubjectPattern = regexp.MustCompile(`^(?:[^*]+|[^*]+[:/]\*)$`)

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
