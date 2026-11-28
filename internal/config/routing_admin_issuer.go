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

package config

import (
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// SplitQualifiedUser splits an issuer-qualified users entry or named user
// budget subject, issuer#subject (identity.Person.ID, GAP-0792): the issuer
// is an https URL and never holds a '#'. ok is false for a bare name, so a
// host account name with a '#' keeps matching as before.
func SplitQualifiedUser(entry string) (issuer, subject string, ok bool) {
	entry = strings.TrimSpace(entry)
	if !strings.HasPrefix(entry, "https://") {
		return "", "", false
	}
	issuer, subject, ok = strings.Cut(entry, "#")
	if !ok {
		return "", "", false
	}
	return issuer, subject, true
}

// SubstrateKubeIssuer is the issuer of a person signed in with Kubernetes
// credentials (identity.KubeIssuer; config does not import identity).
const SubstrateKubeIssuer = "kubernetes"

// kubeSignInPin is the gateway's boot-time Kubernetes sign-in decision
// (PinKubeSignIn): 0 not pinned, 1 on, 2 off. It is process-wide, so a
// reloaded configuration cannot change it: the gateway builds its sign-in
// verifiers once at start (substrate.identity is restart-only), and the
// issuers routing.admin users entries match against must stay the ones
// those verifiers can produce (GAP-0968).
var kubeSignInPin atomic.Int32

// PinKubeSignIn records whether the gateway built a Kubernetes sign-in at
// start (the key, the --no-kube-sign-in flag, an OIDC issuer and a managed
// install all folded in). From then on SubstrateKubeSignIn returns it for
// every configuration this process loads, until the next start.
func PinKubeSignIn(on bool) {
	if on {
		kubeSignInPin.Store(1)
	} else {
		kubeSignInPin.Store(2)
	}
}

// UnpinKubeSignIn clears the pin. Tests only: the gateway pins once at start.
func UnpinKubeSignIn() { kubeSignInPin.Store(0) }

// SubstrateKubeSignIn reports whether people sign in to the Substrate
// admin listener with their Kubernetes credentials. In the gateway it is
// the decision made at start (PinKubeSignIn). Elsewhere (the CLI, doctor) it
// is read from this configuration: no identity.oidc.issuer, an install that
// is not managed, and identity.kube_sign_in not false.
func (c *Config) SubstrateKubeSignIn() bool {
	if c == nil {
		return false
	}
	switch kubeSignInPin.Load() {
	case 1:
		return true
	case 2:
		return false
	}
	id := c.Substrate.Identity
	return strings.TrimSpace(id.OIDC.Issuer) == "" && !managed.IsManagedEnterprise(c.DeploymentMode) &&
		(id.KubeSignIn == nil || *id.KubeSignIn)
}

// PersonIssuers lists the distinct trusted person and workload issuers of
// a Substrate cluster, the primary one first: identity.oidc.issuer; else
// the Kubernetes sign-in issuer while that sign-in is on
// (SubstrateKubeSignIn: people sign in with their Kubernetes credentials
// there, GAP-0893; when it is off no one can, GAP-0939); then the
// identity.workload_oidc issuers. Nil when Substrate is off.
func (c *Config) PersonIssuers() []string {
	if c == nil || !c.Substrate.Enabled {
		return nil
	}
	s := c.Substrate
	var out []string
	add := func(iss string) {
		if iss = strings.TrimSpace(iss); iss != "" && !containsString(out, iss) {
			out = append(out, iss)
		}
	}
	add(s.Identity.OIDC.Issuer)
	if c.SubstrateKubeSignIn() {
		add(SubstrateKubeIssuer)
	}
	for _, w := range s.Identity.WorkloadOIDC {
		add(w.Issuer)
	}
	return out
}

// validateQualifiedUser refuses an issuer#subject entry with no subject.
func validateQualifiedUser(at, entry string) error {
	if _, subject, ok := SplitQualifiedUser(entry); ok && strings.TrimSpace(subject) == "" {
		return settingErrorAt(at, fmt.Errorf("%s: %q names an issuer but no subject; write issuer#subject", at, entry))
	}
	return nil
}

// RoutingAdminIssuerWarnings names the routing.admin users entries and
// named user budgets that do not name whom they seem to:
//   - a bare name while the Substrate cluster trusts more than one person
//     issuer (GAP-0792): it then matches only a person of the primary issuer
//     (and host accounts), never the same subject at another issuer;
//   - an issuer#subject entry whose issuer is not a trusted one, exactly as
//     written (a typo, a trailing slash, another case: GAP-0895): it matches
//     no one, so a named budget written that way charges no one.
//
// config validate, the gateway at load and doctor give them.
func (c *Config) RoutingAdminIssuerWarnings() []string {
	if c == nil || c.Routing.Admin == nil {
		return nil
	}
	issuers := c.PersonIssuers()
	var out []string
	check := func(what, entry string) {
		if iss, _, ok := SplitQualifiedUser(entry); ok {
			if !containsString(issuers, iss) {
				trusted := "none"
				if len(issuers) > 0 {
					trusted = strings.Join(issuers, ", ")
				}
				out = append(out, fmt.Sprintf("%s: %q names issuer %q, which is not a trusted issuer (trusted: %s); it matches no one (routing_admin_unknown_issuer)",
					what, entry, iss, trusted))
			}
			return
		}
		if len(issuers) >= 2 && bareRoutingUser(entry) {
			out = append(out, fmt.Sprintf("%s: %q has no issuer; with %d trusted issuers it matches only a person of the primary issuer %s (write issuer#subject for another issuer) (routing_admin_bare_user)",
				what, entry, len(issuers), issuers[0]))
		}
	}
	for _, r := range c.Routing.Admin.Rules {
		for _, u := range r.Match.Users {
			check("routing.admin rule "+r.ID+" users entry", u)
		}
	}
	for _, b := range c.Routing.Admin.Budgets {
		if b.Scope == RoutingBudgetScopeUser && b.Subject != RoutingBudgetSubjectAll {
			check("routing.admin budget "+b.ID+" subject", b.Subject)
		}
	}
	return out
}

// bareRoutingUser is a users entry that can name a person by subject or
// principal without an issuer (not issuer#subject, not a uid: or sid:).
func bareRoutingUser(entry string) bool {
	if _, _, ok := SplitQualifiedUser(entry); ok {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(entry))
	return !strings.HasPrefix(lower, "uid:") && !strings.HasPrefix(lower, "sid:")
}
