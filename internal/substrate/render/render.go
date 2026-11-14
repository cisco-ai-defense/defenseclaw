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

// Package render turns a DefenseClaw profile, the cluster's Substrate
// settings and the secrets bound to an actor's person into the actor's
// Substrate EgressPolicy. Rendering is deterministic (the same input gives
// the same rules in the same order), never reaches a model provider (D2),
// never sends a secret on a passthrough rule (D14), stays within
// upstream's 256-rule limit, and the result passes the same admission
// checks ate-api-server runs (Validate). Canonical and Equal compare a
// rendered policy with what the server returns, for drift detection.
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
)

const (
	// ActorHeader is the header the actor kit sends with a placeholder on
	// every call to DefenseClaw; egress replaces it with the actor JWT.
	ActorHeader = "x-defenseclaw-actor"
	// DefaultAudience and DefaultTokenLifetime are the actor JWT's aud and
	// lifetime (seconds) unless the config sets others.
	DefaultAudience      = "defenseclaw"
	DefaultTokenLifetime = 300
	// DefaultActorServicePort is the actor listener Service's plain HTTP
	// port (the chart's defenseclaw-actor Service).
	DefaultActorServicePort = 80
	// MaxRules is upstream's limit on rules per policy, and
	// maxHostnamesPerRule its limit on hostnames per rule.
	MaxRules            = 256
	maxHostnamesPerRule = 256
	maxHeadersPerRule   = 16
	// PersonPlaceholder in a per_person secret's source is replaced with
	// PersonKey of the actor's person.
	PersonPlaceholder = egressspec.PersonPlaceholder
)

// Secret scopes.
const (
	ScopeShared    = egressspec.ScopeShared
	ScopePerPerson = egressspec.ScopePerPerson
)

// Settings are the cluster-wide inputs, from the substrate config section.
type Settings struct {
	// ActorService is the DefenseClaw actor listener's Service host
	// (substrate.services.actor), the only DefenseClaw host an actor may
	// reach, over an http rule; ActorServicePort its port (80 when zero). AdminService is
	// never reachable (D15); no rule may overlap it or the actor
	// Service's namespace domain.
	ActorService     string
	ActorServicePort int32
	AdminService     string
	// Audience and TokenLifetimeSeconds shape the injected actor JWT.
	Audience             string
	TokenLifetimeSeconds int64
	// AllowHosts is the base allow list for every actor.
	AllowHosts []string
	// EcosystemPacks names packs from EcosystemPacks() to allow.
	EcosystemPacks []string
	// MCPHosts and RegistryHosts are the admin-allowed remote MCP servers
	// and image or package registries.
	MCPHosts      []string
	RegistryHosts []string
	// PassthroughFor lists hosts forwarded without inspection
	// (certificate pinning, E8). A secret is never bound to one.
	PassthroughFor []string
	// ProviderHosts adds model provider hosts (configured LLM base URLs)
	// to the built-in list no rule may reach.
	ProviderHosts []string
}

// Profile is the actor's DefenseClaw profile, reduced to what shapes egress.
// Profiles only tighten: AllowOnly and Block remove destinations.
type Profile struct {
	Name string
	// AllowOnly, when non-empty, admits only destinations it covers
	// (OpenShell syntax: a host name admits itself, "*.<name>" every name
	// under it).
	AllowOnly []string
	// Block removes every rule that could reach a listed host (a host name
	// blocks itself and every name under it).
	Block []string
	// AllowedCredentials limits which secrets (by name) may be bound; nil
	// allows all, ["none"] none.
	AllowedCredentials []string
}

// Secret is one entry of substrate.secrets.
type Secret struct {
	Name string
	// Source is an ate-secret://<class>/<provider>/<tail> reference; a
	// per_person source contains PersonPlaceholder.
	Source string
	// Hosts the credential is injected on (inspected https only).
	Hosts []string
	// Header is replaced when the actor sends it; Prefix is prepended.
	Header string
	Prefix string
	// Scope is shared or per_person.
	Scope string
	// Profiles are profile-name globs the secret is bound for; empty binds
	// it for none.
	Profiles []string
}

// Input is everything one actor's policy depends on.
type Input struct {
	Settings Settings
	Profile  Profile
	// Person is the verified OIDC subject the actor is bound to; empty for
	// an actor attributed only to its atespace or a workload.
	Person string
	// Approved are hosts allowed through asks for this actor.
	Approved []string
	Secrets  []Secret
}

// Drop is a destination or secret binding left out of the policy.
type Drop struct {
	// Host is the pattern as written; Secret the secret's name for a
	// binding.
	Host   string `json:"host,omitempty"`
	Secret string `json:"secret,omitempty"`
	// Source says where it came from: allow, pack:<name>, mcp, registry,
	// approved, passthrough or secret.
	Source string `json:"source"`
	// Reason is a stable token (see the Reason constants).
	Reason string `json:"reason"`
	// Detail names the matching entry, when there is one.
	Detail string `json:"detail,omitempty"`
}

// Drop reasons.
const (
	ReasonInvalid            = "invalid_pattern"
	ReasonProvider           = "provider_host"
	ReasonInternal           = "defenseclaw_internal"
	ReasonBlocked            = "blocked"
	ReasonNotAllowed         = "not_in_allow_only"
	ReasonPassthroughSecret  = "secret_on_passthrough"
	ReasonSecretProfile      = "secret_not_for_profile"
	ReasonSecretCredentials  = "secret_not_in_allowed_credentials"
	ReasonSecretNoPerson     = "secret_needs_person"
	ReasonSecretInvalid      = "secret_invalid"
	ReasonSecretHeader       = "secret_header_conflict"
	ReasonSecretTooManyHeads = "secret_too_many_headers"
)

// Binding is a secret injected on a host.
type Binding struct {
	Secret string `json:"secret"`
	Host   string `json:"host"`
}

// Result is a rendered policy and what was left out.
type Result struct {
	Policy   *ateapi.EgressPolicy
	Dropped  []Drop
	Bindings []Binding
}

// ErrTooManyRules means the inputs need more than MaxRules rules.
var ErrTooManyRules = errors.New("render: the policy needs more than 256 rules")

type candidate struct {
	p           pattern
	source      string
	passthrough bool
}

// EgressPolicy renders an actor's EgressPolicy. It fails only on invalid
// settings or a policy over MaxRules; destinations and secrets that may
// not be allowed are dropped and reported.
func EgressPolicy(in Input) (Result, error) {
	s := in.Settings
	actor, svc, err := actorRule(s)
	if err != nil {
		return Result{}, err
	}
	// DefenseClaw's own namespace domain and the admin Service are never
	// reachable (D15), in both the short (<svc>.<ns>.svc) and the fully
	// qualified (.svc.cluster.local) spelling.
	var internal []hostClass
	for _, name := range spellings(svc.Name) {
		internal = append(internal, hostClass{suffix: name})
		if ns := parent(name); strings.Contains(ns, ".") {
			internal = append(internal, hostClass{suffix: ns})
		}
	}
	if a, ok := parsePattern(s.AdminService); ok && !a.Any {
		for _, name := range spellings(a.Name) {
			internal = append(internal, hostClass{suffix: name})
		}
	}
	providers := append(slices.Clone(providerHosts), blockClasses(s.ProviderHosts)...)
	blocks := blockClasses(in.Profile.Block)

	var res Result
	drop := func(d Drop) { res.Dropped = append(res.Dropped, d) }
	// admit reports whether a destination may get a rule, recording why not.
	admit := func(raw, source, secret string) (pattern, bool) {
		p, ok := parsePattern(raw)
		d := Drop{Host: raw, Secret: secret, Source: source}
		switch {
		case !ok:
			d.Reason = ReasonInvalid
		default:
			if m, hit := anyOverlap(internal, p); hit {
				d.Reason, d.Detail = ReasonInternal, m
			} else if m, hit := anyOverlap(providers, p); hit {
				d.Reason, d.Detail = ReasonProvider, m
			} else if m, hit := anyOverlap(blocks, p); hit {
				d.Reason, d.Detail = ReasonBlocked, m
			} else if len(in.Profile.AllowOnly) > 0 && !covered(in.Profile.AllowOnly, p) {
				d.Reason = ReasonNotAllowed
			} else {
				return p, true
			}
		}
		drop(d)
		return pattern{}, false
	}

	passthrough := map[string]bool{}
	cands := map[string]*candidate{}
	add := func(raw, source string, pt bool) {
		p, ok := admit(raw, source, "")
		if !ok {
			return
		}
		k := p.String()
		if pt {
			passthrough[k] = true
		}
		if c, ok := cands[k]; ok {
			c.passthrough = c.passthrough || pt
			return
		}
		cands[k] = &candidate{p: p, source: source, passthrough: pt}
	}
	for _, h := range s.PassthroughFor {
		add(h, "passthrough", true)
	}
	for _, h := range s.AllowHosts {
		add(h, "allow", false)
	}
	packs := slices.Clone(s.EcosystemPacks)
	slices.Sort(packs)
	for _, name := range slices.Compact(packs) {
		hosts := egressspec.PackHosts(name)
		if hosts == nil {
			return Result{}, fmt.Errorf("render: unknown ecosystem pack %q", name)
		}
		for _, h := range hosts {
			add(h, "pack:"+name, false)
		}
	}
	for _, h := range s.MCPHosts {
		add(h, "mcp", false)
	}
	for _, h := range s.RegistryHosts {
		add(h, "registry", false)
	}
	for _, h := range in.Approved {
		add(h, "approved", false)
	}

	effects := bindSecrets(in, admit, passthrough, &res)
	for k := range effects {
		delete(cands, k) // a secret host gets its own rule
	}

	rules := []*ateapi.EgressRule{actor}
	for _, k := range sortedKeys(effects) {
		rules = append(rules, &ateapi.EgressRule{Https: &ateapi.HttpsRule{
			Hostnames: []string{k}, Ports: port443(), Effects: &ateapi.HttpRuleEffects{ReplaceHeaders: effects[k]},
		}})
	}
	var inspected, forwarded []string
	for k, c := range cands {
		if c.passthrough {
			forwarded = append(forwarded, k)
		} else {
			inspected = append(inspected, k)
		}
	}
	slices.Sort(inspected)
	slices.Sort(forwarded)
	for chunk := range slices.Chunk(inspected, maxHostnamesPerRule) {
		rules = append(rules, &ateapi.EgressRule{Https: &ateapi.HttpsRule{Hostnames: chunk, Ports: port443()}})
	}
	for chunk := range slices.Chunk(forwarded, maxHostnamesPerRule) {
		rules = append(rules, &ateapi.EgressRule{TlsPassthrough: &ateapi.TlsPassthroughRule{Hostnames: chunk, Ports: port443()}})
	}
	if len(rules) > MaxRules {
		return Result{}, ErrTooManyRules
	}
	res.Policy = &ateapi.EgressPolicy{Rules: rules}
	if err := Validate(res.Policy); err != nil {
		return Result{}, fmt.Errorf("render: rendered policy fails admission: %w", err)
	}
	return res, nil
}

// actorRule is the one rule every DefenseClaw policy has: cleartext HTTP
// to the actor listener's Service (port 80 unless set) with the actor JWT
// injected. Egress trusts only public CAs for an https upstream, so the
// in-cluster hop egress -> actor listener is plain HTTP, limited to
// atenet-egress by NetworkPolicy (GAP-0023 outcome; chart README).
func actorRule(s Settings) (*ateapi.EgressRule, pattern, error) {
	svc, ok := parsePattern(s.ActorService)
	if !ok || svc.Wildcard || svc.Any {
		return nil, pattern{}, fmt.Errorf("render: actor service %q is not a host name", s.ActorService)
	}
	port := s.ActorServicePort
	if port == 0 {
		port = DefaultActorServicePort
	}
	if port < 1 || port > 65535 {
		return nil, pattern{}, fmt.Errorf("render: actor service port %d", port)
	}
	aud := s.Audience
	if aud == "" {
		aud = DefaultAudience
	}
	life := s.TokenLifetimeSeconds
	if life == 0 {
		life = DefaultTokenLifetime
	}
	if life != DefaultTokenLifetime {
		return nil, pattern{}, fmt.Errorf("render: token lifetime %d s: egress caches the actor JWT by actor name, so it is %d s (GAP-0133)", life, DefaultTokenLifetime)
	}
	return &ateapi.EgressRule{Http: &ateapi.HttpRule{
		Hostnames: []string{svc.Name},
		Ports:     &ateapi.Ports{Numbers: []int32{port}},
		Effects: &ateapi.HttpRuleEffects{ReplaceHeaders: []*ateapi.CredentialHeader{{
			Header: ActorHeader, Prefix: "Bearer ",
			ActorJwt: &ateapi.ActorJwtSource{Audiences: []string{aud}, ExpirationSeconds: life},
		}}},
	}}, svc, nil
}

// DenyOnly is the policy of an actor in policy_conflict: the actor rule
// alone, so its hooks still reach DefenseClaw and every other destination
// is denied (GAP-0055).
func DenyOnly(s Settings) (*ateapi.EgressPolicy, error) {
	r, _, err := actorRule(s)
	if err != nil {
		return nil, err
	}
	p := &ateapi.EgressPolicy{Rules: []*ateapi.EgressRule{r}}
	if err := Validate(p); err != nil {
		return nil, fmt.Errorf("render: deny-only policy fails admission: %w", err)
	}
	return p, nil
}

// IsDefenseClaw reports whether a policy carries DefenseClaw's actor rule
// (a rule to the actor Service that injects the actor JWT): DefenseClaw
// wrote it, or someone copied it, and either way only DefenseClaw may keep
// it in force.
func IsDefenseClaw(p *ateapi.EgressPolicy, s Settings) bool {
	svc, ok := parsePattern(s.ActorService)
	if !ok {
		return false
	}
	for _, r := range p.GetRules() {
		var hosts []string
		var eff *ateapi.HttpRuleEffects
		switch {
		case r.GetHttp() != nil:
			hosts, eff = r.GetHttp().GetHostnames(), r.GetHttp().GetEffects()
		case r.GetHttps() != nil:
			hosts, eff = r.GetHttps().GetHostnames(), r.GetHttps().GetEffects()
		default:
			continue
		}
		if !slices.Contains(hosts, svc.Name) {
			continue
		}
		for _, h := range eff.GetReplaceHeaders() {
			if h.GetActorJwt() != nil {
				return true
			}
		}
	}
	return false
}

// bindSecrets returns the credential headers per host pattern for every
// secret the actor may receive, in secret-name order, recording drops and
// bindings in res.
func bindSecrets(in Input, admit func(raw, source, secret string) (pattern, bool), passthrough map[string]bool, res *Result) map[string][]*ateapi.CredentialHeader {
	effects := map[string][]*ateapi.CredentialHeader{}
	secrets := slices.Clone(in.Secrets)
	slices.SortStableFunc(secrets, func(a, b Secret) int { return strings.Compare(a.Name, b.Name) })
	allowed := in.Profile.AllowedCredentials
	for _, sec := range secrets {
		d := Drop{Secret: sec.Name, Source: "secret"}
		uri := sec.Source
		switch {
		case !profileMatches(sec.Profiles, in.Profile.Name):
			d.Reason = ReasonSecretProfile
		case len(allowed) > 0 && (slices.Contains(allowed, "none") || !slices.Contains(allowed, sec.Name)):
			d.Reason = ReasonSecretCredentials
		case sec.Scope == ScopePerPerson && in.Person == "":
			d.Reason = ReasonSecretNoPerson
		case sec.Scope != ScopeShared && sec.Scope != ScopePerPerson:
			d.Reason, d.Detail = ReasonSecretInvalid, "scope"
		default:
			if sec.Scope == ScopePerPerson {
				if !strings.Contains(uri, PersonPlaceholder) {
					// Without {person} one secret would serve every person
					// (config validation refuses it too; GAP-0068).
					d.Reason, d.Detail = ReasonSecretInvalid, "per_person source does not name "+PersonPlaceholder
					break
				}
				uri = strings.ReplaceAll(uri, PersonPlaceholder, PersonKey(in.Person))
			} else if strings.Contains(uri, PersonPlaceholder) {
				d.Reason, d.Detail = ReasonSecretInvalid, "shared source names "+PersonPlaceholder
			}
			if d.Reason == "" {
				if err := ValidateCredentialHeader(sec.Header, sec.Prefix, uri); err != nil {
					d.Reason, d.Detail = ReasonSecretInvalid, err.Error()
				}
			}
		}
		if d.Reason != "" {
			res.Dropped = append(res.Dropped, d)
			continue
		}
		hosts := slices.Clone(sec.Hosts)
		slices.Sort(hosts)
		for _, h := range slices.Compact(hosts) {
			p, ok := admit(h, "secret", sec.Name)
			if !ok {
				continue
			}
			k := p.String()
			hd := Drop{Host: h, Secret: sec.Name, Source: "secret"}
			switch {
			case passthrough[k]:
				hd.Reason = ReasonPassthroughSecret
			case hasHeader(effects[k], sec.Header):
				hd.Reason = ReasonSecretHeader
			case len(effects[k]) >= maxHeadersPerRule:
				hd.Reason = ReasonSecretTooManyHeads
			}
			if hd.Reason != "" {
				res.Dropped = append(res.Dropped, hd)
				continue
			}
			effects[k] = append(effects[k], &ateapi.CredentialHeader{Header: sec.Header, Prefix: sec.Prefix, CredentialUri: uri})
			res.Bindings = append(res.Bindings, Binding{Secret: sec.Name, Host: k})
		}
	}
	return effects
}

// spellings returns a Service name (given first) in every form that names
// it from a pod: fully qualified (.svc.cluster.local), .svc, <svc>.<ns> and
// <svc>; other names unchanged.
func spellings(name string) []string {
	const fq = ".svc.cluster.local"
	var svc string
	switch {
	case strings.HasSuffix(name, fq):
		svc = strings.TrimSuffix(name, fq)
	case strings.HasSuffix(name, ".svc"):
		svc = strings.TrimSuffix(name, ".svc")
	default:
		return []string{name}
	}
	// <svc>.<ns> and <svc> resolve through the pod's search path, so they
	// name the same Service (GAP-0066).
	out := []string{name}
	for _, n := range []string{svc + fq, svc + ".svc", svc} {
		if n != name {
			out = append(out, n)
		}
	}
	if i := strings.IndexByte(svc, '.'); i > 0 {
		out = append(out, svc[:i])
	}
	return out
}

func hasHeader(hs []*ateapi.CredentialHeader, h string) bool {
	return slices.ContainsFunc(hs, func(c *ateapi.CredentialHeader) bool { return strings.EqualFold(c.GetHeader(), h) })
}

func profileMatches(globs []string, name string) bool {
	for _, g := range globs {
		if ok, err := path.Match(g, name); err == nil && ok {
			return true
		}
	}
	return false
}

// PersonKey is the path-safe key of a person's OIDC subject used in
// per_person secret sources: "p-" and 20 hex digits of its SHA-256. The
// `secrets set --mine` writer uses the same key.
func PersonKey(sub string) string {
	sum := sha256.Sum256([]byte(sub))
	return "p-" + hex.EncodeToString(sum[:])[:20]
}

func port443() *ateapi.Ports { return &ateapi.Ports{Numbers: []int32{443}} }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
