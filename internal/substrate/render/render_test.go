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

package render

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json")

func baseSettings() Settings {
	return Settings{
		ActorService: "defenseclaw-actor.defenseclaw-system.svc",
		AdminService: "defenseclaw-admin.defenseclaw-system.svc",
	}
}

func fullSettings() Settings {
	s := baseSettings()
	s.AllowHosts = []string{"github.com", "api.github.com", "*.githubusercontent.com", "Docs.Example.com.",
		"api.openai.com", "*", "10.0.0.1", "*.us-east-1.amazonaws.com", "defenseclaw-admin.defenseclaw-system.svc",
		"*.defenseclaw-system.svc", "pins.example.org", "bad_host"}
	s.EcosystemPacks = []string{"pypi", "npm", "crates", "go", "npm"}
	s.MCPHosts = []string{"mcp.internal.example.com"}
	s.RegistryHosts = []string{"registry.example.com", "ghcr.io"}
	s.PassthroughFor = []string{"pins.example.org"}
	s.ProviderHosts = []string{"llm.internal.example.com"}
	return s
}

func fullSecrets() []Secret {
	return []Secret{
		{Name: "github-push", Source: "ate-secret://k8s.io/default/dc-secrets/github/token", Hosts: []string{"github.com", "api.github.com"},
			Header: "Authorization", Prefix: "Bearer ", Scope: ScopeShared, Profiles: []string{"eng-*"}},
		{Name: "mine-npm", Source: "ate-secret://k8s.io/default/dc-people/{person}-npm/token", Hosts: []string{"registry.npmjs.org"},
			Header: "Authorization", Prefix: "Bearer ", Scope: ScopePerPerson, Profiles: []string{"eng-*"}},
		{Name: "pinned", Source: "ate-secret://k8s.io/default/dc-secrets/pins/token", Hosts: []string{"pins.example.org"},
			Header: "X-Api-Key", Scope: ScopeShared, Profiles: []string{"*"}},
		{Name: "to-provider", Source: "ate-secret://k8s.io/default/dc-secrets/oai/key", Hosts: []string{"api.openai.com", "llm.internal.example.com"},
			Header: "Authorization", Scope: ScopeShared, Profiles: []string{"*"}},
		{Name: "sales-only", Source: "ate-secret://k8s.io/default/dc-secrets/crm/token", Hosts: []string{"crm.example.com"},
			Header: "Authorization", Scope: ScopeShared, Profiles: []string{"sales"}},
		{Name: "dup-header", Source: "ate-secret://k8s.io/default/dc-secrets/gh2/token", Hosts: []string{"github.com"},
			Header: "authorization", Scope: ScopeShared, Profiles: []string{"eng-*"}},
		{Name: "bad-uri", Source: "vault://kv/ci/github-app", Hosts: []string{"git.example.com"},
			Header: "Authorization", Scope: ScopeShared, Profiles: []string{"*"}},
		{Name: "no-profiles", Source: "ate-secret://k8s.io/default/dc-secrets/x/y", Hosts: []string{"x.example.com"},
			Header: "Authorization", Scope: ScopeShared},
	}
}

var cases = []struct {
	name string
	in   Input
}{
	{"minimal", Input{Settings: baseSettings(), Profile: Profile{Name: "default"}}},
	{"full-person", Input{
		Settings: fullSettings(), Profile: Profile{Name: "eng-payments"}, Person: "00u1abcd",
		Approved: []string{"status.example.net"}, Secrets: fullSecrets(),
	}},
	{"full-atespace", Input{Settings: fullSettings(), Profile: Profile{Name: "eng-payments"}, Secrets: fullSecrets()}},
	{"tightened", Input{
		Settings: fullSettings(), Person: "00u1abcd", Secrets: fullSecrets(),
		Profile: Profile{
			Name: "eng-web", AllowOnly: []string{"github.com", "*.github.com", "*.npmjs.org", "pypi.org"},
			Block: []string{"api.github.com"}, AllowedCredentials: []string{"mine-npm"},
		},
	}},
	{"no-credentials", Input{
		Settings: fullSettings(), Person: "00u1abcd", Secrets: fullSecrets(),
		Profile: Profile{Name: "eng-web", AllowedCredentials: []string{"none"}, Block: []string{"*.crates.io"}},
	}},
	{"custom-service", Input{Settings: Settings{
		ActorService: "dc-actor.security.svc.cluster.local", ActorServicePort: 8443, Audience: "dc-prod", TokenLifetimeSeconds: 600,
		AllowHosts: []string{"*.svc.cluster.local", "other.security.svc.cluster.local", "*.cluster.local"},
	}, Profile: Profile{Name: "default"}}},
}

type golden struct {
	Policy   json.RawMessage `json:"policy"`
	Dropped  []Drop          `json:"dropped"`
	Bindings []Binding       `json:"bindings"`
}

func goldenBytes(t *testing.T, r Result) []byte {
	t.Helper()
	raw, err := protojson.Marshal(r.Policy)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pol, _ := json.Marshal(v)
	out, err := json.MarshalIndent(golden{Policy: pol, Dropped: r.Dropped, Bindings: r.Bindings}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func TestGoldens(t *testing.T) {
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := EgressPolicy(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			got := goldenBytes(t, r)
			path := filepath.Join("testdata", tc.name+".golden.json")
			if *update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s differs from the golden (run with -update and review):\n%s", path, got)
			}
		})
	}
}

func shuffled(in Input, seed uint64) Input {
	r := rand.New(rand.NewPCG(seed, seed))
	sh := func(s []string) []string {
		s = slices.Clone(s)
		r.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
		return s
	}
	out := in
	out.Settings.AllowHosts = sh(in.Settings.AllowHosts)
	out.Settings.EcosystemPacks = sh(in.Settings.EcosystemPacks)
	out.Settings.RegistryHosts = sh(in.Settings.RegistryHosts)
	out.Secrets = slices.Clone(in.Secrets)
	r.Shuffle(len(out.Secrets), func(i, j int) { out.Secrets[i], out.Secrets[j] = out.Secrets[j], out.Secrets[i] })
	for i := range out.Secrets {
		out.Secrets[i].Hosts = sh(out.Secrets[i].Hosts)
	}
	return out
}

func TestDeterministicUnderInputOrder(t *testing.T) {
	for _, tc := range cases {
		want, err := EgressPolicy(tc.in)
		if err != nil {
			t.Fatal(err)
		}
		for seed := range uint64(20) {
			got, err := EgressPolicy(shuffled(tc.in, seed))
			if err != nil {
				t.Fatal(err)
			}
			// Rule order and hostnames are byte-identical; drops follow input order of sources.
			if !bytes.Equal(policyJSON(t, got.Policy), policyJSON(t, want.Policy)) {
				t.Fatalf("%s seed %d: policy depends on input order", tc.name, seed)
			}
			if !slices.Equal(got.Bindings, want.Bindings) {
				t.Fatalf("%s seed %d: bindings depend on input order", tc.name, seed)
			}
		}
	}
}

func policyJSON(t *testing.T, p *ateapi.EgressPolicy) []byte {
	t.Helper()
	raw, _ := protojson.Marshal(p)
	var v any
	_ = json.Unmarshal(raw, &v)
	b, _ := json.Marshal(v)
	return b
}

func TestNeverReachesAProvider(t *testing.T) {
	hosts := []string{
		"api.anthropic.com", "anthropic.com", "*.anthropic.com", "statsig.anthropic.com", "claude.ai", "api.openai.com",
		"*.openai.com", "chatgpt.com", "myres.openai.azure.com", "*.openai.azure.com", "azure.com", /* allowed: family is below */
		"bedrock-runtime.us-east-1.amazonaws.com", "bedrock.eu-west-1.amazonaws.com", "bedrock-runtime-fips.us-east-1.amazonaws.com",
		"*.us-east-1.amazonaws.com", "us-central1-aiplatform.googleapis.com", "*.googleapis.com", "generativelanguage.googleapis.com",
		"api.mistral.ai", "openrouter.ai", "*", "llm.internal.example.com", "*.internal.example.com",
	}
	allowed := map[string]bool{"azure.com": true}
	s := baseSettings()
	s.AllowHosts = hosts
	s.ProviderHosts = []string{"https://llm.internal.example.com/v1"} // not a host: ignored
	s.ProviderHosts = append(s.ProviderHosts, "llm.internal.example.com")
	r, err := EgressPolicy(Input{Settings: s, Profile: Profile{Name: "p"}})
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, rule := range r.Policy.GetRules()[1:] {
		kept = append(kept, rule.GetHttps().GetHostnames()...)
	}
	for _, h := range hosts {
		if slices.Contains(kept, h) != allowed[h] {
			t.Errorf("%s: kept=%v want %v", h, slices.Contains(kept, h), allowed[h])
		}
	}
	// "*.amazonaws.com" matches one label, never a regional Bedrock host.
	s.AllowHosts = []string{"*.amazonaws.com", "s3.amazonaws.com"}
	r, _ = EgressPolicy(Input{Settings: s})
	if len(r.Dropped) != 0 {
		t.Errorf("non-provider AWS hosts dropped: %+v", r.Dropped)
	}
}

func TestInternalServicesUnreachable(t *testing.T) {
	s := baseSettings()
	s.AllowHosts = []string{"defenseclaw-admin.defenseclaw-system.svc", "*.defenseclaw-system.svc", "defenseclaw-actor.defenseclaw-system.svc",
		"x.defenseclaw-admin.defenseclaw-system.svc", "other.ns.svc"}
	r, err := EgressPolicy(Input{Settings: s})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(r.Policy.GetRules()); n != 2 || r.Policy.GetRules()[1].GetHttps().GetHostnames()[0] != "other.ns.svc" {
		t.Fatalf("rules = %v", r.Policy.GetRules())
	}
	for _, d := range r.Dropped {
		if d.Reason != ReasonInternal {
			t.Errorf("%s: %s", d.Host, d.Reason)
		}
	}
	if len(r.Dropped) != 4 {
		t.Fatalf("dropped = %+v", r.Dropped)
	}
}

func TestActorServiceRule(t *testing.T) {
	r, err := EgressPolicy(Input{Settings: baseSettings()})
	if err != nil {
		t.Fatal(err)
	}
	rule := r.Policy.GetRules()[0].GetHttps()
	h := rule.GetEffects().GetReplaceHeaders()[0]
	if rule.GetHostnames()[0] != "defenseclaw-actor.defenseclaw-system.svc" || h.GetHeader() != ActorHeader ||
		h.GetPrefix() != "Bearer " || h.GetActorJwt().GetAudiences()[0] != "defenseclaw" || h.GetActorJwt().GetExpirationSeconds() != 900 ||
		h.GetCredentialUri() != "" {
		t.Fatalf("actor service rule = %v", rule)
	}
	for _, bad := range []Settings{
		{ActorService: ""}, {ActorService: "*.x.svc"}, {ActorService: "a.svc", TokenLifetimeSeconds: 100},
		{ActorService: "a.svc", ActorServicePort: 70000}, {ActorService: "a.svc", EcosystemPacks: []string{"maven"}},
	} {
		if _, err := EgressPolicy(Input{Settings: bad}); err == nil {
			t.Errorf("settings %+v accepted", bad)
		}
	}
}

func TestPassthroughNeverCarriesASecret(t *testing.T) {
	r, err := EgressPolicy(cases[1].in)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range r.Policy.GetRules() {
		if pt := rule.GetTlsPassthrough(); pt != nil && !slices.Equal(pt.GetHostnames(), []string{"pins.example.org"}) {
			t.Fatalf("passthrough = %v", pt.GetHostnames())
		}
	}
	found := false
	for _, d := range r.Dropped {
		if d.Secret == "pinned" && d.Reason == ReasonPassthroughSecret {
			found = true
		}
	}
	if !found {
		t.Fatalf("pinned secret not refused on the passthrough host: %+v", r.Dropped)
	}
}

func TestPerPersonSourceUsesPersonKey(t *testing.T) {
	r, _ := EgressPolicy(cases[1].in)
	want := "ate-secret://k8s.io/default/dc-people/" + PersonKey("00u1abcd") + "-npm/token"
	var got string
	for _, rule := range r.Policy.GetRules() {
		if slices.Contains(rule.GetHttps().GetHostnames(), "registry.npmjs.org") {
			got = rule.GetHttps().GetEffects().GetReplaceHeaders()[0].GetCredentialUri()
		}
	}
	if got != want {
		t.Fatalf("uri = %q want %q", got, want)
	}
	if strings.Contains(got, "00u1abcd") {
		t.Fatal("the raw subject leaks into the policy")
	}
	if k := PersonKey("a"); k == PersonKey("b") || k != PersonKey(string([]byte{'a'})) || len(k) != 22 {
		t.Fatal("PersonKey")
	}
	shared := cases[1].in
	shared.Secrets = []Secret{{Name: "s", Source: "ate-secret://k8s.io/default/x/{person}/t", Hosts: []string{"a.example.com"},
		Header: "Authorization", Scope: ScopeShared, Profiles: []string{"*"}}}
	r, _ = EgressPolicy(shared)
	if r.Dropped[len(r.Dropped)-1].Reason != ReasonSecretInvalid {
		t.Fatal("a shared secret naming {person} must be refused")
	}
}

func TestChunkingAndRuleLimit(t *testing.T) {
	s := baseSettings()
	for i := range 600 {
		s.AllowHosts = append(s.AllowHosts, fmt.Sprintf("h%03d.example.com", i))
	}
	r, err := EgressPolicy(Input{Settings: s})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(r.Policy.GetRules()); n != 1+3 {
		t.Fatalf("rules = %d", n)
	}
	var secrets []Secret
	for i := range 300 {
		secrets = append(secrets, Secret{Name: fmt.Sprintf("s%03d", i), Source: "ate-secret://k8s.io/default/x/y", Hosts: []string{fmt.Sprintf("s%03d.example.com", i)},
			Header: "Authorization", Scope: ScopeShared, Profiles: []string{"*"}})
	}
	if _, err := EgressPolicy(Input{Settings: baseSettings(), Profile: Profile{Name: "p"}, Secrets: secrets}); !errors.Is(err, ErrTooManyRules) {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateMirrorsAdmission(t *testing.T) {
	jwt := &ateapi.ActorJwtSource{Audiences: []string{"a"}, ExpirationSeconds: 900}
	https := func(hosts []string, ports *ateapi.Ports, hs ...*ateapi.CredentialHeader) *ateapi.EgressRule {
		r := &ateapi.HttpsRule{Hostnames: hosts, Ports: ports}
		if hs != nil {
			r.Effects = &ateapi.HttpRuleEffects{ReplaceHeaders: hs}
		}
		return &ateapi.EgressRule{Https: r}
	}
	uri := func(u string) *ateapi.CredentialHeader {
		return &ateapi.CredentialHeader{Header: "Authorization", CredentialUri: u}
	}
	ok := []*ateapi.EgressRule{
		https([]string{"a.example.com", "*.example.com", "*"}, nil),
		{Http: &ateapi.HttpRule{Hostnames: []string{"a.example.com"}}}, // 80 vs 443: no tie
		{TlsPassthrough: &ateapi.TlsPassthroughRule{Hostnames: []string{"b.example.com"}, Ports: &ateapi.Ports{Numbers: []int32{8443}}}},
		https([]string{"c.example.com"}, &ateapi.Ports{All: &ateapi.AllPorts{}}, uri("ate-secret://k8s.io/default/ns/s/k")),
		https([]string{"d.example.com"}, nil, &ateapi.CredentialHeader{Header: "x-a", ActorJwt: jwt}),
	}
	if err := Validate(&ateapi.EgressPolicy{Rules: ok}); err != nil {
		t.Fatalf("valid policy refused: %v", err)
	}
	bad := map[string][]*ateapi.EgressRule{
		"tie https":          {https([]string{"a.example.com"}, nil), https([]string{"a.example.com"}, &ateapi.Ports{Numbers: []int32{443}})},
		"tie across":         {https([]string{"a.example.com"}, nil), {TlsPassthrough: &ateapi.TlsPassthroughRule{Hostnames: []string{"a.example.com"}, Ports: &ateapi.Ports{Numbers: []int32{443}}}}},
		"tie all ports":      {https([]string{"a.example.com"}, &ateapi.Ports{All: &ateapi.AllPorts{}}), {TlsPassthrough: &ateapi.TlsPassthroughRule{Hostnames: []string{"a.example.com"}, Ports: &ateapi.Ports{All: &ateapi.AllPorts{}}}}},
		"no member":          {{}},
		"two members":        {{Http: &ateapi.HttpRule{Hostnames: []string{"a.b"}}, Https: &ateapi.HttpsRule{Hostnames: []string{"a.b"}}}},
		"uppercase":          {https([]string{"A.example.com"}, nil)},
		"ip":                 {https([]string{"10.0.0.1"}, nil)},
		"mid wildcard":       {https([]string{"a.*.com"}, nil)},
		"trailing dot":       {https([]string{"a.example.com."}, nil)},
		"duplicate host":     {https([]string{"a.example.com", "a.example.com"}, nil)},
		"no hosts":           {https(nil, nil)},
		"passthrough noport": {{TlsPassthrough: &ateapi.TlsPassthroughRule{Hostnames: []string{"a.example.com"}}}},
		"port 0":             {https([]string{"a.example.com"}, &ateapi.Ports{Numbers: []int32{0}})},
		"dup port":           {https([]string{"a.example.com"}, &ateapi.Ports{Numbers: []int32{1, 1}})},
		"empty effects":      {{Https: &ateapi.HttpsRule{Hostnames: []string{"a.example.com"}, Effects: &ateapi.HttpRuleEffects{}}}},
		"dup header":         {https([]string{"a.example.com"}, nil, uri("ate-secret://k8s.io/a/b"), &ateapi.CredentialHeader{Header: "authorization", ActorJwt: jwt})},
		"bad header":         {https([]string{"a.example.com"}, nil, &ateapi.CredentialHeader{Header: "a b", ActorJwt: jwt})},
		"bad prefix":         {https([]string{"a.example.com"}, nil, &ateapi.CredentialHeader{Header: "a", Prefix: "x\n", ActorJwt: jwt})},
		"both sources":       {https([]string{"a.example.com"}, nil, &ateapi.CredentialHeader{Header: "a", ActorJwt: jwt, CredentialUri: "ate-secret://k8s.io/a/b"})},
		"no source":          {https([]string{"a.example.com"}, nil, &ateapi.CredentialHeader{Header: "a"})},
		"jwt short":          {https([]string{"a.example.com"}, nil, &ateapi.CredentialHeader{Header: "a", ActorJwt: &ateapi.ActorJwtSource{Audiences: []string{"a"}, ExpirationSeconds: 299}})},
		"jwt no aud":         {https([]string{"a.example.com"}, nil, &ateapi.CredentialHeader{Header: "a", ActorJwt: &ateapi.ActorJwtSource{ExpirationSeconds: 900}})},
	}
	for _, u := range []string{"vault://kv/a/b", "ate-secret://k8s.io/a", "ate-secret://k8s.io/a/", "ate-secret://k8s.io//a/b",
		"ate-secret://K8S.io/a/b", "ate-secret://k8s.io:80/a/b", "ate-secret://u@k8s.io/a/b", "ate-secret://k8s.io/a/b?x=1",
		"ate-secret://k8s.io/a/b#f", "ate-secret://k8s.io/a%2Fb/c", "ate-secret:///a/b"} {
		bad["uri "+u] = []*ateapi.EgressRule{https([]string{"a.example.com"}, nil, uri(u))}
	}
	many := make([]*ateapi.EgressRule, 257)
	for i := range many {
		many[i] = https([]string{fmt.Sprintf("h%d.example.com", i)}, nil)
	}
	bad["257 rules"] = many
	for name, rules := range bad {
		if err := Validate(&ateapi.EgressPolicy{Rules: rules}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCanonicalIgnoresServerDefaults(t *testing.T) {
	a := &ateapi.EgressPolicy{Rules: []*ateapi.EgressRule{
		{Https: &ateapi.HttpsRule{Hostnames: []string{"b.example.com", "a.example.com"}}},
		{Https: &ateapi.HttpsRule{Hostnames: []string{"c.example.com"}, Effects: &ateapi.HttpRuleEffects{ReplaceHeaders: []*ateapi.CredentialHeader{
			{Header: "X-B", CredentialUri: "ate-secret://k8s.io/a/b"}, {Header: "Authorization", Prefix: "Bearer ", CredentialUri: "ate-secret://k8s.io/a/c"}}}}},
	}}
	b := &ateapi.EgressPolicy{Rules: []*ateapi.EgressRule{
		{Https: &ateapi.HttpsRule{Hostnames: []string{"c.example.com"}, Ports: &ateapi.Ports{Numbers: []int32{443}}, Effects: &ateapi.HttpRuleEffects{ReplaceHeaders: []*ateapi.CredentialHeader{
			{Header: "authorization", Prefix: "Bearer ", CredentialUri: "ate-secret://k8s.io/a/c"}, {Header: "x-b", CredentialUri: "ate-secret://k8s.io/a/b"}}}}},
		{Https: &ateapi.HttpsRule{Hostnames: []string{"a.example.com", "b.example.com"}, Ports: &ateapi.Ports{Numbers: []int32{443}}}},
	}}
	if !Equal(a, b) {
		t.Fatalf("not equal:\n%s\n--\n%s", Canonical(a), Canonical(b))
	}
	c := &ateapi.EgressPolicy{Rules: slices.Clone(b.Rules)}
	c.Rules = append(c.Rules, &ateapi.EgressRule{Https: &ateapi.HttpsRule{Hostnames: []string{"evil.example.com"}}})
	if Equal(a, c) {
		t.Fatal("an added rule compares equal")
	}
	d := &ateapi.EgressPolicy{Rules: []*ateapi.EgressRule{a.Rules[0], {Https: &ateapi.HttpsRule{Hostnames: []string{"c.example.com"}}}}}
	if Equal(a, d) {
		t.Fatal("a removed credential compares equal")
	}
	if r, _ := EgressPolicy(cases[1].in); !Equal(r.Policy, r.Policy) || strings.Contains(Canonical(r.Policy), "00u1abcd") {
		t.Fatal("canonical")
	}
}

func TestPatternHelpers(t *testing.T) {
	if !covered([]string{"*.github.com"}, pattern{Name: "github.com", Wildcard: true}) ||
		!covered([]string{"*.github.com"}, pattern{Name: "a.github.com"}) ||
		covered([]string{"*.github.com"}, pattern{Name: "github.com"}) ||
		covered([]string{"github.com"}, pattern{Name: "github.com", Wildcard: true}) ||
		covered([]string{"*"}, pattern{Name: "x.y"}) {
		t.Fatal("covered")
	}
	b := blockClasses([]string{"gist.github.com", "*.evil.com", "10.0.0.0/8"})
	for p, want := range map[string]bool{
		"gist.github.com": true, "x.gist.github.com": true, "*.github.com": true, "github.com": false,
		"evil.com": false, "a.evil.com": true, "*.evil.com": true, "*.com": false, "10.0.0.1": false,
	} {
		pat, ok := parsePattern(p)
		if !ok {
			if want {
				t.Errorf("%s did not parse", p)
			}
			continue
		}
		if _, hit := anyOverlap(b, pat); hit != want {
			t.Errorf("block overlap %s = %v", p, hit)
		}
	}
	if got := egressspec.EcosystemPacks(); !slices.Equal(got, []string{"crates", "go", "npm", "pypi"}) || len(egressspec.PackHosts("go")) != 2 || egressspec.PackHosts("x") != nil {
		t.Fatalf("packs %v", got)
	}
}
