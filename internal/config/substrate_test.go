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
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	publicschemas "github.com/defenseclaw/defenseclaw/schemas"
)

// schemaItemsProperties is schemaObjectProperties for the item object of
// the array at path.
func schemaItemsProperties(t *testing.T, path ...string) []string {
	t.Helper()
	var schema map[string]any
	if err := json.Unmarshal(publicschemas.DefenseClawConfigV8Schema(), &schema); err != nil {
		t.Fatal(err)
	}
	defs := schema["$defs"].(map[string]any)
	node := schema
	for _, name := range path {
		if ref, ok := node["$ref"].(string); ok {
			node = defs[ref[strings.LastIndex(ref, "/")+1:]].(map[string]any)
		}
		node = node["properties"].(map[string]any)[name].(map[string]any)
	}
	items := node["items"].(map[string]any)
	if open, isBool := items["additionalProperties"].(bool); !isBool || open {
		t.Fatalf("schema items of %v are not closed", path)
	}
	names := map[string]bool{}
	for k := range items["properties"].(map[string]any) {
		names[k] = true
	}
	return sortedKeys(names)
}

func TestSubstrateConfigMatchesTheClosedSchema(t *testing.T) {
	for _, tc := range []struct {
		typ  any
		path []string
	}{
		{SubstrateConfig{}, []string{"substrate"}},
		{SubstrateAPIConfig{}, []string{"substrate", "api"}},
		{SubstrateIdentityConfig{}, []string{"substrate", "identity"}},
		{SubstrateOIDCConfig{}, []string{"substrate", "identity", "oidc"}},
		{SubstrateServicesConfig{}, []string{"substrate", "services"}},
		{SubstrateUnattendedConfig{}, []string{"substrate", "unattended"}},
		{SubstrateRateLimitsConfig{}, []string{"substrate", "rate_limits"}},
		{SubstrateExtprocConfig{}, []string{"substrate", "extproc"}},
		{SubstrateExtprocUIDConfig{}, []string{"substrate", "extproc", "uid"}},
		{SubstrateExtprocChainConfig{}, []string{"substrate", "extproc", "chain"}},
		{SubstrateExtprocAskConfig{}, []string{"substrate", "extproc", "ask"}},
		{SubstrateExtprocJudgeConfig{}, []string{"substrate", "extproc", "judge"}},
		{SubstrateExtprocDLPConfig{}, []string{"substrate", "extproc", "dlp"}},
		{SubstrateLLMConfig{}, []string{"substrate", "llm"}},
		{SubstrateLLMCredentialConfig{}, []string{"substrate", "llm", "credential"}},
		{SubstrateEgressConfig{}, []string{"substrate", "egress"}},
	} {
		got := yamlFieldNames(reflect.TypeOf(tc.typ))
		if want := schemaObjectProperties(t, tc.path...); !reflect.DeepEqual(got, want) {
			t.Errorf("%T yaml keys = %v, schema %v = %v", tc.typ, got, tc.path, want)
		}
	}
	for _, tc := range []struct {
		typ  any
		path []string
	}{
		{SubstrateWorkloadOIDCConfig{}, []string{"substrate", "identity", "workload_oidc"}},
		{SubstrateSecret{}, []string{"substrate", "secrets"}},
	} {
		got := yamlFieldNames(reflect.TypeOf(tc.typ))
		if want := schemaItemsProperties(t, tc.path...); !reflect.DeepEqual(got, want) {
			t.Errorf("%T yaml keys = %v, schema %v items = %v", tc.typ, got, tc.path, want)
		}
	}
	got := yamlFieldNames(reflect.TypeOf(SubstrateSecretInject{}))
	var schema map[string]any
	_ = json.Unmarshal(publicschemas.DefenseClawConfigV8Schema(), &schema)
	inject := schema["$defs"].(map[string]any)["substrate"].(map[string]any)["properties"].(map[string]any)["secrets"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["inject"].(map[string]any)
	var want []string
	for k := range inject["properties"].(map[string]any) {
		want = append(want, k)
	}
	if !reflect.DeepEqual(got, sortedKeys(toSet(want))) || inject["additionalProperties"] != false {
		t.Errorf("SubstrateSecretInject yaml keys = %v, schema = %v", got, want)
	}
}

func toSet(s []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range s {
		m[v] = true
	}
	return m
}

const substrateExample = `config_version: 9
substrate:
  enabled: true
  api: {address: api.ate-system.svc:443, ca_file: /var/run/ate/ca.crt, auth: serviceaccount}
  supported_versions: ">=1.0.0 <1.1.0"
  identity:
    issuer: https://idp.ate-system.svc
    audience: defenseclaw
    token_lifetime_seconds: 900
    actor_cert_oid: 1.3.6.1.4.1.11129.2.12.2
    oidc: {issuer: https://login.example.com, client_id: defenseclaw-launcher, groups_claim: groups}
    workload_oidc: [{issuer: https://token.actions.githubusercontent.com, audience: defenseclaw-prod, claims: {repository: acme/web}}]
  services: {actor: defenseclaw-actor.defenseclaw-system.svc, admin: defenseclaw-admin.defenseclaw-system.svc}
  launcher_atespaces: {engineering: [eng-payments, eng-web]}
  require_attested_templates: true
  default_sandbox_class: gvisor
  idle_suspend_after: 30m
  unattended: {asks: deny, ask_timeout: 30m, telemetry_sampling: 1.0}
  rate_limits: {per_actor_rps: 20, per_atespace_rps: 500}
  extproc:
    enabled: true
    failure_mode: closed
    body_inspection: on
    body_max_bytes: 1048576
    mcp_hosts: [mcp.example.com=docs]
    body_hosts: [api.example.com]
    cluster_domains: [svc.cluster.local]
    actor_trust_domain: cluster.local
    egress_peers: [spiffe://cluster.local/ns/ate-system/sa/atenet-egress]
    request_access: security@example.com
    log_headers: true
    redact_headers: [X-Team-Token]
    blocklist_files: [/etc/defenseclaw/feeds/egress.yaml]
    actor_secrets_dir: /var/run/dc/actor-secrets
    uid: {cache_ttl: 60s, stale_max: 60s}
    chain: {check_budget: 20ms, queue_size: 4096}
    ask: {hold: 1500ms}
    judge: {url: https://defenseclaw-leader.defenseclaw-system.svc/api/v1/substrate/callout/verdict, token_file: /var/run/dc/judge-token, ca_file: /var/run/dc/ca.crt, timeout: 1500ms}
    dlp: {credential_headers: deny}
  llm: {providers: [anthropic, openai, bedrock], credential: {provider_uri: "ate-secret://k8s.io/default/defenseclaw-system/llm-keys"}}
  egress: {allow: [github.com, "*.githubusercontent.com"], ecosystem_packs: [pypi, npm], registries: [ghcr.io]}
  secrets:
    - name: github-push
      source: ate-secret://k8s.io/default/dc-secrets/github-app/token
      inject: {hosts: [github.com, api.github.com], header: Authorization, prefix: "Bearer ", placeholder: DC_SECRET_GITHUB}
      scope: shared
      profiles: [eng-*]
    - name: npm-mine
      source: "ate-secret://k8s.io/default/dc-people/{person}-npm/token"
      inject: {hosts: [registry.npmjs.org], header: Authorization, prefix: "Bearer "}
      scope: per_person
      profiles: ["*"]
  allow_passthrough_for: [pins.example.org]
  admin: {egress_block: [paste.example.com]}
`

func TestSubstrateExampleMatchesSchemaAndValidates(t *testing.T) {
	if err := ValidateV8SchemaBytes("substrate.yaml", []byte(substrateExample)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	for _, bad := range []string{
		"config_version: 9\nsubstrate: {unknown: 1}\n",
		"config_version: 9\nsubstrate: {default_sandbox_class: firecracker}\n",
		"config_version: 9\nsubstrate: {secrets: [{name: a, source: \"vault://x\", inject: {hosts: [a.b], header: X}, profiles: [p]}]}\n",
		"config_version: 9\nsubstrate: {identity: {token_lifetime_seconds: 60}}\n",
		"config_version: 9\nsubstrate: {egress: {ecosystem_packs: [maven]}}\n",
		"config_version: 9\nsubstrate: {launcher_atespaces: {eng: [Eng_Web]}}\n",
	} {
		if err := ValidateV8SchemaBytes("bad.yaml", []byte(bad)); err == nil {
			t.Errorf("schema accepted %q", bad)
		}
	}
}

func validSubstrate() SubstrateConfig {
	return SubstrateConfig{
		Enabled:  true,
		Identity: SubstrateIdentityConfig{Issuer: "https://idp.ate-system.svc"},
		Secrets: []SubstrateSecret{{Name: "gh", Source: "ate-secret://k8s.io/default/ns/gh/token",
			Inject: SubstrateSecretInject{Hosts: []string{"github.com"}, Header: "Authorization", Prefix: "Bearer "}, Profiles: []string{"eng-*"}}},
		LauncherAtespaces: map[string][]string{"eng": {"eng-web"}},
	}
}

func TestSubstrateValidate(t *testing.T) {
	ok := validSubstrate()
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if err := (&SubstrateConfig{}).Validate(); err != nil {
		t.Fatalf("the zero (disabled) section must validate: %v", err)
	}
	cases := map[string]func(*SubstrateConfig){
		"identity.issuer":    func(s *SubstrateConfig) { s.Identity.Issuer = "" },
		"https":              func(s *SubstrateConfig) { s.Identity.Issuer = "http://idp" },
		"api.address":        func(s *SubstrateConfig) { s.API.Address = "api.ate-system.svc" },
		"api.auth":           func(s *SubstrateConfig) { s.API.Auth = "kerberos" },
		"supported_versions": func(s *SubstrateConfig) { s.SupportedVersions = "~1.0" },
		"token_lifetime":     func(s *SubstrateConfig) { s.Identity.TokenLifetimeSeconds = 4000 },
		"actor_cert_oid":     func(s *SubstrateConfig) { s.Identity.ActorCertOID = "1.3.x" },
		"oidc client":        func(s *SubstrateConfig) { s.Identity.OIDC.Issuer = "https://login" },
		"workload audience": func(s *SubstrateConfig) {
			s.Identity.WorkloadOIDC = []SubstrateWorkloadOIDCConfig{{Issuer: "https://t", Claims: map[string]string{"repository": "a/b"}}}
		},
		// GAP-0043: issuer and audience alone trust every repository.
		"workload binding": func(s *SubstrateConfig) {
			s.Identity.WorkloadOIDC = []SubstrateWorkloadOIDCConfig{{Issuer: "https://t", Audience: "dc"}}
		},
		"workload wildcard subject": func(s *SubstrateConfig) {
			s.Identity.WorkloadOIDC = []SubstrateWorkloadOIDCConfig{{Issuer: "https://t", Audience: "dc", Subject: "*"}}
		},
		"workload empty claim": func(s *SubstrateConfig) {
			s.Identity.WorkloadOIDC = []SubstrateWorkloadOIDCConfig{{Issuer: "https://t", Audience: "dc", Claims: map[string]string{"repository": ""}}}
		},
		"services same":             func(s *SubstrateConfig) { s.Services = SubstrateServicesConfig{Actor: "a.svc", Admin: "a.svc"} },
		"services host":             func(s *SubstrateConfig) { s.Services.Actor = "http://x" },
		"atespace name":             func(s *SubstrateConfig) { s.LauncherAtespaces["eng"] = []string{"Eng"} },
		"atespace twice":            func(s *SubstrateConfig) { s.LauncherAtespaces["web"] = []string{"eng-web"} },
		"sandbox class":             func(s *SubstrateConfig) { s.DefaultSandboxClass = "kata" },
		"idle short":                func(s *SubstrateConfig) { s.IdleSuspendAfter = "30s" },
		"idle bad":                  func(s *SubstrateConfig) { s.IdleSuspendAfter = "soon" },
		"asks":                      func(s *SubstrateConfig) { s.Unattended.Asks = "allow" },
		"ask timeout":               func(s *SubstrateConfig) { s.Unattended.AskTimeout = "48h" },
		"sampling":                  func(s *SubstrateConfig) { r := 1.5; s.Unattended.TelemetrySampling = &r },
		"rps":                       func(s *SubstrateConfig) { s.RateLimits.PerActorRPS = -1 },
		"failure mode":              func(s *SubstrateConfig) { s.Extproc.FailureMode = "ignore" },
		"body mode":                 func(s *SubstrateConfig) { s.Extproc.BodyInspection = "always" },
		"body cap":                  func(s *SubstrateConfig) { s.Extproc.BodyMaxBytes = 2 << 20 },
		"mcp host":                  func(s *SubstrateConfig) { s.Extproc.MCPHosts = []string{"*"} },
		"provider uri":              func(s *SubstrateConfig) { s.LLM.Credential.ProviderURI = "sk-live-value" },
		"pack":                      func(s *SubstrateConfig) { s.Egress.EcosystemPacks = []string{"maven"} },
		"allow ip":                  func(s *SubstrateConfig) { s.Egress.Allow = []string{"10.0.0.1"} },
		"secret name":               func(s *SubstrateConfig) { s.Secrets[0].Name = "GH" },
		"secret dup":                func(s *SubstrateConfig) { s.Secrets = append(s.Secrets, s.Secrets[0]) },
		"secret value as source":    func(s *SubstrateConfig) { s.Secrets[0].Source = "ghp_notareference" },
		"secret per_person":         func(s *SubstrateConfig) { s.Secrets[0].Scope = "per_person" },
		"secret shared person":      func(s *SubstrateConfig) { s.Secrets[0].Source = "ate-secret://k8s.io/default/ns/{person}/t" },
		"secret scope":              func(s *SubstrateConfig) { s.Secrets[0].Scope = "team" },
		"secret no hosts":           func(s *SubstrateConfig) { s.Secrets[0].Inject.Hosts = nil },
		"secret header":             func(s *SubstrateConfig) { s.Secrets[0].Inject.Header = "Auth orization" },
		"secret prefix":             func(s *SubstrateConfig) { s.Secrets[0].Inject.Prefix = "x\n" },
		"secret placeholder":        func(s *SubstrateConfig) { s.Secrets[0].Inject.Placeholder = "ghp_123" },
		"secret no profiles":        func(s *SubstrateConfig) { s.Secrets[0].Profiles = nil },
		"secret bad glob":           func(s *SubstrateConfig) { s.Secrets[0].Profiles = []string{"eng-["} },
		"secret on passthrough":     func(s *SubstrateConfig) { s.AllowPassthroughFor = []string{"GitHub.com"} },
		"admin floor (min_profile)": func(s *SubstrateConfig) { s.Admin.MinProfile = "loose" },
	}
	for name, mutate := range cases {
		s := validSubstrate()
		s.LauncherAtespaces = map[string][]string{"eng": {"eng-web"}}
		s.Secrets = append([]SubstrateSecret(nil), s.Secrets...)
		mutate(&s)
		if err := s.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	per := validSubstrate()
	per.Secrets[0].Scope = "per_person"
	per.Secrets[0].Source = "ate-secret://k8s.io/default/people/{person}-gh/token"
	if err := per.Validate(); err != nil {
		t.Errorf("per_person secret refused: %v", err)
	}
	off := validSubstrate()
	off.IdleSuspendAfter = "0s"
	if err := off.Validate(); err != nil || off.EffectiveIdleSuspendAfter() != 0 {
		t.Errorf("idle off: %v %v", err, off.EffectiveIdleSuspendAfter())
	}
}

func TestSubstrateDefaults(t *testing.T) {
	var s SubstrateConfig
	if s.EffectiveSupportedVersions() != ">=1.0.0 <1.1.0" || !s.AttestationRequired() || s.EffectiveSandboxClass() != "gvisor" ||
		s.EffectiveIdleSuspendAfter() != 30*time.Minute || s.EffectiveAsks() != "deny" || s.EffectiveAskTimeout() != 30*time.Minute ||
		s.EffectiveActorService() != DefaultSubstrateActorService || s.EffectiveAdminService() != DefaultSubstrateAdminService ||
		s.EffectiveAudience() != "defenseclaw" || s.EffectiveTokenLifetime() != 900 || len(s.EffectiveEcosystemPacks()) != 4 {
		t.Fatalf("defaults: %+v", s)
	}
	f := false
	s.RequireAttestedTemplates = &f
	s.Egress.EcosystemPacks = []string{}
	if s.AttestationRequired() || len(s.EffectiveEcosystemPacks()) != 0 {
		t.Fatal("explicit false / empty pack list")
	}
	s.LauncherAtespaces = map[string][]string{"eng": {"eng-web"}, "ops": {"ops-a"}}
	if p, ok := s.LauncherAtespace("ops-a"); !ok || p != "ops" {
		t.Fatal("LauncherAtespace")
	}
	if _, ok := s.LauncherAtespace("eng-evil"); ok {
		t.Fatal("a foreign atespace matched")
	}
}

func TestSubstrateVersionRange(t *testing.T) {
	r, err := ParseSubstrateVersionRange(">=1.0.0 <1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	for v, want := range map[string]bool{"v1.0.0": true, "1.0.9": true, "v1.1.0": false, "0.9.9": false, "v1.0.1-rc.1": true, "1.0": false, "x": false} {
		if r.Contains(v) != want {
			t.Errorf("Contains(%s) = %v", v, !want)
		}
	}
	for _, bad := range []string{"", "1.0.0", "~1.0", ">=1.0", ">=a.b.c"} {
		if _, err := ParseSubstrateVersionRange(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestProfileMatchSubstrate(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{"ci": {}}
	cfg.Guardrail.ProfileAssignments = []ProfileAssignment{{Profile: "ci",
		Match: ProfileMatch{Substrate: &ProfileMatchSubstrate{Atespaces: []string{"ci-runs", "eng-*"}, Templates: []string{"ci-runs/claude"}}}}}
	if err := cfg.ValidateGuardrailProfiles(); err != nil {
		t.Fatalf("a substrate-only match was refused: %v", err)
	}
	for name, m := range map[string]*ProfileMatchSubstrate{
		"empty":         {},
		"atespace case": {Atespaces: []string{"CI"}},
		"template form": {Templates: []string{"claude"}},
		"bad glob":      {Atespaces: []string{"eng-["}},
		"workload":      {Workloads: []string{" "}},
	} {
		cfg.Guardrail.ProfileAssignments[0].Match.Substrate = m
		if err := cfg.ValidateGuardrailProfiles(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	doc := "config_version: 9\nguardrail:\n  profiles: {ci: {}}\n  profile_assignments:\n    - {profile: ci, match: {substrate: {atespaces: [ci-runs], templates: [ci-runs/claude], workloads: [repo:org/x]}}}\n"
	if err := ValidateV8SchemaBytes("m.yaml", []byte(doc)); err != nil {
		t.Fatalf("schema: %v", err)
	}
	if err := ValidateV8SchemaBytes("m.yaml", []byte("config_version: 9\nguardrail:\n  profiles: {ci: {}}\n  profile_assignments:\n    - {profile: ci, match: {substrate: {}}}\n")); err == nil {
		t.Fatal("schema accepted an empty substrate match")
	}
}

func TestMCPHostName(t *testing.T) {
	if MCPHostName("mcp.example.com=docs") != "mcp.example.com" || MCPHostName(" a.b ") != "a.b" {
		t.Fatal("MCPHostName")
	}
}
