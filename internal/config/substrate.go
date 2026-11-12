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
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/egressspec"
)

// SubstrateConfig is substrate: (PLAN §7.1), DefenseClaw on Agent Substrate.
// It is additive and off by default; a host install never reads it. The
// controller, gateway listeners, callout and launcher read their keys from
// it, and the chart renders it into the cluster ConfigMap.
type SubstrateConfig struct {
	Enabled bool               `mapstructure:"enabled" yaml:"enabled"`
	API     SubstrateAPIConfig `mapstructure:"api"     yaml:"api,omitempty"`
	// SupportedVersions is the Substrate version range DefenseClaw is
	// tested on (DefaultSubstrateSupportedVersions when empty).
	SupportedVersions string                  `mapstructure:"supported_versions" yaml:"supported_versions,omitempty"`
	Identity          SubstrateIdentityConfig `mapstructure:"identity"           yaml:"identity,omitempty"`
	Services          SubstrateServicesConfig `mapstructure:"services"           yaml:"services,omitempty"`
	// LauncherAtespaces maps a profile to the atespaces DefenseClaw creates
	// and owns for it: only DefenseClaw creates, forks and proxies there,
	// and every actor in them is bound to a verified person.
	LauncherAtespaces map[string][]string `mapstructure:"launcher_atespaces" yaml:"launcher_atespaces,omitempty"`
	// RequireAttestedTemplates (nil = true) gives no network to an actor
	// whose template digest has no valid DefenseClaw attestation.
	RequireAttestedTemplates *bool `mapstructure:"require_attested_templates" yaml:"require_attested_templates,omitempty"`
	// Templates is how the controller verifies template attestations.
	Templates SubstrateTemplatesConfig `mapstructure:"templates" yaml:"templates,omitempty"`
	// DefaultSandboxClass is gvisor (default) or microvm.
	DefaultSandboxClass string `mapstructure:"default_sandbox_class" yaml:"default_sandbox_class,omitempty"`
	// IdleSuspendAfter is a Go duration (default 30m; "0s" turns idle
	// suspend off).
	IdleSuspendAfter string                    `mapstructure:"idle_suspend_after" yaml:"idle_suspend_after,omitempty"`
	Unattended       SubstrateUnattendedConfig `mapstructure:"unattended"         yaml:"unattended,omitempty"`
	RateLimits       SubstrateRateLimitsConfig `mapstructure:"rate_limits"        yaml:"rate_limits,omitempty"`
	Extproc          SubstrateExtprocConfig    `mapstructure:"extproc"            yaml:"extproc,omitempty"`
	LLM              SubstrateLLMConfig        `mapstructure:"llm"                yaml:"llm,omitempty"`
	Egress           SubstrateEgressConfig     `mapstructure:"egress"             yaml:"egress,omitempty"`
	Secrets          []SubstrateSecret         `mapstructure:"secrets"            yaml:"secrets,omitempty"`
	// AllowPassthroughFor lists hosts forwarded without inspection
	// (certificate pinning). A secret is never bound to one.
	AllowPassthroughFor []string `mapstructure:"allow_passthrough_for" yaml:"allow_passthrough_for,omitempty"`
	// Admin is the organization floor for Substrate actors, the same keys
	// as openshell.admin; guardrail profiles tighten it.
	Admin OpenShellAdminConfig `mapstructure:"admin" yaml:"admin,omitempty"`
	// Bundles is signed policy bundles (substrate_bundles.go).
	Bundles SubstrateBundlesConfig `mapstructure:"bundles" yaml:"bundles,omitempty"`
}

// SubstrateTemplatesConfig is how the controller admits templates (PLAN
// §5.3, §6.6): every container image must be pinned by digest and carry a
// DefenseClaw attestation signed by a key in the trust anchors, and its
// repository must be one the allow lists name.
type SubstrateTemplatesConfig struct {
	// TrustAnchors is the PEM trust bundle (an admin-only Secret mount;
	// DefaultSubstrateTemplateAnchors when empty). It is re-read when it
	// changes, so a rotation or revocation applies at the next poll.
	TrustAnchors string `mapstructure:"trust_anchors" yaml:"trust_anchors,omitempty"`
	// MinPolicyGeneration refuses templates scanned under an older policy.
	MinPolicyGeneration int64 `mapstructure:"min_policy_generation" yaml:"min_policy_generation,omitempty"`
	// MaxAge refuses templates built longer ago (Go duration; empty = no limit).
	MaxAge string `mapstructure:"max_age" yaml:"max_age,omitempty"`
	// AllowUnverifiedBase admits a template whose base image is neither
	// allowlisted nor attested (default false).
	AllowUnverifiedBase bool `mapstructure:"allow_unverified_base" yaml:"allow_unverified_base,omitempty"`
	// AllowedImages are repository globs ("registry/team/*") an attested
	// container image must match; empty allows any attested image.
	AllowedImages []string `mapstructure:"allowed_images" yaml:"allowed_images,omitempty"`
	// ProfileImages narrows AllowedImages per DefenseClaw profile: an actor
	// whose profile is listed may run only images matching its globs.
	ProfileImages map[string][]string `mapstructure:"profile_images" yaml:"profile_images,omitempty"`
	// VolumeImages are repository globs a template may mount as read-only
	// image volumes without an attestation; any other image volume refuses
	// the template.
	VolumeImages []string `mapstructure:"volume_images" yaml:"volume_images,omitempty"`
	// PlainHTTPRegistries are registry host:port names reached over plain
	// HTTP (an in-cluster dev registry only).
	PlainHTTPRegistries []string `mapstructure:"plain_http_registries" yaml:"plain_http_registries,omitempty"`
	// RevokedDigests are image digests (sha256:...) never admitted again,
	// whatever their attestation says.
	RevokedDigests []string `mapstructure:"revoked_digests" yaml:"revoked_digests,omitempty"`
}

// EffectiveTrustAnchors is TrustAnchors or the chart's Secret mount path.
func (t SubstrateTemplatesConfig) EffectiveTrustAnchors() string {
	return orDefault(t.TrustAnchors, DefaultSubstrateTemplateAnchors)
}

// EffectiveMaxAge is MaxAge, zero when empty or invalid (Validate refuses
// an invalid one).
func (t SubstrateTemplatesConfig) EffectiveMaxAge() time.Duration {
	return durationOr(t.MaxAge, 0)
}

// SubstrateAPIConfig is how DefenseClaw reaches ate-api-server.
type SubstrateAPIConfig struct {
	Address    string `mapstructure:"address"     yaml:"address,omitempty"`
	ServerName string `mapstructure:"server_name" yaml:"server_name,omitempty"`
	CAFile     string `mapstructure:"ca_file"     yaml:"ca_file,omitempty"`
	// Auth is serviceaccount (a projected token, default) or mtls (a pod
	// certificate).
	Auth             string `mapstructure:"auth"              yaml:"auth,omitempty"`
	TokenFile        string `mapstructure:"token_file"        yaml:"token_file,omitempty"`
	CredentialBundle string `mapstructure:"credential_bundle" yaml:"credential_bundle,omitempty"`
}

// SubstrateIdentityConfig is how actor JWTs and people are verified.
type SubstrateIdentityConfig struct {
	// Issuer is the cluster's actor JWT issuer; it must be unique per
	// cluster (E13).
	Issuer               string `mapstructure:"issuer"                 yaml:"issuer,omitempty"`
	Audience             string `mapstructure:"audience"               yaml:"audience,omitempty"`
	TokenLifetimeSeconds int64  `mapstructure:"token_lifetime_seconds" yaml:"token_lifetime_seconds,omitempty"`
	// ActorCertOID is the ActorIdentity extension OID in actor
	// certificates (it changes after the CNCF donation).
	ActorCertOID string                        `mapstructure:"actor_cert_oid" yaml:"actor_cert_oid,omitempty"`
	OIDC         SubstrateOIDCConfig           `mapstructure:"oidc"           yaml:"oidc,omitempty"`
	WorkloadOIDC []SubstrateWorkloadOIDCConfig `mapstructure:"workload_oidc" yaml:"workload_oidc,omitempty"`
}

// SubstrateOIDCConfig is the people's identity provider (launcher sign-in).
type SubstrateOIDCConfig struct {
	Issuer      string `mapstructure:"issuer"       yaml:"issuer,omitempty"`
	ClientID    string `mapstructure:"client_id"    yaml:"client_id,omitempty"`
	GroupsClaim string `mapstructure:"groups_claim" yaml:"groups_claim,omitempty"`
}

// SubstrateWorkloadOIDCConfig trusts a CI identity provider for unattended
// launches.
type SubstrateWorkloadOIDCConfig struct {
	Issuer   string `mapstructure:"issuer"   yaml:"issuer"`
	Audience string `mapstructure:"audience" yaml:"audience"`
	// Subject and Claims bind the entry to the workloads it trusts; at
	// least one is required, since a CI issuer signs tokens for every
	// repository (GAP-0043). Subject is exact, or a prefix when it ends
	// in "*"; Claims are top-level string claims compared exactly (for
	// GitHub Actions: repository, ref, environment).
	Subject string            `mapstructure:"subject" yaml:"subject,omitempty"`
	Claims  map[string]string `mapstructure:"claims"  yaml:"claims,omitempty"`
}

// SubstrateServicesConfig names the gateway's two Services (D15).
type SubstrateServicesConfig struct {
	Actor string `mapstructure:"actor" yaml:"actor,omitempty"`
	Admin string `mapstructure:"admin" yaml:"admin,omitempty"`
}

// SubstrateUnattendedConfig governs --task and --batch runs (D8, D12).
type SubstrateUnattendedConfig struct {
	// Asks is deny (default) or queue.
	Asks       string `mapstructure:"asks"        yaml:"asks,omitempty"`
	AskTimeout string `mapstructure:"ask_timeout" yaml:"ask_timeout,omitempty"`
	// TelemetrySampling is the share of routine records kept (blocks and
	// lifecycle events are never sampled); nil = 1.0.
	TelemetrySampling *float64 `mapstructure:"telemetry_sampling" yaml:"telemetry_sampling,omitempty"`
}

// SubstrateRateLimitsConfig is the actor listener's fair-share limits (E11).
type SubstrateRateLimitsConfig struct {
	PerActorRPS    float64 `mapstructure:"per_actor_rps"    yaml:"per_actor_rps,omitempty"`
	PerAtespaceRPS float64 `mapstructure:"per_atespace_rps" yaml:"per_atespace_rps,omitempty"`
}

// SubstrateExtprocConfig is the egress callout (D9, D10), lane A4's
// substrate-extproc. The chart renders its file from these keys plus the
// profiles, secrets and services; the callout validates the same bounds
// (extproc.Config).
type SubstrateExtprocConfig struct {
	Enabled *bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// FailureMode is closed (default) or open when the callout can't
	// decide; managed installs are always closed.
	FailureMode string `mapstructure:"failure_mode" yaml:"failure_mode,omitempty"`
	// BodyInspection is auto (default: when the egress filter allows the
	// body override, detected at run time), on or off.
	BodyInspection string `mapstructure:"body_inspection" yaml:"body_inspection,omitempty"`
	BodyMaxBytes   int    `mapstructure:"body_max_bytes"  yaml:"body_max_bytes,omitempty"`
	// MCPHosts are the remote MCP servers whose JSON-RPC bodies are
	// inspected, "host" or "host=name" (the MCP server name tool rules
	// see). They are also allowed in every actor's egress policy.
	MCPHosts []string `mapstructure:"mcp_hosts" yaml:"mcp_hosts,omitempty"`
	// BodyHosts are other admin-listed hosts whose bodies get the DLP scans.
	BodyHosts []string `mapstructure:"body_hosts" yaml:"body_hosts,omitempty"`
	// ClusterDomains are in-cluster name suffixes the intranet rule must not
	// refuse (default svc.cluster.local).
	ClusterDomains []string `mapstructure:"cluster_domains" yaml:"cluster_domains,omitempty"`
	// ActorTrustDomain is the SPIFFE trust domain of actor identities and
	// EgressPeers the SPIFFE IDs allowed to call the callout (defaults are
	// the callout's).
	ActorTrustDomain string   `mapstructure:"actor_trust_domain" yaml:"actor_trust_domain,omitempty"`
	EgressPeers      []string `mapstructure:"egress_peers"       yaml:"egress_peers,omitempty"`
	// RequestAccess is the contact refusals name.
	RequestAccess string `mapstructure:"request_access" yaml:"request_access,omitempty"`
	// LogHeaders adds the request headers, redacted, to every event;
	// RedactHeaders are extra header names always redacted.
	LogHeaders    bool     `mapstructure:"log_headers"    yaml:"log_headers,omitempty"`
	RedactHeaders []string `mapstructure:"redact_headers" yaml:"redact_headers,omitempty"`
	// BlocklistFiles replace the built-in egress feed.
	BlocklistFiles []string `mapstructure:"blocklist_files" yaml:"blocklist_files,omitempty"`
	// ActorSecretsDir holds the profiles' actor_secrets values, one file per
	// name (a mounted Secret).
	ActorSecretsDir string                      `mapstructure:"actor_secrets_dir" yaml:"actor_secrets_dir,omitempty"`
	UID             SubstrateExtprocUIDConfig   `mapstructure:"uid"   yaml:"uid,omitempty"`
	Chain           SubstrateExtprocChainConfig `mapstructure:"chain" yaml:"chain,omitempty"`
	Ask             SubstrateExtprocAskConfig   `mapstructure:"ask"   yaml:"ask,omitempty"`
	Judge           SubstrateExtprocJudgeConfig `mapstructure:"judge" yaml:"judge,omitempty"`
	DLP             SubstrateExtprocDLPConfig   `mapstructure:"dlp"   yaml:"dlp,omitempty"`
}

// SubstrateExtprocUIDConfig is the live-UID cache (Go durations; defaults
// 60s and 60s, at most 10m).
type SubstrateExtprocUIDConfig struct {
	CacheTTL string `mapstructure:"cache_ttl" yaml:"cache_ttl,omitempty"`
	StaleMax string `mapstructure:"stale_max" yaml:"stale_max,omitempty"`
}

// SubstrateExtprocChainConfig bounds the egress chain check (default 20ms,
// at most 500ms) and the observed_egress queue (default 4096).
type SubstrateExtprocChainConfig struct {
	CheckBudget string `mapstructure:"check_budget" yaml:"check_budget,omitempty"`
	QueueSize   int    `mapstructure:"queue_size"   yaml:"queue_size,omitempty"`
}

// SubstrateExtprocAskConfig is how long a request waits for an ask
// (default 1.5s; keep it under the egress filter's 2 s message timeout).
type SubstrateExtprocAskConfig struct {
	Hold string `mapstructure:"hold" yaml:"hold,omitempty"`
}

// SubstrateExtprocJudgeConfig is the gateway's callout verdict route.
type SubstrateExtprocJudgeConfig struct {
	URL       string `mapstructure:"url"        yaml:"url,omitempty"`
	TokenFile string `mapstructure:"token_file" yaml:"token_file,omitempty"`
	CAFile    string `mapstructure:"ca_file"    yaml:"ca_file,omitempty"`
	Timeout   string `mapstructure:"timeout"    yaml:"timeout,omitempty"`
}

// SubstrateExtprocDLPConfig: CredentialHeaders is alert (default) or deny
// for a secret-shaped credential header on a host no secret is bound to.
type SubstrateExtprocDLPConfig struct {
	CredentialHeaders string `mapstructure:"credential_headers" yaml:"credential_headers,omitempty"`
}

// MCPHostName is the host part of an extproc.mcp_hosts entry ("host" or
// "host=name").
func MCPHostName(entry string) string {
	host, _, _ := strings.Cut(entry, "=")
	return strings.TrimSpace(host)
}

// SubstrateLLMConfig is the model traffic of actors, always through the
// DefenseClaw proxy (D2).
type SubstrateLLMConfig struct {
	Providers  []string                     `mapstructure:"providers"  yaml:"providers,omitempty"`
	Credential SubstrateLLMCredentialConfig `mapstructure:"credential" yaml:"credential,omitempty"`
}

// SubstrateLLMCredentialConfig is where the proxy reads provider keys.
type SubstrateLLMCredentialConfig struct {
	ProviderURI string `mapstructure:"provider_uri" yaml:"provider_uri,omitempty"`
}

// SubstrateEgressConfig is the base egress every actor gets before its
// profile tightens it.
type SubstrateEgressConfig struct {
	Allow []string `mapstructure:"allow" yaml:"allow,omitempty"`
	// EcosystemPacks (nil = every pack) names package-index packs.
	EcosystemPacks []string `mapstructure:"ecosystem_packs" yaml:"ecosystem_packs,omitempty"`
	Registries     []string `mapstructure:"registries"      yaml:"registries,omitempty"`
}

// SubstrateSecret is one entry of substrate.secrets (PLAN §7.2). The value
// never enters an actor: egress replaces the placeholder header on the
// bound hosts.
type SubstrateSecret struct {
	Name   string                `mapstructure:"name"   yaml:"name"`
	Source string                `mapstructure:"source" yaml:"source"`
	Inject SubstrateSecretInject `mapstructure:"inject" yaml:"inject"`
	// Scope is shared (default) or per_person.
	Scope    string   `mapstructure:"scope"    yaml:"scope,omitempty"`
	Profiles []string `mapstructure:"profiles" yaml:"profiles"`
}

// SubstrateSecretInject is where and how a secret is injected.
type SubstrateSecretInject struct {
	Hosts  []string `mapstructure:"hosts"  yaml:"hosts"`
	Header string   `mapstructure:"header" yaml:"header"`
	Prefix string   `mapstructure:"prefix" yaml:"prefix,omitempty"`
	// Placeholder is the environment variable the actor carries in place
	// of the value.
	Placeholder string `mapstructure:"placeholder" yaml:"placeholder,omitempty"`
}

// Substrate defaults.
const (
	DefaultSubstrateAPIAddress        = "api.ate-system.svc:443"
	DefaultSubstrateSupportedVersions = ">=1.0.0 <1.1.0"
	DefaultSubstrateAudience          = "defenseclaw"
	// DefaultSubstrateTokenLifetime is also the most: egress caches an actor JWT
	// by actor name, so a recreated same-name actor gets the old one until
	// it expires (GAP-0133); 300 s is the upstream minimum.
	DefaultSubstrateTokenLifetime = 300
	DefaultSubstrateActorCertOID  = "1.3.6.1.4.1.11129.2.12.2"
	// The Service defaults are fully qualified: the egress DNS relay answers
	// only names an actor's policy lists, so the rule, the kit's URLs and
	// the request Host must all be this one spelling (GAP-0023).
	DefaultSubstrateActorService     = "defenseclaw-actor.defenseclaw-system.svc.cluster.local"
	DefaultSubstrateAdminService     = "defenseclaw-admin.defenseclaw-system.svc.cluster.local"
	DefaultSubstrateIdleSuspendAfter = 30 * time.Minute
	DefaultSubstrateAskTimeout       = 30 * time.Minute
	DefaultSubstratePerActorRPS      = 20
	DefaultSubstratePerAtespaceRPS   = 500
	DefaultSubstrateBodyMaxBytes     = 1 << 20
	// DefaultSubstrateTemplateAnchors is where the chart mounts the
	// admin-only template trust anchors Secret.
	DefaultSubstrateTemplateAnchors = "/etc/defenseclaw/substrate/template-anchors/anchors.pem"

	SubstrateSandboxGVisor  = "gvisor"
	SubstrateSandboxMicroVM = "microvm"
	SubstrateAsksDeny       = "deny"
	SubstrateAsksQueue      = "queue"
	SubstrateFailClosed     = "closed"
	SubstrateFailOpen       = "open"
	SubstrateBodyAuto       = "auto"
	SubstrateBodyOn         = "on"
	SubstrateBodyOff        = "off"
)

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return strings.TrimSpace(v)
}

// EffectiveSupportedVersions is SupportedVersions or the default.
func (s SubstrateConfig) EffectiveSupportedVersions() string {
	return orDefault(s.SupportedVersions, DefaultSubstrateSupportedVersions)
}

// AttestationRequired reports require_attested_templates (default true).
func (s SubstrateConfig) AttestationRequired() bool {
	return s.RequireAttestedTemplates == nil || *s.RequireAttestedTemplates
}

// EffectiveSandboxClass is DefaultSandboxClass or gvisor (D7).
func (s SubstrateConfig) EffectiveSandboxClass() string {
	return strings.ToLower(orDefault(s.DefaultSandboxClass, SubstrateSandboxGVisor))
}

// EffectiveIdleSuspendAfter is the idle suspend delay; zero means off.
func (s SubstrateConfig) EffectiveIdleSuspendAfter() time.Duration {
	return durationOr(s.IdleSuspendAfter, DefaultSubstrateIdleSuspendAfter)
}

func durationOr(v string, def time.Duration) time.Duration {
	if strings.TrimSpace(v) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return d
}

// EffectiveActorService and EffectiveAdminService are the Service hosts.
func (s SubstrateConfig) EffectiveActorService() string {
	return orDefault(s.Services.Actor, DefaultSubstrateActorService)
}

func (s SubstrateConfig) EffectiveAdminService() string {
	return orDefault(s.Services.Admin, DefaultSubstrateAdminService)
}

// EffectiveAudience and EffectiveTokenLifetime shape the actor JWT.
func (s SubstrateConfig) EffectiveAudience() string {
	return orDefault(s.Identity.Audience, DefaultSubstrateAudience)
}

func (s SubstrateConfig) EffectiveTokenLifetime() int64 {
	if s.Identity.TokenLifetimeSeconds == 0 {
		return DefaultSubstrateTokenLifetime
	}
	return s.Identity.TokenLifetimeSeconds
}

// EffectiveEcosystemPacks is egress.ecosystem_packs, or every pack when
// unset.
func (s SubstrateConfig) EffectiveEcosystemPacks() []string {
	if s.Egress.EcosystemPacks == nil {
		return egressspec.EcosystemPacks()
	}
	return slices.Clone(s.Egress.EcosystemPacks)
}

// EffectiveAsks is unattended.asks or deny (D12).
func (s SubstrateConfig) EffectiveAsks() string {
	return strings.ToLower(orDefault(s.Unattended.Asks, SubstrateAsksDeny))
}

// EffectiveAskTimeout is unattended.ask_timeout or 30m.
func (s SubstrateConfig) EffectiveAskTimeout() time.Duration {
	return durationOr(s.Unattended.AskTimeout, DefaultSubstrateAskTimeout)
}

// LauncherAtespace reports whether atespace is one DefenseClaw owns, and
// the profile it belongs to.
func (s SubstrateConfig) LauncherAtespace(atespace string) (string, bool) {
	for _, profile := range sortedKeys(s.LauncherAtespaces) {
		if slices.Contains(s.LauncherAtespaces[profile], atespace) {
			return profile, true
		}
	}
	return "", false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

var (
	substrateOIDRe          = regexp.MustCompile(`^[0-2](\.(0|[1-9][0-9]*))+$`)
	substratePlaceholderRe  = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)
	substrateProfileRe      = regexp.MustCompile(`^[A-Za-z0-9_.*?\[\]-]+$`)
	substrateAtespaceGlobRe = regexp.MustCompile(`^[a-z0-9*?\[\]-]{1,63}$`)
)

// Validate checks substrate: whether or not it is enabled, so a typo fails
// at load and not when the controller starts. Errors name the key.
func (s *SubstrateConfig) Validate() error {
	if s == nil {
		return nil
	}
	var errs []error
	bad := func(key, format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s: %s", key, fmt.Sprintf(format, a...)))
	}

	if a := s.API.Address; a != "" {
		if _, port, err := net.SplitHostPort(a); err != nil || port == "" {
			bad("api.address", "%q must be host:port", a)
		}
	}
	if sn := s.API.ServerName; sn != "" && !egressspec.IsHostname(sn) {
		bad("api.server_name", "%q is not a host name", sn)
	}
	switch strings.ToLower(strings.TrimSpace(s.API.Auth)) {
	case "", "serviceaccount", "mtls":
	default:
		bad("api.auth", "%q must be serviceaccount or mtls", s.API.Auth)
	}
	if _, err := ParseSubstrateVersionRange(s.EffectiveSupportedVersions()); err != nil {
		bad("supported_versions", "%v", err)
	}

	id := s.Identity
	if id.Issuer != "" && !httpsURL(id.Issuer) {
		bad("identity.issuer", "%q must be an https URL", id.Issuer)
	}
	if s.Enabled && id.Issuer == "" {
		bad("identity.issuer", "is required when substrate is enabled (unique per cluster)")
	}
	if l := id.TokenLifetimeSeconds; l != 0 && l != DefaultSubstrateTokenLifetime {
		bad("identity.token_lifetime_seconds", "%d must be 300: egress caches the actor token by actor name, so a recreated actor would get the old one longer (GAP-0133)", l)
	}
	if aud := id.Audience; aud != "" && len(aud) > 512 {
		bad("identity.audience", "is longer than 512 bytes")
	}
	if oid := id.ActorCertOID; oid != "" && !substrateOIDRe.MatchString(oid) {
		bad("identity.actor_cert_oid", "%q is not a dotted OID", oid)
	}
	if o := id.OIDC; o.Issuer != "" || o.ClientID != "" {
		if !httpsURL(o.Issuer) {
			bad("identity.oidc.issuer", "%q must be an https URL", o.Issuer)
		}
		if strings.TrimSpace(o.ClientID) == "" {
			bad("identity.oidc.client_id", "is required with identity.oidc.issuer")
		}
	}
	for i, w := range id.WorkloadOIDC {
		if !httpsURL(w.Issuer) {
			bad(fmt.Sprintf("identity.workload_oidc[%d].issuer", i), "%q must be an https URL", w.Issuer)
		}
		if strings.TrimSpace(w.Audience) == "" {
			bad(fmt.Sprintf("identity.workload_oidc[%d].audience", i), "is required (use one unique to this install)")
		}
		if strings.Trim(strings.TrimSpace(w.Subject), "*") == "" && len(w.Claims) == 0 {
			bad(fmt.Sprintf("identity.workload_oidc[%d]", i),
				"needs subject or claims naming the trusted workloads (for example claims: {repository: acme/web}); the issuer signs tokens for every repository")
		}
		for k, v := range w.Claims {
			if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
				bad(fmt.Sprintf("identity.workload_oidc[%d].claims", i), "keys and values must not be empty")
			}
		}
	}

	actorSvc, adminSvc := s.EffectiveActorService(), s.EffectiveAdminService()
	if !egressspec.IsHostname(actorSvc) {
		bad("services.actor", "%q is not a host name", actorSvc)
	}
	if !egressspec.IsHostname(adminSvc) {
		bad("services.admin", "%q is not a host name", adminSvc)
	}
	if actorSvc == adminSvc {
		bad("services", "actor and admin must be different Services (D15)")
	}

	owner := map[string]string{}
	for _, profile := range sortedKeys(s.LauncherAtespaces) {
		if strings.TrimSpace(profile) == "" {
			bad("launcher_atespaces", "a profile name is empty")
		}
		for _, ns := range s.LauncherAtespaces[profile] {
			key := fmt.Sprintf("launcher_atespaces.%s", profile)
			switch {
			case !egressspec.IsDNS1123Label(ns):
				bad(key, "%q is not an atespace name", ns)
			case owner[ns] != "" && owner[ns] != profile:
				bad(key, "%q is already listed for %s", ns, owner[ns])
			}
			owner[ns] = profile
		}
	}

	switch s.EffectiveSandboxClass() {
	case SubstrateSandboxGVisor, SubstrateSandboxMicroVM:
	default:
		bad("default_sandbox_class", "%q must be gvisor or microvm", s.DefaultSandboxClass)
	}
	if v := s.IdleSuspendAfter; v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err != nil || d < 0 || (d > 0 && d < time.Minute) {
			bad("idle_suspend_after", "%q must be a Go duration of at least 1m, or 0s for off", v)
		}
	}
	switch s.EffectiveAsks() {
	case SubstrateAsksDeny, SubstrateAsksQueue:
	default:
		bad("unattended.asks", "%q must be deny or queue", s.Unattended.Asks)
	}
	if v := s.Unattended.AskTimeout; v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err != nil || d <= 0 || d > 24*time.Hour {
			bad("unattended.ask_timeout", "%q must be a Go duration over 0 and at most 24h", v)
		}
	}
	if r := s.Unattended.TelemetrySampling; r != nil && (*r < 0 || *r > 1) {
		bad("unattended.telemetry_sampling", "%v is outside 0-1", *r)
	}
	if s.RateLimits.PerActorRPS < 0 {
		bad("rate_limits.per_actor_rps", "must not be negative")
	}
	if s.RateLimits.PerAtespaceRPS < 0 {
		bad("rate_limits.per_atespace_rps", "must not be negative")
	}

	switch strings.ToLower(orDefault(s.Extproc.FailureMode, SubstrateFailClosed)) {
	case SubstrateFailClosed, SubstrateFailOpen:
	default:
		bad("extproc.failure_mode", "%q must be closed or open", s.Extproc.FailureMode)
	}
	switch strings.ToLower(orDefault(s.Extproc.BodyInspection, SubstrateBodyAuto)) {
	case SubstrateBodyAuto, SubstrateBodyOn, SubstrateBodyOff:
	default:
		bad("extproc.body_inspection", "%q must be auto, on or off", s.Extproc.BodyInspection)
	}
	if n := s.Extproc.BodyMaxBytes; n < 0 || n > DefaultSubstrateBodyMaxBytes {
		bad("extproc.body_max_bytes", "%d is outside 0-%d (D9 caps bodies at 1 MiB)", n, DefaultSubstrateBodyMaxBytes)
	}
	checkPatterns := func(key string, hosts []string) {
		for i, h := range hosts {
			if p, ok := egressspec.ParsePattern(h); !ok || p.Any {
				bad(fmt.Sprintf("%s[%d]", key, i), `%q must be a host name or "*.<host>"`, h)
			}
		}
	}
	for i, h := range s.Extproc.MCPHosts {
		host, name, named := strings.Cut(h, "=")
		if p, ok := egressspec.ParsePattern(host); !ok || p.Any || (named && strings.TrimSpace(name) == "") {
			bad(fmt.Sprintf("extproc.mcp_hosts[%d]", i), `%q must be "host", "*.<host>" or "host=<mcp server name>"`, h)
		}
	}
	s.validateExtproc(bad, checkPatterns)

	for i, p := range s.LLM.Providers {
		if strings.TrimSpace(p) == "" || strings.ContainsAny(p, " /:") {
			bad(fmt.Sprintf("llm.providers[%d]", i), "%q is not a provider name", p)
		}
	}
	if u := s.LLM.Credential.ProviderURI; u != "" && !egressspec.ValidCredentialURI(u) {
		bad("llm.credential.provider_uri", "must be ate-secret://<provider-class>/<provider-name>/<path>")
	}

	checkPatterns("egress.allow", s.Egress.Allow)
	checkPatterns("egress.registries", s.Egress.Registries)
	checkPatterns("allow_passthrough_for", s.AllowPassthroughFor)
	known := egressspec.EcosystemPacks()
	for i, p := range s.Egress.EcosystemPacks {
		if !slices.Contains(known, p) {
			bad(fmt.Sprintf("egress.ecosystem_packs[%d]", i), "%q is not one of %s", p, strings.Join(known, ", "))
		}
	}

	passthrough := map[string]bool{}
	for _, h := range s.AllowPassthroughFor {
		if p, ok := egressspec.ParsePattern(h); ok {
			passthrough[p.String()] = true
		}
	}
	names := map[string]bool{}
	for i, sec := range s.Secrets {
		key := fmt.Sprintf("secrets[%d]", i)
		if !egressspec.IsDNS1123Subdomain(sec.Name) {
			bad(key+".name", "%q must be lower case letters, digits, '-' and '.'", sec.Name)
		} else if names[sec.Name] {
			bad(key+".name", "%q is listed twice", sec.Name)
		}
		names[sec.Name] = true
		scope := orDefault(sec.Scope, egressspec.ScopeShared)
		hasPerson := strings.Contains(sec.Source, egressspec.PersonPlaceholder)
		switch {
		case scope != egressspec.ScopeShared && scope != egressspec.ScopePerPerson:
			bad(key+".scope", "%q must be shared or per_person", sec.Scope)
		case scope == egressspec.ScopePerPerson && !hasPerson:
			bad(key+".source", "a per_person source must contain %s", egressspec.PersonPlaceholder)
		case scope == egressspec.ScopeShared && hasPerson:
			bad(key+".source", "a shared source must not contain %s", egressspec.PersonPlaceholder)
		}
		src := strings.ReplaceAll(sec.Source, egressspec.PersonPlaceholder, "p-0")
		if !egressspec.ValidCredentialURI(src) {
			bad(key+".source", "must be ate-secret://<provider-class>/<provider-name>/<path> (a reference, never a value)")
		}
		if len(sec.Inject.Hosts) == 0 {
			bad(key+".inject.hosts", "needs at least one host")
		}
		checkPatterns(key+".inject.hosts", sec.Inject.Hosts)
		for _, h := range sec.Inject.Hosts {
			if p, ok := egressspec.ParsePattern(h); ok && passthrough[p.String()] {
				bad(key+".inject.hosts", "%q is in allow_passthrough_for; a secret is never sent without inspection", h)
			}
		}
		if !egressspec.ValidHeaderName(sec.Inject.Header) {
			bad(key+".inject.header", "%q is not an HTTP header name", sec.Inject.Header)
		}
		if !egressspec.ValidHeaderValue(sec.Inject.Prefix) {
			bad(key+".inject.prefix", "holds a control character")
		}
		if ph := sec.Inject.Placeholder; ph != "" && !substratePlaceholderRe.MatchString(ph) {
			bad(key+".inject.placeholder", "%q must be an environment variable name", ph)
		}
		if len(sec.Profiles) == 0 {
			bad(key+".profiles", "needs at least one profile name or glob")
		}
		for _, g := range sec.Profiles {
			if _, err := path.Match(g, ""); err != nil || !substrateProfileRe.MatchString(g) {
				bad(key+".profiles", "%q is not a profile name or glob", g)
			}
		}
	}

	s.validateTemplates(bad)

	s.Bundles.validate(bad)
	if err := s.Admin.validateAs("admin"); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (s *SubstrateConfig) validateTemplates(bad func(key, format string, a ...any)) {
	t := s.Templates
	if g := t.MinPolicyGeneration; g < 0 {
		bad("templates.min_policy_generation", "%d must not be negative", g)
	}
	if v := strings.TrimSpace(t.MaxAge); v != "" {
		if d, err := time.ParseDuration(v); err != nil || d < 0 {
			bad("templates.max_age", "%q must be a Go duration of 0 or more", t.MaxAge)
		}
	}
	globs := func(key string, list []string) {
		for i, g := range list {
			slash := strings.LastIndex(g, "/")
			if slash <= 0 || strings.ContainsAny(g, "@ ") || strings.Contains(g[slash:], ":") {
				bad(fmt.Sprintf("%s[%d]", key, i), "%q must be a repository glob (registry/path, no tag or digest)", g)
				continue
			}
			if _, err := path.Match(g, ""); err != nil {
				bad(fmt.Sprintf("%s[%d]", key, i), "%q is not a valid glob", g)
			}
		}
	}
	globs("templates.allowed_images", t.AllowedImages)
	for i, g := range t.AllowedImages {
		if host, _, _ := strings.Cut(g, "/"); strings.ContainsAny(host, "*?[") {
			bad(fmt.Sprintf("templates.allowed_images[%d]", i), "%q: name the registry host exactly (the controller connects only to named hosts); globs go in the path", g)
		}
	}
	globs("templates.volume_images", t.VolumeImages)
	for _, p := range sortedKeys(t.ProfileImages) {
		if !substrateProfileRe.MatchString(p) {
			bad("templates.profile_images", "%q is not a profile name", p)
		}
		if len(t.ProfileImages[p]) == 0 {
			bad("templates.profile_images."+p, "needs at least one repository glob")
		}
		globs("templates.profile_images."+p, t.ProfileImages[p])
	}
	for i, d := range t.RevokedDigests {
		if !substrateDigestRe.MatchString(strings.ToLower(strings.TrimSpace(d))) {
			bad(fmt.Sprintf("templates.revoked_digests[%d]", i), "%q must be sha256:<64 hex>", d)
		}
	}
	for i, h := range t.PlainHTTPRegistries {
		if host, port, err := net.SplitHostPort(h); err != nil || host == "" || port == "" {
			bad(fmt.Sprintf("templates.plain_http_registries[%d]", i), "%q must be host:port", h)
		}
	}
}

var substrateDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateManaged applies the managed-enterprise rules (D8): the callout
// always fails closed, templates are always attested, and the template
// registries are named (GAP-0131).
func (s *SubstrateConfig) ValidateManaged(deploymentMode string) error {
	if s == nil || !strings.EqualFold(strings.TrimSpace(deploymentMode), string(DeploymentModeManagedEnterprise)) {
		return nil
	}
	var errs []error
	if strings.EqualFold(strings.TrimSpace(s.Extproc.FailureMode), SubstrateFailOpen) {
		errs = append(errs, errors.New(`extproc.failure_mode: "open" is not allowed in managed_enterprise (the callout always fails closed)`))
	}
	if s.Enabled && !s.AttestationRequired() {
		errs = append(errs, errors.New("require_attested_templates: false is not allowed in managed_enterprise"))
	}
	if s.Enabled && len(s.Templates.AllowedImages) == 0 {
		errs = append(errs, errors.New("templates.allowed_images: managed_enterprise names the template registries and repositories"))
	}
	return errors.Join(errs...)
}

func (s *SubstrateConfig) validateExtproc(bad func(key, format string, a ...any), checkPatterns func(string, []string)) {
	e := s.Extproc
	checkPatterns("extproc.body_hosts", e.BodyHosts)
	for i, d := range e.ClusterDomains {
		if !egressspec.IsDNS1123Subdomain(strings.TrimPrefix(strings.ToLower(d), ".")) {
			bad(fmt.Sprintf("extproc.cluster_domains[%d]", i), "%q is not a DNS suffix", d)
		}
	}
	if td := e.ActorTrustDomain; td != "" && !egressspec.IsDNS1123Subdomain(td) {
		bad("extproc.actor_trust_domain", "%q is not a SPIFFE trust domain", td)
	}
	for i, p := range e.EgressPeers {
		if u, err := url.Parse(p); err != nil || u.Scheme != "spiffe" || u.Host == "" {
			bad(fmt.Sprintf("extproc.egress_peers[%d]", i), "%q is not a SPIFFE ID", p)
		}
	}
	for i, h := range e.RedactHeaders {
		if !egressspec.ValidHeaderName(h) {
			bad(fmt.Sprintf("extproc.redact_headers[%d]", i), "%q is not an HTTP header name", h)
		}
	}
	for i, f := range e.BlocklistFiles {
		if strings.TrimSpace(f) == "" {
			bad(fmt.Sprintf("extproc.blocklist_files[%d]", i), "an entry is empty")
		}
	}
	for _, d := range []struct {
		key, v string
		max    time.Duration
	}{
		{"extproc.uid.cache_ttl", e.UID.CacheTTL, 10 * time.Minute},
		{"extproc.uid.stale_max", e.UID.StaleMax, 10 * time.Minute},
		{"extproc.chain.check_budget", e.Chain.CheckBudget, 500 * time.Millisecond},
		{"extproc.ask.hold", e.Ask.Hold, time.Hour},
		{"extproc.judge.timeout", e.Judge.Timeout, time.Hour},
	} {
		if d.v == "" {
			continue
		}
		if v, err := time.ParseDuration(strings.TrimSpace(d.v)); err != nil || v < 0 || v > d.max {
			bad(d.key, "%q must be a Go duration from 0 to %s", d.v, d.max)
		}
	}
	if q := e.Chain.QueueSize; q < 0 || q > 1<<20 {
		bad("extproc.chain.queue_size", "%d is outside 0-%d", q, 1<<20)
	}
	if u := e.Judge.URL; u != "" && !httpsURL(u) {
		bad("extproc.judge.url", "%q must be an https URL", u)
	}
	switch strings.ToLower(orDefault(e.DLP.CredentialHeaders, "alert")) {
	case "alert", "deny":
	default:
		bad("extproc.dlp.credential_headers", "%q must be alert or deny", e.DLP.CredentialHeaders)
	}
}

func (m *ProfileMatchSubstrate) validate(prefix string) error {
	if m.Empty() {
		return fmt.Errorf("%s: set atespaces, templates or workloads", prefix)
	}
	var errs []error
	for _, ns := range m.Atespaces {
		if _, err := path.Match(ns, ""); err != nil || !substrateAtespaceGlobRe.MatchString(ns) {
			errs = append(errs, fmt.Errorf("%s.atespaces: %q is not an atespace name or glob", prefix, ns))
		}
	}
	for _, t := range m.Templates {
		ns, name, ok := strings.Cut(t, "/")
		_, err := path.Match(t, "")
		if !ok || err != nil || !substrateAtespaceGlobRe.MatchString(ns) || !substrateAtespaceGlobRe.MatchString(name) {
			errs = append(errs, fmt.Errorf("%s.templates: %q must be <atespace>/<template>", prefix, t))
		}
	}
	for _, w := range m.Workloads {
		if strings.TrimSpace(w) == "" {
			errs = append(errs, fmt.Errorf("%s.workloads: an entry is empty", prefix))
		}
	}
	return errors.Join(errs...)
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

// SubstrateVersionRange is a space-separated list of comparisons, every one
// of which a version must meet, e.g. ">=1.0.0 <1.1.0".
type SubstrateVersionRange []substrateComparison

type substrateComparison struct {
	op string
	v  [3]int
}

// ParseSubstrateVersionRange parses a range of >=, >, <=, < or =
// comparisons against MAJOR.MINOR.PATCH versions.
func ParseSubstrateVersionRange(s string) (SubstrateVersionRange, error) {
	var out SubstrateVersionRange
	for _, f := range strings.Fields(s) {
		op := ""
		for _, cand := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(f, cand) {
				op = cand
				break
			}
		}
		if op == "" {
			return nil, fmt.Errorf("%q: each comparison starts with >=, >, <=, < or =", f)
		}
		v, err := parseSubstrateVersion(strings.TrimPrefix(f, op))
		if err != nil {
			return nil, fmt.Errorf("%q: %w", f, err)
		}
		out = append(out, substrateComparison{op: op, v: v})
	}
	if len(out) == 0 {
		return nil, errors.New("the version range is empty")
	}
	return out, nil
}

func parseSubstrateVersion(s string) ([3]int, error) {
	var v [3]int
	s = strings.TrimPrefix(s, "v")
	if core, _, ok := strings.Cut(s, "-"); ok {
		s = core // a pre-release compares as its release
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return v, errors.New("versions are MAJOR.MINOR.PATCH")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, errors.New("versions are MAJOR.MINOR.PATCH")
		}
		v[i] = n
	}
	return v, nil
}

// Contains reports whether version (e.g. "v1.0.3") meets every comparison.
func (r SubstrateVersionRange) Contains(version string) bool {
	v, err := parseSubstrateVersion(version)
	if err != nil {
		return false
	}
	for _, c := range r {
		cmp := slices.Compare(v[:], c.v[:])
		ok := false
		switch c.op {
		case ">=":
			ok = cmp >= 0
		case ">":
			ok = cmp > 0
		case "<=":
			ok = cmp <= 0
		case "<":
			ok = cmp < 0
		case "=":
			ok = cmp == 0
		}
		if !ok {
			return false
		}
	}
	return true
}
