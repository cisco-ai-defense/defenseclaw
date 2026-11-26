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
	"gopkg.in/yaml.v3"
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
	IdleSuspendAfter string `mapstructure:"idle_suspend_after" yaml:"idle_suspend_after,omitempty"`
	// IdleSuspendWithoutCPU, an opt-in, makes silence alone idle when the
	// controller has no CPU feed (no --usage-listen), an attached actor's
	// too. Off, such a controller never suspends an actor with a terminal
	// attached (GAP-0534).
	IdleSuspendWithoutCPU bool `mapstructure:"idle_suspend_without_cpu" yaml:"idle_suspend_without_cpu,omitempty"`
	// ChainEgressAction is what a request that leaves the cluster after a
	// secret read gets at the egress callout: block (the default, in every
	// mode, because actors are unattended) refuses it; alert, an opt-in,
	// lets it through with an alert. The leader answers the callout's chain
	// check with it; the gateway and the leader read it from the same
	// config (GAP-0250).
	ChainEgressAction string `mapstructure:"chain_egress_action" yaml:"chain_egress_action,omitempty"`
	// RelayTLS is how the gateway reaches an actor's relay (B3.5): auto
	// (default) uses TLS when the template's signed kit serves it and plain
	// HTTP with an audit row and a doctor warning for older templates;
	// required refuses those; off drops the row and the warning. A kit that
	// serves TLS is dialed with TLS in every mode.
	RelayTLS string `mapstructure:"relay_tls" yaml:"relay_tls,omitempty"`
	// RelayCertReissue is what the gateway does with a second relay
	// serving certificate for an actor asked for without proof of the live
	// key (GAP-0861): refuse answers 403 until an owner or administrator
	// runs recover; flag issues it with a HIGH audit row; auto (default)
	// is refuse in a managed enterprise install and flag in OSS.
	RelayCertReissue string `mapstructure:"relay_cert_reissue" yaml:"relay_cert_reissue,omitempty"`
	// WorkspaceMaxBytes caps a workspace upload through the admin
	// listener's attach route (E23; 0 = DefaultSubstrateWorkspaceMaxBytes).
	WorkspaceMaxBytes int64 `mapstructure:"workspace_max_bytes" yaml:"workspace_max_bytes,omitempty"`
	// Launcher holds what the gateway tells launchers (GET
	// /api/v1/substrate/launcher), read live.
	Launcher SubstrateLauncherConfig `mapstructure:"launcher" yaml:"launcher,omitempty"`
	// Files holds the admin switches of sending more files into a running
	// actor (push, sync); both on when unset.
	Files SubstrateFilesConfig `mapstructure:"files" yaml:"files,omitempty"`
	// Git is how agents reach private repositories (B2 2.5): the https
	// rewrite map, submodules and LFS in run --clone.
	Git        SubstrateGitConfig        `mapstructure:"git" yaml:"git,omitempty"`
	Unattended SubstrateUnattendedConfig `mapstructure:"unattended"         yaml:"unattended,omitempty"`
	// Interactive is the port forward and MCP bridge switches (B3).
	Interactive SubstrateInteractiveConfig `mapstructure:"interactive" yaml:"interactive,omitempty"`
	RateLimits  SubstrateRateLimitsConfig  `mapstructure:"rate_limits"        yaml:"rate_limits,omitempty"`
	// Usage is per-person and per-actor model spend through the leader
	// (substrate_usage.go).
	Usage   SubstrateUsageConfig   `mapstructure:"usage" yaml:"usage,omitempty"`
	Extproc SubstrateExtprocConfig `mapstructure:"extproc"            yaml:"extproc,omitempty"`
	LLM     SubstrateLLMConfig     `mapstructure:"llm"                yaml:"llm,omitempty"`
	Egress  SubstrateEgressConfig  `mapstructure:"egress"             yaml:"egress,omitempty"`
	Secrets []SubstrateSecret      `mapstructure:"secrets"            yaml:"secrets,omitempty"`
	// SelfServiceSecrets is how people bind their own secrets (B1 2.5).
	SelfServiceSecrets SubstrateSelfServiceSecretsConfig `mapstructure:"self_service_secrets" yaml:"self_service_secrets,omitempty"`
	// SecretTemplates is the admin catalog of templates people bind their
	// own secrets with; none = the built-in seven (secretbind.Builtin).
	SecretTemplates []SubstrateSecretTemplate `mapstructure:"secret_templates" yaml:"secret_templates,omitempty"`
	// AllowPassthroughFor lists hosts forwarded without inspection
	// (certificate pinning). A secret is never bound to one.
	AllowPassthroughFor []string `mapstructure:"allow_passthrough_for" yaml:"allow_passthrough_for,omitempty"`
	// Admin is the organization floor for Substrate actors, the same keys
	// as openshell.admin; guardrail profiles tighten it.
	Admin OpenShellAdminConfig `mapstructure:"admin" yaml:"admin,omitempty"`
	// Bundles is signed policy bundles (substrate_bundles.go).
	Bundles SubstrateBundlesConfig `mapstructure:"bundles" yaml:"bundles,omitempty"`
	// Activity is the agent state in list and status and the notification
	// switch (substrate_activity.go).
	Activity SubstrateActivityConfig `mapstructure:"activity" yaml:"activity,omitempty"`
	// Skills is the gateway's scan of skill folders an agent adds while it
	// runs (B5.4, GAP-0477).
	Skills SubstrateSkillsConfig `mapstructure:"skills" yaml:"skills,omitempty"`
}

// Self-service secret modes (substrate.self_service_secrets.mode).
const (
	SelfServiceBindings   = "bindings"
	SelfServiceValuesOnly = "values_only"
	SelfServiceOff        = "off"
)

// SubstrateSelfServiceSecretsConfig is substrate.self_service_secrets.
type SubstrateSelfServiceSecretsConfig struct {
	// Mode is bindings (default), values_only (people only set values of
	// listed secrets) or off (no binding store is read at all).
	Mode string `mapstructure:"mode" yaml:"mode,omitempty"`
	// Namespace holds the self-service values; never the release or
	// Substrate namespace (the chart refuses it).
	Namespace string `mapstructure:"namespace" yaml:"namespace,omitempty"`
	// Provider is the provider name in the generated sources
	// (ate-secret://k8s.io/<provider>/...), default "default": the
	// Kubernetes credential provider resolves only local Secrets, under the
	// name default (GAP-1076).
	Provider string `mapstructure:"provider" yaml:"provider,omitempty"`
	// MaxPerPerson bounds one person's bindings (1-200, default 20).
	MaxPerPerson int `mapstructure:"max_per_person" yaml:"max_per_person,omitempty"`
	// OutsideTemplates is ask (default) or refuse, for a host no template
	// covers.
	OutsideTemplates string `mapstructure:"outside_templates" yaml:"outside_templates,omitempty"`
	// AskTimeout bounds an administrator ask for a binding (default 72h,
	// at most 168h).
	AskTimeout string `mapstructure:"ask_timeout" yaml:"ask_timeout,omitempty"`
	// AllowEchoBindings lets a person set allow_echo on their own binding.
	AllowEchoBindings bool `mapstructure:"allow_echo_bindings" yaml:"allow_echo_bindings,omitempty"`
}

// SubstrateSecretTemplate is one substrate.secret_templates entry.
type SubstrateSecretTemplate struct {
	Name      string   `mapstructure:"name"       yaml:"name"`
	Hosts     []string `mapstructure:"hosts"      yaml:"hosts,omitempty"`
	Header    string   `mapstructure:"header"     yaml:"header,omitempty"`
	Form      string   `mapstructure:"form"       yaml:"form,omitempty"`
	BasicUser string   `mapstructure:"basic_user" yaml:"basic_user,omitempty"`
	Profiles  []string `mapstructure:"profiles"   yaml:"profiles,omitempty"`
	Registry  string   `mapstructure:"registry"   yaml:"registry,omitempty"`
}

// MarshalYAML keeps an explicit empty host list: hosts: [] means no host
// without an administrator, while an unset list takes a built-in
// template's hosts. Plain omitempty would turn the first into the second
// on any config save (RV3 P2-3).
func (t SubstrateSecretTemplate) MarshalYAML() (any, error) {
	type plain SubstrateSecretTemplate
	var n yaml.Node
	if err := n.Encode(plain(t)); err != nil {
		return nil, err
	}
	if t.Hosts != nil && len(t.Hosts) == 0 && n.Kind == yaml.MappingNode && len(n.Content) >= 2 {
		k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "hosts"}
		v := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: yaml.FlowStyle}
		n.Content = append(n.Content[:2:2], append([]*yaml.Node{k, v}, n.Content[2:]...)...)
	}
	return &n, nil
}

// substrateReservedNamespaces are never the self-service namespace: the
// gateway gets get/patch on every Secret there and the actors' credential
// provider reads it (RV3 P3-5).
var substrateReservedNamespaces = []string{"default", "kube-system", "kube-public", "kube-node-lease"}

// substrateBasicUserRE is secretbind's basic_user rule: printable ASCII,
// no space and no ":" (RV3 P3-7).
var substrateBasicUserRE = regexp.MustCompile(`^[!-9;-~]{1,128}$`)

// EffectiveMode is the self-service mode, bindings when unset.
func (s SubstrateSelfServiceSecretsConfig) EffectiveMode() string {
	if s.Mode == "" {
		return SelfServiceBindings
	}
	return s.Mode
}

// EffectiveNamespace is where self-service values live.
func (s SubstrateSelfServiceSecretsConfig) EffectiveNamespace() string {
	if s.Namespace == "" {
		return "defenseclaw-user-secrets"
	}
	return s.Namespace
}

// EffectiveProvider is the provider name of self-service sources. The
// default is the one name the Kubernetes credential provider answers:
// "default", the local cluster. The deployment name it had before
// (k8s-credential-provider) was refused at every egress fetch with "path
// must begin with default (only local Secrets are supported)", so a bound
// person secret was never injected (GAP-1076).
func (s SubstrateSelfServiceSecretsConfig) EffectiveProvider() string {
	if s.Provider == "" {
		return "default"
	}
	return s.Provider
}

// EffectiveMaxPerPerson is the per-person binding limit.
func (s SubstrateSelfServiceSecretsConfig) EffectiveMaxPerPerson() int {
	if s.MaxPerPerson <= 0 {
		return 20
	}
	return s.MaxPerPerson
}

// EffectiveOutsideTemplates is ask or refuse.
func (s SubstrateSelfServiceSecretsConfig) EffectiveOutsideTemplates() string {
	if s.OutsideTemplates == "" {
		return "ask"
	}
	return s.OutsideTemplates
}

// EffectiveAskTimeout is the binding ask timeout.
func (s SubstrateSelfServiceSecretsConfig) EffectiveAskTimeout() time.Duration {
	if d, err := time.ParseDuration(s.AskTimeout); err == nil && d > 0 {
		return d
	}
	return 72 * time.Hour
}

var (
	substrateTemplateNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	substrateHeaderNameRE   = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]{1,64}$`)
)

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
	// RegistryAuth is how the controller and the gateway's create path log
	// in to the template registries to read images and attestations
	// (GAP-0190). Unset: anonymous.
	RegistryAuth SubstrateRegistryAuthConfig `mapstructure:"registry_auth" yaml:"registry_auth,omitempty"`
}

// SubstrateRegistryAuthConfig names the template registry logins. Each one
// belongs to exactly one registry host and is sent only to that host, in
// answer to its challenge (GAP-0052); every other host is read anonymously.
type SubstrateRegistryAuthConfig struct {
	// DockerConfig is a docker config.json (the chart mounts a
	// kubernetes.io/dockerconfigjson Secret here). Each auths entry is for
	// its own host. The file is re-read when it changes; a missing file is
	// no logins.
	DockerConfig string `mapstructure:"docker_config" yaml:"docker_config,omitempty"`
	// ECRHosts are Amazon ECR registry hosts
	// (<account>.dkr.ecr.<region>.amazonaws.com) logged in to with an
	// ecr:GetAuthorizationToken token through the AWS SDK default
	// credential chain (IRSA or EKS Pod Identity), refreshed before it
	// expires.
	ECRHosts []string `mapstructure:"ecr_hosts" yaml:"ecr_hosts,omitempty"`
}

// substrateECRHostRe is an Amazon ECR private registry host: account,
// optional FIPS endpoint, region, and the partition's domain.
var substrateECRHostRe = regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr(-fips)?\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.amazonaws\.com(?:\.cn)?$`)

// ParseECRRegistryHost splits an Amazon ECR registry host into its account
// and region; fips is true for a dkr.ecr-fips host.
func ParseECRRegistryHost(host string) (account, region string, fips, ok bool) {
	m := substrateECRHostRe.FindStringSubmatch(host)
	if m == nil {
		return "", "", false, false
	}
	return m[1], m[3], m[2] != "", true
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
	ActorCertOID string `mapstructure:"actor_cert_oid" yaml:"actor_cert_oid,omitempty"`
	// KeysURL is where the gateway reads the keys that sign actor tokens
	// (a JWK set). Empty: the in-cluster idp Service,
	// https://idp.<substrate namespace>.svc/openid/v1/jwks, whatever the
	// issuer is, so a per-cluster issuer is only compared as the iss
	// string and need not resolve (GAP-0194). KeysCAFile is the PEM bundle
	// that signed the keys URL's certificate (empty: the servicedns trust
	// bundle the chart mounts).
	KeysURL      string                        `mapstructure:"keys_url"       yaml:"keys_url,omitempty"`
	KeysCAFile   string                        `mapstructure:"keys_ca_file"   yaml:"keys_ca_file,omitempty"`
	OIDC         SubstrateOIDCConfig           `mapstructure:"oidc"           yaml:"oidc,omitempty"`
	WorkloadOIDC []SubstrateWorkloadOIDCConfig `mapstructure:"workload_oidc" yaml:"workload_oidc,omitempty"`
	// AdminGroups are the groups (OIDC groups claim, or Kubernetes groups
	// with the Kubernetes sign-in) whose members are Substrate
	// administrators on the admin listener. The gateway's --admin-groups
	// flag adds to them.
	AdminGroups []string `mapstructure:"admin_groups" yaml:"admin_groups,omitempty"`
	// KubeSignIn false turns the Kubernetes sign-in off (nil = on). It
	// applies only with no oidc.issuer on an install that is not managed
	// (Config.SubstrateKubeSignIn). The gateway's --no-kube-sign-in flag
	// turns it off too. The gateway reads it at start only (restart it after
	// a change), and routing.admin users entries match against the issuers
	// people can sign in with then (GAP-0939, GAP-0968).
	KubeSignIn *bool `mapstructure:"kube_sign_in" yaml:"kube_sign_in,omitempty"`
	// Revocation is the list of ended sign-ins (B5.1): logout, logout
	// --all and admin revoke.
	Revocation SubstrateRevocationConfig `mapstructure:"revocation" yaml:"revocation,omitempty"`
}

// SubstrateRevocationConfig is the list of ended sign-ins the leader keeps
// and every gateway replica pulls (B5.1). Enabled is read at start: turning
// it on or off takes a gateway restart. Managed installs may not turn it
// off.
type SubstrateRevocationConfig struct {
	// Enabled (default true). false: no list, no pull loop; a copied
	// sign-in token works until it expires (doctor warns).
	Enabled *bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// SyncInterval is how often a replica pulls from the leader (Go
	// duration, 1s to 60s, default 5s).
	SyncInterval string `mapstructure:"sync_interval" yaml:"sync_interval,omitempty"`
	// MaxStale is how old a replica's copy may get before it refuses
	// sign-ins with revocation_unavailable (default 60s or 2 x
	// sync_interval, whichever is longer; at least 2 x sync_interval, so
	// one slow pull does not make the replica refuse, at most 1h).
	MaxStale string `mapstructure:"max_stale" yaml:"max_stale,omitempty"`
	// MaxTokensPerPerson is how many single-token ends the leader keeps
	// per person before it turns them into one person-wide end (default
	// 64, 1 to 4096).
	MaxTokensPerPerson int `mapstructure:"max_tokens_per_person" yaml:"max_tokens_per_person,omitempty"`
}

// Defaults of substrate.identity.revocation.
const (
	DefaultSubstrateRevocationSyncInterval = 5 * time.Second
	DefaultSubstrateRevocationMaxStale     = 60 * time.Second
	DefaultSubstrateRevocationMaxTokens    = 64
)

// EffectiveEnabled reports whether ended sign-ins are kept (default on).
func (r SubstrateRevocationConfig) EffectiveEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// EffectiveSyncInterval is the replica pull interval.
func (r SubstrateRevocationConfig) EffectiveSyncInterval() time.Duration {
	return durationOr(r.SyncInterval, DefaultSubstrateRevocationSyncInterval)
}

// EffectiveMaxStale is the age past which a replica refuses sign-ins:
// max_stale, or 60s or 2 x sync_interval, whichever is longer (RV1-09).
func (r SubstrateRevocationConfig) EffectiveMaxStale() time.Duration {
	return durationOr(r.MaxStale, max(DefaultSubstrateRevocationMaxStale, 2*r.EffectiveSyncInterval()))
}

// EffectiveMaxTokensPerPerson is the per-person single-token cap.
func (r SubstrateRevocationConfig) EffectiveMaxTokensPerPerson() int {
	if r.MaxTokensPerPerson <= 0 {
		return DefaultSubstrateRevocationMaxTokens
	}
	return r.MaxTokensPerPerson
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
	// BodyInspection is auto (default) or on: the callout asks for the body
	// of every qualifying request (an egress filter without mode override
	// ignores it and each request is an alert); off: headers only.
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
	// RateLimits holds each actor's requests through the callout to a rate
	// (GAP-0635); the callout applies its default when unset.
	RateLimits SubstrateExtprocRateLimitsConfig `mapstructure:"rate_limits" yaml:"rate_limits,omitempty"`
}

// SubstrateExtprocRateLimitsConfig is the callout's per-actor request rate,
// across its replicas (extproc.RateLimitsConfig; 0 is the callout's
// default, 200).
type SubstrateExtprocRateLimitsConfig struct {
	PerActorRPS float64 `mapstructure:"per_actor_rps" yaml:"per_actor_rps,omitempty"`
}

// SubstrateExtprocUIDConfig is the live-UID cache (Go durations; defaults
// 60s and 60s, at most 10m).
type SubstrateExtprocUIDConfig struct {
	CacheTTL string `mapstructure:"cache_ttl" yaml:"cache_ttl,omitempty"`
	StaleMax string `mapstructure:"stale_max" yaml:"stale_max,omitempty"`
}

// SubstrateExtprocChainConfig bounds the egress chain check (default 20ms,
// at most 500ms; 250ms for a check whose miss refuses the request) and the
// observed_egress queue (default 4096). FailureMode decides a request whose
// check could not answer: auto (default) refuses for unattended actors and
// alerts for the rest, closed always refuses (managed installs), open always
// alerts; a request that can carry data out is refused in every mode
// (GAP-0601).
type SubstrateExtprocChainConfig struct {
	CheckBudget string `mapstructure:"check_budget" yaml:"check_budget,omitempty"`
	// SendBudget bounds a check whose miss refuses the request (a send, a
	// policy that refuses unchecked egress, a cached registration) and the
	// refresh that confirms one (default 250ms, at most 500ms, never shorter
	// than CheckBudget).
	SendBudget  string `mapstructure:"send_budget"  yaml:"send_budget,omitempty"`
	QueueSize   int    `mapstructure:"queue_size"   yaml:"queue_size,omitempty"`
	FailureMode string `mapstructure:"failure_mode" yaml:"failure_mode,omitempty"`
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
	// BedrockModels, when set, are the Bedrock model IDs actors may call
	// through /llm/bedrock. A call naming another model (for example the
	// opus and sonnet probes Claude Code sends at start, GAP-0008) goes to
	// the first entry instead, through the same guardrails. Empty serves
	// the model the call names.
	BedrockModels []string `mapstructure:"bedrock_models" yaml:"bedrock_models,omitempty"`
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
	// NoSwapHosts are added to the built-in echo hosts: no secret is added
	// on a host they cover unless its entry sets inject.allow_echo. Hot.
	NoSwapHosts []string `mapstructure:"no_swap_hosts" yaml:"no_swap_hosts,omitempty"`
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
	// AllowEcho lets the secret be added on a host that returns the
	// requests it gets (egressspec.EchoHosts, egress.no_swap_hosts). Off by
	// default: the real value would come back to the agent.
	AllowEcho bool `mapstructure:"allow_echo" yaml:"allow_echo,omitempty"`
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
	// DefaultSubstrateNamespace is where Substrate runs when the API
	// address does not name another namespace.
	DefaultSubstrateNamespace = "ate-system"
	// DefaultSubstrateKeysCAFile is the servicedns trust bundle the chart
	// projects into the gateway: it signs the idp Service's certificate.
	DefaultSubstrateKeysCAFile = "/run/servicedns.podcert.ate.dev/trust-bundle.pem"
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
	// substrate.git.push_branch and the floor key git_push (B2 2.4).
	SubstrateGitPushAllow = "allow"
	SubstrateGitPushAsk   = "ask"
	SubstrateGitPushDeny  = "deny"
	SubstrateFailClosed   = "closed"
	SubstrateFailOpen     = "open"
	SubstrateBodyAuto     = "auto"
	SubstrateBodyOn       = "on"
	SubstrateBodyOff      = "off"
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
// DefaultSubstrateWorkspaceMaxBytes is the workspace upload cap, the relay's
// own default (1 GiB).
const DefaultSubstrateWorkspaceMaxBytes int64 = 1 << 30

// EffectiveWorkspaceMaxBytes is WorkspaceMaxBytes or its default.
func (s SubstrateConfig) EffectiveWorkspaceMaxBytes() int64 {
	if s.WorkspaceMaxBytes > 0 {
		return s.WorkspaceMaxBytes
	}
	return DefaultSubstrateWorkspaceMaxBytes
}

// SubstrateFilesConfig is substrate.files: the admin-off switches of
// substrate push (Push) and substrate sync --watch (Sync). The gateway
// refuses the upload of a push or a sync batch when its switch is off;
// the first copy of a run is not affected. Sync needs both.
type SubstrateFilesConfig struct {
	Push *bool `mapstructure:"push" yaml:"push,omitempty"`
	Sync *bool `mapstructure:"sync" yaml:"sync,omitempty"`
}

// PushAllowed is substrate.files.push, true when unset.
func (f SubstrateFilesConfig) PushAllowed() bool { return f.Push == nil || *f.Push }

// SyncAllowed is substrate.files.sync (and push), true when unset.
func (f SubstrateFilesConfig) SyncAllowed() bool {
	return f.PushAllowed() && (f.Sync == nil || *f.Sync)
}

// SubstrateGitRewrite is one substrate.git.https_rewrite pair: git in an
// agent reads an address that starts with From as To followed by the rest
// (a git url.<To>.insteadOf = From rule).
type SubstrateGitRewrite struct {
	From string `mapstructure:"from" yaml:"from" json:"from"`
	To   string `mapstructure:"to" yaml:"to" json:"to"`
}

// SubstrateGitConfig is substrate.git. The rewrite map is a convenience,
// not a control: egress still decides which hosts an agent reaches and
// where a credential is added, so an agent that edits its own git config
// only breaks its own git calls.
type SubstrateGitConfig struct {
	// HTTPSRewrite turns ssh and scp-form addresses into https ones, which
	// is the only way out of an agent (egress carries no SSH). A list adds
	// to the rules every actor image bakes in (SubstrateGitBakedRewrites:
	// the three SaaS scp forms and ssh://git@). Git reads those first, so
	// a list cannot drop one and a baked rule wins a tie; Validate refuses
	// a from that is baked with another to. Unset adds nothing. At most 64.
	HTTPSRewrite []SubstrateGitRewrite `mapstructure:"https_rewrite" yaml:"https_rewrite,omitempty"`
	// Submodules: run --clone also clones the repository's submodules
	// (true when unset).
	Submodules *bool `mapstructure:"submodules" yaml:"submodules,omitempty"`
	// LFS: run --clone fetches Git LFS files when the template has git-lfs
	// (true when unset); off leaves them as pointer files.
	LFS *bool `mapstructure:"lfs" yaml:"lfs,omitempty"`
	// PushBranch is allow, ask (unset) or deny: whether `substrate pull
	// --push-branch` pushes an actor's work to its origin as a new branch
	// (B2 2.4). deny is the admin-off switch: it wins over every profile.
	PushBranch string `mapstructure:"push_branch" yaml:"push_branch,omitempty"`
}

// MaxSubstrateGitRewrites caps substrate.git.https_rewrite.
const MaxSubstrateGitRewrites = 64

// DefaultSubstrateGitHTTPSRewrite is the rewrite map when none is set: the
// scp-form addresses of the three SaaS git hosts. Actor images bake the
// same three (kit gitConfig), so an image made before the map still has
// them.
func DefaultSubstrateGitHTTPSRewrite() []SubstrateGitRewrite {
	out := make([]SubstrateGitRewrite, 0, 3)
	for _, host := range []string{"github.com", "gitlab.com", "bitbucket.org"} {
		out = append(out, SubstrateGitRewrite{From: "git@" + host + ":", To: "https://" + host + "/"})
	}
	return out
}

// SubstrateGitGenericRewrites are the rules every actor image bakes in
// besides the map: any ssh://git@ address goes over https to the same host.
var SubstrateGitGenericRewrites = []SubstrateGitRewrite{
	{From: "ssh://git@", To: "https://"},
	{From: "git+ssh://git@", To: "https://"},
}

// SubstrateGitBakedRewrites are the rules every actor image bakes into
// /etc/gitconfig (kit gitConfig), in the order git reads them: the generic
// ssh rules, then the default map.
func SubstrateGitBakedRewrites() []SubstrateGitRewrite {
	return append(append([]SubstrateGitRewrite{}, SubstrateGitGenericRewrites...), DefaultSubstrateGitHTTPSRewrite()...)
}

// SubstrateGitRewriteMap is every rule git in an agent applies, in the
// order git reads them: the baked rules (the system config), then the
// pairs of admin (substrate.git.https_rewrite, in the actor user's config,
// B2 2.5) that WriteGitRewrite writes, which are those CheckSubstrateGitRewrite
// accepts.
func SubstrateGitRewriteMap(admin []SubstrateGitRewrite) []SubstrateGitRewrite {
	out := SubstrateGitBakedRewrites()
	for _, r := range admin {
		if CheckSubstrateGitRewrite(r) == nil {
			out = append(out, r)
		}
	}
	return out
}

// EffectiveHTTPSRewrite is substrate.git.https_rewrite, the default when
// unset.
func (g SubstrateGitConfig) EffectiveHTTPSRewrite() []SubstrateGitRewrite {
	if g.HTTPSRewrite == nil {
		return DefaultSubstrateGitHTTPSRewrite()
	}
	return g.HTTPSRewrite
}

// SubmodulesOn is substrate.git.submodules, true when unset.
func (g SubstrateGitConfig) SubmodulesOn() bool { return g.Submodules == nil || *g.Submodules }

// EffectivePushBranch is substrate.git.push_branch, ask when unset.
func (g SubstrateGitConfig) EffectivePushBranch() string {
	if v := strings.ToLower(strings.TrimSpace(g.PushBranch)); v != "" {
		return v
	}
	return SubstrateGitPushAsk
}

// LFSOn is substrate.git.lfs, true when unset.
func (g SubstrateGitConfig) LFSOn() bool { return g.LFS == nil || *g.LFS }

// CheckSubstrateGitRewrite refuses a pair git would misread or that is not
// an https target: from ends in ":" or "/" and has no upper case in its
// scheme or host (git compares the prefix as written, and remotes name
// hosts in lower case), to is an https address with a host and no user
// that ends in "/" (git joins the rest of the address to it as is), and
// neither carries spaces, quotes, backslashes or control characters (the
// pair is written into the agent's git config).
func CheckSubstrateGitRewrite(r SubstrateGitRewrite) error {
	plain := func(v string) bool {
		return v != "" && len(v) <= 256 && !strings.ContainsAny(v, "\"\\ \t") &&
			!strings.ContainsFunc(v, func(c rune) bool { return c < 0x20 || c == 0x7f })
	}
	switch {
	case !plain(r.From) || strings.HasPrefix(r.From, "-"):
		return fmt.Errorf("from %q must be a plain address prefix", r.From)
	case !strings.HasSuffix(r.From, ":") && !strings.HasSuffix(r.From, "/"):
		return fmt.Errorf("from %q must end in : or /", r.From)
	case gitRewriteHostPart(r.From) != strings.ToLower(gitRewriteHostPart(r.From)):
		return fmt.Errorf("from %q must name its scheme and host in lower case, as remotes do (git compares it as written)", r.From)
	case !plain(r.To):
		return fmt.Errorf("to %q must be a plain https address", r.To)
	}
	u, err := url.Parse(r.To)
	if err != nil || u.Scheme != "https" || !strings.HasPrefix(r.To, "https://") || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("to %q must be an https:// address with a host and no user name", r.To)
	}
	if !strings.HasSuffix(r.To, "/") {
		return fmt.Errorf("to %q must end in / (git adds the rest of the address to it as is)", r.To)
	}
	return nil
}

// gitRewriteHostPart is the scheme and host of a rewrite from (no user
// name, port or path): "ssh://" + "ghe.example" for ssh://git@ghe.example/,
// "ghe.example" for git@ghe.example:.
func gitRewriteHostPart(from string) string {
	scheme, rest := "", from
	if i := strings.Index(from, "://"); i >= 0 {
		scheme, rest = from[:i+3], from[i+3:]
	}
	if j := strings.IndexAny(rest, "/:"); j >= 0 {
		rest = rest[:j]
	}
	if k := strings.LastIndex(rest, "@"); k >= 0 {
		rest = rest[k+1:]
	}
	return scheme + rest
}

// RewriteGitURL is the address git in an agent uses for raw with admin,
// substrate.git.https_rewrite, on top of the baked rules
// (SubstrateGitRewriteMap). It follows git: the longest insteadOf prefix
// wins and, on a tie, the rule git read first, so a baked rule. ok is
// false when no rule matches.
func RewriteGitURL(raw string, admin []SubstrateGitRewrite) (string, bool) {
	best := -1
	out := ""
	for _, r := range SubstrateGitRewriteMap(admin) {
		if strings.HasPrefix(raw, r.From) && len(r.From) > best {
			best, out = len(r.From), r.To+raw[len(r.From):]
		}
	}
	return out, best >= 0
}

// SubstrateLauncherConfig is substrate.launcher: launcher behaviour the
// cluster admin sets for everyone.
type SubstrateLauncherConfig struct {
	// KeyReplay is what a launcher does with keys typed while its terminal
	// link is down (B3.1): ask (default) shows them after the reconnect and
	// sends them on Enter, on sends them, off drops them with a count. A
	// launcher flag can only tighten it; off is the admin-off switch.
	KeyReplay string `mapstructure:"key_replay" yaml:"key_replay,omitempty"`
	// UploadScan tunes the secret scan of a project copy before it goes to
	// an actor (B1, Linux and macOS copies; the Windows host copy keeps
	// holding files back).
	UploadScan SubstrateUploadScanConfig `mapstructure:"upload_scan" yaml:"upload_scan,omitempty"`
}

// SubstrateUploadScanConfig is substrate.launcher.upload_scan.
type SubstrateUploadScanConfig struct {
	// MaxFileBytes is the largest file the scan reads (default 8 MiB); a
	// bigger one is uploaded unscanned and named in the run's report.
	MaxFileBytes int64 `mapstructure:"max_file_bytes" yaml:"max_file_bytes,omitempty"`
	// TimeBudget bounds the scan (a Go duration, default 120s); the files
	// it did not reach are named in the run's report.
	TimeBudget string `mapstructure:"time_budget" yaml:"time_budget,omitempty"`
	// SecretAction is replace (default: the value is replaced with a
	// placeholder in the uploaded copy) or hold_back (the whole file stays
	// on the computer). hold_back is the admin-off switch.
	SecretAction string `mapstructure:"secret_action" yaml:"secret_action,omitempty"`
	// PlaceholderForm is token (default, DC_SECRET_<n>) or env
	// (${DC_SECRET_<n>}).
	PlaceholderForm string `mapstructure:"placeholder_form" yaml:"placeholder_form,omitempty"`
}

// Upload scan secret actions and placeholder forms.
const (
	SubstrateUploadReplace  = "replace"
	SubstrateUploadHoldBack = "hold_back"
	SubstratePlaceholderTok = "token"
	SubstratePlaceholderEnv = "env"

	substrateUploadMaxFileDefault = 8 << 20
	substrateUploadMaxFileCeiling = 64 << 20
	substrateUploadBudgetDefault  = 120 * time.Second
)

// EffectiveMaxFileBytes is upload_scan.max_file_bytes, 8 MiB when unset.
func (u SubstrateUploadScanConfig) EffectiveMaxFileBytes() int64 {
	if u.MaxFileBytes > 0 {
		return u.MaxFileBytes
	}
	return substrateUploadMaxFileDefault
}

// EffectiveTimeBudget is upload_scan.time_budget, 120s when unset or bad.
func (u SubstrateUploadScanConfig) EffectiveTimeBudget() time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(u.TimeBudget)); err == nil && d > 0 {
		return d
	}
	return substrateUploadBudgetDefault
}

// EffectiveSecretAction is upload_scan.secret_action, replace when unset.
// It is matched exactly, as the config schemas do: Replace or a padded
// value is refused by Validate, not read as replace (RV5-8).
func (u SubstrateUploadScanConfig) EffectiveSecretAction() string {
	if u.SecretAction != "" {
		return u.SecretAction
	}
	return SubstrateUploadReplace
}

// EffectivePlaceholderForm is upload_scan.placeholder_form, token when
// unset, matched exactly like EffectiveSecretAction.
func (u SubstrateUploadScanConfig) EffectivePlaceholderForm() string {
	if u.PlaceholderForm != "" {
		return u.PlaceholderForm
	}
	return SubstratePlaceholderTok
}

// Key replay modes (substrate.launcher.key_replay).
const (
	SubstrateKeyReplayAsk = "ask"
	SubstrateKeyReplayOn  = "on"
	SubstrateKeyReplayOff = "off"
)

// EffectiveKeyReplay is substrate.launcher.key_replay, ask when unset.
func (l SubstrateLauncherConfig) EffectiveKeyReplay() string {
	if v := strings.ToLower(strings.TrimSpace(l.KeyReplay)); v != "" {
		return v
	}
	return SubstrateKeyReplayAsk
}

// Chain egress actions (substrate.chain_egress_action).
const (
	SubstrateChainEgressBlock = "block"
	SubstrateChainEgressAlert = "alert"
)

// Values of substrate.relay_tls.
const (
	SubstrateRelayTLSAuto     = "auto"
	SubstrateRelayTLSRequired = "required"
	SubstrateRelayTLSOff      = "off"
)

// EffectiveRelayTLS is substrate.relay_tls, auto when unset.
func (s SubstrateConfig) EffectiveRelayTLS() string {
	if v := strings.ToLower(strings.TrimSpace(s.RelayTLS)); v != "" {
		return v
	}
	return SubstrateRelayTLSAuto
}

// Values of substrate.relay_cert_reissue.
const (
	SubstrateRelayCertReissueAuto   = "auto"
	SubstrateRelayCertReissueFlag   = "flag"
	SubstrateRelayCertReissueRefuse = "refuse"
)

// EffectiveRelayCertReissue is substrate.relay_cert_reissue, auto when
// unset.
func (s SubstrateConfig) EffectiveRelayCertReissue() string {
	if v := strings.ToLower(strings.TrimSpace(s.RelayCertReissue)); v != "" {
		return v
	}
	return SubstrateRelayCertReissueAuto
}

// RelayCertReissueFor is the active substrate.relay_cert_reissue: auto is
// refuse in a managed enterprise install and flag in OSS.
func (s SubstrateConfig) RelayCertReissueFor(managed bool) string {
	switch v := s.EffectiveRelayCertReissue(); {
	case v != SubstrateRelayCertReissueAuto:
		return v
	case managed:
		return SubstrateRelayCertReissueRefuse
	}
	return SubstrateRelayCertReissueFlag
}

// EffectiveChainEgressAction is substrate.chain_egress_action, block when
// unset.
func (s SubstrateConfig) EffectiveChainEgressAction() string {
	if v := strings.ToLower(strings.TrimSpace(s.ChainEgressAction)); v != "" {
		return v
	}
	return SubstrateChainEgressBlock
}

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

// ActorGatewayURL is the actor listener base URL a kit image posts to: plain
// HTTP to the actor Service FQDN (egress re-originates the in-cluster hop and
// adds the actor JWT; substrate-1 GAP-0023 and GAP-0042).
func (s SubstrateConfig) ActorGatewayURL() string {
	return "http://" + strings.TrimSpace(s.EffectiveActorService())
}

// RelaySessionIssuer is the iss of the relay session tokens the gateway
// signs, https://<admin Service>. Template builds bake the same value into
// the relay (substrate-1 GAP-0147), so both sides take it from here.
func (s SubstrateConfig) RelaySessionIssuer() string {
	return "https://" + strings.TrimSpace(s.EffectiveAdminService())
}

// EffectiveAudience and EffectiveTokenLifetime shape the actor JWT.
func (s SubstrateConfig) EffectiveAudience() string {
	return orDefault(s.Identity.Audience, DefaultSubstrateAudience)
}

// SubstrateNamespace is the namespace Substrate runs in, read from the API
// address (api.<namespace>.svc[.cluster.local]:port), else ate-system.
func (s SubstrateConfig) SubstrateNamespace() string {
	host := strings.TrimSpace(s.API.Address)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimSuffix(host, "."), ".cluster.local")
	if parts := strings.Split(host, "."); len(parts) == 3 && parts[0] == "api" && parts[2] == "svc" && parts[1] != "" {
		return parts[1]
	}
	return DefaultSubstrateNamespace
}

// EffectiveKeysURL is identity.keys_url, or the idp Service's key set
// (GAP-0194): ate-idp-server serves it at /openid/v1/jwks.
func (s SubstrateConfig) EffectiveKeysURL() string {
	if u := strings.TrimSpace(s.Identity.KeysURL); u != "" {
		return u
	}
	return "https://idp." + s.SubstrateNamespace() + ".svc/openid/v1/jwks"
}

// EffectiveKeysCAFile is identity.keys_ca_file, or the servicedns trust
// bundle.
func (s SubstrateConfig) EffectiveKeysCAFile() string {
	return orDefault(s.Identity.KeysCAFile, DefaultSubstrateKeysCAFile)
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

	switch s.EffectiveChainEgressAction() {
	case SubstrateChainEgressBlock, SubstrateChainEgressAlert:
	default:
		bad("chain_egress_action", "%q is not block or alert", s.ChainEgressAction)
	}
	switch s.Launcher.EffectiveKeyReplay() {
	case SubstrateKeyReplayAsk, SubstrateKeyReplayOn, SubstrateKeyReplayOff:
	default:
		bad("launcher.key_replay", "%q is not ask, on or off", s.Launcher.KeyReplay)
	}
	switch s.Git.EffectivePushBranch() {
	case SubstrateGitPushAllow, SubstrateGitPushAsk, SubstrateGitPushDeny:
	default:
		bad("git.push_branch", "%q is not allow, ask or deny", s.Git.PushBranch)
	}
	if n := len(s.Git.HTTPSRewrite); n > MaxSubstrateGitRewrites {
		bad("git.https_rewrite", "has %d entries; at most %d", n, MaxSubstrateGitRewrites)
	}
	seenRewrite := map[string]bool{}
	baked := map[string]string{}
	for _, r := range SubstrateGitBakedRewrites() {
		baked[r.From] = r.To
	}
	for i, r := range s.Git.HTTPSRewrite {
		if err := CheckSubstrateGitRewrite(r); err != nil {
			bad(fmt.Sprintf("git.https_rewrite[%d]", i), "%v", err)
		} else if seenRewrite[r.From] {
			bad(fmt.Sprintf("git.https_rewrite[%d]", i), "from %q is listed twice", r.From)
		} else if to, ok := baked[r.From]; ok && to != r.To {
			bad(fmt.Sprintf("git.https_rewrite[%d]", i), "from %q is built into every actor image with to %q, which git keeps; use a longer from (for example %sORG/)", r.From, to, r.From)
		}
		seenRewrite[r.From] = true
	}
	up := s.Launcher.UploadScan
	if up.MaxFileBytes < 0 || up.MaxFileBytes > substrateUploadMaxFileCeiling {
		bad("launcher.upload_scan.max_file_bytes", "%d is not between 0 and %d", up.MaxFileBytes, substrateUploadMaxFileCeiling)
	}
	if t := strings.TrimSpace(up.TimeBudget); t != "" {
		if d, err := time.ParseDuration(t); err != nil || d < time.Second || d > time.Hour {
			bad("launcher.upload_scan.time_budget", "%q is not a duration from 1s to 1h", up.TimeBudget)
		}
	}
	switch up.EffectiveSecretAction() {
	case SubstrateUploadReplace, SubstrateUploadHoldBack:
	default:
		bad("launcher.upload_scan.secret_action", "%q is not replace or hold_back", up.SecretAction)
	}
	switch up.EffectivePlaceholderForm() {
	case SubstratePlaceholderTok, SubstratePlaceholderEnv:
	default:
		bad("launcher.upload_scan.placeholder_form", "%q is not token or env", up.PlaceholderForm)
	}
	switch s.EffectiveRelayTLS() {
	case SubstrateRelayTLSAuto, SubstrateRelayTLSRequired, SubstrateRelayTLSOff:
	default:
		bad("relay_tls", "%q is not auto, required or off", s.RelayTLS)
	}
	switch s.EffectiveRelayCertReissue() {
	case SubstrateRelayCertReissueAuto, SubstrateRelayCertReissueFlag, SubstrateRelayCertReissueRefuse:
	default:
		bad("relay_cert_reissue", "%q is not auto, flag or refuse", s.RelayCertReissue)
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
	if u := id.KeysURL; u != "" && (!httpsURL(u) || strings.TrimSpace(u) != u) {
		bad("identity.keys_url", "%q must be an https URL with no query or fragment", u)
	}
	if o := id.OIDC; o.Issuer != "" || o.ClientID != "" {
		if !httpsURL(o.Issuer) {
			bad("identity.oidc.issuer", "%q must be an https URL", o.Issuer)
		}
		if strings.TrimSpace(o.ClientID) == "" {
			bad("identity.oidc.client_id", "is required with identity.oidc.issuer")
		}
	}
	for i, g := range id.AdminGroups {
		if strings.TrimSpace(g) == "" || len(g) > 256 {
			bad(fmt.Sprintf("identity.admin_groups[%d]", i), "must be a group name of 1 to 256 bytes")
		}
	}
	for i, w := range id.WorkloadOIDC {
		if !httpsURL(w.Issuer) {
			bad(fmt.Sprintf("identity.workload_oidc[%d].issuer", i), "%q must be an https URL", w.Issuer)
		}
		if strings.TrimSpace(w.Audience) == "" {
			bad(fmt.Sprintf("identity.workload_oidc[%d].audience", i), "is required (use one unique to this install)")
		}
		if sub := strings.TrimSpace(w.Subject); sub != "" && !substrateWorkloadSubjectRe.MatchString(sub) {
			bad(fmt.Sprintf("identity.workload_oidc[%d].subject", i), substrateWorkloadSubjectHint, w.Subject)
		} else if sub == "" && len(w.Claims) == 0 {
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
	rv := s.Identity.Revocation
	if v := rv.SyncInterval; v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err != nil || d < time.Second || d > time.Minute {
			bad("identity.revocation.sync_interval", "%q must be a Go duration from 1s to 60s", v)
		}
	}
	if v := rv.MaxStale; v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err != nil || d < 2*rv.EffectiveSyncInterval() || d > time.Hour {
			bad("identity.revocation.max_stale", "%q must be a Go duration of at least 2 x sync_interval (%s) and at most 1h", v, 2*rv.EffectiveSyncInterval())
		}
	}
	if n := rv.MaxTokensPerPerson; n < 0 || n > 4096 {
		bad("identity.revocation.max_tokens_per_person", "%d must be from 1 to 4096 (0 = default 64)", n)
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
	if v := s.Skills.Scan.Timeout; v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err != nil || d <= 0 || d > MaxSubstrateSkillScanTimeout {
			bad("skills.scan.timeout", "%q must be a Go duration over 0 and at most 10m", v)
		}
	}
	if v := s.Skills.PendingWait; v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err != nil || d <= 0 || d > MaxSubstrateSkillPendingWait {
			bad("skills.pending_wait", "%q must be a Go duration over 0 and at most 8s (under the kit's 9 s first attempt)", v)
		}
	}
	if r := s.Unattended.TelemetrySampling; r != nil && (*r < 0 || *r > 1) {
		bad("unattended.telemetry_sampling", "%v is outside 0-1", *r)
	}
	s.Interactive.validate(bad)
	s.Usage.validate(bad)
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
	if n := s.Extproc.RateLimits.PerActorRPS; n < 0 || n > 1e6 {
		bad("extproc.rate_limits.per_actor_rps", "%v is outside 0-1000000 (0 is the callout's default)", n)
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
	checkPatterns("egress.no_swap_hosts", s.Egress.NoSwapHosts)
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
	ss := s.SelfServiceSecrets
	if !slices.Contains([]string{"", SelfServiceBindings, SelfServiceValuesOnly, SelfServiceOff}, ss.Mode) {
		bad("self_service_secrets.mode", "must be bindings, values_only or off")
	}
	if ss.Namespace != "" && !egressspec.IsDNS1123Label(ss.Namespace) {
		bad("self_service_secrets.namespace", "%q is not a Kubernetes namespace name", ss.Namespace)
	} else if slices.Contains(substrateReservedNamespaces, ss.Namespace) {
		bad("self_service_secrets.namespace", "%q is a Kubernetes system namespace; use a namespace of its own", ss.Namespace)
	} else if _, ok := s.LauncherAtespace(ss.Namespace); ok && ss.Namespace != "" {
		bad("self_service_secrets.namespace", "%q is a launcher atespace, where actors run; use a namespace of its own", ss.Namespace)
	}
	if ss.Provider != "" && !egressspec.IsDNS1123Subdomain(ss.Provider) {
		bad("self_service_secrets.provider", "%q is not a provider name", ss.Provider)
	}
	if ss.MaxPerPerson < 0 || ss.MaxPerPerson > 200 {
		bad("self_service_secrets.max_per_person", "must be 1-200")
	}
	if !slices.Contains([]string{"", "ask", "refuse"}, ss.OutsideTemplates) {
		bad("self_service_secrets.outside_templates", "must be ask or refuse")
	}
	if ss.AskTimeout != "" {
		if d, err := time.ParseDuration(ss.AskTimeout); err != nil || d <= 0 || d > 168*time.Hour {
			bad("self_service_secrets.ask_timeout", "must be a duration over 0 and at most 168h")
		}
	}
	tmplNames := map[string]bool{}
	for i, t := range s.SecretTemplates {
		key := fmt.Sprintf("secret_templates[%d]", i)
		if !substrateTemplateNameRE.MatchString(t.Name) {
			bad(key+".name", "%q must be 1-63 lower-case letters, digits and \"-\"", t.Name)
		} else if tmplNames[t.Name] {
			bad(key+".name", "%q is listed twice", t.Name)
		}
		tmplNames[t.Name] = true
		checkPatterns(key+".hosts", t.Hosts)
		if !slices.Contains([]string{"", "bearer", "basic", "raw"}, t.Form) {
			bad(key+".form", "must be bearer, basic or raw")
		}
		if !slices.Contains([]string{"", "none", "npm", "pypi"}, t.Registry) {
			bad(key+".registry", "must be none, npm or pypi")
		}
		if t.Header != "" && !substrateHeaderNameRE.MatchString(t.Header) {
			bad(key+".header", "%q is not a header name", t.Header)
		}
		if t.BasicUser != "" && !substrateBasicUserRE.MatchString(t.BasicUser) {
			bad(key+".basic_user", "must be 1-128 printable characters with no space or \":\"")
		}
		for j, g := range t.Profiles {
			if _, err := path.Match(g, ""); err != nil {
				bad(fmt.Sprintf("%s.profiles[%d]", key, j), "%q is not a profile glob", g)
			}
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
	s.Activity.validate(bad)
	if err := s.Admin.validateAs("admin"); err != nil {
		errs = append(errs, err)
	}
	if err := s.Admin.substrateScopeError("admin"); err != nil {
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
	if f := t.RegistryAuth.DockerConfig; f != "" && !path.IsAbs(f) {
		bad("templates.registry_auth.docker_config", "%q must be an absolute path", f)
	}
	for i, h := range t.RegistryAuth.ECRHosts {
		if _, _, _, ok := ParseECRRegistryHost(h); !ok {
			bad(fmt.Sprintf("templates.registry_auth.ecr_hosts[%d]", i), "%q must be an Amazon ECR registry host (<account>.dkr.ecr.<region>.amazonaws.com)", h)
		}
	}
}

var substrateDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateManaged applies the managed-enterprise rules (D8): the callout
// always fails closed (extproc.failure_mode and extproc.chain.failure_mode
// open are refused; chain auto already means closed there, GAP-0063 and
// GAP-0090), templates are always attested, and the template registries are
// named (GAP-0131).
func (s *SubstrateConfig) ValidateManaged(deploymentMode string) error {
	if s == nil || !strings.EqualFold(strings.TrimSpace(deploymentMode), string(DeploymentModeManagedEnterprise)) {
		return nil
	}
	var errs []error
	if strings.EqualFold(strings.TrimSpace(s.Extproc.FailureMode), SubstrateFailOpen) {
		errs = append(errs, errors.New(`extproc.failure_mode: "open" is not allowed in managed_enterprise (the callout always fails closed)`))
	}
	if strings.EqualFold(strings.TrimSpace(s.Extproc.Chain.FailureMode), SubstrateFailOpen) {
		errs = append(errs, errors.New("extproc.chain.failure_mode: open is not allowed with deployment_mode managed_enterprise: the callout fails closed there (use auto or closed)"))
	}
	if s.Enabled && !s.AttestationRequired() {
		errs = append(errs, errors.New("require_attested_templates: false is not allowed in managed_enterprise"))
	}
	if s.Enabled && len(s.Templates.AllowedImages) == 0 {
		errs = append(errs, errors.New("templates.allowed_images: managed_enterprise names the template registries and repositories"))
	}
	if !s.Identity.Revocation.EffectiveEnabled() {
		errs = append(errs, errors.New("identity.revocation.enabled: false is not allowed in managed_enterprise (ended sign-ins are always refused)"))
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
		{"extproc.chain.send_budget", e.Chain.SendBudget, 500 * time.Millisecond},
		{"extproc.ask.hold", e.Ask.Hold, 1800 * time.Millisecond},
		{"extproc.judge.timeout", e.Judge.Timeout, 1800 * time.Millisecond},
	} {
		if d.v == "" {
			continue
		}
		if v, err := time.ParseDuration(strings.TrimSpace(d.v)); err != nil || v < 0 || v > d.max {
			bad(d.key, "%q must be a Go duration from 0 to %s", d.v, d.max)
		}
	}
	switch strings.ToLower(strings.TrimSpace(e.Chain.FailureMode)) {
	case "", "auto", SubstrateFailClosed, SubstrateFailOpen:
	default:
		bad("extproc.chain.failure_mode", "%q must be auto, closed or open", e.Chain.FailureMode)
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
		} else if !substrateWorkloadSubjectRe.MatchString(strings.TrimSpace(w)) {
			errs = append(errs, fmt.Errorf("%s.workloads: "+substrateWorkloadSubjectHint, prefix, w))
		}
	}
	return errors.Join(errs...)
}

// substrateWorkloadSubjectRe is the workload subject rule (GAP-0043), the
// same as identity.WorkloadSubjectPattern (config does not import the
// identity package): exact, or a prefix ending in ":*" or "/*" with a
// separator before the last one (so repo:* is refused, repo:acme/* is not).
var substrateWorkloadSubjectRe = regexp.MustCompile(`^(?:[^*]+|[^*]*[:/][^*]+[:/]\*)$`)

const substrateWorkloadSubjectHint = `%q must be exact or end in ":*" or "/*" (for example repo:acme/web:*); a raw prefix such as repo:acme/web* also trusts repo:acme/web-evil, a wildcard right after the first segment (repo:*) trusts every repository of the issuer, and a bare * trusts everything`

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	// '#' and '?' anywhere, empty ones too: the person key is
	// issuer#subject, so an issuer ending in '#' would be ambiguous.
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && !strings.ContainsAny(raw, "#?")
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

// SubstrateSkillsConfig is the gateway's scan of skill folders an agent adds
// while it runs (B5.4, GAP-0477): the chart's scanner sidecar runs the
// laptop's skill-scanner on each folder the kit attaches.
type SubstrateSkillsConfig struct {
	Scan SubstrateSkillsScanConfig `mapstructure:"scan" yaml:"scan,omitempty"`
	// PendingWait is how long one hook post waits for the scans of its skill
	// folders, in every tier: one deadline for the post, the wait for a scan
	// slot and every folder included (default 8s, at most 8s: under the
	// kit's 9 s first attempt, so every post is answered; GAP-0980,
	// GAP-0982). Past it the folder is still being checked and its scan goes
	// on (Scan.Timeout): the OSS tiers ask or allow it with an alert; managed
	// installs and the strict tier refuse every tool call until it has a
	// verdict. The kit sends it again with its next hook.
	PendingWait string `mapstructure:"pending_wait" yaml:"pending_wait,omitempty"`
}

// SubstrateSkillsScanConfig turns the scanner sidecar on or off and bounds
// one scan.
type SubstrateSkillsScanConfig struct {
	// Enabled uses the scanner sidecar (nil = on). Off: no folder is scanned
	// and the fail mode decides, as before the sidecar (managed installs and
	// the strict tier refuse every new skill). This is the admin-off switch.
	Enabled *bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// Timeout bounds one folder's scan (default 20s, at most 10m); past it
	// the fail mode decides (reason skill_scan_timeout).
	Timeout string `mapstructure:"timeout" yaml:"timeout,omitempty"`
}

const (
	DefaultSubstrateSkillScanTimeout = 20 * time.Second
	MaxSubstrateSkillScanTimeout     = 10 * time.Minute
	DefaultSubstrateSkillPendingWait = 8 * time.Second
	MaxSubstrateSkillPendingWait     = 8 * time.Second
)

// SkillScanEnabled says whether the gateway scans skill folders (default on).
func (s SubstrateConfig) SkillScanEnabled() bool {
	return s.Skills.Scan.Enabled == nil || *s.Skills.Scan.Enabled
}

// EffectiveSkillScanTimeout is skills.scan.timeout, bounded.
func (s SubstrateConfig) EffectiveSkillScanTimeout() time.Duration {
	d := durationOr(s.Skills.Scan.Timeout, DefaultSubstrateSkillScanTimeout)
	if d <= 0 || d > MaxSubstrateSkillScanTimeout {
		return DefaultSubstrateSkillScanTimeout
	}
	return d
}

// EffectiveSkillPendingWait is skills.pending_wait, bounded.
func (s SubstrateConfig) EffectiveSkillPendingWait() time.Duration {
	d := durationOr(s.Skills.PendingWait, DefaultSubstrateSkillPendingWait)
	if d <= 0 || d > MaxSubstrateSkillPendingWait {
		return DefaultSubstrateSkillPendingWait
	}
	return d
}
