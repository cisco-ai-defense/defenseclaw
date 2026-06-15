// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package configs

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxOverlayBytes bounds the operator overlay read so a runaway
// (malicious or accidental) file cannot OOM the guardrail. 1 MiB is
// three orders of magnitude beyond any realistic provider overlay —
// the built-in providers.json is under 5 KiB.
const maxOverlayBytes = 1 << 20 // 1 MiB

//go:embed providers.json
var providersJSON []byte

// Provider describes a single LLM provider: its canonical name, the domain
// substrings used to identify outbound requests, and the OpenClaw
// auth-profiles.json profile ID used to look up the API key.
//
// Custom-provider extensions (all optional, zero-valued for built-in
// entries) let operator overlays in “~/.defenseclaw/custom-providers.json“
// declare internal/self-hosted endpoints with their own upstream
// adapter, base URL, TLS posture, and request-path overrides. The
// guardrail Bifrost adapter consults these fields at runtime via
// :func:`provider_bifrost.ResolveCustomInstance` so a single overlay
// entry can rebind judge/LLM-agent traffic without code changes.
type Provider struct {
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	ProfileID *string  `json:"profile_id"` // nil when no auth-profile exists (e.g. bedrock)
	EnvKeys   []string `json:"env_keys"`   // env var names for the API key, checked in order

	// BaseProviderType selects the Bifrost adapter family for this
	// instance ("openai" / "bedrock" / "vertex_ai" / "azure" / ...).
	// Empty for built-in providers (the adapter is inferred from Name).
	BaseProviderType string `json:"base_provider_type,omitempty"`

	// BaseURL is the HTTP(S) origin for the custom endpoint, e.g.
	// "https://llm.internal:8443". The Bifrost client appends standard
	// route paths unless overridden by RequestPathOverrides.
	BaseURL string `json:"base_url,omitempty"`

	// AllowedRequests restricts the instance to listed request types
	// (chat / completion / embedding / rerank / image / audio / responses).
	// Empty means "all".
	AllowedRequests []string `json:"allowed_requests,omitempty"`

	// AvailableModels enumerates model ids served by this endpoint.
	// Surfaced to the wizard's model picker; not enforced by the
	// gateway (Bifrost rejects unknown models on its own).
	AvailableModels []string `json:"available_models,omitempty"`

	// RequestPathOverrides remaps Bifrost's default route paths. Keys
	// match AllowedRequests; values are absolute URL paths beginning
	// with "/" (e.g. {"chat": "/openai/v1/chat/completions"}).
	RequestPathOverrides map[string]string `json:"request_path_overrides,omitempty"`

	// TLS holds per-instance TLS settings for self-signed labs.
	TLS *ProviderTLS `json:"tls,omitempty"`

	// Bedrock holds per-instance Bedrock posture (region / auth /
	// deployment aliases). Pointer-typed so absent in the overlay
	// stays absent in the marshalled output and the gateway can
	// distinguish "operator omitted" from "operator set defaults".
	Bedrock *ProviderBedrock `json:"bedrock,omitempty"`

	// Vertex holds per-instance Vertex AI posture (project / region /
	// auth credentials env). Same omitempty semantics as Bedrock.
	Vertex *ProviderVertex `json:"vertex,omitempty"`

	// Azure holds per-instance Azure OpenAI posture (endpoint / API
	// version / auth / deployment aliases). Same omitempty semantics.
	Azure *ProviderAzure `json:"azure,omitempty"`

	// ExtraHeaders are additional HTTP headers sent on every request to
	// this provider (e.g. {"llm-model": "gpt-5-5"} for Circuit routing).
	// Forwarded to Bifrost's NetworkConfig.ExtraHeaders.
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// ProviderTLS describes how the gateway should validate the provider's
// TLS certificate. Mirrors LLMConfig.tls on the Python side so the
// custom-providers.json overlay can carry both.
type ProviderTLS struct {
	// CACertPEM is an inline PEM bundle trusted for this endpoint.
	// Empty means "use the system root store".
	CACertPEM string `json:"ca_cert_pem,omitempty"`
	// InsecureSkipVerify disables certificate validation entirely.
	// Mutually exclusive with CACertPEM; lab use only.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// ProviderBedrock mirrors the Python BedrockKeyConfig dataclass so the
// operator overlay can pre-declare a Bedrock instance's region / auth
// posture / inference-profile prefix / deployment aliases. The gateway
// dispatcher merges this onto the role-level LLM config (role wins,
// overlay fills blanks) before handing it to Bifrost.
type ProviderBedrock struct {
	Region            string            `json:"region,omitempty"`
	AuthMode          string            `json:"auth_mode,omitempty"`
	AccessKeyEnv      string            `json:"access_key_env,omitempty"`
	SecretKeyEnv      string            `json:"secret_key_env,omitempty"`
	SessionTokenEnv   string            `json:"session_token_env,omitempty"`
	ProfileName       string            `json:"profile_name,omitempty"`
	InferenceProfile  string            `json:"inference_profile,omitempty"`
	DeploymentAliases map[string]string `json:"deployment_aliases,omitempty"`
}

// ProviderVertex mirrors the Python VertexKeyConfig dataclass. Auth
// modes: "service_account" (env var holds the JSON), "adc" (ADC chain),
// "workload_identity" (k8s WIF).
type ProviderVertex struct {
	ProjectID             string `json:"project_id,omitempty"`
	Region                string `json:"region,omitempty"`
	AuthMode              string `json:"auth_mode,omitempty"`
	ServiceAccountJSONEnv string `json:"service_account_json_env,omitempty"`
}

// ProviderAzure mirrors the Python AzureKeyConfig dataclass. Auth
// modes: "api_key" (gateway-injected from env), "managed_identity"
// (AAD on the host).
type ProviderAzure struct {
	Endpoint          string            `json:"endpoint,omitempty"`
	APIVersion        string            `json:"api_version,omitempty"`
	AuthMode          string            `json:"auth_mode,omitempty"`
	DeploymentAliases map[string]string `json:"deployment_aliases,omitempty"`
}

// ProvidersConfig is the top-level structure of providers.json.
type ProvidersConfig struct {
	Providers   []Provider `json:"providers"`
	OllamaPorts []int      `json:"ollama_ports"`
}

// LoadProviders parses the embedded providers.json and merges an
// optional operator overlay at ~/.defenseclaw/custom-providers.json.
// The overlay is "additive only": it can introduce new providers or
// extend the ollama_ports list, but a failing parse is tolerated —
// the built-in registry is always returned even if the overlay is
// malformed, so a typo in the overlay file can never take the
// guardrail offline.
//
// Merge rules:
//   - Provider entries are matched by Name (case-insensitive).
//     Same-name providers have their Domains and EnvKeys unioned
//     rather than replaced, so an operator can add a custom domain
//     to a built-in provider without copy-pasting the whole record.
//   - OllamaPorts values are unioned; duplicates are collapsed.
//   - Overlay parse errors are logged to stderr (same surface as the
//     gateway's runtime alerts) but do not fail the load.
func LoadProviders() (*ProvidersConfig, error) {
	var cfg ProvidersConfig
	if err := json.Unmarshal(providersJSON, &cfg); err != nil {
		return nil, err
	}
	mergeCustomProviders(&cfg)
	return &cfg, nil
}

// CustomProvidersPath returns the location of the operator overlay,
// honoring DEFENSECLAW_CUSTOM_PROVIDERS_PATH for test / container
// installs. Empty return value means no overlay applies.
func CustomProvidersPath() string {
	if p := os.Getenv("DEFENSECLAW_CUSTOM_PROVIDERS_PATH"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".defenseclaw", "custom-providers.json")
}

// mergeCustomProviders applies the operator overlay in place.
// Exported through LoadProviders; split for testability.
func mergeCustomProviders(cfg *ProvidersConfig) {
	path := CustomProvidersPath()
	if path == "" {
		return
	}
	f, err := os.Open(path) // #nosec G304 — path is a fixed per-user overlay, documented.
	if err != nil {
		// ENOENT is the common case — overlay absent. Any other
		// error is logged but non-fatal.
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[defenseclaw] custom-providers overlay open error: %v\n", err)
		}
		return
	}
	defer f.Close()
	// Read one extra byte so we can detect (and reject) oversize
	// overlays without having to stat the file separately (which
	// would race the read and let a TOCTOU attacker grow the file
	// after the stat).
	data, err := io.ReadAll(io.LimitReader(f, maxOverlayBytes+1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[defenseclaw] custom-providers overlay read error: %v\n", err)
		return
	}
	if len(data) > maxOverlayBytes {
		fmt.Fprintf(os.Stderr,
			"[defenseclaw] custom-providers overlay rejected: exceeds %d-byte cap (got at least %d bytes)\n",
			maxOverlayBytes, len(data))
		return
	}
	var overlay ProvidersConfig
	if err := json.Unmarshal(data, &overlay); err != nil {
		fmt.Fprintf(os.Stderr, "[defenseclaw] custom-providers overlay parse error: %v\n", err)
		return
	}
	applyOverlay(cfg, overlay)
}

func applyOverlay(base *ProvidersConfig, overlay ProvidersConfig) {
	if base == nil {
		return
	}
	// Normalize overlay domains before merging. The gateway's
	// host-matching (inferProviderFromURL, isKnownProviderDomain)
	// lower-cases the request host but compares to the raw stored
	// entry — so a hand-edited overlay with "Api.OpenAI.com" or
	// " api.openai.com " would silently never match. Normalize here
	// so operator typos become working entries instead of dead ones.
	//
	// Parity with the TypeScript side (applyProviderRegistry): trim,
	// lowercase, and drop empty / scheme-prefixed / path-containing
	// entries that cannot be a valid host.
	for i := range overlay.Providers {
		overlay.Providers[i].Domains = sanitizeDomains(overlay.Providers[i].Domains)
	}
	// Index the base by lowercase name for case-insensitive matching.
	byName := make(map[string]int, len(base.Providers))
	for i, p := range base.Providers {
		byName[lower(p.Name)] = i
	}
	for _, op := range overlay.Providers {
		if op.Name == "" {
			continue
		}
		idx, ok := byName[lower(op.Name)]
		if ok {
			base.Providers[idx].Domains = unionStrings(
				base.Providers[idx].Domains, op.Domains,
			)
			base.Providers[idx].EnvKeys = unionStrings(
				base.Providers[idx].EnvKeys, op.EnvKeys,
			)
			// ProfileID: overlay wins if set.
			if op.ProfileID != nil {
				base.Providers[idx].ProfileID = op.ProfileID
			}
			// Custom-provider fields: overlay wins for scalars, unions for
			// list fields so an operator can incrementally extend the
			// allowed-request set or model list without losing what was
			// already declared.
			if op.BaseProviderType != "" {
				base.Providers[idx].BaseProviderType = op.BaseProviderType
			}
			if op.BaseURL != "" {
				base.Providers[idx].BaseURL = op.BaseURL
			}
			if len(op.AllowedRequests) > 0 {
				base.Providers[idx].AllowedRequests = unionStrings(
					base.Providers[idx].AllowedRequests, op.AllowedRequests,
				)
			}
			if len(op.AvailableModels) > 0 {
				base.Providers[idx].AvailableModels = unionStrings(
					base.Providers[idx].AvailableModels, op.AvailableModels,
				)
			}
			if len(op.RequestPathOverrides) > 0 {
				if base.Providers[idx].RequestPathOverrides == nil {
					base.Providers[idx].RequestPathOverrides = make(map[string]string, len(op.RequestPathOverrides))
				}
				for k, v := range op.RequestPathOverrides {
					base.Providers[idx].RequestPathOverrides[k] = v
				}
			}
			if op.TLS != nil {
				base.Providers[idx].TLS = op.TLS
			}
			// Provider-typed sub-blocks. Overlay wins outright because
			// the embedded providers.json never declares them — the
			// operator overlay is the only source. Pointer assignment
			// rather than field-wise merge keeps the surface tiny and
			// honors omitempty in the marshalled overlay shape.
			if op.Bedrock != nil {
				base.Providers[idx].Bedrock = op.Bedrock
			}
			if op.Vertex != nil {
				base.Providers[idx].Vertex = op.Vertex
			}
			if op.Azure != nil {
				base.Providers[idx].Azure = op.Azure
			}
		} else {
			base.Providers = append(base.Providers, op)
			byName[lower(op.Name)] = len(base.Providers) - 1
		}
	}
	base.OllamaPorts = unionInts(base.OllamaPorts, overlay.OllamaPorts)
}

// sanitizeDomains trims, lower-cases, and filters a slice of
// operator-supplied domain entries. Mirrors the TS
// applyProviderRegistry validation so a hand-edited overlay cannot
// smuggle in a scheme, path, or whitespace-padded entry that the
// Go side silently stores but never matches. Empty / malformed
// entries are dropped (not reported) so a single bad line in the
// overlay does not take the entire file out.
func sanitizeDomains(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if strings.ContainsAny(s, " \t\r\n/\\") {
			continue
		}
		if strings.Contains(s, "://") {
			continue
		}
		out = append(out, s)
	}
	return out
}

func lower(s string) string {
	// local lowercase — stdlib strings would add a dep to a package
	// that currently has zero third-party imports.
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func unionStrings(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func unionInts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	out := make([]int, 0, len(a)+len(b))
	for _, v := range a {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	for _, v := range b {
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
