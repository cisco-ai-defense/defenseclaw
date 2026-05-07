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
type Provider struct {
	Name             string                 `json:"name"`
	Domains          []string               `json:"domains"`
	ProfileID        *string                `json:"profile_id"` // nil when no auth-profile exists (e.g. bedrock)
	EnvKeys          []string               `json:"env_keys"`   // env var names for the API key, checked in order
	RequestOverrides map[string]interface{} `json:"request_overrides,omitempty"`
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
			base.Providers[idx].RequestOverrides = mergeJSONObjects(
				base.Providers[idx].RequestOverrides,
				op.RequestOverrides,
			)
			// ProfileID: overlay wins if set.
			if op.ProfileID != nil {
				base.Providers[idx].ProfileID = op.ProfileID
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

func mergeJSONObjects(base, overlay map[string]interface{}) map[string]interface{} {
	if len(base) == 0 && len(overlay) == 0 {
		return nil
	}

	out := make(map[string]interface{}, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}

	for k, v := range overlay {
		if ov, ok := v.(map[string]interface{}); ok {
			if bv, ok := out[k].(map[string]interface{}); ok {
				out[k] = mergeJSONObjects(bv, ov)
				continue
			}
		}
		out[k] = v
	}

	return out
}
