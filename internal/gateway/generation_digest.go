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

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// The effective policy digest (spec section 5) is
// "sha256:" + hex(sha256(canonical JSON of
// {"v":1,"config":<config digest>,"assets":{...},"profiles":{...}})).
// Every component digest is also kept in Generation.Components so doctor and
// /health can say which part changed.

// dataDirToken replaces the data_dir prefix of every path, so two users with
// the same policy produce the same digest.
const dataDirToken = "${data_dir}"

// configDigestSecretKeys are the config keys whose values are secret
// material. They are dropped from the digest; *_env and credential refs stay.
var configDigestSecretKeys = map[string]struct{}{
	"token": {}, "api_key": {}, "virustotal_api_key": {}, "bearer_token": {},
	"password": {}, "secret": {}, "client_secret": {}, "private_key": {},
}

// configDigestRuntimeKeys are dotted config paths that are host runtime
// state, not policy: the enterprise hook enumerator fills
// ai_discovery.home_dirs with the machine's eligible users.
var configDigestRuntimeKeys = map[string]struct{}{
	"ai_discovery.home_dirs": {},
}

// configDigest is "sha256:" + hex of the canonical JSON of cfg: secret values
// dropped, paths under data_dir rewritten to ${data_dir}. Map keys marshal
// sorted, so the JSON is canonical.
func configDigest(cfg *config.Config) (string, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("config digest: %w", err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("config digest: %w", err)
	}
	doc = materializeConfigDefaults(cfg, doc)
	canonical, err := json.Marshal(canonicalConfigValue("", doc, dataDirOf(cfg)))
	if err != nil {
		return "", fmt.Errorf("config digest: %w", err)
	}
	return sha256Digest(canonical), nil
}

// materializeConfigDefaults makes the config document digest what is
// enforced, not how it was written (spec section 5, defaults materialised):
// admission: becomes the compiled admission policy, so an explicit empty
// first_party_allow_list (which YAML omits) differs from the built-in list and
// a value equal to its default digests like the unset key; a connector's
// enabled: true is the default and is dropped. A Secure Client host keeps its
// document as written.
func materializeConfigDefaults(cfg *config.Config, doc any) any {
	root, ok := doc.(map[string]any)
	if !ok || cfg == nil || cfg.SecureClientIntegration() {
		return doc
	}
	if raw, err := json.Marshal(policy.CompileAdmission(cfg)); err == nil {
		var compiled any
		if json.Unmarshal(raw, &compiled) == nil {
			root["admission"] = compiled
		}
	}
	if guardrail, ok := root["guardrail"].(map[string]any); ok {
		if overrides, ok := guardrail["connectors"].(map[string]any); ok {
			for _, override := range overrides {
				if fields, ok := override.(map[string]any); ok && fields["enabled"] == true {
					delete(fields, "enabled")
				}
			}
		}
	}
	return root
}

// observabilityDigest digests the observability section of config.yaml
// (local retention, destinations, redaction profiles) the way configDigest
// digests the rest. The typed Config carries only per-connector overrides of
// that section, so configDigest alone never saw a retention or redaction
// change (GAP-0007). raw is the file's bytes; nil reads cfg.ConfigFilePath. A
// config with no readable file has no observability component.
func observabilityDigest(cfg *config.Config, raw []byte) string {
	if raw == nil {
		path := strings.TrimSpace(cfg.ConfigFilePath)
		if path == "" {
			return ""
		}
		var err error
		if raw, err = os.ReadFile(path); err != nil { // #nosec G304 -- the loaded config file.
			return ""
		}
	}
	var doc struct {
		Observability any `yaml:"observability"`
	}
	if yaml.Unmarshal(raw, &doc) != nil {
		return ""
	}
	canonical, err := json.Marshal(canonicalConfigValue("observability", doc.Observability, dataDirOf(cfg)))
	if err != nil {
		return ""
	}
	return sha256Digest(canonical)
}

func canonicalConfigValue(path string, value any, dataDir string) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, child := range v {
			childPath := key
			if path != "" {
				childPath = path + "." + key
			}
			if _, secret := configDigestSecretKeys[key]; secret {
				continue
			}
			if _, runtime := configDigestRuntimeKeys[childPath]; runtime {
				continue
			}
			out[key] = canonicalConfigValue(childPath, child, dataDir)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = canonicalConfigValue(path, child, dataDir)
		}
		return out
	case string:
		return rewriteDataDir(v, dataDir)
	default:
		return v
	}
}

func dataDirOf(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	return strings.TrimRight(filepath.Clean(strings.TrimSpace(cfg.DataDir)), `/\`)
}

// rewriteDataDir replaces a leading data_dir with ${data_dir}. On Windows a
// value written with forward slashes still matches the cleaned data_dir.
func rewriteDataDir(value, dataDir string) string {
	if dataDir == "" || dataDir == "." {
		return value
	}
	slashed, root := filepath.ToSlash(value), filepath.ToSlash(dataDir)
	if !strings.HasPrefix(slashed, root) {
		return value
	}
	rest := slashed[len(root):]
	if rest == "" || rest[0] == '/' || rest[0] == '\\' {
		return dataDirToken + rest
	}
	return value
}

// assetDigestComponents digests the policy assets config references by path
// (spec section 5): the sandbox pack pin, signature packs, the discovery
// confidence policy, the skill-scanner policy file, the MCP scanner's extra
// YARA rules, and the built-in policy bundle compiled into this binary. A
// file that cannot be read is recorded as "missing" so its later appearance
// changes the digest.
func assetDigestComponents(cfg *config.Config) map[string]string {
	out := map[string]string{}
	if cfg == nil {
		return out
	}
	dataDir := dataDirOf(cfg)
	if digest := strings.TrimSpace(cfg.OpenShell.Admin.RequiredPackDigest); digest != "" {
		out["sandbox_pack"] = digest
	}
	for key, digest := range signaturePackDigests(cfg) {
		out[key] = digest
	}
	if digest := confidencePolicyDigest(cfg); digest != "" {
		out[confidencePolicyComponent] = digest
	}
	if ref := cfg.Scanners.SkillScanner.PolicyFile; strings.TrimSpace(ref.Path) != "" {
		out["scanner_policy:skill"] = assetRefDigest(ref)
	}
	if refs := cfg.Scanners.MCPScanner.YARA.ExtraRules; len(refs) > 0 {
		digests := make([]string, 0, len(refs))
		for _, ref := range refs {
			digests = append(digests, rewriteDataDir(ref.Path, dataDir)+"="+assetRefDigest(ref))
		}
		sort.Strings(digests)
		out["yara_rules:mcp"] = sha256Digest([]byte(strings.Join(digests, "\n")))
	}
	for _, provider := range cfg.LLMProviders.Custom {
		if provider.TLS != nil && strings.TrimSpace(provider.TLS.CACertFile) != "" {
			out["provider_ca:"+provider.Name] = fileDigest(strings.TrimSpace(provider.TLS.CACertFile))
		}
	}
	if digest := builtinPolicyDigest(); digest != "" {
		out["builtin"] = digest
	}
	return out
}

// signaturePackDigests digests each ai_discovery.signature_packs entry, keyed
// "signature_pack:<entry>". An entry that is a directory or a glob is digested
// over the pack files it names now, so adding, removing or editing one changes
// the digest.
func signaturePackDigests(cfg *config.Config) map[string]string {
	out := map[string]string{}
	dataDir := dataDirOf(cfg)
	for _, entry := range cfg.AIDiscovery.SignaturePacks {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		files, _ := inventory.SignaturePackEntry(entry)
		digest := "missing"
		if len(files) > 0 {
			parts := make([]string, 0, len(files))
			for _, file := range files {
				parts = append(parts, rewriteDataDir(file, dataDir)+"="+fileDigest(file))
			}
			sort.Strings(parts)
			digest = sha256Digest([]byte(strings.Join(parts, "\n")))
		}
		out["signature_pack:"+rewriteDataDir(entry, dataDir)] = digest
	}
	return out
}

// confidencePolicyComponent is the generation component of the discovery
// confidence policy file.
const confidencePolicyComponent = "confidence_policy"

// confidencePolicyDigest digests ai_discovery.confidence_policy_path, or is
// "" when no path is set or the file does not exist (the built-in policy).
func confidencePolicyDigest(cfg *config.Config) string {
	path := strings.TrimSpace(cfg.AIDiscovery.ConfidencePolicyPath)
	if path == "" {
		return ""
	}
	if digest := fileDigest(path); digest != "missing" {
		return digest
	}
	return ""
}

// discoveryAssetsChanged reports whether a file AI discovery loads once, when
// its service is built, changed on disk since the live generation was built: a
// signature pack or the confidence policy. Such a file edited, created or
// removed in place only takes effect (or is refused, under its pin) when the
// service is rebuilt; without the rebuild the reported digest named a
// confidence policy discovery did not apply (GAP-0316). Secure Client keeps the
// discovery service of main, which a confidence policy edit never rebuilt.
func discoveryAssetsChanged(live *Generation, cfg *config.Config) bool {
	if live == nil || cfg == nil || !cfg.AIDiscovery.Enabled {
		return false
	}
	for key, digest := range signaturePackDigests(cfg) {
		if live.Components[key] != digest {
			return true
		}
	}
	return !cfg.SecureClientIntegration() && live.Components[confidencePolicyComponent] != confidencePolicyDigest(cfg)
}

// assetRefDigest is a reference's pinned digest, else the file's.
func assetRefDigest(ref config.AssetFileRef) string {
	if digest := strings.TrimSpace(ref.Digest); digest != "" {
		return digest
	}
	return fileDigest(ref.Path)
}

func fileDigest(path string) string {
	raw, err := os.ReadFile(path) // #nosec G304 -- a config-referenced policy asset.
	if err != nil {
		return "missing"
	}
	return sha256Digest(raw)
}

// builtinPolicyDigest digests the vendor policy files compiled into this
// binary (policies.Files), so a binary that ships different defaults
// reports a different effective policy.
func builtinPolicyDigest() string {
	files, err := policyassets.Files()
	if err != nil {
		return ""
	}
	h := sha256.New()
	for _, file := range files {
		sum := sha256.Sum256(file.Data)
		fmt.Fprintf(h, "%s\x00%x\n", file.Path, sum)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func sha256Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EffectivePolicy is the effective policy digest of a configuration and its
// per-component digests, as the gateway would publish them.
type EffectivePolicy struct {
	Digest     string            `json:"effective_digest"`
	Components map[string]string `json:"components"`
	// ConfigGeneration and ConfigGenerationRecorded come from
	// config.generation.json.
	ConfigGeneration         uint64 `json:"config_generation"`
	ConfigGenerationRecorded bool   `json:"config_generation_recorded"`
}

// ComputeEffectivePolicy builds the generation the gateway would publish for
// cfg, without publishing it, and returns its digest. doctor and the
// enterprise status result compare it with the running gateway's
// /health policy.effective_digest to detect a stale gateway.
func ComputeEffectivePolicy(ctx context.Context, cfg *config.Config) (EffectivePolicy, error) {
	if cfg == nil {
		return EffectivePolicy{}, fmt.Errorf("effective policy: configuration is unavailable")
	}
	cfg = cloneConfig(cfg)
	rulePacks, err := generationRulePacks(cfg)
	if err != nil {
		return EffectivePolicy{}, err
	}
	profiles, err := newGuardrailProfileSet(cfg, rulePacks.cache, false)
	if err != nil {
		profiles = nil
	}
	g, err := buildGeneration(ctx, generationInputs{cfg: cfg, rulePacks: rulePacks, profiles: profiles})
	if err != nil {
		return EffectivePolicy{}, err
	}
	return EffectivePolicy{
		Digest:                   g.Digest,
		Components:               g.Components,
		ConfigGeneration:         g.ConfigGen,
		ConfigGenerationRecorded: g.ConfigGenRecorded,
	}, nil
}

// generationRulePacks is the rule-pack set a generation digests: the reload
// preflight's (global, every enabled connector's and sandbox harness's
// pack), else the boot set (global and the active pack) when a connector
// pack fails, as boot tolerates.
func generationRulePacks(cfg *config.Config) (*sidecarRulePackCandidate, error) {
	if candidate, err := preflightSidecarRulePacks(cfg); err == nil {
		return candidate, nil
	}
	global, active, cache, err := loadInitialSidecarRulePack(cfg)
	if err != nil {
		return nil, err
	}
	return &sidecarRulePackCandidate{cache: cache, global: global, active: active}, nil
}
