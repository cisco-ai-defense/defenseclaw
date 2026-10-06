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
	canonical, err := json.Marshal(canonicalConfigValue("", doc, dataDirOf(cfg)))
	if err != nil {
		return "", fmt.Errorf("config digest: %w", err)
	}
	return sha256Digest(canonical), nil
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

// rewriteDataDir replaces a leading data_dir with ${data_dir}.
func rewriteDataDir(value, dataDir string) string {
	if dataDir == "" || dataDir == "." || !strings.HasPrefix(value, dataDir) {
		return value
	}
	rest := value[len(dataDir):]
	if rest == "" || rest[0] == '/' || rest[0] == '\\' {
		return dataDirToken + filepath.ToSlash(rest)
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
	for _, path := range cfg.AIDiscovery.SignaturePacks {
		if path = strings.TrimSpace(path); path != "" {
			out["signature_pack:"+rewriteDataDir(path, dataDir)] = fileDigest(path)
		}
	}
	if path := strings.TrimSpace(cfg.AIDiscovery.ConfidencePolicyPath); path != "" {
		if digest := fileDigest(path); digest != "missing" {
			out["confidence_policy"] = digest
		}
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
	if digest := builtinPolicyDigest(); digest != "" {
		out["builtin"] = digest
	}
	return out
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
	profiles, err := newGuardrailProfileSet(cfg, false)
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
	global, active, err := loadInitialSidecarRulePack(cfg)
	if err != nil {
		return nil, err
	}
	return &sidecarRulePackCandidate{global: global, active: active}, nil
}
