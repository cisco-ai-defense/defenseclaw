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
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
	kernelcontrols "github.com/defenseclaw/defenseclaw/policies/kernel"
)

// The effective policy digest (spec section 5) is
// "sha256:" + hex(sha256(canonical JSON of
// {"v":1,"config":<config digest>,"assets":{...},"profiles":{...}})).
// Every component digest is also kept in Generation.Components so doctor and
// /health can say which part changed.

// dataDirToken replaces the data_dir prefix of every path, so two users with
// the same policy produce the same digest.
const dataDirToken = "${data_dir}"

// bundleRootToken replaces the policy bundle root prefix of every path, so a
// bundle digests the same in the signer's working directory and in the
// versioned directory a device installs it to.
const bundleRootToken = "${bundle_root}"

// digestScope is what the effective digest abstracts away from the host: the
// data_dir and policy bundle root path prefixes, and the platform whose
// policy is digested (the kernel control set exists only on Linux).
type digestScope struct {
	dataDir                  string
	bundleRoot               string
	goos                     string
	vendorRoot, vendorTarget string
}

// newDigestScope is the scope of cfg on goos ("" is this platform) with a
// policy bundle installed at bundleRoot ("" for none).
func newDigestScope(cfg *config.Config, goos, bundleRoot string) digestScope {
	if goos == "" {
		goos = runtime.GOOS
	}
	root := ""
	if bundleRoot = strings.TrimSpace(bundleRoot); bundleRoot != "" {
		root = strings.TrimRight(filepath.Clean(bundleRoot), `/\`)
	}
	return digestScope{dataDir: dataDirOf(cfg), bundleRoot: root, goos: goos}
}

// rewrite replaces a leading bundle root with ${bundle_root}, else a leading
// data_dir with ${data_dir}.
func (s digestScope) rewrite(value string) string {
	if s.vendorRoot != "" {
		if out, ok := rewritePathPrefix(value, s.vendorRoot, s.vendorTarget, s.goos); ok {
			value = out
		}
	}
	if out, ok := rewritePathPrefix(value, s.bundleRoot, bundleRootToken, s.goos); ok {
		return out
	}
	out, _ := rewritePathPrefix(value, s.dataDir, dataDirToken, s.goos)
	return out
}

// bundleFile reports whether an asset is shipped by this bundle. Runtime
// files outside it may differ between an offline signer and a device.
func (s digestScope) bundleFile(value string) bool {
	if s.bundleRoot == "" {
		return true
	}
	_, ok := rewritePathPrefix(value, s.bundleRoot, bundleRootToken, s.goos)
	return ok
}

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
func configDigest(cfg *config.Config, scope digestScope) (string, error) {
	if canonical := cfg.OpenShellPackDirForDigest(); canonical != cfg.OpenShell.PackDir {
		copy := *cfg
		copy.OpenShell.PackDir = canonical
		cfg = &copy
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("config digest: %w", err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("config digest: %w", err)
	}
	dropTetragonDefaults(doc)
	dropFleetDefaults(doc)
	doc = materializeConfigDefaults(cfg, doc)
	canonical, err := json.Marshal(canonicalConfigValue("", doc, scope))
	if err != nil {
		return "", fmt.Errorf("config digest: %w", err)
	}
	return sha256Digest(canonical), nil
}

// dropTetragonDefaults removes the enterprise.tetragon values equal to their
// built-in defaults (mode consume, burn_in 168h, an empty enforce_ack,
// customer_events agent) from the marshalled config, and the block (and an
// enterprise block it leaves empty) once nothing is left: an absent block and
// one that spells out the defaults are the same intent and digest the same.
// An enforce_ack list of two or more digests is never a default; a one-item
// list marshals as its string.
func dropTetragonDefaults(doc any) {
	root, _ := doc.(map[string]any)
	enterprise, _ := root["enterprise"].(map[string]any)
	tetragon, _ := enterprise["tetragon"].(map[string]any)
	if tetragon == nil {
		return
	}
	text := func(key string) string {
		value, _ := tetragon[key].(string)
		return value
	}
	written := config.EnterpriseTetragonConfig{Mode: text("mode"), BurnIn: text("burn_in"),
		EnforceAck: config.TetragonEnforceAcks{text("enforce_ack")}, CustomerEvents: text("customer_events")}
	effective, defaults := written.Effective(), config.EnterpriseTetragonConfig{}.Effective()
	for key, isDefault := range map[string]bool{
		"mode":            effective.Mode == defaults.Mode,
		"burn_in":         effective.BurnIn == defaults.BurnIn,
		"enforce_ack":     len(effective.EnforceAck) == 0,
		"customer_events": effective.CustomerEvents == defaults.CustomerEvents,
	} {
		if _, isText := tetragon[key].(string); isDefault && isText {
			delete(tetragon, key)
		}
	}
	if len(tetragon) == 0 {
		delete(enterprise, "tetragon")
	}
	if len(enterprise) == 0 {
		delete(root, "enterprise")
	}
}

func dropFleetDefaults(doc any) {
	root, _ := doc.(map[string]any)
	fleet, ok := root["fleet"].(map[string]any)
	if !ok {
		return
	}
	enabled, _ := fleet["enabled"].(bool)
	if !enabled {
		delete(root, "fleet")
	}
}

// materializeConfigDefaults makes the config document digest what is
// enforced, not how it was written (spec section 5, defaults materialised):
// admission: becomes the compiled admission policy, so an explicit empty
// first_party_allow_list (which YAML omits) differs from the built-in list and
// a value equal to its default digests like the unset key; a connector's
// enabled: true is the default and is dropped; a block_at or alert_at level is
// upper-cased (the schema takes it in any case and enforcement reads it so, so
// high and HIGH are one policy, GAP-0329). A Secure Client host keeps its
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
		canonicalizeGuardrailLevels(guardrail)
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

// canonicalizeGuardrailLevels upper-cases every block_at and alert_at string
// in value (the guardrail section: global, connectors and profiles).
func canonicalizeGuardrailLevels(value any) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if level, ok := child.(string); ok && (key == "block_at" || key == "alert_at") {
				v[key] = strings.ToUpper(strings.TrimSpace(level))
				continue
			}
			canonicalizeGuardrailLevels(child)
		}
	case []any:
		for _, child := range v {
			canonicalizeGuardrailLevels(child)
		}
	}
}

// observabilityDigest digests the observability section of config.yaml
// (local retention, destinations, redaction profiles) the way configDigest
// digests the rest. The typed Config carries only per-connector overrides of
// that section, so configDigest alone never saw a retention or redaction
// change (GAP-0007). raw is the file's bytes; nil reads cfg.ConfigFilePath. A
// config with no readable file has no observability component.
func observabilityDigest(cfg *config.Config, raw []byte, scope digestScope) string {
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
	canonical, err := json.Marshal(canonicalConfigValue("observability", doc.Observability, scope))
	if err != nil {
		return ""
	}
	return sha256Digest(canonical)
}

func canonicalConfigValue(path string, value any, scope digestScope) any {
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
			out[key] = canonicalConfigValue(childPath, child, scope)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = canonicalConfigValue(path, child, scope)
		}
		return out
	case string:
		return scope.rewrite(v)
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

// rewritePathPrefix replaces a leading root (a cleaned directory) with token
// and reports whether it did. On Windows a value written with forward slashes
// still matches the cleaned root.
func rewritePathPrefix(value, root, token, goos string) (string, bool) {
	if root == "" || root == "." {
		return value, false
	}
	slashed, prefix := filepath.ToSlash(value), filepath.ToSlash(root)
	if goos == "windows" {
		slashed = strings.ReplaceAll(value, `\`, "/")
		prefix = strings.ReplaceAll(root, `\`, "/")
		if !strings.HasPrefix(strings.ToLower(slashed), strings.ToLower(prefix)) {
			return value, false
		}
	} else if !strings.HasPrefix(slashed, prefix) {
		return value, false
	}
	rest := slashed[len(prefix):]
	if rest == "" || rest[0] == '/' || rest[0] == '\\' {
		return token + rest, true
	}
	return value, false
}

// assetDigestComponents digests the policy assets config references by path
// (spec section 5): the sandbox pack pin, signature packs, the discovery
// confidence policy, the skill-scanner policy file, the MCP scanner's extra
// YARA rules, and the built-in policy bundle compiled into this binary. A
// file that cannot be read is recorded as "missing" so its later appearance
// changes the digest.
func assetDigestComponents(cfg *config.Config, scope digestScope) map[string]string {
	out := map[string]string{}
	if cfg == nil {
		return out
	}
	if digest := strings.TrimSpace(packs.BaseFloor(cfg).RequiredPackDigest); digest != "" {
		out["sandbox_pack"] = digest
	}
	for key, digest := range signaturePackDigests(cfg, scope) {
		out[key] = digest
	}
	if digest := confidencePolicyDigest(cfg, scope); digest != "" {
		out[confidencePolicyComponent] = digest
	}
	if ref := cfg.Scanners.SkillScanner.PolicyFile; strings.TrimSpace(ref.Path) != "" && scope.bundleFile(ref.Path) {
		out["scanner_policy:skill"] = assetRefDigest(ref)
	}
	if refs := cfg.Scanners.MCPScanner.YARA.ExtraRules; len(refs) > 0 {
		digests := make([]string, 0, len(refs))
		for _, ref := range refs {
			if !scope.bundleFile(ref.Path) {
				continue
			}
			digests = append(digests, scope.rewrite(ref.Path)+"="+assetRefDigest(ref))
		}
		if len(digests) > 0 {
			sort.Strings(digests)
			out["yara_rules:mcp"] = sha256Digest([]byte(strings.Join(digests, "\n")))
		}
	}
	for _, provider := range cfg.LLMProviders.Custom {
		if provider.TLS != nil && strings.TrimSpace(provider.TLS.CACertFile) != "" && scope.bundleFile(provider.TLS.CACertFile) {
			out["provider_ca:"+provider.Name] = fileDigest(strings.TrimSpace(provider.TLS.CACertFile))
		}
	}
	if digest := builtinPolicyDigest(); digest != "" {
		out["builtin"] = digest
	}
	if digest := kernelPolicyComponent(cfg, scope.goos); digest != "" {
		out["kernel_policy"] = digest
	}
	return out
}

// kernelPolicyComponent is the kernel_policy component (spec 12.2): the
// digest of the kernel control set compiled into this binary, present only
// where the sensor helper loads it, a Linux standalone deployment whose
// effective enterprise.tetragon mode is observe or enforce. It is the short
// form ("sha256:" and 12 hex) that the helper reports in kernel_status and
// that enforce_ack approves, so doctor, enterprise status and the kernel
// denial records compare the same value. A new build with another control
// set therefore moves the effective digest.
func kernelPolicyComponent(cfg *config.Config, goos string) string {
	switch mode, _ := cfg.TetragonMode(goos); mode {
	case config.TetragonModeObserve, config.TetragonModeEnforce:
		return kernelcontrols.Digest()
	}
	return ""
}

// signaturePackDigests digests each ai_discovery.signature_packs entry, keyed
// "signature_pack:<entry>". An entry that is a directory or a glob is digested
// over the pack files it names now, so adding, removing or editing one changes
// the digest. A glob with wildcards in its folders is digested over the
// folders they match as well: a new matching folder makes a new generation,
// whose watch includes it, so a pack created there is seen (GAP-0858).
func signaturePackDigests(cfg *config.Config, scope digestScope) map[string]string {
	out := map[string]string{}
	for _, entry := range cfg.AIDiscovery.SignaturePacks {
		if entry = strings.TrimSpace(entry); entry == "" {
			continue
		}
		if !scope.bundleFile(entry) {
			continue
		}
		files, _ := inventory.SignaturePackEntry(entry)
		dirs := inventory.SignaturePackWildcardDirs(entry)
		digest := "missing"
		if len(files) > 0 || len(dirs) > 0 {
			parts := make([]string, 0, len(files)+len(dirs))
			for _, file := range files {
				parts = append(parts, scope.rewrite(file)+"="+fileDigest(file))
			}
			for _, dir := range dirs {
				parts = append(parts, "dir:"+scope.rewrite(dir))
			}
			sort.Strings(parts)
			digest = sha256Digest([]byte(strings.Join(parts, "\n")))
		}
		out["signature_pack:"+scope.rewrite(entry)] = digest
	}
	return out
}

// confidencePolicyComponent is the generation component of the discovery
// confidence policy file.
const confidencePolicyComponent = "confidence_policy"

// confidencePolicyDigest digests ai_discovery.confidence_policy_path, or is
// "" when no path is set or the file does not exist (the built-in policy).
func confidencePolicyDigest(cfg *config.Config, scope digestScope) string {
	path := strings.TrimSpace(cfg.AIDiscovery.ConfidencePolicyPath)
	if path == "" || !scope.bundleFile(path) {
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
	for key, digest := range signaturePackDigests(cfg, newDigestScope(cfg, live.goos, live.bundleRoot)) {
		if live.Components[key] != digest {
			return true
		}
	}
	return !cfg.SecureClientIntegration() && live.Components[confidencePolicyComponent] != confidencePolicyDigest(cfg, newDigestScope(cfg, live.goos, live.bundleRoot))
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

// EffectivePolicyOptions select what ComputeEffectivePolicyFor digests.
type EffectivePolicyOptions struct {
	// GOOS is the platform whose policy is digested; "" is this platform.
	// The kernel control set is part of the Linux policy only.
	GOOS string
	// BundleRoot is the directory of the policy bundle cfg was rendered
	// from; every path under it digests as ${bundle_root}/..., so a bundle
	// digests the same wherever it is unpacked. "" for no bundle. A bundle
	// digest is computed offline (bundle sign runs on any host), so the
	// managed policy_dir ownership check, which guards what a gateway
	// loads, is skipped; it does not change the digest.
	BundleRoot string
	// Raw is the config.yaml bytes cfg was loaded from; nil reads
	// cfg.ConfigFilePath.
	Raw []byte
}

// ComputeEffectivePolicy builds the generation the gateway would publish for
// cfg, without publishing it, and returns its digest. doctor and the
// enterprise status result compare it with the running gateway's
// /health policy.effective_digest to detect a stale gateway.
func ComputeEffectivePolicy(ctx context.Context, cfg *config.Config) (EffectivePolicy, error) {
	return ComputeEffectivePolicyFor(ctx, cfg, EffectivePolicyOptions{})
}

// ComputeEffectivePolicyFor is ComputeEffectivePolicy for another platform
// or for a configuration rendered from a policy bundle (bundle sign computes
// one digest per target platform). It publishes nothing. An offline bundle
// load stages a temporary copy of built-in vendor packs and removes it.
func ComputeEffectivePolicyFor(ctx context.Context, cfg *config.Config, opts EffectivePolicyOptions) (EffectivePolicy, error) {
	if cfg == nil {
		return EffectivePolicy{}, fmt.Errorf("effective policy: configuration is unavailable")
	}
	cfg = cloneConfig(cfg)
	packCfg := cfg
	vendorRoot, vendorTarget := "", ""
	if strings.TrimSpace(opts.BundleRoot) != "" {
		var cleanup func()
		var err error
		packCfg, vendorRoot, vendorTarget, cleanup, err = offlineVendorPolicyConfig(cfg, opts.GOOS)
		if err != nil {
			return EffectivePolicy{}, err
		}
		defer cleanup()
	}
	rulePacks, err := generationRulePacks(packCfg)
	if err != nil {
		return EffectivePolicy{}, err
	}
	profiles, err := newGuardrailProfileSet(packCfg, rulePacks.cache, false)
	if err != nil {
		profiles = nil
	}
	g, err := buildGeneration(ctx, generationInputs{cfg: cfg, raw: opts.Raw, rulePacks: rulePacks, profiles: profiles,
		goos: opts.GOOS, bundleRoot: opts.BundleRoot, offline: strings.TrimSpace(opts.BundleRoot) != "",
		vendorRoot: vendorRoot, vendorTarget: vendorTarget})
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

// offlineVendorPolicyConfig loads shipped rule packs from this binary rather
// than from the signer's /opt tree. Their content is pinned by product_version
// and excluded from the bundle digest. The gateway still loads its installed
// copies for enforcement. Every pack that resolves under the vendor folder is
// substituted, whatever policy_dir is: the shipped templates set policy_dir to
// the administrator folder, whose missing default pack falls back to the
// vendor folder on the signer as it does on a device (GAP-0223).
func offlineVendorPolicyConfig(cfg *config.Config, goos string) (*config.Config, string, string, func(), error) {
	if goos == "" {
		goos = runtime.GOOS
	}
	if (goos != "linux" && goos != "darwin") || !cfg.StandaloneEnterprise() {
		return cfg, "", "", func() {}, nil
	}
	layout, err := managed.StandaloneLayoutFor(goos)
	if err != nil {
		return nil, "", "", nil, err
	}
	if !referencesVendorPolicies(cfg, layout.VendorPolicyDir) {
		return cfg, "", "", func() {}, nil
	}
	root, err := os.MkdirTemp("", "defenseclaw-vendor-policy-")
	if err != nil {
		return nil, "", "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	files, err := policyassets.Files()
	if err != nil {
		cleanup()
		return nil, "", "", nil, err
	}
	for _, file := range files {
		name := filepath.Join(root, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			cleanup()
			return nil, "", "", nil, err
		}
		if err := os.WriteFile(name, file.Data, 0o600); err != nil {
			cleanup()
			return nil, "", "", nil, err
		}
	}
	copy := cloneConfig(cfg)
	copy.UseOfflineVendorPolicies(layout.VendorPolicyDir, root)
	return copy, root, layout.VendorPolicyDir, cleanup, nil
}

// referencesVendorPolicies reports whether a rule pack cfg can load resolves
// under the shipped policy folder vendorDir.
func referencesVendorPolicies(cfg *config.Config, vendorDir string) bool {
	vendor := strings.TrimRight(path.Clean(filepath.ToSlash(vendorDir)), "/")
	for _, dir := range cfg.ReferencedRulePackDirs() {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		clean := path.Clean(filepath.ToSlash(dir))
		if clean == vendor || strings.HasPrefix(clean, vendor+"/") {
			return true
		}
	}
	return false
}

// generationRulePacks is the rule-pack set a generation digests: the reload
// preflight's (global, every enabled connector's and sandbox harness's
// pack), else the boot set with valid connector packs retained when one
// connector pack fails, as boot tolerates.
func generationRulePacks(cfg *config.Config) (*sidecarRulePackCandidate, error) {
	if candidate, err := preflightSidecarRulePacks(cfg); err == nil {
		return candidate, nil
	}
	global, active, cache, err := loadInitialSidecarRulePack(cfg)
	if err != nil {
		return nil, err
	}
	if candidate, err := preflightSidecarRulePacksWithCacheMode(cache, cfg, true); err == nil {
		return candidate, nil
	}
	return &sidecarRulePackCandidate{cache: cache, global: global, active: active}, nil
}
