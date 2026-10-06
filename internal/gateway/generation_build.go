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
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// Building and publishing a Generation (generation.go). The sidecar builds
// one at boot and on every validated reload (config or referenced asset),
// before its commit point; a build error keeps the previous generation.
// Requests load the published generation once (currentGeneration) and read
// thresholds, the prepared OPA queries and the profile set from it.

// generationInputs is what one build compiles. rulePacks and profiles are
// prepared by the caller, which decides how strict a pack load is (boot
// isolates multi-connector packs, a reload validates every one).
type generationInputs struct {
	cfg *config.Config
	// raw is the config.yaml bytes cfg was loaded from; nil reads the file.
	raw       []byte
	rulePacks *sidecarRulePackCandidate
	profiles  *guardrailProfileSet
	// strictOPA makes a Rego module that fails to load a build error. When
	// false the generation has no OPA and the guardrail falls back.
	strictOPA bool
}

func buildGeneration(ctx context.Context, in generationInputs) (*Generation, error) {
	cfg := in.cfg
	if cfg == nil {
		return nil, fmt.Errorf("generation: configuration is unavailable")
	}
	g := &Generation{
		Config:     cfg,
		RulePacks:  map[string]*guardrail.RulePack{},
		Profiles:   in.profiles,
		Components: map[string]string{},
		BuiltAt:    time.Now().UTC(),
		Scanners: scannerSettings{
			Skill: cfg.Scanners.SkillScanner,
			MCP:   cfg.Scanners.MCPScanner,
		},
	}
	assetPolicy := cfg.AssetPolicy
	g.AssetPolicy = &assetPolicy

	if rp := in.rulePacks; rp != nil {
		if rp.global != nil {
			g.RulePacks["global"] = rp.global
		}
		for name, pack := range rp.connectors {
			g.RulePacks["conn:"+name] = pack
		}
		g.active = rp.active
	}
	if in.profiles != nil {
		for name, derived := range in.profiles.profiles {
			if pack := in.profiles.packs[globalRulePackScope(derived.Config).key()]; pack != nil {
				g.RulePacks["prof:"+name] = pack
			}
			for _, connector := range thresholdConnectorNames(derived.Config) {
				if pack := in.profiles.packs[effectiveRulePackKey(derived.Config, connector)]; pack != nil {
					g.RulePacks["prof:"+name+"/"+connector] = pack
				}
			}
		}
	}

	if dir := strings.TrimSpace(cfg.PolicyDir); dir != "" {
		prepared, err := policy.Prepare(ctx, dir)
		switch {
		case err == nil:
			g.OPA = prepared
		case in.strictOPA:
			return nil, fmt.Errorf("generation: OPA policy: %w", err)
		default:
			g.opaError = err.Error()
			fmt.Fprintf(os.Stderr, "[sidecar] OPA policy unavailable (guardrail falls back to the resolved thresholds): %v\n", err)
		}
	}

	g.Thresholds = buildThresholdTable(cfg, in.profiles)
	g.ConfigGen, g.ConfigGenRecorded = readConfigGeneration(cfg.ConfigFilePath, in.raw)

	configComponent, err := configDigest(cfg)
	if err != nil {
		return nil, fmt.Errorf("generation: %w", err)
	}
	g.Components["config"] = configComponent
	if digest := observabilityDigest(cfg, in.raw); digest != "" {
		g.Components["observability"] = digest
	}
	if digest, err := config.GuardrailPolicyDigest(cfg); err == nil {
		g.Components["guardrail_policy"] = digest
	}
	for key, digest := range assetDigestComponents(cfg) {
		g.Components[key] = digest
	}
	// The config digest cannot tell an unset list (built-in default) from an
	// empty one: the marshalled config drops both. The compiled admission
	// carries the lists as enforced, so unset and [] digest differently.
	if !cfg.SecureClientIntegration() {
		if raw, err := json.Marshal(policy.CompileAdmission(cfg)); err == nil {
			g.Components["admission"] = sha256Digest(raw)
		}
	}
	g.Providers = buildGenerationProviders(cfg)
	g.Components["providers"] = g.Providers.digest()
	for key, pack := range g.RulePacks {
		g.Components["rule_pack:"+key] = "sha256:" + pack.Summary().Digest
	}
	if g.OPA != nil {
		g.Components["rego"] = g.OPA.RegoDigest
	}
	profileDigests := map[string]string{}
	if in.profiles != nil {
		for name, derived := range in.profiles.profiles {
			profileDigests[name] = derived.Digest
			g.Components["profile:"+name] = derived.Digest
		}
	}
	g.Digest = effectivePolicyDigest(g.Components, profileDigests)
	g.assetDirs = generationAssetDirs(cfg, g)
	g.assetFiles = generationAssetFiles(cfg)
	return g, nil
}

// generationAssetFiles lists the single-file assets the effective digest
// covers (assetDigestComponents), so an edit to one rebuilds the generation.
func generationAssetFiles(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	seen := map[string]struct{}{}
	add := func(path string) {
		if path = strings.TrimSpace(path); path != "" {
			seen[filepath.Clean(path)] = struct{}{}
		}
	}
	for _, path := range cfg.AIDiscovery.SignaturePacks {
		add(path)
	}
	add(cfg.AIDiscovery.ConfidencePolicyPath)
	add(cfg.Scanners.SkillScanner.PolicyFile.Path)
	for _, ref := range cfg.Scanners.MCPScanner.YARA.ExtraRules {
		add(ref.Path)
	}
	for _, provider := range cfg.LLMProviders.Custom {
		if provider.TLS != nil {
			add(provider.TLS.CACertFile)
		}
	}
	files := make([]string, 0, len(seen))
	for path := range seen {
		files = append(files, path)
	}
	sort.Strings(files)
	return files
}

// effectivePolicyDigest is "sha256:" + the hex SHA-256 of the canonical JSON
// {"v":1,"config":...,"assets":{...},"profiles":{...}}. Map keys marshal
// sorted.
func effectivePolicyDigest(components, profiles map[string]string) string {
	assets := make(map[string]string, len(components))
	for key, value := range components {
		if key != "config" && !strings.HasPrefix(key, "profile:") {
			assets[key] = value
		}
	}
	raw, _ := json.Marshal(struct {
		V        int               `json:"v"`
		Config   string            `json:"config"`
		Assets   map[string]string `json:"assets"`
		Profiles map[string]string `json:"profiles"`
	}{V: 1, Config: components["config"], Assets: assets, Profiles: profiles})
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// readConfigGeneration returns config_generation from config.generation.json
// and whether it recorded the current config bytes (false for a hand edit or
// a missing state file).
func readConfigGeneration(configPath string, raw []byte) (uint64, bool) {
	if strings.TrimSpace(configPath) == "" {
		return 0, false
	}
	state, err := configwrite.ReadGenerationState(configPath)
	if err != nil {
		return 0, false
	}
	if raw == nil {
		raw, err = os.ReadFile(configPath)
		if err != nil {
			return state.Generation, false
		}
	}
	sum := sha256.Sum256(raw)
	recorded := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(state.ConfigSHA256)), "sha256:")
	return state.Generation, recorded == hex.EncodeToString(sum[:])
}

// generationAssetDirs lists the directories the config watcher follows for
// this generation: every loaded rule-pack directory (with its rules/ and
// judge/ folders), custom packs and the Rego modules.
func generationAssetDirs(cfg *config.Config, g *Generation) []string {
	seen := map[string]struct{}{}
	add := func(dir string) {
		if dir = strings.TrimSpace(dir); dir == "" {
			return
		}
		dir = filepath.Clean(dir)
		if _, ok := seen[dir]; ok {
			return
		}
		seen[dir] = struct{}{}
	}
	addPack := func(dir string) {
		if strings.TrimSpace(dir) == "" {
			return
		}
		add(dir)
		add(filepath.Join(dir, "rules"))
		add(filepath.Join(dir, "judge"))
	}
	addPack(globalRulePackScope(cfg).dir)
	for _, name := range thresholdConnectorNames(cfg) {
		addPack(cfg.EffectiveRulePackDirForConnector(name))
	}
	for _, custom := range cfg.Guardrail.CustomPacks {
		addPack(custom.Path)
	}
	if g.Profiles != nil {
		tuned := profileConnectorNames(cfg)
		for _, derived := range g.Profiles.profiles {
			for _, scope := range profileRulePackScopes(derived.Config, tuned) {
				addPack(scope.dir)
			}
		}
	}
	if dir := strings.TrimSpace(cfg.PolicyDir); dir != "" {
		rego := filepath.Join(dir, "rego")
		if info, err := os.Stat(rego); err == nil && info.IsDir() {
			add(rego)
		} else {
			add(dir)
		}
	}
	dirs := make([]string, 0, len(seen))
	for dir := range seen {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	return dirs
}

// liveGeneration is the generation the running gateway last published. The
// proxy and inspectors, which have no Sidecar, read it.
var liveGeneration atomic.Pointer[Generation]

// liveReloadError is the last generation build failure ("" after a
// successful swap), shown as policy.last_reload_error.
var liveReloadError atomic.Value // string

// generationSeq numbers published generations (Generation.N).
var generationSeq atomic.Uint64

var publishGenerationMu sync.Mutex

// currentGeneration returns the published generation, or nil before the
// first one.
func currentGeneration() *Generation {
	return liveGeneration.Load()
}

// publishGeneration numbers g and makes it the live generation.
func publishGeneration(g *Generation) {
	if g == nil {
		return
	}
	publishGenerationMu.Lock()
	defer publishGenerationMu.Unlock()
	g.N = generationSeq.Add(1)
	liveGeneration.Store(g)
	liveReloadError.Store("")
	applyGenerationProviders(g.Providers)
}

// refreshConfigGeneration republishes the live generation with the current
// config_generation state, after config.generation.json changed without a
// policy change. The applied counter N is unchanged.
func refreshConfigGeneration(raw []byte) {
	publishGenerationMu.Lock()
	defer publishGenerationMu.Unlock()
	current := liveGeneration.Load()
	if current == nil || current.Config == nil {
		return
	}
	gen, recorded := readConfigGeneration(current.Config.ConfigFilePath, raw)
	if gen == current.ConfigGen && recorded == current.ConfigGenRecorded {
		return
	}
	next := *current
	next.ConfigGen, next.ConfigGenRecorded = gen, recorded
	liveGeneration.Store(&next)
}

// recordGenerationBuildError keeps the live generation and reports why the
// candidate was rejected.
func recordGenerationBuildError(err error) {
	if err != nil {
		liveReloadError.Store(err.Error())
	}
}

// CurrentPolicyHealth is the "policy" object of /health and /status for the
// live generation. ok is false before the first generation and under the
// Secure Client integration, where the object is omitted.
func CurrentPolicyHealth() (PolicyHealth, bool) {
	g := currentGeneration()
	if g == nil || g.Config == nil || g.Config.SecureClientIntegration() {
		return PolicyHealth{}, false
	}
	health := PolicyHealth{
		EffectiveDigest:          g.Digest,
		Generation:               g.N,
		ConfigGeneration:         g.ConfigGen,
		ConfigGenerationRecorded: g.ConfigGenRecorded,
		BuiltAt:                  g.BuiltAt.Format(time.RFC3339),
		Components:               make(map[string]string, len(g.Components)),
	}
	for key, value := range g.Components {
		health.Components[key] = value
	}
	if msg, _ := liveReloadError.Load().(string); msg != "" {
		health.LastReloadError = msg
	} else if g.opaError != "" {
		health.LastReloadError = "opa: " + g.opaError
	}
	return health, true
}
