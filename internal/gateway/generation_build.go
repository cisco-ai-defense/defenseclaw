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
	"errors"
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
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
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
	// goos is the platform whose policy is digested ("" is this one) and
	// bundleRoot the policy bundle root whose prefix the digests replace
	// with ${bundle_root} ("" for none).
	goos, bundleRoot string
	// vendorRoot is a temporary copy of the binary's shipped policies used
	// by an offline signer; vendorTarget is its standard installed path.
	vendorRoot, vendorTarget string
	// offline marks a digest computed for a policy bundle, not loaded into
	// a gateway: the managed policy_dir trust check, which keeps a loosened
	// tree out of an enforcing generation, does not apply to a signing host.
	offline bool
	// strictOPA makes a Rego module that fails to load a build error. When
	// false (boot) the generation has no OPA and the guardrail falls back.
	strictOPA bool
	// strictScannerPins makes a pinned scanner file that does not match its
	// digest a build error, so a reload keeps the previous generation. When
	// false (boot) the generation records it and the scans that load the
	// file fail closed.
	strictScannerPins bool
}

// managedPolicyTreeTrust refuses a managed standalone policy_dir that a
// standard user could change (config.ValidateManagedPolicyDir).
var managedPolicyTreeTrust = func(cfg *config.Config, dir string) error {
	if !cfg.StandaloneEnterprise() || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// The same check as the config validation: the rule pack folders no
	// setting names are not loaded, so they are not trust inputs (GAP-1694).
	return validateManagedPolicyDir(cfg, dir, os.Getenv(managed.WindowsServiceAccountEnv))
}

// validateManagedPolicyDir is the shared check managedPolicyTreeTrust runs;
// a test replaces it (the real one needs root-owned folders) to prove the
// gateway's build uses it (GAP-1890).
var validateManagedPolicyDir = config.ValidateManagedPolicyDir

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
		goos:       in.goos,
		bundleRoot: in.bundleRoot,
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
		g.activeRules = rp.activeRules
		g.activePatterns = rp.activePatterns
		for raw, rules := range rp.connectorRules {
			if name := canonicalConnectorRulePackKey(raw); name != "" && rules != nil {
				if g.connectorRules == nil {
					g.connectorRules = make(map[string]*compiledRulePackCategories, len(rp.connectorRules))
				}
				g.connectorRules[name] = rules
			}
		}
	}
	if in.profiles != nil {
		tuned := profileConnectorNames(in.profiles.base)
		for name, derived := range in.profiles.profiles {
			if pack := in.profiles.packs[globalRulePackScope(derived.Config).key()]; pack != nil {
				g.RulePacks["prof:"+name] = pack
			}
			for _, connector := range thresholdConnectorNamesWith(derived.Config, tuned) {
				if pack := in.profiles.packs[effectiveRulePackKey(derived.Config, connector)]; pack != nil {
					g.RulePacks["prof:"+name+"/"+connector] = pack
				}
			}
		}
	}

	dir := strings.TrimSpace(cfg.PolicyDir)
	if in.offline && dir != "" && !newDigestScope(cfg, in.goos, in.bundleRoot).bundleFile(dir) {
		// An offline digest (bundle sign and verify) loads Rego only from
		// the bundle. A policy_dir outside it names the target device's
		// folder, which the signer need not have, and its Rego is never
		// digested (the "rego" component below), so it is not read
		// (GAP-0239).
		dir = ""
	}
	if dir != "" {
		// A module a standard user could change since the config was
		// loaded is not loaded as managed policy: the build fails, so a
		// reload keeps the previous generation (GAP-1499). An offline
		// digest loads no policy into a gateway.
		if !in.offline {
			if err := managedPolicyTreeTrust(cfg, dir); err != nil {
				return nil, fmt.Errorf("generation: OPA policy: managed standalone policy_dir is not administrator-controlled: %w", err)
			}
		}
		prepared, err := policy.Prepare(ctx, dir)
		switch {
		case err == nil:
			g.OPA = prepared
		case errors.Is(err, policy.ErrNoModules):
			// No Rego in the policy directory is the config-driven mode
			// (the managed packages ship none), not a failed load.
		case in.strictOPA:
			return nil, fmt.Errorf("generation: OPA policy: %w", err)
		default:
			g.opaError = err.Error()
			// Secure Client logs the start-up line of main instead
			// (logSecureClientPolicyEngine, issue #1092).
			if !cfg.SecureClientIntegration() {
				fmt.Fprintf(os.Stderr, "[sidecar] OPA policy unavailable (guardrail falls back to the resolved thresholds): %v\n", err)
			}
		}
	}

	if !cfg.SecureClientIntegration() {
		if err := cfg.Scanners.CheckPinnedFiles(); err != nil {
			if in.strictScannerPins {
				return nil, fmt.Errorf("generation: %w", err)
			}
			g.scannerPinError = err.Error()
		}
	}

	g.Thresholds = buildThresholdTable(cfg, in.profiles)
	record := readConfigGenerationRecord(cfg.ConfigFilePath, in.raw)
	g.ConfigGen, g.ConfigGenRecorded = record.Generation, record.Recorded
	g.BundleID, g.BundleVersion = record.BundleID, record.BundleVersion
	if in.bundleRoot == "" && record.Recorded && enterprisebundle.ValidBundleID(record.BundleID) && record.BundleVersion > 0 {
		// The signer and staged verifier digest paths beneath their bundle
		// root as ${bundle_root}. The installed config names the immutable
		// directory for this receipt (retries of one version use fresh
		// names), or none for a settings-only bundle.
		bundlesDir := filepath.Join(filepath.Dir(cfg.ConfigFilePath), enterprisebundle.BundlesDirName)
		raw := in.raw
		if raw == nil {
			raw, _ = os.ReadFile(cfg.ConfigFilePath)
		}
		switch names := enterprisebundle.VersionDirsNamed(raw, bundlesDir); len(names) {
		case 0:
			// A settings-only bundle (config.yaml names no bundle file) is
			// still digested in the bundle scope: the signer and the staged
			// verifier set a bundle root, which leaves out the rule packs and
			// other assets outside the bundle. No config path is under this
			// root, so only that scope applies (GAP-0158).
			in.bundleRoot = filepath.Join(bundlesDir, enterprisebundle.VersionDirName(record.BundleVersion, record.BundleID))
		case 1:
			root := filepath.Join(bundlesDir, names[0])
			if info, err := os.Stat(root); err != nil || !info.IsDir() {
				return nil, fmt.Errorf("generation: installed bundle version directory %s is unavailable", root)
			}
			in.bundleRoot = root
		default:
			return nil, fmt.Errorf("generation: config names more than one bundle version directory")
		}
	}
	g.bundleRoot = in.bundleRoot

	scope := newDigestScope(cfg, in.goos, in.bundleRoot)
	scope.vendorRoot, scope.vendorTarget = in.vendorRoot, in.vendorTarget
	if managed.IsManagedEnterprise(cfg.DeploymentMode) && !cfg.SecureClientIntegration() {
		loaded, err := loadSandboxRequiredPacks(cfg, scope, in.offline)
		if err != nil {
			return nil, fmt.Errorf("generation: %w", err)
		}
		g.sandboxPacks, g.sandboxPackDir = loaded, cfg.OpenShell.PackDir
		for ref, pack := range loaded {
			if scope.bundleFile(pack.Source) {
				// Attest the exact validated copy this generation publishes,
				// including inherited content, whether or not a pin is set.
				g.Components["sandbox_pack:"+scope.rewrite(ref)] = pack.Digest
			}
		}
	}
	configComponent, err := configDigest(cfg, scope)
	if err != nil {
		return nil, fmt.Errorf("generation: %w", err)
	}
	g.Components["config"] = configComponent
	if digest := observabilityDigest(cfg, in.raw, scope); digest != "" {
		g.Components["observability"] = digest
	}
	guardrailDigest := config.GuardrailPolicyDigest
	if scope.bundleRoot != "" {
		guardrailDigest = func(cfg *config.Config) (string, error) {
			return config.GuardrailPolicyDigestWithPathRewrite(cfg, scope.rewrite)
		}
	}
	if digest, err := guardrailDigest(cfg); err == nil {
		g.Components["guardrail_policy"] = digest
	}
	for key, digest := range assetDigestComponents(cfg, scope) {
		g.Components[key] = digest
	}
	g.Providers, err = buildGenerationProvidersForScope(cfg, scope, in.offline)
	if err != nil {
		return nil, fmt.Errorf("generation: providers: %w", err)
	}
	g.Components["providers"] = g.Providers.digestForBundle(cfg, scope)
	// Every profile scope that resolves to a pack points at the same loaded
	// pack, so each pack is digested once: digesting it per scope cost about
	// 1.5 s of gateway start with 1,000 profiles (GAP-0276).
	packDigests := make(map[*guardrail.RulePack]string, 4)
	for key, pack := range g.RulePacks {
		if scope.bundleRoot != "" && !scope.bundleFile(rulePackSourceDir(cfg, in.profiles, key)) {
			continue
		}
		digest, done := packDigests[pack]
		if !done {
			digest = rulePackComponentDigest(pack)
			packDigests[pack] = digest
		}
		g.Components["rule_pack:"+key] = digest
	}
	if g.OPA != nil && scope.bundleFile(cfg.PolicyDir) {
		g.Components["rego"] = g.OPA.RegoDigest
	}
	profileDigests := map[string]string{}
	if in.profiles != nil {
		for name, derived := range in.profiles.profiles {
			digest := derived.Digest
			if scope.bundleRoot != "" {
				var err error
				digest, err = derived.DigestWithPathRewrite(scope.rewrite)
				if err != nil {
					return nil, fmt.Errorf("generation: guardrail profile %s digest: %w", name, err)
				}
			}
			profileDigests[name] = digest
			g.Components["profile:"+name] = digest
		}
	}
	g.Digest = effectivePolicyDigest(g.Components, profileDigests)
	g.assetDirs = generationAssetDirs(cfg, g)
	g.assetFiles = generationAssetFiles(cfg)
	return g, nil
}

// loadSandboxGenerationPack is replaced by content-only tests of attestation.
var loadSandboxGenerationPack = packs.LoadGenerationPack

// loadSandboxRequiredPacks loads every custom required sandbox pack that a
// floor of cfg names (openshell.admin, alone and with each guardrail
// profile's sandbox section) as the sandbox routes load it. A pack that
// does not load (malformed, a value it does not build with, missing, a
// file standard users could change, or content other than its pin) fails
// the generation: a reload keeps the last good generation and its packs,
// the gateway refuses to start on it, and `policy digest` refuses it, so
// ensure neither records nor restarts for it (GAP-0229). A pack this
// process may not read (a standard user's `policy digest`) is left to the
// gateway, which can. A floor that does not resolve is refused by the
// sandbox routes, as before.
func loadSandboxRequiredPacks(cfg *config.Config, scope digestScope, offline bool) (map[string]*packs.Pack, error) {
	// A profile without a required pack of its own runs the
	// administrator's: only those with one name another pack.
	names := []string{""}
	for name, profile := range cfg.Guardrail.Profiles {
		if profile.Sandbox != nil && strings.TrimSpace(profile.Sandbox.RequiredPack) != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	subject := packs.Subject{UID: os.Getuid()}
	loaded := map[string]*packs.Pack{}
	for _, name := range names {
		floor, _, err := cfg.SandboxManagedFloor(name)
		if err != nil {
			continue
		}
		ref := strings.TrimSpace(floor.RequiredPack)
		if ref == "" || packs.IsBuiltin(ref) {
			continue
		}
		assetPath := ref
		if !filepath.IsAbs(assetPath) {
			assetPath = filepath.Join(cfg.OpenShell.PackDir, ref)
		}
		if offline && !scope.bundleFile(assetPath) {
			// A signer cannot inspect assets outside the bundle. Runtime
			// still validates and publishes them, as before.
			continue
		}
		pack, done := loaded[ref]
		if !done {
			var packErr *packs.Error
			if offline {
				// A signer hashes staged bundle data before the installer
				// promotes it to administrator ownership. This generation is
				// never published; runtime still uses the trusted loader.
				pack, err = packs.LoadRequired(subject, ref, cfg.OpenShell.PackDir, false)
			} else {
				pack, err = loadSandboxGenerationPack(subject, ref, cfg.OpenShell.PackDir)
			}
			switch {
			case err == nil:
				loaded[ref] = pack
			case errors.As(err, &packErr) && packErr.Code == "unreadable":
				continue
			default:
				return nil, fmt.Errorf("sandbox pack %s does not load: %w", ref, err)
			}
		}
		if pin := strings.TrimSpace(floor.RequiredPackDigest); pin != "" && pack.Digest != pin {
			return nil, fmt.Errorf("sandbox pack %s has digest %s, not the pinned required_pack_digest %s", ref, pack.Digest, pin)
		}
	}
	return loaded, nil
}

// rulePackSourceDir identifies the files behind a loaded pack component.
// Product-installed packs are pinned by product_version rather than bundle
// content, so only packs inside the bundle root contribute to its digest.
func rulePackSourceDir(cfg *config.Config, profiles *guardrailProfileSet, key string) string {
	if key == "global" {
		return globalRulePackScope(cfg).dir
	}
	if connector, ok := strings.CutPrefix(key, "conn:"); ok {
		return connectorRulePackScope(cfg, connector).dir
	}
	if profile, ok := strings.CutPrefix(key, "prof:"); ok && profiles != nil {
		name, connector, _ := strings.Cut(profile, "/")
		if derived, exists := profiles.profiles[name]; exists {
			if connector == "" {
				return globalRulePackScope(derived.Config).dir
			}
			return connectorRulePackScope(derived.Config, connector).dir
		}
	}
	return ""
}

// rulePackComponentDigest is a pack's effective-digest component; a seam
// for tests.
var rulePackComponentDigest = func(pack *guardrail.RulePack) string {
	return "sha256:" + pack.Summary().Digest
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
	for _, entry := range cfg.AIDiscovery.SignaturePacks {
		files, _ := inventory.SignaturePackEntry(entry)
		for _, file := range files {
			add(file)
		}
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
	record := readConfigGenerationRecord(configPath, raw)
	return record.Generation, record.Recorded
}

// configGenerationRecord is what config.generation.json says about the
// config bytes a generation runs.
type configGenerationRecord struct {
	Generation uint64
	// Recorded is true when the record names these bytes.
	Recorded bool
	// BundleID and BundleVersion name the policy bundle the lifecycle
	// installed in this generation; set only when Recorded.
	BundleID      string
	BundleVersion uint64
}

func readConfigGenerationRecord(configPath string, raw []byte) configGenerationRecord {
	if strings.TrimSpace(configPath) == "" {
		return configGenerationRecord{}
	}
	state, err := configwrite.ReadGenerationState(configPath)
	if err != nil {
		return configGenerationRecord{}
	}
	if raw == nil {
		raw, err = os.ReadFile(configPath)
		if err != nil {
			return configGenerationRecord{Generation: state.Generation}
		}
	}
	sum := sha256.Sum256(raw)
	recorded := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(state.ConfigSHA256)), "sha256:")
	out := configGenerationRecord{Generation: state.Generation, Recorded: recorded == hex.EncodeToString(sum[:])}
	if out.Recorded {
		out.BundleID, out.BundleVersion = state.BundleID, state.BundleVersion
	}
	return out
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
	for _, entry := range cfg.AIDiscovery.SignaturePacks {
		_, watchDirs := inventory.SignaturePackEntry(entry)
		for _, dir := range watchDirs {
			add(dir)
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
	bindRegisteredConnectorRules(g)
	liveGeneration.Store(g)
	packs.UseGenerationPacks(g.sandboxPackDir, g.sandboxPacks)
	publishPackPostures()
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
	record := readConfigGenerationRecord(current.Config.ConfigFilePath, raw)
	if record.Generation == current.ConfigGen && record.Recorded == current.ConfigGenRecorded &&
		record.BundleID == current.BundleID && record.BundleVersion == current.BundleVersion {
		return
	}
	next := *current
	next.ConfigGen, next.ConfigGenRecorded = record.Generation, record.Recorded
	next.BundleID, next.BundleVersion = record.BundleID, record.BundleVersion
	liveGeneration.Store(&next)
}

// recordGenerationBuildError keeps the live generation and reports why the
// candidate was rejected.
func recordGenerationBuildError(err error) {
	if err != nil {
		liveReloadError.Store(err.Error())
	}
}

// livePendingRestart holds the config keys the running gateway keeps at their
// running values until it restarts (a listener, a connector's hooks),
// published as policy.pending_restart so doctor can tell a pending restart
// from a stale gateway.
var livePendingRestart atomic.Value // []string

func setPendingRestart(keys []string) {
	livePendingRestart.Store(append([]string(nil), keys...))
}

// clearGenerationBuildError ends a rejection: the next rebuild succeeded,
// even when it built the generation already live and swapped nothing.
func clearGenerationBuildError() {
	liveReloadError.Store("")
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
		BundleID:                 g.BundleID,
		BundleVersion:            g.BundleVersion,
		BuiltAt:                  g.BuiltAt.Format(time.RFC3339),
		ComponentCount:           len(g.Components),
	}
	health.PendingRestart, _ = livePendingRestart.Load().([]string)
	if msg, _ := liveReloadError.Load().(string); msg != "" {
		health.LastReloadError = msg
	} else if g.opaError != "" {
		health.LastReloadError = "opa: " + g.opaError
	} else if g.scannerPinError != "" {
		health.LastReloadError = g.scannerPinError
	}
	health.OPAUnavailable = g.opaError
	return health, true
}
