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

package inventory

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

//go:embed ai_signatures.json
var aiSignatureFS embed.FS

const aiSignatureCatalogVersion = 1

const (
	defaultMaxSignaturePacks = 64
	defaultMaxSignatureBytes = 1024 * 1024
)

// AISignatureComponent declares a high-fidelity sub-identity that the
// `package_manifest` detector can resolve a matched package name to.
//
// When a signature pack ships `components`, the detector emits one signal
// per matched component (instead of collapsing them all into a single
// catch-all row), and the resulting signals carry the component's
// `framework` / `vendor` / parsed `version` instead of the generic
// signature `name` / `vendor`.
//
// Match priority: when the matched package matches more than one
// component (e.g. `langchain` and `langchain-openai`), the longest
// component name wins to prefer the most specific framework label.
type AISignatureComponent struct {
	Ecosystem string `json:"ecosystem"`           // pypi | npm | cargo | go | dotnet | rubygems | maven | gradle
	Name      string `json:"name"`                // canonical package name (case-insensitive match against PackageNames)
	Framework string `json:"framework,omitempty"` // human-readable label used as the signal `Product`
	Vendor    string `json:"vendor,omitempty"`    // optional per-component vendor override
}

// AISignature describes one known AI surface or provider family. It is the
// shared source used by the continuous sidecar scanner and the Python CLI
// rendering/tests. Keep the JSON shape intentionally primitive so other
// runtimes can consume it without linking Go code.
//
// Confidence model (back-compat):
//   - Legacy catalogs ship a single `confidence` field. Loaders normalize
//     it into `CuratorConfidence` and default `Specificity` to 0.7.
//   - The two-axis Bayesian engine in confidence.go reads
//     `CuratorConfidence` as the prior probability for identity (when
//     the policy says `priors.identity: signature`), and uses
//     `Specificity` as a per-signature exponent on detector LRs so
//     overly-generic signatures (e.g. matching the literal word "ai")
//     contribute less per observation than tightly-scoped ones.
type AISignature struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Vendor             string   `json:"vendor"`
	Category           string   `json:"category"`
	Confidence         float64  `json:"confidence,omitempty"`         // legacy seed; normalized into CuratorConfidence on load
	CuratorConfidence  float64  `json:"curator_confidence,omitempty"` // operator-meaningful base prior on identity, in (0, 1)
	Specificity        float64  `json:"specificity,omitempty"`        // how unique the matched value is; (0, 1], default 0.7
	SupportedConnector string   `json:"supported_connector,omitempty"`
	BinaryNames        []string `json:"binary_names,omitempty"`
	ProcessNames       []string `json:"process_names,omitempty"`
	ApplicationNames   []string `json:"application_names,omitempty"`
	ConfigPaths        []string `json:"config_paths,omitempty"`
	ExtensionIDs       []string `json:"extension_ids,omitempty"`
	// JetBrainsPluginIDs, ZedExtensionIDs and VimPlugins flag the AI
	// plugins of the IDE inventory: JetBrains plugin.xml ids, Zed
	// extension ids and Vim/Neovim plugin folder (repository) names.
	JetBrainsPluginIDs []string `json:"jetbrains_plugin_ids,omitempty"`
	ZedExtensionIDs    []string `json:"zed_extension_ids,omitempty"`
	VimPlugins         []string `json:"vim_plugins,omitempty"`
	MCPPaths           []string `json:"mcp_paths,omitempty"`
	// SkillPaths / RulePaths / PluginPaths are directory globs whose
	// per-user existence + non-emptiness produce SignalSkill / SignalRule /
	// SignalPlugin signals. Semantics mirror MCPPaths (path-based detection,
	// no content scan) but each targets a specific agent-component surface:
	//   - Codex: $CODEX_HOME/skills, ~/.agents/skills, project skill roots,
	//     ~/.codex/plugins, and .codex/rules
	//   - Claude Code: ~/.claude/skills, ~/.claude/rules
	//   - Cursor: ~/.cursor/rules, .cursor/rules
	// Watcher-scanned skills/plugins live under the same directories, so an
	// inventory hit here means "this endpoint has that surface configured
	// with at least one entry" — dashboarding rollup, not per-file safety
	// (which is what the watcher's EventScan captures).
	SkillPaths      []string               `json:"skill_paths,omitempty"`
	RulePaths       []string               `json:"rule_paths,omitempty"`
	PluginPaths     []string               `json:"plugin_paths,omitempty"`
	PackageNames    []string               `json:"package_names,omitempty"`
	EnvVarNames     []string               `json:"env_var_names,omitempty"`
	DomainPatterns  []string               `json:"domain_patterns,omitempty"`
	HistoryPatterns []string               `json:"history_patterns,omitempty"`
	LocalEndpoints  []string               `json:"local_endpoints,omitempty"`
	Components      []AISignatureComponent `json:"components,omitempty"`
}

type aiSignatureCatalog struct {
	Version    int           `json:"version"`
	ID         string        `json:"id,omitempty"`
	Name       string        `json:"name,omitempty"`
	Signatures []AISignature `json:"signatures"`
}

// promotedAgentKinds maps signature.ID → connector slug for
// signatures we treat as first-class agents WITHOUT setting the
// catalog's `supported_connector` field on them.
//
// Why keep this separate from `SupportedConnector`: setting the
// catalog field would flip the emitted `category` inside
// `detectConfigPaths` from `workspace_artifact` (or `editor_extension`
// / `desktop_app`) to `supported_connector`, which in turn changes
// every affected signal's fingerprint. In non-managed_enterprise mode
// the sidecar ships only lifecycle deltas, so that reclassification
// would produce a one-time `gone`+`new` delta pair per user on every
// host running one of these agents. This table gives us the agent
// identity on the wire (as `agent_kind`) without disturbing the
// existing category-level classification or the signal fingerprints.
//
// Only expand this table for signatures whose product IS an agent the
// dashboards should treat as first-class. For signatures that already
// carry `SupportedConnector` in ai_signatures.json (openclaw, codex,
// claudecode, cursor, devin, …), the connector value flows through
// directly and this table is not consulted.
var promotedAgentKinds = map[string]string{
	"aider":          "aider",
	"continue":       "continue",
	"cline":          "cline",
	"claude-desktop": "claudedesktop",
}

// AgentKindForSignature returns the connector slug that identifies
// this signature's owning agent (e.g. "cursor", "claudecode",
// "aider"), or "" if the signature is not associated with a
// first-class agent. Callers should prefer `sig.SupportedConnector`
// when set — this helper only handles the promotion cases above.
func AgentKindForSignature(sig AISignature) string {
	if sig.SupportedConnector != "" {
		return sig.SupportedConnector
	}
	return promotedAgentKinds[sig.ID]
}

// LoadAISignatures returns the embedded catalog after basic validation.
func LoadAISignatures() ([]AISignature, error) {
	raw, err := aiSignatureFS.ReadFile("ai_signatures.json")
	if err != nil {
		return nil, fmt.Errorf("ai signature catalog: read embedded catalog: %w", err)
	}
	return parseAISignatureCatalog("builtin", raw)
}

// AISignatureLoadOptions controls runtime catalog merging. The embedded
// catalog is always loaded first, followed by the configured pack paths and
// globs (ai_discovery.signature_packs, the only operator source since
// config_version 9) and optional workspace-local packs.
type AISignatureLoadOptions struct {
	// DataDir is the data directory whose signature-packs/*.json the Secure
	// Client profile still loads (issue #1092).
	DataDir        string
	SignaturePacks []string
	// PackDigests pins pack files by path (ai_discovery.signature_pack_digests).
	PackDigests map[string]string
	// RequireDigests refuses a pack without a pin (managed standalone).
	RequireDigests           bool
	AllowWorkspaceSignatures bool
	ScanRoots                []string
	DisabledSignatureIDs     []string
	HomeDir                  string
	WorkingDir               string
	MaxPacks                 int
	MaxPackBytes             int64
	// SecureClient loads the embedded catalog as 1.0.0 shipped it
	// (secureClientSignatures).
	SecureClient bool
}

// LoadAISignaturesForConfig loads the embedded catalog plus any configured
// operator packs. It is used by the sidecar so CLI/TUI config edits take
// effect on restart without rebuilding DefenseClaw.
func LoadAISignaturesForConfig(cfg *config.Config) ([]AISignature, error) {
	if cfg == nil {
		return LoadAISignatures()
	}
	home, _ := platformDiscoveryHomeDir()
	wd, _ := os.Getwd()
	dataDir := ""
	if cfg.SecureClientIntegration() {
		dataDir = cfg.DataDir
	}
	return LoadAISignaturesWithOptions(AISignatureLoadOptions{
		DataDir:                  dataDir,
		SignaturePacks:           append([]string{}, cfg.AIDiscovery.SignaturePacks...),
		PackDigests:              cfg.AIDiscovery.SignaturePackDigests,
		RequireDigests:           cfg.StandaloneEnterprise(),
		AllowWorkspaceSignatures: WorkspaceSignaturesAllowed(cfg),
		ScanRoots:                append([]string{}, cfg.AIDiscovery.ScanRoots...),
		DisabledSignatureIDs:     append([]string{}, cfg.AIDiscovery.DisabledSignatureIDs...),
		HomeDir:                  home,
		WorkingDir:               wd,
		SecureClient:             cfg.SecureClientIntegration(),
	})
}

// CheckSignaturePackPins refuses, on a managed standalone host, a configured
// signature pack file that the loader would skip: it does not match its pin in
// ai_discovery.signature_pack_digests, or it has none. The loader only logs
// the skip, so without this check an apply accepts a config whose pack never
// loads (GAP-0173). A pack file that is not there yet is not a pin problem.
func CheckSignaturePackPins(cfg *config.Config) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	home, _ := platformDiscoveryHomeDir()
	packs, err := signaturePackPaths(AISignatureLoadOptions{SignaturePacks: cfg.AIDiscovery.SignaturePacks, HomeDir: home})
	if err != nil {
		return nil // reported when the catalog loads
	}
	pins := pinnedDigests(cfg.AIDiscovery.SignaturePackDigests, home, !cfg.SecureClientIntegration())
	for _, pack := range packs {
		raw, err := readAISignaturePackBytes(pack, defaultMaxSignatureBytes)
		if err != nil {
			continue
		}
		if refusal := pinRefusal(pins[signaturePinPath(pack, !cfg.SecureClientIntegration())], raw, true); refusal != "" {
			return &config.V8SemanticError{
				Path:     "$.ai_discovery.signature_pack_digests",
				Summary:  "signature pack " + pack + " would not load: " + refusal,
				Expected: "a sha256:<hex> digest of the pack file, keyed by its path",
				Action:   "pin the file's current digest (sha256sum), or restore the pack the pin was taken from",
			}
		}
	}
	return nil
}

// SignaturePackEntry resolves one ai_discovery.signature_packs entry the way
// the loader does (a ~ path, a directory of *.json, a glob). files are the
// pack files it names now (a plain path stays listed while the file is not
// there yet); watchDir is the folder a new pack would appear in, "" for an
// entry that names one file.
func SignaturePackEntry(entry string) (files []string, watchDir string) {
	home, _ := platformDiscoveryHomeDir()
	files, _ = expandSignaturePackCandidate(entry, home)
	expanded := expandHome(entry, home)
	if info, err := os.Stat(expanded); err == nil && info.IsDir() {
		return files, filepath.Clean(expanded)
	}
	if hasGlobMeta(expanded) {
		if dir := filepath.Dir(expanded); !hasGlobMeta(dir) {
			return files, filepath.Clean(dir)
		}
		return files, ""
	}
	if len(files) == 0 && expanded != "" {
		files = []string{expanded}
	}
	return files, ""
}

// Signature data added to the embedded catalog after 1.0.0. The Secure Client
// profile keeps the catalog of 1.0.0 (issue #1092), so secureClientSignatures
// removes it there.
var (
	postReleaseSignatureIDs = map[string]bool{"jetbrains-ai": true}
	postReleaseExtensionIDs = map[string]string{"codex": "openai.chatgpt", "claudecode": "anthropic.claude-code"}
)

// secureClientSignatures returns the embedded catalog as 1.0.0 shipped it:
// without the signatures and VS Code extension ids added since, and without
// the JetBrains, Zed and Vim plugin ids, which only the IDE inventory reads.
func secureClientSignatures(base []AISignature) []AISignature {
	out := make([]AISignature, 0, len(base))
	for _, sig := range base {
		if postReleaseSignatureIDs[sig.ID] {
			continue
		}
		if added := postReleaseExtensionIDs[sig.ID]; added != "" {
			sig.ExtensionIDs = slices.DeleteFunc(slices.Clone(sig.ExtensionIDs), func(id string) bool { return id == added })
		}
		sig.JetBrainsPluginIDs, sig.ZedExtensionIDs, sig.VimPlugins = nil, nil, nil
		out = append(out, sig)
	}
	return out
}

// LoadAISignaturesWithOptions merges all configured catalog sources and
// rejects duplicates or malformed packs before discovery starts.
func LoadAISignaturesWithOptions(opts AISignatureLoadOptions) ([]AISignature, error) {
	base, err := LoadAISignatures()
	if err != nil {
		return nil, err
	}
	if opts.SecureClient {
		base = secureClientSignatures(base)
	}
	disabled := normalizedSignatureIDSet(opts.DisabledSignatureIDs)
	merged := make([]AISignature, 0, len(base))
	seen := map[string]string{}
	for _, sig := range base {
		if disabled[sig.ID] {
			continue
		}
		merged = append(merged, sig)
		seen[sig.ID] = "builtin"
	}

	packs, err := signaturePackPaths(opts)
	if err != nil {
		return nil, err
	}
	maxPacks := opts.MaxPacks
	if maxPacks <= 0 {
		maxPacks = defaultMaxSignaturePacks
	}
	if len(packs) > maxPacks {
		return nil, fmt.Errorf("ai signature catalog: too many signature packs (%d > %d)", len(packs), maxPacks)
	}
	maxBytes := opts.MaxPackBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxSignatureBytes
	}
	pins := pinnedDigests(opts.PackDigests, opts.HomeDir, !opts.SecureClient)
	for _, packPath := range packs {
		raw, err := readAISignaturePackBytes(packPath, maxBytes)
		if err != nil {
			return nil, err
		}
		if refusal := pinRefusal(pins[signaturePinPath(packPath, !opts.SecureClient)], raw, opts.RequireDigests); refusal != "" {
			// A pack that is not the one the administrator pinned is not
			// loaded; the rest of the catalog still is.
			fmt.Fprintf(os.Stderr, "[ai-discovery] signature pack %s not loaded: %s\n", packPath, refusal)
			continue
		}
		sigs, err := parseAISignatureCatalog(packPath, raw)
		if err != nil {
			return nil, err
		}
		for _, sig := range sigs {
			if disabled[sig.ID] {
				continue
			}
			if prev := seen[sig.ID]; prev != "" {
				// This ID was introduced in the 1.0 builtin catalog. An older
				// operator pack with the same ID keeps its configured signature.
				if sig.ID != "jetbrains-ai" || prev != "builtin" || opts.SecureClient {
					return nil, fmt.Errorf("ai signature catalog: duplicate id %q in %s (already defined in %s)", sig.ID, packPath, prev)
				}
				for i := range merged {
					if merged[i].ID == sig.ID {
						merged[i] = sig
						break
					}
				}
				seen[sig.ID] = packPath
				continue
			}
			merged = append(merged, sig)
			seen[sig.ID] = packPath
		}
	}
	return merged, nil
}

func parseAISignatureCatalog(source string, raw []byte) ([]AISignature, error) {
	var cat aiSignatureCatalog
	if err := json.Unmarshal(raw, &cat); err != nil {
		return nil, fmt.Errorf("ai signature catalog: parse %s: %w", source, err)
	}
	if cat.Version != aiSignatureCatalogVersion {
		return nil, fmt.Errorf("ai signature catalog: %s: unsupported version %d", source, cat.Version)
	}
	seen := map[string]bool{}
	if len(cat.Signatures) == 0 {
		return nil, fmt.Errorf("ai signature catalog: %s: signatures must not be empty", source)
	}
	for i := range cat.Signatures {
		normalizeAISignature(&cat.Signatures[i])
		if err := validateAISignature(cat.Signatures[i]); err != nil {
			return nil, err
		}
		if seen[cat.Signatures[i].ID] {
			return nil, fmt.Errorf("ai signature catalog: %s: duplicate id %q", source, cat.Signatures[i].ID)
		}
		seen[cat.Signatures[i].ID] = true
	}
	return cat.Signatures, nil
}

// pinnedDigests keys ai_discovery.signature_pack_digests by resolved path
// outside Secure Client. Secure Client keeps the legacy cleaned-path lookup.
func pinnedDigests(pins map[string]string, home string, resolve bool) map[string]string {
	out := make(map[string]string, len(pins))
	for path, digest := range pins {
		path = strings.TrimSpace(path)
		if strings.HasPrefix(path, "~/") && home != "" {
			path = filepath.Join(home, path[2:])
		}
		out[signaturePinPath(path, resolve)] = strings.ToLower(strings.TrimSpace(digest))
	}
	return out
}

// signaturePinPath matches Python Path.resolve for existing pack files and
// relative keys, including symlinked directories.
func signaturePinPath(path string, resolve bool) string {
	path = filepath.Clean(path)
	if !resolve {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	return abs
}

// pinRefusal is why raw may not load under the pinned digest want ("" when
// it may): a pin that does not match, or no pin where one is required.
func pinRefusal(want string, raw []byte, required bool) string {
	if want == "" {
		if required {
			return "a managed device loads only packs pinned in ai_discovery.signature_pack_digests"
		}
		return ""
	}
	sum := sha256.Sum256(raw)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != want {
		return "its digest " + got + " does not match the pinned " + want
	}
	return ""
}

func readAISignaturePackBytes(path string, maxBytes int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("ai signature catalog: stat %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("ai signature catalog: %s is a directory", path)
	}
	if info.Size() > maxBytes {
		return nil, fmt.Errorf("ai signature catalog: %s exceeds %d bytes", path, maxBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ai signature catalog: read %s: %w", path, err)
	}
	return raw, nil
}

type signaturePackCandidate struct {
	path     string
	required bool
}

// WorkspaceSignaturesAllowed is ai_discovery.allow_workspace_signatures,
// forced off on a managed standalone host: a workspace pack is
// user-controlled input, and there the administrator config is the policy.
func WorkspaceSignaturesAllowed(cfg *config.Config) bool {
	return cfg != nil && cfg.AIDiscovery.AllowWorkspaceSignatures && !cfg.StandaloneEnterprise()
}

func signaturePackPaths(opts AISignatureLoadOptions) ([]string, error) {
	var candidates []signaturePackCandidate
	if opts.DataDir != "" {
		candidates = append(candidates, signaturePackCandidate{
			path: filepath.Join(opts.DataDir, "signature-packs", "*.json"),
		})
	}
	for _, p := range opts.SignaturePacks {
		candidates = append(candidates, signaturePackCandidate{path: p, required: true})
	}
	if opts.AllowWorkspaceSignatures {
		for _, root := range workspaceSignatureRoots(opts) {
			candidates = append(candidates, signaturePackCandidate{
				path: filepath.Join(root, ".defenseclaw", "ai-signatures.json"),
			})
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, candidate := range candidates {
		paths, err := expandSignaturePackCandidate(candidate.path, opts.HomeDir)
		if err != nil {
			return nil, err
		}
		if len(paths) == 0 && candidate.required {
			if opts.SecureClient {
				return nil, fmt.Errorf("ai signature catalog: signature pack path matched nothing: %s", candidate.path)
			}
			// A configured pack whose file is gone is left out, like one
			// that fails its pin: the rest of the catalog, and every other
			// key of the configuration generation, still applies (GAP-0232).
			// doctor and config set name it.
			fmt.Fprintf(os.Stderr, "[ai-discovery] signature pack %s not loaded: the path matches no file\n", candidate.path)
			continue
		}
		for _, p := range paths {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func workspaceSignatureRoots(opts AISignatureLoadOptions) []string {
	roots := append([]string{}, opts.ScanRoots...)
	if opts.WorkingDir != "" {
		roots = append(roots, opts.WorkingDir)
	}
	seen := map[string]bool{}
	var out []string
	for _, root := range roots {
		root = expandHome(root, opts.HomeDir)
		if root == "" {
			continue
		}
		abs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, abs)
		}
	}
	return out
}

func expandSignaturePackCandidate(pattern, home string) ([]string, error) {
	pattern = expandHome(pattern, home)
	if pattern == "" {
		return nil, nil
	}
	if info, err := os.Stat(pattern); err == nil && info.IsDir() {
		pattern = filepath.Join(pattern, "*.json")
	}
	if hasGlobMeta(pattern) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return nil, fmt.Errorf("ai signature catalog: bad signature pack glob %s: %w", pattern, err)
		}
		return readableJSONFiles(matches), nil
	}
	if _, err := os.Stat(pattern); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ai signature catalog: stat %s: %w", pattern, err)
	}
	return []string{pattern}, nil
}

func readableJSONFiles(paths []string) []string {
	var out []string
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Ext(path), ".json") {
			out = append(out, path)
		}
	}
	return out
}

func expandHome(path, home string) string {
	path = strings.TrimSpace(path)
	if path == "" || path == "~" {
		if path == "~" {
			return home
		}
		return ""
	}
	if strings.HasPrefix(path, "~/") {
		if home == "" {
			if h, err := platformDiscoveryHomeDir(); err == nil {
				home = h
			}
		}
		if home != "" {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

func normalizedSignatureIDSet(ids []string) map[string]bool {
	out := map[string]bool{}
	for _, id := range ids {
		if normalized := normalizeAIID(id); normalized != "" {
			out[normalized] = true
		}
	}
	return out
}

func normalizeAISignature(sig *AISignature) {
	sig.ID = normalizeAIID(sig.ID)
	sig.Category = normalizeAICategory(sig.Category)
	sig.SupportedConnector = normalizeAIID(sig.SupportedConnector)
	sig.Name = strings.TrimSpace(sig.Name)
	sig.Vendor = strings.TrimSpace(sig.Vendor)
	// Legacy `confidence` field becomes the seed for both
	// CuratorConfidence (when the operator hasn't declared one
	// explicitly) and stays populated for any downstream code that
	// still reads it directly. Order matters: catalog edits that
	// declare `curator_confidence` win, then `confidence` fills the
	// gap, then a sane default (0.85 -- intentionally above the
	// presence prior so the engine's identity prior is never lower
	// than its presence prior).
	if sig.Confidence <= 0 {
		sig.Confidence = 0.5
	}
	if sig.Confidence > 1 {
		sig.Confidence = 1
	}
	if sig.CuratorConfidence <= 0 {
		sig.CuratorConfidence = sig.Confidence
	}
	if sig.CuratorConfidence > 1 {
		sig.CuratorConfidence = 1
	}
	// Specificity defaults to 0.7 (neutral): high enough that an
	// observation contributes most of its log-odds, low enough that
	// extremely-generic signatures (like a regex matching "ai") need
	// to be explicitly declared to prevent over-counting.
	if sig.Specificity <= 0 {
		sig.Specificity = 0.7
	}
	if sig.Specificity > 1 {
		sig.Specificity = 1
	}
}

func validateAISignature(sig AISignature) error {
	if sig.ID == "" {
		return fmt.Errorf("ai signature catalog: id is required")
	}
	if len(sig.ID) > 96 {
		return fmt.Errorf("ai signature catalog: %s: id is too long", sig.ID)
	}
	if sig.Name == "" {
		return fmt.Errorf("ai signature catalog: %s: name is required", sig.ID)
	}
	if sig.Vendor == "" {
		return fmt.Errorf("ai signature catalog: %s: vendor is required", sig.ID)
	}
	if sig.Category == "" {
		return fmt.Errorf("ai signature catalog: %s: category is required", sig.ID)
	}
	if !allowedAISignalCategories[sig.Category] {
		return fmt.Errorf("ai signature catalog: %s: unsupported category %q", sig.ID, sig.Category)
	}
	for field, values := range map[string][]string{
		"binary_names":         sig.BinaryNames,
		"process_names":        sig.ProcessNames,
		"application_names":    sig.ApplicationNames,
		"config_paths":         sig.ConfigPaths,
		"extension_ids":        sig.ExtensionIDs,
		"jetbrains_plugin_ids": sig.JetBrainsPluginIDs,
		"zed_extension_ids":    sig.ZedExtensionIDs,
		"vim_plugins":          sig.VimPlugins,
		"mcp_paths":            sig.MCPPaths,
		"skill_paths":          sig.SkillPaths,
		"rule_paths":           sig.RulePaths,
		"plugin_paths":         sig.PluginPaths,
		"package_names":        sig.PackageNames,
		"env_var_names":        sig.EnvVarNames,
		"domain_patterns":      sig.DomainPatterns,
		"history_patterns":     sig.HistoryPatterns,
		"local_endpoints":      sig.LocalEndpoints,
	} {
		if err := validateSignatureValues(sig.ID, field, values); err != nil {
			return err
		}
	}
	if len(sig.Components) > 1024 {
		return fmt.Errorf("ai signature catalog: %s: components has too many entries", sig.ID)
	}
	for i, comp := range sig.Components {
		if strings.TrimSpace(comp.Ecosystem) == "" {
			return fmt.Errorf("ai signature catalog: %s: components[%d].ecosystem is required", sig.ID, i)
		}
		if strings.TrimSpace(comp.Name) == "" {
			return fmt.Errorf("ai signature catalog: %s: components[%d].name is required", sig.ID, i)
		}
		if len(comp.Ecosystem) > 64 || len(comp.Name) > 256 ||
			len(comp.Framework) > 256 || len(comp.Vendor) > 128 {
			return fmt.Errorf("ai signature catalog: %s: components[%d] field too long", sig.ID, i)
		}
		for _, value := range []string{comp.Ecosystem, comp.Name, comp.Framework, comp.Vendor} {
			if strings.ContainsRune(value, '\x00') {
				return fmt.Errorf("ai signature catalog: %s: components[%d] entry contains NUL", sig.ID, i)
			}
		}
	}
	return nil
}

// resolveComponent finds the most specific component declared for a
// signature that matches a value (typically a lower-case package name
// substring). Match rule: case-insensitive equality, with longest-name
// preference so `langchain-openai` beats `langchain` for that string.
// Returns nil when no component is declared.
func (sig AISignature) resolveComponent(value, ecosystem string) *AISignatureComponent {
	if len(sig.Components) == 0 {
		return nil
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	ecosystem = strings.ToLower(strings.TrimSpace(ecosystem))
	// Short package names (≤3 chars) are too noisy to match
	// without an ecosystem hint. Files like `Dockerfile`,
	// `docker-compose.yml`, and shell history don't carry an
	// ecosystem (lockparse returns ""), and their bodies
	// always contain the substring "ai" via words like
	// "main", "args", "RUN apt install", etc. Refusing the
	// match preserves recall for longer names like "openai"
	// while killing the Dockerfile/Cargo.toml-class false
	// positives that produced 685 spurious "Vercel AI SDK"
	// signals on the live machine.
	if ecosystem == "" && len(value) <= 3 {
		return nil
	}
	var best *AISignatureComponent
	for i := range sig.Components {
		c := &sig.Components[i]
		if c == nil {
			continue
		}
		// Ecosystem hint: when the caller knows the ecosystem
		// (manifest filename → npm, pypi, …) prefer same-ecosystem
		// matches. Fall back to ecosystem-agnostic match when no
		// caller hint is given (`ecosystem == ""`).
		if ecosystem != "" && strings.ToLower(c.Ecosystem) != ecosystem {
			continue
		}
		if strings.ToLower(c.Name) != value {
			continue
		}
		if best == nil || len(c.Name) > len(best.Name) {
			best = c
		}
	}
	if best != nil {
		return best
	}
	// Second-pass ecosystem-agnostic fallback so packs that omit a
	// per-ecosystem listing still resolve -- but ONLY when the
	// caller couldn't determine the ecosystem (`ecosystem == ""`).
	// When the caller passed a real ecosystem hint (manifest
	// filename → npm/pypi/cargo/…) we must NOT silently drop it,
	// otherwise short package names like `ai` (npm) get attributed
	// to a Cargo.toml hit because the npm component is the only
	// one named `ai` in the catalog. This was the root cause of
	// "685 Vercel AI SDK signals" with 209 of them being Cargo.toml
	// false positives.
	if ecosystem != "" {
		return nil
	}
	// Note: short-name guard already ran at function entry
	// (`ecosystem == "" && len(value) <= 3`), so by here we know
	// `len(value) > 3` and the agnostic fallback is safe.
	for i := range sig.Components {
		c := &sig.Components[i]
		if c == nil || strings.ToLower(c.Name) != value {
			continue
		}
		if best == nil || len(c.Name) > len(best.Name) {
			best = c
		}
	}
	return best
}

func validateSignatureValues(id, field string, values []string) error {
	if len(values) > 256 {
		return fmt.Errorf("ai signature catalog: %s: %s has too many entries", id, field)
	}
	for _, value := range values {
		if len(value) > 1024 {
			return fmt.Errorf("ai signature catalog: %s: %s entry is too long", id, field)
		}
		if strings.ContainsRune(value, '\x00') {
			return fmt.Errorf("ai signature catalog: %s: %s entry contains NUL", id, field)
		}
	}
	return nil
}

func normalizeAIID(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func normalizeAICategory(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var b strings.Builder
	lastUnderscore := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}
