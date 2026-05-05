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
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// AISignature describes one known AI surface or provider family. It is the
// shared source used by the continuous sidecar scanner and the Python CLI
// rendering/tests. Keep the JSON shape intentionally primitive so other
// runtimes can consume it without linking Go code.
type AISignature struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Vendor             string   `json:"vendor"`
	Category           string   `json:"category"`
	Confidence         float64  `json:"confidence"`
	SupportedConnector string   `json:"supported_connector,omitempty"`
	BinaryNames        []string `json:"binary_names,omitempty"`
	ProcessNames       []string `json:"process_names,omitempty"`
	ApplicationNames   []string `json:"application_names,omitempty"`
	ConfigPaths        []string `json:"config_paths,omitempty"`
	ExtensionIDs       []string `json:"extension_ids,omitempty"`
	MCPPaths           []string `json:"mcp_paths,omitempty"`
	PackageNames       []string `json:"package_names,omitempty"`
	EnvVarNames        []string `json:"env_var_names,omitempty"`
	DomainPatterns     []string `json:"domain_patterns,omitempty"`
	HistoryPatterns    []string `json:"history_patterns,omitempty"`
	LocalEndpoints     []string `json:"local_endpoints,omitempty"`
}

type aiSignatureCatalog struct {
	Version    int           `json:"version"`
	ID         string        `json:"id,omitempty"`
	Name       string        `json:"name,omitempty"`
	Signatures []AISignature `json:"signatures"`
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
// catalog is always loaded first, followed by managed packs under DataDir,
// explicit pack paths/globs, and optional workspace-local packs.
type AISignatureLoadOptions struct {
	DataDir                  string
	SignaturePacks           []string
	AllowWorkspaceSignatures bool
	ScanRoots                []string
	DisabledSignatureIDs     []string
	HomeDir                  string
	WorkingDir               string
	MaxPacks                 int
	MaxPackBytes             int64
}

// LoadAISignaturesForConfig loads the embedded catalog plus any configured
// operator packs. It is used by the sidecar so CLI/TUI config edits take
// effect on restart without rebuilding DefenseClaw.
func LoadAISignaturesForConfig(cfg *config.Config) ([]AISignature, error) {
	if cfg == nil {
		return LoadAISignatures()
	}
	home, _ := os.UserHomeDir()
	wd, _ := os.Getwd()
	return LoadAISignaturesWithOptions(AISignatureLoadOptions{
		DataDir:                  cfg.DataDir,
		SignaturePacks:           append([]string{}, cfg.AIDiscovery.SignaturePacks...),
		AllowWorkspaceSignatures: cfg.AIDiscovery.AllowWorkspaceSignatures,
		ScanRoots:                append([]string{}, cfg.AIDiscovery.ScanRoots...),
		DisabledSignatureIDs:     append([]string{}, cfg.AIDiscovery.DisabledSignatureIDs...),
		HomeDir:                  home,
		WorkingDir:               wd,
	})
}

// LoadAISignaturesWithOptions merges all configured catalog sources and
// rejects duplicates or malformed packs before discovery starts.
func LoadAISignaturesWithOptions(opts AISignatureLoadOptions) ([]AISignature, error) {
	base, err := LoadAISignatures()
	if err != nil {
		return nil, err
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
	for _, packPath := range packs {
		sigs, err := readAISignaturePack(packPath, maxBytes)
		if err != nil {
			return nil, err
		}
		for _, sig := range sigs {
			if disabled[sig.ID] {
				continue
			}
			if prev := seen[sig.ID]; prev != "" {
				return nil, fmt.Errorf("ai signature catalog: duplicate id %q in %s (already defined in %s)", sig.ID, packPath, prev)
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

func readAISignaturePack(path string, maxBytes int64) ([]AISignature, error) {
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
	return parseAISignatureCatalog(path, raw)
}

type signaturePackCandidate struct {
	path     string
	required bool
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
			return nil, fmt.Errorf("ai signature catalog: signature pack path matched nothing: %s", candidate.path)
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
			if h, err := os.UserHomeDir(); err == nil {
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
	if sig.Confidence <= 0 {
		sig.Confidence = 0.5
	}
	if sig.Confidence > 1 {
		sig.Confidence = 1
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
		"binary_names":      sig.BinaryNames,
		"process_names":     sig.ProcessNames,
		"application_names": sig.ApplicationNames,
		"config_paths":      sig.ConfigPaths,
		"extension_ids":     sig.ExtensionIDs,
		"mcp_paths":         sig.MCPPaths,
		"package_names":     sig.PackageNames,
		"env_var_names":     sig.EnvVarNames,
		"domain_patterns":   sig.DomainPatterns,
		"history_patterns":  sig.HistoryPatterns,
		"local_endpoints":   sig.LocalEndpoints,
	} {
		if err := validateSignatureValues(sig.ID, field, values); err != nil {
			return err
		}
	}
	return nil
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
