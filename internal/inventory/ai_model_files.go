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
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

const (
	maxModelArtifactEvidence   = 8
	maxOllamaManifestBytes     = int64(64 << 10)
	modelFileVisitMultiplier   = 64
	minModelFileVisitedEntries = 4096
	maxModelFileVisitedEntries = 200_000
	minModelFileVisitsPerRoot  = 1024
	maxModelFileVisitsPerRoot  = 50_000
)

type modelScanRoot struct {
	path        string
	provider    string
	specialized bool
}

type modelFileAggregate struct {
	key           string
	id            string
	format        string
	provider      string
	provenance    modelProvenanceHints
	sizeBytes     int64
	evidence      []AIEvidence
	artifactKeys  map[string]struct{}
	artifactKey   string
	aggregateHash string
	artifactCount int
}

type modelFileScanOutcome struct {
	conclusive map[string]bool
	attempted  map[string]bool
	deferred   map[string]bool
}

// modelFileCycle accumulates bounded pages for one root until its cursor
// reaches EOF. This makes lifecycle classification operate on one complete
// logical traversal instead of treating alternating shard/pages as changes.
// The aggregate count is capped at twice MaxFilesPerScan; overflowing cycles
// remain deferred and are never used to assert removals.
type modelFileCycle struct {
	aggregates   map[string]*modelFileAggregate
	order        []string
	artifactKeys int
	overflow     bool
}

var modelWeightShardPattern = regexp.MustCompile(`(?i)-[0-9]{1,6}-of-[0-9]{1,6}(?:\.|$)`)

// detectModelFiles inventories local model artifacts without reading model
// binary contents. Specialized model caches are scanned first so the global
// entry budget cannot be consumed by an unrelated part of a broad home-dir
// scan before Hugging Face, Ollama, MLX, LM Studio, or Lemonade caches are
// reached. The returned count is the number of matching artifact entries
// inspected (not every directory entry visited).
func (s *ContinuousDiscoveryService) detectModelFiles(ctx context.Context) ([]AISignal, int, error) {
	out, files, _, err := s.detectModelFilesWithOutcome(ctx)
	return out, files, err
}

func (s *ContinuousDiscoveryService) detectModelFilesWithOutcome(ctx context.Context) ([]AISignal, int, modelFileScanOutcome, error) {
	outcome := modelFileScanOutcome{
		conclusive: make(map[string]bool),
		attempted:  make(map[string]bool),
		deferred:   make(map[string]bool),
	}
	if s == nil {
		return nil, 0, outcome, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, outcome, err
	}

	roots := s.modelFileScanRoots()
	if len(roots) == 0 {
		return nil, 0, outcome, nil
	}
	delegatedRoots := nestedModelScanRoots(roots)
	if len(roots) > 1 {
		start := int((s.modelFileRootCursor.Add(1) - 1) % uint64(len(roots)))
		if start > 0 {
			rotated := make([]modelScanRoot, 0, len(roots))
			rotated = append(rotated, roots[start:]...)
			rotated = append(rotated, roots[:start]...)
			roots = rotated
		}
	}
	matchLimit := s.opts.MaxFilesPerScan
	if matchLimit <= 0 {
		matchLimit = 1000
	}
	visitLimit := matchLimit * modelFileVisitMultiplier
	if visitLimit < minModelFileVisitedEntries {
		visitLimit = minModelFileVisitedEntries
	}
	if visitLimit > maxModelFileVisitedEntries {
		visitLimit = maxModelFileVisitedEntries
	}
	perRootVisitLimit := visitLimit / 4
	if perRootVisitLimit < minModelFileVisitsPerRoot {
		perRootVisitLimit = minModelFileVisitsPerRoot
	}
	if perRootVisitLimit > maxModelFileVisitsPerRoot {
		perRootVisitLimit = maxModelFileVisitsPerRoot
	}

	var out []AISignal
	seenPaths := make(map[string]struct{})
	visited, matched, walkErrors := 0, 0, 0
	budgetExhausted := false

	deferredFrom := -1
	for rootIndex, root := range roots {
		if budgetExhausted || matched >= matchLimit {
			deferredFrom = rootIndex
			break
		}
		rootKey := hashPath(root.path)
		outcome.attempted[rootKey] = true
		resumeAfter := s.modelFileCursor(root.path)
		resumed := resumeAfter != ""
		lastCompleted := ""
		pageAggregates := make(map[string]*modelFileAggregate)
		pageOrder := make([]string, 0)
		rootVisited := 0
		rootIncomplete := false
		rootHadErrors := false
		walkErr := filepath.WalkDir(root.path, func(path string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				walkErrors++
				rootIncomplete = true
				rootHadErrors = true
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if resumed && path != root.path && path <= resumeAfter {
				if !d.IsDir() {
					return nil
				}
				// Walk cursor paths may themselves be atomic directory
				// artifacts (Core ML packages or Ollama blob stores). Skip a
				// completed directory, but keep descending through ancestors of
				// a cursor that points at a file deeper in the same subtree.
				if path == resumeAfter || !strings.HasPrefix(resumeAfter, path+string(os.PathSeparator)) {
					return filepath.SkipDir
				}
			}
			visited++
			rootVisited++
			if visited > visitLimit {
				budgetExhausted = true
				rootIncomplete = true
				return filepath.SkipAll
			}
			if rootVisited > perRootVisitLimit {
				rootIncomplete = true
				return filepath.SkipAll
			}
			if d.IsDir() {
				if path != root.path && modelPathInSet(path, delegatedRoots[root.path]) {
					// A more specific configured root owns this subtree. Skipping it
					// here keeps provider/evidence identity stable even when the
					// fairness cursor rotates the root traversal order.
					lastCompleted = path
					return filepath.SkipDir
				}
				macOSHomeLibrary := runtime.GOOS == "darwin" && !root.specialized &&
					filepath.Clean(path) == filepath.Join(filepath.Clean(s.opts.HomeDir), "Library")
				if path != root.path && (shouldSkipModelDirectory(d.Name(), root.specialized) || macOSHomeLibrary) {
					lastCompleted = path
					return filepath.SkipDir
				}
				lowerName := strings.ToLower(d.Name())
				if lowerName == "blobs" && isOllamaStorePath(path, root) {
					if resumed && path <= resumeAfter {
						return filepath.SkipDir
					}
					if _, duplicate := seenPaths[path]; duplicate {
						return filepath.SkipDir
					}
					seenPaths[path] = struct{}{}
					if matched >= matchLimit {
						budgetExhausted, rootIncomplete = true, true
						return filepath.SkipAll
					}
					if candidate, ok := s.ollamaBlobCacheAggregate(path, root); ok {
						addModelFileAggregate(pageAggregates, &pageOrder, candidate)
						matched++
					}
					lastCompleted = path
					return filepath.SkipDir
				}
				if lowerName == "blobs" && isHuggingFacePath(path, root) {
					// Snapshot filenames retain model extensions and are enough to
					// identify the model. Walking content-addressed blobs adds cost
					// without identity.
					lastCompleted = path
					return filepath.SkipDir
				}
				if strings.HasSuffix(lowerName, ".mlpackage") || strings.HasSuffix(lowerName, ".mlmodelc") {
					if resumed && path <= resumeAfter {
						return filepath.SkipDir
					}
					if _, duplicate := seenPaths[path]; !duplicate {
						if matched >= matchLimit {
							budgetExhausted, rootIncomplete = true, true
							return filepath.SkipAll
						}
						seenPaths[path] = struct{}{}
						if candidate, ok := s.modelArtifactCandidate(path, root, "coreml", true, ""); ok {
							addModelFileAggregate(pageAggregates, &pageOrder, candidate)
							matched++
						}
					}
					lastCompleted = path
					return filepath.SkipDir
				}
				return nil
			}

			if matched >= matchLimit {
				budgetExhausted = true
				rootIncomplete = true
				return filepath.SkipAll
			}
			// A non-directory entry is a complete lexical traversal unit even
			// when it is not a model. Advancing across all completed leaves is
			// what lets broad roots eventually move past thousands of unrelated
			// files instead of retrying the same prefix forever.
			lastCompleted = path
			modelID, isManifest := ollamaManifestModelID(path)
			isManifest = isManifest && isOllamaStorePath(path, root)
			format := ""
			if !isManifest {
				var formatOK bool
				format, formatOK = modelArtifactFormat(path, root)
				if !formatOK {
					return nil
				}
			}
			if resumed && path <= resumeAfter {
				return nil
			}
			if _, duplicate := seenPaths[path]; duplicate {
				return nil
			}
			seenPaths[path] = struct{}{}

			if isManifest {
				manifestHash, manifestOK, manifestErr := boundedOllamaManifestHash(path, s.opts.MaxFileBytes)
				if manifestErr != nil {
					rootIncomplete = true
					rootHadErrors = true
					walkErrors++
					return nil
				}
				candidate, candidateOK := s.modelArtifactCandidate(path, root, "ollama", false, modelID)
				if candidateOK && manifestOK {
					candidate.evidence[0].ValueHash = manifestHash
					candidate.provider = "ollama"
					candidate.sizeBytes = 0 // manifest bytes are not model bytes
					addModelFileAggregate(pageAggregates, &pageOrder, candidate)
					matched++
				} else if manifestOK {
					rootIncomplete = true
					rootHadErrors = true
					walkErrors++
				}
				return nil
			}

			candidate, ok := s.modelArtifactCandidate(path, root, format, false, "")
			if ok {
				addModelFileAggregate(pageAggregates, &pageOrder, candidate)
				matched++
			}
			return nil
		})
		if walkErr != nil {
			if err := ctx.Err(); err != nil {
				outcome.deferred[rootKey] = true
				for _, remainingRoot := range roots[rootIndex+1:] {
					outcome.deferred[hashPath(remainingRoot.path)] = true
				}
				out = append(out, modelAggregatesToSignals(s, pageAggregates, pageOrder)...)
				sortAISignals(out)
				return out, matched, outcome, err
			}
			walkErrors++
			rootIncomplete = true
			rootHadErrors = true
		}
		emitAggregates, emitOrder := pageAggregates, pageOrder
		if rootHadErrors {
			// A page with an unreadable/vanished subtree cannot participate in
			// a complete traversal. Restart the cycle next time and keep this
			// page deferred; it may still contain useful positive discoveries.
			s.resetModelFileCycle(root.path)
			s.setModelFileCursor(root.path, "")
			outcome.deferred[rootKey] = true
		} else if rootIncomplete {
			if lastCompleted != "" {
				s.setModelFileCursor(root.path, lastCompleted)
			}
			s.mergeModelFileCycle(root.path, pageAggregates, pageOrder, fileCycleAggregateLimit(matchLimit), false)
			outcome.deferred[rootKey] = true
		} else if resumed {
			// Reaching EOF after a resumed suffix completes the logical root
			// traversal. Emit the bounded cycle-wide aggregate so shards and
			// removals are reconciled against a consistent snapshot.
			cycleAggregates, cycleOrder, cycleOverflow := s.mergeModelFileCycle(
				root.path, pageAggregates, pageOrder, fileCycleAggregateLimit(matchLimit), true,
			)
			emitAggregates, emitOrder = cycleAggregates, cycleOrder
			s.setModelFileCursor(root.path, "")
			if cycleOverflow {
				emitAggregates, emitOrder = pageAggregates, pageOrder
				outcome.deferred[rootKey] = true
			} else {
				outcome.conclusive[rootKey] = true
			}
		} else {
			s.resetModelFileCycle(root.path)
			s.setModelFileCursor(root.path, "")
			outcome.conclusive[rootKey] = true
		}
		out = append(out, modelAggregatesToSignals(s, emitAggregates, emitOrder)...)
	}
	if deferredFrom >= 0 {
		for _, root := range roots[deferredFrom:] {
			key := hashPath(root.path)
			if !outcome.conclusive[key] {
				outcome.deferred[key] = true
			}
		}
	}

	sortAISignals(out)
	if walkErrors > 0 {
		return out, matched, outcome, fmt.Errorf("model file walk encountered %d errors (permission / vanished entries)", walkErrors)
	}
	return out, matched, outcome, nil
}

func (s *ContinuousDiscoveryService) modelFileCursor(root string) string {
	if s == nil {
		return ""
	}
	s.modelFileCursorMu.Lock()
	defer s.modelFileCursorMu.Unlock()
	return s.modelFileCursors[root]
}

func (s *ContinuousDiscoveryService) setModelFileCursor(root, cursor string) {
	if s == nil || root == "" {
		return
	}
	s.modelFileCursorMu.Lock()
	defer s.modelFileCursorMu.Unlock()
	if cursor == "" {
		delete(s.modelFileCursors, root)
		return
	}
	if s.modelFileCursors == nil {
		s.modelFileCursors = make(map[string]string)
	}
	s.modelFileCursors[root] = cursor
}

func fileCycleAggregateLimit(matchLimit int) int {
	if matchLimit <= 0 {
		return 1
	}
	if matchLimit > maxModelFileVisitedEntries/2 {
		return maxModelFileVisitedEntries
	}
	return matchLimit * 2
}

func addModelFileAggregate(aggregates map[string]*modelFileAggregate, order *[]string, candidate modelFileAggregate) {
	if candidate.key == "" || candidate.id == "" {
		return
	}
	if safeID, ok := safeLocalModelID(candidate.id); ok {
		candidate.id = safeID
	} else {
		return
	}
	candidate.format = boundedLocalModelField(candidate.format, maxLocalModelFormatBytes)
	candidate.provider = boundedLocalModelField(candidate.provider, maxLocalModelProviderBytes)
	existing := aggregates[candidate.key]
	if existing == nil {
		copyCandidate := candidate
		copyCandidate.artifactKeys = make(map[string]struct{})
		if candidate.artifactKey != "" {
			copyCandidate.artifactKeys[candidate.artifactKey] = struct{}{}
		}
		copyCandidate.aggregateHash = modelArtifactAggregateEntryHash(candidate)
		copyCandidate.artifactCount = 1
		aggregates[candidate.key] = &copyCandidate
		*order = append(*order, candidate.key)
		return
	}
	if candidate.artifactKey != "" {
		if _, duplicate := existing.artifactKeys[candidate.artifactKey]; duplicate {
			return
		}
		existing.artifactKeys[candidate.artifactKey] = struct{}{}
	}
	existing.aggregateHash = combineModelArtifactHashes(existing.aggregateHash, modelArtifactAggregateEntryHash(candidate))
	existing.artifactCount++
	mergeModelFileAggregateMetadata(existing, &candidate)
}

func mergeModelFileAggregateMetadata(existing, candidate *modelFileAggregate) {
	if existing == nil || candidate == nil {
		return
	}
	if formatPriority(candidate.format) > formatPriority(existing.format) {
		existing.format = candidate.format
	}
	if existing.provider == "" {
		existing.provider = candidate.provider
	}
	existing.provenance = mergeModelProvenanceHints(existing.provenance, candidate.provenance)
	if candidate.sizeBytes > 0 && existing.sizeBytes <= math.MaxInt64-candidate.sizeBytes {
		existing.sizeBytes += candidate.sizeBytes
	}
	for _, evidence := range candidate.evidence {
		if len(existing.evidence) >= maxModelArtifactEvidence {
			break
		}
		existing.evidence = append(existing.evidence, evidence)
	}
}

func combineModelArtifactHashes(left, right string) string {
	if left == "" {
		return right
	}
	if right == "" {
		return left
	}
	leftBytes, leftErr := hex.DecodeString(strings.TrimPrefix(left, "sha256:"))
	rightBytes, rightErr := hex.DecodeString(strings.TrimPrefix(right, "sha256:"))
	if leftErr != nil || rightErr != nil || len(leftBytes) != len(rightBytes) || len(leftBytes) == 0 {
		return hashValue(left + "|" + right)
	}
	for i := range leftBytes {
		leftBytes[i] ^= rightBytes[i]
	}
	return "sha256:" + hex.EncodeToString(leftBytes)
}

func (s *ContinuousDiscoveryService) mergeModelFileCycle(
	root string,
	page map[string]*modelFileAggregate,
	pageOrder []string,
	limit int,
	finish bool,
) (map[string]*modelFileAggregate, []string, bool) {
	s.modelFileCycleMu.Lock()
	defer s.modelFileCycleMu.Unlock()
	if s.modelFileCycles == nil {
		s.modelFileCycles = make(map[string]*modelFileCycle)
	}
	cycle := s.modelFileCycles[root]
	if cycle == nil {
		cycle = &modelFileCycle{aggregates: make(map[string]*modelFileAggregate)}
		s.modelFileCycles[root] = cycle
	}
	for _, key := range pageOrder {
		candidate := page[key]
		if candidate == nil {
			continue
		}
		existing := cycle.aggregates[key]
		if existing == nil {
			if len(cycle.aggregates) >= limit ||
				cycle.artifactKeys+len(candidate.artifactKeys) > maxModelFileVisitedEntries {
				cycle.overflow = true
				continue
			}
			copyCandidate := *candidate
			copyCandidate.evidence = append([]AIEvidence(nil), candidate.evidence...)
			copyCandidate.artifactKeys = make(map[string]struct{}, len(candidate.artifactKeys))
			for artifactKey := range candidate.artifactKeys {
				copyCandidate.artifactKeys[artifactKey] = struct{}{}
			}
			cycle.artifactKeys += len(copyCandidate.artifactKeys)
			cycle.aggregates[key] = &copyCandidate
			cycle.order = append(cycle.order, key)
			continue
		}
		newArtifactKeys := make([]string, 0, len(candidate.artifactKeys))
		duplicates := 0
		for artifactKey := range candidate.artifactKeys {
			if _, duplicate := existing.artifactKeys[artifactKey]; duplicate {
				duplicates++
			} else {
				newArtifactKeys = append(newArtifactKeys, artifactKey)
			}
		}
		if duplicates > 0 {
			if len(newArtifactKeys) == 0 {
				continue
			}
			// A page aggregate that mixes repeated and new aliases cannot be
			// split back into exact size/hash contributions. Keep the cycle
			// deferred instead of publishing an inflated conclusive snapshot.
			cycle.overflow = true
			continue
		}
		if cycle.artifactKeys+len(newArtifactKeys) > maxModelFileVisitedEntries {
			cycle.overflow = true
			continue
		}
		for _, artifactKey := range newArtifactKeys {
			existing.artifactKeys[artifactKey] = struct{}{}
		}
		cycle.artifactKeys += len(newArtifactKeys)
		existing.aggregateHash = combineModelArtifactHashes(existing.aggregateHash, candidate.aggregateHash)
		if candidate.artifactCount > 0 && existing.artifactCount <= math.MaxInt-candidate.artifactCount {
			existing.artifactCount += candidate.artifactCount
		}
		mergeModelFileAggregateMetadata(existing, candidate)
	}
	if !finish {
		return nil, nil, cycle.overflow
	}
	delete(s.modelFileCycles, root)
	return cycle.aggregates, cycle.order, cycle.overflow
}

func (s *ContinuousDiscoveryService) resetModelFileCycle(root string) {
	if s == nil || root == "" {
		return
	}
	s.modelFileCycleMu.Lock()
	defer s.modelFileCycleMu.Unlock()
	delete(s.modelFileCycles, root)
}

func (s *ContinuousDiscoveryService) modelFileScanRoots() []modelScanRoot {
	var roots []modelScanRoot
	seen := map[string]struct{}{}
	add := func(path, provider string, specialized bool) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if strings.HasPrefix(path, "~") {
			path = filepath.Join(s.opts.HomeDir, strings.TrimPrefix(path, "~"))
		}
		if !filepath.IsAbs(path) {
			return
		}
		path = filepath.Clean(path)
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return
		}
		path = filepath.Clean(resolved)
		if _, ok := seen[path]; ok {
			return
		}
		info, err := os.Stat(path)
		if err != nil || !info.IsDir() {
			return
		}
		seen[path] = struct{}{}
		roots = append(roots, modelScanRoot{path: path, provider: provider, specialized: specialized})
	}

	// Environment-selected stores take precedence over conventional paths.
	add(os.Getenv("HF_HUB_CACHE"), "huggingface", true)
	if hfHome := strings.TrimSpace(os.Getenv("HF_HOME")); hfHome != "" {
		add(filepath.Join(hfHome, "hub"), "huggingface", true)
	}
	add(os.Getenv("OLLAMA_MODELS"), "ollama", true)
	if lmHome := strings.TrimSpace(os.Getenv("LM_STUDIO_HOME")); lmHome != "" {
		add(lmHome, "lmstudio", true)
		add(filepath.Join(lmHome, "models"), "lmstudio", true)
	}
	add(os.Getenv("FLM_MODEL_PATH"), "flm", true)

	home := filepath.Clean(s.opts.HomeDir)
	if home != "" && home != "." {
		add(filepath.Join(home, ".cache", "huggingface", "hub"), "huggingface", true)
		add(filepath.Join(home, ".ollama", "models"), "ollama", true)
		add(filepath.Join(home, ".lmstudio", "models"), "lmstudio", true)
		add(filepath.Join(home, ".cache", "lm-studio", "models"), "lmstudio", true)
		add(filepath.Join(home, ".cache", "llama.cpp"), "llamacpp", true)
		add(filepath.Join(home, ".cache", "mlx"), "mlx", true)
		add(filepath.Join(home, ".mlx", "models"), "mlx", true)
		if runtime.GOOS == "darwin" {
			add(filepath.Join(home, "Library", "Application Support", "LM Studio", "models"), "lmstudio", true)
			add(filepath.Join(home, "Library", "Caches", "mlx"), "mlx", true)
		}
	}
	for _, root := range platformModelScanRoots(home) {
		add(root.path, root.provider, root.specialized)
	}
	for _, dir := range s.lemonadeConfiguredModelDirs() {
		add(dir, "lemonade", true)
	}
	for _, root := range s.scanRoots() {
		add(root, "filesystem", false)
	}
	return normalizeModelScanRoots(roots)
}

// normalizeModelScanRoots removes a broad root that is fully contained by a
// specialized store. The specialized root retains provider semantics and
// independently participates in the fairness rotation, so keeping the broad
// duplicate would only make artifact ownership order-dependent.
func normalizeModelScanRoots(roots []modelScanRoot) []modelScanRoot {
	out := make([]modelScanRoot, 0, len(roots))
	for i, root := range roots {
		drop := false
		if !root.specialized {
			for j, owner := range roots {
				if i != j && owner.specialized && modelPathWithin(root.path, owner.path) {
					drop = true
					break
				}
			}
		}
		if !drop {
			out = append(out, root)
		}
	}
	return out
}

// nestedModelScanRoots delegates each nested subtree to its more specific
// root. This prevents an ancestor from claiming the same model first when the
// root fairness cursor rotates, while still allowing every retained root to
// make bounded progress.
func nestedModelScanRoots(roots []modelScanRoot) map[string][]string {
	out := make(map[string][]string)
	for i, parent := range roots {
		for j, child := range roots {
			if i == j || !modelPathWithin(child.path, parent.path) {
				continue
			}
			out[parent.path] = append(out[parent.path], child.path)
		}
		sort.Strings(out[parent.path])
	}
	return out
}

func modelPathWithin(path, parent string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(path))
	if err != nil || relative == "." || relative == ".." {
		return false
	}
	return !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func modelPathInSet(path string, candidates []string) bool {
	path = filepath.Clean(path)
	for _, candidate := range candidates {
		candidate = filepath.Clean(candidate)
		if path == candidate || (runtime.GOOS == "windows" && strings.EqualFold(path, candidate)) {
			return true
		}
	}
	return false
}

func (s *ContinuousDiscoveryService) lemonadeConfiguredModelDirs() []string {
	var configs []string
	if cacheDir := strings.TrimSpace(os.Getenv("LEMONADE_CACHE_DIR")); cacheDir != "" {
		configs = append(configs, filepath.Join(cacheDir, "config.json"))
	} else {
		if s.opts.HomeDir != "" {
			configs = append(configs, filepath.Join(s.opts.HomeDir, ".cache", "lemonade", "config.json"))
		}
		actualHome, _ := os.UserHomeDir()
		if actualHome != "" && filepath.Clean(actualHome) == filepath.Clean(s.opts.HomeDir) {
			switch runtime.GOOS {
			case "darwin":
				configs = append(configs, "/Library/Application Support/lemonade/.cache/config.json")
			case "linux":
				configs = append(configs,
					"/var/lib/lemonade/.cache/lemonade/config.json",
					"/opt/var/lib/lemonade/.cache/lemonade/config.json",
				)
			}
		}
	}

	var out []string
	seen := map[string]struct{}{}
	for _, configPath := range configs {
		raw, err := readBoundedRegularFile(configPath, maxLemonadeConfigBytes)
		if err != nil {
			continue
		}
		var cfg struct {
			ModelsDir      string `json:"models_dir"`
			ExtraModelsDir string `json:"extra_models_dir"`
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		if err := dec.Decode(&cfg); err != nil {
			continue
		}
		for _, value := range []string{cfg.ModelsDir, cfg.ExtraModelsDir} {
			value = strings.TrimSpace(value)
			if value == "" || strings.EqualFold(value, "auto") {
				continue
			}
			if strings.HasPrefix(value, "~") {
				value = filepath.Join(s.opts.HomeDir, strings.TrimPrefix(value, "~"))
			} else if !filepath.IsAbs(value) {
				value = filepath.Join(filepath.Dir(configPath), value)
			}
			value = filepath.Clean(value)
			if _, exists := seen[value]; !exists {
				seen[value] = struct{}{}
				out = append(out, value)
			}
		}
	}
	return out
}

func shouldSkipModelDirectory(name string, specialized bool) bool {
	switch strings.ToLower(name) {
	case ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "dist", "build", "target":
		return true
	case ".cache":
		return !specialized
	default:
		return false
	}
}

func modelArtifactFormat(path string, root modelScanRoot) (string, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	var format string
	switch ext {
	case ".gguf":
		format = "gguf"
	case ".ggml":
		format = "ggml"
	case ".safetensors":
		format = "safetensors"
	case ".onnx":
		format = "onnx"
	case ".ort":
		format = "ort"
	case ".tflite":
		format = "tflite"
	case ".mlmodel":
		format = "coreml"
	case ".q4nx":
		format = "q4nx"
	case ".pt", ".pth", ".ckpt", ".bin":
		if !strongModelFileContext(path, root) {
			return "", false
		}
		format = strings.TrimPrefix(ext, ".")
	default:
		return "", false
	}
	if format == "safetensors" && isMLXPath(path, root) {
		format = "mlx"
	}
	return format, true
}

func strongModelFileContext(path string, root modelScanRoot) bool {
	if root.specialized {
		return true
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	for _, segment := range []string{"/models/", "/model/", "/weights/", "/checkpoints/", "/huggingface/", "/mlx/", "/.ollama/", "/lm studio/", "/llama.cpp/"} {
		if strings.Contains(lower, segment) {
			return true
		}
	}
	return false
}

func isMLXPath(path string, root modelScanRoot) bool {
	if root.provider == "mlx" {
		return true
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(lower, "models--mlx-community--") ||
		strings.Contains(lower, "/mlx/") || strings.Contains(lower, "/.mlx/")
}

func isHuggingFacePath(path string, root modelScanRoot) bool {
	return root.provider == "huggingface" || strings.Contains(strings.ToLower(path), "models--")
}

func isOllamaStorePath(path string, root modelScanRoot) bool {
	if root.provider == "ollama" {
		return true
	}
	lower := strings.ToLower(filepath.ToSlash(path))
	return strings.Contains(lower, "/.ollama/models/")
}

func (s *ContinuousDiscoveryService) modelArtifactCandidate(path string, root modelScanRoot, format string, directory bool, explicitID string) (modelFileAggregate, bool) {
	// Follows cache snapshot symlinks. Weight tensors are never read; a bounded
	// metadata prefix may be opened for self-describing containers such as GGUF.
	info, err := os.Stat(path)
	if err != nil || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return modelFileAggregate{}, false
	}
	id, key, provider := explicitID, "", root.provider
	artifactKey := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		artifactKey = filepath.Clean(resolved)
	}
	provenance := modelProvenanceHints{}
	if hfDir, hfID, ok := huggingFaceModelIdentity(path); ok {
		id, key, provider = hfID, "huggingface:"+hfDir, "huggingface"
		provenance.References = []string{hfID}
		provenance.HuggingFaceRepoIDs = []string{hfID}
		provenance.Source = "hf_cache"
		if strings.HasPrefix(strings.ToLower(hfID), "mlx-community/") {
			format, provider = "mlx", "mlx"
		}
	} else if explicitID != "" {
		key = "ollama-manifest:" + path
		provider = "ollama"
	} else if format == "mlx" || shouldAggregateWeightShards(path) {
		id = filepath.Base(filepath.Dir(path))
		key = "model-dir:" + filepath.Dir(path) + ":" + format
		if format == "mlx" {
			provider = "mlx"
		}
	} else if genericModelArtifactStem(path) {
		parentDir := filepath.Dir(path)
		parent := filepath.Base(parentDir)
		if filepath.Clean(parentDir) != filepath.Clean(root.path) && !genericModelDirectoryName(parent) {
			id = parent
			key = "model-dir:" + parentDir + ":" + format
		} else {
			id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			key = "model-file:" + path
		}
	} else {
		id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		key = "model-file:" + path
	}
	if directory {
		id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		key = "model-dir:" + path + ":" + format
	}
	if id == "" {
		return modelFileAggregate{}, false
	}
	if !directory {
		provenance = mergeModelProvenanceHints(provenance, modelArtifactProvenanceHints(path, format))
	}
	workspaceHash := hashPath(root.path)
	metadata := fmt.Sprintf("%s|%d|%d", format, info.Size(), info.ModTime().UTC().UnixNano())
	evidence := AIEvidence{
		Type:          "model_file",
		Basename:      filepath.Base(path),
		PathHash:      hashPath(path),
		ValueHash:     hashValue(metadata),
		WorkspaceHash: workspaceHash,
		Quality:       1,
		MatchKind:     MatchKindExact,
	}
	if s.opts.StoreRawLocalPaths {
		evidence.RawPath = path
	}
	sizeBytes := info.Size()
	if directory {
		sizeBytes = 0
	}
	return modelFileAggregate{
		key: key, id: id, format: format, provider: provider, provenance: provenance,
		sizeBytes: sizeBytes,
		evidence:  []AIEvidence{evidence}, artifactKey: artifactKey,
	}, true
}

func (s *ContinuousDiscoveryService) ollamaBlobCacheAggregate(path string, root modelScanRoot) (modelFileAggregate, bool) {
	fh, err := os.Open(path)
	if err != nil {
		return modelFileAggregate{}, false
	}
	names, readErr := fh.Readdirnames(64)
	_ = fh.Close()
	if readErr != nil && readErr != io.EOF {
		return modelFileAggregate{}, false
	}
	var blobs []string
	for _, name := range names {
		if strings.HasPrefix(strings.ToLower(name), "sha256-") {
			blobs = append(blobs, name)
		}
	}
	if len(blobs) == 0 {
		return modelFileAggregate{}, false
	}
	sort.Strings(blobs)
	evidence := AIEvidence{
		Type: "model_file", Basename: filepath.Base(path), PathHash: hashPath(path),
		ValueHash: hashValue(blobs[0]), WorkspaceHash: hashPath(root.path),
		Quality: 0.8, MatchKind: MatchKindHeuristic,
	}
	if s.opts.StoreRawLocalPaths {
		evidence.RawPath = path
	}
	return modelFileAggregate{
		key: "ollama-blobs:" + path, id: "Ollama blob cache", format: "ollama-blob",
		provider: "ollama", evidence: []AIEvidence{evidence},
	}, true
}

func huggingFaceModelIdentity(path string) (string, string, bool) {
	dir := path
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		dir = filepath.Dir(path)
	}
	for {
		base := filepath.Base(dir)
		if strings.HasPrefix(base, "models--") {
			encoded := strings.TrimPrefix(base, "models--")
			if encoded == "" {
				return "", "", false
			}
			return dir, strings.ReplaceAll(encoded, "--", "/"), true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", false
		}
		dir = parent
	}
}

func shouldAggregateWeightShards(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".safetensors" && ext != ".onnx" && ext != ".gguf" {
		return false
	}
	return modelWeightShardPattern.MatchString(filepath.Base(path))
}

func genericModelArtifactStem(path string) bool {
	stem := strings.ToLower(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	switch stem {
	case "model", "weights", "pytorch_model", "tf_model", "saved_model", "flax_model", "consolidated":
		return true
	default:
		return false
	}
}

func genericModelDirectoryName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", ".", "models", "model", "weights", "checkpoints", "checkpoint", "snapshots":
		return true
	default:
		return false
	}
}

func ollamaManifestModelID(path string) (string, bool) {
	parts := strings.Split(filepath.ToSlash(filepath.Clean(path)), "/")
	manifestIndex := -1
	for i, part := range parts {
		if strings.EqualFold(part, "manifests") {
			manifestIndex = i
			break
		}
	}
	if manifestIndex < 0 || len(parts)-manifestIndex < 4 {
		return "", false
	}
	remaining := append([]string(nil), parts[manifestIndex+1:]...)
	if len(remaining) > 0 && strings.Contains(remaining[0], ".") {
		remaining = remaining[1:] // registry host
	}
	if len(remaining) < 2 {
		return "", false
	}
	tag := remaining[len(remaining)-1]
	modelParts := remaining[:len(remaining)-1]
	if len(modelParts) > 1 && strings.EqualFold(modelParts[0], "library") {
		modelParts = modelParts[1:]
	}
	if len(modelParts) == 0 || tag == "" {
		return "", false
	}
	return strings.Join(modelParts, "/") + ":" + tag, true
}

func boundedOllamaManifestHash(path string, configuredMax int64) (string, bool, error) {
	limit := configuredMax
	if limit <= 0 || limit > maxOllamaManifestBytes {
		limit = maxOllamaManifestBytes
	}
	raw, err := readBoundedRegularFile(path, limit)
	if err != nil {
		return "", false, err
	}
	if !json.Valid(raw) {
		return "", false, nil
	}
	var manifest struct {
		SchemaVersion int               `json:"schemaVersion"`
		Config        json.RawMessage   `json:"config"`
		Layers        []json.RawMessage `json:"layers"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil || manifest.SchemaVersion <= 0 || (len(manifest.Config) == 0 && manifest.Layers == nil) {
		return "", false, nil
	}
	return hashValue(string(raw)), true, nil
}

func formatPriority(format string) int {
	switch format {
	case "mlx":
		return 100
	case "gguf":
		return 90
	case "onnx", "ort":
		return 80
	case "safetensors":
		return 70
	case "coreml":
		return 60
	default:
		return 10
	}
}

func modelAggregatesToSignals(s *ContinuousDiscoveryService, aggregates map[string]*modelFileAggregate, order []string) []AISignal {
	if len(order) == 0 {
		return nil
	}
	out := make([]AISignal, 0, len(order))
	for _, key := range order {
		candidate := aggregates[key]
		if candidate == nil || len(candidate.evidence) == 0 {
			continue
		}
		product, vendor := localModelArtifactProduct(candidate.provider)
		signature := AISignature{
			ID: "local-model-artifact", Name: product, Vendor: vendor,
			Category: SignalLocalModel, Confidence: 0.9, CuratorConfidence: 0.9, Specificity: 0.9,
		}
		signal := s.signalFromEvidence(signature, SignalLocalModel, "model_file", candidate.evidence)
		signal.EvidenceHash = hashValue(fmt.Sprintf(
			"%s|%s|artifacts:%d|bytes:%d",
			signal.EvidenceHash, candidate.aggregateHash, candidate.artifactCount, candidate.sizeBytes,
		))
		// EvidenceHash includes size/mtime/content metadata; the identity
		// fingerprint stays path/model stable so a modified model is classified
		// as changed rather than as an unrelated gone+new pair.
		signal.Fingerprint = hashValue("local-model-artifact|" + candidate.key)
		signal.Model = &LocalModelInfo{
			ID: candidate.id, Status: "installed", Format: candidate.format,
			Provider: candidate.provider, SizeBytes: candidate.sizeBytes,
		}
		enrichLocalModelProvenance(signal.Model, candidate.provenance)
		if signal.Model.Provenance != nil {
			provenanceJSON, _ := json.Marshal(signal.Model.Provenance)
			signal.EvidenceHash = hashValue(signal.EvidenceHash + "|provenance:" + string(provenanceJSON))
		}
		out = append(out, signal)
	}
	sortAISignals(out)
	return out
}

func modelArtifactAggregateEntryHash(candidate modelFileAggregate) string {
	parts := []string{candidate.artifactKey, candidate.format}
	for _, evidence := range candidate.evidence {
		parts = append(parts, evidence.PathHash, evidence.ValueHash)
	}
	return hashValue(strings.Join(parts, "|"))
}

func localModelArtifactProduct(provider string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "lemonade":
		return "Lemonade Server", "Lemonade"
	case "ollama":
		return "Ollama", "Ollama"
	case "lmstudio":
		return "LM Studio", "LM Studio"
	case "llamacpp":
		return "llama.cpp", "ggml.ai"
	case "jan":
		return "Jan", "Jan"
	case "gpt4all":
		return "GPT4All", "Nomic AI"
	case "anythingllm":
		return "AnythingLLM", "Mintplex Labs"
	default:
		return "Local Model Artifact", "Local"
	}
}
