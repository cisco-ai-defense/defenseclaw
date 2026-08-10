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
	"unicode"
)

const (
	maxModelArtifactEvidence   = 8
	maxOllamaManifestBytes     = int64(64 << 10)
	modelFileVisitMultiplier   = 64
	minModelFileVisitedEntries = 4096
	maxModelFileVisitedEntries = 200_000
	minModelFileVisitsPerRoot  = 1024
	maxModelFileVisitsPerRoot  = 50_000
	maxMacOSAppResourceRoots   = 512
	maxModelRootDiagnostics    = 16
)

const (
	modelScanScopeKnownStore         = "known_store"
	modelScanScopeConfigured         = "configured"
	modelScanScopeApplicationSupport = "application_support"
	modelScanScopeContainer          = "container"
	modelScanScopeGroupContainer     = "group_container"
	modelScanScopeCache              = "cache"
	modelScanScopeAppResources       = "app_resources"
)

const (
	localModelModalityGenerative = "generative"
	localModelModalitySpeech     = "speech"
	localModelModalityVision     = "vision"
	localModelModalityEmbedding  = "embedding"
	localModelModalityAudio      = "audio"
	localModelModalityUnknown    = "unknown"

	localModelRelevancePrimary    = "primary"
	localModelRelevanceSupporting = "supporting"
	localModelRelevanceEmbedded   = "embedded"
	localModelRelevanceUnknown    = "unknown"
)

type modelScanRoot struct {
	path                string
	provider            string
	specialized         bool
	scope               string
	owner               string
	metadataSidecars    map[string]bool
	macOSOwnershipRoots []modelScanRoot
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
	owner         string
	modality      string
	relevance     string
	confidence    float64
}

type modelFileScanOutcome struct {
	conclusive map[string]bool
	attempted  map[string]bool
	deferred   map[string]bool
	rootErrors map[string]string
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
	incomplete   bool
}

var modelWeightShardPattern = regexp.MustCompile(`(?i)-[0-9]{1,6}-of-[0-9]{1,6}(?:\.|$)`)

// detectModelFiles inventories local model artifacts without reading model
// binary contents. Specialized stores receive bounded recurring starts while
// generic roots rotate independently, so neither known runtimes nor unknown
// application stores can be starved by a saturated global budget. The returned
// count is the number of matching artifact entries inspected (not every
// directory entry visited).
func (s *ContinuousDiscoveryService) detectModelFiles(ctx context.Context) ([]AISignal, int, error) {
	out, files, _, err := s.detectModelFilesWithOutcome(ctx)
	return out, files, err
}

func (s *ContinuousDiscoveryService) detectModelFilesWithOutcome(ctx context.Context) ([]AISignal, int, modelFileScanOutcome, error) {
	outcome := modelFileScanOutcome{
		conclusive: make(map[string]bool),
		attempted:  make(map[string]bool),
		deferred:   make(map[string]bool),
		rootErrors: make(map[string]string),
	}
	if s == nil {
		return nil, 0, outcome, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, 0, outcome, err
	}

	roots, rootDiscoveryErrors := s.modelFileScanRootsWithErrors()
	for rootKey, detail := range rootDiscoveryErrors {
		outcome.rootErrors[rootKey] = detail
		outcome.attempted[rootKey] = true
		outcome.deferred[rootKey] = true
	}
	if len(roots) == 0 {
		if len(rootDiscoveryErrors) > 0 {
			outcome.rootErrors = boundedModelRootDiagnostics(outcome.rootErrors)
			return nil, 0, outcome, fmt.Errorf("model file scan incomplete for %d roots", len(rootDiscoveryErrors))
		}
		return nil, 0, outcome, nil
	}
	roots, priorityRootCount := prioritizeModelScanRoots(roots)
	homes := s.homesToScan()
	macOSOwnershipRoots := macOSLibraryModelScanRootsForHomes(homes)
	metadataSidecars := make(map[string]bool)
	for i := range roots {
		roots[i].metadataSidecars = metadataSidecars
		roots[i].macOSOwnershipRoots = macOSOwnershipRoots
	}
	delegatedRoots := nestedModelScanRoots(roots)
	if len(roots) > 1 {
		sequence := s.modelFileRootCursor.Add(1) - 1
		start := modelRootRotationStart(sequence, len(roots), priorityRootCount)
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
	rootDivisor := len(roots)
	if rootDivisor < 4 {
		rootDivisor = 4
	}
	if rootDivisor > 16 {
		rootDivisor = 16
	}
	perRootVisitLimit := visitLimit / rootDivisor
	if perRootVisitLimit < minModelFileVisitsPerRoot {
		perRootVisitLimit = minModelFileVisitsPerRoot
	}
	if perRootVisitLimit > maxModelFileVisitsPerRoot {
		perRootVisitLimit = maxModelFileVisitsPerRoot
	}

	var out []AISignal
	seenPaths := make(map[string]struct{})
	visited, matched, walkErrors := 0, 0, len(rootDiscoveryErrors)
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
		rootVisitLimit := modelRootVisitLimit(root, perRootVisitLimit, visitLimit)
		rootIncomplete := false
		rootHadErrors := false
		rootErrorCount := 0
		walkErr := filepath.WalkDir(root.path, func(path string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			// A cursor represents a lexical prefix already attempted during this
			// logical traversal. Do not let the same protected/vanished entry in
			// that completed prefix poison every resumed page forever.
			if resumed && path != root.path && path <= resumeAfter && walkErr != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if walkErr != nil {
				walkErrors++
				rootErrorCount++
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
			if rootVisited > rootVisitLimit {
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
					isMacOSHomeLibrary(path, homes)
				if path != root.path && (shouldSkipModelDirectoryForRoot(d.Name(), root) || macOSHomeLibrary) {
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
						if candidate, ok := s.modelArtifactCandidate(path, root, "coreml", true, "", nil); ok {
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
			var admittedIdentity *modelArtifactIdentity
			if !isManifest {
				var formatOK bool
				format, admittedIdentity, formatOK = modelArtifactFormat(path, root)
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
					rootErrorCount++
					return nil
				}
				candidate, candidateOK := s.modelArtifactCandidate(path, root, "ollama", false, modelID, nil)
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
					rootErrorCount++
				}
				return nil
			}

			candidate, ok := s.modelArtifactCandidate(path, root, format, false, "", admittedIdentity)
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
				outcome.rootErrors = boundedModelRootDiagnostics(outcome.rootErrors)
				return out, matched, outcome, err
			}
			walkErrors++
			rootErrorCount++
			rootIncomplete = true
			rootHadErrors = true
		}
		if rootHadErrors {
			outcome.rootErrors[rootKey] = modelRootErrorDetail(root, rootErrorCount)
		}
		emitAggregates, emitOrder := pageAggregates, pageOrder
		if rootHadErrors {
			// Broad roots can contain a permanently protected subtree. Preserve
			// bounded forward progress for those roots, while tainting the logical
			// cycle so it can emit positive discoveries but never assert removals.
			if !root.specialized && lastCompleted != "" {
				s.setModelFileCursor(root.path, lastCompleted)
				s.mergeModelFileCycle(
					root.path, pageAggregates, pageOrder,
					fileCycleAggregateLimit(matchLimit), false, true,
				)
			} else {
				s.resetModelFileCycle(root.path)
				s.setModelFileCursor(root.path, "")
			}
			outcome.deferred[rootKey] = true
		} else if rootIncomplete {
			if lastCompleted != "" {
				s.setModelFileCursor(root.path, lastCompleted)
			}
			_, _, _, cycleIncomplete := s.mergeModelFileCycle(
				root.path, pageAggregates, pageOrder,
				fileCycleAggregateLimit(matchLimit), false, false,
			)
			if cycleIncomplete {
				outcome.rootErrors[rootKey] = modelRootDeferredErrorDetail(root)
				walkErrors++
			}
			outcome.deferred[rootKey] = true
		} else if resumed {
			// Reaching EOF after a resumed suffix completes the logical root
			// traversal. Emit the bounded cycle-wide aggregate so shards and
			// removals are reconciled against a consistent snapshot.
			cycleAggregates, cycleOrder, cycleOverflow, cycleIncomplete := s.mergeModelFileCycle(
				root.path, pageAggregates, pageOrder,
				fileCycleAggregateLimit(matchLimit), true, false,
			)
			emitAggregates, emitOrder = cycleAggregates, cycleOrder
			s.setModelFileCursor(root.path, "")
			if cycleOverflow {
				emitAggregates, emitOrder = pageAggregates, pageOrder
				outcome.deferred[rootKey] = true
			} else if cycleIncomplete {
				outcome.rootErrors[rootKey] = modelRootDeferredErrorDetail(root)
				walkErrors++
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
		erroredRoots := len(outcome.rootErrors)
		outcome.rootErrors = boundedModelRootDiagnostics(outcome.rootErrors)
		return out, matched, outcome, fmt.Errorf(
			"model file scan incomplete: %d filesystem errors across %d roots",
			walkErrors, erroredRoots,
		)
	}
	outcome.rootErrors = boundedModelRootDiagnostics(outcome.rootErrors)
	return out, matched, outcome, nil
}

func prioritizeModelScanRoots(roots []modelScanRoot) ([]modelScanRoot, int) {
	prioritized := make([]modelScanRoot, 0, len(roots))
	for _, root := range roots {
		if root.specialized {
			prioritized = append(prioritized, root)
		}
	}
	priorityCount := len(prioritized)
	for _, root := range roots {
		if !root.specialized {
			prioritized = append(prioritized, root)
		}
	}
	return prioritized, priorityCount
}

func modelRootVisitLimit(root modelScanRoot, baseLimit, globalLimit int) int {
	limit := baseLimit
	switch root.scope {
	case modelScanScopeApplicationSupport, modelScanScopeContainer, modelScanScopeGroupContainer:
		// These are the highest-yield catalog-independent macOS roots. Give
		// each selected page enough depth to move through a large app store in
		// a few scans, while retaining the global cap and root rotation.
		if limit <= maxModelFileVisitsPerRoot/4 {
			limit *= 4
		} else {
			limit = maxModelFileVisitsPerRoot
		}
		if limit < 8*minModelFileVisitsPerRoot {
			limit = 8 * minModelFileVisitsPerRoot
		}
	}
	if limit > maxModelFileVisitsPerRoot {
		limit = maxModelFileVisitsPerRoot
	}
	if globalLimit > 0 && limit > globalLimit {
		limit = globalLimit
	}
	if limit < 1 {
		return 1
	}
	return limit
}

func modelRootRotationStart(sequence uint64, rootCount, priorityRootCount int) int {
	if rootCount <= 1 {
		return 0
	}
	if priorityRootCount < 0 {
		priorityRootCount = 0
	} else if priorityRootCount > rootCount {
		priorityRootCount = rootCount
	}
	remaining := rootCount - priorityRootCount
	if priorityRootCount == rootCount {
		return int(sequence % uint64(rootCount))
	}
	if priorityRootCount > 0 && sequence%2 == 0 {
		return int((sequence / 2) % uint64(priorityRootCount))
	}
	genericSequence := sequence
	if priorityRootCount > 0 {
		genericSequence = sequence / 2
	}
	if remaining <= 1 {
		return priorityRootCount
	}
	return priorityRootCount + distributedModelRootIndex(genericSequence, remaining)
}

func distributedModelRootIndex(sequence uint64, rootCount int) int {
	if rootCount <= 1 {
		return 0
	}
	stride := int(math.Sqrt(float64(rootCount)))
	if stride < 1 {
		stride = 1
	}
	for greatestCommonDivisor(stride, rootCount) != 1 {
		stride++
	}
	return int((sequence * uint64(stride)) % uint64(rootCount))
}

func greatestCommonDivisor(left, right int) int {
	for right != 0 {
		left, right = right, left%right
	}
	return left
}

func boundedModelRootDiagnostics(in map[string]string) map[string]string {
	if len(in) <= maxModelRootDiagnostics {
		return in
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[string]string, maxModelRootDiagnostics+1)
	for _, key := range keys[:maxModelRootDiagnostics] {
		out[key] = in[key]
	}
	out["additional_roots"] = fmt.Sprintf(
		"%d additional model roots had errors; details omitted", len(in)-maxModelRootDiagnostics,
	)
	return out
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
	candidate.owner = boundedModelOwner(candidate.owner)
	if !validLocalModelModality(candidate.modality) {
		candidate.modality = localModelModalityUnknown
	}
	if !validLocalModelRelevance(candidate.relevance) {
		candidate.relevance = localModelRelevanceUnknown
	}
	if candidate.confidence < 0 {
		candidate.confidence = 0
	} else if candidate.confidence > 1 {
		candidate.confidence = 1
	}
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
	if existing.owner == "" || (candidate.owner != "" && candidate.owner < existing.owner) {
		existing.owner = candidate.owner
	}
	if modelModalityPriority(candidate.modality) > modelModalityPriority(existing.modality) {
		existing.modality = candidate.modality
	}
	if modelRelevancePriority(candidate.relevance) > modelRelevancePriority(existing.relevance) {
		existing.relevance = candidate.relevance
	}
	if candidate.confidence > existing.confidence {
		existing.confidence = candidate.confidence
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
	markIncomplete bool,
) (map[string]*modelFileAggregate, []string, bool, bool) {
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
	cycle.incomplete = cycle.incomplete || markIncomplete
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
		return nil, nil, cycle.overflow, cycle.incomplete
	}
	delete(s.modelFileCycles, root)
	return cycle.aggregates, cycle.order, cycle.overflow, cycle.incomplete
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
	roots, _ := s.modelFileScanRootsWithErrors()
	return roots
}

func (s *ContinuousDiscoveryService) modelFileScanRootsWithErrors() ([]modelScanRoot, map[string]string) {
	var roots []modelScanRoot
	seen := map[string]struct{}{}
	rootErrors := make(map[string]string)
	add := func(root modelScanRoot) {
		path := strings.TrimSpace(root.path)
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
			if !os.IsNotExist(err) {
				rootErrors[hashPath(path)] = modelRootAccessErrorDetail(root, err)
			}
			return
		}
		path = filepath.Clean(resolved)
		if _, ok := seen[path]; ok {
			return
		}
		info, err := os.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				rootErrors[hashPath(path)] = modelRootAccessErrorDetail(root, err)
			}
			return
		}
		if !info.IsDir() {
			return
		}
		seen[path] = struct{}{}
		root.path = path
		if root.provider == "" {
			root.provider = "filesystem"
		}
		if root.scope == "" {
			root.scope = modelScanScopeConfigured
		}
		root.owner = boundedModelOwner(root.owner)
		roots = append(roots, root)
	}
	known := func(path, provider string) {
		add(modelScanRoot{
			path: path, provider: provider, specialized: true, scope: modelScanScopeKnownStore,
		})
	}

	// Environment-selected stores take precedence over conventional paths.
	known(os.Getenv("HF_HUB_CACHE"), "huggingface")
	if hfHome := strings.TrimSpace(os.Getenv("HF_HOME")); hfHome != "" {
		known(filepath.Join(hfHome, "hub"), "huggingface")
	}
	known(os.Getenv("OLLAMA_MODELS"), "ollama")
	if lmHome := strings.TrimSpace(os.Getenv("LM_STUDIO_HOME")); lmHome != "" {
		known(lmHome, "lmstudio")
		known(filepath.Join(lmHome, "models"), "lmstudio")
	}
	known(os.Getenv("FLM_MODEL_PATH"), "flm")

	homes := s.homesToScan()
	if len(homes) == 0 && strings.TrimSpace(s.opts.HomeDir) != "" {
		homes = []string{s.opts.HomeDir}
	}
	macOSAppResourceRoots := 0
	for _, candidateHome := range homes {
		home := filepath.Clean(candidateHome)
		if home == "" || home == "." {
			continue
		}
		known(filepath.Join(home, ".cache", "huggingface", "hub"), "huggingface")
		known(filepath.Join(home, ".ollama", "models"), "ollama")
		known(filepath.Join(home, ".lmstudio", "models"), "lmstudio")
		known(filepath.Join(home, ".cache", "lm-studio", "models"), "lmstudio")
		known(filepath.Join(home, ".cache", "llama.cpp"), "llamacpp")
		known(filepath.Join(home, ".cache", "mlx"), "mlx")
		known(filepath.Join(home, ".mlx", "models"), "mlx")
		if runtime.GOOS == "darwin" {
			known(filepath.Join(home, "Library", "Application Support", "LM Studio", "models"), "lmstudio")
			known(filepath.Join(home, "Library", "Caches", "mlx"), "mlx")
			if strings.EqualFold(s.opts.Mode, "enhanced") {
				actualHome, _ := os.UserHomeDir()
				includeGlobalApplications := filepath.Clean(actualHome) == home
				remainingAppRoots := maxMacOSAppResourceRoots - macOSAppResourceRoots
				for _, root := range enhancedMacOSModelScanRoots(home, includeGlobalApplications, remainingAppRoots) {
					before := len(roots)
					add(root)
					if root.scope == modelScanScopeAppResources && len(roots) > before {
						macOSAppResourceRoots++
					}
				}
			}
		}
	}
	for _, root := range platformModelScanRoots(filepath.Clean(s.opts.HomeDir)) {
		if root.scope == "" {
			root.scope = modelScanScopeKnownStore
		}
		add(root)
	}
	for _, dir := range s.lemonadeConfiguredModelDirs() {
		known(dir, "lemonade")
	}
	configured := make([]string, 0, len(s.opts.ScanRoots))
	for _, candidate := range s.opts.ScanRoots {
		configured = append(configured, s.expandCandidatePath(candidate)...)
	}
	if len(configured) == 0 {
		configured = append(configured, homes...)
	}
	for _, path := range configured {
		if strings.EqualFold(s.opts.Mode, "passive") && isBroadModelHomeRoot(path, homes) {
			continue
		}
		add(modelScanRoot{path: path, provider: "filesystem", scope: modelScanScopeConfigured})
	}
	return normalizeModelScanRoots(roots), rootErrors
}

// enhancedMacOSModelScanRoots keeps the privacy boundary around a broad home
// scan: ~/Library is still skipped by that walk, while the four areas where
// sandboxed and desktop applications commonly store models each receive an
// independent traversal budget and cursor. App bundle resources are admitted
// as per-application roots, capped to bound root-list memory and scan latency.
func enhancedMacOSModelScanRoots(home string, includeGlobalApplications bool, appResourceLimit int) []modelScanRoot {
	roots := macOSLibraryModelScanRoots(home)
	if len(roots) == 0 {
		return nil
	}
	return append(roots, macOSApplicationResourceScanRoots(home, includeGlobalApplications, appResourceLimit)...)
}

func macOSApplicationResourceScanRoots(home string, includeGlobalApplications bool, limit int) []modelScanRoot {
	if limit <= 0 {
		return nil
	}
	home = filepath.Clean(strings.TrimSpace(home))

	applicationParents := []string{filepath.Join(home, "Applications")}
	if includeGlobalApplications {
		applicationParents = append(applicationParents, "/Applications")
	}
	var roots []modelScanRoot
	for _, parent := range applicationParents {
		children, err := os.ReadDir(parent)
		if err != nil {
			continue
		}
		for _, child := range children {
			if len(roots) >= limit {
				return roots
			}
			name := strings.TrimSpace(child.Name())
			if !strings.HasSuffix(strings.ToLower(name), ".app") {
				continue
			}
			roots = append(roots, modelScanRoot{
				path:     filepath.Join(parent, name, "Contents", "Resources"),
				provider: "filesystem", scope: modelScanScopeAppResources,
				owner: humanizeApplicationIdentifier(strings.TrimSuffix(name, filepath.Ext(name))),
			})
		}
	}
	return roots
}

func macOSLibraryModelScanRoots(home string) []modelScanRoot {
	home = filepath.Clean(strings.TrimSpace(home))
	if home == "" || home == "." {
		return nil
	}
	library := filepath.Join(home, "Library")
	return []modelScanRoot{
		{path: filepath.Join(library, "Application Support"), provider: "filesystem", scope: modelScanScopeApplicationSupport},
		{path: filepath.Join(library, "Containers"), provider: "filesystem", scope: modelScanScopeContainer},
		{path: filepath.Join(library, "Group Containers"), provider: "filesystem", scope: modelScanScopeGroupContainer},
		{path: filepath.Join(library, "Caches"), provider: "filesystem", scope: modelScanScopeCache},
	}
}

func macOSLibraryModelScanRootsForHomes(homes []string) []modelScanRoot {
	roots := make([]modelScanRoot, 0, len(homes)*4)
	for _, home := range homes {
		roots = append(roots, macOSLibraryModelScanRoots(home)...)
	}
	return roots
}

func isBroadModelHomeRoot(path string, homes []string) bool {
	path = filepath.Clean(path)
	for _, home := range homes {
		if path == filepath.Clean(home) {
			return true
		}
	}
	return false
}

func modelRootAccessErrorDetail(root modelScanRoot, err error) string {
	reason := "unavailable"
	if os.IsPermission(err) {
		reason = "permission denied"
	}
	return fmt.Sprintf("%s root %s", modelRootDiagnosticLabel(root), reason)
}

func modelRootErrorDetail(root modelScanRoot, count int) string {
	if count < 1 {
		count = 1
	}
	return fmt.Sprintf("%s root incomplete (%d unreadable or changed entries)", modelRootDiagnosticLabel(root), count)
}

func modelRootDeferredErrorDetail(root modelScanRoot) string {
	return fmt.Sprintf("%s root remains incomplete after an unreadable or changed entry", modelRootDiagnosticLabel(root))
}

func modelRootDiagnosticLabel(root modelScanRoot) string {
	switch root.scope {
	case modelScanScopeApplicationSupport:
		return "application-support"
	case modelScanScopeContainer:
		return "application-container"
	case modelScanScopeGroupContainer:
		return "group-container"
	case modelScanScopeCache:
		return "application-cache"
	case modelScanScopeAppResources:
		return "application-resources"
	case modelScanScopeKnownStore:
		return "known-model-store"
	default:
		return "configured-filesystem"
	}
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

func shouldSkipModelDirectoryForRoot(name string, root modelScanRoot) bool {
	if !isMacOSApplicationModelScope(root.scope) {
		return shouldSkipModelDirectory(name, root.specialized)
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	switch lower {
	case ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "target":
		return true
	case "logs", "log", "crashpad", "crash reports", "crashreporter", "code cache",
		"gpucache", "shadercache", "dawncache", "httpstorages", "webkit", "webstorage",
		"indexeddb", "service worker", "saved application state", "cookies", "preferences",
		"local storage":
		return true
	}
	if root.scope == modelScanScopeAppResources {
		return strings.HasSuffix(lower, ".lproj") || lower == "locales" || lower == "translations" ||
			lower == "help" || lower == "documentation" || lower == "fonts" || lower == "icons" || lower == "images"
	}
	return false
}

func isMacOSApplicationModelScope(scope string) bool {
	switch scope {
	case modelScanScopeApplicationSupport, modelScanScopeContainer, modelScanScopeGroupContainer,
		modelScanScopeCache, modelScanScopeAppResources:
		return true
	default:
		return false
	}
}

func isMacOSHomeLibrary(path string, homes []string) bool {
	path = filepath.Clean(path)
	for _, home := range homes {
		if path == filepath.Join(filepath.Clean(home), "Library") {
			return true
		}
	}
	return false
}

func modelArtifactFormat(path string, root modelScanRoot) (string, *modelArtifactIdentity, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	var format string
	var admittedIdentity *modelArtifactIdentity
	ambiguous := false
	switch ext {
	case ".gguf":
		format = "gguf"
	case ".ggml":
		format = "ggml"
	case ".safetensors":
		format = "safetensors"
	case ".onnx":
		format = "onnx"
		ambiguous = true
	case ".ort":
		format = "ort"
		ambiguous = true
	case ".tflite":
		format = "tflite"
		ambiguous = true
	case ".mlmodel":
		format = "coreml"
	case ".q4nx":
		format = "q4nx"
	case ".pt", ".pth", ".ckpt", ".bin":
		format = strings.TrimPrefix(ext, ".")
		ambiguous = true
	default:
		return "", nil, false
	}
	if ambiguous {
		var admitted bool
		admittedIdentity, admitted = admitAmbiguousModelArtifact(path, root, format)
		if !admitted {
			return "", nil, false
		}
	}
	if format == "safetensors" && isMLXPath(path, root) {
		format = "mlx"
	}
	return format, admittedIdentity, true
}

// admitAmbiguousModelArtifact requires two independent signals outside known
// model stores: an explicit model context and a meaningful artifact identity.
// This keeps generic runtime payloads such as model.tflite and weights.bin from
// being promoted to model rows merely because their basename contains "model"
// or "weights". Specialized stores retain their established behavior because
// the store itself supplies both ownership and model context.
func admitAmbiguousModelArtifact(path string, root modelScanRoot, format string) (*modelArtifactIdentity, bool) {
	if root.specialized {
		return nil, true
	}
	if knownEmbeddedModelPayloadPath(path) {
		return nil, false
	}

	explicitContext := strongModelFileContext(path, root) || hasModelMetadataSidecar(path, root)
	if !explicitContext && scopedApplicationSemanticContext(root, path) {
		explicitContext = true
	}
	if !explicitContext {
		return nil, false
	}
	identity, ok := deriveModelArtifactIdentity(path, root, format, false, "")
	if !ok {
		return nil, false
	}
	if !identity.trusted && !modelLikeArtifactIdentity(identity.id) {
		return nil, false
	}
	return &identity, true
}

// scopedApplicationSemanticContext allows a clearly named artifact directly
// inside an application's support/container/resources tree. A cache root is
// deliberately excluded: semantic filenames are common in browser and app
// caches and do not establish that a user-manageable model is installed.
func scopedApplicationSemanticContext(root modelScanRoot, path string) bool {
	switch root.scope {
	case modelScanScopeApplicationSupport, modelScanScopeContainer,
		modelScanScopeGroupContainer, modelScanScopeAppResources:
		return semanticModelArtifactName(path)
	default:
		return false
	}
}

// knownEmbeddedModelPayloadPath identifies browser optimization-guide stores
// observed to use opaque hash/version directory names for internal classifier
// and on-device payloads. High-signal formats are unaffected because this
// predicate is consulted only for ambiguous containers.
func knownEmbeddedModelPayloadPath(path string) bool {
	for _, part := range strings.Split(strings.ToLower(filepath.ToSlash(filepath.Clean(path))), "/") {
		switch part {
		case "optimization_guide_model_store", "optimizationguidepredictionmodels",
			"optguideondevicemodel", "optguideondeviceclassifiermodel":
			return true
		}
	}
	return false
}

func modelLikeArtifactIdentity(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || genericModelArtifactStem(value) || genericModelDirectoryName(value) {
		return false
	}
	if versionOnlyModelArtifactIdentity(value) {
		return false
	}
	switch strings.ToLower(value) {
	case "artifact", "blob", "cache", "data", "default", "payload", "resource", "resources", "runtime", "unknown":
		return false
	}

	hasLetter := false
	hexDigits := 0
	opaqueHex := true
	for _, r := range value {
		if unicode.IsLetter(r) {
			hasLetter = true
		}
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			hexDigits++
		case r == '-', r == '_':
			// Hashes and UUID-shaped cache keys commonly include separators.
		default:
			opaqueHex = false
		}
	}
	if !hasLetter || (opaqueHex && hexDigits >= 12) {
		return false
	}
	return true
}

// versionOnlyModelArtifactIdentity rejects cache/version directory names while
// deliberately leaving ordinary versioned model names (for example,
// whisper-v3 or qwen2.5) alone. Only a leading v/version prefix followed
// exclusively by numeric components and separators qualifies.
func versionOnlyModelArtifactIdentity(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	var remainder string
	switch {
	case strings.HasPrefix(value, "version"):
		remainder = strings.TrimPrefix(value, "version")
	case len(value) > 1 && value[0] == 'v' &&
		((value[1] >= '0' && value[1] <= '9') || strings.ContainsRune("-_. ", rune(value[1]))):
		remainder = value[1:]
	default:
		return false
	}
	remainder = strings.TrimLeft(remainder, "-_. ")
	if remainder == "" {
		return false
	}
	hasDigit := false
	for _, r := range remainder {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case strings.ContainsRune("-_. ", r):
		default:
			return false
		}
	}
	return hasDigit
}

func strongModelFileContext(path string, root modelScanRoot) bool {
	if root.specialized {
		return true
	}
	dir := filepath.Dir(filepath.Clean(path))
	for {
		segment := strings.ToLower(strings.TrimSpace(filepath.Base(dir)))
		switch segment {
		case "models", "model", "weights", "weight", "checkpoints", "checkpoint", "huggingface",
			"mlx", ".mlx", ".ollama", "lm studio", "llama.cpp", "onnx", "ort", "tflite",
			"coreml", "mlmodels", "modelstore", "model_store", "model-cache", "model_cache",
			"ai-models", "ai_models", "optimizationguidepredictionmodels":
			return true
		}
		if strings.HasPrefix(segment, "models--") || strings.HasSuffix(segment, "-models") ||
			strings.HasSuffix(segment, "_models") || strings.HasSuffix(segment, " model") ||
			strings.HasSuffix(segment, " models") {
			return true
		}
		if dir == root.path {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir || !modelPathWithin(dir, root.path) {
			break
		}
		dir = parent
	}
	return false
}

func semanticModelArtifactName(path string) bool {
	stem := strings.ToLower(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
	for _, token := range []string{
		"model", "weight", "checkpoint", "encoder", "decoder", "whisper", "parakeet", "speech",
		"transcrib", "diar", "speaker", "vad", "silero", "moonshine", "sensevoice", "embedding",
		"rerank", "sentence-transform", "vision", "image", "yolo", "classifier", "detector", "segment",
		"depth", "ocr", "wav2vec", "encodec",
	} {
		if strings.Contains(stem, token) {
			return true
		}
	}
	return false
}

func hasModelMetadataSidecar(path string, root modelScanRoot) (found bool) {
	dir := filepath.Dir(filepath.Clean(path))
	cleanRoot := filepath.Clean(root.path)
	cacheKey := cleanRoot + "\x00" + dir
	if root.metadataSidecars != nil {
		if cached, ok := root.metadataSidecars[cacheKey]; ok {
			return cached
		}
		defer func() {
			root.metadataSidecars[cacheKey] = found
		}()
	}
	for level := 0; level < 2; level++ {
		for _, name := range []string{
			"config.json", "model_config.json", "generation_config.json", "tokenizer.json",
			"tokenizer_config.json", "preprocessor_config.json", "processor_config.json",
			"model_index.json", "vocab.json",
		} {
			if info, err := os.Stat(filepath.Join(dir, name)); err == nil && info.Mode().IsRegular() {
				return true
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir || dir == cleanRoot || (parent != cleanRoot && !modelPathWithin(parent, cleanRoot)) {
			break
		}
		dir = parent
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

func (s *ContinuousDiscoveryService) modelArtifactOwner(path string, root modelScanRoot) string {
	if owner := boundedModelOwner(root.owner); owner != "" {
		return owner
	}
	switch strings.ToLower(strings.TrimSpace(root.provider)) {
	case "ollama":
		return "Ollama"
	case "lmstudio":
		return "LM Studio"
	case "lemonade":
		return "Lemonade"
	case "jan":
		return "Jan"
	case "gpt4all":
		return "GPT4All"
	case "anythingllm":
		return "AnythingLLM"
	}
	if owner := ownerFromMacOSModelScope(path, root.path, root.scope); owner != "" {
		return owner
	}
	ownershipRoots := root.macOSOwnershipRoots
	if ownershipRoots == nil {
		// Direct candidate callers do not pass through scan setup. Preserve their
		// owner inference without rebuilding these roots on the scan hot path.
		ownershipRoots = macOSLibraryModelScanRootsForHomes(s.homesToScan())
	}
	for _, scopedRoot := range ownershipRoots {
		if owner := ownerFromMacOSModelScope(path, scopedRoot.path, scopedRoot.scope); owner != "" {
			return owner
		}
	}
	return ownerFromApplicationBundlePath(path)
}

func ownerFromMacOSModelScope(path, rootPath, scope string) string {
	if !isMacOSApplicationModelScope(scope) || scope == modelScanScopeAppResources {
		return ""
	}
	relative, err := filepath.Rel(filepath.Clean(rootPath), filepath.Clean(path))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return ""
	}
	parts := strings.Split(relative, string(os.PathSeparator))
	if len(parts) == 0 {
		return ""
	}
	ownerPart := parts[0]
	if len(parts) > 1 {
		switch strings.ToLower(ownerPart) {
		case "adobe", "cisco", "google", "microsoft":
			ownerPart = parts[1]
		}
	}
	return humanizeApplicationIdentifier(ownerPart)
}

func ownerFromApplicationBundlePath(path string) string {
	for _, part := range strings.Split(filepath.ToSlash(filepath.Clean(path)), "/") {
		if strings.HasSuffix(strings.ToLower(part), ".app") {
			return humanizeApplicationIdentifier(strings.TrimSuffix(part, filepath.Ext(part)))
		}
	}
	return ""
}

func humanizeApplicationIdentifier(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasSuffix(strings.ToLower(value), ".app") {
		value = strings.TrimSuffix(value, filepath.Ext(value))
	}
	if value == "" {
		return ""
	}
	selected := value
	if strings.Contains(value, ".") {
		generic := map[string]bool{
			"ai": true, "app": true, "application": true, "cache": true, "caches": true,
			"com": true, "container": true, "desktop": true, "group": true, "helper": true,
			"mac": true, "macos": true, "net": true, "org": true, "shared": true,
		}
		parts := strings.Split(value, ".")
		for i := len(parts) - 1; i >= 0; i-- {
			part := strings.TrimSpace(parts[i])
			if part != "" && !generic[strings.ToLower(part)] {
				selected = part
				break
			}
		}
	}
	selected = strings.Join(strings.Fields(strings.NewReplacer("_", " ", "-", " ").Replace(selected)), " ")
	runes := []rune(selected)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return boundedModelOwner(string(runes))
}

func boundedModelOwner(value string) string {
	value = strings.NewReplacer("/", " ", "\\", " ").Replace(value)
	value = strings.Join(strings.Fields(boundedLocalModelField(value, maxLocalModelProviderBytes)), " ")
	if value == "." || value == ".." {
		return ""
	}
	return value
}

func inferModelArtifactModality(path string, root modelScanRoot, id, format string) string {
	primary := strings.ToLower(id + " " + filepath.Base(path))
	if modality := modelModalityFromSemanticText(primary); modality != localModelModalityUnknown {
		return modality
	}
	relative := path
	if value, err := filepath.Rel(root.path, path); err == nil {
		relative = value
	}
	if modality := modelModalityFromSemanticText(strings.ToLower(relative)); modality != localModelModalityUnknown {
		return modality
	}
	switch format {
	case "gguf", "ggml", "mlx", "q4nx", "ollama":
		return localModelModalityGenerative
	default:
		return localModelModalityUnknown
	}
}

func modelModalityFromSemanticText(value string) string {
	containsAny := func(tokens ...string) bool {
		for _, token := range tokens {
			if strings.Contains(value, token) {
				return true
			}
		}
		return false
	}
	if containsAny("whisper", "parakeet", "speech", "transcrib", "asr", "diar", "speaker", "moonshine", "sensevoice") {
		return localModelModalitySpeech
	}
	if containsAny("embedding", "sentence-transform", "rerank", "text-encoder", "text_encoder", "bge-", "e5-", "clip") {
		return localModelModalityEmbedding
	}
	if containsAny("vision", "image", "yolo", "object-detect", "object_detect", "segment", "depth", "ocr", "face-detect", "face_detect") {
		return localModelModalityVision
	}
	if containsAny("vad", "silero", "wav2vec", "encodec", "audio", "voice-activity", "voice_activity", "music") {
		return localModelModalityAudio
	}
	if containsAny("llama", "qwen", "mistral", "gemma", "deepseek", "phi-", "phi_", "instruct", "chat", "text-generation", "text_generation", "language-model", "language_model") {
		return localModelModalityGenerative
	}
	return localModelModalityUnknown
}

func inferModelArtifactRelevance(path string, root modelScanRoot, owner, modality string) string {
	if root.scope == modelScanScopeAppResources || root.scope == modelScanScopeCache ||
		embeddedModelOwner(owner) || embeddedModelArtifactPath(path, root) {
		return localModelRelevanceEmbedded
	}
	if modality == localModelModalityGenerative {
		return localModelRelevancePrimary
	}
	if modality != "" && modality != localModelModalityUnknown {
		return localModelRelevanceSupporting
	}
	if root.specialized && strongModelFileContext(path, root) {
		return localModelRelevancePrimary
	}
	return localModelRelevanceUnknown
}

func embeddedModelArtifactPath(path string, root modelScanRoot) bool {
	relative := path
	if value, err := filepath.Rel(root.path, path); err == nil {
		relative = value
	}
	lower := strings.ToLower(filepath.ToSlash(relative))
	for _, token := range []string{"/chrome/", "/chromium/", "/edge/", "/firefox/", "/safari/", "/webex/", "/zoom/", "/teams/", "/slack/", "/discord/"} {
		if strings.Contains("/"+lower+"/", token) {
			return true
		}
	}
	return false
}

func embeddedModelOwner(owner string) bool {
	for _, word := range strings.FieldsFunc(strings.ToLower(owner), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r)
	}) {
		switch word {
		case "chrome", "chromium", "edge", "firefox", "safari", "webex", "zoom", "teams", "slack", "discord":
			return true
		}
	}
	return false
}

func modelArtifactDiscoveryConfidence(path string, root modelScanRoot, format string) float64 {
	if root.specialized {
		return 0.98
	}
	if isHighSignalModelFormat(format) {
		if strongModelFileContext(path, root) || semanticModelArtifactName(path) || hasModelMetadataSidecar(path, root) {
			return 0.95
		}
		return 0.9
	}
	if hasModelMetadataSidecar(path, root) {
		return 0.88
	}
	if strongModelFileContext(path, root) {
		return 0.84
	}
	return 0.8
}

func isHighSignalModelFormat(format string) bool {
	switch format {
	case "gguf", "ggml", "safetensors", "mlx", "coreml", "q4nx", "ollama":
		return true
	default:
		return false
	}
}

func modelArtifactMatchKind(format string) string {
	if isHighSignalModelFormat(format) {
		return MatchKindExact
	}
	return MatchKindHeuristic
}

func validLocalModelModality(value string) bool {
	switch value {
	case localModelModalityGenerative, localModelModalitySpeech, localModelModalityVision,
		localModelModalityEmbedding, localModelModalityAudio, localModelModalityUnknown:
		return true
	default:
		return false
	}
}

func validLocalModelRelevance(value string) bool {
	switch value {
	case localModelRelevancePrimary, localModelRelevanceSupporting, localModelRelevanceEmbedded,
		localModelRelevanceUnknown:
		return true
	default:
		return false
	}
}

func modelModalityPriority(value string) int {
	switch value {
	case localModelModalityGenerative:
		return 6
	case localModelModalitySpeech:
		return 5
	case localModelModalityAudio:
		return 4
	case localModelModalityVision:
		return 3
	case localModelModalityEmbedding:
		return 2
	case localModelModalityUnknown:
		return 1
	default:
		return 0
	}
}

func modelRelevancePriority(value string) int {
	switch value {
	case localModelRelevanceEmbedded:
		return 4
	case localModelRelevancePrimary:
		return 3
	case localModelRelevanceSupporting:
		return 2
	case localModelRelevanceUnknown:
		return 1
	default:
		return 0
	}
}

type modelArtifactIdentity struct {
	id          string
	key         string
	provider    string
	format      string
	hfDirectory string
	trusted     bool
}

// deriveModelArtifactIdentity is the single identity policy used by both
// ambiguous-format admission and emitted candidates. The branch order is
// significant: a configured (non-specialized) Hugging Face cache must retain
// its repository identity instead of being reduced to a snapshot revision or
// generic model basename.
func deriveModelArtifactIdentity(
	path string,
	root modelScanRoot,
	format string,
	directory bool,
	explicitID string,
) (modelArtifactIdentity, bool) {
	identity := modelArtifactIdentity{
		id: explicitID, provider: root.provider, format: format,
	}
	if hfDir, hfID, ok := huggingFaceModelIdentity(path); ok {
		identity.id = hfID
		identity.key = "huggingface:" + hfDir
		identity.provider = "huggingface"
		identity.hfDirectory = hfDir
		identity.trusted = true
		if strings.HasPrefix(strings.ToLower(hfID), "mlx-community/") {
			identity.format = "mlx"
			identity.provider = "mlx"
		}
	} else if explicitID != "" {
		identity.key = "ollama-manifest:" + path
		identity.provider = "ollama"
	} else if format == "mlx" || shouldAggregateWeightShards(path) {
		identity.id = filepath.Base(filepath.Dir(path))
		identity.key = "model-dir:" + filepath.Dir(path) + ":" + format
		if format == "mlx" {
			identity.provider = "mlx"
		}
	} else if genericModelArtifactStem(path) {
		parentDir := filepath.Dir(path)
		parent := filepath.Base(parentDir)
		if filepath.Clean(parentDir) != filepath.Clean(root.path) && !genericModelDirectoryName(parent) {
			identity.id = parent
			identity.key = "model-dir:" + parentDir + ":" + format
		} else {
			identity.id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			identity.key = "model-file:" + path
		}
	} else {
		identity.id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		identity.key = "model-file:" + path
	}
	if directory {
		identity.id = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		identity.key = "model-dir:" + path + ":" + identity.format
	}
	return identity, identity.id != ""
}

func (s *ContinuousDiscoveryService) modelArtifactCandidate(
	path string,
	root modelScanRoot,
	format string,
	directory bool,
	explicitID string,
	admittedIdentity *modelArtifactIdentity,
) (modelFileAggregate, bool) {
	// Follows cache snapshot symlinks. Weight tensors are never read; a bounded
	// metadata prefix may be opened for self-describing containers such as GGUF.
	info, err := os.Stat(path)
	if err != nil || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return modelFileAggregate{}, false
	}
	artifactKey := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		artifactKey = filepath.Clean(resolved)
	}
	identity := modelArtifactIdentity{}
	if admittedIdentity != nil {
		identity = *admittedIdentity
	} else {
		var ok bool
		identity, ok = deriveModelArtifactIdentity(path, root, format, directory, explicitID)
		if !ok {
			return modelFileAggregate{}, false
		}
	}
	id, key, provider := identity.id, identity.key, identity.provider
	format = identity.format
	provenance := modelProvenanceHints{}
	if identity.hfDirectory != "" {
		provenance.References = []string{id}
		provenance.HuggingFaceRepoIDs = []string{id}
		provenance.Source = "hf_cache"
	}
	if !directory {
		provenance = mergeModelProvenanceHints(provenance, modelArtifactProvenanceHints(path, format))
	}
	ownerRoot := root
	ownerRoot.provider = provider
	owner := s.modelArtifactOwner(path, ownerRoot)
	modality := inferModelArtifactModality(path, root, id, format)
	relevance := inferModelArtifactRelevance(path, root, owner, modality)
	discoveryConfidence := modelArtifactDiscoveryConfidence(path, root, format)
	workspaceHash := hashPath(root.path)
	metadata := fmt.Sprintf("%s|%d|%d", format, info.Size(), info.ModTime().UTC().UnixNano())
	evidence := AIEvidence{
		Type:          "model_file",
		Basename:      filepath.Base(path),
		PathHash:      hashPath(path),
		ValueHash:     hashValue(metadata),
		WorkspaceHash: workspaceHash,
		Quality:       discoveryConfidence,
		MatchKind:     modelArtifactMatchKind(format),
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
		owner: owner, modality: modality, relevance: relevance, confidence: discoveryConfidence,
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
		provider: "ollama", evidence: []AIEvidence{evidence}, owner: "Ollama",
		modality: localModelModalityUnknown, relevance: localModelRelevanceUnknown, confidence: 0.8,
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
			OwnerApplication: candidate.owner, Modality: candidate.modality,
			Relevance: candidate.relevance, DiscoveryConfidence: modelDiscoveryConfidence(candidate.confidence),
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

func modelDiscoveryConfidence(value float64) *float64 {
	return &value
}

func modelArtifactAggregateEntryHash(candidate modelFileAggregate) string {
	parts := []string{
		candidate.artifactKey, candidate.format, candidate.owner, candidate.modality,
		candidate.relevance, fmt.Sprintf("%.4f", candidate.confidence),
	}
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
