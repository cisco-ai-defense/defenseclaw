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
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const (
	modelProvenanceCatalogVersion = 1
	maxModelPublisherBytes        = 128
	maxModelRootBytes             = maxLocalModelIDBytes
	maxModelBaseModels            = 8
	maxModelQuantizationBytes     = 64
	maxModelDerivationBytes       = 64
	maxModelProvenanceSourceBytes = 64
)

//go:embed model_provenance.json
var embeddedModelProvenanceCatalog []byte

type modelPublisherRule struct {
	ID                  string   `json:"id"`
	Publisher           string   `json:"publisher"`
	CountryCode         string   `json:"country_code"`
	CanonicalNamespace  string   `json:"canonical_namespace"`
	Namespaces          []string `json:"namespaces"`
	OrganizationAliases []string `json:"organization_aliases"`
	FamilyTokens        []string `json:"family_tokens"`
	SourceURL           string   `json:"source_url"`
}

type modelLineageRule struct {
	ID          string   `json:"id"`
	Match       string   `json:"match"`
	Publisher   string   `json:"publisher"`
	CountryCode string   `json:"country_code"`
	RootModel   string   `json:"root_model"`
	BaseModels  []string `json:"base_models"`
	Distilled   bool     `json:"distilled"`
	SourceURL   string   `json:"source_url"`
}

type modelProvenanceCatalog struct {
	Version    int                  `json:"version"`
	Publishers []modelPublisherRule `json:"publishers"`
	Lineages   []modelLineageRule   `json:"lineages"`
}

// modelProvenanceHints contains bounded metadata obtained without inference
// or network access. It is deliberately internal: only normalized provenance
// claims are exposed in LocalModelInfo.
type modelProvenanceHints struct {
	References        []string
	Organizations     []string
	BaseOrganizations []string
	BaseModels        []string
	// HuggingFaceRepoIDs are exact IDs observed on a trusted local metadata
	// surface. Keep this separate from References: References also contains
	// family/name hints that are useful offline but unsafe as network queries.
	HuggingFaceRepoIDs []string
	Quantization       string
	Quantized          *bool
	Distilled          *bool
	Source             string
}

var (
	modelProvenanceOnce       sync.Once
	modelProvenanceBuiltin    modelProvenanceCatalog
	modelProvenanceBuiltinErr error
	quantizationTokenPattern  = regexp.MustCompile(`(?i)(^|[^a-z0-9])(iq[1-4](?:_[a-z0-9]+)*|q[2-8](?:_[a-z0-9]+)*|[2-8](?:\.[0-9]+)?bpw|awq|gptq|exl[23]|nf4|int[48]|[48]bit|fp8|nvfp4|mxfp[48]|w4a16|w8a8)($|[^a-z0-9])`)
	distillationTokenPattern  = regexp.MustCompile(`(?i)(^|[^a-z0-9])distill(?:ed|ation)?($|[^a-z0-9])`)
	mergeTokenPattern         = regexp.MustCompile(`(?i)(^|[^a-z0-9])(frankenmerge|mergekit|merged|merge)($|[^a-z0-9])`)
)

func loadModelProvenanceCatalog() (modelProvenanceCatalog, error) {
	modelProvenanceOnce.Do(func() {
		var catalog modelProvenanceCatalog
		if err := json.Unmarshal(embeddedModelProvenanceCatalog, &catalog); err != nil {
			modelProvenanceBuiltinErr = fmt.Errorf("model provenance catalog: decode: %w", err)
			return
		}
		if err := validateModelProvenanceCatalog(catalog); err != nil {
			modelProvenanceBuiltinErr = err
			return
		}
		modelProvenanceBuiltin = catalog
	})
	return modelProvenanceBuiltin, modelProvenanceBuiltinErr
}

func validateModelProvenanceCatalog(catalog modelProvenanceCatalog) error {
	if catalog.Version != modelProvenanceCatalogVersion {
		return fmt.Errorf("model provenance catalog: version %d is unsupported", catalog.Version)
	}
	seen := make(map[string]bool)
	for _, rule := range catalog.Publishers {
		if rule.ID == "" || seen[rule.ID] {
			return fmt.Errorf("model provenance catalog: missing or duplicate publisher id %q", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Publisher == "" || len(rule.Publisher) > maxModelPublisherBytes ||
			!isValidModelCountryCode(rule.CountryCode) || rule.CanonicalNamespace == "" ||
			len(rule.Namespaces) == 0 || len(rule.FamilyTokens) == 0 || !isHTTPSURL(rule.SourceURL) {
			return fmt.Errorf("model provenance catalog: invalid publisher rule %q", rule.ID)
		}
	}
	seen = make(map[string]bool)
	for _, rule := range catalog.Lineages {
		if rule.ID == "" || seen[rule.ID] || rule.Match == "" || rule.RootModel == "" ||
			len(rule.RootModel) > maxModelRootBytes || len(rule.BaseModels) > maxModelBaseModels ||
			rule.Publisher == "" || !isValidModelCountryCode(rule.CountryCode) || !isHTTPSURL(rule.SourceURL) {
			return fmt.Errorf("model provenance catalog: invalid lineage rule %q", rule.ID)
		}
		seen[rule.ID] = true
		for _, base := range rule.BaseModels {
			if _, ok := safeLocalModelID(base); !ok {
				return fmt.Errorf("model provenance catalog: invalid base model in %q", rule.ID)
			}
		}
	}
	return nil
}

func isHTTPSURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && strings.EqualFold(u.Scheme, "https") && u.Hostname() != ""
}

// isValidModelCountryCode intentionally accepts only countries represented
// by the embedded, reviewed catalog. Adding a publisher therefore requires an
// explicit country review instead of silently accepting an arbitrary pair of
// letters from external reports.
func isValidModelCountryCode(value string) bool {
	switch value {
	case "AE", "CA", "CN", "DE", "FR", "GB", "US":
		return true
	default:
		return false
	}
}

func enrichLocalModelProvenance(model *LocalModelInfo, hints modelProvenanceHints) {
	if model == nil {
		return
	}
	if provenance := resolveLocalModelProvenance(*model, hints); provenance != nil {
		model.Provenance = provenance
	}
	model.huggingFaceRepoIDs = uniqueCredibleHuggingFaceRepoIDs(hints.HuggingFaceRepoIDs)
}

func checkpointProvenanceHints(checkpoint string) modelProvenanceHints {
	checkpoint = boundedLocalModelField(checkpoint, maxLocalModelIDBytes)
	if checkpoint == "" {
		return modelProvenanceHints{}
	}
	hints := modelProvenanceHints{References: []string{checkpoint}, Source: "checkpoint"}
	if repoID, ok := explicitHuggingFaceRepoID(checkpoint); ok {
		hints.HuggingFaceRepoIDs = []string{repoID}
	}
	return hints
}

func resolveLocalModelProvenance(model LocalModelInfo, hints modelProvenanceHints) *LocalModelProvenance {
	catalog, err := loadModelProvenanceCatalog()
	if err != nil {
		return nil
	}
	references := append([]string(nil), hints.References...)
	references = append(references, model.ID)
	references = uniqueBoundedModelReferences(references, maxModelBaseModels+4)
	baseModels := uniqueBoundedModelReferences(hints.BaseModels, maxModelBaseModels)
	ambiguousOrigin := len(baseModels) > 1 || referencesContainMergeMarker(references)

	provenance := &LocalModelProvenance{}
	confidence := ""
	lineageMatched := false
	if !ambiguousOrigin {
		for _, lineage := range catalog.Lineages {
			if lineageMatches(lineage.Match, references) {
				lineageMatched = true
				provenance.Publisher = lineage.Publisher
				provenance.CountryCode = lineage.CountryCode
				provenance.RootModel = lineage.RootModel
				provenance.BaseModels = append([]string(nil), lineage.BaseModels...)
				if lineage.Distilled {
					provenance.Distilled = modelBool(true)
				}
				provenance.Source = "catalog_exact"
				confidence = "high"
				break
			}
		}
	}

	rootReference := model.ID
	if ambiguousOrigin {
		// Explicit multi-parent metadata or a merge-marked artifact is not a
		// singular lineage claim. Preserve every known parent, but do not let an
		// exact-name rule or one family token invent a publisher, country, or root.
		provenance.BaseModels = append([]string(nil), baseModels...)
		rootReference = ""
	} else if lineageMatched {
		// Reviewed exact lineages are authoritative. Local metadata still adds
		// derivation/quantization evidence below, but cannot replace curated roots.
		rootReference = provenance.RootModel
	} else if len(baseModels) > 0 {
		provenance.BaseModels = append([]string(nil), baseModels...)
		rootReference = baseModels[0]
	} else if hints.Source != "ollama_metadata" && len(hints.References) > 0 {
		// GGUF source/base keys, a Lemonade checkpoint, or a model config can
		// recover identity after the artifact itself was renamed. Ollama's
		// `family`, by contrast, is intentionally coarse (for example qwen2),
		// so retain the more specific model tag as the displayed root.
		rootReference = hints.References[0]
	} else if rootReference == "" && len(references) > 0 {
		rootReference = references[0]
	}

	var matchedRule *modelPublisherRule
	matchScore := 0
	if !ambiguousOrigin {
		publisherBaseModels := baseModels
		if lineageMatched {
			publisherBaseModels = provenance.BaseModels
		}
		matchedRule, matchScore = bestPublisherRule(
			catalog.Publishers, references, hints.Organizations, hints.BaseOrganizations, publisherBaseModels,
		)
	}
	if ambiguousOrigin {
		// A merge can have unrelated roots. Preserve every immediate parent but
		// do not invent one publisher/country/root by selecting the first row.
		if len(baseModels) > 0 {
			provenance.Source = boundedProvenanceField(hints.Source, maxModelProvenanceSourceBytes)
			confidence = "medium"
		}
	}
	if matchedRule != nil {
		if provenance.Publisher == "" {
			provenance.Publisher = matchedRule.Publisher
			provenance.CountryCode = matchedRule.CountryCode
		}
		if provenance.RootModel == "" && rootReference != "" {
			provenance.RootModel = canonicalRootModel(rootReference, *matchedRule)
		}
		if confidence == "" {
			if matchScore >= 400 && (model.Provider == "huggingface" || strings.EqualFold(hints.Source, "hf_cache")) {
				confidence = "high"
			} else {
				confidence = "medium"
			}
		}
		if provenance.Source == "" {
			if hints.Source != "" {
				provenance.Source = boundedProvenanceField(hints.Source, maxModelProvenanceSourceBytes)
			} else if matchScore >= 400 {
				provenance.Source = "catalog_exact"
			} else {
				provenance.Source = "catalog_family"
			}
		}
	} else if provenance.RootModel == "" && rootReference != "" && len(baseModels) > 0 {
		provenance.RootModel = rootReference
		confidence = "medium"
		provenance.Source = boundedProvenanceField(hints.Source, maxModelProvenanceSourceBytes)
	}

	quantization := normalizeQuantization(hints.Quantization)
	quantized := hints.Quantized
	if quantization == "" {
		quantization = quantizationFromReferences(references)
	}
	if quantization != "" && quantized == nil {
		value := !isUnquantizedEncoding(quantization)
		quantized = &value
	}
	if quantized != nil {
		value := *quantized
		provenance.Quantized = &value
	}
	if quantization != "" {
		provenance.Quantization = boundedProvenanceField(quantization, maxModelQuantizationBytes)
	}

	distilled := hints.Distilled
	if distilled == nil && referencesContainDistillation(references) {
		distilled = modelBool(true)
	}
	if distilled != nil {
		value := *distilled
		provenance.Distilled = &value
	}
	provenance.Derivation = modelDerivation(provenance.Distilled, provenance.Quantized)

	if provenance.Source == "" && (provenance.Quantized != nil || provenance.Distilled != nil) {
		if hints.Source != "" {
			provenance.Source = boundedProvenanceField(hints.Source, maxModelProvenanceSourceBytes)
		} else {
			provenance.Source = "model_id"
		}
	}
	if confidence == "" && provenance.Source != "" {
		if hints.Source == "gguf_metadata" || hints.Source == "ollama_metadata" || hints.Source == "model_config" {
			confidence = "medium"
		} else {
			confidence = "low"
		}
	}
	provenance.Confidence = confidence
	normalizeLocalModelProvenance(provenance)
	if localModelProvenanceEmpty(provenance) {
		return nil
	}
	return provenance
}

func bestPublisherRule(
	rules []modelPublisherRule,
	references, organizations, baseOrganizations, baseModels []string,
) (*modelPublisherRule, int) {
	scores := make([]int, len(rules))
	for i := range rules {
		rule := &rules[i]
		for _, org := range organizations {
			for _, alias := range rule.OrganizationAliases {
				if strings.EqualFold(strings.TrimSpace(org), strings.TrimSpace(alias)) && scores[i] < 500 {
					scores[i] = 500
				}
			}
		}
		for _, org := range baseOrganizations {
			for _, alias := range rule.OrganizationAliases {
				if strings.EqualFold(strings.TrimSpace(org), strings.TrimSpace(alias)) && scores[i] < 650 {
					scores[i] = 650
				}
			}
		}
	}
	scoreReferences := func(values []string, namespaceScore, familyScore int) {
		for _, reference := range values {
			for i, score := range publisherReferenceScores(rules, reference, namespaceScore, familyScore) {
				if score > scores[i] {
					scores[i] = score
				}
			}
		}
	}
	// Explicit parent metadata outranks the derived artifact name. This is
	// what keeps a cross-family distillation or merge anchored to the root
	// weights rather than the uploader/teacher named in the derivative.
	scoreReferences(baseModels, 600, 300)
	scoreReferences(references, 400, 200)

	bestIndex, bestScore := -1, 0
	bestTied := false
	for i, score := range scores {
		if score > bestScore {
			bestIndex, bestScore, bestTied = i, score, false
		} else if score > 0 && score == bestScore {
			bestTied = true
		}
	}
	if bestIndex < 0 || bestTied {
		return nil, 0
	}
	return &rules[bestIndex], bestScore
}

// publisherReferenceScores resolves the identity evidence within one model
// reference before combining it with other metadata. A publisher namespace is
// authoritative when the basename is unknown or names that publisher's own
// family. When a publisher also uploads or quantizes a clearly named foreign
// family, the unique family token wins at family confidence. Competing family
// tokens deliberately produce no identity score.
func publisherReferenceScores(
	rules []modelPublisherRule, reference string, namespaceScore, familyScore int,
) []int {
	scores := make([]int, len(rules))
	owner, name := splitModelReference(reference)
	namespaceMatches := make([]int, 0, 1)
	familyMatches := make(map[int]int)
	for i, rule := range rules {
		for _, namespace := range rule.Namespaces {
			if owner != "" && strings.EqualFold(owner, namespace) {
				namespaceMatches = append(namespaceMatches, i)
				break
			}
		}
		for _, token := range rule.FamilyTokens {
			if containsModelToken(name, token) && familyScore+len(token) > familyMatches[i] {
				familyMatches[i] = familyScore + len(token)
			}
		}
	}

	// A namespace paired with its own family remains strong evidence even when
	// the derivative name also mentions a teacher or base family.
	ownFamilyMatch := -1
	for _, i := range namespaceMatches {
		if familyMatches[i] == 0 {
			continue
		}
		if ownFamilyMatch >= 0 {
			return scores
		}
		ownFamilyMatch = i
	}
	if ownFamilyMatch >= 0 {
		scores[ownFamilyMatch] = namespaceScore
		return scores
	}

	if len(familyMatches) == 1 {
		for i, score := range familyMatches {
			scores[i] = score
		}
		return scores
	}
	if len(familyMatches) > 1 {
		return scores
	}
	if len(namespaceMatches) == 1 {
		scores[namespaceMatches[0]] = namespaceScore
	}
	return scores
}

func lineageMatches(match string, references []string) bool {
	match = normalizeModelMatchText(match)
	if match == "" {
		return false
	}
	for _, reference := range references {
		if normalizedLineageContains(normalizeModelMatchText(reference), match) {
			return true
		}
	}
	return false
}

func normalizedLineageContains(value, match string) bool {
	for offset := 0; offset <= len(value)-len(match); {
		index := strings.Index(value[offset:], match)
		if index < 0 {
			return false
		}
		index += offset
		beforeOK := index == 0
		if !beforeOK {
			r, _ := utf8.DecodeLastRuneInString(value[:index])
			beforeOK = !isModelTokenRune(r)
		}
		after := index + len(match)
		afterOK := after == len(value)
		if !afterOK {
			r, _ := utf8.DecodeRuneInString(value[after:])
			afterOK = !isModelTokenRune(r)
		}
		if beforeOK && afterOK {
			return true
		}
		offset = index + 1
	}
	return false
}

func normalizeModelMatchText(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func splitModelReference(value string) (string, string) {
	value = modelReferenceFromURL(strings.TrimSpace(value))
	value = strings.TrimPrefix(value, "hf.co/")
	value = strings.TrimPrefix(value, "huggingface.co/")
	parts := strings.Split(strings.Trim(value, "/"), "/")
	for _, part := range parts {
		if !strings.HasPrefix(part, "models--") {
			continue
		}
		encoded := strings.TrimPrefix(part, "models--")
		pair := strings.SplitN(encoded, "--", 2)
		if len(pair) == 2 {
			if repoID, ok := credibleHuggingFaceRepoID(pair[0] + "/" + pair[1]); ok {
				return splitExactModelRepoID(repoID)
			}
		}
	}
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	if len(parts) > 2 {
		// An arbitrary filesystem path does not identify which adjacent pair is a
		// repository. Retain only its basename for offline family matching rather
		// than manufacturing a high-confidence namespace claim from path segments.
		return "", parts[len(parts)-1]
	}
	return "", value
}

func splitExactModelRepoID(repoID string) (string, string) {
	parts := strings.SplitN(repoID, "/", 2)
	if len(parts) != 2 {
		return "", repoID
	}
	return parts[0], parts[1]
}

func modelReferenceFromURL(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return value
	}
	if !strings.EqualFold(u.Hostname(), "huggingface.co") && !strings.EqualFold(u.Hostname(), "www.huggingface.co") {
		return value
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) < 2 {
		return value
	}
	owner, _ := url.PathUnescape(parts[0])
	name, _ := url.PathUnescape(parts[1])
	return owner + "/" + name
}

func containsModelToken(value, token string) bool {
	value = strings.ToLower(value)
	token = strings.ToLower(strings.TrimSpace(token))
	if value == "" || token == "" {
		return false
	}
	for start := 0; ; {
		index := strings.Index(value[start:], token)
		if index < 0 {
			return false
		}
		index += start
		beforeOK := index == 0 || !isModelTokenRune(rune(value[index-1]))
		after := index + len(token)
		// Family names conventionally attach their generation directly
		// (Qwen3, Llama3.1, Gemma2). A following digit is therefore a valid
		// boundary, while a following letter still rejects lookalikes such as
		// "qwench" or "llamazing".
		afterOK := after == len(value) || !unicode.IsLetter(rune(value[after]))
		if beforeOK && afterOK {
			return true
		}
		start = index + 1
	}
}

func isModelTokenRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

func canonicalRootModel(reference string, rule modelPublisherRule) string {
	owner, name := splitModelReference(reference)
	name = cleanDerivedModelName(name)
	if name == "" {
		return ""
	}
	canonicalOwner := rule.CanonicalNamespace
	for _, namespace := range rule.Namespaces {
		if strings.EqualFold(owner, namespace) {
			canonicalOwner = owner
			break
		}
	}
	root := name
	if canonicalOwner != "" {
		root = canonicalOwner + "/" + name
	}
	return boundedProvenanceField(root, maxModelRootBytes)
}

func cleanDerivedModelName(value string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	for _, ext := range []string{".safetensors", ".gguf", ".ggml", ".onnx", ".ort", ".bin"} {
		if strings.HasSuffix(lower, ext) {
			value = value[:len(value)-len(ext)]
			break
		}
	}
	if colon := strings.LastIndex(value, ":"); colon >= 0 {
		tag := value[colon+1:]
		if strings.EqualFold(tag, "latest") || quantizationFromReferences([]string{tag}) != "" {
			value = value[:colon]
		}
	}
	// Conversion/container and quantization suffixes appear in either order in
	// common community artifact names. Peel both until stable so a filename such
	// as `Llama-3.1-8B-GGUF-Q4_K_M.gguf` resolves to the weight family rather
	// than presenting the converted artifact name as its root.
	for {
		before := value
		for _, suffix := range []string{"-gguf", "_gguf", "-mlx", "_mlx", "-awq", "_awq", "-gptq", "_gptq", "-exl2", "_exl2"} {
			if strings.HasSuffix(strings.ToLower(value), suffix) {
				value = value[:len(value)-len(suffix)]
				break
			}
		}
		value = stripTrailingQuantizationToken(value)
		if value == before {
			break
		}
	}
	return strings.Trim(value, "-_. ")
}

func stripTrailingQuantizationToken(value string) string {
	for _, indexes := range quantizationTokenPattern.FindAllStringSubmatchIndex(value, -1) {
		// Submatch 2 is the quantization token itself. It is trailing only when
		// the third boundary submatch is the zero-width end-of-string branch.
		if len(indexes) >= 8 && indexes[4] >= 0 && indexes[5] == len(value) && indexes[6] == len(value) && indexes[7] == len(value) {
			return strings.TrimRight(value[:indexes[4]], "-_. ")
		}
	}
	return value
}

func quantizationFromReferences(references []string) string {
	for _, reference := range references {
		matches := quantizationTokenPattern.FindStringSubmatch(reference)
		if len(matches) >= 3 {
			return normalizeQuantization(matches[2])
		}
	}
	return ""
}

func normalizeQuantization(value string) string {
	value = boundedProvenanceField(value, maxModelQuantizationBytes)
	if value == "" {
		return ""
	}
	return strings.ToUpper(value)
}

func isUnquantizedEncoding(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "F32", "FP32", "F16", "FP16", "BF16":
		return true
	default:
		return false
	}
}

func referencesContainDistillation(references []string) bool {
	for _, reference := range references {
		if distillationTokenPattern.MatchString(reference) {
			return true
		}
	}
	return false
}

func referencesContainMergeMarker(references []string) bool {
	for _, reference := range references {
		if mergeTokenPattern.MatchString(reference) {
			return true
		}
	}
	return false
}

func modelDerivation(distilled, quantized *bool) string {
	parts := make([]string, 0, 2)
	if distilled != nil && *distilled {
		parts = append(parts, "distilled")
	}
	if quantized != nil && *quantized {
		parts = append(parts, "quantized")
	}
	return strings.Join(parts, "+")
}

func uniqueBoundedModelReferences(values []string, limit int) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, min(len(values), limit))
	for _, value := range values {
		value = modelReferenceFromURL(strings.TrimSpace(value))
		if safe, ok := safeLocalModelID(value); ok {
			value = safe
		} else {
			continue
		}
		key := strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, value)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func boundedProvenanceField(value string, maxBytes int) string {
	return boundedLocalModelField(value, maxBytes)
}

func normalizeLocalModelProvenance(provenance *LocalModelProvenance) {
	if provenance == nil {
		return
	}
	provenance.Publisher = boundedProvenanceField(provenance.Publisher, maxModelPublisherBytes)
	provenance.CountryCode = strings.ToUpper(strings.TrimSpace(provenance.CountryCode))
	if !isValidModelCountryCode(provenance.CountryCode) {
		provenance.CountryCode = ""
	}
	provenance.RootModel = boundedProvenanceField(provenance.RootModel, maxModelRootBytes)
	provenance.BaseModels = uniqueBoundedModelReferences(provenance.BaseModels, maxModelBaseModels)
	provenance.Quantization = boundedProvenanceField(provenance.Quantization, maxModelQuantizationBytes)
	provenance.Source = boundedProvenanceField(provenance.Source, maxModelProvenanceSourceBytes)
	switch provenance.Confidence {
	case "high", "medium", "low":
	default:
		provenance.Confidence = ""
	}
	if provenance.Quantization != "" && provenance.Quantized == nil {
		provenance.Quantized = modelBool(!isUnquantizedEncoding(provenance.Quantization))
	}
	provenance.Derivation = modelDerivation(provenance.Distilled, provenance.Quantized)
	sort.Strings(provenance.BaseModels)
}

func localModelProvenanceEmpty(provenance *LocalModelProvenance) bool {
	return provenance == nil || (provenance.Publisher == "" && provenance.CountryCode == "" &&
		provenance.RootModel == "" && len(provenance.BaseModels) == 0 && provenance.Quantized == nil &&
		provenance.Quantization == "" && provenance.Distilled == nil && provenance.Derivation == "")
}

func validateLocalModelProvenance(provenance *LocalModelProvenance) error {
	if provenance == nil {
		return nil
	}
	for field, rule := range map[string]struct {
		value string
		max   int
	}{
		"publisher":    {provenance.Publisher, maxModelPublisherBytes},
		"root_model":   {provenance.RootModel, maxModelRootBytes},
		"quantization": {provenance.Quantization, maxModelQuantizationBytes},
		"derivation":   {provenance.Derivation, maxModelDerivationBytes},
		"source":       {provenance.Source, maxModelProvenanceSourceBytes},
	} {
		if len(rule.value) > rule.max || containsUnicodeControl(rule.value) {
			return fmt.Errorf("model provenance %s must be at most %d printable characters", field, rule.max)
		}
	}
	if provenance.CountryCode != "" && !isValidModelCountryCode(provenance.CountryCode) {
		return errors.New("model provenance country_code is not a supported uppercase ISO alpha-2 code")
	}
	if provenance.CountryCode != "" && (provenance.Publisher == "" || provenance.RootModel == "") {
		return errors.New("model provenance country_code requires publisher and root_model")
	}
	if len(provenance.BaseModels) > maxModelBaseModels {
		return fmt.Errorf("model provenance base_models exceeds %d entries", maxModelBaseModels)
	}
	seenBases := make(map[string]bool)
	for _, base := range provenance.BaseModels {
		if strings.TrimSpace(base) == "" || len(base) > maxModelRootBytes || containsUnicodeControl(base) {
			return errors.New("model provenance base_models must contain printable model IDs")
		}
		key := strings.ToLower(base)
		if seenBases[key] {
			return errors.New("model provenance base_models must be unique")
		}
		seenBases[key] = true
	}
	if localModelProvenanceEmpty(provenance) || provenance.Source == "" || provenance.Confidence == "" {
		return errors.New("model provenance requires a claim, source, and confidence")
	}
	switch provenance.Source {
	case "catalog_exact", "catalog_family", "hf_cache", "gguf_metadata", "model_config",
		"ollama_metadata", "checkpoint", "model_id", "huggingface_hub", "mixed":
	default:
		return fmt.Errorf("unsupported model provenance source %q", provenance.Source)
	}
	switch provenance.Confidence {
	case "high", "medium", "low":
	default:
		return fmt.Errorf("unsupported model provenance confidence %q", provenance.Confidence)
	}
	if expected := modelDerivation(provenance.Distilled, provenance.Quantized); provenance.Derivation != expected {
		return errors.New("model provenance derivation is inconsistent with quantized/distilled")
	}
	return nil
}

func modelBool(value bool) *bool { return &value }
