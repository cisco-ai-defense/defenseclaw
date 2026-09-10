// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
)

// NormalizationManifest is the value-free adapter record emitted beside a
// normalized public corpus. It records exclusions and deduplication without
// embedding downloaded source values.
type NormalizationManifest struct {
	SchemaVersion          string                    `json:"schema_version"`
	Datasets               []string                  `json:"datasets"`
	Cases                  int                       `json:"cases"`
	Counts                 map[string]int            `json:"counts"`
	ExactPayloadDuplicates int                       `json:"exact_payload_duplicates_removed"`
	LabelConflictsExcluded int                       `json:"label_conflicts_excluded"`
	AdapterStatistics      map[string]map[string]int `json:"adapter_statistics"`
	OutputSHA256           string                    `json:"output_sha256"`
	Partition              *PartitionMetadata        `json:"partition,omitempty"`
}

type PartitionMetadata struct {
	Strategy                  string         `json:"strategy"`
	Seed                      int64          `json:"seed"`
	SourceCorpusSHA256        string         `json:"source_corpus_sha256"`
	SourceNormalizationSHA256 string         `json:"source_normalization_sha256"`
	Split                     string         `json:"split"`
	Ratios                    map[string]int `json:"ratios"`
	SplitGroupCount           int            `json:"split_group_count"`
	AssignmentSHA256          string         `json:"assignment_sha256"`
}

// CorpusManifest is included in every benchmark result bundle. The optional
// normalization record is present for public downloaded corpora and absent for
// the checked-in smoke fixture.
type CorpusManifest struct {
	SchemaVersion       string                 `json:"schema_version"`
	CorpusSHA256        string                 `json:"corpus_sha256"`
	TruthCorpusSHA256   string                 `json:"truth_corpus_sha256,omitempty"`
	Cases               int                    `json:"cases"`
	DatasetCounts       map[string]int         `json:"dataset_counts"`
	SurfaceCounts       map[string]int         `json:"surface_counts"`
	SplitCounts         map[string]int         `json:"split_counts"`
	SourceTruthCounts   map[string]int         `json:"source_truth_counts"`
	ApplicabilityCounts map[string]int         `json:"applicability_counts"`
	DispositionCounts   map[string]int         `json:"disposition_counts"`
	SplitGroupCounts    map[string]int         `json:"split_group_counts,omitempty"`
	Normalization       *NormalizationManifest `json:"normalization,omitempty"`
}

func BuildCorpusManifest(cases []Case, corpusSHA256 string, normalizationData []byte) (CorpusManifest, error) {
	return buildCorpusManifest(cases, cases, corpusSHA256, "", normalizationData)
}

// BuildCorpusManifestWithTruth binds an independently labeled truth overlay
// while retaining the normalized corpus digest used for detector evaluation.
func BuildCorpusManifestWithTruth(
	sourceCases, truthCases []Case,
	corpusSHA256, truthCorpusSHA256 string,
	normalizationData []byte,
) (CorpusManifest, error) {
	if err := ValidateTruthOverlay(sourceCases, truthCases); err != nil {
		return CorpusManifest{}, err
	}
	if !validSHA256(truthCorpusSHA256) {
		return CorpusManifest{}, fmt.Errorf("truth corpus has an invalid digest")
	}
	return buildCorpusManifest(sourceCases, truthCases, corpusSHA256, truthCorpusSHA256, normalizationData)
}

// ValidateTruthOverlay requires a row-for-row copy of the evaluated corpus in
// which only the Truth field may differ. This prevents labels from changing
// detector inputs, provenance, splits, or strata after predictions are frozen.
func ValidateTruthOverlay(sourceCases, truthCases []Case) error {
	if len(sourceCases) != len(truthCases) {
		return fmt.Errorf("truth overlay case count differs from evaluated corpus")
	}
	for index := range sourceCases {
		sourceCase := sourceCases[index]
		truthCase := truthCases[index]
		if sourceCase.ID != truthCase.ID {
			return fmt.Errorf("truth overlay case %d has ID %q, want %q", index, truthCase.ID, sourceCase.ID)
		}
		truthCase.Truth = sourceCase.Truth
		if !reflect.DeepEqual(sourceCase, truthCase) {
			return fmt.Errorf("truth overlay changes non-truth fields for case %q", sourceCase.ID)
		}
	}
	return nil
}

func buildCorpusManifest(
	sourceCases, truthCases []Case,
	corpusSHA256, truthCorpusSHA256 string,
	normalizationData []byte,
) (CorpusManifest, error) {
	manifest := CorpusManifest{
		SchemaVersion:       SchemaVersion,
		CorpusSHA256:        corpusSHA256,
		TruthCorpusSHA256:   truthCorpusSHA256,
		Cases:               len(sourceCases),
		DatasetCounts:       make(map[string]int),
		SurfaceCounts:       make(map[string]int),
		SplitCounts:         make(map[string]int),
		SourceTruthCounts:   make(map[string]int),
		ApplicabilityCounts: make(map[string]int),
		DispositionCounts:   make(map[string]int),
		SplitGroupCounts:    make(map[string]int),
	}
	groupSplits := make(map[string]string)
	groupedCases := 0
	for _, benchmarkCase := range truthCases {
		manifest.DatasetCounts[benchmarkCase.Source.Dataset]++
		manifest.SurfaceCounts[benchmarkCase.Surface]++
		manifest.SplitCounts[benchmarkCase.Split]++
		manifest.SourceTruthCounts[benchmarkCase.Truth.SourceTruth]++
		manifest.ApplicabilityCounts[benchmarkCase.Truth.Applicability]++
		manifest.DispositionCounts[benchmarkCase.Truth.ExpectedDisposition]++
	}
	for _, benchmarkCase := range sourceCases {
		if benchmarkCase.Strata.SplitGroup != "" {
			groupedCases++
			if prior, exists := groupSplits[benchmarkCase.Strata.SplitGroup]; exists && prior != benchmarkCase.Split {
				return CorpusManifest{}, fmt.Errorf(
					"split group %s appears in both %s and %s",
					benchmarkCase.Strata.SplitGroup,
					prior,
					benchmarkCase.Split,
				)
			}
			groupSplits[benchmarkCase.Strata.SplitGroup] = benchmarkCase.Split
		}
	}
	for _, split := range groupSplits {
		manifest.SplitGroupCounts[split]++
	}
	if len(groupSplits) == 0 {
		manifest.SplitGroupCounts = nil
	}
	if len(normalizationData) == 0 {
		return manifest, nil
	}
	var normalized NormalizationManifest
	decoder := json.NewDecoder(io.LimitReader(bytes.NewReader(normalizationData), 4<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&normalized); err != nil {
		return CorpusManifest{}, fmt.Errorf("decode normalization manifest: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return CorpusManifest{}, fmt.Errorf("decode normalization manifest: %w", err)
	}
	if normalized.SchemaVersion != SchemaVersion || normalized.OutputSHA256 != corpusSHA256 || normalized.Cases != len(sourceCases) {
		return CorpusManifest{}, fmt.Errorf("normalization manifest identity differs from corpus")
	}
	datasets := make([]string, 0, len(manifest.DatasetCounts))
	for dataset := range manifest.DatasetCounts {
		datasets = append(datasets, dataset)
	}
	sort.Strings(datasets)
	if !equalStrings(datasets, normalized.Datasets) {
		return CorpusManifest{}, fmt.Errorf("normalization manifest dataset list differs from corpus")
	}
	if !equalCounts(manifest.DatasetCounts, normalized.Counts) {
		return CorpusManifest{}, fmt.Errorf("normalization manifest counts differ from corpus")
	}
	if normalized.Partition != nil {
		partition := normalized.Partition
		if partition.Strategy != "adapter-group-balanced-v1" ||
			partition.Split == "" ||
			manifest.SplitCounts[partition.Split] != len(sourceCases) ||
			len(manifest.SplitCounts) != 1 {
			return CorpusManifest{}, fmt.Errorf("partition metadata differs from corpus splits")
		}
		if partition.SplitGroupCount != manifest.SplitGroupCounts[partition.Split] ||
			partition.SplitGroupCount == 0 ||
			len(groupSplits) != partition.SplitGroupCount ||
			groupedCases != len(sourceCases) {
			return CorpusManifest{}, fmt.Errorf("partition split-group count differs from corpus")
		}
		if !validSHA256(partition.SourceCorpusSHA256) ||
			!validSHA256(partition.SourceNormalizationSHA256) ||
			!validSHA256(partition.AssignmentSHA256) {
			return CorpusManifest{}, fmt.Errorf("partition metadata has an invalid digest")
		}
		if len(partition.Ratios) != 3 ||
			partition.Ratios["development"] <= 0 ||
			partition.Ratios["validation"] <= 0 ||
			partition.Ratios["test"] <= 0 ||
			partition.Ratios["development"]+partition.Ratios["validation"]+partition.Ratios["test"] != 100 {
			return CorpusManifest{}, fmt.Errorf("partition metadata has invalid ratios")
		}
	}
	manifest.Normalization = &normalized
	return manifest, nil
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalCounts(left, right map[string]int) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
