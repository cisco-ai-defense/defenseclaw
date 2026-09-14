// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/benchmarks/internal/benchmark"
)

func TestBinaryVCSSettings(t *testing.T) {
	revision, modified := binaryVCSSettings([]debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef"},
		{Key: "vcs.modified", Value: "false"},
	})
	if revision != "0123456789abcdef" || modified == nil || *modified {
		t.Fatalf("binary VCS state = revision %q modified %v", revision, modified)
	}

	revision, modified = binaryVCSSettings(nil)
	if revision != "" || modified != nil {
		t.Fatalf("unknown binary VCS state = revision %q modified %v", revision, modified)
	}

	revision, modified = linkedBinaryVCS("abcdefabcdefabcdefabcdefabcdefabcdefabcd", "false")
	if revision != "abcdefabcdefabcdefabcdefabcdefabcdefabcd" || modified == nil || *modified {
		t.Fatalf("linked binary VCS state = revision %q modified %v", revision, modified)
	}
}

func TestValidateRunBinaryProvenance(t *testing.T) {
	clean := false
	dirty := true
	tests := []struct {
		name           string
		commit         string
		repoDirty      bool
		binaryRevision string
		binaryModified *bool
		wantError      bool
	}{
		{name: "match", commit: "0123456789abcdef0123456789abcdef01234567", binaryRevision: "0123456789abcdef0123456789abcdef01234567", binaryModified: &clean},
		{name: "mismatch", commit: "0123456789abcdef0123456789abcdef01234567", binaryRevision: "fedcba9876543210fedcba9876543210fedcba98", binaryModified: &clean, wantError: true},
		{name: "unknown binary revision", commit: "0123456789abcdef0123456789abcdef01234567", binaryModified: &clean, wantError: true},
		{name: "unknown modified state", commit: "0123456789abcdef0123456789abcdef01234567", binaryRevision: "0123456789abcdef0123456789abcdef01234567", wantError: true},
		{name: "dirty binary", commit: "0123456789abcdef0123456789abcdef01234567", binaryRevision: "0123456789abcdef0123456789abcdef01234567", binaryModified: &dirty, wantError: true},
		{name: "dirty repository", commit: "0123456789abcdef0123456789abcdef01234567", repoDirty: true, binaryRevision: "0123456789abcdef0123456789abcdef01234567", binaryModified: &clean, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateRunBinaryProvenance(test.commit, test.repoDirty, test.binaryRevision, test.binaryModified)
			if (err != nil) != test.wantError {
				t.Fatalf("validateRunBinaryProvenance() error = %v, want error %v", err, test.wantError)
			}
		})
	}
}

func TestVendoredFixturesPassStrictNormalizationGate(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", ".."))
	lockPath := filepath.Join(repoRoot, "benchmarks", "datasets.lock.json")
	fixtureNames := []string{
		"smoke",
		"cloud-production-conformance-v1",
		"database-destruction-conformance-v1",
		"kubernetes-production-conformance-v1",
		"infrastructure-destruction-conformance-v1",
		"postgresql-copy-program-v1",
		"sql-command-udf-atomic-v1",
	}
	for _, fixtureName := range fixtureNames {
		t.Run(fixtureName, func(t *testing.T) {
			corpusPath := filepath.Join(repoRoot, "benchmarks", "fixtures", fixtureName+".jsonl")
			corpusSHA256, cases, _, _, err := loadInputs(corpusPath, lockPath)
			if err != nil {
				t.Fatal(err)
			}
			normalizationData, err := readNormalizationManifest("", corpusPath)
			if err != nil {
				t.Fatal(err)
			}
			if len(normalizationData) == 0 {
				t.Fatal("strict normalization sidecar was not loaded")
			}
			manifest, err := benchmark.BuildCorpusManifest(cases, corpusSHA256, normalizationData)
			if err != nil {
				t.Fatal(err)
			}
			if manifest.Normalization == nil || manifest.Normalization.Source == nil {
				t.Fatal("strict normalization source authority was not preserved")
			}
			wantPath := filepath.ToSlash(filepath.Join("benchmarks", "fixtures", fixtureName+".jsonl"))
			if manifest.Normalization.Source.Path != wantPath {
				t.Fatalf("normalization source path = %q, want %q", manifest.Normalization.Source.Path, wantPath)
			}
		})
	}
}

func TestRunBenchmarkRejectsBinaryProvenanceBeforeLoadingCorpus(t *testing.T) {
	commit := "0123456789abcdef0123456789abcdef01234567"
	clean := false
	previousGitState := gitStateForRun
	previousBinaryVCS := runningBinaryVCSForRun
	gitStateForRun = func(string) (string, bool) { return commit, false }
	runningBinaryVCSForRun = func() (string, *bool) {
		return "fedcba9876543210fedcba9876543210fedcba98", &clean
	}
	t.Cleanup(func() {
		gitStateForRun = previousGitState
		runningBinaryVCSForRun = previousBinaryVCS
	})

	err := runBenchmark([]string{
		"--repo-root", t.TempDir(),
		"--corpus", filepath.Join(t.TempDir(), "must-not-be-opened.jsonl"),
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "differs from selected clean repository commit") {
		t.Fatalf("runBenchmark() error = %v, want pre-input binary revision mismatch", err)
	}
}

func stubRunBinaryProvenance(t *testing.T, repoRoot string) {
	t.Helper()
	commit, _ := gitState(repoRoot)
	clean := false
	previousGitState := gitStateForRun
	previousBinaryVCS := runningBinaryVCSForRun
	gitStateForRun = func(string) (string, bool) { return commit, false }
	runningBinaryVCSForRun = func() (string, *bool) { return commit, &clean }
	t.Cleanup(func() {
		gitStateForRun = previousGitState
		runningBinaryVCSForRun = previousBinaryVCS
	})
}

func TestValidateBenchmarkChecksStrictNormalizationManifest(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(repoRoot, "benchmarks", "fixtures", "smoke.jsonl")
	lockPath := filepath.Join(repoRoot, "benchmarks", "datasets.lock.json")
	corpusSHA256, cases, _, _, err := loadInputs(corpusPath, lockPath)
	if err != nil {
		t.Fatal(err)
	}
	counts := make(map[string]int)
	statistics := make(map[string]map[string]int)
	for _, benchmarkCase := range cases {
		counts[benchmarkCase.Source.Dataset]++
		statistics[benchmarkCase.Source.Dataset] = map[string]int{"projected_rows": counts[benchmarkCase.Source.Dataset]}
	}
	datasets := make([]string, 0, len(counts))
	for dataset := range counts {
		datasets = append(datasets, dataset)
	}
	sort.Strings(datasets)
	manifest := benchmark.NormalizationManifest{
		SchemaVersion:          benchmark.SchemaVersion,
		Datasets:               datasets,
		Cases:                  len(cases),
		Counts:                 counts,
		AdapterStatistics:      statistics,
		OutputSHA256:           corpusSHA256,
		ExactPayloadDuplicates: 0,
		LabelConflictsExcluded: 0,
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(t.TempDir(), "strict.manifest.json")
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := validateBenchmark([]string{
		"--corpus", corpusPath,
		"--dataset-lock", lockPath,
		"--normalization-manifest", manifestPath,
	}, &stdout); err != nil {
		t.Fatalf("strict normalization manifest rejected: %v", err)
	}

	var malformed map[string]any
	if err := json.Unmarshal(data, &malformed); err != nil {
		t.Fatal(err)
	}
	malformed["adapter_statistics"] = map[string]int{"projected_rows": len(cases)}
	data, err = json.Marshal(malformed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateBenchmark([]string{
		"--corpus", corpusPath,
		"--dataset-lock", lockPath,
		"--normalization-manifest", manifestPath,
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "adapter_statistics") {
		t.Fatalf("flat adapter statistics error = %v, want strict decode rejection", err)
	}
}

func TestCompareBenchmarkUsesTruthOverlay(t *testing.T) {
	dir := t.TempDir()
	sourceCase := benchmark.Case{
		SchemaVersion: benchmark.SchemaVersion,
		ID:            "test/contextual-command",
		Source: benchmark.Source{
			Dataset:        "test",
			Revision:       "1",
			OriginalID:     "contextual-command",
			License:        "Apache-2.0",
			Redistribution: "vendored",
		},
		Split:   "validation",
		Surface: "action",
		Payload: benchmark.Payload{Command: "example --dual-use"},
		Truth: benchmark.Truth{
			SourceTruth:         benchmark.TruthMalicious,
			Applicability:       benchmark.InScope,
			ExpectedDisposition: benchmark.DispositionDetectOnly,
		},
	}
	truthCase := sourceCase
	truthCase.Truth.DeterministicTruth = benchmark.DeterministicContextual
	truthCase.Truth.LabelConfidence = "high"
	truthCase.Truth.LabelSource = "test-review"

	baseline := benchmark.Prediction{
		SchemaVersion: benchmark.SchemaVersion,
		RunID:         "baseline",
		CaseID:        sourceCase.ID,
		Engine:        "command",
		Profile:       "default",
		Applicable:    true,
		Detected:      true,
		Action:        "alert",
		Severity:      "HIGH",
	}
	candidate := baseline
	candidate.RunID = "candidate"
	candidate.Detected = false
	candidate.Action = "allow"
	candidate.Severity = "NONE"

	corpusPath := writeJSONLForTest(t, dir, "corpus.jsonl", sourceCase)
	truthPath := writeJSONLForTest(t, dir, "truth.jsonl", truthCase)
	baselinePath := writeJSONLForTest(t, dir, "baseline.jsonl", baseline)
	candidatePath := writeJSONLForTest(t, dir, "candidate.jsonl", candidate)

	withoutTruth := runCompareForTest(t, corpusPath, "", baselinePath, candidatePath)
	if got := withoutTruth.Profiles[0].Changes.PositiveDetectionLosses; got != 1 {
		t.Fatalf("source-label positive losses=%d, want 1", got)
	}

	withTruth := runCompareForTest(t, corpusPath, truthPath, baselinePath, candidatePath)
	if got := withTruth.Profiles[0].Changes.PositiveDetectionLosses; got != 0 {
		t.Fatalf("truth-overlay positive losses=%d, want 0", got)
	}
	if withTruth.CorpusSHA256 == "" || withTruth.TruthCorpusSHA256 == "" {
		t.Fatal("comparison did not bind source and truth corpus digests")
	}
}

func TestRunBenchmarkEvaluatesRowsPromotedByTruthOverlay(t *testing.T) {
	dir := t.TempDir()
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	stubRunBinaryProvenance(t, repoRoot)
	sourceCase := benchmark.Case{
		SchemaVersion: benchmark.SchemaVersion,
		ID:            "test/promoted-command",
		Source: benchmark.Source{
			Dataset:        "defenseclaw-smoke",
			Revision:       "1",
			OriginalID:     "promoted-command",
			License:        "Apache-2.0",
			Redistribution: "vendored",
		},
		Split:   "development",
		Surface: "action",
		Payload: benchmark.Payload{ToolName: "shell", Command: "echo hello", Dialect: "posix"},
		Truth: benchmark.Truth{
			SourceTruth:         benchmark.TruthUnknown,
			Applicability:       benchmark.OutOfScope,
			ExpectedDisposition: benchmark.DispositionAllow,
			ExclusionReason:     "pending_review",
		},
	}
	truthCase := sourceCase
	truthCase.Truth = benchmark.Truth{
		SourceTruth:         benchmark.TruthUnknown,
		DeterministicTruth:  benchmark.DeterministicBenign,
		LabelConfidence:     "high",
		LabelSource:         "test-review",
		Applicability:       benchmark.InScope,
		ExpectedDisposition: benchmark.DispositionAllow,
	}
	corpusPath := writeJSONLForTest(t, dir, "corpus.jsonl", sourceCase)
	truthPath := writeJSONLForTest(t, dir, "truth.jsonl", truthCase)
	outputDir := filepath.Join(dir, "output")
	if err := runBenchmark([]string{
		"--corpus", corpusPath,
		"--truth-corpus", truthPath,
		"--dataset-lock", filepath.Join(repoRoot, "benchmarks", "datasets.lock.json"),
		"--repo-root", repoRoot,
		"--policy-root", filepath.Join(repoRoot, "policies", "guardrail"),
		"--profiles", "default",
		"--run-id", "truth-overlay-promotion-test",
		"--output", outputDir,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	predictions, err := readPredictions(filepath.Join(outputDir, "predictions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(predictions) != 1 {
		t.Fatalf("predictions=%d, want 1", len(predictions))
	}
	if !predictions[0].Applicable || predictions[0].Action == "not_applicable" {
		t.Fatalf("prediction=%+v, want evaluated in-scope row", predictions[0])
	}
	var environment benchmark.Environment
	environmentData, err := os.ReadFile(filepath.Join(outputDir, "environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(environmentData, &environment); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(environment.Profiles, []string{"default"}) ||
		environment.BinaryProvenanceVersion != benchmark.BinaryProvenanceSchemaVersion ||
		environment.BinaryVCSRevision == "" || environment.BinaryVCSModified == nil || *environment.BinaryVCSModified ||
		len(environment.OptInPolicyPacks) != 0 || environment.OptInPolicyRoot != "" ||
		len(environment.PolicyPostures) != 0 {
		t.Fatalf("standard-only environment changed: %+v", environment)
	}
}

func TestRunBenchmarkStrictTrajectoryAdapterManifests(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	stubRunBinaryProvenance(t, repoRoot)
	for _, test := range []struct {
		dataset          string
		adapter          string
		revision         string
		license          string
		trajectorySource bool
	}{
		{dataset: "AI-Secure/DTap-Bench-Agent-Trajectories", adapter: "dtap-agent-trajectories-v3", revision: "836caf2fdd78b888ddd14fb62dc038e932e17898", license: "Apache-2.0", trajectorySource: true},
		{dataset: "internlm/WildClawBench-Trajectories", adapter: "wildclawbench-result-authority-v2", revision: "d2816016a7a7b41fa6b7ba368b28ddafcb54fd93", license: "MIT"},
	} {
		t.Run(test.adapter, func(t *testing.T) {
			dir := t.TempDir()
			benchmarkCase := benchmark.Case{
				SchemaVersion: benchmark.SchemaVersion,
				ID:            test.adapter + "/case",
				Source: benchmark.Source{
					Dataset: test.dataset, Revision: test.revision, OriginalID: "case",
					License: test.license, Redistribution: "download-only",
				},
				Split:   "development",
				Surface: "action",
				Payload: benchmark.Payload{ToolName: "shell", Command: "echo safe", Dialect: "posix"},
				Truth: benchmark.Truth{
					SourceTruth: benchmark.TruthBenign, DeterministicTruth: benchmark.DeterministicBenign,
					LabelConfidence: "high", LabelSource: "source", Applicability: benchmark.InScope,
					ExpectedDisposition: benchmark.DispositionAllow,
				},
			}
			corpusPath := writeJSONLForTest(t, dir, "cases.jsonl", benchmarkCase)
			corpusData, err := os.ReadFile(corpusPath)
			if err != nil {
				t.Fatal(err)
			}
			manifest := benchmark.NormalizationManifest{
				SchemaVersion: benchmark.SchemaVersion, Datasets: []string{test.dataset}, Cases: 1,
				Counts: map[string]int{test.dataset: 1}, AdapterStatistics: map[string]map[string]int{test.adapter: {"cases": 1}},
				OutputSHA256: fmt.Sprintf("%x", sha256.Sum256(corpusData)),
				Source: &benchmark.NormalizationSource{
					Dataset: test.dataset, Revision: test.revision, License: test.license,
					Redistribution: "download-only", Path: "source", Bytes: 1, SHA256: strings.Repeat("a", 64),
				},
			}
			if test.trajectorySource {
				manifest.TrajectorySource = json.RawMessage(fmt.Sprintf(
					`{"dataset":%q,"license":%q,"redistribution":"download-only","revision":%q}`,
					test.dataset, test.license, test.revision,
				))
			}
			manifestData, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "cases.manifest.json"), manifestData, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := runBenchmark([]string{
				"--corpus", corpusPath,
				"--dataset-lock", filepath.Join(repoRoot, "benchmarks", "datasets.lock.json"),
				"--repo-root", repoRoot,
				"--profiles", "default",
				"--run-id", test.adapter,
				"--output", filepath.Join(dir, "output"),
			}, &bytes.Buffer{}); err != nil {
				t.Fatalf("runner rejected strict manifest: %v", err)
			}
		})
	}
}

func TestDTapMigrationOutputLoadsEndToEnd(t *testing.T) {
	dir := t.TempDir()
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	legacyCase := benchmark.Case{
		SchemaVersion: benchmark.SchemaVersion,
		ID:            "dtap-agent-trajectories/legacy-malicious",
		Source: benchmark.Source{
			Dataset: "AI-Secure/DTap-Bench-Agent-Trajectories", Revision: "836caf2fdd78b888ddd14fb62dc038e932e17898",
			OriginalID: "fixture/malicious/case.json", License: "Apache-2.0", Redistribution: "download-only",
		},
		Split: "development", Surface: "action",
		Strata:  benchmark.Strata{Domain: "research", SplitGroup: strings.Repeat("a", 24)},
		Payload: benchmark.Payload{ToolName: "shell", Command: "echo safe", Dialect: "posix"},
		Truth: benchmark.Truth{
			SourceTruth: "malicious", DeterministicTruth: "malicious", LabelConfidence: "high",
			LabelSource: "source:deterministic_environment_judge", Applicability: "in_scope",
			ExpectedDisposition: "block", Categories: []string{"execution_grounded", "judge_confirmed", "research", "malicious"},
		},
	}
	corpusPath := writeJSONLForTest(t, dir, "legacy.jsonl", legacyCase)
	corpusData, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	legacyManifest := map[string]any{
		"counts": map[string]int{"cases": 1}, "dataset": legacyCase.Source.Dataset,
		"label_limitation": "legacy fixture", "license": legacyCase.Source.License,
		"output_sha256": fmt.Sprintf("%x", sha256.Sum256(corpusData)), "revision": legacyCase.Source.Revision,
		"row_count": 1, "schema_version": benchmark.SchemaVersion,
		"source_url": "https://huggingface.co/datasets/AI-Secure/DTap-Bench-Agent-Trajectories",
	}
	legacyManifestData, err := json.Marshal(legacyManifest)
	if err != nil {
		t.Fatal(err)
	}
	legacyManifestPath := filepath.Join(dir, "legacy-manifest.json")
	if err := os.WriteFile(legacyManifestPath, legacyManifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	migratedPath := filepath.Join(dir, "migrated.jsonl")
	migratedManifestPath := filepath.Join(dir, "migrated.manifest.json")
	command := exec.Command("python3", filepath.Join(repoRoot, "benchmarks", "scripts", "benchmark_normalize_dtap.py"),
		"--migrate-existing-corpus", corpusPath, "--legacy-manifest", legacyManifestPath,
		"--output", migratedPath, "--manifest", migratedManifestPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("DTap migration failed: %v\n%s", err, output)
	}
	file, err := os.Open(migratedPath)
	if err != nil {
		t.Fatal(err)
	}
	cases, loadErr := benchmark.LoadCases(file)
	closeErr := file.Close()
	if loadErr != nil {
		t.Fatalf("LoadCases rejected migrated DTap fixture: %v", loadErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if len(cases) != 1 || cases[0].Truth.SourceTruth != benchmark.TruthMalicious ||
		cases[0].Truth.DeterministicTruth != benchmark.DeterministicContextual ||
		cases[0].Truth.Applicability != benchmark.OutOfScope ||
		cases[0].Truth.ExpectedDisposition != benchmark.DispositionDetectOnly {
		t.Fatalf("migrated truth=%+v", cases)
	}
	wantNonTruth := legacyCase
	wantNonTruth.Truth = benchmark.Truth{}
	gotNonTruth := cases[0]
	gotNonTruth.Truth = benchmark.Truth{}
	if !reflect.DeepEqual(wantNonTruth, gotNonTruth) {
		t.Fatalf("migration changed detector input or provenance")
	}
	migratedData, err := os.ReadFile(migratedPath)
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := os.ReadFile(migratedManifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := benchmark.BuildCorpusManifest(cases, fmt.Sprintf("%x", sha256.Sum256(migratedData)), manifestData); err != nil {
		t.Fatalf("strict manifest rejected migrated DTap fixture: %v", err)
	}
}

func TestRunBenchmarkLoadsAndLabelsOptInPolicyPack(t *testing.T) {
	dir := t.TempDir()
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	stubRunBinaryProvenance(t, repoRoot)
	outputDir := filepath.Join(dir, "output")
	if err := runBenchmark([]string{
		"--corpus", filepath.Join(repoRoot, "benchmarks", "fixtures", "cloud-production-conformance-v1.jsonl"),
		"--dataset-lock", filepath.Join(repoRoot, "benchmarks", "datasets.lock.json"),
		"--repo-root", repoRoot,
		"--profiles", "default",
		"--opt-in-packs", "cloud-production-protection",
		"--run-id", "opt-in-pack-cli-test",
		"--output", outputDir,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	predictions, err := readPredictions(filepath.Join(outputDir, "predictions.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(predictions) != 58 {
		t.Fatalf("predictions=%d, want 58", len(predictions))
	}
	var selected benchmark.Prediction
	for _, prediction := range predictions {
		if prediction.Profile == "opt-in/cloud-production-protection" &&
			prediction.CaseID == "cloud-v1/aws-s3-recursive" {
			selected = prediction
		}
	}
	if selected.Action != "block" || selected.Severity != "CRITICAL" {
		t.Fatalf("selected opt-in prediction=%+v", selected)
	}
	var environment benchmark.Environment
	environmentData, err := os.ReadFile(filepath.Join(outputDir, "environment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(environmentData, &environment); err != nil {
		t.Fatal(err)
	}
	wantProfiles := []string{"default", "opt-in/cloud-production-protection"}
	if !reflect.DeepEqual(environment.Profiles, wantProfiles) ||
		!reflect.DeepEqual(environment.OptInPolicyPacks, []string{"cloud-production-protection"}) ||
		environment.PolicyPostures["opt-in/cloud-production-protection"] != "default" ||
		environment.PolicyDigests["opt-in/cloud-production-protection"] == "" {
		t.Fatalf("opt-in environment=%+v", environment)
	}
}

func TestParseOptInPolicyPacks(t *testing.T) {
	got, err := parseOptInPolicyPacks("cloud-production-protection, privacy-high-assurance,cloud-production-protection")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"cloud-production-protection", "privacy-high-assurance"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("packs=%v, want %v", got, want)
	}
	if _, err := parseOptInPolicyPacks("../strict"); err == nil {
		t.Fatal("path-like opt-in policy pack was accepted")
	}
}

func TestReadCasesSupportsGzipWithDecompressedDigest(t *testing.T) {
	dir := t.TempDir()
	benchmarkCase := benchmark.Case{
		SchemaVersion: benchmark.SchemaVersion,
		ID:            "test/gzip-case",
		Source: benchmark.Source{
			Dataset:        "test",
			Revision:       "1",
			OriginalID:     "gzip-case",
			License:        "Apache-2.0",
			Redistribution: "vendored",
		},
		Split:   "validation",
		Surface: "action",
		Payload: benchmark.Payload{Command: "echo hello"},
		Truth: benchmark.Truth{
			SourceTruth:         benchmark.TruthBenign,
			DeterministicTruth:  benchmark.DeterministicBenign,
			LabelConfidence:     "high",
			LabelSource:         "test-fixture",
			Applicability:       benchmark.InScope,
			ExpectedDisposition: benchmark.DispositionAllow,
		},
	}
	data, err := json.Marshal(benchmarkCase)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	gzipPath := filepath.Join(dir, "cases.jsonl.gz")
	file, err := os.OpenFile(gzipPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	cases, err := readCases(gzipPath)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cases, []benchmark.Case{benchmarkCase}) {
		t.Fatalf("cases=%+v, want %+v", cases, benchmarkCase)
	}
	wantDigest := fmt.Sprintf("%x", sha256.Sum256(data))
	gotDigest, err := corpusSHA256(gzipPath)
	if err != nil {
		t.Fatal(err)
	}
	if gotDigest != wantDigest {
		t.Fatalf("digest=%s, want %s", gotDigest, wantDigest)
	}
	manifestData := []byte(`{"datasets":["test"],"cases":1,"counts":{"test":1},"output_sha256":"` + wantDigest + `"}`)
	manifestPath := filepath.Join(dir, "cases.manifest.json")
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	loadedManifest, err := readNormalizationManifest("", gzipPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loadedManifest, manifestData) {
		t.Fatalf("manifest=%s, want %s", loadedManifest, manifestData)
	}
}

func runCompareForTest(t *testing.T, corpusPath, truthPath, baselinePath, candidatePath string) benchmark.RunComparison {
	t.Helper()
	args := []string{
		"--corpus", corpusPath,
		"--baseline-predictions", baselinePath,
		"--candidate-predictions", candidatePath,
	}
	if truthPath != "" {
		args = append(args, "--truth-corpus", truthPath)
	}
	var output bytes.Buffer
	if err := compareBenchmark(args, &output); err != nil {
		t.Fatal(err)
	}
	var comparison benchmark.RunComparison
	if err := json.Unmarshal(output.Bytes(), &comparison); err != nil {
		t.Fatal(err)
	}
	return comparison
}

func writeJSONLForTest(t *testing.T, dir, name string, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
