// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/benchmarks/internal/benchmark"
)

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
