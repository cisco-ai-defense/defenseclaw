// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Dataset holds paths and counts for the extracted training data.
type Dataset struct {
	TrainFile  string
	EvalFile   string
	TrainCount int
	EvalCount  int
	Category   string
}

// JSONLEntry represents a single line in the JSONL output files.
type JSONLEntry struct {
	Prompt    string `json:"prompt"`
	Response  string `json:"response"`
	ModelUsed string `json:"model_used"`
}

// Extract pulls traces from store, splits train/eval, writes JSONL files to outDir.
// evalRatio is the fraction held out for evaluation (e.g., 0.1 = 10%).
func Extract(store *Store, category string, limit int, evalRatio float64, outDir string) (*Dataset, error) {
	// Validate parameters
	if evalRatio < 0 || evalRatio > 1 {
		return nil, fmt.Errorf("evalRatio must be between 0 and 1, got %.2f", evalRatio)
	}

	// Extract traces from store
	traces, err := store.ExtractForTraining(category, limit)
	if err != nil {
		return nil, fmt.Errorf("extract traces: %w", err)
	}

	if len(traces) == 0 {
		return nil, fmt.Errorf("no traces found for category %q", category)
	}

	// Calculate split point (eval set comes from the end, which is oldest since traces are newest-first)
	evalCount := int(float64(len(traces)) * evalRatio)
	trainCount := len(traces) - evalCount

	// Split traces
	trainTraces := traces[:trainCount]
	evalTraces := traces[trainCount:]

	// Ensure output directory exists
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}

	// Write training file
	trainFile := filepath.Join(outDir, fmt.Sprintf("%s_train.jsonl", category))
	if err := writeJSONL(trainFile, trainTraces); err != nil {
		return nil, fmt.Errorf("write training file: %w", err)
	}

	// Write evaluation file
	evalFile := filepath.Join(outDir, fmt.Sprintf("%s_eval.jsonl", category))
	if err := writeJSONL(evalFile, evalTraces); err != nil {
		return nil, fmt.Errorf("write evaluation file: %w", err)
	}

	return &Dataset{
		TrainFile:  trainFile,
		EvalFile:   evalFile,
		TrainCount: trainCount,
		EvalCount:  evalCount,
		Category:   category,
	}, nil
}

// writeJSONL writes trace entries to a JSONL file.
func writeJSONL(path string, traces []TraceEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	for _, trace := range traces {
		entry := JSONLEntry{
			Prompt:    trace.Prompt,
			Response:  trace.Response,
			ModelUsed: trace.ModelUsed,
		}
		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("encode entry: %w", err)
		}
	}

	return nil
}
