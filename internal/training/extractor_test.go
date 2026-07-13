// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExtract_SplitsTrainEval(t *testing.T) {
	// Setup: create temp store and insert 100 traces
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	category := "code-generation"
	for i := 0; i < 100; i++ {
		err := store.CaptureTrace(TraceEntry{
			Category:  category,
			Prompt:    "write a function",
			Response:  "func example() {}",
			ModelUsed: "claude-3",
		})
		if err != nil {
			t.Fatalf("CaptureTrace failed: %v", err)
		}
	}

	// Extract with 0.1 eval ratio
	outDir := filepath.Join(tmpDir, "output")
	dataset, err := Extract(store, category, 100, 0.1, outDir)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Verify split
	if dataset.TrainCount != 90 {
		t.Errorf("expected 90 training samples, got %d", dataset.TrainCount)
	}
	if dataset.EvalCount != 10 {
		t.Errorf("expected 10 eval samples, got %d", dataset.EvalCount)
	}

	// Verify files exist
	if _, err := os.Stat(dataset.TrainFile); err != nil {
		t.Errorf("training file does not exist: %v", err)
	}
	if _, err := os.Stat(dataset.EvalFile); err != nil {
		t.Errorf("eval file does not exist: %v", err)
	}
}

func TestExtract_WritesValidJSONL(t *testing.T) {
	// Setup: create temp store and insert traces
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	category := "code-generation"
	expectedPrompt := "write a function to sum numbers"
	expectedResponse := "func sum(a, b int) int { return a + b }"
	expectedModel := "claude-3-opus"

	err = store.CaptureTrace(TraceEntry{
		Category:  category,
		Prompt:    expectedPrompt,
		Response:  expectedResponse,
		ModelUsed: expectedModel,
	})
	if err != nil {
		t.Fatalf("CaptureTrace failed: %v", err)
	}

	// Extract
	outDir := filepath.Join(tmpDir, "output")
	dataset, err := Extract(store, category, 10, 0.1, outDir)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Read first line of training file
	f, err := os.Open(dataset.TrainFile)
	if err != nil {
		t.Fatalf("failed to open training file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("training file is empty")
	}

	// Parse JSON
	var entry JSONLEntry
	if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	// Verify fields
	if entry.Prompt != expectedPrompt {
		t.Errorf("expected prompt %q, got %q", expectedPrompt, entry.Prompt)
	}
	if entry.Response != expectedResponse {
		t.Errorf("expected response %q, got %q", expectedResponse, entry.Response)
	}
	if entry.ModelUsed != expectedModel {
		t.Errorf("expected model_used %q, got %q", expectedModel, entry.ModelUsed)
	}
}

func TestExtract_EmptyCategoryErrors(t *testing.T) {
	// Setup: create temp store with no traces
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	// Try to extract from empty category
	outDir := filepath.Join(tmpDir, "output")
	_, err = Extract(store, "nonexistent-category", 10, 0.1, outDir)
	if err == nil {
		t.Fatal("expected error for empty category, got nil")
	}

	// Verify error message mentions no traces
	expectedMsg := "no traces found"
	if err.Error() != "no traces found for category \"nonexistent-category\"" {
		t.Errorf("expected error containing %q, got %q", expectedMsg, err.Error())
	}
}

func TestExtract_RespectLimit(t *testing.T) {
	// Setup: create temp store and insert 200 traces
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	category := "summarization"
	for i := 0; i < 200; i++ {
		err := store.CaptureTrace(TraceEntry{
			Category:  category,
			Prompt:    "summarize this text",
			Response:  "summary here",
			ModelUsed: "claude-3",
		})
		if err != nil {
			t.Fatalf("CaptureTrace failed: %v", err)
		}
	}

	// Extract with limit=50
	outDir := filepath.Join(tmpDir, "output")
	dataset, err := Extract(store, category, 50, 0.1, outDir)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Verify total is 50 (45 train + 5 eval)
	total := dataset.TrainCount + dataset.EvalCount
	if total != 50 {
		t.Errorf("expected total of 50 samples, got %d (train=%d, eval=%d)",
			total, dataset.TrainCount, dataset.EvalCount)
	}

	if dataset.TrainCount != 45 {
		t.Errorf("expected 45 training samples, got %d", dataset.TrainCount)
	}
	if dataset.EvalCount != 5 {
		t.Errorf("expected 5 eval samples, got %d", dataset.EvalCount)
	}
}
