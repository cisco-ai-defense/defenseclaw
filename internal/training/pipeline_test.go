// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPipeline_NotEnoughTraces(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Create registry
	registry, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Add a few traces (below minimum)
	for i := 0; i < 5; i++ {
		err := store.CaptureTrace(TraceEntry{
			Category: "test-category",
			Prompt:   "test prompt",
			Response: "test response",
		})
		if err != nil {
			t.Fatalf("Failed to capture trace: %v", err)
		}
	}

	// Create pipeline
	pipeline := NewPipeline(store, registry)

	// Run pipeline with min_traces = 10
	cfg := PipelineConfig{
		Category:  "test-category",
		MinTraces: 10,
		DataDir:   tmpDir,
	}

	result := pipeline.Run(context.Background(), cfg)

	// Verify failure
	if result.State != StateFailed {
		t.Errorf("Expected state StateFailed, got %v", result.State)
	}

	if result.Error == nil {
		t.Error("Expected error, got nil")
	} else if result.Error.Error() != "pipeline: need 10 traces for \"test-category\", have 5" {
		t.Errorf("Unexpected error message: %v", result.Error)
	}
}

func TestPipeline_ExtractFails(t *testing.T) {
	// Create temporary database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Create registry
	registry, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create registry: %v", err)
	}

	// Create pipeline
	pipeline := NewPipeline(store, registry)

	// Run pipeline with empty category (no traces)
	cfg := PipelineConfig{
		Category:  "nonexistent-category",
		MinTraces: 1,
		DataDir:   tmpDir,
	}

	result := pipeline.Run(context.Background(), cfg)

	// Verify failure
	if result.State != StateFailed {
		t.Errorf("Expected state StateFailed, got %v", result.State)
	}

	if result.Error == nil {
		t.Error("Expected error, got nil")
	}
}

func TestCopyFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create source file
	srcPath := filepath.Join(tmpDir, "source.txt")
	content := []byte("test content for copy")
	if err := os.WriteFile(srcPath, content, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Copy to destination in subdirectory
	dstPath := filepath.Join(tmpDir, "subdir", "dest.txt")
	if err := copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("Failed to copy file: %v", err)
	}

	// Verify destination exists
	if _, err := os.Stat(dstPath); os.IsNotExist(err) {
		t.Error("Destination file was not created")
	}

	// Verify contents match
	dstContent, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("Failed to read destination file: %v", err)
	}

	if string(dstContent) != string(content) {
		t.Errorf("Content mismatch: expected %q, got %q", string(content), string(dstContent))
	}

	// Verify subdirectory was created
	subdir := filepath.Join(tmpDir, "subdir")
	if info, err := os.Stat(subdir); os.IsNotExist(err) || !info.IsDir() {
		t.Error("Subdirectory was not created")
	}
}

func TestCopyFile_SourceNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	srcPath := filepath.Join(tmpDir, "nonexistent.txt")
	dstPath := filepath.Join(tmpDir, "dest.txt")

	err := copyFile(srcPath, dstPath)
	if err == nil {
		t.Error("Expected error when source file does not exist")
	}
}

func TestPipelineState_Constants(t *testing.T) {
	// Verify all pipeline states are defined
	states := []PipelineState{
		StateIdle,
		StateExtracting,
		StateBuildingDataset,
		StateTraining,
		StateExporting,
		StateDeploying,
		StateEvaluating,
		StatePromoted,
		StateFailed,
	}

	for _, state := range states {
		if string(state) == "" {
			t.Errorf("State has empty string value: %v", state)
		}
	}
}
