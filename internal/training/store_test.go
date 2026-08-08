// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package training

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStore_CaptureAndCount(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	entry := TraceEntry{
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Category:         "code-generation",
		RecommendedModel: "qwen-2.5-coder-7b",
		Prompt:           "write a hello world",
		Response:         "print('hello world')",
		ModelUsed:        "gpt-4o",
		IsPromotedModel:  false,
		LatencyMs:        123,
		TokensIn:         10,
		TokensOut:        5,
		UsedForTraining:  false,
		TrainingRunID:    "",
	}

	if err := store.CaptureTrace(entry); err != nil {
		t.Fatalf("CaptureTrace: %v", err)
	}

	count, err := store.CountByCategory("code-generation")
	if err != nil {
		t.Fatalf("CountByCategory: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count=1, got %d", count)
	}

	countOther, err := store.CountByCategory("other-category")
	if err != nil {
		t.Fatalf("CountByCategory(other): %v", err)
	}
	if countOther != 0 {
		t.Errorf("expected count=0 for other category, got %d", countOther)
	}
}

func TestStore_ExtractAndMarkUsed(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	// Insert 10 traces
	for i := 0; i < 10; i++ {
		entry := TraceEntry{
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			Category:         "test-category",
			RecommendedModel: "test-model",
			Prompt:           "test prompt",
			Response:         "test response",
			ModelUsed:        "test-used",
			IsPromotedModel:  false,
			LatencyMs:        100,
			TokensIn:         10,
			TokensOut:        5,
			UsedForTraining:  false,
			TrainingRunID:    "",
		}
		if err := store.CaptureTrace(entry); err != nil {
			t.Fatalf("CaptureTrace: %v", err)
		}
	}

	// Extract 5
	traces, err := store.ExtractForTraining("test-category", 5)
	if err != nil {
		t.Fatalf("ExtractForTraining: %v", err)
	}
	if len(traces) != 5 {
		t.Errorf("expected 5 traces, got %d", len(traces))
	}

	// Mark used
	ids := make([]int64, len(traces))
	for i, tr := range traces {
		ids[i] = tr.ID
	}
	if err := store.MarkUsed(ids, "run-123"); err != nil {
		t.Fatalf("MarkUsed: %v", err)
	}

	// Count remaining
	count, err := store.CountByCategory("test-category")
	if err != nil {
		t.Fatalf("CountByCategory: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 remaining traces, got %d", count)
	}
}

func TestStore_ExtractReturnsNewest(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	// Insert with different timestamps
	baseTime := time.Now().UTC()
	for i := 0; i < 3; i++ {
		ts := baseTime.Add(time.Duration(i) * time.Second)
		entry := TraceEntry{
			Timestamp:        ts.Format(time.RFC3339),
			Category:         "test-category",
			RecommendedModel: "test-model",
			Prompt:           "test prompt " + string(rune('A'+i)),
			Response:         "test response",
			ModelUsed:        "test-used",
			IsPromotedModel:  false,
			LatencyMs:        100,
			TokensIn:         10,
			TokensOut:        5,
			UsedForTraining:  false,
			TrainingRunID:    "",
		}
		if err := store.CaptureTrace(entry); err != nil {
			t.Fatalf("CaptureTrace: %v", err)
		}
		// Sleep to ensure timestamp order in SQLite
		time.Sleep(10 * time.Millisecond)
	}

	// Extract all
	traces, err := store.ExtractForTraining("test-category", 10)
	if err != nil {
		t.Fatalf("ExtractForTraining: %v", err)
	}
	if len(traces) != 3 {
		t.Errorf("expected 3 traces, got %d", len(traces))
	}

	// Verify LIFO order (newest first)
	if traces[0].Prompt != "test prompt C" {
		t.Errorf("expected newest trace first, got %s", traces[0].Prompt)
	}
}

func TestStore_EmptyCategory(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	traces, err := store.ExtractForTraining("non-existent-category", 10)
	if err != nil {
		t.Fatalf("ExtractForTraining should not error on empty category: %v", err)
	}
	if len(traces) != 0 {
		t.Errorf("expected empty slice, got %d traces", len(traces))
	}
}

func TestStore_Close(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("database file should exist after Close")
	}
}
