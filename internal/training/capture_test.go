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

// TestCapturer_WritesAsync verifies that entries are written asynchronously.
func TestCapturer_WritesAsync(t *testing.T) {
	// Create temp store
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_async.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	// Create capturer
	capturer := NewCapturer(store)
	defer capturer.Stop()

	// Capture 10 entries
	for i := 0; i < 10; i++ {
		entry := TraceEntry{
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			Category:         "test",
			Prompt:           "prompt",
			Response:         "response",
			ModelUsed:        "test-model",
			IsPromotedModel:  false,
			RecommendedModel: "recommended",
		}
		capturer.Capture(entry)
	}

	// Sleep to allow async writes
	time.Sleep(100 * time.Millisecond)

	// Verify count
	count, err := store.CountByCategory("test")
	if err != nil {
		t.Fatalf("CountByCategory failed: %v", err)
	}

	if count != 10 {
		t.Errorf("expected 10 entries, got %d", count)
	}
}

// TestCapturer_NonBlockingWhenFull verifies that captures don't block when buffer is full.
func TestCapturer_NonBlockingWhenFull(t *testing.T) {
	// Create temp store
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_nonblock.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	// Create capturer
	capturer := NewCapturer(store)
	defer capturer.Stop()

	// Capture 200 entries (buffer size is 100)
	// This should NOT hang or panic
	done := make(chan bool)
	go func() {
		for i := 0; i < 200; i++ {
			entry := TraceEntry{
				Timestamp:        time.Now().UTC().Format(time.RFC3339),
				Category:         "test",
				Prompt:           "prompt",
				Response:         "response",
				ModelUsed:        "test-model",
				IsPromotedModel:  false,
				RecommendedModel: "recommended",
			}
			capturer.Capture(entry)
		}
		done <- true
	}()

	// Wait with timeout to ensure non-blocking
	select {
	case <-done:
		// Success - captures completed without blocking
	case <-time.After(2 * time.Second):
		t.Fatal("captures blocked - should be non-blocking")
	}

	// Some entries may be dropped, but we should have at least some
	time.Sleep(200 * time.Millisecond)
	count, err := store.CountByCategory("test")
	if err != nil {
		t.Fatalf("CountByCategory failed: %v", err)
	}

	// We expect some entries were captured, but not necessarily all 200
	// due to buffer overflow and non-blocking behavior
	if count == 0 {
		t.Error("expected at least some entries to be captured")
	}

	t.Logf("captured %d out of 200 entries (some dropped due to buffer overflow)", count)
}

// TestCapturer_StopDrainsRemaining verifies that Stop() flushes remaining entries.
func TestCapturer_StopDrainsRemaining(t *testing.T) {
	// Create temp store
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_drain.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	// Create capturer
	capturer := NewCapturer(store)

	// Capture entries
	numEntries := 50
	for i := 0; i < numEntries; i++ {
		entry := TraceEntry{
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			Category:         "test",
			Prompt:           "prompt",
			Response:         "response",
			ModelUsed:        "test-model",
			IsPromotedModel:  false,
			RecommendedModel: "recommended",
		}
		capturer.Capture(entry)
	}

	// Stop immediately - should drain remaining entries
	capturer.Stop()

	// Small sleep to ensure drain completes
	time.Sleep(100 * time.Millisecond)

	// Verify all entries were flushed
	count, err := store.CountByCategory("test")
	if err != nil {
		t.Fatalf("CountByCategory failed: %v", err)
	}

	if count != numEntries {
		t.Errorf("expected %d entries after Stop(), got %d", numEntries, count)
	}
}

// TestCapturer_CaptureAfterStop verifies no panic when capturing after Stop().
func TestCapturer_CaptureAfterStop(t *testing.T) {
	// Create temp store
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_after_stop.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	// Create capturer
	capturer := NewCapturer(store)

	// Stop immediately
	capturer.Stop()

	// Try to capture after stop - should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Capture() panicked after Stop(): %v", r)
		}
	}()

	entry := TraceEntry{
		Timestamp:        time.Now().UTC().Format(time.RFC3339),
		Category:         "test",
		Prompt:           "prompt",
		Response:         "response",
		ModelUsed:        "test-model",
		IsPromotedModel:  false,
		RecommendedModel: "recommended",
	}
	capturer.Capture(entry)

	// Verify no entries were captured
	count, err := store.CountByCategory("test")
	if err != nil {
		t.Fatalf("CountByCategory failed: %v", err)
	}

	if count != 0 {
		t.Errorf("expected 0 entries after Stop(), got %d", count)
	}
}

// TestCapturer_MultipleStopCalls verifies that calling Stop() multiple times is safe.
func TestCapturer_MultipleStopCalls(t *testing.T) {
	// Create temp store
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_multi_stop.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	// Create capturer
	capturer := NewCapturer(store)

	// Call Stop multiple times - should not panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Multiple Stop() calls panicked: %v", r)
		}
	}()

	capturer.Stop()
	capturer.Stop()
	capturer.Stop()
}

// Helper to ensure temp files are cleaned up
func TestMain(m *testing.M) {
	code := m.Run()
	os.Exit(code)
}
