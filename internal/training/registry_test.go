package training

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistry_RegisterAndPromote(t *testing.T) {
	tmpDir := t.TempDir()
	registry, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	category := "test_category"
	version := ModelVersion{
		ID:                "v1",
		File:              "/models/v1.pkl",
		BaseModel:         "gpt-4",
		Algorithm:         "setfit",
		Created:           time.Now(),
		TracesUsed:        100,
		EvalScoreLocal:    0.85,
		EvalScoreFrontier: 0.90,
		EvalRatio:         0.944,
	}

	// Register version
	if err := registry.RegisterVersion(category, version); err != nil {
		t.Fatalf("RegisterVersion failed: %v", err)
	}

	// Verify not promoted initially
	promoted := registry.GetPromoted(category)
	if promoted != nil {
		t.Errorf("Expected no promoted version, got: %v", promoted)
	}

	// Promote version
	if err := registry.Promote(category, "v1"); err != nil {
		t.Fatalf("Promote failed: %v", err)
	}

	// Verify promoted
	promoted = registry.GetPromoted(category)
	if promoted == nil {
		t.Fatal("Expected promoted version, got nil")
	}
	if promoted.ID != "v1" {
		t.Errorf("Expected promoted ID v1, got: %s", promoted.ID)
	}
	if !promoted.Promoted {
		t.Error("Expected Promoted=true")
	}
	if promoted.PromotedAt.IsZero() {
		t.Error("Expected PromotedAt to be set")
	}
}

func TestRegistry_Rollback(t *testing.T) {
	tmpDir := t.TempDir()
	registry, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	category := "test_category"
	version := ModelVersion{
		ID:        "v1",
		File:      "/models/v1.pkl",
		BaseModel: "gpt-4",
		Algorithm: "setfit",
		Created:   time.Now(),
	}

	// Register and promote
	if err := registry.RegisterVersion(category, version); err != nil {
		t.Fatalf("RegisterVersion failed: %v", err)
	}
	if err := registry.Promote(category, "v1"); err != nil {
		t.Fatalf("Promote failed: %v", err)
	}

	// Verify promoted
	promoted := registry.GetPromoted(category)
	if promoted == nil {
		t.Fatal("Expected promoted version before rollback")
	}

	// Rollback
	if err := registry.Rollback(category); err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Verify no promoted version
	promoted = registry.GetPromoted(category)
	if promoted != nil {
		t.Errorf("Expected nil promoted after rollback, got: %v", promoted)
	}

	// Verify rolled back flag is set
	versions := registry.ListVersions(category)
	if len(versions) != 1 {
		t.Fatalf("Expected 1 version, got: %d", len(versions))
	}
	if !versions[0].RolledBack {
		t.Error("Expected RolledBack=true")
	}
	if versions[0].Promoted {
		t.Error("Expected Promoted=false after rollback")
	}
}

func TestRegistry_PersistsToFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create first registry instance
	registry1, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	category := "test_category"
	version := ModelVersion{
		ID:                "v1",
		File:              "/models/v1.pkl",
		BaseModel:         "gpt-4",
		Algorithm:         "setfit",
		Created:           time.Now(),
		TracesUsed:        100,
		EvalScoreLocal:    0.85,
		EvalScoreFrontier: 0.90,
		EvalRatio:         0.944,
	}

	// Register and promote
	if err := registry1.RegisterVersion(category, version); err != nil {
		t.Fatalf("RegisterVersion failed: %v", err)
	}
	if err := registry1.Promote(category, "v1"); err != nil {
		t.Fatalf("Promote failed: %v", err)
	}

	// Verify file exists
	registryPath := filepath.Join(tmpDir, "registry.json")
	if _, err := os.Stat(registryPath); os.IsNotExist(err) {
		t.Fatal("Registry file was not created")
	}

	// Create second registry instance from same directory
	registry2, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("NewRegistry (second instance) failed: %v", err)
	}

	// Verify state persisted
	promoted := registry2.GetPromoted(category)
	if promoted == nil {
		t.Fatal("Expected promoted version in new registry instance")
	}
	if promoted.ID != "v1" {
		t.Errorf("Expected promoted ID v1, got: %s", promoted.ID)
	}
	if !promoted.Promoted {
		t.Error("Expected Promoted=true in new instance")
	}

	versions := registry2.ListVersions(category)
	if len(versions) != 1 {
		t.Fatalf("Expected 1 version in new instance, got: %d", len(versions))
	}
	if versions[0].ID != "v1" {
		t.Errorf("Expected version ID v1, got: %s", versions[0].ID)
	}
}

func TestRegistry_MultipleVersions(t *testing.T) {
	tmpDir := t.TempDir()
	registry, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	category := "test_category"

	// Register three versions
	versions := []ModelVersion{
		{
			ID:        "v1",
			File:      "/models/v1.pkl",
			BaseModel: "gpt-4",
			Algorithm: "setfit",
			Created:   time.Now(),
		},
		{
			ID:        "v2",
			File:      "/models/v2.pkl",
			BaseModel: "gpt-4",
			Algorithm: "setfit",
			Created:   time.Now().Add(time.Hour),
		},
		{
			ID:        "v3",
			File:      "/models/v3.pkl",
			BaseModel: "gpt-4",
			Algorithm: "setfit",
			Created:   time.Now().Add(2 * time.Hour),
		},
	}

	for _, v := range versions {
		if err := registry.RegisterVersion(category, v); err != nil {
			t.Fatalf("RegisterVersion failed for %s: %v", v.ID, err)
		}
	}

	// List and verify order
	listed := registry.ListVersions(category)
	if len(listed) != 3 {
		t.Fatalf("Expected 3 versions, got: %d", len(listed))
	}

	expectedIDs := []string{"v1", "v2", "v3"}
	for i, v := range listed {
		if v.ID != expectedIDs[i] {
			t.Errorf("Expected version %s at index %d, got: %s", expectedIDs[i], i, v.ID)
		}
	}

	// Promote v2
	if err := registry.Promote(category, "v2"); err != nil {
		t.Fatalf("Promote v2 failed: %v", err)
	}

	promoted := registry.GetPromoted(category)
	if promoted == nil || promoted.ID != "v2" {
		t.Errorf("Expected promoted version v2, got: %v", promoted)
	}

	// Verify only v2 is marked as promoted
	listed = registry.ListVersions(category)
	for _, v := range listed {
		if v.ID == "v2" {
			if !v.Promoted {
				t.Error("Expected v2 to be promoted")
			}
		} else {
			if v.Promoted {
				t.Errorf("Expected %s to not be promoted", v.ID)
			}
		}
	}
}

func TestRegistry_EmptyCategory(t *testing.T) {
	tmpDir := t.TempDir()
	registry, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	// GetPromoted on unknown category should return nil
	promoted := registry.GetPromoted("unknown_category")
	if promoted != nil {
		t.Errorf("Expected nil for unknown category, got: %v", promoted)
	}

	// ListVersions on unknown category should return nil
	versions := registry.ListVersions("unknown_category")
	if versions != nil {
		t.Errorf("Expected nil versions for unknown category, got: %v", versions)
	}

	// Promote on unknown category should error
	err = registry.Promote("unknown_category", "v1")
	if err == nil {
		t.Error("Expected error when promoting in unknown category")
	}

	// Rollback on unknown category should error
	err = registry.Rollback("unknown_category")
	if err == nil {
		t.Error("Expected error when rolling back unknown category")
	}
}
