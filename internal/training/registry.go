package training

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ModelVersion represents a trained model version with its metadata
type ModelVersion struct {
	ID                 string    `json:"id"`
	File               string    `json:"file"`
	BaseModel          string    `json:"base_model"`
	Algorithm          string    `json:"algorithm"`
	Created            time.Time `json:"created"`
	TracesUsed         int       `json:"traces_used"`
	EvalScoreLocal     float64   `json:"eval_score_local"`
	EvalScoreFrontier  float64   `json:"eval_score_frontier"`
	EvalRatio          float64   `json:"eval_ratio"`
	Promoted           bool      `json:"promoted"`
	PromotedAt         time.Time `json:"promoted_at,omitempty"`
	RolledBack         bool      `json:"rolled_back"`
}

// registryData represents the internal structure of the registry
type registryData struct {
	Categories map[string]categoryData `json:"categories"`
}

// categoryData tracks versions and current promoted version for a category
type categoryData struct {
	Versions        []ModelVersion `json:"versions"`
	CurrentPromoted string         `json:"current_promoted,omitempty"`
}

// Registry manages model versions with JSON persistence
type Registry struct {
	path string
	data registryData
	mu   sync.RWMutex
}

// NewRegistry creates or loads a registry from the specified directory
func NewRegistry(dir string) (*Registry, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create registry directory: %w", err)
	}

	path := filepath.Join(dir, "registry.json")
	r := &Registry{
		path: path,
		data: registryData{
			Categories: make(map[string]categoryData),
		},
	}

	// Try to load existing registry
	if _, err := os.Stat(path); err == nil {
		if err := r.load(); err != nil {
			return nil, fmt.Errorf("load registry: %w", err)
		}
	}

	return r, nil
}

// RegisterVersion appends a new model version to the specified category
func (r *Registry) RegisterVersion(category string, v ModelVersion) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cat, exists := r.data.Categories[category]
	if !exists {
		cat = categoryData{
			Versions: make([]ModelVersion, 0),
		}
	}

	cat.Versions = append(cat.Versions, v)
	r.data.Categories[category] = cat

	return r.save()
}

// ListVersions returns all versions for a category
func (r *Registry) ListVersions(category string) []ModelVersion {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cat, exists := r.data.Categories[category]
	if !exists {
		return nil
	}

	// Return a copy to prevent external modifications
	versions := make([]ModelVersion, len(cat.Versions))
	copy(versions, cat.Versions)
	return versions
}

// GetPromoted returns the currently promoted version for a category
func (r *Registry) GetPromoted(category string) *ModelVersion {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cat, exists := r.data.Categories[category]
	if !exists || cat.CurrentPromoted == "" {
		return nil
	}

	// Find the promoted version
	for _, v := range cat.Versions {
		if v.ID == cat.CurrentPromoted {
			// Return a copy
			vCopy := v
			return &vCopy
		}
	}

	return nil
}

// Promote marks a version as promoted and updates the current promoted version
func (r *Registry) Promote(category, versionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cat, exists := r.data.Categories[category]
	if !exists {
		return fmt.Errorf("category not found: %s", category)
	}

	// Find the version to promote
	versionIdx := -1
	for i, v := range cat.Versions {
		if v.ID == versionID {
			versionIdx = i
			break
		}
	}

	if versionIdx == -1 {
		return fmt.Errorf("version not found: %s", versionID)
	}

	// Demote previous promoted version
	if cat.CurrentPromoted != "" {
		for i, v := range cat.Versions {
			if v.ID == cat.CurrentPromoted {
				cat.Versions[i].Promoted = false
				cat.Versions[i].PromotedAt = time.Time{}
				break
			}
		}
	}

	// Promote the new version
	cat.Versions[versionIdx].Promoted = true
	cat.Versions[versionIdx].PromotedAt = time.Now()
	cat.CurrentPromoted = versionID

	r.data.Categories[category] = cat
	return r.save()
}

// Rollback marks the current promoted version as rolled back and clears promotion
func (r *Registry) Rollback(category string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	cat, exists := r.data.Categories[category]
	if !exists || cat.CurrentPromoted == "" {
		return fmt.Errorf("no promoted version to rollback in category: %s", category)
	}

	// Find and rollback the promoted version
	for i, v := range cat.Versions {
		if v.ID == cat.CurrentPromoted {
			cat.Versions[i].Promoted = false
			cat.Versions[i].PromotedAt = time.Time{}
			cat.Versions[i].RolledBack = true
			break
		}
	}

	cat.CurrentPromoted = ""
	r.data.Categories[category] = cat

	return r.save()
}

// load reads the registry from disk
func (r *Registry) load() error {
	data, err := os.ReadFile(r.path)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &r.data)
}

// save writes the registry to disk atomically
func (r *Registry) save() error {
	data, err := json.MarshalIndent(r.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal registry: %w", err)
	}

	tmpPath := r.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}

	if err := os.Rename(tmpPath, r.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("atomic rename: %w", err)
	}

	return nil
}
