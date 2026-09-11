// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

type DatasetLock struct {
	SchemaVersion string        `json:"schema_version"`
	FrozenAt      string        `json:"frozen_at"`
	Datasets      []DatasetSpec `json:"datasets"`
}

type DatasetSpec struct {
	ID             string   `json:"id"`
	Purpose        []string `json:"purpose"`
	SourceURL      string   `json:"source_url"`
	Revision       string   `json:"revision"`
	Fetch          string   `json:"fetch"`
	License        string   `json:"license"`
	LicenseStatus  string   `json:"license_status"`
	Redistribution string   `json:"redistribution"`
	IncludePaths   []string `json:"include_paths,omitempty"`
	Enabled        bool     `json:"enabled"`
}

var fullGitRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)

func ParseDatasetLock(data []byte) (DatasetLock, error) {
	var lock DatasetLock
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&lock); err != nil {
		return DatasetLock{}, fmt.Errorf("decode dataset lock: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return DatasetLock{}, fmt.Errorf("decode dataset lock: %w", err)
	}
	if lock.SchemaVersion != SchemaVersion || strings.TrimSpace(lock.FrozenAt) == "" {
		return DatasetLock{}, fmt.Errorf("dataset lock requires schema_version=%s and frozen_at", SchemaVersion)
	}
	seen := make(map[string]struct{}, len(lock.Datasets))
	for index, dataset := range lock.Datasets {
		if strings.TrimSpace(dataset.ID) == "" || len(dataset.Purpose) == 0 ||
			strings.TrimSpace(dataset.SourceURL) == "" || strings.TrimSpace(dataset.Revision) == "" ||
			strings.TrimSpace(dataset.License) == "" {
			return DatasetLock{}, fmt.Errorf("dataset %d has incomplete provenance", index)
		}
		if _, exists := seen[dataset.ID]; exists {
			return DatasetLock{}, fmt.Errorf("duplicate dataset ID %q", dataset.ID)
		}
		seen[dataset.ID] = struct{}{}
		switch dataset.Fetch {
		case "vendored", "git", "manual":
		default:
			return DatasetLock{}, fmt.Errorf("dataset %q has unsupported fetch type %q", dataset.ID, dataset.Fetch)
		}
		if dataset.Fetch == "git" && !fullGitRevision.MatchString(dataset.Revision) {
			return DatasetLock{}, fmt.Errorf("dataset %q must pin a full Git revision", dataset.ID)
		}
		seenPaths := make(map[string]struct{}, len(dataset.IncludePaths))
		for _, includePath := range dataset.IncludePaths {
			if strings.TrimSpace(includePath) == "" || strings.HasPrefix(includePath, "/") ||
				strings.Contains(includePath, "\\") || strings.ContainsAny(includePath, "*?[") {
				return DatasetLock{}, fmt.Errorf("dataset %q has unsafe include path %q", dataset.ID, includePath)
			}
			for _, component := range strings.Split(includePath, "/") {
				if component == "" || component == "." || component == ".." {
					return DatasetLock{}, fmt.Errorf("dataset %q has unsafe include path %q", dataset.ID, includePath)
				}
			}
			if _, exists := seenPaths[includePath]; exists {
				return DatasetLock{}, fmt.Errorf("dataset %q repeats include path %q", dataset.ID, includePath)
			}
			seenPaths[includePath] = struct{}{}
		}
		switch dataset.LicenseStatus {
		case "approved", "review_required", "restricted":
		default:
			return DatasetLock{}, fmt.Errorf("dataset %q has unsupported license_status %q", dataset.ID, dataset.LicenseStatus)
		}
		if dataset.Enabled && dataset.LicenseStatus != "approved" {
			return DatasetLock{}, fmt.Errorf("dataset %q cannot be enabled before license approval", dataset.ID)
		}
		switch dataset.Redistribution {
		case "vendored", "download-only", "aggregate-only", "manual":
		default:
			return DatasetLock{}, fmt.Errorf("dataset %q has unsupported redistribution %q", dataset.ID, dataset.Redistribution)
		}
	}
	return lock, nil
}
