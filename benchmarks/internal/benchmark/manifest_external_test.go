// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestStrictNormalizationManifestFiles lets corpus adapter tests prove that
// externally generated, value-free sidecars decode through the runner's exact
// strict path without reading normalized payload rows. Paths are whitespace
// separated so the test remains explicit and shell-portable.
func TestStrictNormalizationManifestFiles(t *testing.T) {
	paths := strings.Fields(os.Getenv("DEFENSECLAW_STRICT_NORMALIZATION_MANIFESTS"))
	requirePartition := os.Getenv("DEFENSECLAW_REQUIRE_PARTITION_MANIFESTS") == "1"
	if len(paths) == 0 {
		t.Skip("DEFENSECLAW_STRICT_NORMALIZATION_MANIFESTS is not set")
	}
	for _, path := range paths {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			normalized, err := decodeNormalizationManifest(data)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateNormalizationManifestMetadata(normalized); err != nil {
				t.Fatal(err)
			}
			if normalized.SchemaVersion != SchemaVersion || len(normalized.Datasets) == 0 || normalized.Cases <= 0 {
				t.Fatal("normalization manifest identity is incomplete")
			}
			if requirePartition {
				partition := normalized.Partition
				if partition == nil || partition.Strategy != "adapter-group-balanced-v1" ||
					partition.Split == "" || partition.SplitGroupCount <= 0 ||
					!validSHA256(partition.SourceCorpusSHA256) ||
					!validSHA256(partition.SourceNormalizationSHA256) ||
					!validSHA256(partition.AssignmentSHA256) {
					t.Fatal("strict partition manifest identity is incomplete")
				}
			}
		})
	}
}
