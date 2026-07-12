//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package local

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// This runs on Windows CI and pins the preparation seam: validation must open
// the parent directory, not the not-yet-created JSONL leaf path.
func TestWindowsJSONLPreparesNewFileInTrustedParent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "new", "events.jsonl")
	adapter, err := NewJSONL(JSONLConfig{Path: path, MaxSizeMB: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("mode = %v, want regular file", info.Mode())
	}
}
