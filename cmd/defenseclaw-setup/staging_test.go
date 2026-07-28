// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateExclusiveStagingRootMaterializesMissingParent(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "Programs", "DefenseClaw.staging.fixture")
	parent := filepath.Dir(staging)
	if _, err := os.Lstat(parent); !os.IsNotExist(err) {
		t.Fatalf("staging parent unexpectedly exists before test: %v", err)
	}

	if err := createExclusiveStagingRoot(staging); err != nil {
		t.Fatalf("createExclusiveStagingRoot: %v", err)
	}
	info, err := os.Stat(staging)
	if err != nil {
		t.Fatalf("stat staging root: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("staging root is not a directory: %s", staging)
	}
}

func TestCreateExclusiveStagingRootRejectsPreexistingRoot(t *testing.T) {
	staging := filepath.Join(t.TempDir(), "Programs", "DefenseClaw.staging.fixture")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := createExclusiveStagingRoot(staging); err == nil {
		t.Fatal("createExclusiveStagingRoot accepted a pre-existing staging root")
	}
}
