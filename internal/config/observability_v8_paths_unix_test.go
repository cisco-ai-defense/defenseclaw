// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A jsonl destination whose folder the gateway account may not traverse
// warns instead of stopping the gateway at start (GAP-1265). A missing
// folder is no warning, and any other inspect failure stays an error.
func TestObservabilityV8JSONLDestinationBehindDeniedFolderWarns(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses a mode 000 folder; the Windows test covers the logic with a denied lookup")
	}
	dataDir := t.TempDir()
	denied := filepath.Join(dataDir, "rv13")
	if err := os.MkdirAll(filepath.Join(denied, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o700) })
	assertObservabilityV8DeniedJSONLWarns(t, dataDir, denied)

	if compiled, err := compileObservabilityV8JSONLAt(dataDir, "", filepath.Join(dataDir, "missing", "events.jsonl")); err != nil ||
		len(compiled.PathWarnings) != 0 {
		t.Fatalf("jsonl destination in a missing folder = %v, warnings %#v", err, compiled)
	}
	file := filepath.Join(dataDir, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := compileObservabilityV8JSONLAt(dataDir, "", filepath.Join(file, "events.jsonl"))
	var pathError *V8ConfigPathError
	if !errors.As(err, &pathError) || pathError.Path != "observability.destinations[0].path" {
		t.Fatalf("jsonl destination under a file = %v, want a config path error", err)
	}
}
