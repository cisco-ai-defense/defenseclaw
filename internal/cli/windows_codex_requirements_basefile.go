// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// windowsCodexRequirementsBaseFileLimit bounds a --base-file document.
const windowsCodexRequirementsBaseFileLimit = 4 << 20

// readWindowsCodexRequirementsBaseFile reads the document a reconcile renders
// the managed policy into (GAP-1001). It must be a regular, non-link file of
// text inside the recovered-policy folder next to the ownership record, which
// only administrators can write; it may be empty (the managed policy alone).
func readWindowsCodexRequirementsBaseFile(path, ownershipPath string) ([]byte, error) {
	allowed := filepath.Join(filepath.Dir(ownershipPath), "recovered-policy")
	full, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("Codex requirements base file: %w", err)
	}
	rel, err := filepath.Rel(allowed, full)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("Codex requirements base file %s is not inside %s", path, allowed)
	}
	info, err := os.Lstat(full)
	if err != nil {
		return nil, fmt.Errorf("Codex requirements base file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Codex requirements base file %s is not a regular file", full)
	}
	if info.Size() > windowsCodexRequirementsBaseFileLimit {
		return nil, fmt.Errorf("Codex requirements base file %s exceeds %d bytes", full, windowsCodexRequirementsBaseFileLimit)
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, fmt.Errorf("Codex requirements base file: %w", err)
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		return nil, fmt.Errorf("Codex requirements base file %s is not valid UTF-8 text", full)
	}
	return data, nil
}
