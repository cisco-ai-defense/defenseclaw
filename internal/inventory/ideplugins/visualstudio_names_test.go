// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ideplugins

import (
	"fmt"
	"io"
	"testing"
)

// registryValueNames answers like registry.Key.ReadValueNames: at most n
// names, io.EOF only when the list ends within the page.
func registryValueNames(all []string) func(int) ([]string, error) {
	return func(n int) ([]string, error) {
		if n >= len(all) {
			return all, io.EOF
		}
		return all[:n], nil
	}
}

// An enabled extension listed after the first 2048 value names is still
// enabled, and a list that reaches the cap leaves the state unknown rather
// than marking the rest disabled (GAP-1137).
func TestVisualStudioEnabledNamesReadsPastAFullPage(t *testing.T) {
	names := make([]string, 0, visualStudioMaxExtensions+1)
	for i := range visualStudioMaxExtensions {
		names = append(names, fmt.Sprintf("Removed.Extension%d,1.0", i))
	}
	names = append(names, "Example.Late,2.0")
	enabled, ok := visualStudioEnabledNames(registryValueNames(names))
	if !ok || !enabled["example.late"] || len(enabled) != len(names) {
		t.Fatalf("enabled = %d names (late one %v), ok %v; want all %d", len(enabled), enabled["example.late"], ok, len(names))
	}
	full := make([]string, visualStudioMaxEnabledNames+1)
	for i := range full {
		full[i] = fmt.Sprintf("Example.Tool%d,1.0", i)
	}
	if enabled, ok := visualStudioEnabledNames(registryValueNames(full)); ok || enabled != nil {
		t.Fatalf("a list past the cap was taken as complete (%d names)", len(enabled))
	}
}
