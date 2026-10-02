// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

// A Windows console on a legacy code page shows the UTF-8 bytes of an em
// dash as mojibake in `defenseclaw-gateway --help` (GAP-1300), so the root
// help text stays ASCII.
func TestRootHelpTextIsASCII(t *testing.T) {
	for name, text := range map[string]string{"Short": rootCmd.Short, "Long": rootCmd.Long} {
		for i, r := range text {
			if r > 127 {
				t.Fatalf("rootCmd.%s has non-ASCII %q at byte %d", name, r, i)
			}
		}
	}
}
