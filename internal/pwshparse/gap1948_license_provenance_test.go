// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package pwshparse

import (
	"os"
	"strings"
	"testing"
)

// TestGAP1948LicenseProvenancePinsTheTag (rel-1-0-10:GAP-1948): the
// THIRD_PARTY_LICENSES.txt entry of the port names the upstream tag the parser
// sources come from and links the LICENSE at that tag, so the recorded hash is
// the hash of a fixed revision (a branch link moves). Red at ad6ab569dd (the
// link was on master).
func TestGAP1948LicenseProvenancePinsTheTag(t *testing.T) {
	raw, err := os.ReadFile("../../THIRD_PARTY_LICENSES.txt")
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout may convert the file to CRLF (core.autocrlf): the
	// entry is read by its lines, not its line ends.
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	_, entry, ok := strings.Cut(text, "  Module: github.com/PowerShell/PowerShell\n")
	if !ok {
		t.Fatal("no github.com/PowerShell/PowerShell module entry")
	}
	entry, _, _ = strings.Cut(entry, "\n\n")
	for _, want := range []string{
		"Version: v7.6.6 (tag v7.6.6, commit f260eb9c31ec72c5282f98e5ea24d9be4f8d7536)",
		"Upstream file: https://github.com/PowerShell/PowerShell/blob/v7.6.6/LICENSE.txt",
	} {
		if !strings.Contains(entry, want) {
			t.Errorf("PowerShell entry lacks %q:\n%s", want, entry)
		}
	}
	if strings.Contains(entry, "/blob/master/") || strings.Contains(entry, "/blob/main/") {
		t.Errorf("PowerShell entry links a branch, not the tag:\n%s", entry)
	}
}
