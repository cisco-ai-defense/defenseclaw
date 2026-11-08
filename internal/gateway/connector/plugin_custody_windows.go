// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// pluginCustodyQuote writes p for a PowerShell command line as the repair
// does (managed.PowerShellLiteral), and only when it needs it.
func pluginCustodyQuote(p string) string {
	if p != "" && strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@%+=:,./\\-") == "" {
		return p
	}
	return managed.PowerShellLiteral(p)
}

// explainPluginArtifactRefusal adds the command that clears a refused plugin
// folder DACL to the refusal (GAP-0731). safefile names every account whose
// entry makes the DACL unsafe and every folder that holds each entry itself;
// icaclsRemovalFix removes each account at each of them. Any other cause, and a
// DACL refusal that names no single entry or cannot place one of its entries,
// is returned unchanged.
func explainPluginArtifactRefusal(_ string, cause error) error {
	var refusal *safefile.UnsafePrivateDACLError
	if !errors.As(cause, &refusal) || len(refusal.Entries) == 0 {
		return cause
	}
	entries := make([]icaclsRefusedEntry, 0, len(refusal.Entries))
	for _, entry := range refusal.Entries {
		if entry.Trustee == "" || len(entry.Carriers) == 0 {
			// A repair that leaves one refused entry in place is not offered.
			return cause
		}
		entries = append(entries, icaclsRefusedEntry{trustee: entry.Trustee, deny: entry.Deny, carriers: entry.Carriers})
	}
	fix, failing := icaclsRemovalFix(entries)
	return &pluginCustodyError{cause: cause, failing: failing, fix: fix}
}
