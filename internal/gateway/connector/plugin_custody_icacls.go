// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// icaclsRefusedEntry is one refused entry of a plugin folder DACL: the account
// as icacls takes it, whether it is a deny entry, and every folder or file that
// holds the entry as its own.
type icaclsRefusedEntry struct {
	trustee  string
	deny     bool
	carriers []string
}

// icaclsRemovalFix is the PowerShell command line that clears every refused
// entry (GAP-0731): for each account, the account is removed at each folder
// that holds its entry, because removing it from an inheriting child does
// nothing and one granted again higher up is inherited again. A DACL can
// refuse several accounts, so each gets its own commands; stopping at the first
// leaves the refusal in place. Commands are separated by a semicolon, which
// PowerShell runs in turn (&& is not available in Windows PowerShell 5). The
// path and the account are inert single-quoted literals (managed.PowerShellLiteral),
// so a folder name that holds a dollar sign or a backtick reaches icacls as it
// is. failing is every folder or file named, outermost first, once each.
func icaclsRemovalFix(entries []icaclsRefusedEntry) (fix string, failing []string) {
	var steps []string
	seen := map[string]bool{}
	for _, entry := range entries {
		scope := ":g"
		if entry.deny {
			scope = ":d"
		}
		for _, carrier := range entry.carriers {
			steps = append(steps, "icacls "+managed.PowerShellLiteral(carrier)+" /remove"+scope+" "+managed.PowerShellLiteral(entry.trustee))
			if !seen[carrier] {
				seen[carrier] = true
				failing = append(failing, carrier)
			}
		}
	}
	sort.SliceStable(failing, func(i, j int) bool { return len(failing[i]) < len(failing[j]) })
	return strings.Join(steps, "; "), failing
}
