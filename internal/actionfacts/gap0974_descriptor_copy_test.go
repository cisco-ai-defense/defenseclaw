// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

// GAP-0974: a 2>&1 before a file redirect (echo K 2>&1 >> T) left the
// Windows parse partial, so the proven authorized_keys append was
// detection-only in every tier while the same line without 2>&1 blocked.
func TestGAP0974DescriptorCopyKeepsRedirectAuthoritative(t *testing.T) {
	t.Parallel()
	const target = `C:\Users\alice\.ssh\authorized_keys`
	for _, dialect := range []Dialect{DialectPowerShell, DialectCMD} {
		for _, command := range []string{
			`echo ssh-ed25519 AAAAk 2>&1 >> ` + target,
			`echo ssh-ed25519 AAAAk >> ` + target + ` 2>&1`,
		} {
			facts := Analyze(Input{
				Tool: "shell", Command: command, DialectHint: dialect,
				CWD: `C:\Users\bob\project`, ActiveHome: `C:\Users\bob`,
			})
			if facts.Parse.Status != StatusComplete {
				t.Fatalf("%s %q: status %q issues %v, want complete", dialect, command, facts.Parse.Status, facts.Parse.Issues)
			}
			found := false
			for _, path := range facts.EnforcementProjection().Paths {
				found = found || path.Access == PathAccessAppend && path.Value == target
			}
			if !found {
				t.Fatalf("%s %q: no enforceable append to %s: %#v", dialect, command, target, facts.Paths)
			}
		}
	}
	// A copy in a pipeline adds that stream to the piped data: the modeled
	// Tee pipeline stays complete without it and partial with it.
	for command, want := range map[string]ParseStatus{
		`Write-Output hi | Tee-Object out.txt`:      StatusComplete,
		`Write-Output hi 2>&1 | Tee-Object out.txt`: StatusPartial,
	} {
		facts := Analyze(Input{Tool: "shell", Command: command, DialectHint: DialectPowerShell, CWD: `C:\Users\bob\project`, ActiveHome: `C:\Users\bob`})
		if facts.Parse.Status != want {
			t.Fatalf("%q: status %q, want %q", command, facts.Parse.Status, want)
		}
	}
}
