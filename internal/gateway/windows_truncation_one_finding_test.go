// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// TestWindowsTruncationIsOneFinding (s7/winrecall x int/r110-b11 53fca0e1c6): a
// PowerShell call past the tokenizer's word limit or past the input bound is
// truncated by winrecall's GAP-0345 defer, and the same call may also take
// batch 11's windowsTwinCut truncation (the reading twins) and the sender
// GAP-0595 limit finding. All three are the one evaluation-limit rule
// (ACTION-COMPOUND-LIMIT): withBoundedTruncation unions the caps into a limit
// finding the call already carries and never lowers it, and the sender defer
// adds none when one is there. So the call carries ONE evaluation-limit
// finding and is never judged below the unknown tier: never a clean allow in
// default, a block in strict.
func TestWindowsTruncationIsOneFinding(t *testing.T) {
	for _, pack := range []string{"default", "strict"} {
		for name, size := range map[string]int{
			"word-limit": 6 << 10,
			// The call past the 64 KiB input bound is not a row here: one long
			// ordinary statement is left as the readers leave it (GAP-0318), and
			// the byte floor of 551f865dbb that made it a truncation is reverted
			// until psf2 returns it scoped to the Windows dialects.
		} {
			t.Run(pack+"/"+name, func(t *testing.T) {
				big := `Set-Content -Path C:\Users\alice\work\a.txt -Value '` + strings.Repeat("x", size) + `'`
				findings := windowsBoundsFindings(t, pack, "PowerShell", big, `C:\Users\alice`, pack == "strict")
				limits := 0
				for _, f := range findings {
					if canonicalTrustedRuleID(f.RuleID) == evaluationLimitRuleID {
						limits++
						if !f.contributesToEnforcement() && !f.contributesToAlertOnly() {
							t.Errorf("the limit finding decides nothing: %+v", f)
						}
						if pack == "strict" && !f.contributesToEnforcement() {
							t.Errorf("strict: the limit finding does not block: %+v", f)
						}
					}
				}
				if limits != 1 {
					t.Fatalf("%d evaluation-limit findings, want exactly one: %v", limits, FindingStrings(findings))
				}
				if windowsBoundsAllowed(findings) {
					t.Fatalf("a truncated call is a clean allow: %v", FindingStrings(findings))
				}
			})
		}
	}
}
