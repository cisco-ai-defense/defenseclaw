// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// rel-1-0-10:GAP-1046. The glob compare charged one work unit per probe, not
// the bytes path.Match scans, so the Time cap did not track the real cost of
// a long glob word. A compare now charges the bytes of the segment it reads.
func TestGAP1046GlobCompareChargesTheBytesItReads(t *testing.T) {
	dir := t.TempDir()
	command := "sed -n p .env ." + strings.Repeat("*a", 200)
	analyze := func(limits credentialPathLimits) *credentialPathRecord {
		t.Helper()
		out := parsePOSIX(command, 1, 0)
		classifyOutput(&out)
		return resolveCredentialPathReadsWithin(NewCredentialWalkBudget(context.Background()), limits, out.credentialWords, dir, dir, out.commands, out.paths)
	}
	if record := analyze(credentialPathLimits{candidates: 64, work: 4096, lookups: 64}); record == nil || !record.caps.Has(bounded.Time) {
		t.Fatalf("a 400-byte glob word under a 4096-unit work cap did not report the Time cap: %+v", record)
	}
	if record := analyze(defaultCredentialPathLimits); record == nil || record.caps.Any() {
		t.Fatalf("under the default caps the resolve truncated: %+v", record)
	}
}
