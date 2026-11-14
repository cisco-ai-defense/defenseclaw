// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The file-unknown marker joins any identity on either role and never counts
// as a mismatch; two different exact identities still do; the terminal role
// of a partial parse needs a digest (GAP-0388, GAP-0389).
func TestSecretReadChainFileUnknownMarker(t *testing.T) {
	index, _ := ToolChainIndexByID(ToolChainSecretReadThenEgress)
	step1, _ := ToolChainStepMask(ToolChainSecretReadThenEgress, 1)
	step2, _ := ToolChainStepMask(ToolChainSecretReadThenEgress, 2)
	exactA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	exactB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	marker := ToolChainFileUnknownDigest
	now := time.Now()
	rows := []struct {
		name         string
		readStatus   actionfacts.ParseStatus
		readDigest   string
		finalStatus  actionfacts.ParseStatus
		finalDigest  string
		wantDetected bool
	}{
		{"same exact file", actionfacts.StatusComplete, exactA, actionfacts.StatusComplete, exactA, true},
		{"different exact files", actionfacts.StatusComplete, exactA, actionfacts.StatusComplete, exactB, false},
		{"read marker, exact upload", actionfacts.StatusPartial, marker, actionfacts.StatusComplete, exactA, true},
		{"exact read, upload marker", actionfacts.StatusComplete, exactA, actionfacts.StatusPartial, marker, true},
		{"both markers", actionfacts.StatusPartial, marker, actionfacts.StatusPartial, marker, true},
		{"partial upload with an exact other file", actionfacts.StatusPartial, exactA, actionfacts.StatusPartial, exactB, false},
		{"partial upload with the same file", actionfacts.StatusPartial, exactA, actionfacts.StatusPartial, exactA, true},
		{"partial upload without a digest", actionfacts.StatusComplete, exactA, actionfacts.StatusPartial, "", false},
		{"partial read without a digest", actionfacts.StatusPartial, "", actionfacts.StatusComplete, exactA, false},
		{"partial read, complete upload without digest", actionfacts.StatusPartial, marker, actionfacts.StatusComplete, "", true},
	}
	for _, row := range rows {
		var prior, final ToolChainProjection
		prior.ParseStatus, final.ParseStatus = row.readStatus, row.finalStatus
		prior.DetectionStepMask, final.DetectionStepMask = step1, step2
		prior.EnforcementJoinDigests[index] = row.readDigest
		final.EnforcementJoinDigests[index] = row.finalDigest
		matches, err := MatchToolChains(
			[]ToolChainWindowEvent{{SemanticEventID: "read", Sequence: 1, ReceivedAt: now, Projection: prior}},
			ToolChainWindowEvent{SemanticEventID: "send", Sequence: 2, ReceivedAt: now.Add(time.Second), Projection: final},
		)
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		detected := matches.DetectedMask&definitionResultBit(ToolChainSecretReadThenEgress) != 0
		if detected != row.wantDetected {
			t.Errorf("%s: detected = %t, want %t", row.name, detected, row.wantDetected)
		}
		if matches.EnforcementSafeMask != 0 {
			t.Errorf("%s: a detection-only chain must not enforce", row.name)
		}
	}
	if len(marker) != 64 {
		t.Errorf("marker %q is not a sha256 digest", marker)
	}
}

func definitionResultBit(id string) uint32 {
	index, _ := ToolChainIndexByID(id)
	return toolChainDefinitions[index].ResultBit
}
