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
		// wantFileUnknown: the chain joined only through the marker on the
		// read (FileUnknownJoinMask); an exact or absent read identity is
		// resolved, whatever the upload carries.
		wantFileUnknown bool
	}{
		{"same exact file", actionfacts.StatusComplete, exactA, actionfacts.StatusComplete, exactA, true, false},
		{"different exact files", actionfacts.StatusComplete, exactA, actionfacts.StatusComplete, exactB, false, false},
		{"read marker, exact upload", actionfacts.StatusPartial, marker, actionfacts.StatusComplete, exactA, true, true},
		{"exact read, upload marker", actionfacts.StatusComplete, exactA, actionfacts.StatusPartial, marker, true, false},
		{"both markers", actionfacts.StatusPartial, marker, actionfacts.StatusPartial, marker, true, true},
		{"partial upload with an exact other file", actionfacts.StatusPartial, exactA, actionfacts.StatusPartial, exactB, false, false},
		{"partial upload with the same file", actionfacts.StatusPartial, exactA, actionfacts.StatusPartial, exactA, true, false},
		{"partial upload without a digest", actionfacts.StatusComplete, exactA, actionfacts.StatusPartial, "", false, false},
		{"partial read without a digest", actionfacts.StatusPartial, "", actionfacts.StatusComplete, exactA, false, false},
		{"partial read, complete upload without digest", actionfacts.StatusPartial, marker, actionfacts.StatusComplete, "", true, true},
		{"complete read without a digest, exact upload", actionfacts.StatusComplete, "", actionfacts.StatusComplete, exactA, true, false},
		{"exact read, complete upload without digest", actionfacts.StatusComplete, exactA, actionfacts.StatusComplete, "", true, false},
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
		fileUnknown := matches.FileUnknownJoinMask&definitionResultBit(ToolChainSecretReadThenEgress) != 0
		if fileUnknown != row.wantFileUnknown || matches.FileUnknownJoinMask&^matches.DetectedMask != 0 {
			t.Errorf("%s: file-unknown mask %#x (detected %#x), want file-unknown %t",
				row.name, matches.FileUnknownJoinMask, matches.DetectedMask, row.wantFileUnknown)
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

// A chain is file-unknown only when EVERY read that completes it carries the
// marker: one exact read of the uploaded file (or a read with no identity)
// resolves it; an exact read of another file does not complete it, so it
// does not resolve it either.
func TestSecretReadChainFileUnknownMaskNeedsEveryJoiningRead(t *testing.T) {
	index, _ := ToolChainIndexByID(ToolChainSecretReadThenEgress)
	step1, _ := ToolChainStepMask(ToolChainSecretReadThenEgress, 1)
	step2, _ := ToolChainStepMask(ToolChainSecretReadThenEgress, 2)
	bit := definitionResultBit(ToolChainSecretReadThenEgress)
	exactA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	exactB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	now := time.Now()
	read := func(seq uint64, status actionfacts.ParseStatus, digest string) ToolChainWindowEvent {
		var p ToolChainProjection
		p.ParseStatus, p.DetectionStepMask = status, step1
		p.EnforcementJoinDigests[index] = digest
		return ToolChainWindowEvent{SemanticEventID: "read", Sequence: seq, ReceivedAt: now.Add(time.Duration(seq) * time.Second), Projection: p}
	}
	var upload ToolChainProjection
	upload.ParseStatus, upload.DetectionStepMask = actionfacts.StatusComplete, step2
	upload.EnforcementJoinDigests[index] = exactA
	final := ToolChainWindowEvent{SemanticEventID: "send", Sequence: 3, ReceivedAt: now.Add(time.Minute), Projection: upload}
	for _, row := range []struct {
		name            string
		window          []ToolChainWindowEvent
		wantFileUnknown bool
	}{
		{"marker read, then exact read of the uploaded file", []ToolChainWindowEvent{
			read(1, actionfacts.StatusPartial, ToolChainFileUnknownDigest), read(2, actionfacts.StatusComplete, exactA)}, false},
		{"exact read of the uploaded file, then marker read", []ToolChainWindowEvent{
			read(1, actionfacts.StatusComplete, exactA), read(2, actionfacts.StatusPartial, ToolChainFileUnknownDigest)}, false},
		{"marker read and an exact read of another file", []ToolChainWindowEvent{
			read(1, actionfacts.StatusPartial, ToolChainFileUnknownDigest), read(2, actionfacts.StatusComplete, exactB)}, true},
		{"two marker reads", []ToolChainWindowEvent{
			read(1, actionfacts.StatusPartial, ToolChainFileUnknownDigest), read(2, actionfacts.StatusPartial, ToolChainFileUnknownDigest)}, true},
		{"marker read and a read without identity", []ToolChainWindowEvent{
			read(1, actionfacts.StatusPartial, ToolChainFileUnknownDigest), read(2, actionfacts.StatusComplete, "")}, false},
	} {
		matches, err := MatchToolChains(row.window, final)
		if err != nil {
			t.Fatalf("%s: %v", row.name, err)
		}
		if matches.DetectedMask&bit == 0 {
			t.Fatalf("%s: chain not detected", row.name)
		}
		if got := matches.FileUnknownJoinMask&bit != 0; got != row.wantFileUnknown {
			t.Errorf("%s: file-unknown %t, want %t", row.name, got, row.wantFileUnknown)
		}
	}
}
