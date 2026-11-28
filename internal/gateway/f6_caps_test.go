// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/skilldigest"
)

// GAP-0039 (fail closed past every cap), gateway side.

// Attached folders past the per-post scan cap follow the fail mode instead
// of being skipped without a receipt or a refusal.
func TestGAP0039FoldersPastThePostScanCapAreNotSkipped(t *testing.T) {
	var files, skills []map[string]any
	var within []string
	for i := 0; i <= substrateSkillFoldersMax; i++ {
		dir := fmt.Sprintf("/home/agent/.claude/skills/s%02d", i)
		body := []byte(fmt.Sprintf("---\nname: s%02d\n---\nok", i))
		files = append(files, map[string]any{"role": "skill_file", "path": dir + "/SKILL.md", "size": len(body), "sha256": "x", "content": body})
		skills = append(skills, map[string]any{"path": dir, "fp": skilldigest.Digest(map[string][]byte{"SKILL.md": body}), "attached": true})
		if i < substrateSkillFoldersMax {
			within = append(within, dir)
		}
	}
	// The cap keeps the first folders in path order; the folders within it
	// are scanned in parallel (GAP-0980/0982), so every check below is on a
	// set, never on the scan order (GAP-1058).
	scan := &fakeSkillScanner{}
	outs, alerts := gap0039DoWith(t, scan, true, gap0039Post{files: files, skills: skills})
	last := fmt.Sprintf("/home/agent/.claude/skills/s%02d", substrateSkillFoldersMax)
	var q []SubstrateQuarantine
	_ = json.Unmarshal(outs[0][substrateQuarantineField], &q)
	if len(q) != 1 || q[0].Path != last || len(alerts) == 0 {
		t.Fatalf("want only the folder past the cap refused, with an alert: %+v %v", q, alerts)
	}
	if got := scan.dirs(); !slices.Equal(got, within) {
		t.Fatalf("scanned %v, want the %d folders within the cap", got, substrateSkillFoldersMax)
	}
	for _, dir := range within {
		if !receipted(outs[0], dir) {
			t.Fatalf("no receipt for %s within the cap: %s", dir, outs[0][substrateScannedField])
		}
	}
	if receipted(outs[0], last) {
		t.Fatal("a receipt for the folder past the cap")
	}
}

// A folder that stays pending keeps its count when other folders fill the
// pending memory (it used to reset as a whole).
func TestGAP0039PendingCountSurvivesAFullMemory(t *testing.T) {
	st := &substrateState{}
	for i := 0; i < substrateSkillMaxPending-1; i++ {
		st.pendingPosts("u", "/target", "fp")
	}
	for i := 0; i < substrateAlertMemory; i++ {
		st.pendingPosts("u", fmt.Sprintf("/churn/%d", i), "fp")
		if i%1000 == 0 {
			st.pendingPosts("u", "/target", "fp") // seen in every post
		}
	}
	if n := st.pendingPosts("u", "/target", "fp"); n <= substrateSkillMaxPending {
		t.Fatalf("pending count %d after a full memory, want > %d", n, substrateSkillMaxPending)
	}
}
