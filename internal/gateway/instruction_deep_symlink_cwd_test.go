// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// deepLinkedProject is a spelling of h.base, the physical project, through
// a symlink at the end of a deep directory chain: the start directory's
// full sighting (its parents and their .claude folders) does not fit in
// the hook client's evidence header.
func deepLinkedProject(t *testing.T, h *protectHomeCodexHandler) string {
	t.Helper()
	deep := h.home
	for index := range 130 {
		deep = filepath.Join(deep, fmt.Sprintf("d%04d", index))
	}
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(deep, "lnk")
	if err := os.Symlink(h.base, link); err != nil {
		t.Fatal(err)
	}
	if len(link) > hookpaths.MaxWriteTargetPathBytes {
		t.Skip("the temporary directory is too long for the deep spelling")
	}
	return link
}

// Benign corpus (round q loop 2, header overflow). A managed ProtectHome
// Codex session started in a deep symlinked spelling of its project creates
// AGENTS.md there; a later call from the short physical directory edits it.
// The start's full sighting did not fit in the evidence header, so the hook
// client sent the start directory's identity alone, and the physical
// directory keeps the start directory's first record: the file stays the
// session's own and no edit of it blocks.
func TestInstructionBenignProtectHomeDeepSymlinkedSessionCreatedFile(t *testing.T) {
	h := newProtectHomeCodexHandler(t, "action")
	link := deepLinkedProject(t, h)
	h.post("SessionStart", link, map[string]interface{}{"source": "startup"})
	if action, findings := h.patch(link, sightingAddPatch); cogBlocked(action, false, findings) {
		t.Fatalf("creating AGENTS.md through the deep link was blocked: %v", findings)
	}
	writeActiveAgentTestFile(t, h.base, "AGENTS.md")
	steps := []struct {
		name string
		run  func() (string, []string)
	}{
		{"physical patch", func() (string, []string) { return h.patch(h.base, sightingUpdatePatch) }},
		{"physical relative append", func() (string, []string) { return h.bash(h.base, "printf x >> AGENTS.md") }},
		{"physical absolute append", func() (string, []string) {
			return h.bash(h.base, "printf x >> "+filepath.Join(h.base, "AGENTS.md"))
		}},
		{"link patch", func() (string, []string) { return h.patch(link, sightingUpdatePatch) }},
	}
	for _, step := range steps {
		if action, findings := step.run(); cogBlocked(action, false, findings) {
			t.Fatalf("%s of the session's own AGENTS.md was blocked: %v", step.name, findings)
		}
	}
}

// Protected-target corpus (round q loop 2, header overflow control). The
// AGENTS.md a session started with through the deep link stays protected
// from both spellings.
func TestInstructionProtectHomeDeepSymlinkedStartupFileStaysProtected(t *testing.T) {
	h := newProtectHomeCodexHandler(t, "action")
	link := deepLinkedProject(t, h)
	writeActiveAgentTestFile(t, h.base, "AGENTS.md")
	h.post("SessionStart", link, map[string]interface{}{"source": "startup"})
	steps := []struct {
		name string
		run  func() (string, []string)
	}{
		{"link patch", func() (string, []string) { return h.patch(link, sightingUpdatePatch) }},
		{"physical patch", func() (string, []string) { return h.patch(h.base, sightingUpdatePatch) }},
		{"physical relative append", func() (string, []string) { return h.bash(h.base, "printf x >> AGENTS.md") }},
	}
	for _, step := range steps {
		if action, findings := step.run(); !cogBlocked(action, false, findings) || !findingStringHasRuleID(findings, "COG-AGENTS-MD") {
			t.Fatalf("%s of the startup AGENTS.md was not blocked: action=%q findings=%v", step.name, action, findings)
		}
	}
}
