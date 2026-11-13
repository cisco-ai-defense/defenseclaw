// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0279: an actor starts Claude Code with
// CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG=1, so a user-scope plugin in the
// template is scanned and admitted but never loads. The scan says so in a
// note; it is not a finding and changes no verdict.

const pluginManifest = `{"name":"demo"}`

func scanNotes(t *testing.T, extra ...tarFile) ScanSummary {
	t.Helper()
	f := newFixture(t, extra...)
	res, err := f.build(t, func(o *BuildOptions) { o.DryRun = true })
	if err != nil {
		t.Fatal(err)
	}
	return res.Report.Summary
}

func TestScanNotesThatUserScopePluginsDoNotLoad(t *testing.T) {
	sum := scanNotes(t, tarFile{path: "/home/agent/.claude/plugins/demo/.claude-plugin/plugin.json", mode: 0o644, data: pluginManifest})
	if sum.Plugins != 1 {
		t.Fatalf("plugins scanned = %d, want 1 (the plugin is still scanned and admitted)", sum.Plugins)
	}
	if sum.Verdict != VerdictClean {
		t.Fatalf("verdict %q: the note must not change the verdict", sum.Verdict)
	}
	for _, it := range sum.Items {
		if it.Verdict != VerdictClean || it.Findings != 0 {
			t.Fatalf("item %+v: the note is not a finding", it)
		}
	}
	if len(sum.Notes) != 1 {
		t.Fatalf("notes = %q, want exactly one", sum.Notes)
	}
	for _, want := range []string{"user-scope plugins do not load in Substrate actors", "personal config is restricted", "project or managed scope", "demo"} {
		if !strings.Contains(sum.Notes[0], want) {
			t.Errorf("note %q lacks %q", sum.Notes[0], want)
		}
	}
}

func TestScanNoNoteForProjectOrManagedScopePlugins(t *testing.T) {
	sum := scanNotes(t,
		tarFile{path: "/work/.claude/plugins/proj/.claude-plugin/plugin.json", mode: 0o644, data: pluginManifest},
		tarFile{path: "/etc/claude-code/plugins/managed/.claude-plugin/plugin.json", mode: 0o644, data: pluginManifest},
		// A Codex plugin is not affected by the Claude Code flag.
		tarFile{path: "/home/agent/.codex/plugins/cx/.codex-plugin/plugin.json", mode: 0o644, data: pluginManifest})
	if sum.Plugins != 3 {
		t.Fatalf("plugins scanned = %d, want 3", sum.Plugins)
	}
	if len(sum.Notes) != 0 {
		t.Fatalf("notes = %q, want none for project, managed or Codex plugins", sum.Notes)
	}
}

func TestScanNoNoteWithoutPlugins(t *testing.T) {
	if sum := scanNotes(t); len(sum.Notes) != 0 {
		t.Fatalf("notes = %q, want none", sum.Notes)
	}
}
