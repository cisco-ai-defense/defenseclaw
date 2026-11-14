// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"strings"
	"testing"
)

// rel-1-0-10 GAP-0279: an actor starts Claude Code with
// CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG=1. Measured on Claude Code 2.1.311
// (image e-osh24-sandbox, evidence/substrate-1/g279/claude-2.1.311-scope.txt):
//   - a plugin installed from a marketplace loads at user, project and local
//     scope, with or without the flag (the files sit in ~/.claude/plugins/cache
//     and the scope comes from installed_plugins.json and enabledPlugins in
//     ~/.claude/settings.json, <project>/.claude/settings.json or
//     settings.local.json);
//   - a plugin folder directly in the personal skills folder
//     (~/.claude/skills/NAME) loads as a plugin without the flag and loads as
//     skills only with it ("[skill-as-plugin] not loading plugins from ...").
//
// The scan says so in a note for the second case. It is not a finding and it
// changes no verdict.

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

func TestScanNotesAPluginInThePersonalSkillsFolderDoesNotLoadAsAPlugin(t *testing.T) {
	sum := scanNotes(t, tarFile{path: "/home/agent/.claude/skills/demo/.claude-plugin/plugin.json", mode: 0o644, data: pluginManifest})
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
	for _, want := range []string{"personal skills folder", "does not load as a plugin in Substrate actors", "personal config is restricted", "loads it as skills only", "project or managed scope", "demo"} {
		if !strings.Contains(sum.Notes[0], want) {
			t.Errorf("note %q lacks %q", sum.Notes[0], want)
		}
	}
}

func TestScanNoNoteForPluginsThatLoad(t *testing.T) {
	sum := scanNotes(t,
		// Marketplace installs: the files sit in the cache whichever settings
		// file (user, project, local, managed) enables them, and they load.
		tarFile{path: "/home/agent/.claude/plugins/cache/mkt/user-enabled/1.0.0/.claude-plugin/plugin.json", mode: 0o644, data: pluginManifest},
		tarFile{path: "/home/agent/.claude/plugins/cache/mkt/project-enabled/1.0.0/.claude-plugin/plugin.json", mode: 0o644, data: pluginManifest},
		tarFile{path: "/home/agent/.claude/settings.json", mode: 0o644, data: `{"enabledPlugins":{"user-enabled@mkt":true}}`},
		tarFile{path: "/work/.claude/settings.json", mode: 0o644, data: `{"enabledPlugins":{"project-enabled@mkt":true}}`},
		// A project skills folder and the managed folder are not personal.
		tarFile{path: "/work/.claude/skills/proj/.claude-plugin/plugin.json", mode: 0o644, data: pluginManifest},
		tarFile{path: "/etc/claude-code/.claude/skills/managed/.claude-plugin/plugin.json", mode: 0o644, data: pluginManifest},
		// A Codex plugin is not affected by the Claude Code flag.
		tarFile{path: "/home/agent/.codex/plugins/cx/.codex-plugin/plugin.json", mode: 0o644, data: pluginManifest})
	if sum.Plugins != 5 {
		t.Fatalf("plugins scanned = %d, want 5", sum.Plugins)
	}
	if len(sum.Notes) != 0 {
		t.Fatalf("notes = %q, want none for plugins that load", sum.Notes)
	}
}

func TestScanNoNoteWithoutPlugins(t *testing.T) {
	if sum := scanNotes(t); len(sum.Notes) != 0 {
		t.Fatalf("notes = %q, want none", sum.Notes)
	}
}
