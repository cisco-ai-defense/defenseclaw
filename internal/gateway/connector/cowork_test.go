// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "testing"

// The Cowork vocabulary is pinned to the engine build it was measured on: a
// change here must name the build the new names were measured on.
func TestCoworkVocabularyIsPinnedToItsEngine(t *testing.T) {
	if CoworkVocabularyEngineVersion != "2.1.309" {
		t.Fatalf("CoworkVocabularyEngineVersion = %q; update this test with the build the vocabulary was re-measured on", CoworkVocabularyEngineVersion)
	}
	want := map[string]CoworkToolClass{
		"mcp__workspace__bash":                        CoworkToolShell,
		"mcp__workspace__web_fetch":                   CoworkToolFetch,
		"mcp__workspace__new_tool":                    CoworkToolWorkspace,
		"mcp__Claude_Browser__navigate":               CoworkToolBrowserNavigate,
		"mcp__Claude_Browser__javascript_tool":        CoworkToolBrowserScript,
		"mcp__Claude_Browser__form_input":             CoworkToolBrowserForm,
		"mcp__Claude_Browser__read_page":              CoworkToolBrowser,
		"mcp__Claude_Browser__computer":               CoworkToolBrowser,
		"mcp__cowork__allow_cowork_file_delete":       CoworkToolDestructive,
		"mcp__cowork__request_cowork_directory":       CoworkToolScopeChange,
		"mcp__cowork__save_skill":                     CoworkToolSkillAdmission,
		"mcp__cowork__read_widget_context":            CoworkToolDesktop,
		"mcp__scheduled-tasks__create_scheduled_task": CoworkToolPersistence,
		"mcp__scheduled-tasks__update_scheduled_task": CoworkToolPersistence,
		"mcp__scheduled-tasks__delete_scheduled_task": CoworkToolDesktop,
		"mcp__plugins__suggest_plugin_install":        CoworkToolPluginAdmission,
		"mcp__plugins__search_plugins":                CoworkToolPluginAdmission,
		"mcp__plugins__search_connectors":             CoworkToolPluginAdmission,
		"mcp__mcp-registry__search":                   CoworkToolMCPAdmission,
		"mcp__session_info__read_transcript":          CoworkToolTranscriptAccess,
		"mcp__session_info__list_sessions":            CoworkToolTranscriptAccess,
		"mcp__skills__list":                           CoworkToolDesktop,
	}
	for tool, class := range want {
		if got, ok := CoworkToolClassFor(tool); !ok || got != class {
			t.Errorf("CoworkToolClassFor(%q) = %q, %v; want %q", tool, got, ok, class)
		}
	}
	for _, tool := range []string{
		"Bash", "Read", "Write", "WebFetch", "Agent",
		"mcp__0b6c9f5e-2d1a-4c4e-9a63-0e7c5d2b1f40__search", // a connector the user added
		"mcp__workspace", "mcp__workspace__", "mcp__workspace__bash__x", "mcp__Workspace__bash", "workspace__bash",
	} {
		if class, ok := CoworkToolClassFor(tool); ok {
			t.Errorf("CoworkToolClassFor(%q) = %q; want no Cowork class", tool, class)
		}
	}
}

func TestCoworkSDKServerNeedsTheEnginesOwnServer(t *testing.T) {
	sdk := map[string]interface{}{"name": "workspace", "source": "sdk"}
	if !CoworkSDKServer("mcp__workspace__bash", sdk) {
		t.Fatal("the engine's workspace server was not recognized")
	}
	for _, tc := range []struct {
		tool   string
		server map[string]interface{}
	}{
		{"mcp__workspace__bash", nil},
		{"mcp__workspace__bash", map[string]interface{}{"name": "workspace"}},
		{"mcp__workspace__bash", map[string]interface{}{"name": "workspace", "source": "user"}},
		{"mcp__workspace__bash", map[string]interface{}{"name": "other", "source": "sdk"}},
		{"Bash", sdk},
		{"mcp__unknown__bash", map[string]interface{}{"name": "unknown", "source": "sdk"}},
	} {
		if CoworkSDKServer(tc.tool, tc.server) {
			t.Errorf("CoworkSDKServer(%q, %v) = true", tc.tool, tc.server)
		}
	}
}
