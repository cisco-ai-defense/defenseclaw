// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstructionStartupSurvivesNonterminalSessionError(t *testing.T) {
	project := t.TempDir()
	dataDir := t.TempDir()
	newGateway := func() *APIServer {
		api := instructionProtectionTestAPI(t, "opencode", "action", "HIGH")
		api.scannerCfg.DataDir = dataDir
		return api
	}
	api := newGateway()
	auth := withAuthenticatedHookConnector(t.Context(), "opencode")
	api.applyInstructionStartup(auth, "opencode", "first", "session.created", project)
	if err := os.WriteFile(filepath.Join(project, "AGENTS.md"), []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	api.applyInstructionStartup(auth, "opencode", "first", "session.error", project)
	if got := api.applyInstructionStartup(auth, "opencode", "first", "tool.execute.before", project); !got.startupKnown || len(got.startupFiles) != 0 {
		t.Fatalf("session.error discarded startup absence: %+v", got)
	}
	api = newGateway()
	if got := api.applyInstructionStartup(auth, "opencode", "first", "tool.execute.before", project); !got.startupKnown || len(got.startupFiles) != 0 {
		t.Fatalf("restart lost startup absence after session.error: %+v", got)
	}
	// An ended session's record is gone: a later call takes a first
	// sighting, in which the AGENTS.md that exists now is protected.
	agents := filepath.Join(project, "AGENTS.md")
	for _, event := range []string{"SessionEnd", "on_session_end", "on_session_finalize", "session.deleted"} {
		if err := os.Remove(agents); err != nil {
			t.Fatal(err)
		}
		api.applyInstructionStartup(auth, "opencode", event, "session.created", project)
		if err := os.WriteFile(agents, []byte("new\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		api.applyInstructionStartup(auth, "opencode", event, event, project)
		got := api.applyInstructionStartup(auth, "opencode", event, "tool.execute.before", project)
		if normalized, ok := activeAgentInstructionPath(agents, instructionHostFlavor()); !ok ||
			got.startupKnown && got.startupFiles[normalized] == "" {
			t.Fatalf("%s retained ended session snapshot: %+v", event, got)
		}
	}
}
