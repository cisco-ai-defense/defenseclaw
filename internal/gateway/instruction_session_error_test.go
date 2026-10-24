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
	for _, event := range []string{"SessionEnd", "on_session_end", "on_session_finalize", "session.deleted"} {
		api.applyInstructionStartup(auth, "opencode", event, "session.created", project)
		api.applyInstructionStartup(auth, "opencode", event, event, project)
		if got := api.applyInstructionStartup(auth, "opencode", event, "tool.execute.before", project); got.startupKnown {
			t.Fatalf("%s retained ended session snapshot: %+v", event, got)
		}
	}
}
