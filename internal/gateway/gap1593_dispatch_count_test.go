// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGAP1593ProcessSubstitutionShellDispatches: sh < <(cat <<EOF ... EOF)
// is read as bash -c SCRIPT (rel-1-0-10:GAP-1147). The twin kept the
// redirect, so its dispatch judged the same here-document again as a child
// of its own: 10 dispatches per hook call on the openclaw exec route (2
// reading passes of the call, each with the twin, the twin's cat child, its
// whole-statement child and the script), where the call alone took 2. The
// twin leaves the redirect out as it does a here-document (GAP-1088): 8, and
// the verdict stays the one the twin proves, the direct form's
// (sh <<'EOF'). The last 6 go with the twin itself, when the effects reading
// of nested bodies replaces it (DET111 step 3).
func TestGAP1593ProcessSubstitutionShellDispatches(t *testing.T) {
	a := gap0437Server(t, gap0437Packs[0], "openclaw", "action")
	a.inspectToolScanTimeout = time.Minute
	dir := t.TempDir()
	runs := func(command string) (int, string) {
		count := 0
		trustedDispatchRunHook = func(trustedActionRequest) { count++ }
		defer func() { trustedDispatchRunHook = nil }()
		raw, _ := json.Marshal(map[string]any{"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": command, "workdir": dir}})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		a.handleInspectTool(rec, req)
		var verdict struct {
			Action string `json:"action"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &verdict); err != nil {
			t.Fatalf("%q: %v (%s)", command, err, rec.Body.String())
		}
		return count, verdict.Action
	}
	direct, directAction := runs("sh <<'EOF'\ndefenseclaw stop\nEOF")
	got, action := runs("sh < <(cat <<'EOF'\ndefenseclaw stop\nEOF\n)")
	t.Logf("GAP1593 dispatches: process substitution %d (%s), direct form %d (%s)", got, action, direct, directAction)
	if got > 8 {
		t.Errorf("sh < <(cat <<EOF ... EOF) costs %d dispatches, want at most 8 (its direct form sh <<EOF: %d)", got, direct)
	}
	if action != directAction {
		t.Errorf("sh < <(cat <<EOF ... EOF) is %s, its direct form %s", action, directAction)
	}
}
