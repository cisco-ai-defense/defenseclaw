// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-10:GAP-1635: Codex 0.169 writes files by running exec_command with
// `apply_patch <<PATCH ... PATCH`, which reaches the hook as a Bash call. Its
// envelope is the same patch the native apply_patch tool carries, so CodeGuard
// judges its content as it judges the native tool and Claude Code Write, in
// every tier. The file builds only on helpers that exist at rel 8e58b26846,
// so the same test runs at rel, at the FU12 tip and at the fix.

var fx1635Rank = map[string]int{"allow": 0, "": 0, "alert": 2, "warn": 2, "confirm": 2, "ask": 2, "block": 3}

func fx1635Hook(t *testing.T, h http.HandlerFunc, conn, name string, body map[string]any, headers map[string]string, managedTier bool) string {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+conn+"/hook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if managedTier {
		if ev := hookpaths.ResolveConnector(conn, "", "PreToolUse", raw); ev != "" {
			req.Header.Set(hookpaths.Header, ev)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: http %d", name, w.Code)
	}
	var resp struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%s: answer is not JSON", name)
	}
	return resp.Action
}

// fx1635HeredocForms are the here-document spellings of the patch command, as
// Codex sends it and as a shell reads it the same way.
var fx1635HeredocForms = []struct{ name, open, close string }{
	{"bare", "apply_patch <<PATCH\n", "\nPATCH"},
	{"quoted", "apply_patch <<'PATCH'\n", "\nPATCH"},
	{"dquoted-eof", "apply_patch <<\"EOF\"\n", "\nEOF"},
	{"cd-prefix", "cd /tmp && apply_patch <<'PATCH'\n", "\nPATCH"},
}

func TestFX1635CodexHeredocApplyPatchIsCodeGuardScanned(t *testing.T) {
	rows := []struct{ id, file, content string }{
		{"CG-EXEC-001", "run.py", "import os\ndef go(cmd):\n    os.system(cmd)"},
		{"CG-DESER-001", "load.py", "import pickle\ndef load(data):\n    return pickle.loads(data)"},
		{"CG-NET-001", "fetch.py", "import requests\ndef fetch(url):\n    return requests.get(url)"},
		// The cert marker of FC-RHEL-10 (cg2.py).
		{"CG-MARKER", "cg2.py", "import os, pickle, requests\nos.system(cmd)\nrequests.get(url)\npickle.loads(data)"},
	}
	codexHeaders := map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cx := gap0437Server(t, p, "codex", "action")
		installToolCallCorpusProfileConnector(t, "codex", p.pack)
		hook := cx.handleAgentHook("codex")
		call := func(tool, command string) string {
			return fx1635Hook(t, hook, "codex", "codex/"+tool, shapeParityEnvelope("PreToolUse", t.TempDir(), tool,
				map[string]any{"command": command}), codexHeaders, p.managed)
		}
		cwd := t.TempDir()
		for _, r := range rows {
			envelope := shapeParityPatch(filepath.Join(cwd, r.file), r.content)
			native := call("apply_patch", envelope)
			if (p.pack == "default" || p.pack == "strict") && fx1635Rank[native] < fx1635Rank["alert"] {
				t.Errorf("%s %s: the native apply_patch baseline is %q, the fixture proves nothing", p.name, r.id, native)
			}
			for _, form := range fx1635HeredocForms {
				if got := call("Bash", form.open+envelope+form.close); fx1635Rank[got] < fx1635Rank[native] {
					t.Errorf("%s %s %s: Bash heredoc apply_patch %q is weaker than the native apply_patch %q", p.name, r.id, form.name, got, native)
				}
			}
		}
		// Benign twins: clean code through the heredoc patch is allowed, as
		// through the native tool. A document the shell expands keeps the
		// verdict of its unplaced headers (GAP-1093), so only the quoted
		// forms carry the expansion-shaped twin.
		for _, clean := range []string{"def add(a, b):\n    return a + b", "home = \"$HOME\"\nprint(home)"} {
			envelope := shapeParityPatch(filepath.Join(cwd, "ok.py"), clean)
			if got := call("apply_patch", envelope); got != "allow" {
				t.Fatalf("%s benign native apply_patch %q: %s, want allow", p.name, clean, got)
			}
			for _, form := range fx1635HeredocForms {
				if strings.Contains(clean, "$") && !strings.Contains(form.open, "'") && !strings.Contains(form.open, "\"") {
					continue
				}
				if got := call("Bash", form.open+envelope+form.close); got != "allow" {
					t.Errorf("%s benign %s %q: %s, want allow", p.name, form.name, clean, got)
				}
			}
		}
	})
}

// The view CodeGuard reads of a shell call: an envelope fed by a document
// the shell expands is the partial view (its findings are shown, never
// enforced by CodeGuard alone), a literal one the complete view, and shell
// text that only names apply_patch or writes code another way is no patch.
func TestFX1635ShellPatchArgsView(t *testing.T) {
	env := shapeParityPatch("/w/run.py", "import os\nos.system(cmd)")
	for _, c := range []struct {
		name, command           string
		wantComplete, wantShown bool
	}{
		{"quoted", "apply_patch <<'PATCH'\n" + env + "\nPATCH", true, false},
		{"expanded", "apply_patch <<PATCH\n" + strings.Replace(env, "os.system(cmd)", "os.system(\"$HOME\")", 1) + "\nPATCH", false, true},
		{"echo-only", "echo 'apply_patch *** Begin Patch'", false, false},
		// A file written from a literal document is an added file of the
		// view (rel-1-0-10:GAP-1640).
		{"cat-heredoc", "cat > /w/run.py <<'EOF'\n*** Begin Patch\nimport os\nEOF\n# apply_patch", true, false},
		// A data here-document that names the patch markers and is written
		// nowhere is no envelope.
		{"data-heredoc", "cat <<'EOF' | wc -l\n*** Begin Patch\nEOF\n# apply_patch", false, false},
		{"argv-free-text", "printf '%s' apply_patch", false, false},
	} {
		args, _ := json.Marshal(map[string]string{"command": c.command})
		complete, shown, ok := codeGuardShellPatchArgs(actionfacts.Input{Tool: "Bash", Args: args})
		if (complete != nil) != c.wantComplete || (shown != nil) != c.wantShown || ok != (c.wantComplete || c.wantShown) {
			t.Errorf("%s: complete=%v shown=%v ok=%v, want complete=%v shown=%v", c.name, complete != nil, shown != nil, ok, c.wantComplete, c.wantShown)
		}
		if ok && !strings.Contains(string(complete)+string(shown), "*** Add File: /w/run.py") {
			t.Errorf("%s: view %s %s holds no envelope", c.name, complete, shown)
		}
	}
}
