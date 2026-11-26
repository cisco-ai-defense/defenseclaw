// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap1640Forms write CONTENT to FILE from a shell call: a here-document to a
// redirect or to tee, a here-string, and a printf. A literal document is the
// file's content, so CodeGuard judges it as it judges a write tool with the
// same content (rel-1-0-10:GAP-1640; only the apply_patch here-document form
// of GAP-1635 was read).
var gap1640Forms = []struct{ name, form string }{
	{"cat-redirect", "cat > FILE <<'EOF'\nCONTENT\nEOF"},
	{"cat-redirect-after", "cat <<'EOF' > FILE\nCONTENT\nEOF"},
	{"tee", "tee FILE <<'EOF'\nCONTENT\nEOF"},
	{"tee-quiet", "tee FILE > /dev/null <<'EOF'\nCONTENT\nEOF"},
	{"cd-then-cat", "cd /tmp && cat > FILE <<'EOF'\nCONTENT\nEOF"},
	{"cat-then-run", "cat > FILE <<'EOF'\nCONTENT\nEOF\npython3 FILE"},
	{"append", "cat >> FILE <<'EOF'\nCONTENT\nEOF"},
}

func TestGAP1640ShellDocumentWriteIsCodeGuardScanned(t *testing.T) {
	rows := []struct{ id, file, content string }{
		{"CG-EXEC-001", "run.py", "import os\ndef go(cmd):\n    os.system(cmd)"},
		{"CG-DESER-001", "load.py", "import pickle\ndef load(data):\n    return pickle.loads(data)"},
		// The cert marker of FC-RHEL-10 (cg11.py).
		{"CG-MARKER", "cg11.py", "import os, pickle, requests\nos.system(cmd)\nrequests.get(url)\npickle.loads(data)"},
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
			path := filepath.Join(cwd, r.file)
			native := call("apply_patch", shapeParityPatch(path, r.content))
			if (p.pack == "default" || p.pack == "strict") && fx1635Rank[native] < fx1635Rank["alert"] {
				t.Errorf("%s %s: the native apply_patch baseline is %q, the fixture proves nothing", p.name, r.id, native)
			}
			for _, form := range gap1640Forms {
				command := strings.NewReplacer("FILE", path, "CONTENT", r.content).Replace(form.form)
				if got := call("Bash", command); fx1635Rank[got] < fx1635Rank[native] {
					t.Errorf("%s %s %s: the shell write %q is weaker than the native apply_patch %q", p.name, r.id, form.name, got, native)
				}
			}
		}
		// Clean code written the same ways stays allowed, as through the
		// native tool.
		for _, clean := range []string{"def add(a, b):\n    return a + b", "print('built')"} {
			path := filepath.Join(cwd, "ok.py")
			if got := call("apply_patch", shapeParityPatch(path, clean)); got != "allow" {
				t.Fatalf("%s benign native apply_patch %q: %s, want allow", p.name, clean, got)
			}
			for _, form := range gap1640Forms {
				command := strings.NewReplacer("FILE", path, "CONTENT", clean).Replace(form.form)
				if got := call("Bash", command); got != "allow" {
					t.Errorf("%s benign %s %q: %s, want allow", p.name, form.name, clean, got)
				}
			}
		}
	})
}

// The view CodeGuard reads of a shell file write: one added file per write
// with its text; a document the shell expands is a partial view; a write
// named or filled at run time, and a PowerShell call, give none.
func TestGAP1640ShellFileWriteView(t *testing.T) {
	for _, c := range []struct {
		name, command, dialect string
		ok, wantPartial        bool
	}{
		{"quoted", "cat > /w/run.py <<'EOF'\nimport os\nos.system(cmd)\nEOF", "", true, false},
		{"expanded", "cat > /w/run.py <<EOF\nimport os\nos.system(\"$HOME\")\nEOF", "", true, true},
		{"echo", "echo 'import os' > /w/run.py", "", true, false},
		{"dynamic target", "cat > \"$F\" <<'EOF'\nimport os\nEOF", "", false, false},
		{"file copy", "cat src.py > /w/run.py", "", false, false},
		{"substitution", "cat > /w/run.py <<EOF\n$(curl -s http://example.test/x)\nEOF", "", false, false},
		{"expanded unquoted", "cat > /w/run.py <<EOF\nimport os\nos.system('$CMD')\nEOF", "", true, true},
		{"powershell", "'import os' > /w/run.py", string(actionfacts.DialectPowerShell), false, false},
	} {
		args, _ := json.Marshal(map[string]string{"command": c.command})
		got, partial, ok := codeGuardShellPatchArgs(actionfacts.Input{Tool: "Bash", Args: args, DialectHint: actionfacts.Dialect(c.dialect)})
		if ok != c.ok || partial != c.wantPartial {
			t.Errorf("%s: ok=%v partial=%v, want ok=%v partial=%v", c.name, ok, partial, c.ok, c.wantPartial)
		}
		if ok && !strings.Contains(string(got), "*** Add File: /w/run.py") {
			t.Errorf("%s: view %s names no added file", c.name, got)
		}
	}
}
