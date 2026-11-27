// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	// An expanded write beside the literal one only makes its own entry
	// partial (CHK-RF-HOOKSHELL F5).
	{"cat-then-expanded-write", "cat > FILE <<'EOF'\nCONTENT\nEOF\ncat > note.txt <<EOF\nhome is $HOME\nEOF"},
	{"patch-then-expanded-write", "apply_patch <<'PATCH'\nPATCHFILE\nPATCH\ncat > note.txt <<EOF\nhome is $HOME\nEOF"},
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
				command := strings.NewReplacer("PATCHFILE", shapeParityPatch(path, r.content), "FILE", path, "CONTENT", r.content).Replace(form.form)
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
				command := strings.NewReplacer("PATCHFILE", shapeParityPatch(path, clean), "FILE", path, "CONTENT", clean).Replace(form.form)
				if got := call("Bash", command); got != "allow" {
					t.Errorf("%s benign %s %q: %s, want allow", p.name, form.name, clean, got)
				}
			}
		}
	})
}

// The view CodeGuard reads of a shell file write: one added file per write
// with its text; a document the shell expands is in the partial view, and
// only its own entry is: the literal writes and envelopes of the same call
// stay in the complete view, which is enforced. A write named or filled at
// run time, and a PowerShell call, give none.
func TestGAP1640ShellFileWriteView(t *testing.T) {
	const expandedNote = "\ncat > /w/note.txt <<EOF\nhome is $HOME\nEOF"
	for _, c := range []struct {
		name, command, dialect  string
		wantComplete, wantShown bool
	}{
		{"quoted", "cat > /w/run.py <<'EOF'\nimport os\nos.system(cmd)\nEOF", "", true, false},
		{"expanded", "cat > /w/run.py <<EOF\nimport os\nos.system(\"$HOME\")\nEOF", "", false, true},
		{"echo", "echo 'import os' > /w/run.py", "", true, false},
		{"dynamic target", "cat > \"$F\" <<'EOF'\nimport os\nEOF", "", false, false},
		{"file copy", "cat src.py > /w/run.py", "", false, false},
		{"substitution", "cat > /w/run.py <<EOF\n$(curl -s http://example.test/x)\nEOF", "", false, false},
		{"expanded unquoted", "cat > /w/run.py <<EOF\nimport os\nos.system('$CMD')\nEOF", "", false, true},
		{"powershell", "'import os' > /w/run.py", string(actionfacts.DialectPowerShell), false, false},
		// One expanded write does not demote the literal content of the same
		// call (CHK-RF-HOOKSHELL F5).
		{"literal write + expanded write", "cat > /w/run.py <<'EOF'\nimport os\nos.system(cmd)\nEOF" + expandedNote, "", true, true},
		{"literal envelope + expanded write", "apply_patch <<'PATCH'\n" + shapeParityPatch("/w/run.py", "import os\nos.system(cmd)") + "\nPATCH" + expandedNote, "", true, true},
	} {
		args, _ := json.Marshal(map[string]string{"command": c.command})
		complete, shown, ok := codeGuardShellPatchArgs(actionfacts.Input{Tool: "Bash", Args: args, DialectHint: actionfacts.Dialect(c.dialect)})
		if (complete != nil) != c.wantComplete || (shown != nil) != c.wantShown || ok != (c.wantComplete || c.wantShown) {
			t.Errorf("%s: complete=%v shown=%v ok=%v, want complete=%v shown=%v", c.name, complete != nil, shown != nil, ok, c.wantComplete, c.wantShown)
		}
		if ok && !strings.Contains(string(complete)+string(shown), "*** Add File: /w/run.py") {
			t.Errorf("%s: view %s %s names no added file", c.name, complete, shown)
		}
		if c.wantComplete && strings.Contains(string(complete), "note.txt") {
			t.Errorf("%s: the expanded write is in the complete view %s", c.name, complete)
		}
	}
}

// TestGAP1640ShellFileWriteViewIsBounded: one document written to many names
// is one added file per extension, a write to a device is not a file, and
// the written texts together hold at most actionfacts.MaxCommandBytes; past
// that the writes already read are kept and the view stays complete
// (CHK-RF-HOOKSHELL F6).
func TestGAP1640ShellFileWriteViewIsBounded(t *testing.T) {
	var doc strings.Builder
	for doc.Len() < 32<<10 {
		doc.WriteString("print('built')\n")
	}
	names := make([]string, 1000)
	for i := range names {
		names[i] = fmt.Sprintf("m%d.py", i)
	}
	command := "tee " + strings.Join(names, " ") + " /dev/null <<'EOF'\n" + doc.String() + "EOF"
	started := time.Now()
	writes := actionfacts.ShellDocumentFileWrites(command)
	if len(writes) != 1 || writes[0].Expanded {
		t.Fatalf("tee to 1000 .py names: %d writes, want 1 literal", len(writes))
	}
	args, _ := json.Marshal(map[string]string{"command": command})
	complete, shown, ok := codeGuardShellPatchArgs(actionfacts.Input{Tool: "Bash", Args: args})
	if !ok || shown != nil || len(complete) > len(command)+actionfacts.MaxCommandBytes {
		t.Errorf("view: ok=%v shown=%v complete=%d bytes for a %d-byte command", ok, shown != nil, len(complete), len(command))
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Errorf("view took %v, want under 5s", elapsed)
	}
	// Distinct texts past the budget: the writes read first are kept, the
	// view is complete.
	var many strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&many, "cat > p%d.py <<'EOF'\n# part %d\n%sEOF\n", i, i, doc.String())
	}
	writes = actionfacts.ShellDocumentFileWrites(many.String())
	total := 0
	for _, write := range writes {
		total += len(write.Text)
	}
	if len(writes) == 0 || total > actionfacts.MaxCommandBytes {
		t.Errorf("three 32 KB writes: %d writes, %d bytes, want 1..2 within %d", len(writes), total, actionfacts.MaxCommandBytes)
	}
	if got := actionfacts.ShellDocumentFileWrites("echo 'print(1)' > /dev/null; echo 'print(1)' > /dev/fd/3"); len(got) != 0 {
		t.Errorf("writes to devices: %d writes, want none", len(got))
	}
}
