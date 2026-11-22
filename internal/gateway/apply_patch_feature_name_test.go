//go:build !windows

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestApplyPatchFeatureNamedSourceIsNoKeyWrite is rel-1-0-10:GAP-0432: a
// call that reads or searches source files named for the authorized-keys
// feature (semantic_authorized_keys_proof.go,
// authorized_keys_symlink_write_test.go) and that holds the word apply_patch
// on a line with a list or pipe operator was read as an apply_patch of
// unknown targets, and the bare substring authorized_keys in a file name
// then named a protected target. The protected name is a whole name: a
// longer file or test name names no protected file, in every tier. A call
// that names the keys file or the SSH folder as a word still blocks.
func TestApplyPatchFeatureNamedSourceIsNoKeyWrite(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(project, "internal", "gateway"), filepath.Join(project, "internal", "hookpaths"), filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"internal/gateway/semantic_authorized_keys_proof.go", "internal/gateway/authorized_keys_symlink_write_test.go", "internal/hookpaths/applypatch.go"} {
		if err := os.WriteFile(filepath.Join(project, f), []byte("package x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	envelope := func(path string) string {
		return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-package x\n+package y\n*** End Patch\n"
	}
	type row struct {
		id, tool, command string
		block             bool
	}
	rows := []row{
		// GAP-0432 shapes: read-only shell calls.
		{"R1-cat-pipe-rg", "Bash", `cat internal/gateway/semantic_authorized_keys_proof.go | rg apply_patch`, false},
		{"R2-rg-alternation", "Bash", `rg -n "PatchCallNamesProtectedTarget|apply_patch" internal/gateway/semantic_authorized_keys_proof.go`, false},
		{"R3-rg-and-sed", "Bash", `rg -n 'apply_patch' internal/gateway/authorized_keys_symlink_write_test.go && sed -n 1,40p internal/hookpaths/applypatch.go`, false},
		{"R4-gitlog-and-rg", "Bash", `git log --oneline -5 -- internal/gateway/semantic_authorized_keys_proof.go && rg -c apply_patch internal/`, false},
		{"R5-diff-pipe-rg", "Bash", `git diff internal/gateway/semantic_authorized_keys_proof.go | rg -n 'apply_patch'`, false},
		{"R6-sed-semicolon", "Bash", `sed -n 1,80p internal/gateway/semantic_authorized_keys_proof.go; rg -n apply_patch internal/hookpaths/applypatch.go`, false},
		// GAP-0432 shapes: native patches of the feature's own sources.
		{"N1-native-test-file", "apply_patch", envelope("internal/gateway/authorized_keys_symlink_write_test.go"), false},
		{"N2-native-abs-source", "apply_patch", envelope(filepath.Join(project, "internal/gateway/semantic_authorized_keys_proof.go")), false},
		{"N3-native-rel-source", "apply_patch", envelope("internal/gateway/semantic_authorized_keys_proof.go"), false},
		// Benign twins a developer runs.
		{"B1-rg-head", "Bash", `rg -n apply_patch internal/ | head -20`, false},
		{"B2-test-and-diff", "Bash", `go test ./internal/hookpaths -run ApplyPatch && git diff --stat`, false},
		{"B3-grep-wc", "Bash", `grep -rn apply_patch docs/ | wc -l`, false},
		// Calls that name the keys file or the SSH folder keep the block.
		{"K1-heredoc-keys", "Bash", "apply_patch <<'EOF'\n" + envelope(filepath.Join(home, ".ssh", "authorized_keys")) + "EOF", true},
		{"K2-dynamic-comment", "Bash", `apply_patch "$PATCH" # adds to ~/.ssh/authorized_keys`, true},
		{"K3-staged-and-cat", "Bash", `apply_patch < /tmp/p.diff && cat ~/.ssh/authorized_keys`, true},
		{"K4-staged-keys-patch", "Bash", `apply_patch < /tmp/authorized_keys.patch`, true},
		{"K5-ssh-folder", "Bash", `cd ~/.ssh && apply_patch < /tmp/p.diff`, true},
		{"K6-keys2", "Bash", `apply_patch < /tmp/p.diff; echo authorized_keys2`, true},
		{"K7-admin-keys", "Bash", `apply_patch < /tmp/p.diff; type C:\ProgramData\ssh\administrators_authorized_keys`, true},
		{"K8-pipe-keys", "Bash", `cat /tmp/p.diff | apply_patch && ls -l authorized_keys`, true},
		{"K9-native-abs-keys", "apply_patch", envelope(filepath.Join(home, ".ssh", "authorized_keys")), true},
		{"K10-native-rel-keys", "apply_patch", envelope("../.ssh/authorized_keys"), true},
	}
	for _, pack := range gap0437Packs {
		a := gap0437Server(t, pack, "codex", "action")
		for index, r := range rows {
			input := map[string]any{"command": r.command}
			body, _ := json.Marshal(map[string]any{
				"hook_event_name": "PreToolUse", "session_id": fmt.Sprintf("g0432-%s-%d", pack.name, index), "cwd": project,
				"tool_name": r.tool, "tool_use_id": fmt.Sprintf("tu-g0432-%d", index), "tool_input": input,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
			setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
			w := httptest.NewRecorder()
			a.handleAgentHook("codex").ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("%s/%s: status %d body %s", pack.name, r.id, w.Code, w.Body.String())
			}
			var out map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			action, severity, rules := g0432Verdict(out)
			name := pack.name + "/" + r.id
			t.Logf("ROW %s %s/%s/%v", name, action, severity, rules)
			keyRule := slices.Contains(rules, "persistence.ssh_authorized_keys_command")
			if r.block && (action != "block" || !keyRule) {
				t.Errorf("%s: a call that names the keys file answered %s %s %v, want a block on the key rule", name, action, severity, rules)
			}
			if !r.block && keyRule {
				t.Errorf("%s: a feature-named source file read as a key write: %s %s %v", name, action, severity, rules)
			}
			if !r.block && pack.name == "default" && action != "allow" {
				t.Errorf("%s: answered %s %s %v in default, want allow", name, action, severity, rules)
			}
		}
	}
}

// g0432Verdict is action, severity and the sorted rule ids of a hook answer.
func g0432Verdict(out map[string]any) (action, severity string, rules []string) {
	action, _ = out["action"].(string)
	if action == "" {
		action = "allow"
	}
	severity, _ = out["severity"].(string)
	if raw, ok := out["rule_ids"].([]any); ok {
		for _, rule := range raw {
			rules = append(rules, fmt.Sprint(rule))
		}
	}
	sort.Strings(rules)
	return action, severity, rules
}
