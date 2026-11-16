// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A Claude Code file call through a project symbolic link or junction to a
// protected file gets the verdict of the protected name, on Windows too: the
// physical target the file system reports is judged in the spelling the
// rules read. A link to an ordinary file stays allowed.
func TestWindowsFileToolThroughLinkGetsDirectPathVerdict(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	project := t.TempDir()
	// A credential file in a user-home-shaped folder of its own, outside the
	// project, as the rules protect it on every OS.
	protectedDir := filepath.Join(t.TempDir(), "Users", "fixture")
	if err := os.MkdirAll(protectedDir, 0o700); err != nil {
		t.Fatal(err)
	}
	protected, rule := filepath.Join(protectedDir, ".netrc"), "PATH-NETRC"
	if err := os.WriteFile(protected, []byte("machine example.invalid\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A second, empty folder with the same protected shape: the file name
	// does not exist yet behind the junction.
	emptyDir := filepath.Join(t.TempDir(), "Users", "fixture")
	if err := os.MkdirAll(emptyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ordinaryDir := t.TempDir()
	ordinary := filepath.Join(ordinaryDir, "notes.txt")
	if err := os.WriteFile(ordinary, []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	junction := func(name, target string) string {
		link := filepath.Join(project, name)
		if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J %s: %v: %s", name, err, out)
		}
		return link
	}
	junctionToProtected := junction("jn", protectedDir)
	junctionToEmpty := junction("jn-new", emptyDir)
	junctionToOrdinary := junction("jn-ok", ordinaryDir)
	fileLinks := map[string]string{}
	if err := os.Symlink(protected, filepath.Join(project, "netrc-link")); err == nil {
		fileLinks["file symlink"] = filepath.Join(project, "netrc-link")
	} else {
		t.Logf("no symbolic link privilege, junction cases only: %v", err)
	}
	// A directory symbolic link whose target starts at the drive root, as
	// Windows allows (\Users\x): it reaches the same folder as the absolute
	// spelling, for an existing file and for a new file name.
	rootedLink := func(name, target string) string {
		link := filepath.Join(project, name)
		rooted := target[len(filepath.VolumeName(target)):]
		if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/D", link, rooted).CombinedOutput(); err != nil {
			t.Logf("no symbolic link privilege, no drive-rooted link cases: %v: %s", err, out)
			return ""
		}
		return link
	}
	rootedToProtected := rootedLink("rooted", protectedDir)
	rootedToEmpty := rootedLink("rooted-new", emptyDir)
	rootedToOrdinary := rootedLink("rooted-ok", ordinaryDir)
	ordinaryLink := ""
	if err := os.Symlink(ordinary, filepath.Join(project, "ok-link")); err == nil {
		ordinaryLink = filepath.Join(project, "ok-link")
	}

	decide := func(t *testing.T, tool, path string) (string, []string) {
		t.Helper()
		input := map[string]any{"file_path": path}
		if tool == "Write" {
			input["content"] = "b"
		}
		body := string(mustJSON(t, map[string]any{"session_id": "wlink", "hook_event_name": "PreToolUse",
			"tool_name": tool, "cwd": project, "tool_input": input}))
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "claudecode"
		api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(body))
		req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(body)))
		w := httptest.NewRecorder()
		api.handleAgentHook("claudecode").ServeHTTP(w, req)
		var answer struct {
			Action  string   `json:"action"`
			RuleIDs []string `json:"rule_ids"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
			t.Fatalf("%v %s", err, w.Body.String())
		}
		return answer.Action, answer.RuleIDs
	}
	forwardSlash := func(path string) string { return filepath.ToSlash(path) }

	rows := []struct {
		name, tool, direct string
		link, name_        string
	}{
		{name: "junction in the middle, Write", tool: "Write", direct: "block", link: filepath.Join(junctionToProtected, ".netrc"), name_: protected},
		{name: "junction in the middle, Read", tool: "Read", direct: "alert", link: filepath.Join(junctionToProtected, ".netrc"), name_: protected},
		{name: "junction in the middle, slash spelling", tool: "Write", direct: "block", link: forwardSlash(filepath.Join(junctionToProtected, ".netrc")), name_: protected},
		{name: "junction and a new file name", tool: "Write", direct: "block", link: filepath.Join(junctionToEmpty, ".netrc"), name_: filepath.Join(emptyDir, ".netrc")},
	}
	if rootedToProtected != "" && rootedToEmpty != "" {
		rows = append(rows,
			struct{ name, tool, direct, link, name_ string }{"drive-rooted link, Write", "Write", "block", filepath.Join(rootedToProtected, ".netrc"), protected},
			struct{ name, tool, direct, link, name_ string }{"drive-rooted link, Read", "Read", "alert", filepath.Join(rootedToProtected, ".netrc"), protected},
			struct{ name, tool, direct, link, name_ string }{"drive-rooted link and a new file name", "Write", "block", filepath.Join(rootedToEmpty, ".netrc"), filepath.Join(emptyDir, ".netrc")})
	}
	for kind, link := range fileLinks {
		rows = append(rows,
			struct{ name, tool, direct, link, name_ string }{kind + ", Write", "Write", "block", link, protected},
			struct{ name, tool, direct, link, name_ string }{kind + ", Read", "Read", "alert", link, protected})
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			action, rules := decide(t, row.tool, row.name_)
			if action != row.direct || !slices.Contains(rules, rule) {
				t.Fatalf("direct name action=%s rules=%v, want %s with %s", action, rules, row.direct, rule)
			}
			action, rules = decide(t, row.tool, row.link)
			if action != row.direct || !slices.Contains(rules, rule) {
				t.Fatalf("link action=%s rules=%v, want the direct verdict %s with %s", action, rules, row.direct, rule)
			}
		})
	}
	ordinaryPaths := map[string]string{"junction": filepath.Join(junctionToOrdinary, "notes.txt")}
	if ordinaryLink != "" {
		ordinaryPaths["file symlink"] = ordinaryLink
	}
	if rootedToOrdinary != "" {
		ordinaryPaths["drive-rooted link"] = filepath.Join(rootedToOrdinary, "notes.txt")
	}
	for kind, path := range ordinaryPaths {
		for _, tool := range []string{"Write", "Read"} {
			t.Run("ordinary "+kind+", "+tool, func(t *testing.T) {
				if action, rules := decide(t, tool, path); action != "allow" {
					t.Fatalf("link to an ordinary file: action=%s rules=%v", action, rules)
				}
			})
		}
	}
}
