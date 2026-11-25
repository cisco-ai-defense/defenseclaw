//go:build !windows

package gateway

// File-tool arguments through the real hook handler (GAP-0076): unknown
// keys, unverifiable argument classes, nested path overflow and declared
// links block in every policy and deployment cell.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

var fileToolRuleIDRE = regexp.MustCompile(`PATH-[A-Z0-9-]+|HOOK-[A-Z0-9-]+|\b[a-z]+\.[a-z]+_[a-z_]+\b`)

type fileToolShape struct {
	connector, tool, key string
	shape                func(p string) map[string]any
}

func fileToolShapes() []fileToolShape {
	upd := func(p string) string {
		return "*** Begin Patch\n*** Update File: " + p + "\n@@\n # base\n+# k\n*** End Patch\n"
	}
	return []fileToolShape{
		{"claudecode", "Write", "file_path", func(p string) map[string]any { return map[string]any{"file_path": p, "content": "# k\n"} }},
		{"claudecode", "Edit", "file_path", func(p string) map[string]any {
			return map[string]any{"file_path": p, "old_string": "# base", "new_string": "# k"}
		}},
		{"claudecode", "MultiEdit", "file_path", func(p string) map[string]any {
			return map[string]any{"file_path": p, "edits": []any{map[string]any{"old_string": "# base", "new_string": "# k"}}}
		}},
		{"claudecode", "NotebookEdit", "notebook_path", func(p string) map[string]any {
			return map[string]any{"notebook_path": p, "new_source": "x", "cell_id": "c1", "cell_type": "code", "edit_mode": "replace"}
		}},
		{"claudecode", "Read", "file_path", func(p string) map[string]any { return map[string]any{"file_path": p} }},
		{"opencode", "write", "filePath", func(p string) map[string]any { return map[string]any{"filePath": p, "content": "# k\n"} }},
		{"opencode", "write", "path", func(p string) map[string]any { return map[string]any{"path": p, "content": "# k\n"} }},
		{"opencode", "edit", "filePath", func(p string) map[string]any {
			return map[string]any{"filePath": p, "oldString": "# base", "newString": "# k"}
		}},
		{"opencode", "multiedit", "filePath", func(p string) map[string]any {
			return map[string]any{"filePath": p, "edits": []any{map[string]any{"filePath": p, "oldString": "# base", "newString": "# k"}}}
		}},
		{"opencode", "read", "filePath", func(p string) map[string]any { return map[string]any{"filePath": p} }},
		{"opencode", "patch", "", func(p string) map[string]any { return map[string]any{"patchText": upd(p)} }},
		{"opencode", "apply_patch", "", func(p string) map[string]any { return map[string]any{"patchText": upd(p)} }},
		{"codex", "apply_patch", "", func(p string) map[string]any { return map[string]any{"command": upd(p)} }},
		{"copilot", "create", "path", func(p string) map[string]any { return map[string]any{"path": p, "file_text": "# k\n"} }},
		{"copilot", "edit", "path", func(p string) map[string]any { return map[string]any{"path": p, "old_str": "# base", "new_str": "# k"} }},
		{"cursor", "Write", "file_path", func(p string) map[string]any { return map[string]any{"file_path": p, "content": "# k\n"} }},
		{"cursor", "Read", "path", func(p string) map[string]any { return map[string]any{"path": p} }},
		{"hermes", "write_file", "path", func(p string) map[string]any { return map[string]any{"path": p, "content": "# k\n"} }},
		{"hermes", "patch", "path", func(p string) map[string]any {
			return map[string]any{"mode": "replace", "path": p, "old_string": "# base", "new_string": "# k"}
		}},
		{"amp", "create_file", "path", func(p string) map[string]any { return map[string]any{"path": p, "content": "# k\n"} }},
		{"amp", "edit_file", "path", func(p string) map[string]any { return map[string]any{"path": p, "old_str": "# base", "new_str": "# k"} }},
		{"kiro", "fs_write", "path", func(p string) map[string]any {
			return map[string]any{"command": "create", "path": p, "file_text": "# k\n"}
		}},
	}
}

func cloneToolArgs(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func fileToolHookBody(t *testing.T, connector, tool string, args any, cwd, session string) (string, string) {
	t.Helper()
	switch connector {
	case "copilot":
		return string(mustJSON(t, map[string]any{"sessionId": session, "timestamp": 1790483549431, "cwd": cwd,
			"toolName": tool, "toolArgs": string(mustJSON(t, args))})), "preToolUse"
	case "opencode":
		return string(mustJSON(t, map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": args,
			"session_id": session, "turn_id": "m1", "tool_call_id": "c1", "agent_name": "build", "cwd": cwd,
			"arguments_authoritative": true, "mcp_identity_status": "not_mcp"})), "tool.execute.before"
	case "cursor", "kiro":
		return string(mustJSON(t, map[string]any{"hook_event_name": "preToolUse", "session_id": session, "tool_call_id": "c1",
			"cwd": cwd, "tool_name": tool, "tool_input": args})), "preToolUse"
	case "hermes":
		return string(mustJSON(t, map[string]any{"hook_event_name": "pre_tool_call", "session_id": session, "tool_call_id": "c1",
			"cwd": cwd, "tool_name": tool, "tool_input": args})), "pre_tool_call"
	case "amp":
		return string(mustJSON(t, map[string]any{"hook_event_name": "tool.call", "session_id": session, "cwd": cwd,
			"tool_name": tool, "tool_input": args})), "tool.call"
	default:
		return string(mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": session, "turn_id": "t1",
			"cwd": cwd, "tool_name": tool, "tool_input": args, "tool_use_id": "u1"})), "PreToolUse"
	}
}

func fileToolHookVerdict(t *testing.T, connector, tool string, args any, profile string, managed bool, home, project, session string) (int, string, string, string) {
	t.Helper()
	body, event := fileToolHookBody(t, connector, tool, args, project, session)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	switch connector {
	case "copilot":
		req.Header.Set("X-DefenseClaw-Copilot-Event", event)
	case "codex":
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(connector, "", event, []byte(body)))
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	rec := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(rec, req)
	text := rec.Body.String()
	var resp map[string]any
	_ = json.Unmarshal([]byte(text), &resp)
	action, _ := resp["action"].(string)
	raw, _ := resp["raw_action"].(string)
	seen := map[string]bool{}
	for _, m := range fileToolRuleIDRE.FindAllString(text, -1) {
		seen[m] = true
	}
	var ids []string
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return rec.Code, action + "/" + raw, strings.Join(ids, ","), text
}

func fileToolHookHome(t *testing.T) (string, string) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	for _, rel := range []string{".defenseclaw/config.yaml", ".defenseclaw/policies/file-tool.yaml", ".aws/credentials", ".ssh/id_ed25519",
		".ssh/authorized_keys", ".claude/settings.json", ".codex/hooks.json", ".cursor/hooks.json", "proj/notes.txt"} {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Symlink(filepath.Join(home, ".ssh/authorized_keys"), filepath.Join(project, "aklink"))
	_ = os.Symlink(filepath.Join(home, ".defenseclaw/config.yaml"), filepath.Join(project, "stlink"))
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	return home, project
}

var fileToolPolicyCells = []struct {
	profile string
	managed bool
}{{"default", false}, {"default", true}, {"strict", false}, {"strict", true}}

// TestFileToolUnverifiableArgumentClassesBlockInEveryCell exercises the named and unverifiable argument classes
// through the real hook handler in all four policy and deployment cells.
//
// Each class is judged twice, per-user and managed, one of the two in the
// strict profile (in turn), on the tools in turn; the 200 KB description
// pad is judged once per route (owner TEST BUDGET 2026-11-10: a hook call
// costs about 120 ms under -race and the tools x classes x cells product
// ran 3 minutes). As before, a class is judged on a tool only where the
// tool's plain write (or read) of the target blocks in that cell: a tool
// that does not block there passes the class to the next tool. A tool that
// no class reached is then judged with the next class in a strict cell.
// The plan check fails the test when a class is not judged per-user,
// managed and in strict, or a tool is never judged. The profile pack is
// loaded once per profile, not per connector and cell.
func TestFileToolUnverifiableArgumentClassesBlockInEveryCell(t *testing.T) {
	home, project := fileToolHookHome(t)
	state := filepath.Join(home, ".defenseclaw/config.yaml")
	aws := filepath.Join(home, ".aws/credentials")
	ordinary := filepath.Join(project, "notes.txt")
	type check func(tool fileToolShape, target string, judge func(fileToolShape, map[string]any) string) []string
	mutation := func(add func(map[string]any)) check {
		return func(tool fileToolShape, target string, judge func(fileToolShape, map[string]any) string) []string {
			a := cloneToolArgs(tool.shape(target))
			add(a)
			if got := judge(tool, a); got != "block" {
				return []string{"target " + got}
			}
			return nil
		}
	}
	spelled := func(spelling string) check {
		return func(tool fileToolShape, _ string, judge func(fileToolShape, map[string]any) string) []string {
			if judge(tool, tool.shape(spelling)) != "block" {
				return nil
			}
			a := tool.shape(spelling)
			a["description"] = "x"
			if got := judge(tool, a); got != "block" {
				return []string{"with extra key: " + got}
			}
			return nil
		}
	}
	classes := []struct {
		name  string
		named bool // a value named in another field: not for copilot and kiro
		check check
	}{
		{"cwd", false, mutation(func(a map[string]any) { a["cwd"] = "/var/tmp/x" })},
		{"workdir", false, mutation(func(a map[string]any) { a["workdir"] = "/var/tmp/x" })},
		{"working_directory", false, mutation(func(a map[string]any) { a["working_directory"] = "/var/tmp/x" })},
		{"command", false, mutation(func(a map[string]any) {
			if _, ok := a["command"]; ok {
				a["cmd"] = "echo hi"
			} else {
				a["command"] = "echo hi"
			}
		})},
		{"input", false, mutation(func(a map[string]any) { a["input"] = map[string]any{"file_path": ordinary} })},
		{"FILE_PATH", false, mutation(func(a map[string]any) { a["FILE_PATH"] = ordinary })},
		{"other-target-field", false, mutation(func(a map[string]any) {
			if _, ok := a["path"]; ok {
				a["file_path"] = ordinary
			} else {
				a["path"] = ordinary
			}
		})},
		{"home", false, spelled("$HOME/.defenseclaw/config.yaml")},
		{"tilde", false, spelled("~/.defenseclaw/config.yaml")},
		{"relative", false, spelled("../.defenseclaw/config.yaml")},
		{"named value in input", true, func(tool fileToolShape, _ string, judge func(fileToolShape, map[string]any) string) []string {
			a := tool.shape(ordinary)
			a["input"] = map[string]any{"file_path": state}
			if got := judge(tool, a); got != "block" {
				return []string{got}
			}
			return nil
		}},
		{"named value in alternate target field", true, func(tool fileToolShape, _ string, judge func(fileToolShape, map[string]any) string) []string {
			b := tool.shape(ordinary)
			if _, ok := b["path"]; ok {
				b["file_path"] = state
			} else {
				b["path"] = state
			}
			if got := judge(tool, b); got != "block" {
				return []string{got}
			}
			return nil
		}},
	}
	huge := mutation(func(a map[string]any) { a["description"] = strings.Repeat("x", 200000) })
	tools := fileToolShapes()
	toolID := func(tool fileToolShape) string { return tool.connector + "/" + tool.tool + "/" + tool.key }
	// One cell at a time: the profile packs are installed once per cell.
	type cellRun struct {
		t       *testing.T
		profile string
		managed bool
		n       int
		base    map[string]string
	}
	judged := map[string]bool{}
	judgeIn := func(c *cellRun, tool fileToolShape, args map[string]any) string {
		c.n++
		_, action, _, body := fileToolHookVerdict(c.t, tool.connector, tool.tool, args, c.profile, c.managed, home, project, fmt.Sprintf("gxarg-r2-%d", c.n))
		return gap0747StateVerdict(strings.Split(action, "/")[0], body, c.profile == "strict")
	}
	// blocks reports whether the plain write (or read) of the target by
	// tool blocks in cell c, judging it once per cell.
	blocks := func(c *cellRun, tool fileToolShape) (string, bool) {
		target := state
		if strings.EqualFold(tool.tool, "read") {
			target = aws
		}
		id := toolID(tool)
		if _, ok := c.base[id]; !ok {
			c.base[id] = judgeIn(c, tool, tool.shape(target))
			judged["tool="+id] = true
		}
		return target, c.base[id] == "block"
	}
	type entry struct {
		class string
		named bool
		check check
	}
	plan := make([][]entry, len(fileToolPolicyCells)) // cell index -> class entries
	cellFor := func(perUser, strict bool) int {
		for i, cell := range fileToolPolicyCells {
			if cell.managed != perUser && (cell.profile == "strict") == strict {
				return i
			}
		}
		panic("no cell")
	}
	for c, class := range classes {
		plan[cellFor(true, c%2 == 0)] = append(plan[cellFor(true, c%2 == 0)], entry{class.name, class.named, class.check})
		plan[cellFor(false, c%2 == 1)] = append(plan[cellFor(false, c%2 == 1)], entry{class.name, class.named, class.check})
	}
	plan[cellFor(true, false)] = append(plan[cellFor(true, false)], entry{"huge", false, huge})
	plan[cellFor(false, true)] = append(plan[cellFor(false, true)], entry{"huge", false, huge})
	cursor := 0
	reached := map[string]bool{}
	apply := func(c *cellRun, e entry, start int) bool {
		for try := 0; try < len(tools); try++ {
			tool := tools[(start+try)%len(tools)]
			if e.named && (tool.connector == "copilot" || tool.connector == "kiro") {
				continue
			}
			target, ok := blocks(c, tool)
			if !ok {
				continue
			}
			for _, problem := range e.check(tool, target, func(tool fileToolShape, args map[string]any) string { return judgeIn(c, tool, args) }) {
				c.t.Errorf("%s/%s %s: %s", tool.connector, tool.tool, e.class, problem)
			}
			judged["class="+e.class+"/managed="+fmt.Sprint(c.managed)] = true
			judged["class="+e.class+"/"+c.profile] = true
			reached[toolID(tool)] = true
			cursor = (start + try + 1) % len(tools)
			return true
		}
		return false
	}
	for i, cell := range fileToolPolicyCells {
		// The cells of one profile share its install (fileToolPolicyCells lists them
		// side by side).
		if i == 0 || fileToolPolicyCells[i-1].profile != cell.profile {
			installFileToolProfile(t, cell.profile)
		}
		t.Run(cell.profile+fmt.Sprint(cell.managed), func(t *testing.T) {
			c := &cellRun{t: t, profile: cell.profile, managed: cell.managed, base: map[string]string{}}
			for _, e := range plan[i] {
				if e.class == "huge" {
					// The pad on a tool_input map per-user, on the
					// Copilot CLI toolArgs string managed.
					start := 0
					if cell.managed {
						start = slices.IndexFunc(tools, func(tool fileToolShape) bool { return tool.connector == "copilot" })
					}
					apply(c, e, start)
					continue
				}
				apply(c, e, cursor)
			}
			// The strict cells sweep the tools no class reached yet.
			if cell.profile != "strict" {
				return
			}
			for ti, tool := range tools {
				if reached[toolID(tool)] {
					continue
				}
				if _, ok := blocks(c, tool); !ok {
					continue
				}
				k := ti
				for classes[k%len(classes)].named && (tool.connector == "copilot" || tool.connector == "kiro") {
					k++
				}
				class := classes[k%len(classes)]
				apply(c, entry{class.name, class.named, class.check}, ti)
			}
		})
	}
	// The plan check.
	var missing []string
	names := []string{"huge"}
	for _, class := range classes {
		names = append(names, class.name)
	}
	for _, name := range names {
		for _, key := range []string{"/managed=false", "/managed=true", "/strict"} {
			if !judged["class="+name+key] {
				missing = append(missing, name+key)
			}
		}
	}
	for _, tool := range tools {
		if !judged["tool="+toolID(tool)] {
			missing = append(missing, "tool "+toolID(tool))
		}
	}
	if len(missing) > 0 {
		t.Errorf("rotation left unjudged: %v", missing)
	}
	for _, tool := range tools {
		if !reached[toolID(tool)] {
			t.Logf("%s: the plain write blocks in no cell it was judged in, no class judged on it", toolID(tool))
		}
	}
}

// installFileToolProfile is installFileToolProfile with the profile pack loaded once for
// all eight connectors: installFileToolProfile loads it again for every connector
// (a pack load, strict YAML decode and CEL compile is ~0.3 s of CPU under
// -race). Each connector keeps its own compiled categories, and its
// previous ones come back when t ends.
func installFileToolProfile(t *testing.T, profile string) {
	t.Helper()
	pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), profile))
	for _, c := range []string{"claudecode", "codex", "copilot", "opencode", "cursor", "hermes", "amp", "kiro"} {
		ruleCategoriesMu.Lock()
		savedCategories, hadCategories := connectorRuleCategories[c]
		savedGeneration, hadGeneration := connectorRuleGenerations[c]
		ruleCategoriesMu.Unlock()
		t.Cleanup(func() {
			ruleCategoriesMu.Lock()
			defer ruleCategoriesMu.Unlock()
			if hadCategories {
				connectorRuleCategories[c] = savedCategories
			} else {
				delete(connectorRuleCategories, c)
			}
			if hadGeneration {
				connectorRuleGenerations[c] = savedGeneration
			} else {
				delete(connectorRuleGenerations, c)
			}
		})
		if err := ApplyConnectorRulePackOverrides(c, pack); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileToolNestedPathOverflowAndDeclaredLinkBlock(t *testing.T) {
	home, project := fileToolHookHome(t)
	ordinary := filepath.Join(project, "notes.txt")
	state := filepath.Join(home, ".defenseclaw/config.yaml")
	aws := filepath.Join(home, ".aws/credentials")
	nest := any(state)
	for i := 0; i < 5; i++ {
		nest = map[string]any{"path": nest}
	}
	for _, cell := range fileToolPolicyCells {
		t.Run(cell.profile+fmt.Sprint(cell.managed), func(t *testing.T) {
			installFileToolProfile(t, cell.profile)
			cases := []struct {
				connector, tool, name string
				args                  map[string]any
				named                 bool
			}{
				{"claudecode", "Write", "write-overflow", map[string]any{"file_path": ordinary, "content": "x"}, false},
				{"claudecode", "Read", "read-overflow", map[string]any{"file_path": ordinary}, false},
				{"claudecode", "Write", "depth-five", map[string]any{"file_path": ordinary, "content": "x", "options": nest}, false},
				{"claudecode", "Write", "named-plus-overflow", map[string]any{"file_path": ordinary, "content": "x"}, true},
			}
			for i := range cases {
				if cases[i].name == "depth-five" {
					continue
				}
				var files []any
				if cases[i].named {
					files = append(files, state)
				}
				for n := len(files); n < 16; n++ {
					files = append(files, filepath.Join(project, fmt.Sprintf("out-%d", n)))
				}
				last := filepath.Join(project, "out-last")
				if cases[i].name == "read-overflow" {
					last = aws
				}
				cases[i].args["files"] = append(files, last)
			}
			for i, row := range cases {
				_, action, _, body := fileToolHookVerdict(t, row.connector, row.tool, row.args, cell.profile, cell.managed, home, project, fmt.Sprintf("gxarg-over-%d", i))
				got := gap0747StateVerdict(strings.Split(action, "/")[0], body, cell.profile == "strict")
				if row.named || cell.profile == "strict" {
					if got != "block" {
						t.Errorf("%s: %s, want block (%.600s)", row.name, got, body)
					}
				} else if got == "block" || !strings.Contains(body, "Warning: file tool arguments exceed") {
					t.Errorf("%s: action %s lacks visible warning", row.name, got)
				}
			}
			for i, tool := range fileToolShapes() {
				args := tool.shape(ordinary)
				var files []any
				for n := 0; n < 17; n++ {
					files = append(files, filepath.Join(project, fmt.Sprintf("extra-%d", n)))
				}
				args["files"] = files
				_, action, _, body := fileToolHookVerdict(t, tool.connector, tool.tool, args, cell.profile, cell.managed, home, project, fmt.Sprintf("gxarg-tool-over-%d", i))
				got := strings.Split(action, "/")[0]
				if cell.profile == "strict" {
					if got != "block" {
						t.Errorf("%s/%s overflow strict: %s", tool.connector, tool.tool, got)
					}
				} else if tool.connector != "copilot" && tool.connector != "kiro" && (got == "block" || !strings.Contains(body, "Warning: file tool arguments exceed")) {
					t.Errorf("%s/%s overflow balanced: %s", tool.connector, tool.tool, got)
				}
			}
			link := filepath.Join(project, "stlink")
			for i, command := range []string{"printf x > " + link, "export F=" + link + `; printf x > "$F"`} {
				_, action, _, body := fileToolHookVerdict(t, "claudecode", "Bash", map[string]any{"command": command}, cell.profile, cell.managed, home, project, fmt.Sprintf("gxarg-link-%d", i))
				if got := gap0747StateVerdict(strings.Split(action, "/")[0], body, cell.profile == "strict"); got != "block" {
					t.Errorf("declared link %d: %s", i, got)
				}
			}
		})
	}
}
