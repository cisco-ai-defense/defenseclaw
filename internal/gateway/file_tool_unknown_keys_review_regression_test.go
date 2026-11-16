//go:build !windows

package gateway

// Real-handler regression harness for GAP-0076. The optional matrix and D1 corpus modes write verdict evidence.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

var rvgxRuleRE = regexp.MustCompile(`PATH-[A-Z0-9-]+|HOOK-[A-Z0-9-]+|\b[a-z]+\.[a-z]+_[a-z_]+\b`)

type rvgxRow struct {
	id, ref, connector, tool string
	args                     any
}

type rvgxTool struct {
	connector, tool, key string
	shape                func(p string) map[string]any
}

func rvgxTools() []rvgxTool {
	upd := func(p string) string {
		return "*** Begin Patch\n*** Update File: " + p + "\n@@\n # base\n+# k\n*** End Patch\n"
	}
	return []rvgxTool{
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

func rvgxClone(m map[string]any) map[string]any {
	raw, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func rvgxRows(home, project string) []rvgxRow {
	benign := filepath.Join(project, "notes.txt")
	elsewhere := "/var/tmp/rvgx-else/a/b"
	targets := []struct{ label, rel string }{
		{"state", ".defenseclaw/config.yaml"}, {"statepol", ".defenseclaw/policies/rvgx.yaml"}, {"aws", ".aws/credentials"},
		{"sshkey", ".ssh/id_ed25519"}, {"ak", ".ssh/authorized_keys"}, {"claude", ".claude/settings.json"},
		{"codexhooks", ".codex/hooks.json"}, {"cursorhooks", ".cursor/hooks.json"}, {"ordinary", "proj/notes.txt"},
		{"aklink", "proj/aklink"}, {"stlink", "proj/stlink"},
	}
	type spelled struct{ label, spell, value string }
	var spells []spelled
	for _, tg := range targets {
		abs := filepath.Join(home, tg.rel)
		spells = append(spells, spelled{tg.label, "abs", abs})
		if tg.label == "state" || tg.label == "ak" {
			spells = append(spells, spelled{tg.label, "tilde", "~/" + tg.rel}, spelled{tg.label, "home", "$HOME/" + tg.rel},
				spelled{tg.label, "rel", "../" + tg.rel}, spelled{tg.label, "fileurl", "file://" + abs})
		}
	}
	nest := func(depth int, v any) any {
		for i := 0; i < depth; i++ {
			v = map[string]any{"path": v}
		}
		return v
	}
	extras := map[string]func(t rvgxTool, a map[string]any){
		"desc": func(_ rvgxTool, a map[string]any) { a["description"] = "add a line" },
		"several": func(_ rvgxTool, a map[string]any) {
			a["description"], a["timeout"], a["meta"] = "x", 5, map[string]any{"a": "b"}
		},
		"k-file":   func(_ rvgxTool, a map[string]any) { a["file"] = benign },
		"k-target": func(_ rvgxTool, a map[string]any) { a["target"] = benign },
		"k-dest":   func(_ rvgxTool, a map[string]any) { a["dest"] = benign },
		"k-path2":  func(_ rvgxTool, a map[string]any) { a["path2"] = benign },
		"k-alt": func(t rvgxTool, a map[string]any) {
			a[map[bool]string{true: "filePath", false: "file_path"}[t.key != "filePath"]] = benign
		},
		"k-path": func(t rvgxTool, a map[string]any) {
			if t.key != "path" {
				a["path"] = benign
			} else {
				a["file_path"] = benign
			}
		},
		"nest1": func(_ rvgxTool, a map[string]any) { a["options"] = nest(1, benign) },
		"nest5": func(_ rvgxTool, a map[string]any) { a["options"] = nest(5, benign) },
		"arrobj": func(_ rvgxTool, a map[string]any) {
			a["files"] = []any{map[string]any{"file": benign}, map[string]any{"filePath": benign}}
		},
		"arrpaths":    func(_ rvgxTool, a map[string]any) { a["files"] = []any{benign, benign + "2"} },
		"FILE_PATH":   func(_ rvgxTool, a map[string]any) { a["FILE_PATH"] = benign },
		"File_Path":   func(_ rvgxTool, a map[string]any) { a["File_Path"] = benign },
		"filepath":    func(_ rvgxTool, a map[string]any) { a["filepath"] = benign },
		"cwd":         func(_ rvgxTool, a map[string]any) { a["cwd"] = elsewhere },
		"workdir":     func(_ rvgxTool, a map[string]any) { a["workdir"] = elsewhere },
		"wd2":         func(_ rvgxTool, a map[string]any) { a["working_directory"] = elsewhere },
		"dir":         func(_ rvgxTool, a map[string]any) { a["dir"] = elsewhere },
		"wrap-input":  func(_ rvgxTool, a map[string]any) { a["input"] = map[string]any{"file_path": benign} },
		"wrap-params": func(_ rvgxTool, a map[string]any) { a["parameters"] = map[string]any{"note": "x"} },
		"k-source":    func(_ rvgxTool, a map[string]any) { a["source"] = benign },
		"k-data":      func(_ rvgxTool, a map[string]any) { a["data"] = "x" },
		"command": func(_ rvgxTool, a map[string]any) {
			if _, ok := a["command"]; !ok {
				a["command"] = "echo hi"
			} else {
				a["cmd"] = "echo hi"
			}
		},
		"null":     func(_ rvgxTool, a map[string]any) { a["extra"] = nil },
		"num":      func(_ rvgxTool, a map[string]any) { a["extra"] = 3.5 },
		"bool":     func(_ rvgxTool, a map[string]any) { a["extra"] = true },
		"unikey":   func(_ rvgxTool, a map[string]any) { a["désc"] = "x" },
		"emptykey": func(_ rvgxTool, a map[string]any) { a[""] = "x" },
		"url":      func(_ rvgxTool, a map[string]any) { a["description"] = "see https://example.com/a/b" },
		"spacey":   func(_ rvgxTool, a map[string]any) { a["description"] = "update ./README.md and docs/x.md" },
		"over20": func(_ rvgxTool, a map[string]any) {
			var v []any
			for i := 0; i < 20; i++ {
				v = append(v, fmt.Sprintf("%s/out/f%d.txt", project, i))
			}
			a["files"] = v
		},
	}
	var rows []rvgxRow
	for ti, tool := range rvgxTools() {
		tid := fmt.Sprintf("%s.%s.%s.%d", tool.connector, tool.tool, tool.key, ti)
		for _, s := range spells {
			ref := tid + "|" + s.label + "|" + s.spell + "|reviewed"
			rows = append(rows, rvgxRow{ref, "", tool.connector, tool.tool, tool.shape(s.value)})
			for name, f := range extras {
				a := rvgxClone(tool.shape(s.value))
				f(tool, a)
				rows = append(rows, rvgxRow{tid + "|" + s.label + "|" + s.spell + "|x-" + name, ref, tool.connector, tool.tool, a})
			}
			if s.label == "state" && s.spell == "abs" {
				a := rvgxClone(tool.shape(s.value))
				a["description"] = strings.Repeat("a", 200000)
				rows = append(rows, rvgxRow{tid + "|state|abs|x-huge", ref, tool.connector, tool.tool, a})
			}
		}
		for _, tg := range targets {
			if tg.label == "ordinary" {
				continue
			}
			p := filepath.Join(home, tg.rel)
			ref := tid + "|" + tg.label + "|abs|reviewed"
			hidden := map[string]any{
				"target_file": p, "file": p, "dest": p, "path2": p, "target": p,
				"FILE_PATH": p, "filepath": p,
			}
			hv := map[string]func(a map[string]any){}
			for k, v := range hidden {
				k, v := k, v
				hv["k-"+k] = func(a map[string]any) { a[k] = v }
			}
			for d := 1; d <= 5; d++ {
				d := d
				hv[fmt.Sprintf("nest%d", d)] = func(a map[string]any) { a["options"] = nest(d, p) }
			}
			hv["arrobj"] = func(a map[string]any) { a["files"] = []any{map[string]any{"file": benign}, map[string]any{"path": p}} }
			hv["arrpaths"] = func(a map[string]any) { a["files"] = []any{benign, p} }
			hv["fileurl"] = func(a map[string]any) { a["target_file"] = "file://" + p }
			hv["tilde"] = func(a map[string]any) { a["target_file"] = "~/" + tg.rel }
			hv["home"] = func(a map[string]any) { a["target_file"] = "$HOME/" + tg.rel }
			hv["rel"] = func(a map[string]any) { a["target_file"] = "../" + tg.rel }
			hv["urlenc"] = func(a map[string]any) { a["target_file"] = url.PathEscape(p) }
			hv["split"] = func(a map[string]any) { a["dir"], a["name"] = filepath.Dir(p), filepath.Base(p) }
			hv["after16"] = func(a map[string]any) {
				var v []any
				for i := 0; i < 16; i++ {
					v = append(v, fmt.Sprintf("%s/out/f%d.txt", project, i))
				}
				a["files"] = append(v, p)
			}
			for _, k := range []string{"input", "parameters", "request", "args"} {
				k := k
				hv["wrap-"+k] = func(a map[string]any) { a[k] = map[string]any{"file_path": p, "path": p} }
			}
			hv["cwdrel"] = func(a map[string]any) { a["cwd"] = filepath.Dir(p); a["target_file"] = filepath.Base(p) }
			hv["alt"] = func(a map[string]any) {
				a[map[bool]string{true: "filePath", false: "file_path"}[tool.key != "filePath"]] = p
			}
			hv["pathkey"] = func(a map[string]any) {
				if tool.key != "path" {
					a["path"] = p
				} else {
					a["file_path"] = p
				}
			}
			for name, f := range hv {
				a := rvgxClone(tool.shape(benign))
				f(a)
				rows = append(rows, rvgxRow{tid + "|" + tg.label + "|abs|h-" + name, ref, tool.connector, tool.tool, a})
			}
		}
	}
	// shell export forms vs the literal write
	for _, tg := range targets {
		p := filepath.Join(home, tg.rel)
		for _, c := range []string{"claudecode", "codex"} {
			ref := "sh." + c + "|" + tg.label + "|abs|literal"
			rows = append(rows, rvgxRow{ref, "", c, "Bash", map[string]any{"command": "printf x > " + p}})
			for name, form := range map[string]string{
				"export":         "export F=" + p + `; printf x > "$F"`,
				"export-and":     "export F=" + p + ` && printf x > "$F"`,
				"export-dir":     "export D=" + filepath.Dir(p) + `; printf x > "$D/` + filepath.Base(p) + `"`,
				"declare-x":      "declare -x F=" + p + `; printf x > "$F"`,
				"typeset-x":      "typeset -x F=" + p + `; printf x > "$F"`,
				"readonly":       "readonly F=" + p + `; printf x > "$F"`,
				"export-n":       "export -n F=" + p + `; printf x > "$F"`,
				"export-i":       "export -i F=" + p + `; printf x > "$F"`,
				"declare-a":      "declare -a F=" + p + `; printf x > "$F"`,
				"local":          "f() { local F=" + p + `; printf x > "$F"; }; f`,
				"local-after":    "F=" + p + `; f() { local F=/var/tmp/rvgx-else/x; }; f; printf x > "$F"`,
				"ro-reassign":    "readonly F=" + p + `; F=notes.txt; printf x > "$F"`,
				"declr-reassign": "declare -r F=" + p + `; F=notes.txt; printf x > "$F"`,
				"export-two":     "export A=/var/tmp/rvgx-else/x F=" + p + `; printf x > "$F"`,
			} {
				rows = append(rows, rvgxRow{"sh." + c + "|" + tg.label + "|abs|" + name, ref, c, "Bash", map[string]any{"command": form}})
			}
		}
	}
	for name, cmd := range map[string]string{
		"b-export-out":  `export OUT=out; mkdir -p "$OUT"; printf x > "$OUT/status.txt"`,
		"b-export-path": `export PATH="$PATH:./bin"; ls`,
		"b-export-cc":   `export CC=gcc CFLAGS=-O2; echo "$CC" > build.log`,
		"b-declare":     `declare -x NODE_ENV=production; printf "%s" "$NODE_ENV" > env.txt`,
		"b-local":       `f() { local out=build/out.txt; mkdir -p build; printf x > "$out"; }; f`,
		"b-readonly":    `readonly LOG=run.log; date > "$LOG"`,
		"b-export-home": `export GOPATH=$HOME/go; ls "$GOPATH"`,
	} {
		for _, c := range []string{"claudecode", "codex"} {
			rows = append(rows, rvgxRow{"sh." + c + "|benign|" + name, "", c, "Bash", map[string]any{"command": cmd}})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	return rows
}

func rvgxBody(t *testing.T, connector, tool string, args any, cwd, session string) (string, string) {
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

func rvgxVerdict(t *testing.T, connector, tool string, args any, profile string, managed bool, home, project, session string) (int, string, string, string) {
	t.Helper()
	body, event := rvgxBody(t, connector, tool, args, project, session)
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
	for _, m := range rvgxRuleRE.FindAllString(text, -1) {
		seen[m] = true
	}
	var ids []string
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return rec.Code, action + "/" + raw, strings.Join(ids, ","), text
}

func rvgxSetup(t *testing.T) (string, string) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	for _, rel := range []string{".defenseclaw/config.yaml", ".defenseclaw/policies/rvgx.yaml", ".aws/credentials", ".ssh/id_ed25519",
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

var rvgxCells = []struct {
	profile string
	managed bool
}{{"default", false}, {"default", true}, {"strict", false}, {"strict", true}}

func rvgxInstall(t *testing.T, profile string) {
	for _, c := range []string{"claudecode", "codex", "copilot", "opencode", "cursor", "hermes", "amp", "kiro"} {
		installToolCallCorpusProfileConnector(t, c, profile)
	}
}

func TestRVGXARG(t *testing.T) {
	out := os.Getenv("RVGX_OUT")
	if out == "" {
		t.Skip("RVGX_OUT not set")
	}
	file, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	defer w.Flush()
	home, project := rvgxSetup(t)
	rows := rvgxRows(home, project)
	for _, cell := range rvgxCells {
		topo := map[bool]string{false: "per-user", true: "managed"}[cell.managed]
		t.Run(cell.profile+"/"+topo, func(t *testing.T) {
			rvgxInstall(t, cell.profile)
			for i, row := range rows {
				start := time.Now()
				code, action, ids, text := rvgxVerdict(t, row.connector, row.tool, row.args, cell.profile, cell.managed, home, project,
					fmt.Sprintf("rvgx%s%s%d", cell.profile, topo, i))
				short := strings.NewReplacer("\t", " ", "\n", " ", home, "{H}").Replace(text)
				if len(short) > 400 {
					short = short[:400]
				}
				fmt.Fprintf(w, "%s\t%s\t%s/%s\t%d\t%s\t%s\t%d\t%s\n", row.id, row.ref, cell.profile, topo, code, action, ids,
					time.Since(start).Microseconds(), short)
			}
		})
	}
}

// TestRVGXARGRound2 exercises the review's named and unverifiable classes
// through the real hook handler in all four policy and deployment cells.
func TestRVGXARGRound2(t *testing.T) {
	home, project := rvgxSetup(t)
	state := filepath.Join(home, ".defenseclaw/config.yaml")
	aws := filepath.Join(home, ".aws/credentials")
	ordinary := filepath.Join(project, "notes.txt")
	for _, cell := range rvgxCells {
		t.Run(cell.profile+fmt.Sprint(cell.managed), func(t *testing.T) {
			rvgxInstall(t, cell.profile)
			n := 0
			judge := func(tool rvgxTool, args map[string]any) string {
				n++
				_, action, _, _ := rvgxVerdict(t, tool.connector, tool.tool, args, cell.profile, cell.managed, home, project, fmt.Sprintf("gxarg-r2-%d", n))
				return strings.Split(action, "/")[0]
			}
			for _, tool := range rvgxTools() {
				target := state
				if strings.EqualFold(tool.tool, "read") {
					target = aws
				}
				base := judge(tool, tool.shape(target))
				if base != "block" {
					continue
				}
				for name, add := range map[string]func(map[string]any){
					"cwd":               func(a map[string]any) { a["cwd"] = "/var/tmp/x" },
					"workdir":           func(a map[string]any) { a["workdir"] = "/var/tmp/x" },
					"working_directory": func(a map[string]any) { a["working_directory"] = "/var/tmp/x" },
					"command": func(a map[string]any) {
						if _, ok := a["command"]; ok {
							a["cmd"] = "echo hi"
						} else {
							a["command"] = "echo hi"
						}
					},
					"input":     func(a map[string]any) { a["input"] = map[string]any{"file_path": ordinary} },
					"FILE_PATH": func(a map[string]any) { a["FILE_PATH"] = ordinary },
					"other-target-field": func(a map[string]any) {
						if _, ok := a["path"]; ok {
							a["file_path"] = ordinary
						} else {
							a["path"] = ordinary
						}
					},
					"huge": func(a map[string]any) { a["description"] = strings.Repeat("x", 200000) },
				} {
					a := rvgxClone(tool.shape(target))
					add(a)
					if got := judge(tool, a); got != "block" {
						t.Errorf("%s/%s %s: target %s", tool.connector, tool.tool, name, got)
					}
				}
				for name, spelling := range map[string]string{"home": "$HOME/.defenseclaw/config.yaml", "tilde": "~/.defenseclaw/config.yaml", "relative": "../.defenseclaw/config.yaml"} {
					if judge(tool, tool.shape(spelling)) != "block" {
						continue
					}
					a := tool.shape(spelling)
					a["description"] = "x"
					if got := judge(tool, a); got != "block" {
						t.Errorf("%s/%s %s with extra key: %s", tool.connector, tool.tool, name, got)
					}
				}
				if tool.connector != "copilot" && tool.connector != "kiro" {
					a := tool.shape(ordinary)
					a["input"] = map[string]any{"file_path": state}
					if got := judge(tool, a); got != "block" {
						t.Errorf("%s/%s named value in input: %s", tool.connector, tool.tool, got)
					}
					b := tool.shape(ordinary)
					if _, ok := b["path"]; ok {
						b["file_path"] = state
					} else {
						b["path"] = state
					}
					if got := judge(tool, b); got != "block" {
						t.Errorf("%s/%s named value in alternate target field: %s", tool.connector, tool.tool, got)
					}
				}
			}
		})
	}
}

func TestRVGXARGPossibleOverflowAndDeclaredLink(t *testing.T) {
	home, project := rvgxSetup(t)
	ordinary := filepath.Join(project, "notes.txt")
	state := filepath.Join(home, ".defenseclaw/config.yaml")
	aws := filepath.Join(home, ".aws/credentials")
	nest := any(state)
	for i := 0; i < 5; i++ {
		nest = map[string]any{"path": nest}
	}
	for _, cell := range rvgxCells {
		t.Run(cell.profile+fmt.Sprint(cell.managed), func(t *testing.T) {
			rvgxInstall(t, cell.profile)
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
				_, action, _, body := rvgxVerdict(t, row.connector, row.tool, row.args, cell.profile, cell.managed, home, project, fmt.Sprintf("gxarg-over-%d", i))
				got := strings.Split(action, "/")[0]
				if row.named || cell.profile == "strict" {
					if got != "block" {
						t.Errorf("%s: %s, want block (%.600s)", row.name, got, body)
					}
				} else if got == "block" || !strings.Contains(body, "Warning: file tool arguments exceed") {
					t.Errorf("%s: action %s lacks visible warning", row.name, got)
				}
			}
			for i, tool := range rvgxTools() {
				args := tool.shape(ordinary)
				var files []any
				for n := 0; n < 17; n++ {
					files = append(files, filepath.Join(project, fmt.Sprintf("extra-%d", n)))
				}
				args["files"] = files
				_, action, _, body := rvgxVerdict(t, tool.connector, tool.tool, args, cell.profile, cell.managed, home, project, fmt.Sprintf("gxarg-tool-over-%d", i))
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
				_, action, _, _ := rvgxVerdict(t, "claudecode", "Bash", map[string]any{"command": command}, cell.profile, cell.managed, home, project, fmt.Sprintf("gxarg-link-%d", i))
				if got := strings.Split(action, "/")[0]; got != "block" {
					t.Errorf("declared link %d: %s", i, got)
				}
			}
		})
	}
}

// TestRVGXD1 runs the D1 benign file corpus, as is and with extra keys.
func TestRVGXD1(t *testing.T) {
	out, in := os.Getenv("RVGX_D1_OUT"), os.Getenv("RVGX_D1_IN")
	if out == "" || in == "" {
		t.Skip("RVGX_D1_* not set")
	}
	src, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	w := bufio.NewWriter(file)
	defer w.Flush()
	home, project := rvgxSetup(t)
	type d1 struct {
		ID         string         `json:"id"`
		CCTool     string         `json:"cc_tool"`
		Args       map[string]any `json:"args"`
		UserIntent string         `json:"user_intent"`
	}
	var rows []d1
	for _, line := range strings.Split(string(src), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var r d1
		if json.Unmarshal([]byte(line), &r) == nil && r.CCTool != "" {
			rows = append(rows, r)
		}
	}
	for _, cell := range []struct {
		profile string
		managed bool
	}{{"default", false}, {"strict", false}} {
		t.Run(cell.profile, func(t *testing.T) {
			rvgxInstall(t, cell.profile)
			for i, r := range rows {
				variants := map[string]map[string]any{"plain": r.Args}
				a := rvgxClone(r.Args)
				a["description"] = "edit the file"
				variants["desc"] = a
				b := rvgxClone(r.Args)
				b["description"], b["timeout"], b["meta"] = r.UserIntent, 30, map[string]any{"reason": r.UserIntent}
				variants["intent"] = b
				c := rvgxClone(r.Args)
				c["context_files"] = []any{"src/main.go", "./README.md", "docs/a.md"}
				variants["ctxfiles"] = c
				for _, name := range []string{"plain", "desc", "intent", "ctxfiles"} {
					code, action, ids, text := rvgxVerdict(t, "claudecode", r.CCTool, variants[name], cell.profile, false, home, project,
						fmt.Sprintf("rvgxd1%s%d%s", cell.profile, i, name))
					short := strings.NewReplacer("\t", " ", "\n", " ").Replace(text)
					if len(short) > 300 {
						short = short[:300]
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", r.ID, name, r.CCTool, cell.profile, code, action, ids, short)
				}
			}
		})
	}
}
