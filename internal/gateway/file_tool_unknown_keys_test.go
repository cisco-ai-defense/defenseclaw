// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// fileToolUnknownKeyCall is one file tool of a connector in its reviewed
// argument shape, for the file at path.
type fileToolUnknownKeyCall struct {
	connector, tool string
	args            func(path string) map[string]any
}

func fileToolUnknownKeyCalls() []fileToolUnknownKeyCall {
	patch := func(p string) string {
		return "*** Begin Patch\n*** Update File: " + p + "\n@@\n # base\n+# k\n*** End Patch\n"
	}
	return []fileToolUnknownKeyCall{
		{"claudecode", "Write", func(p string) map[string]any { return map[string]any{"file_path": p, "content": "# k\n"} }},
		{"claudecode", "Edit", func(p string) map[string]any {
			return map[string]any{"file_path": p, "old_string": "# base", "new_string": "# k"}
		}},
		{"claudecode", "MultiEdit", func(p string) map[string]any {
			return map[string]any{"file_path": p, "edits": []any{map[string]any{"old_string": "# base", "new_string": "# k"}}}
		}},
		{"claudecode", "NotebookEdit", func(p string) map[string]any {
			return map[string]any{"notebook_path": p, "new_source": "x", "cell_id": "c1", "cell_type": "code", "edit_mode": "replace"}
		}},
		{"claudecode", "Read", func(p string) map[string]any { return map[string]any{"file_path": p} }},
		{"opencode", "write", func(p string) map[string]any { return map[string]any{"filePath": p, "content": "# k\n"} }},
		{"opencode", "write", func(p string) map[string]any { return map[string]any{"path": p, "content": "# k\n"} }},
		{"opencode", "edit", func(p string) map[string]any {
			return map[string]any{"filePath": p, "oldString": "# base", "newString": "# k"}
		}},
		{"opencode", "edit", func(p string) map[string]any {
			return map[string]any{"path": p, "oldString": "# base", "newString": "# k", "replaceAll": true}
		}},
		{"opencode", "multiedit", func(p string) map[string]any {
			return map[string]any{"filePath": p, "edits": []any{map[string]any{"filePath": p, "oldString": "# base", "newString": "# k"}}}
		}},
		{"opencode", "patch", func(p string) map[string]any { return map[string]any{"patchText": patch(p)} }},
		{"opencode", "apply_patch", func(p string) map[string]any { return map[string]any{"patchText": patch(p)} }},
		{"codex", "apply_patch", func(p string) map[string]any { return map[string]any{"command": patch(p)} }},
		{"copilot", "create", func(p string) map[string]any { return map[string]any{"path": p, "file_text": "# k\n"} }},
		{"copilot", "edit", func(p string) map[string]any { return map[string]any{"path": p, "old_str": "# base", "new_str": "# k"} }},
		{"cursor", "Write", func(p string) map[string]any { return map[string]any{"file_path": p, "content": "# k\n"} }},
		{"cursor", "Read", func(p string) map[string]any { return map[string]any{"path": p} }},
		{"hermes", "write_file", func(p string) map[string]any { return map[string]any{"path": p, "content": "# k\n"} }},
	}
}

// fileToolUnknownKeyVariants add keys outside the reviewed schema to a call
// that names the target with its reviewed key. benign is an ordinary file.
func fileToolUnknownKeyVariants(benign string) map[string]func(map[string]any) map[string]any {
	return map[string]func(map[string]any) map[string]any{
		"one-key": func(a map[string]any) map[string]any { a["description"] = "add a line"; return a },
		"several-keys": func(a map[string]any) map[string]any {
			a["description"], a["timeout"], a["meta"] = "x", 5, map[string]any{"a": "b"}
			return a
		},
		"path-named": func(a map[string]any) map[string]any { a["file"], a["target_path"] = benign, benign; return a },
		"nested": func(a map[string]any) map[string]any {
			a["options"] = map[string]any{"path": benign, "mode": "0600"}
			return a
		},
		"case-twin": func(a map[string]any) map[string]any { a["FILE_PATH"] = benign; return a },
	}
}

// fileToolHiddenTargetVariants name the target only under keys outside the
// reviewed schema; the reviewed target key names an ordinary file.
func fileToolHiddenTargetVariants(target string) map[string]func(map[string]any) map[string]any {
	return map[string]func(map[string]any) map[string]any{
		"hidden-key": func(a map[string]any) map[string]any { a["target_file"] = target; return a },
		"hidden-nested": func(a map[string]any) map[string]any {
			a["options"] = map[string]any{"dest": map[string]any{"to": target}}
			return a
		},
		// "extra" names no place: its strings are text to every protected
		// class but DefenseClaw's own state (GAP-0729, owner ruling).
		"hidden-array":       func(a map[string]any) map[string]any { a["extra"] = []any{"x", target}; return a },
		"hidden-array-files": func(a map[string]any) map[string]any { a["files"] = []any{"x", target}; return a },
	}
}

func fileToolUnknownKeyBody(t *testing.T, connector, tool string, args any, cwd, key string) string {
	t.Helper()
	session := "s-fuk-" + key
	switch connector {
	case "copilot":
		return string(mustJSON(t, map[string]any{"sessionId": session, "timestamp": 1790483549431, "cwd": cwd,
			"toolName": tool, "toolArgs": string(mustJSON(t, args))}))
	case "opencode":
		return string(mustJSON(t, map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": args,
			"session_id": session, "turn_id": "m1", "tool_call_id": "c1", "agent_name": "build", "cwd": cwd,
			"arguments_authoritative": true, "mcp_identity_status": "not_mcp"}))
	case "cursor":
		return string(mustJSON(t, map[string]any{"hook_event_name": "preToolUse", "session_id": session, "tool_call_id": "c1",
			"cwd": cwd, "tool_name": tool, "tool_input": args}))
	case "hermes":
		return string(mustJSON(t, map[string]any{"hook_event_name": "pre_tool_call", "session_id": session, "tool_call_id": "c1",
			"cwd": cwd, "tool_name": tool, "tool_input": args}))
	default:
		return string(mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": session, "turn_id": "t1",
			"cwd": cwd, "tool_name": tool, "tool_input": args, "tool_use_id": "u1"}))
	}
}

// fileToolUnknownKeyVerdict posts one hook call through the real handler in
// profile, per user or with a managed hook peer for home.
func fileToolUnknownKeyVerdict(t *testing.T, connector, tool string, args any, profile string, managed bool, home, project, key string) (string, string) {
	t.Helper()
	body := fileToolUnknownKeyBody(t, connector, tool, args, project, key)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connector
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connector+"/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	event := "PreToolUse"
	switch connector {
	case "copilot":
		event = "preToolUse"
		req.Header.Set("X-DefenseClaw-Copilot-Event", event)
	case "codex":
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	case "cursor":
		event = "preToolUse"
	case "hermes":
		event = "pre_tool_call"
	}
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(connector, "", event, []byte(body)))
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connector).ServeHTTP(recorder, req)
	var resp map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%s %s: verdict %.300q: %v", connector, tool, recorder.Body.String(), err)
	}
	action, _ := resp["action"].(string)
	return action, recorder.Body.String()
}

var fileToolUnknownKeyRank = map[string]int{"allow": 0, "alert": 1, "confirm": 1, "block": 2}

// TestFileToolExtraArgumentKeysKeepTheirPathFindings pins the class of
// gas-ux-r1 GAP-0076: a file-tool call with arguments outside its tool's
// reviewed schema is judged at least as strictly as the same call without
// them, for every connector file tool and every protected target
// (DefenseClaw's own state, a credential file, an SSH key, authorized_keys
// and the agents' hook settings), in balanced, strict and managed strict.
// One extra key, several, keys named like path fields, nested objects and
// case twins of the target key never hide the target, and a target named
// only under such a key is judged as the target. The same calls on an
// ordinary file stay allowed in balanced. export NAME=<file> binds NAME
// as NAME=<file> does, so a write through "$NAME" keeps its finding.
func TestFileToolExtraArgumentKeysKeepTheirPathFindings(t *testing.T) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	targets := map[string]string{
		"state": ".defenseclaw/config.yaml", "aws": ".aws/credentials", "ssh-key": ".ssh/id_ed25519",
		"authorized-keys": ".ssh/authorized_keys", "claude-hooks": ".claude/settings.json",
		"codex-hooks": ".codex/hooks.json", "ordinary": "proj/notes.txt",
	}
	for _, rel := range targets {
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	benign := filepath.Join(home, targets["ordinary"])
	labels := slices.Sorted(maps.Keys(targets))
	cells := []struct {
		profile string
		managed bool
	}{{"default", false}, {"default", true}, {"strict", false}, {"strict", true}}
	// The owner's test budget: no cross product of file tool x target x
	// argument variant x cell. Every file tool is judged on every target,
	// with its reviewed call and a third of the variants (variant j on tool
	// i and target k when i+j+k is a multiple of 3), in one cell: cell
	// (i+k) mod 4 for a protected target, and for the ordinary file a
	// balanced cell, per user or managed by i, where its allow is asserted.
	// So every variant is judged on every target (by six tools) and by every
	// tool (on two or three targets), and every variant on a protected target
	// in all four cells; every cell judges protected targets and the ordinary
	// file of its tier. The export forms rotate the same way over target,
	// connector and form. The checks at the end show the rotation is complete.
	type rotation struct{ a, b string }
	used := map[rotation]bool{}
	cellOf := func(i, k int, label string) int {
		if label == "ordinary" {
			return i % 2
		}
		return (i + k) % len(cells)
	}
	fileToolCalls := fileToolUnknownKeyCalls()
	bashForms := func(target string) []string {
		return []string{
			"export F=" + target + `; printf x > "$F"`,
			"export F=" + target + ` && printf x > "$F"`,
			"declare -x F=" + target + `; printf x > "$F"`,
			"readonly F=" + target + `; printf x > "$F"`,
			"export -n F=" + target + `; printf x > "$F"`,
			"f() { local F=" + target + `; printf x > "$F"; }; f`,
		}
	}
	for ci, cell := range cells {
		name := cell.profile + map[bool]string{false: "/per-user", true: "/managed"}[cell.managed]
		t.Run(name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex", "copilot", "opencode", "cursor", "hermes"} {
				installToolCallCorpusProfileConnector(t, connector, cell.profile)
			}
			// The calls are judged on every CPU (each builds its own gateway
			// and only reads the fixture, as concurrent hooks do); the checks
			// then run in order on the verdicts.
			type call struct {
				connector, tool, key string
				args                 any
				action, body         string
			}
			var calls []call
			var checks []func()
			verdict := func(connector, tool string, args any) int {
				calls = append(calls, call{connector: connector, tool: tool, args: args,
					key: fmt.Sprintf("%s-%d", strings.ReplaceAll(name, "/", "-"), len(calls)+1)})
				return len(calls) - 1
			}
			for i, call := range fileToolCalls {
				for k, label := range labels {
					if cellOf(i, k, label) != ci {
						continue
					}
					target := filepath.Join(home, targets[label])
					used[rotation{fmt.Sprintf("tool %d", i), "target " + label}] = true
					used[rotation{"cell " + name, "target " + label}] = true
					reviewed := verdict(call.connector, call.tool, call.args(target))
					checks = append(checks, func() {
						if label == "state" && call.tool != "Read" && calls[reviewed].action != "block" {
							t.Fatalf("%s %s-%d: the reviewed write of DefenseClaw's state is %q, not block", name, call.tool, i, calls[reviewed].action)
						}
					})
					variants := fileToolUnknownKeyVariants(benign)
					if label != "ordinary" {
						for hidden, variant := range fileToolHiddenTargetVariants(target) {
							variants[hidden] = func(map[string]any) map[string]any { return variant(call.args(benign)) }
						}
					}
					for j, variantName := range slices.Sorted(maps.Keys(variants)) {
						if (i+j+k)%3 != 0 {
							continue
						}
						used[rotation{"variant " + variantName, "target " + label}] = true
						used[rotation{"variant " + variantName, fmt.Sprintf("tool %d", i)}] = true
						if label != "ordinary" {
							used[rotation{"variant " + variantName + " on " + label, "cell " + name}] = true
						}
						v := verdict(call.connector, call.tool, variants[variantName](call.args(target)))
						checks = append(checks, func() {
							got, body := calls[v].action, calls[v].body
							if label == "ordinary" {
								// Copilot CLI refuses a call with an unreviewed key
								// before any rule (HOOK-TOOL-CALL-UNPARSED); every
								// other connector judges the ordinary file.
								if cell.profile == "default" && call.connector != "copilot" && got != "allow" {
									t.Errorf("%s %s %s-%d %s: ordinary file got %q: %.400s", name, call.connector, call.tool, i, variantName, got, body)
								}
								return
							}
							if variantName == "hidden-array" && label != "state" {
								return
							}
							if fileToolUnknownKeyRank[got] < fileToolUnknownKeyRank[calls[reviewed].action] {
								t.Errorf("%s %s %s-%d %s on %s: %q, weaker than the reviewed call's %q: %.400s",
									name, call.connector, call.tool, i, variantName, label, got, calls[reviewed].action, body)
							}
						})
					}
				}
			}
			for k, label := range labels {
				target := filepath.Join(home, targets[label])
				for c, connector := range []string{"claudecode", "codex"} {
					literal := -1
					for f, form := range bashForms(target) {
						formCell := (k + c + f) % len(cells)
						if label == "ordinary" {
							formCell = (c + f) % 2
						}
						if formCell != ci {
							continue
						}
						used[rotation{fmt.Sprintf("form %d %s", f, connector), "target " + label}] = true
						if label != "ordinary" {
							used[rotation{fmt.Sprintf("form %d", f), "cell " + name}] = true
						}
						if literal < 0 {
							literal = verdict(connector, "Bash", map[string]any{"command": "printf x > " + target})
						}
						v, lit := verdict(connector, "Bash", map[string]any{"command": form}), literal
						checks = append(checks, func() {
							got, body := calls[v].action, calls[v].body
							if label == "ordinary" {
								if cell.profile == "default" && got != "allow" {
									t.Errorf("%s %s %q: ordinary file got %q: %.400s", name, connector, form, got, body)
								}
								return
							}
							if fileToolUnknownKeyRank[got] < fileToolUnknownKeyRank[calls[lit].action] {
								t.Errorf("%s %s %q on %s: %q, weaker than the literal write's %q: %.400s", name, connector, form, label, got, calls[lit].action, body)
							}
						})
					}
				}
			}
			forEachOnEveryCPU(len(calls), func(i int) {
				c := &calls[i]
				c.action, c.body = fileToolUnknownKeyVerdict(t, c.connector, c.tool, c.args, cell.profile, cell.managed, home, project, c.key)
			})
			for _, check := range checks {
				check()
			}
		})
	}
	// The rotation is complete: every tool on every target, every variant on
	// every target and by every tool, every variant on a protected target in
	// every cell, every export form for both connectors on every target and
	// in every cell, and every cell on a protected target and every balanced
	// cell on the ordinary file.
	var missing []string
	need := func(a, b string) {
		if !used[rotation{a, b}] {
			missing = append(missing, a+" x "+b)
		}
	}
	cellNames := []string{"default/per-user", "default/managed", "strict/per-user", "strict/managed"}
	variantNames := slices.Sorted(maps.Keys(fileToolUnknownKeyVariants(benign)))
	hiddenNames := slices.Sorted(maps.Keys(fileToolHiddenTargetVariants(benign)))
	for _, label := range labels {
		names := variantNames
		if label != "ordinary" {
			names = append(slices.Clone(variantNames), hiddenNames...)
		}
		for i := range fileToolCalls {
			need(fmt.Sprintf("tool %d", i), "target "+label)
		}
		for _, v := range names {
			need("variant "+v, "target "+label)
			if label != "ordinary" {
				for _, cell := range cellNames {
					need("variant "+v+" on "+label, "cell "+cell)
				}
			}
		}
		for f := range 6 {
			for _, connector := range []string{"claudecode", "codex"} {
				need(fmt.Sprintf("form %d %s", f, connector), "target "+label)
			}
		}
	}
	for i := range fileToolCalls {
		for _, v := range variantNames {
			need("variant "+v, fmt.Sprintf("tool %d", i))
		}
	}
	for _, cell := range cellNames {
		need("cell "+cell, "target state")
		for f := range 6 {
			need(fmt.Sprintf("form %d", f), "cell "+cell)
		}
	}
	need("cell default/per-user", "target ordinary")
	need("cell default/managed", "target ordinary")
	if len(missing) > 0 {
		t.Errorf("the rotation left %d combinations unjudged: %v", len(missing), missing)
	}
}

// TestFileToolUnknownKeysPastTheTargetBoundFailClosed pins the Possible-grade
// count bound: balanced warns and audits, strict blocks, and plain text
// values do not trigger the bound.
func TestFileToolUnknownKeysPastTheTargetBoundFailClosed(t *testing.T) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	many := func(spell func(int) string) map[string]any {
		args := map[string]any{"file_path": filepath.Join(project, "notes.txt"), "content": "x"}
		values := make([]any, 0, 24)
		for i := range 24 {
			values = append(values, spell(i))
		}
		args["files"] = values
		return args
	}
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	paths := many(func(i int) string { return fmt.Sprintf("%s/out/f%d.txt", project, i) })
	if got, body := fileToolUnknownKeyVerdict(t, "claudecode", "Write", paths, "default", false, home, project, "bound-paths"); got != "alert" ||
		!strings.Contains(body, "exceed the target verification bound") {
		t.Fatalf("24 path-shaped values: %q: %.400s", got, body)
	}
	installToolCallCorpusProfileConnector(t, "claudecode", "strict")
	if got, body := fileToolUnknownKeyVerdict(t, "claudecode", "Write", paths, "strict", false, home, project, "bound-paths-strict"); got != "block" ||
		!strings.Contains(body, "exceed the target verification bound") {
		t.Fatalf("24 path-shaped values in strict: %q: %.400s", got, body)
	}
	installToolCallCorpusProfileConnector(t, "claudecode", "default")
	words := many(func(i int) string { return fmt.Sprintf("note %d", i) })
	if got, body := fileToolUnknownKeyVerdict(t, "claudecode", "Write", words, "default", false, home, project, "bound-words"); got != "allow" {
		t.Fatalf("24 text values: %q: %.400s", got, body)
	}
}
