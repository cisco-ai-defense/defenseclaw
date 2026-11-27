// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

// DET111 probe (bar step 0b, lane L0-META). Skipped unless DET111_OUT is set.
//
// It sends every row (case-v1 corpus rows and the rows the generators make)
// through the real hook path in the five tiers of gap0437Packs, on each route,
// in the POSIX flavor and the Windows hook-host flavor, and writes one line
// per (row, tier, route):
//
//	<row key>|<tier>|<route>|<action> <severity> <rule ids joined by ,>
//
// plus DET111_OUT.meta with one tab-separated line per row key (role, generator,
// variant, seed, twin, gap, tool, dialect, windows, truth, cwdshift, cwd, command). det111cmp.py compares two
// such files (head against base) and checks the generator properties.
//
// Environment:
//
//	DET111_OUT       output rows file (required to run)
//	DET111_CASES     comma list of case-v1 jsonl files (the corpus rows; also the seeds)
//	DET111_GEN       comma list: corpus, r1, r2w, r2o, r3 (default corpus,r1,r2w,r2o,r3)
//	DET111_SEEDS     optional file: one case id per line; restricts the corpus seeds of the generators
//	DET111_BENIGN    max benign seeds the generators spell (default 300)
//	DET111_BENIGN_CASES  case-v1 files that are the benign seeds (the owner corpora sample); without it the corpus rows with expected_disposition allow are
//	DET111_ROUTES    comma list of routes (default hook-cc,hook-codex,inspect-oc,llm,as-is)
//	DET111_NATIVE    1 adds the native connector shapes of each corpus row (default 1 for corpus rows)
//	DET111_SHARD     k/n: run the seed groups whose hash mod n is k
//	DET111_ONLY      substring filter on row keys (debugging)
//
// A tool call that cannot be sent is written as "error ..." and counted, never
// skipped; the row count of the output is printed so a runner can fail closed.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// det111Esc keeps a value on one tab-separated line.
func det111Esc(s string) string {
	return strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r").Replace(s)
}

func det111Verdict(out map[string]any) string {
	action, _ := out["action"].(string)
	if action == "" {
		action = "allow"
	}
	var rules []string
	switch r := out["rule_ids"].(type) {
	case []any:
		for _, x := range r {
			rules = append(rules, fmt.Sprint(x))
		}
	}
	if len(rules) == 0 {
		if r, ok := out["findings"].([]any); ok {
			for _, x := range r {
				s := fmt.Sprint(x)
				if i := strings.IndexByte(s, ':'); i > 0 {
					s = s[:i]
				}
				rules = append(rules, s)
			}
		}
	}
	sort.Strings(rules)
	severity, _ := out["severity"].(string)
	return action + " " + severity + " " + strings.Join(rules, ",")
}

// det111Send answers one call through a handler. It never fails the test: an
// unreadable answer is the verdict "error ...".
func det111Send(h http.HandlerFunc, call shapeParityCall, managedTier bool) (verdict string) {
	defer func() {
		if r := recover(); r != nil {
			verdict = fmt.Sprintf("error panic %v", r)
		}
	}()
	raw, _ := json.Marshal(call.body)
	route := call.route
	if route == "" {
		route = "/api/v1/" + call.conn + "/hook"
	}
	req := httptest.NewRequest(http.MethodPost, route, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range call.headers {
		req.Header.Set(key, value)
	}
	if managedTier && call.route == "" {
		if ev := hookpaths.ResolveConnector(call.conn, "", call.event, raw); ev != "" {
			req.Header.Set(hookpaths.Header, ev)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		return fmt.Sprintf("error http %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		return "error not-json"
	}
	return det111Verdict(out)
}

func det111SetFlavor(t *testing.T, windows bool, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	windowsHookHost = func() bool { return windows }
	if windows {
		sameHostHomeForTest = home
	} else {
		sameHostHomeForTest = ""
	}
}

// det111Layout is the POSIX file tree the template seeds run in (as the TD probe).
type det111Layout struct {
	Root, Home, Project string
}

func det111MakeLayout(t *testing.T) det111Layout {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{
		filepath.Join(project, ".git", "hooks"), filepath.Join(project, "src"), filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws"), filepath.Join(home, ".kube"), filepath.Join(home, ".claude"),
		filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".config", "systemd", "user"),
		filepath.Join(home, ".config", "autostart"), filepath.Join(home, "bob"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".ssh/authorized_keys", ".ssh/id_rsa", ".aws/credentials", ".kube/config", ".bashrc",
		".claude/settings.json", ".defenseclaw/config.yaml", ".git-credentials", "proj/notes.txt", "proj/src/notes.txt"} {
		p := filepath.Join(home, filepath.FromSlash(f))
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte("marker\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return det111Layout{Root: root, Home: home, Project: project}
}

func det111Fields(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// det111BuildRows makes every row of the run from the corpus files and the generators.
func det111BuildRows(t *testing.T, layout det111Layout) []det111Row {
	t.Helper()
	gens := map[string]bool{}
	genEnv := os.Getenv("DET111_GEN")
	if genEnv == "" {
		genEnv = "corpus,r1,r2w,r2o,r3"
	}
	for _, g := range det111Fields(genEnv) {
		gens[g] = true
	}
	cases, skipped, err := det111LoadCases(det111Fields(os.Getenv("DET111_CASES")))
	if err != nil {
		t.Fatalf("DET111_CASES: %v", err)
	}
	if out := os.Getenv("DET111_OUT"); len(skipped) > 0 {
		_ = os.WriteFile(out+".skipped", []byte(strings.Join(skipped, "\n")+"\n"), 0o644)
	}
	var rows []det111Row
	if gens["corpus"] {
		for _, c := range cases {
			rows = append(rows, c.row())
		}
	}
	// Generators: template seeds (own tree) and corpus seeds.
	restrict := map[string]bool{}
	if p := os.Getenv("DET111_SEEDS"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("DET111_SEEDS: %v", err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				restrict[l] = true
			}
		}
	}
	maxBenign := 300
	if v, err := strconv.Atoi(os.Getenv("DET111_BENIGN")); err == nil {
		maxBenign = v
	}
	var ownerBenign []det111Case
	if p := det111Fields(os.Getenv("DET111_BENIGN_CASES")); len(p) > 0 {
		var err error
		if ownerBenign, _, err = det111LoadCases(p); err != nil {
			t.Fatalf("DET111_BENIGN_CASES: %v", err)
		}
	}
	rows = append(rows, det111Generate(gens, layout, cases, ownerBenign, restrict, maxBenign)...)
	if only := os.Getenv("DET111_ONLY"); only != "" {
		kept := rows[:0]
		for _, r := range rows {
			if strings.Contains(r.Key, only) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	for i := 1; i < len(rows); i++ {
		if rows[i].Key == rows[i-1].Key {
			t.Fatalf("duplicate row key %s", rows[i].Key)
		}
	}
	return rows
}

func TestDET111Probe(t *testing.T) {
	outPath := os.Getenv("DET111_OUT")
	if outPath == "" {
		t.Skip("DET111 probe: set DET111_OUT")
	}
	prevHost, prevSame := windowsHookHost, sameHostHomeForTest
	t.Cleanup(func() { windowsHookHost, sameHostHomeForTest = prevHost, prevSame })
	layout := det111MakeLayout(t)
	rows := det111BuildRows(t, layout)
	shard, shards := 0, 1
	if s := os.Getenv("DET111_SHARD"); s != "" {
		k, n, ok := strings.Cut(s, "/")
		ki, e1 := strconv.Atoi(k)
		ni, e2 := strconv.Atoi(n)
		if !ok || e1 != nil || e2 != nil || ni < 1 || ki < 0 || ki >= ni {
			t.Fatalf("DET111_SHARD %q: want k/n", s)
		}
		shard, shards = ki, ni
	}
	routes := map[string]bool{}
	routeEnv := os.Getenv("DET111_ROUTES")
	if routeEnv == "" {
		routeEnv = "hook-cc,hook-codex,inspect-oc,llm,as-is"
	}
	for _, r := range det111Fields(routeEnv) {
		routes[r] = true
	}
	nativeOff := os.Getenv("DET111_NATIVE") == "0"

	// Rows of one flavor and home run together.
	type flavor struct {
		windows bool
		home    string
	}
	byFlavor := map[flavor][]det111Row{}
	var flavors []flavor
	var meta strings.Builder
	kept := 0
	for _, r := range rows {
		if det111Shard(r.Group, shards) != shard {
			continue
		}
		kept++
		fl := flavor{r.Windows, r.Home}
		if _, ok := byFlavor[fl]; !ok {
			flavors = append(flavors, fl)
		}
		byFlavor[fl] = append(byFlavor[fl], r)
		fmt.Fprintf(&meta, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%t\t%s\t%t\t%s\t%s\n", r.Key, r.Role, r.Gen, r.Variant, r.Seed, r.Pair, r.Gap, r.Tool, r.Dialect, r.Windows, r.Truth, r.CWDShift, det111Esc(r.CWD), det111Esc(r.command()))
	}
	sort.Slice(flavors, func(i, j int) bool {
		if flavors[i].windows != flavors[j].windows {
			return !flavors[i].windows
		}
		return flavors[i].home < flavors[j].home
	})
	f, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	norm := func(s string) string { return strings.ReplaceAll(s, layout.Root, "$T") }
	written, errs := 0, 0
	emit := func(r det111Row, tier, route, v string) {
		if strings.HasPrefix(v, "error") {
			errs++
		}
		fmt.Fprintf(f, "%s|%s|%s|%s\n", r.Key, tier, route, norm(v))
		written++
	}
	started := time.Now()
	for _, fl := range flavors {
		for _, p := range gap0437Packs {
			fl, p := fl, p
			// One subtest per flavor and tier: the servers (a store each) are released when it ends.
			t.Run(fmt.Sprintf("windows=%t/%s/%s", fl.windows, p.name, filepath.Base(strings.ReplaceAll(fl.home, "\\", "/"))), func(t *testing.T) {
				det111SetFlavor(t, fl.windows, fl.home)
				handlers, stores := det111Handlers(t, p)
				var proxy *GuardrailProxy
				if !p.managed && routes["llm"] {
					proxy = newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
					proxy.cfg.RulePack = p.pack
					installToolCallCorpusProfileConnector(t, proxy.connectorName(), p.pack)
				}
				for i, r := range byFlavor[fl] {
					det111RunRow(r, p, handlers, proxy, routes, nativeOff, emit)
					if i%100 == 99 {
						det111TrimWAL(stores)
					}
				}
				det111TrimWAL(stores)
			})
		}
	}
	if err := os.WriteFile(outPath+".meta", []byte(meta.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("DET111 rows=%d lines=%d errors=%d shard=%d/%d elapsed=%s", kept, written, errs, shard, shards, time.Since(started).Round(time.Second))
	fmt.Printf("DET111_ROWS=%d LINES=%d ERRORS=%d\n", kept, written, errs)
}

func det111RunRow(r det111Row, p gap0437Pack, handlers map[string]http.HandlerFunc, proxy *GuardrailProxy,
	routes map[string]bool, nativeOff bool, emit func(det111Row, string, string, string)) {
	cwd := r.CWD
	args := r.Args
	if r.Surface == "text" || r.Surface == "tool_result" || r.Surface == "stateful" {
		det111RunSurface(r, p, handlers, routes, emit)
		return
	}
	envelope := func(tool string) map[string]any { return shapeParityEnvelope("PreToolUse", cwd, tool, args) }
	codexHeaders := map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}
	if r.Tool == "Write" || r.Tool == "Edit" || r.Tool == "Read" {
		// The Claude Code names of the path keys, for rows that carry another connector's key.
		if _, ok := args["file_path"]; !ok {
			for _, k := range []string{"path", "TargetFile", "filepath", "file", "AbsolutePath", "target_file"} {
				if v, ok := args[k]; ok {
					cp := map[string]any{}
					for kk, vv := range args {
						cp[kk] = vv
					}
					cp["file_path"] = v
					args = cp
					break
				}
			}
		}
	}
	switch r.Tool {
	case "":
	case "Bash", "PowerShell":
		if routes["hook-cc"] {
			v := det111Send(handlers["claudecode"], shapeParityCall{name: "hook-cc", conn: "claudecode", event: "PreToolUse", body: envelope(r.Tool)}, p.managed)
			emit(r, p.name, "hook-cc", v)
		}
		if routes["hook-codex"] {
			v := det111Send(handlers["codex"], shapeParityCall{name: "hook-codex", conn: "codex", event: "PreToolUse", headers: codexHeaders, body: envelope("Bash")}, p.managed)
			emit(r, p.name, "hook-codex", v)
		}
		if routes["inspect-oc"] {
			v := det111Send(handlers["openclaw"], shapeParityCall{name: "inspect-oc", conn: "openclaw", route: shapeParityInspectRoute,
				body: map[string]any{"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": r.command(), "workdir": cwd}}}, p.managed)
			emit(r, p.name, "inspect-oc", v)
		}
		if proxy != nil && routes["llm"] {
			raw, _ := json.Marshal(map[string]string{"command": r.command()})
			calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": r.Tool, "arguments": string(raw)}}})
			v := "allow  "
			if res := proxy.inspectToolCalls(context.Background(), calls); res != nil {
				rs := append([]string(nil), res.RuleIDs...)
				sort.Strings(rs)
				v = res.Action + " " + res.Severity + " " + strings.Join(rs, ",")
			}
			emit(r, p.name, "llm", v)
		}
	case "apply_patch":
		if routes["hook-codex"] {
			v := det111Send(handlers["codex"], shapeParityCall{name: "hook-codex", conn: "codex", event: "PreToolUse", headers: codexHeaders, body: envelope("apply_patch")}, p.managed)
			emit(r, p.name, "hook-codex", v)
		}
		return
	default:
		if routes["hook-cc"] {
			v := det111Send(handlers["claudecode"], shapeParityCall{name: "hook-cc", conn: "claudecode", event: "PreToolUse", body: envelope(r.Tool)}, p.managed)
			emit(r, p.name, "hook-cc", v)
		}
	}
	if routes["as-is"] && r.RawTool != "" && r.Conn != "" && (r.RawTool != r.Tool || (r.Conn != "claudecode" && r.Conn != "codex")) {
		if call, ok := det111AsIs(r, cwd); ok {
			if h := handlers[call.conn]; h != nil {
				emit(r, p.name, "as-is:"+call.conn+"/"+r.RawTool, det111Send(h, call, p.managed))
			}
		}
	}
	if !r.Native || nativeOff || r.Tool == "" {
		return
	}
	calls := append(shapeParityNative(r.Tool, args, cwd), shapeParityNativeMore(r.Tool, args, cwd)...)
	for _, c := range calls {
		h := handlers[c.conn]
		if h == nil {
			continue
		}
		emit(r, p.name, "native:"+c.name, det111Send(h, c, p.managed))
	}
}

// det111AsIs sends the row's own tool name and arguments through its own
// connector's hook, for the connectors whose hook body is the generic envelope
// (corpus rows written in a connector's native tool names).
func det111AsIs(r det111Row, cwd string) (shapeParityCall, bool) {
	args := r.Args
	switch r.Conn {
	case "claudecode", "devin":
		return shapeParityCall{name: "as-is", conn: r.Conn, event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, r.RawTool, args)}, true
	case "codex":
		return shapeParityCall{name: "as-is", conn: "codex", event: "PreToolUse",
			headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
			body:    shapeParityEnvelope("PreToolUse", cwd, r.RawTool, args)}, true
	case "amp":
		return shapeParityCall{name: "as-is", conn: "amp", event: "tool.call", body: shapeParityEnvelope("tool.call", cwd, r.RawTool, args)}, true
	case "kiro":
		return shapeParityCall{name: "as-is", conn: "kiro", event: "preToolUse", body: shapeParityEnvelope("preToolUse", cwd, r.RawTool, args)}, true
	case "opencode":
		return shapeParityCall{name: "as-is", conn: "opencode", event: "tool.execute.before", body: shapeParityOpenCode(cwd, r.RawTool, args)}, true
	case "hermes":
		return shapeParityCall{name: "as-is", conn: "hermes", event: "pre_tool_call", body: shapeParityHermes(cwd, r.RawTool, args)}, true
	case "openclaw":
		return shapeParityCall{name: "as-is", conn: "openclaw", route: shapeParityInspectRoute, body: shapeParityOpenClaw(r.RawTool, args)}, true
	}
	return shapeParityCall{}, false
}

// det111RunSurface sends the rows that are not one tool call: a prompt
// (UserPromptSubmit), a tool result (PostToolUse) and a stateful sequence of
// events in one session (the verdict is the last event's).
func det111RunSurface(r det111Row, p gap0437Pack, handlers map[string]http.HandlerFunc, routes map[string]bool,
	emit func(det111Row, string, string, string)) {
	codexHeaders := map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}
	sess := func(route string) string { return "det111-" + det111Key(r.Key, p.name, route) }
	cc := func(route string, body map[string]any) {
		emit(r, p.name, route, det111Send(handlers["claudecode"], shapeParityCall{name: route, conn: "claudecode", event: det111Str(body, "hook_event_name"), body: body}, p.managed))
	}
	switch r.Surface {
	case "text":
		if routes["hook-cc"] {
			cc("hook-cc:prompt", map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": sess("cc"), "cwd": r.CWD, "prompt": r.Content})
		}
	case "tool_result":
		inv := det111Obj(r.Result, "invocation")
		res := det111Obj(r.Result, "result")
		tool := det111Str(inv, "tool_name")
		input, _ := inv["args"].(map[string]any)
		if routes["hook-cc"] {
			cc("hook-cc:tool-result", map[string]any{"hook_event_name": "PostToolUse", "session_id": sess("cc"), "cwd": r.CWD, "tool_name": tool,
				"tool_use_id": "tu-" + sess("cc"), "tool_input": input, "tool_response": det111Str(res, "content")})
		}
	case "stateful":
		for _, route := range []string{"hook-cc", "hook-codex"} {
			if !routes[route] {
				continue
			}
			session := sess(route)
			verdict := "error no-events"
			for i, ev := range r.Events {
				e, _ := ev.(map[string]any)
				tool := det111NormTool(det111Str(e, "tool_name"))
				if tool == "" {
					tool = "Bash"
				}
				input, _ := e["args"].(map[string]any)
				if len(input) == 0 {
					input = map[string]any{"command": det111Str(e, "command")}
				}
				cwd := det111Str(e, "cwd")
				if cwd == "" {
					cwd = r.CWD
				}
				call := shapeParityCall{name: route, conn: "claudecode", event: "PreToolUse"}
				h := handlers["claudecode"]
				tn := tool
				if route == "hook-codex" {
					call.conn, call.headers, h, tn = "codex", codexHeaders, handlers["codex"], "Bash"
				}
				call.body = map[string]any{"hook_event_name": "PreToolUse", "session_id": session, "cwd": cwd, "tool_name": tn,
					"tool_use_id": fmt.Sprintf("tu-%s-%d", session, i), "tool_input": input}
				verdict = det111Send(h, call, p.managed)
				if i == len(r.Events)-1 {
					break
				}
				if det111Str(e, "outcome") == "succeeded" || det111Str(e, "outcome") == "" {
					content := ""
					if tr, ok := e["tool_result"].(map[string]any); ok {
						content = det111Str(tr, "content")
						if content == "" {
							content = det111Str(tr, "text")
						}
					}
					post := shapeParityCall{name: route, conn: call.conn, event: "PostToolUse", headers: call.headers}
					post.body = map[string]any{"hook_event_name": "PostToolUse", "session_id": session, "cwd": cwd, "tool_name": tn,
						"tool_use_id": fmt.Sprintf("tu-%s-%d", session, i), "tool_input": input, "tool_response": content}
					if route == "hook-codex" {
						post.headers = map[string]string{"X-DefenseClaw-Hook-Event": "PostToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract}
					}
					_ = det111Send(h, post, p.managed)
				}
			}
			emit(r, p.name, route+":stateful", verdict)
		}
	}
}

// det111Handlers is shapeParityHandlers that also returns the audit stores. The
// stores run with wal_autocheckpoint=0, so every hook call grows the log of its
// store until a guard pass cuts it; without det111TrimWAL a shard wrote gigabytes.
func det111Handlers(t *testing.T, p gap0437Pack) (map[string]http.HandlerFunc, []*audit.Store) {
	t.Helper()
	handlers := map[string]http.HandlerFunc{}
	var stores []*audit.Store
	for _, conn := range shapeParityConnectors {
		srv := gap0437Server(t, p, conn, "action")
		installToolCallCorpusProfileConnector(t, conn, p.pack)
		stores = append(stores, srv.store)
		if conn == "openclaw" {
			srv.inspectToolScanTimeout = time.Minute
			handlers[conn] = srv.handleInspectTool
			continue
		}
		handlers[conn] = srv.handleAgentHook(conn)
	}
	return handlers, stores
}

// det111TrimWAL cuts the WAL of each store to (near) zero: a copy pass, then a
// truncate pass, which the guard allows when nothing was committed in between.
func det111TrimWAL(stores []*audit.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, s := range stores {
		for i := 0; i < 2; i++ {
			_, _ = s.CheckpointWALIfLarge(ctx, 1<<20, 2*time.Second)
		}
	}
}
