// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

// Command s7bench replays labelled agent tool-call traces through the real
// DefenseClaw hook path (claudecode PreToolUse/PostToolUse) and writes one
// JSON line per decision with per-layer outputs. Build with -tags s7bench.
// It writes no corpus content to stdout; results go to -out.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

type event struct {
	ToolName string          `json:"tool_name"`
	Args     json.RawMessage `json:"args"`
	Command  string          `json:"command"`
	CWD      string          `json:"cwd"`
	Dialect  string          `json:"dialect"`
	Outcome  string          `json:"outcome"`
	// Result is the tool output (tool-result surface corpora); sent as the PostToolUse tool_response with -surface tool-result.
	Result string `json:"result"`
}

type payload struct {
	event
	Events []event `json:"events"`
	Intent string  `json:"user_intent"`
	Prompt string  `json:"user_prompt"`
	// Content is case-v1 payload.content: the user's request (AgentDojo, MCPTox, InjecAgent, agent-trace) or, for prompt corpora, the user turn.
	Content string `json:"content"`
}

type corpusCase struct {
	ID      string  `json:"id"`
	Payload payload `json:"payload"`
	Strata  struct {
		Provider string `json:"provider"`
	} `json:"strata"`
}

type record struct {
	Case       string                `json:"case"`
	Connector  string                `json:"connector,omitempty"`
	Idx        int                   `json:"idx"`
	N          int                   `json:"n"`
	SrcTool    string                `json:"src_tool"`
	Tool       string                `json:"tool"`
	Mapped     string                `json:"mapped"`
	Status     int                   `json:"status"`
	Action     string                `json:"action"`
	RawAction  string                `json:"raw_action"`
	Severity   string                `json:"sev"`
	WouldBlock bool                  `json:"would_block"`
	RuleIDs    []string              `json:"rule_ids,omitempty"`
	Findings   []string              `json:"findings,omitempty"`
	DetOnly    bool                  `json:"detection_only,omitempty"`
	Reason     string                `json:"reason,omitempty"`
	Det        *gateway.S7Det        `json:"det,omitempty"`
	DM         *gateway.S7DM         `json:"dm,omitempty"`
	Judge      *gateway.S7Judge      `json:"judge,omitempty"`
	JudgeCalls []gateway.S7JudgeCall `json:"judge_calls,omitempty"`
	PostStatus int                   `json:"post_status,omitempty"`
	// Session surface (chainbench): the PostToolUse answer of the step, kept apart from the PreToolUse answer above, and the redacted
	// secret-flow shadow hits the step added (internal/flow in shadow records, never answers).
	PostAction   string            `json:"post_action,omitempty"`
	PostRaw      string            `json:"post_raw_action,omitempty"`
	PostSeverity string            `json:"post_sev,omitempty"`
	PostRuleIDs  []string          `json:"post_rule_ids,omitempty"`
	FlowHits     []string          `json:"flow_hits,omitempty"`
	LatencyUs    int64             `json:"lat_us"`
	Err          string            `json:"err,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
}

var shellTools = map[string]bool{"bash_command": true, "bash": true, "execute_command": true, "shell": true,
	"run_command": true, "terminal": true, "exec": true, "run_shell_command": true, "execute_bash": true,
	"run_terminal_cmd": true, "command": true, "sh": true, "zsh": true, "shell_exec": true, "local_shell": true,
	"shell.run": true, "shell.exec": true, "system.execute": true, "terminal.execute": true}
var nativeTools = map[string]string{"bash": "Bash", "read": "Read", "write": "Write", "edit": "Edit", "multiedit": "MultiEdit",
	"glob": "Glob", "grep": "Grep", "webfetch": "WebFetch", "websearch": "WebSearch", "todowrite": "TodoWrite",
	"task": "Task", "notebookedit": "NotebookEdit", "toolsearch": "ToolSearch"}
var nonWord = regexp.MustCompile(`[^A-Za-z0-9_\-]`)

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case []any:
				parts := make([]string, 0, len(t))
				for _, p := range t {
					parts = append(parts, fmt.Sprint(p))
				}
				if len(parts) > 0 {
					return strings.Join(parts, " ")
				}
			}
		}
	}
	return ""
}

// mapTool projects a corpus event onto the Claude Code tool vocabulary.
func mapTool(ev event) (string, json.RawMessage, string) {
	var args map[string]any
	_ = json.Unmarshal(ev.Args, &args)
	if args == nil {
		args = map[string]any{}
	}
	name := strings.TrimSpace(ev.ToolName)
	lower := strings.ToLower(name)
	cmd := ev.Command
	if cmd == "" {
		cmd = str(args, "command", "cmd", "script", "code", "commands", "input")
	}
	if shellTools[lower] && cmd != "" {
		in := map[string]any{"command": cmd}
		b, _ := json.Marshal(in)
		return "Bash", b, "shell"
	}
	if lower == "text_editor" || lower == "str_replace_based_edit_tool" || lower == "str_replace_editor" {
		// The Anthropic text-editor tool: create is a file write, str_replace an edit.
		p := str(args, "path", "file_path")
		switch str(args, "command") {
		case "create":
			if p != "" {
				b, _ := json.Marshal(map[string]any{"file_path": p, "content": str(args, "file_text", "content")})
				return "Write", b, "write"
			}
		case "str_replace", "insert":
			if p != "" {
				b, _ := json.Marshal(map[string]any{"file_path": p, "old_string": str(args, "old_str"), "new_string": str(args, "new_str")})
				return "Edit", b, "edit"
			}
		case "view":
			if p != "" {
				b, _ := json.Marshal(map[string]any{"file_path": p})
				return "Read", b, "read"
			}
		}
	}
	switch lower {
	case "write", "write_file", "create_file", "file_write", "writefile", "save_file":
		p := str(args, "file_path", "path", "filename", "file", "target")
		c := str(args, "content", "text", "contents", "data", "file_text")
		if p != "" {
			b, _ := json.Marshal(map[string]any{"file_path": p, "content": c})
			return "Write", b, "write"
		}
	case "read", "read_file", "file_read", "view_file", "cat", "readfile", "open_file":
		p := str(args, "file_path", "path", "filename", "file", "target")
		if p != "" {
			b, _ := json.Marshal(map[string]any{"file_path": p})
			return "Read", b, "read"
		}
	case "edit", "edit_file", "str_replace", "replace_in_file":
		p := str(args, "file_path", "path", "filename")
		if p != "" {
			b, _ := json.Marshal(map[string]any{"file_path": p, "old_string": str(args, "old_string", "old_str", "old"), "new_string": str(args, "new_string", "new_str", "new", "content")})
			return "Edit", b, "edit"
		}
	}
	if canon, ok := nativeTools[lower]; ok {
		if canon == "Bash" && cmd != "" {
			b, _ := json.Marshal(map[string]any{"command": cmd})
			return "Bash", b, "shell"
		}
		raw := ev.Args
		if len(raw) == 0 {
			raw = json.RawMessage(`{}`)
		}
		return canon, raw, "native"
	}
	raw := ev.Args
	if len(raw) == 0 || string(raw) == "null" {
		raw = json.RawMessage(`{}`)
	}
	return "mcp__bench__" + nonWord.ReplaceAllString(name, "_"), raw, "mcp"
}

func main() {
	corpus := flag.String("corpus", "", "corpus JSONL")
	ids := flag.String("ids", "", "optional file with case ids to run (one per line)")
	out := flag.String("out", "", "output JSONL")
	pack := flag.String("pack", "default", "rule pack: default|permissive|strict")
	mode := flag.String("mode", "action", "hook mode: action|observe")
	policyDir := flag.String("policy-dir", "", "repo policies directory")
	workers := flag.Int("workers", 8, "parallel cases")
	limit := flag.Int("limit", 0, "max cases")
	strategy := flag.String("strategy", "regex_only", "guardrail.detection_strategy for the hook path")
	judgeModel := flag.String("judge-model", "", "judge model (OpenAI-compatible name at -judge-url); empty: no judge")
	judgeURL := flag.String("judge-url", "", "judge base URL")
	dmURL := flag.String("dm-url", "", "decision model System One URL; empty: off")
	dmModel := flag.String("dm-model", "", "decision model name")
	dmTimeout := flag.Float64("dm-timeout", 0, "decision model timeout seconds (0: product default)")
	judgeTimeout := flag.Float64("judge-timeout", 0, "hook judge timeout seconds (0: product default)")
	judgeParallel := flag.Int("judge-max-parallel", 16, "guardrail.judge.max_parallel; the local proxy stands in for a remote endpoint, which the product does not serialize (a loopback judge URL defaults to 1)")
	dmHook := flag.Bool("dm-hook", false, "decision model answers alone for the connector (cascade 2)")
	layers := flag.String("layers", "", "probe layers per call: dm,judge")
	connectorFlag := flag.String("connector", "claudecode", "claudecode (legacy: every case as a Claude Code call) | auto (each case to the hook handler of its strata.provider connector, with that connector's payload shape) | a connector name")
	scratch := flag.String("scratch-dir", "", "parent directory of the run's scratch dir (default: the system temp dir)")
	scratchCapMB := flag.Int("scratch-cap-mb", 2048, "fail the run loudly when its scratch dir (audit.db + WAL) passes this many MiB")
	walGuard := flag.Bool("wal-guard", true, "run the product audit WAL guard pass every 500 ms (false reproduces the unbounded WAL growth; measurement only, keep -scratch-cap-mb low)")
	post := flag.Bool("post", true, "send PostToolUse for events whose outcome is succeeded")
	det := flag.Bool("det", true, "record the trusted-action deterministic evaluation")
	surface := flag.String("surface", "hook", "hook (tool calls through the connector hook) | prompt (payload.content through the /llm proxy GuardrailInspector, direction prompt; the connector UserPromptSubmit answer goes to extra) | tool-result (each event's result as the PostToolUse tool_response; the PostToolUse answer is the decision) | session (whole sessions in order, one session id per case: PreToolUse then, with -post, PostToolUse carrying the event's result; both answers recorded per step, the PostToolUse one in post_*)")
	promptFromContent := flag.Bool("prompt-from-content", false, "send case-v1 payload.content as the session's UserPromptSubmit before the tool calls (the user's task for intent-aware layers)")
	answerWithin := flag.Int("answer-within-ms", 0, "send the hook's answer wait (X-DefenseClaw-Hook-Answer-Within-Ms) on PreToolUse, bounding the judge as a live Claude Code hook does; 0: unbounded")
	secretFlow := flag.String("secret-flow", "", "secret flow tracking (builds that carry it): off | shadow (records hits in flow_hits, never changes an answer); empty keeps the config default")
	resultPlaceholder := flag.Bool("result-placeholder", false, "session surface: a non-shell call whose source recorded no result is replayed with a fixed neutral placeholder as its tool result, so a rule that needs a completed read to have returned content can be measured on corpora that drop results (an upper bound; the owner sessions keep their real results)")
	chainLanes := flag.String("chain-lanes", "", "guardrail.cascade.lanes of the scope chains: <chain_effects>,<chain_effects_value> as off|shadow|on (empty keeps the shipped defaults)")
	flag.Parse()
	if *surface != "hook" && *surface != "prompt" && *surface != "tool-result" && *surface != "session" {
		fmt.Fprintln(os.Stderr, "-surface must be hook, prompt, tool-result or session")
		os.Exit(2)
	}
	if *corpus == "" || *out == "" || *policyDir == "" {
		fmt.Fprintln(os.Stderr, "need -corpus -out -policy-dir")
		os.Exit(2)
	}
	dataDir, err := os.MkdirTemp(*scratch, "s7bench-")
	if err != nil {
		panic(err)
	}
	var engine *gateway.S7Engine
	var scratchPeak atomic.Int64
	var decisionsTotal, casesTotal atomic.Int64
	startRun := time.Now()
	// The scratch dir is removed on every way out: normal end, panic, SIGINT/SIGTERM/SIGHUP, boot failure, cap exceeded.
	cleaned := atomic.Bool{}
	cleanup := func() {
		if cleaned.Swap(true) {
			return
		}
		if engine != nil {
			engine.Close()
		}
		_ = os.RemoveAll(dataDir)
	}
	defer cleanup()
	defer func() {
		if r := recover(); r != nil {
			cleanup()
			panic(r)
		}
	}()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		sig := <-sigs
		fmt.Fprintf(os.Stderr, "[s7bench] %v: removing scratch dir %s and exiting\n", sig, dataDir)
		cleanup()
		os.Exit(130)
	}()
	dirSize := func() int64 {
		var n int64
		_ = filepath.Walk(dataDir, func(_ string, info os.FileInfo, err error) error {
			if err == nil && info.Mode().IsRegular() {
				n += info.Size()
			}
			return nil
		})
		return n
	}
	go func() {
		for range time.Tick(time.Second) {
			n := dirSize()
			if n > scratchPeak.Load() {
				scratchPeak.Store(n)
			}
			if n > int64(*scratchCapMB)<<20 {
				fmt.Fprintf(os.Stderr, "[s7bench] FATAL: scratch dir %s is %d MiB, over the %d MiB cap (audit.db + WAL growth); removing it and exiting 3\n", dataDir, n>>20, *scratchCapMB)
				cleanup()
				os.Exit(3)
			}
		}
	}()

	cfg := config.DefaultConfig()
	cfg.ConfigVersion = config.ConfigVersionV9
	cfg.DataDir = dataDir
	cfg.PolicyDir = *policyDir
	cfg.Guardrail.Enabled = true
	cfg.Guardrail.Mode = *mode
	cfg.Guardrail.RulePack = *pack
	cfg.Guardrail.Connector = "claudecode"
	cfg.ClaudeCode.Enabled = true
	cfg.ClaudeCode.Mode = *mode
	cfg.Codex.Enabled = true
	cfg.Codex.Mode = *mode
	extra := []string{}
	if *connectorFlag != "claudecode" {
		cfg.ConnectorHooks = map[string]config.AgentHookConfig{}
		names := []string{"codex"}
		for name := range knownConnectors {
			if name != "claudecode" && name != "codex" {
				cfg.ConnectorHooks[name] = config.AgentHookConfig{Enabled: true, Mode: *mode}
			}
			names = append(names, name)
		}
		extra = names
	}
	cfg.Guardrail.DetectionStrategy = *strategy
	cfg.Guardrail.DetectionStrategyToolCall = *strategy
	gateway.S7ApplyFlow(cfg, *secretFlow)
	if *chainLanes != "" {
		parts := strings.FieldsFunc(*chainLanes, func(r rune) bool { return r == 0x2c || r == 0x3a })
		if len(parts) != 2 {
			fmt.Fprintln(os.Stderr, "-chain-lanes needs two values")
			os.Exit(2)
		}
		cfg.Guardrail.Cascade.Lanes = map[string]string{"chain_effects": parts[0], "chain_effects_value": parts[1]}
	}
	if *judgeModel != "" {
		cfg.Guardrail.Judge.Enabled = true
		cfg.Guardrail.Judge.ToolInjection = true
		cfg.Guardrail.Judge.HookConnectors = []string{"claudecode"}
		if *judgeTimeout > 0 {
			cfg.Guardrail.Judge.HookTimeout = *judgeTimeout
			cfg.Guardrail.Judge.Timeout = *judgeTimeout
		}
		cfg.Guardrail.Judge.MaxParallel = *judgeParallel
		cfg.Guardrail.Judge.MaxParallelExplicit = true
		cfg.Guardrail.Judge.LLM = config.LLMConfig{Model: "openai/" + *judgeModel, Provider: "openai", BaseURL: *judgeURL, APIKey: "s7-local-proxy"}
	}
	if *dmURL != "" {
		cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: *dmModel, BaseURL: *dmURL, Timeout: *dmTimeout}
		if *dmHook {
			cfg.DecisionModel.HookConnectors = []string{"claudecode"}
		}
	}
	var err2 error
	engine, err2 = gateway.S7NewEngineMulti(cfg, "claudecode", extra)
	err = err2
	if err != nil {
		fmt.Fprintln(os.Stderr, "boot:", err)
		cleanup()
		os.Exit(1)
	}
	if !*walGuard {
		engine.Close()
	}
	hasJudge, hasDM := engine.HasJudge()
	recording := hasJudge && engine.RecordJudgeCalls()
	var preHeaders []string
	if *answerWithin > 0 {
		preHeaders = []string{"X-DefenseClaw-Hook-Answer-Within-Ms", fmt.Sprint(*answerWithin)}
	}
	fmt.Fprintf(os.Stderr, "[s7bench] pack=%s mode=%s strategy=%s judge=%v dm=%v layers=%q record=%v answer_within_ms=%d\n", *pack, *mode, *strategy, hasJudge, hasDM, *layers, recording, *answerWithin)
	wantDM := strings.Contains(*layers, "dm")
	wantJudge := strings.Contains(*layers, "judge")

	var want map[string]bool
	if *ids != "" {
		want = map[string]bool{}
		b, err := os.ReadFile(*ids)
		if err != nil {
			panic(err)
		}
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				want[l] = true
			}
		}
	}
	f, err := os.Open(*corpus)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		panic(err)
	}
	of, err := os.Create(*out)
	if err != nil {
		panic(err)
	}
	defer of.Close()
	w := bufio.NewWriterSize(of, 1<<20)
	defer w.Flush()
	var wmu sync.Mutex
	emit := func(r record) {
		b, _ := json.Marshal(r)
		wmu.Lock()
		w.Write(b)
		w.WriteByte('\n')
		wmu.Unlock()
	}

	jobs := make(chan corpusCase, *workers*2)
	var wg sync.WaitGroup
	var done, decisions atomic.Int64
	start := time.Now()
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				runCase(engine, c, *connectorFlag, *surface, *promptFromContent, *post, *det, wantDM, wantJudge, preHeaders, emit, &decisions, *resultPlaceholder)
				if n := done.Add(1); n%1000 == 0 {
					fmt.Fprintf(os.Stderr, "[s7bench] %d cases %d decisions %.0fs\n", n, decisions.Load(), time.Since(start).Seconds())
				}
			}
		}()
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<20), 64<<20)
	n := 0
	for sc.Scan() {
		var c corpusCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			fmt.Fprintln(os.Stderr, "bad row:", err)
			continue
		}
		if want != nil && !want[c.ID] {
			continue
		}
		jobs <- c
		n++
		if *limit > 0 && n >= *limit {
			break
		}
	}
	close(jobs)
	wg.Wait()
	fmt.Fprintf(os.Stderr, "[s7bench] done cases=%d decisions=%d in %.1fs\n", done.Load(), decisions.Load(), time.Since(start).Seconds())
	casesTotal.Store(done.Load())
	decisionsTotal.Store(decisions.Load())
	stats := engine.Stats(context.Background())
	wall := time.Since(startRun).Seconds()
	rs := map[string]any{"cases": casesTotal.Load(), "decisions": decisionsTotal.Load(), "wall_s": wall, "decisions_per_s": float64(decisionsTotal.Load()) / wall,
		"scratch_peak_bytes": scratchPeak.Load(), "scratch_cap_mb": *scratchCapMB, "load1_at_end": loadAvg(), "audit": stats, "pack": *pack, "connector_flag": *connectorFlag, "gomaxprocs": runtime.GOMAXPROCS(0)}
	if b, err := json.MarshalIndent(rs, "", " "); err == nil {
		_ = os.WriteFile(*out+".runstats.json", b, 0o644)
	}
}

type hookResp struct {
	Action     string   `json:"action"`
	RawAction  string   `json:"raw_action"`
	Severity   string   `json:"severity"`
	Reason     string   `json:"reason"`
	Findings   []string `json:"findings"`
	WouldBlock bool     `json:"would_block"`
	RuleIDs    []string `json:"rule_ids"`
}

func runCase(e *gateway.S7Engine, c corpusCase, connectorFlag, surface string, promptFromContent, post, det, wantDM, wantJudge bool, preHeaders []string, emit func(record), decisions *atomic.Int64, resultPlaceholder bool) {
	conn := connectorOf(connectorFlag, c.Strata.Provider)
	legacy := connectorFlag == "claudecode"
	h := sha256.Sum256([]byte(c.ID))
	sid := "s7-" + hex.EncodeToString(h[:12])
	ctx := context.Background()
	events := c.Payload.Events
	if len(events) == 0 {
		events = []event{c.Payload.event}
	}
	cwd := "/home/bench/work"
	if surface == "prompt" {
		text := firstNonEmpty(c.Payload.Content, c.Payload.Prompt, c.Payload.Intent, c.Payload.Command)
		v := e.InspectText(ctx, "prompt", text)
		body, _ := json.Marshal(map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": sid, "cwd": cwd, "prompt": text, "transcript_path": ""})
		st, hb := e.HookFor(ctx, conn, body)
		var hr hookResp
		_ = json.Unmarshal(hb, &hr)
		r := record{Case: c.ID, Connector: conn, N: 1, SrcTool: "__prompt__", Tool: "UserPromptSubmit", Mapped: "prompt", Status: st,
			Action: v.Action, RawAction: v.Action, Severity: v.Severity, Findings: v.Findings,
			Extra: map[string]string{"hook_action": hr.Action, "hook_raw_action": hr.RawAction, "hook_sev": hr.Severity, "hook_findings": strings.Join(hr.Findings, ",")}}
		decisions.Add(1)
		emit(r)
		return
	}
	intent := firstNonEmpty(c.Payload.Intent, c.Payload.Prompt)
	if intent == "" && promptFromContent {
		intent = c.Payload.Content
	}
	if intent != "" {
		body, _ := json.Marshal(map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": sid, "cwd": cwd, "prompt": intent, "transcript_path": ""})
		e.HookFor(ctx, conn, body)
	}
	for i, ev := range events {
		var tool string
		var input json.RawMessage
		var mapped string
		if legacy {
			tool, input, mapped = mapTool(ev)
		} else {
			tool, input, mapped = buildCall(conn, ev)
		}
		ecwd := cwd
		if ev.CWD != "" {
			ecwd = ev.CWD
		}
		body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": sid, "cwd": ecwd,
			"tool_name": tool, "tool_input": input, "permission_mode": "default", "transcript_path": "",
			"tool_use_id": fmt.Sprintf("toolu_%s_%d", sid[3:15], i)})
		if conn == "codex" {
			var bm map[string]any
			_ = json.Unmarshal(body, &bm)
			bm["turn_id"] = sid
			bm["model"] = "bench"
			body, _ = json.Marshal(bm)
		}
		if conn == "cursor" && mapped == "shell" {
			// Cursor's shell hook is beforeShellExecution: it names no tool, its payload is the command.
			var in struct {
				Command string `json:"command"`
			}
			_ = json.Unmarshal(input, &in)
			body, _ = json.Marshal(map[string]any{"hook_event_name": "beforeShellExecution", "conversation_id": sid, "generation_id": sid, "cwd": ecwd, "command": in.Command, "workspace_roots": []string{ecwd}})
		}
		t0 := time.Now()
		status, resp := e.HookFor(ctx, conn, body, preHeaders...)
		fallback := ""
		if status >= 400 && conn != "claudecode" && !legacy {
			// The connector's handler refused the payload shape (a binding this harness cannot supply): judge the call through the
			// Claude Code handler instead, and say so in the record, so a refused shape is never scored as an allow.
			cc := ev
			ftool, finput, _ := mapTool(cc)
			fbody, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": sid, "cwd": ecwd, "tool_name": ftool, "tool_input": finput,
				"permission_mode": "default", "transcript_path": "", "tool_use_id": fmt.Sprintf("toolu_%s_%d", sid[3:15], i)})
			fallback = fmt.Sprintf("%s:%d", conn, status)
			status, resp = e.HookFor(ctx, "claudecode", fbody, preHeaders...)
		}
		r := record{Case: c.ID, Connector: conn, Idx: i, N: len(events), SrcTool: ev.ToolName, Tool: tool, Mapped: mapped, Status: status,
			LatencyUs: time.Since(t0).Microseconds()}
		r.JudgeCalls = e.TakeJudgeCalls(sid)
		var hr hookResp
		if err := json.Unmarshal(resp, &hr); err != nil {
			r.Err = "decode: " + err.Error()
		}
		r.Action, r.RawAction, r.Severity, r.WouldBlock, r.RuleIDs, r.Findings = hr.Action, hr.RawAction, hr.Severity, hr.WouldBlock, hr.RuleIDs, hr.Findings
		r.DetOnly = strings.HasPrefix(hr.Reason, "detection-only")
		if len(hr.Reason) > 240 {
			hr.Reason = hr.Reason[:240]
		}
		r.Reason = hr.Reason
		if status != 200 {
			if os.Getenv("S7_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "[s7bench-debug] %s status=%d body=%s resp=%s\n", conn, status, string(body), string(resp))
			}
			r.Err = fmt.Sprintf("http %d", status)
		}
		if fallback != "" {
			r.Extra = map[string]string{"connector_fallback": fallback}
		}
		if det {
			d := e.DeterministicFor(ctx, conn, tool, input, ecwd)
			r.Det = &d
		}
		if wantDM || wantJudge {
			dm, jv := e.Layers(ctx, sid, tool, string(input), wantDM, wantJudge)
			r.DM, r.Judge = &dm, &jv
		}
		// Session surface: a source trace records the calls that ran, so a call whose outcome the source does not state ("unknown", "")
		// is replayed as one that completed; only a call the source says failed gets no PostToolUse.
		if (post && (ev.Outcome == "succeeded" || (surface == "session" && ev.Outcome != "failed"))) || surface == "tool-result" {
			var resp any = map[string]any{"stdout": "", "stderr": "", "interrupted": false}
			if surface == "tool-result" {
				resp = ev.Result
			}
			if surface == "session" && ev.Result == "" && resultPlaceholder && mapped != "shell" {
				ev.Result = "[result not recorded by the source corpus]"
			}
			if surface == "session" && ev.Result != "" {
				// The result the tool returned in the source session: a shell call's stdout, any other tool's text.
				if mapped == "shell" {
					resp = map[string]any{"stdout": ev.Result, "stderr": "", "interrupted": false}
				} else {
					resp = ev.Result
				}
			}
			pb, _ := json.Marshal(map[string]any{"hook_event_name": "PostToolUse", "session_id": sid, "cwd": ecwd,
				"tool_name": tool, "tool_input": input, "tool_response": resp,
				"transcript_path": "", "tool_use_id": fmt.Sprintf("toolu_%s_%d", sid[3:15], i)})
			var pbody []byte
			r.PostStatus, pbody = e.HookFor(ctx, conn, pb)
			if surface == "session" {
				var pr hookResp
				_ = json.Unmarshal(pbody, &pr)
				r.PostAction, r.PostRaw, r.PostSeverity, r.PostRuleIDs = pr.Action, pr.RawAction, pr.Severity, pr.RuleIDs
			}
			if surface == "tool-result" {
				// The decision on this surface is the PostToolUse answer; the PreToolUse answer moves to extra.
				var pr hookResp
				_ = json.Unmarshal(pbody, &pr)
				if r.Extra == nil {
					r.Extra = map[string]string{}
				}
				r.Extra["pre_action"], r.Extra["pre_raw_action"] = r.Action, r.RawAction
				r.Action, r.RawAction, r.Severity, r.Findings, r.RuleIDs = pr.Action, pr.RawAction, pr.Severity, pr.Findings, pr.RuleIDs
				r.Mapped = "tool-result"
			}
		}
		if surface == "session" {
			r.FlowHits = e.FlowHitsSince(sid)
		}
		decisions.Add(1)
		emit(r)
	}
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func loadAvg() string {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return ""
	}
	f := strings.Fields(string(b))
	if len(f) > 0 {
		return f[0]
	}
	return ""
}
