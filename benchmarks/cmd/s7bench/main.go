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
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
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
}

type payload struct {
	event
	Events []event `json:"events"`
	Intent string  `json:"user_intent"`
	Prompt string  `json:"user_prompt"`
}

type corpusCase struct {
	ID      string  `json:"id"`
	Payload payload `json:"payload"`
}

type record struct {
	Case       string            `json:"case"`
	Idx        int               `json:"idx"`
	N          int               `json:"n"`
	SrcTool    string            `json:"src_tool"`
	Tool       string            `json:"tool"`
	Mapped     string            `json:"mapped"`
	Status     int               `json:"status"`
	Action     string            `json:"action"`
	RawAction  string            `json:"raw_action"`
	Severity   string            `json:"sev"`
	WouldBlock bool              `json:"would_block"`
	RuleIDs    []string          `json:"rule_ids,omitempty"`
	Findings   []string          `json:"findings,omitempty"`
	DetOnly    bool              `json:"detection_only,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Det        *gateway.S7Det    `json:"det,omitempty"`
	DM         *gateway.S7DM     `json:"dm,omitempty"`
	Judge      *gateway.S7Judge  `json:"judge,omitempty"`
	PostStatus int               `json:"post_status,omitempty"`
	LatencyUs  int64             `json:"lat_us"`
	Err        string            `json:"err,omitempty"`
	Extra      map[string]string `json:"extra,omitempty"`
}

var shellTools = map[string]bool{"bash_command": true, "bash": true, "execute_command": true, "shell": true,
	"run_command": true, "terminal": true, "exec": true, "run_shell_command": true, "execute_bash": true,
	"run_terminal_cmd": true, "command": true, "sh": true, "zsh": true, "shell_exec": true, "local_shell": true}
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
	dmHook := flag.Bool("dm-hook", false, "decision model answers alone for the connector (cascade 2)")
	layers := flag.String("layers", "", "probe layers per call: dm,judge")
	post := flag.Bool("post", true, "send PostToolUse for events whose outcome is succeeded")
	det := flag.Bool("det", true, "record the trusted-action deterministic evaluation")
	flag.Parse()
	if *corpus == "" || *out == "" || *policyDir == "" {
		fmt.Fprintln(os.Stderr, "need -corpus -out -policy-dir")
		os.Exit(2)
	}
	dataDir, err := os.MkdirTemp("", "s7bench-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dataDir)

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
	cfg.Guardrail.DetectionStrategy = *strategy
	cfg.Guardrail.DetectionStrategyToolCall = *strategy
	if *judgeModel != "" {
		cfg.Guardrail.Judge.Enabled = true
		cfg.Guardrail.Judge.ToolInjection = true
		cfg.Guardrail.Judge.HookConnectors = []string{"claudecode"}
		if *judgeTimeout > 0 {
			cfg.Guardrail.Judge.HookTimeout = *judgeTimeout
			cfg.Guardrail.Judge.Timeout = *judgeTimeout
		}
		cfg.Guardrail.Judge.LLM = config.LLMConfig{Model: "openai/" + *judgeModel, Provider: "openai", BaseURL: *judgeURL, APIKey: "s7-local-proxy"}
	}
	if *dmURL != "" {
		cfg.DecisionModel = config.DecisionModelConfig{Enabled: true, Model: *dmModel, BaseURL: *dmURL, Timeout: *dmTimeout}
		if *dmHook {
			cfg.DecisionModel.HookConnectors = []string{"claudecode"}
		}
	}
	engine, err := gateway.S7NewEngine(cfg, "claudecode")
	if err != nil {
		fmt.Fprintln(os.Stderr, "boot:", err)
		os.Exit(1)
	}
	hasJudge, hasDM := engine.HasJudge()
	fmt.Fprintf(os.Stderr, "[s7bench] pack=%s mode=%s strategy=%s judge=%v dm=%v layers=%q\n", *pack, *mode, *strategy, hasJudge, hasDM, *layers)
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
				runCase(engine, c, *post, *det, wantDM, wantJudge, emit, &decisions)
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

func runCase(e *gateway.S7Engine, c corpusCase, post, det, wantDM, wantJudge bool, emit func(record), decisions *atomic.Int64) {
	h := sha256.Sum256([]byte(c.ID))
	sid := "s7-" + hex.EncodeToString(h[:12])
	ctx := context.Background()
	events := c.Payload.Events
	if len(events) == 0 {
		events = []event{c.Payload.event}
	}
	cwd := "/home/bench/work"
	if intent := firstNonEmpty(c.Payload.Intent, c.Payload.Prompt); intent != "" {
		body, _ := json.Marshal(map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": sid, "cwd": cwd, "prompt": intent, "transcript_path": ""})
		e.Hook(ctx, body)
	}
	for i, ev := range events {
		tool, input, mapped := mapTool(ev)
		ecwd := cwd
		if ev.CWD != "" {
			ecwd = ev.CWD
		}
		body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": sid, "cwd": ecwd,
			"tool_name": tool, "tool_input": input, "permission_mode": "default", "transcript_path": "",
			"tool_use_id": fmt.Sprintf("toolu_%s_%d", sid[3:15], i)})
		t0 := time.Now()
		status, resp := e.Hook(ctx, body)
		r := record{Case: c.ID, Idx: i, N: len(events), SrcTool: ev.ToolName, Tool: tool, Mapped: mapped, Status: status,
			LatencyUs: time.Since(t0).Microseconds()}
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
			r.Err = fmt.Sprintf("http %d", status)
		}
		if det {
			d := e.Deterministic(ctx, tool, input, ecwd)
			r.Det = &d
		}
		if wantDM || wantJudge {
			dm, jv := e.Layers(ctx, sid, tool, string(input), wantDM, wantJudge)
			r.DM, r.Judge = &dm, &jv
		}
		if post && ev.Outcome == "succeeded" {
			pb, _ := json.Marshal(map[string]any{"hook_event_name": "PostToolUse", "session_id": sid, "cwd": ecwd,
				"tool_name": tool, "tool_input": input, "tool_response": map[string]any{"stdout": "", "stderr": "", "interrupted": false},
				"transcript_path": "", "tool_use_id": fmt.Sprintf("toolu_%s_%d", sid[3:15], i)})
			r.PostStatus, _ = e.Hook(ctx, pb)
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
