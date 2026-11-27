// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package gateway

// DET111 probe: rows, case-v1 loader and the seed model the generators use.
// The probe itself (det111_probe_test.go) is skipped unless DET111_OUT is set.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// det111Row is one tool call the probe sends through every tier and route.
type det111Row struct {
	Key      string // unique, no '|' and no whitespace
	Role     string // corpus | seed | variant | twin-seed | twin-variant | benign-seed | benign-variant
	Gen      string // corpus | r1 | r2w | r2o | r3
	Variant  string // spelling name inside the generator
	Seed     string // key of the plain-spelling row this row derives from ("" for a seed)
	Pair     string // attack row: its benign twin key; twin: its attack row key
	Gap      string // GAP-NNNN when the row comes from a gap
	Tool     string // Bash | PowerShell | Write | Edit | Read | apply_patch
	Dialect  string // posix | powershell | cmd | none
	Windows  bool   // the Windows hook-host flavor
	Home     string // value of HOME (and USERPROFILE) while the row runs
	CWD      string
	Args     map[string]any // the tool_input as the agent sends it
	Native   bool           // also send the native connector shapes
	Group    string         // seed group: rows of one group are never split across shards
	Surface  string         // text | tool_result | stateful | "" (a plain tool call)
	Content  string         // text rows: the prompt
	Result   map[string]any // tool_result rows: payload.tool_result
	Events   []any          // stateful rows: payload.events
	RawTool  string         // the tool name as the case carries it (as-is route)
	Conn     string         // the connector (strata.provider) for the as-is route
	CWDShift bool           // the variant runs in another folder than its seed
	Truth    string         // corpus rows: expected_disposition of the case (allow | detect_only | block)
}

func (r det111Row) command() string {
	s, _ := r.Args["command"].(string)
	return s
}

// det111Key makes a row key safe for the output format.
var det111KeyBad = regexp.MustCompile(`[^A-Za-z0-9._/:+=@-]+`)

func det111Key(parts ...string) string {
	return det111KeyBad.ReplaceAllString(strings.Join(parts, "/"), "_")
}

func det111Shard(group string, shards int) int {
	if shards <= 1 {
		return 0
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(group))
	return int(h.Sum32() % uint32(shards))
}

// det111Case is the part of a case-v1 row the probe reads.
type det111Case struct {
	ID       string
	Gap      string
	Tool     string
	RawTool  string
	Dialect  string
	Windows  bool
	Platform string
	Provider string
	CWD      string
	Home     string
	Args     map[string]any
	Surface  string
	Content  string
	Result   map[string]any
	Events   []any
	Truth    string // expected_disposition: allow | detect_only | block
	Source   string
}

var det111GapRe = regexp.MustCompile(`GAP-\d+`)

func det111Str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func det111Obj(m map[string]any, key string) map[string]any {
	o, _ := m[key].(map[string]any)
	if o == nil {
		o = map[string]any{}
	}
	return o
}

// det111NormTool maps the tool names the corpora carry to the Claude Code names.
func det111NormTool(tool string) string {
	switch strings.ToLower(tool) {
	case "bash", "shell", "terminal", "exec", "shell_command", "run_command", "execute_bash":
		return "Bash"
	case "powershell", "execute_pwsh":
		return "PowerShell"
	case "write", "write_file", "create", "create_file", "write_to_file", "fs_write":
		return "Write"
	case "edit", "str_replace", "replace":
		return "Edit"
	case "read", "read_file", "view":
		return "Read"
	case "apply_patch":
		return "apply_patch"
	}
	return ""
}

var det111HomeRe = regexp.MustCompile(`^(/home/[^/]+|/Users/[^/]+|[A-Za-z]:\\Users\\[^\\]+)`)

func det111HomeOf(cwd, active, platform string) string {
	if active != "" {
		return active
	}
	if m := det111HomeRe.FindString(cwd); m != "" {
		return m
	}
	switch platform {
	case "windows":
		return `C:\Users\alice`
	case "macos":
		return "/Users/alice"
	}
	return "/home/alice"
}

// det111LoadCases reads case-v1 jsonl files. A row that is not a tool call the
// probe can send (no tool, no command) is returned in skipped, never dropped
// silently.
func det111LoadCases(paths []string) (cases []det111Case, skipped []string, err error) {
	seen := map[string]bool{}
	for _, path := range paths {
		f, e := os.Open(path)
		if e != nil {
			return nil, nil, e
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		line := 0
		for sc.Scan() {
			line++
			var raw map[string]any
			if e := json.Unmarshal(sc.Bytes(), &raw); e != nil {
				f.Close()
				return nil, nil, fmt.Errorf("%s:%d: %v", path, line, e)
			}
			payload, strata, truth, source := det111Obj(raw, "payload"), det111Obj(raw, "strata"), det111Obj(raw, "truth"), det111Obj(raw, "source")
			id := det111Str(raw, "id")
			rawTool := det111Str(payload, "tool_name")
			tool := det111NormTool(rawTool)
			args := det111Obj(payload, "args")
			if len(args) == 0 {
				args = map[string]any{}
				if c := det111Str(payload, "command"); c != "" {
					args["command"] = c
				}
			}
			surface := det111Str(raw, "surface")
			content := det111Str(payload, "content")
			result, _ := payload["tool_result"].(map[string]any)
			events, _ := payload["events"].([]any)
			special := (surface == "text" && content != "") || (surface == "tool_result" && result != nil) || (surface == "stateful" && len(events) > 1)
			if id == "" || (!special && (rawTool == "" || len(args) == 0)) {
				skipped = append(skipped, fmt.Sprintf("%s:%d\t%s\tno id, tool or args", filepath.Base(path), line, id))
				continue
			}
			if seen[id] {
				skipped = append(skipped, fmt.Sprintf("%s:%d\t%s\tduplicate id", filepath.Base(path), line, id))
				continue
			}
			seen[id] = true
			platform := det111Str(strata, "platform")
			c := det111Case{ID: id, Tool: tool, RawTool: rawTool, Dialect: det111Str(payload, "dialect"), Platform: platform,
				Windows: platform == "windows", Provider: det111Str(strata, "provider"), CWD: det111Str(payload, "cwd"),
				Args: args, Surface: surface, Content: content, Result: result, Events: events, Truth: det111Str(truth, "expected_disposition"), Source: det111Str(source, "original_id")}
			c.Home = det111HomeOf(c.CWD, det111Str(payload, "active_home"), platform)
			if g := det111GapRe.FindString(strings.Join([]string{c.Source, id, det111Str(source, "gap")}, " ")); g != "" {
				c.Gap = g
			}
			if cats, ok := truth["categories"].([]any); ok {
				for _, x := range cats {
					if s, _ := x.(string); strings.HasPrefix(s, "gap:") && c.Gap == "" {
						c.Gap = strings.ToUpper(strings.TrimPrefix(s, "gap:"))
					}
				}
			}
			cases = append(cases, c)
		}
		if e := sc.Err(); e != nil {
			f.Close()
			return nil, nil, e
		}
		f.Close()
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].ID < cases[j].ID })
	return cases, skipped, nil
}

func (c det111Case) row() det111Row {
	dialect := c.Dialect
	if dialect == "" || dialect == "none" || dialect == "argv" || dialect == "mixed" || dialect == "python" {
		dialect = "posix"
		if c.Tool == "PowerShell" {
			dialect = "powershell"
		}
	}
	tool := c.Tool
	if tool == "Bash" && c.Windows && dialect == "powershell" {
		tool = "Bash" // the hook names Bash; the dialect hint rides in the command
	}
	return det111Row{Key: det111Key("corpus", c.ID), Role: "corpus", Gen: "corpus", Gap: c.Gap, Tool: tool, Dialect: dialect,
		Windows: c.Windows, Home: c.Home, CWD: c.CWD, Args: c.Args, Native: true, Group: c.ID, Truth: c.Truth, RawTool: c.RawTool, Conn: c.Provider, Surface: c.Surface, Content: c.Content, Result: c.Result, Events: c.Events}
}
