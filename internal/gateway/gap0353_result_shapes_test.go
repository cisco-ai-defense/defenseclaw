// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"testing"
)

// substrate-1 GAP-0353 (SMK-CH4 at 8131b61509, review rk347b P2-1): Claude Code
// 2.1.323 in an actor posts PostToolUse after the PostToolUseFailure of a
// failed Bash, and its result is the transcript's toolUseResult, "Error: Exit
// code 1\ncat: .env.production: No such file or directory". resultShowsRead
// read the "Error: " line as output, so the call's cleared read chained. The
// proof and resultShowsRead now read the output fields only, without the
// harness's metadata and wrappers (resultOutputLines). The rows are rk347b's
// 17 shapes (evidence/substrate-1/rk347b/shapes.log), the bodies captured on
// dev (Claude Code 2.1.322 and 2.1.323, evidence/substrate-1/kind347/
// cc-bodies) and in an actor (actor-capture-try2, transcript of actor
// k347cap-1a064483), and the proof forms review rk347b P3-1 asked for.
func TestGAP0353ResultShapes(t *testing.T) {
	const (
		cmd  = "cat .env.production"
		miss = "cat: .env.production: No such file or directory"
	)
	std := func(extra map[string]interface{}) map[string]interface{} {
		r := map[string]interface{}{"stdout": "", "stderr": "", "interrupted": false, "isImage": false}
		for k, v := range extra {
			r[k] = v
		}
		return r
	}
	type row struct {
		name     string
		command  string
		tool     string
		response interface{}
		extra    map[string]interface{}
		shows    bool // as a further PostToolUse
		proves   bool // as the first, failed result
	}
	rows := []row{
		{"S01 empty stdout/stderr", cmd, "", std(nil), nil, false, false},
		{"S02 error on stderr", cmd, "", std(map[string]interface{}{"stderr": miss}), nil, false, true},
		{"S03 error on stdout (merged streams)", cmd, "", std(map[string]interface{}{"stdout": miss}), nil, false, true},
		{"S04 noOutputExpected false", cmd, "", std(map[string]interface{}{"noOutputExpected": false}), nil, false, false},
		{"S05 returnCodeInterpretation", cmd, "", std(map[string]interface{}{"returnCodeInterpretation": "No such file or directory"}), nil, false, false},
		{"S05b returnCodeInterpretation + stderr error", cmd, "", std(map[string]interface{}{"stderr": miss, "returnCodeInterpretation": "No such file or directory"}), nil, false, true},
		{"S06 'Error: Exit code 1' + error", cmd, "", "Error: Exit code 1\n" + miss, nil, false, true},
		{"S07 'Exit code 1' + error", cmd, "", "Exit code 1\n" + miss, nil, false, true},
		{"S08 <tool_use_error> wrapped", cmd, "", "<tool_use_error>Error: Exit code 1\n" + miss + "</tool_use_error>", nil, false, true},
		{"S09 stderr + 'Shell cwd was reset'", cmd, "", std(map[string]interface{}{"stderr": miss + "\nShell cwd was reset to /work"}), nil, false, true},
		{"S10 top-level error, empty response", cmd, "", std(nil), map[string]interface{}{"error": "Exit code 1\n" + miss}, false, true},
		{"S11 persistedOutputPath", cmd, "", std(map[string]interface{}{"persistedOutputPath": "/tmp/x"}), nil, false, false},
		{"S12 sandboxStatus", cmd, "", std(map[string]interface{}{"sandboxStatus": "enabled"}), nil, false, false},
		{"S13 content blocks", cmd, "", []interface{}{map[string]interface{}{"type": "text", "text": "Exit code 1\n" + miss}}, nil, false, true},
		{"S14 stderr with trailing CRLF", cmd, "", std(map[string]interface{}{"stderr": miss + "\r\n"}), nil, false, true},
		{"S15 /bin/cat prefix", cmd, "", std(map[string]interface{}{"stderr": "/bin/cat: .env.production: No such file or directory"}), nil, false, true},
		{"S16 quoted operand", cmd, "", std(map[string]interface{}{"stderr": "cat: '.env.production': No such file or directory"}), nil, false, true},
		{"S17 printed secret (positive)", cmd, "", std(map[string]interface{}{"stdout": "API_KEY=canary-1"}), nil, true, false},
		{"S18 unknown string field is output (fail closed)", cmd, "", std(map[string]interface{}{"notes": "API_KEY=canary-1"}), nil, true, false},
		{"S19 printed secret beside the error", cmd, "", std(map[string]interface{}{"stdout": "API_KEY=canary-1", "stderr": miss}), nil, true, false},
		// The bodies captured from Claude Code.
		{"C01 dev 2.1.322 and 2.1.323 PostToolUseFailure", cmd, "", nil, map[string]interface{}{"error": "Exit code 1\n" + miss,
			"is_interrupt": false, "duration_ms": float64(41)}, false, true},
		{"C02 in-actor 2.1.323 PostToolUse result (transcript toolUseResult)", cmd, "", "Error: Exit code 1\n" + miss, nil, false, true},
		{"C03 in-actor stream-json tool_result content", cmd, "", []interface{}{map[string]interface{}{"type": "tool_result",
			"content": "Exit code 1\n" + miss, "is_error": true}}, nil, false, true},
		// rk347b P3-1: forms the proof now covers.
		{"P01 cat X 2>/dev/null, failed, printed nothing", "cat .env.production 2>/dev/null", "", "Exit code 1", nil, false, true},
		{"P02 cat X 2>/dev/null, 'Error: Exit code 1'", "cat .env.production 2>/dev/null", "", "Error: Exit code 1", nil, false, true},
		{"P03 cat X 2>/dev/null that printed", "cat .env.production 2>/dev/null", "", "Exit code 1\nAPI_KEY=canary-1", nil, true, false},
		{"P04 cat X 2>/dev/null, no exit status", "cat .env.production 2>/dev/null", "", std(nil), nil, false, false},
		{"P05 cat X 2>/dev/null, exit 0", "cat .env.production 2>/dev/null", "", "Exit code 0", nil, false, false},
		{"P06 F=X; cat $F", "F=.env.production; cat $F", "", "Exit code 1\n" + miss, nil, false, true},
		{"P07 F=X && cat \"$F\"", `F=.env.production && cat "$F"`, "", "Exit code 1\n" + miss, nil, false, true},
		{"P08 F=X; cat $G (another variable)", "F=.env.production; cat $G", "", "Exit code 1\n" + miss, nil, true, false},
		{"P09 Read tool: File does not exist.", "", "Read", nil, map[string]interface{}{"error": "File does not exist."}, false, true},
		{"P10 Read tool: wrapped", "", "Read", nil, map[string]interface{}{"error": "<tool_use_error>File does not exist. Note: your current working directory is /work.</tool_use_error>"}, false, true},
		{"P11 Read tool: content", "", "Read", map[string]interface{}{"type": "text", "file": map[string]interface{}{"content": "API_KEY=canary-1"}}, nil, true, false},
		// Residual (GAP-0337 owner decision): not proven, so a read.
		{"N02 cat X 2>&1", "cat .env.production 2>&1", "", "Exit code 1\n" + miss, nil, false, false},
		{"N06 grep KEY X", "grep API_KEY .env.production", "", "Exit code 2\ngrep: .env.production: No such file or directory", nil, false, false},
	}
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			tool := tc.tool
			args := json.RawMessage(`{"file_path":".env.production"}`)
			if tool == "" {
				tool = "Bash"
				args, _ = json.Marshal(map[string]string{"command": tc.command, "description": "Read .env.production file"})
			}
			payload := func(event string) map[string]interface{} {
				p := map[string]interface{}{"hook_event_name": event, "session_id": "s1", "tool_use_id": "read-1", "tool_name": tool}
				if tc.response != nil {
					p["tool_response"] = tc.response
				}
				for k, v := range tc.extra {
					p[k] = v
				}
				return p
			}
			post := agentHookRequest{ConnectorName: "claudecode", ToolName: tool, ToolArgs: args, Payload: payload("PostToolUse")}
			fail := agentHookRequest{ConnectorName: "claudecode", ToolName: tool, ToolArgs: args, Payload: payload("PostToolUseFailure")}
			if got := resultShowsRead(post); got != tc.shows {
				t.Errorf("resultShowsRead %v, want %v", got, tc.shows)
			}
			if got := toolResultProvesNothingRead(fail); got != tc.proves {
				t.Errorf("toolResultProvesNothingRead %v, want %v", got, tc.proves)
			}
		})
	}
}
