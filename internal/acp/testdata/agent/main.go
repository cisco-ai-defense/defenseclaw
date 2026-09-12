// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Command agent is a deterministic ACP peer used by subprocess and platform
// E2E tests. It is deliberately kept under testdata so it cannot enter release
// packages.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

func send(value any) {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(body))
}

func result(id json.RawMessage, value any) {
	send(map[string]any{"jsonrpc": "2.0", "id": id, "result": value})
}

func request(id int, method string, params any) {
	send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	var promptID json.RawMessage
	for scanner.Scan() {
		var msg message
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			os.Exit(2)
		}
		switch msg.Method {
		case "initialize":
			result(msg.ID, map[string]any{
				"protocolVersion":   1,
				"agentCapabilities": map[string]any{},
				"agentInfo":         map[string]any{"name": "DefenseClaw ACP E2E fixture", "version": "1"},
			})
		case "session/new":
			result(msg.ID, map[string]any{"sessionId": "fixture-session"})
		case "session/prompt":
			promptID = append(promptID[:0], msg.ID...)
			send(map[string]any{
				"jsonrpc": "2.0", "method": "session/update",
				"params": map[string]any{
					"sessionId": "fixture-session",
					"update":    map[string]any{"sessionUpdate": "agent_message_chunk", "content": map[string]any{"type": "text", "text": "fixture-safe-output"}},
				},
			})
			request(900, "fs/write_text_file", map[string]any{"sessionId": "fixture-session", "path": "/tmp/defenseclaw-acp-e2e.txt", "content": "fixture-safe-write"})
		case "":
			switch string(msg.ID) {
			case "900":
				if len(msg.Error) != 0 {
					return
				}
				request(901, "terminal/create", map[string]any{"sessionId": "fixture-session", "command": "true", "args": []string{}})
			case "901":
				request(902, "session/request_permission", map[string]any{"sessionId": "fixture-session", "options": []any{}})
			case "902":
				result(promptID, map[string]any{"stopReason": "end_turn"})
				return
			}
		default:
			if len(msg.ID) != 0 {
				result(msg.ID, map[string]any{})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		os.Exit(3)
	}
}
