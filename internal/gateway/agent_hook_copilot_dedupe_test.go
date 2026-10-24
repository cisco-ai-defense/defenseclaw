// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"
)

// TestCopilotHookDedupe: a second delivery of one call (same tool_use_id,
// or the other CLI dialect with the same arguments) waits for and reuses
// the first verdict; a same-dialect repeat or different arguments do not.
func TestCopilotHookDedupe(t *testing.T) {
	ctx := context.Background()
	snake := func(id, command string) agentHookRequest {
		input := map[string]interface{}{"command": command}
		args, _ := json.Marshal(input)
		payload := map[string]interface{}{"tool_name": "bash", "tool_input": input}
		if id != "" {
			payload["tool_use_id"] = id
		}
		return agentHookRequest{HookEventName: "PreToolUse", SessionID: "s1", CWD: "/project", ToolName: "bash", ToolArgs: args, Payload: payload}
	}
	camel := func(command string) agentHookRequest {
		text := `{"command":"` + command + `"}`
		args, _ := json.Marshal(text)
		return agentHookRequest{HookEventName: "preToolUse", SessionID: "s1", CWD: "/project", ToolName: "bash", ToolArgs: args,
			Payload: map[string]interface{}{"toolName": "bash", "toolArgs": text}}
	}
	verdict := agentHookResponse{Action: "block", Severity: "HIGH", EvaluationID: "e1"}

	var d copilotHookDedupe
	if _, hit, _ := d.begin(ctx, "claudecode", snake("t1", "ls")); hit {
		t.Fatal("non-Copilot request deduplicated")
	}
	_, hit, first := d.begin(ctx, "copilot", snake("t1", "ls"))
	if hit {
		t.Fatal("first delivery hit")
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		first.complete(verdict)
	}()
	if got, hit, _ := d.begin(ctx, "copilot", snake("t1", "ls")); !hit || got.EvaluationID != "e1" {
		t.Fatalf("same tool_use_id did not wait for the verdict: hit=%v got=%+v", hit, got)
	}
	if _, hit, _ := d.begin(ctx, "copilot", snake("t1", "rm -rf /")); hit {
		t.Fatal("same tool_use_id with other arguments reused the verdict")
	}

	var cli copilotHookDedupe
	_, _, policy := cli.begin(ctx, "copilot", camel("ls"))
	policy.complete(verdict)
	if _, hit, _ := cli.begin(ctx, "copilot", camel("ls")); hit {
		t.Fatal("same-dialect repeat reused the verdict")
	}
	if got, hit, _ := cli.begin(ctx, "copilot", snake("", "ls")); !hit || got.Action != "block" {
		t.Fatalf("CLI hook-file delivery did not reuse the policy verdict: hit=%v", hit)
	}

	var released copilotHookDedupe
	_, _, abandoned := released.begin(ctx, "copilot", snake("t2", "ls"))
	abandoned.release()
	if _, hit, _ := released.begin(ctx, "copilot", snake("t2", "ls")); hit {
		t.Fatal("a delivery that ended without a verdict answered the next one")
	}
}

// A repeated relative write changes target when its working directory
// changes. A later live block for the same tool request also revokes an
// earlier cached allow, including one still finishing evaluation.
func TestCopilotHookDedupeTargetAndBlockInvalidation(t *testing.T) {
	ctx := context.Background()
	request := func(id, cwd, target string) agentHookRequest {
		input := map[string]any{"path": target, "file_text": "updated"}
		args, _ := json.Marshal(input)
		return agentHookRequest{HookEventName: "preToolUse", SessionID: "s1", CWD: cwd,
			ToolName: "create", ToolArgs: args, Payload: map[string]any{"toolName": "create", "toolArgs": input, "tool_use_id": id}}
	}
	allow := agentHookResponse{Action: "allow", EvaluationID: "allowed"}
	block := agentHookResponse{Action: "block", EvaluationID: "blocked"}
	var d copilotHookDedupe
	_, _, first := d.begin(ctx, "copilot", request("one", "/safe", "notes.txt"))
	first.complete(allow)
	if got, hit, _ := d.begin(ctx, "copilot", request("one", "/protected", "notes.txt")); hit && got.Action == "allow" {
		t.Fatal("cached allow crossed to a different resolved target")
	}
	if got, hit, _ := d.begin(ctx, "copilot", request("one", "/safe", "notes.txt")); !hit || got.Action != "allow" {
		t.Fatalf("same target was not cached before a block: hit=%v action=%s", hit, got.Action)
	}
	from := context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{"/safe/notes.txt": "/safe/notes.txt"})
	to := context.WithValue(ctx, resolvedWritesContextKey{}, map[string]string{"/safe/notes.txt": "/protected/notes.txt"})
	_, _, evidenced := d.begin(from, "copilot", request("evidence", "/safe", "notes.txt"))
	evidenced.complete(allow)
	if got, hit, _ := d.begin(to, "copilot", request("evidence", "/safe", "notes.txt")); hit && got.Action == "allow" {
		t.Fatal("cached allow crossed to a different resolved write target")
	}
	_, _, changed := d.begin(ctx, "copilot", request("one", "/safe", "protected.txt"))
	changed.complete(block)
	if got, hit, _ := d.begin(ctx, "copilot", request("one", "/safe", "notes.txt")); hit && got.Action == "allow" {
		t.Fatal("a live block left the earlier allow cached for its request ID")
	}

	var pending copilotHookDedupe
	_, _, old := pending.begin(ctx, "copilot", request("two", "/safe", "notes.txt"))
	_, _, denied := pending.begin(ctx, "copilot", request("two", "/safe", "protected.txt"))
	denied.complete(block)
	old.complete(allow)
	if got, hit, _ := pending.begin(ctx, "copilot", request("two", "/safe", "notes.txt")); hit && got.Action == "allow" {
		t.Fatal("an in-flight allow replaced the later block")
	}

	var full copilotHookDedupe
	_, _, cached := full.begin(ctx, "copilot", request("three", "/safe", "notes.txt"))
	cached.complete(allow)
	for index := len(full.entries); index < copilotDedupeMaxEntries; index++ {
		full.entries["other-"+strconv.Itoa(index)] = &copilotDedupeEntry{expires: time.Now().Add(time.Minute)}
	}
	_, hit, uncached := full.begin(ctx, "copilot", request("three", "/safe", "protected.txt"))
	if hit || len(uncached.entries) != 0 {
		t.Fatal("full cache unexpectedly claimed the changed call")
	}
	uncached.complete(block)
	if got, hit, _ := full.begin(ctx, "copilot", request("three", "/safe", "notes.txt")); hit && got.Action == "allow" {
		t.Fatal("a live block at cache capacity left the old allow reusable")
	}
}
