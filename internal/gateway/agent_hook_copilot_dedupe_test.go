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
		return agentHookRequest{HookEventName: "PreToolUse", SessionID: "s1", ToolName: "bash", ToolArgs: args, Payload: payload}
	}
	camel := func(command string) agentHookRequest {
		text := `{"command":"` + command + `"}`
		args, _ := json.Marshal(text)
		return agentHookRequest{HookEventName: "preToolUse", SessionID: "s1", ToolName: "bash", ToolArgs: args,
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
