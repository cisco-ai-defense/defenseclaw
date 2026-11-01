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
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// hookBench turns on TestAgentHookBenignPreToolUseCost.
var hookBench = flag.Bool("hookbench", false, "measure the per-hook gateway cost (TestAgentHookBenignPreToolUseCost)")

// TestAgentHookBenignPreToolUseCost measures one benign Claude Code
// PreToolUse through the gateway handler with a real audit store (the
// per-hook gateway cost of the r106 performance audit). It runs only with
// the -hookbench test flag: go test ./internal/gateway -run
// TestAgentHookBenignPreToolUseCost -count=1 -v -args -hookbench
// (add -cpuprofile or -memprofile before -args for a profile).
func TestAgentHookBenignPreToolUseCost(t *testing.T) {
	if !*hookBench {
		t.Skip("pass -args -hookbench to measure the per-hook gateway cost")
	}
	fixture := newAuditFailureHookFixture(t, "closed")
	cwd := t.TempDir()
	payloads := map[string]func(int) []byte{
		"bash-echo": func(i int) []byte {
			return mustBenchJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-bench", "cwd": cwd,
				"tool_name": "Bash", "tool_use_id": fmt.Sprintf("toolu_bench_%d", i), "tool_input": map[string]any{"command": "echo ok"}})
		},
		"read-file": func(i int) []byte {
			return mustBenchJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": "s-bench", "cwd": cwd,
				"tool_name": "Read", "tool_use_id": fmt.Sprintf("toolu_read_%d", i), "tool_input": map[string]any{"file_path": cwd + "/README.md"}})
		},
	}
	for _, name := range []string{"bash-echo", "read-file"} {
		build := payloads[name]
		i := 0
		result := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				i++
				recorder := httptest.NewRecorder()
				fixture.api.handleAgentHook("claudecode").ServeHTTP(recorder,
					httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(build(i))))
				if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"allow"`)) {
					b.Fatalf("status %d: %.300s", recorder.Code, recorder.Body.String())
				}
			}
		})
		info, _ := os.Stat(fixture.path)
		size := int64(0)
		if info != nil {
			size = info.Size()
		}
		wal, _ := os.Stat(fixture.path + "-wal")
		if wal != nil {
			size += wal.Size()
		}
		t.Logf("%s: n=%d %s %s; audit db+wal now %d bytes after %d hooks", name, result.N, result.T/time.Duration(max(result.N, 1)), result.MemString(), size, i)
	}
}

func mustBenchJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
