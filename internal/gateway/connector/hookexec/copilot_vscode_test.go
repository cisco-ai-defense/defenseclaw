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

package hookexec

import (
	"errors"
	"strings"
	"testing"
)

// A Copilot command marked --hook-surface vscode-local binds the VS Code
// Local harness's PascalCase event, forwards the dialect, and fails closed
// with the harness's structured deny; an unmarked command keeps the Copilot
// CLI contract, in which a PascalCase binding is a fail-open local error.
func TestCopilotVSCodeLocalDialect(t *testing.T) {
	vscode := func(event, failMode string) func(*Options) {
		return func(o *Options) {
			o.HookSurface = "vscode-local"
			o.Event = event
			o.FailMode = failMode
			o.Stdin = strings.NewReader(`{"hook_event_name":"` + event + `"}`)
		}
	}

	rt := ok(`{"action":"allow"}`)
	res := run(t, "copilot", rt, vscode("PreToolUse", "open"))
	if res.code != 0 || res.stdout != "" || rt.gotReq == nil ||
		rt.gotReq.Header.Get(HookDialectHeader) != "vscode-local" ||
		rt.gotReq.Header.Get("X-DefenseClaw-Copilot-Event") != "PreToolUse" {
		t.Fatalf("allow: code=%d stdout=%q req=%v", res.code, res.stdout, rt.gotReq)
	}

	down := &stubRT{err: errors.New("connection refused")}
	res = run(t, "copilot", down, vscode("PreToolUse", "closed"))
	if res.code != 0 || !strings.Contains(res.stdout, `"permissionDecision":"deny"`) {
		t.Fatalf("closed PreToolUse: code=%d stdout=%q", res.code, res.stdout)
	}
	res = run(t, "copilot", down, vscode("Stop", "closed"))
	if res.code != 0 || res.stdout != "" {
		t.Fatalf("closed Stop must not keep the agent running: code=%d stdout=%q", res.code, res.stdout)
	}

	unmarked := ok(`{"action":"allow"}`)
	res = run(t, "copilot", unmarked, func(o *Options) { o.Event = "PreToolUse"; o.FailMode = "closed" })
	if res.code != 0 || unmarked.requests != 0 {
		t.Fatalf("unmarked PascalCase binding: code=%d requests=%d", res.code, unmarked.requests)
	}
}
