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

package manager

import (
	"encoding/json"
	"strings"
	"testing"
)

// contentRef is the ledger reference of a call named by its content.
func contentRef(session, tool string, input json.RawMessage) toolCallRef {
	return callRef(ContentRef(session, tool, input))
}

// TestRelayedDecisionsPairByCallRef pins that a relayed verdict, which
// carries the managed gateway's content reference instead of the tool
// input, names the same call as the local verdict for a content-keyed
// connector, and that only a well-formed reference names a call.
func TestRelayedDecisionsPairByCallRef(t *testing.T) {
	input := json.RawMessage(`{"command":"echo dccert-block-marker"}`)
	ref := ContentRef("sess-1", "shell", input)
	if !strings.HasPrefix(ref, "call:") || len(ref) != len("call:")+64 {
		t.Fatalf("ContentRef = %q", ref)
	}
	if ContentRef("sess-1", "", input) != "" || ContentRef("sess-1", "shell", nil) != "" {
		t.Fatal("a call without a tool or input has a content reference")
	}
	hooks := toolCallHooksFor("kiro")
	local := hooks.ref(HookDecision{Connector: "kiro", SessionID: "sess-1", Tool: "shell", ToolInput: input})
	relayed := hooks.ref(HookDecision{Connector: "kiro", SessionID: "sess-1", Tool: "shell", CallRef: ref})
	if local.key == "" || local != relayed || !relayed.byContent {
		t.Fatalf("relayed ref %+v, local %+v", relayed, local)
	}
	for _, bad := range []string{"", "call:", "toolu_1", "call:" + strings.Repeat("G", 64), "call:" + strings.Repeat("a", 63), ref + "0"} {
		if got := hooks.ref(HookDecision{Connector: "kiro", Tool: "shell", CallRef: bad}); got.key != "" {
			t.Fatalf("CallRef %q named call %+v", bad, got)
		}
	}
	// The tool input wins over a reference when a decision has both, and an
	// ID-keyed connector ignores the reference.
	other := ContentRef("sess-1", "shell", json.RawMessage(`{"command":"ls"}`))
	if got := hooks.ref(HookDecision{SessionID: "sess-1", Tool: "shell", ToolInput: input, CallRef: other}); got != local {
		t.Fatalf("decision with input and ref = %+v", got)
	}
	if got := toolCallHooksFor("claudecode").ref(HookDecision{Tool: "Bash", CallRef: ref}); got.key != "" {
		t.Fatalf("ID-keyed connector paired by content: %+v", got)
	}
}
