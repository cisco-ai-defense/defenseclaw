// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
)

// rel-1-0-10 GAP-0099: the value lane indexes a tool result whenever the flow
// label set labels the read target (one classifier, the same as the file
// labeler), not only for env, json, ssh and token files. Each case reads a
// credential file that the narrower indexing classifier missed; the secret is
// the synthetic string of flow_results_test.go.
func TestFnvFlowResultIndexingFollowsTheFileLabeler(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths; the Windows dialects are covered by TestSecretFlowResultAdapterWindowsDialects")
	}
	withSecretFlowGeneration(t, "on", "on")
	// A home-relative credential file is a label only under the host's own home.
	homeCmd := func(rel string) string {
		b, _ := json.Marshal("cat " + filepath.Join(trustedSameHostHome(), rel))
		return `{"command":` + string(b) + `}`
	}
	for _, tc := range []r2ResultCase{
		{name: "aws_credentials", connector: "claudecode", event: "PostToolUse", tool: "Bash", args: homeCmd(".aws/credentials"),
			payload: map[string]any{"tool_response": "[default]\naws_access_key_id = AKIAEXAMPLE0000000\naws_secret_access_key = " + r2GatewaySecret + "\n"}},
		{name: "npmrc", connector: "claudecode", event: "PostToolUse", tool: "Bash", args: homeCmd(".npmrc"),
			payload: map[string]any{"tool_response": "//registry.example.test/:_authToken=" + r2GatewaySecret + "\n"}},
		{name: "netrc", connector: "claudecode", event: "PostToolUse", tool: "Bash", args: homeCmd(".netrc"),
			payload: map[string]any{"tool_response": "machine example.test login u password " + r2GatewaySecret + "\n"}},
		{name: "grep_env", connector: "claudecode", event: "PostToolUse", tool: "Bash", args: `{"command":"grep API_KEY .env"}`,
			payload: map[string]any{"tool_response": "API_KEY=" + r2GatewaySecret + "\n"}},
		{name: "cat_n_env", connector: "claudecode", event: "PostToolUse", tool: "Bash", args: `{"command":"cat -n .env"}`,
			payload: map[string]any{"tool_response": "     1\tAPI_KEY=" + r2GatewaySecret + "\n"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sid := "fnv-flow-" + tc.name
			if n := r2Index(t, tc, sid); n == 0 {
				t.Fatalf("nothing indexed from the %s result", tc.name)
			}
			if !r2SendHit(sid) {
				t.Fatalf("a call that sends the %s value is not a flow.secret_egress finding", tc.name)
			}
		})
	}
}
