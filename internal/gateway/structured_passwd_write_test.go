// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const posixNonRootUIDZeroAccountWriteRuleID = "privilege.posix_non_root_uid_zero_account_write"

func TestStructuredPasswdUIDZeroWriteBlocksAllProfiles(t *testing.T) {
	directInput := actionfacts.Input{
		Tool: "write_file",
		Args: structuredPasswdArgs(t, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0:Backdoor:/root:/bin/bash\n"),
	}
	directFacts := actionfacts.Analyze(directInput)
	directProof, directOwned := trustedSemanticOwnerFindingProof(
		posixNonRootUIDZeroAccountWriteRuleID, directInput, directFacts,
	)
	if !directOwned || !directProof.authorizes(posixNonRootUIDZeroAccountWriteRuleID) {
		t.Fatalf("direct proof not authorized: owned=%t proof=%+v facts=%+v", directOwned, directProof, directFacts)
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			const connector = "codex"
			installToolCallCorpusProfileConnector(t, connector, profile)
			directFindings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: directInput, Connector: connector, EnforcementCapable: true,
			})
			if findingWithID(directFindings, posixNonRootUIDZeroAccountWriteRuleID) == nil {
				t.Fatalf("direct dispatch missed rule: facts=%+v findings=%+v", directFacts, directFindings)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = connector
			cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
			response := (&APIServer{scannerCfg: cfg}).evaluateCodexHook(
				t.Context(),
				codexHookRequest{
					HookEventName: "PreToolUse",
					ToolName:      "write_file",
					CWD:           "/workspace",
					ToolInput: map[string]interface{}{
						"path":    "/etc/passwd",
						"content": "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0:Backdoor:/root:/bin/bash\n",
					},
				},
			)
			if response.Action != "block" || response.RawAction != "block" ||
				response.Severity != "CRITICAL" ||
				!findingStringHasRuleID(response.Findings, posixNonRootUIDZeroAccountWriteRuleID) {
				t.Fatalf("response=%+v", response)
			}
		})
	}
}

func TestStructuredPasswdUIDZeroWriteNearMissesStayQuiet(t *testing.T) {
	const connector = "codex"
	installToolCallCorpusProfileConnector(t, connector, "strict")
	tests := []struct {
		name    string
		tool    string
		path    string
		content string
	}{
		{name: "root only", tool: "write_file", path: "/etc/passwd", content: "root:x:0:0:root:/root:/bin/bash\n"},
		{name: "ordinary uid", tool: "write_file", path: "/etc/passwd", content: "service:x:1000:1000:Service:/home/service:/bin/sh\n"},
		{name: "fixture path", tool: "write_file", path: "/workspace/fixtures/etc/passwd", content: "backdoor:x:0:0:Backdoor:/root:/bin/bash\n"},
		{name: "commented example", tool: "write_file", path: "/etc/passwd", content: "# backdoor:x:0:0:Backdoor:/root:/bin/bash\n"},
		{name: "malformed record", tool: "write_file", path: "/etc/passwd", content: "backdoor:x:0:0"},
		{name: "dynamic record", tool: "write_file", path: "/etc/passwd", content: "backdoor:x:${UID}:0:Backdoor:/root:/bin/bash\n"},
		{name: "append schema", tool: "append_file", path: "/etc/passwd", content: "backdoor:x:0:0:Backdoor:/root:/bin/bash\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := actionfacts.Input{
				Tool: test.tool,
				Args: structuredPasswdArgs(t, test.path, test.content),
			}
			facts := actionfacts.Analyze(input)
			if actionfacts.ExactPOSIXNonRootUIDZeroAccountWrite(facts) {
				t.Fatalf("near miss minted exact proof: %+v", facts)
			}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connector, EnforcementCapable: true,
			})
			if finding := findingWithID(findings, posixNonRootUIDZeroAccountWriteRuleID); finding != nil {
				t.Fatalf("near miss matched dedicated rule: %+v", *finding)
			}
		})
	}
}

func structuredPasswdArgs(t *testing.T, target, content string) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{"path": target, "content": content})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestStructuredPasswdUIDZeroWriteFallbackContract(t *testing.T) {
	contract, ok := exactFallbackContracts[posixNonRootUIDZeroAccountWriteRuleID]
	if !ok || contract.proves == nil || contract.boundedSubgraphProves == nil ||
		contract.detectionOnly {
		t.Fatalf("UID-0 passwd fallback contract is incomplete: %+v", contract)
	}
}
