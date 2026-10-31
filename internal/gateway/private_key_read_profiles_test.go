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
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0124: an agent's direct read of an SSH private key through its shell
// tool. In action mode both the shipped default pack and the strict pack
// refuse it (PATH-SSH-KEY); observe mode alerts without refusing. Everyday
// key use never reads the private key's content into the agent and is
// allowed in both packs: the public key, ssh-keygen -y, ssh-add, ssh -i and
// a signed commit.
func TestPrivateKeyReadAcrossShippedPacks(t *testing.T) {
	refused := []string{
		"cat ~/.ssh/id_ed25519",
		"cat ~/.ssh/id_rsa",
		"head -n 5 ~/.ssh/id_ecdsa",
		"base64 ~/.ssh/id_ed25519",
	}
	allowed := []string{
		"cat ~/.ssh/id_ed25519.pub",
		"ssh-keygen -y -f ~/.ssh/id_ed25519",
		"ssh-add ~/.ssh/id_ed25519",
		"ssh -i ~/.ssh/id_ed25519 -o BatchMode=yes git@example.com true",
		"git commit -S -m sign",
		"ls -l ~/.ssh",
	}
	for _, pack := range []string{"default", "strict"} {
		for _, mode := range []string{"action", "observe"} {
			decide := func(t *testing.T, command string) map[string]any {
				t.Helper()
				store, logger := testStoreAndLogger(t)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.Connector = "claudecode"
				cfg.Guardrail.HookFailMode = "closed"
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
				api := &APIServer{scannerCfg: cfg, store: store, logger: logger}
				return postDecisionForTest(t, api, "claudecode", "PreToolUse", command)
			}
			for _, command := range refused {
				t.Run(pack+"/"+mode+"/refused/"+command, func(t *testing.T) {
					response := decide(t, command)
					denied := decisionIsDenied(response["claude_code_output"])
					if mode == "action" && (response["action"] != "block" || !denied) {
						t.Fatalf("action=%v output=%v, want a block", response["action"], response["claude_code_output"])
					}
					if mode == "observe" && (denied || response["would_block"] != true) {
						t.Fatalf("observe: action=%v would_block=%v denied=%v, want an alert that would block",
							response["action"], response["would_block"], denied)
					}
				})
			}
			for _, command := range allowed {
				t.Run(pack+"/"+mode+"/allowed/"+command, func(t *testing.T) {
					response := decide(t, command)
					if decisionIsDenied(response["claude_code_output"]) || response["action"] == "block" || response["would_block"] == true {
						t.Fatalf("everyday key use refused: %v", response)
					}
					if findings, _ := response["findings"].([]any); len(findings) > 0 {
						for _, f := range findings {
							if strings.HasPrefix(f.(string), "PATH-SSH-KEY:") {
								t.Fatalf("everyday key use found as a key read: %v", findings)
							}
						}
					}
				})
			}
		}
	}
}
