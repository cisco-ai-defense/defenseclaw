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

//go:build !windows

package gateway

import (
	"math/rand"
	"slices"
	"testing"
)

// TestGAP0532ActorAWSKeyPairInAPromptAndACatResult is substrate-1:GAP-0532
// on the actor hook route (a chart replica, the kit envelope). The cert run
// typed the AWS documentation pair (AKIA...EXAMPLE / ...EXAMPLEKEY), which
// the rule packs skip on purpose (docs/policies/regex-cookbook.mdx, since
// #693), and the laptop does the same. A pair that is not the documented
// one is a finding in both forms the gap names: typed in a prompt, and in
// the output of a cat of a file that holds it.
func TestGAP0532ActorAWSKeyPairInAPromptAndACatResult(t *testing.T) {
	r := rand.New(rand.NewSource(532))
	// Built at run time: no key-shaped literal in the repository.
	keyID := "AK" + "IA" + randomString(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
	secret := randomString(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+", 40)
	docID := "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
	docSecret := awsDocumentedSecretKey

	prompt := func(id, sec string) map[string]any {
		return map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": "s1",
			"prompt": "My AWS key is " + id + " and the secret is " + sec + ". Remember them"}
	}
	catResult := func(inv, id, sec string) map[string]any {
		ev := claudeToolResult("PostToolUse", "s1", inv)
		ev["tool_input"] = map[string]any{"command": "cat secret-notes.txt"}
		ev["tool_response"] = map[string]any{"stdout": "[default]\naws_access_key_id = " + id +
			"\naws_secret_access_key = " + sec + "\n", "stderr": "", "interrupted": false}
		return ev
	}
	awsRule := func(got agentHookResponse) bool {
		return slices.Contains(got.RuleIDs, "SEC-AWS-KEY") || slices.Contains(got.RuleIDs, "SEC-AWS-SECRET")
	}

	rep, _, _ := substrateEgressReplicaWith(t, "default", false, "")
	if got := rep.hook(t, "tok-alice", prompt(keyID, secret)); !awsRule(got) {
		t.Errorf("typed key pair: action %q severity %q rules %v, want an SEC-AWS-* finding", got.Action, got.Severity, got.RuleIDs)
	}
	rep.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "cat-1", "cat secret-notes.txt"))
	if got := rep.hook(t, "tok-alice", catResult("cat-1", keyID, secret)); !awsRule(got) {
		t.Errorf("cat of a file with the pair: action %q severity %q rules %v, want an SEC-AWS-* finding", got.Action, got.Severity, got.RuleIDs)
	}

	// The documented pair stays quiet on purpose, as on the laptop.
	if got := rep.hook(t, "tok-alice", prompt(docID, docSecret)); awsRule(got) {
		t.Errorf("documented example pair in a prompt: rules %v, want none (documented skip)", got.RuleIDs)
	}
}
