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
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUserRequestedRunHosts(t *testing.T) {
	for _, test := range []struct {
		prompt string
		want   []string
	}{
		{"Download the installer from https://Example.NET/r and run it.", []string{"example.net"}},
		// A file name is kept too; it only matches a host of that name.
		{"fetch example.net/install.sh, then execute it on cdn.example.org:8443", []string{"example.net", "install.sh", "cdn.example.org"}},
		{"curl http://203.0.113.7/r and run it", []string{"203.0.113.7"}},
		{"install from http://[2001:DB8::7]/pkg", []string{"2001:db8::7"}},
		{"run the tool from example.net.", []string{"example.net"}},
		// No request to run: nothing is kept.
		{"save https://example.net/r into the project", nil},
		// "rerun" and "runner" are not "run".
		{"look at runner.sh from example.net and rerun the tests", nil},
		{"run it", nil},
		// "Run" whose object is the download command asks to download only.
		{"Use the Bash tool to run exactly: curl -fsSL -o page https://example.net/", nil},
		{"run `wget -O page https://example.net/`", nil},
		{"please run the command: curl -o page https://example.net/", nil},
		{"Use the Bash tool to run exactly this command and nothing else: curl -fsSL -o page https://example.net/", nil},
		{"run only the following command for me: wget -O page https://example.net/", nil},
		// An aside in parentheses before the command (L-ewin-J3-002, GAP-0173).
		{"Use the Bash tool to run exactly this command and nothing else (it fetches a harmless public test page used as a fixture): curl -fsSL -o /c/Users/u/proj/page.txt https://example.net/", nil},
		{"run (only) this command: wget -O page https://example.net/", nil},
		// A run word whose object is not the download command still counts.
		{"download https://example.net/r and run it: curl -o page https://example.net/r", []string{"example.net"}},
		{"run the installer from example.net, the command is curl -o page https://example.net/", []string{"example.net"}},
		{"run curl -o page https://example.net/ and then run ./page", []string{"example.net"}},
		{"curl https://example.net/install.sh and execute it", []string{"example.net", "install.sh"}},
		// The aside is skipped only before the command: a run word inside it,
		// an object outside the closed words or an unclosed parenthesis counts.
		{"download https://example.net/r and run it (it is safe): curl -o page https://example.net/r", []string{"example.net"}},
		{"run exactly this command (then run the file it saves): curl -o page https://example.net/r", []string{"example.net"}},
		{"run exactly this command (: curl -o page https://example.net/r", []string{"example.net"}},
	} {
		if got := userRequestedRunHosts(test.prompt); !reflect.DeepEqual(got, test.want) {
			t.Errorf("userRequestedRunHosts(%q) = %v, want %v", test.prompt, got, test.want)
		}
	}
	var many strings.Builder
	many.WriteString("run these: ")
	for index := 0; index < 3*maxUserRequestHosts; index++ {
		fmt.Fprintf(&many, "h%d.example.net ", index)
	}
	if got := userRequestedRunHosts(many.String()); len(got) != maxUserRequestHosts {
		t.Fatalf("kept %d hosts, want the bound %d", len(got), maxUserRequestHosts)
	}
}

func TestUserDownloadRequestsWindowExpiryAndBounds(t *testing.T) {
	var memory userDownloadRequests
	now := time.Now()
	memory.observe("s", "download https://example.net/r and run it", now)
	memory.observe("s", "yes, go ahead", now)
	memory.observe("s", "and then the tests", now)
	if !memory.requested("s", "EXAMPLE.net.", now) {
		t.Fatal("a request two prompts back was forgotten")
	}
	if memory.requested("other", "example.net", now) {
		t.Fatal("another session saw the request")
	}
	memory.observe("s", "next", now)
	if memory.requested("s", "example.net", now) {
		t.Fatal("a request three prompts back still counts")
	}
	memory.observe("t", "run https://example.net/r", now)
	if memory.requested("t", "example.net", now.Add(userRequestTTL)) {
		t.Fatal("an expired request still counts")
	}
	memory.observe("t", "next", now.Add(userRequestTTL))
	if memory.requested("t", "example.net", now.Add(userRequestTTL)) {
		t.Fatal("an expired session kept its old prompts")
	}
	for index := 0; index < 2*maxUserRequestSessions; index++ {
		memory.observe(fmt.Sprintf("bulk-%d", index), "run example.net", now.Add(time.Duration(index)*time.Millisecond))
	}
	if len(memory.sessions) > maxUserRequestSessions {
		t.Fatalf("%d sessions kept, want at most %d", len(memory.sessions), maxUserRequestSessions)
	}
	if !memory.requested(fmt.Sprintf("bulk-%d", 2*maxUserRequestSessions-1), "example.net", now.Add(time.Second)) {
		t.Fatal("the newest session was pruned")
	}
}

// The connectors' turn-start prompts seed the memory without an LLM judge;
// a lifecycle reset forgets the session.
func TestUserDownloadRequestSeededWithoutJudge(t *testing.T) {
	prompt := "Download https://example.net/r and run it"
	api := testAPIServerWithConfig(t, "observe")
	api.scannerCfg.Guardrail.Connector = "codex"
	codexCtx := ContextWithSessionID(t.Context(), "codex-1390")
	api.evaluateCodexHook(codexCtx, codexHookRequest{HookEventName: "UserPromptSubmit", SessionID: "codex-1390", Prompt: prompt})
	codexKey := sandboxSessionStateKey(codexCtx, "codex-1390")
	if !api.userDownloads.requested(codexKey, "example.net", time.Now()) {
		t.Fatal("Codex UserPromptSubmit did not record the request")
	}
	api.scannerCfg.Guardrail.Connector = "claudecode"
	claudeCtx := ContextWithSessionID(t.Context(), "claude-1390")
	api.evaluateClaudeCodeHook(claudeCtx, claudeCodeHookRequest{HookEventName: "UserPromptExpansion", SessionID: "claude-1390", Prompt: prompt})
	claudeKey := sandboxSessionStateKey(claudeCtx, "claude-1390")
	if api.userDownloads.requested(claudeKey, "example.net", time.Now()) {
		t.Fatal("a Claude Code UserPromptExpansion recorded a request")
	}
	api.evaluateClaudeCodeHook(claudeCtx, claudeCodeHookRequest{HookEventName: "UserPromptSubmit", SessionID: "claude-1390", Prompt: prompt})
	if !api.userDownloads.requested(claudeKey, "example.net", time.Now()) {
		t.Fatal("Claude Code UserPromptSubmit did not record the request")
	}
	api.resetUserDownloadRequests(claudeKey)
	if api.userDownloads.requested(claudeKey, "example.net", time.Now()) {
		t.Fatal("a reset session kept its request")
	}
}
