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

package connector

import (
	"strings"
	"testing"
)

// A Substrate hook posts to the actor Service with the actor header and no
// bearer, and verifies an https ingress with the baked CA bundle. The same
// hook in an OpenShell image keeps the binding token's bearer.
func TestSubstrateHookSendsTheActorHeaderNotABearer(t *testing.T) {
	in := substrateIngress()
	in.Scheme, in.CAFile = "https", "/var/run/ate/ca.pem"
	artifacts, err := (&ClaudeCodeConnector{}).SandboxArtifacts(SandboxRenderTarget{Ingress: in, AgentVersion: "2.1.156"})
	if err != nil {
		t.Fatal(err)
	}
	h := newSandboxHookHarnessFiles(t, artifacts.Files, SandboxHookPATH)
	env := map[string]string{SandboxTokenEnv: artifacts.Env[SandboxTokenEnv]}
	run := h.run(t, SandboxHookDir+"/claude-code-hook.sh", nil, claudePreToolUse, env, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 {
		t.Fatalf("exit %d, %d calls, stderr %s", run.exitCode, len(run.calls), run.stderr)
	}
	call := run.calls[0]
	var url string
	for _, arg := range call.argv {
		if strings.HasPrefix(arg, "https://") {
			url = arg
		}
	}
	if url != "https://"+testSubstrateActorHost+":443/api/v1/claude-code/hook" {
		t.Fatalf("url %q in %q", url, call.argv)
	}
	if call.flagValue("--cacert") != "/var/run/ate/ca.pem" {
		t.Fatalf("--cacert %q", call.flagValue("--cacert"))
	}
	if call.headers["x-defenseclaw-actor"] != SandboxActorPlaceholder {
		t.Fatalf("actor header %q", call.headers["x-defenseclaw-actor"])
	}
	if _, bearer := call.headers["authorization"]; bearer || strings.Contains(call.config, "Authorization") {
		t.Fatalf("a Substrate hook sent a bearer: %+v", call.headers)
	}

	open := newSandboxHookHarness(t, &ClaudeCodeConnector{}, "2.1.156")
	run = open.run(t, SandboxHookDir+"/claude-code-hook.sh", nil, claudePreToolUse, map[string]string{SandboxTokenEnv: "tok"}, []string{allowResponse})
	if run.exitCode != 0 || len(run.calls) != 1 {
		t.Fatalf("openshell: exit %d, %d calls", run.exitCode, len(run.calls))
	}
	if run.calls[0].headers["authorization"] != "Bearer tok" || run.calls[0].headers["x-defenseclaw-actor"] != "" {
		t.Fatalf("openshell headers %+v", run.calls[0].headers)
	}
	if run.calls[0].url() != "http://host.openshell.internal:18971/api/v1/claude-code/hook" {
		t.Fatalf("openshell url %q", run.calls[0].url())
	}
}
