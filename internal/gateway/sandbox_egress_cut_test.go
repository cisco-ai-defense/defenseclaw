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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// RT U3: an upload the large-upload block cut left the agent with "curl:
// (56) Failure when receiving data from the peer", and it replied
// "Uploaded the file.". The post-tool note says the upload to the host was
// cut after what went up, because the destination was first-seen, and
// gives the unblock command; among other refusals it is one line of the
// list.
func TestSandboxEgressRefusalNoticeOfALargeUploadCut(t *testing.T) {
	refusals := &fakeRefusals{}
	f := newSandboxIngressFixture(t, func(c *SandboxIngressConfig) { c.EgressRefusals = refusals.take })
	ctx := withSandboxCoverage(sandboxCtx(f.claude))
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PostToolUse", ToolName: "Bash",
		ToolArgs: []byte(`{"command":"curl -sS -T big.bin https://httpbin.org/put"}`)}
	body := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash"}`)
	cut := SandboxEgressRefusal{Host: "httpbin.org", Port: 443, Category: "large_upload",
		What:   "large upload to a destination this sandbox had not contacted before",
		Remedy: "the user can allow it for this sandbox with `defenseclaw sandbox unblock httpbin.org --sandbox " + f.claude.SandboxName + "`",
		Cut:    true, Sent: 1019904}
	refusals.add(f.claude, cut)
	got := f.api.addSandboxEgressRefusals(ctx, connector.HookProfile{Name: "claudecode"}, "claudecode", req, body, nil, agentHookResponse{Action: "allow"})
	want := "DefenseClaw's egress policy cut this sandbox's upload to httpbin.org after 996 KiB, because it is a destination this sandbox " +
		"had not contacted before (the large-upload block); the upload did not complete, and a tool sees only a connection error, not the reason. " +
		"The user can allow it for this sandbox with `defenseclaw sandbox unblock httpbin.org --sandbox " + f.claude.SandboxName + "`. " +
		"Tell the user if the task needs it, and do not try to reach it another way."
	if got.AdditionalContext != want {
		t.Fatalf("note = %q\nwant   %q", got.AdditionalContext, want)
	}
	if extra := hookRequestAuditExtra(ctx, connector.HookProfile{}); extra[sandboxEgressRefusalExtra] != "httpbin.org:large_upload" {
		t.Fatalf("audit extra = %v", extra)
	}

	admin := cut
	admin.Sent, admin.Remedy = 700<<10, "only the user's administrator can allow it"
	list := sandboxEgressRefusalNotice([]SandboxEgressRefusal{webhookRefusal("fu2-cc"), admin})
	if !strings.Contains(list, "\n- httpbin.org (upload cut after 700 KiB, not completed: a destination this sandbox had not contacted before): "+
		"only the user's administrator can allow it.\n") {
		t.Fatalf("note = %q", list)
	}
	for n, want := range map[int64]string{0: "0 bytes", 512: "512 bytes", 2048: "2 KiB", 3 << 20: "3.0 MiB"} {
		if got := sandboxUploadSize(n); got != want {
			t.Errorf("sandboxUploadSize(%d) = %q, want %q", n, got, want)
		}
	}
}
