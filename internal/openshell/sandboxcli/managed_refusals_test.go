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

package sandboxcli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// GAP-0502, GAP-0468: an organization's refusal on the feed shows its
// managed text under the line, and a change to the sandbox's rules without
// one destination reads as its message, not "✗  (admin policy)".
func TestActivityShowsManagedRefusals(t *testing.T) {
	ta := newTestApp(t, "")
	refusal := sandboxapi.AccessRefused("egress_allow_only", "api.example.net", "contractors", "brave-otter", "it-security@example.com")
	line := ta.activityLine(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Host: "api.example.net", Port: 443,
		Category: "admin_allow_only", Refusal: refusal, Time: ta.Now()}, false)
	for _, want := range []string{"api.example.net (", "\n         Blocked by your organization's DefenseClaw policy: api.example.net is not on your profile's allowed hosts",
		"\n         Request access: it-security@example.com. Quote: profile contractors, rule egress_allow_only, host api.example.net, sandbox brave-otter."} {
		if !strings.Contains(line, want) {
			t.Errorf("line lacks %q:\n%s", want, line)
		}
	}
	line = ta.activityLine(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Reason: "admin_policy",
		Message: "✗ removed 1 approved rule(s) " + sandboxapi.AdminMessage, Time: ta.Now()}, false)
	if !strings.Contains(line, "✗ removed 1 approved rule(s) "+sandboxapi.AdminMessage) || strings.Contains(line, "  (") {
		t.Fatalf("rule-change line = %q", line)
	}
}

// GAP-0468: under user_approvals: none the banner and status promise no
// approval: the host port stays closed and the contact is named.
func TestBannerUnderApprovalsNone(t *testing.T) {
	ta := newTestApp(t, "")
	sb := sampleSandbox("box")
	sb.UserApprovals = config.OpenShellUserApprovalsNone
	ta.banner(&sb, bannerInfo{o: RunOptions{HostPorts: []int{5432}}, managed: &sandboxapi.ManagedStatus{Profile: "tt-none", RequestAccess: "it-security@example.com"}})
	has(t, ta.output(), "localhost:5432 (stays closed: your profile doesn't let you approve connections to it; request access: it-security@example.com)",
		"your profile doesn't let you approve asks, so a new destination stays closed; request access: it-security@example.com")
	lacks(t, ta.output(), "opens when you approve", "answer them in another terminal")
}

// GAP-0508: a managed refusal is printed as the daemon built it, without
// the openshell.admin key a framing added.
func TestAPIErrorPrintsManagedRefusalVerbatim(t *testing.T) {
	msg := sandboxapi.AccessRefused("allow_unblock", "example.org", "tt-2", "pm28a", "it-security@example.com")
	err := apiError(&sandboxapi.Error{Code: sandboxapi.CodeAdminViolation, Message: msg,
		Violation: &sandboxapi.Violation{Key: "egress.unblock", Constraint: "openshell.admin.allow_unblock", Admin: true, Message: msg}})
	if err == nil || err.Error() != msg {
		t.Fatalf("apiError = %v, want %q", err, msg)
	}
}
