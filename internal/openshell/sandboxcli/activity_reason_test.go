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

package sandboxcli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// TestEveryBlockedReasonReadsInWords (GAP-0071): a draft rule triage
// rejected showed as "(unsupported rule)", the raw token with spaces, next
// to "(no OpenShell rule allows it)" for the same connection. Every reason
// a triage rejection publishes on a blocked line has words.
func TestEveryBlockedReasonReadsInWords(t *testing.T) {
	for _, r := range []triage.Reason{triage.ReasonNoEndpoints, triage.ReasonInvalid, triage.ReasonWildcard, triage.ReasonPolicy,
		triage.ReasonAdmin, triage.ReasonBlocklisted, triage.ReasonIPLiteral, triage.ReasonPortNotAllowed, triage.ReasonAgentProposalOff,
		triage.ReasonResolvesToHost, triage.ReasonUnresolved, triage.ReasonRuleShape, triage.ReasonMultipleHosts, triage.ReasonHarnessFetch,
		triage.ReasonRateLimited, triage.ReasonRuleLimit, triage.ReasonTooManyPending} {
		if _, ok := reasonTexts[string(r)]; !ok {
			t.Errorf("reason %s has no words: %q", r, reasonText(string(r)))
		}
	}
	if got := reasonText(string(triage.ReasonRuleShape)); !strings.HasPrefix(got, "no OpenShell rule allows it") {
		t.Fatalf("unsupported_rule = %q", got)
	}
}

// TestSSHBlocksSayUseHTTPS (GAP-0090, GAP-0111): git over SSH failed with
// only the client's "Permission denied", and the feed offered an unblock
// that cannot open port 22. A refused port 22 says to use an HTTPS remote.
func TestSSHBlocksSayUseHTTPS(t *testing.T) {
	ta := newTestApp(t, "")
	line := ta.activityLine(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: "box", Host: "github.com", Port: 22,
		Reason: "transparent_tcp_policy_denied", Unblockable: true, Time: ta.Now()}, false)
	if !strings.Contains(line, "github.com:22 (SSH does not leave a sandbox: use an HTTPS remote (https://github.com/…))") || strings.Contains(line, "unblock") {
		t.Fatalf("line = %q", line)
	}
}
