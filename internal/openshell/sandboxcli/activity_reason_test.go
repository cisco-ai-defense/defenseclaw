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
		if _, ok := sandboxapi.LookupReasonText(string(r)); !ok {
			t.Errorf("reason %s has no words: %q", r, sandboxapi.ReasonText(string(r)))
		}
	}
	if got := sandboxapi.ReasonText(string(triage.ReasonRuleShape)); !strings.HasPrefix(got, "no OpenShell rule allows it") {
		t.Fatalf("unsupported_rule = %q", got)
	}
}

// TestMetadataBlocksAreNotThisMachine (GAP-0147): a refused request to the
// cloud metadata address read "169.254.169.254:80 (this machine)" through the
// proxy and "(no OpenShell rule allows it)" directly. Both name a cloud
// metadata or link-local address; this machine stays this machine.
func TestMetadataBlocksAreNotThisMachine(t *testing.T) {
	ta := newTestApp(t, "")
	const metadata = "(cloud metadata or link-local address, never reachable from a sandbox)"
	for _, ev := range []sandboxapi.ActivityEvent{
		{Host: "169.254.169.254", Port: 80, Category: "host_internal"},
		{Host: "169.254.169.254", Port: 80, Reason: "transparent_tcp_policy_denied"},
		{Host: "[fe80::1]", Port: 80, Category: "host_internal"},
		{Host: "metadata.google.internal", Port: 80, Category: "host_internal"},
		{Host: "168.63.129.16", Port: 80, Category: "host_internal"},
	} {
		ev.Kind, ev.Time = sandboxapi.ActivityEgressBlocked, ta.Now()
		if line := ta.activityLine(ev, false); !strings.Contains(line, metadata) {
			t.Errorf("%s: line = %q", ev.Host, line)
		}
	}
	if line := ta.activityLine(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Host: "127.0.0.1", Port: 8080,
		Category: "host_internal", Time: ta.Now()}, false); !strings.Contains(line, "(this machine)") {
		t.Fatalf("loopback line = %q", line)
	}
}

// TestSSHBlocksSayUseHTTPS (GAP-0090, GAP-0111): git over SSH failed with
// only the client's "Permission denied", and the feed offered an unblock
// that cannot open port 22. A refused port 22 says to use an HTTPS remote.
// GAP-0309: the second line of a folded burst of refusals read like the
// first; it names the refusals it stands for.
func TestFoldedRefusalsNameTheirCount(t *testing.T) {
	ta := newTestApp(t, "")
	line := ta.activityLine(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Host: "pypi.org", Port: 443,
		Reason: "transparent_tcp_policy_denied", Repeats: 5, Time: ta.Now()}, false)
	if !strings.HasSuffix(line, "pypi.org (no OpenShell rule allows it) (and 5 more like it)") {
		t.Fatalf("line = %q", line)
	}
}

// GAP-0356: a refused port on this machine reads in the daemon's words,
// which tell a port DefenseClaw never opens from one --host-port opens.
func TestClosedHostPortsSayWhy(t *testing.T) {
	ta := newTestApp(t, "")
	const target = "host.openshell.internal:18990"
	why := "the sandbox policy does not open port 18990 on this machine to the sandbox (DefenseClaw never opens DefenseClaw API (port 18990) to a sandbox (choose another port))"
	line := ta.activityLine(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Host: "host.openshell.internal", Port: 18990,
		Reason: sandboxapi.ReasonHostPortClosed, Message: "✗ " + target + ": " + why, Time: ta.Now()}, false)
	if !strings.HasSuffix(line, target+": "+why) || strings.Contains(line, "host port closed") {
		t.Fatalf("line = %q", line)
	}
}

func TestSSHBlocksSayUseHTTPS(t *testing.T) {
	ta := newTestApp(t, "")
	line := ta.activityLine(sandboxapi.ActivityEvent{Kind: sandboxapi.ActivityEgressBlocked, Sandbox: "box", Host: "github.com", Port: 22,
		Reason: "transparent_tcp_policy_denied", Unblockable: true, Time: ta.Now()}, false)
	if !strings.Contains(line, "github.com:22 (SSH does not leave a sandbox: use an HTTPS remote (https://github.com/…))") || strings.Contains(line, "unblock") {
		t.Fatalf("line = %q", line)
	}
}
