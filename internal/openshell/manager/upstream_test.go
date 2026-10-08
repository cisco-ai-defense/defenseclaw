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

package manager

import (
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// TestDestinationsCountUpstreamFailures (GAP-0284): fetches the egress
// proxy allowed and the host refused upstream left an allowed host with a
// clean record, so an outage read as nothing. The destination counts them,
// the status's Egress line has the total, and the feed says once that the
// connection failed upstream, not by policy.
func TestDestinationsCountUpstreamFailures(t *testing.T) {
	e := liveEnv(t, "failbox", nil)
	id, now := e.binding("failbox").ID, time.Now()
	proxy := func(kind egress.EventKind, status int, why string) {
		e.m.egressEvent(t.Context(), egress.Event{Kind: kind, Time: now, BindingID: id, SandboxName: "failbox", Method: "CONNECT",
			Host: "example.org", Port: 443, Status: status, Error: why}, 0)
	}
	proxy(egress.EventAllowed, 0, "")
	proxy(egress.EventClosed, 0, "")
	for range 2 {
		proxy(egress.EventAllowed, 0, "")
		proxy(egress.EventFailed, http.StatusBadGateway, "dial tcp 192.0.2.7:443: connect: connection refused")
	}
	if r := destinationKinds(t, e, "failbox")["example.org"]; r.Failed != 2 {
		t.Fatalf("example.org = %+v, want 2 failed upstream", r)
	}
	if s := e.get("failbox").Egress; s.UpstreamFailed != 2 || s.Blocked != 0 {
		t.Fatalf("egress status = %+v, want 2 failed upstream and nothing blocked", s)
	}
	want := "⚠ example.org: the connection failed upstream, not blocked by DefenseClaw (it refused the connection); " +
		"`defenseclaw sandbox destinations failbox` counts the failures"
	if got := e.events("failbox", sandboxapi.ActivityFinding, sandboxapi.ReasonUpstreamFailed); len(got) != 1 || got[0].Message != want || got[0].Severity != "INFO" {
		t.Fatalf("feed = %+v, want one INFO %q", got, want)
	}
}

// TestAHostWhoseNameDidNotResolveIsADestination (GAP-0340): the proxy
// reports only the failure of a request whose dial failed, so a name that
// did not resolve was in the audit alone. It gets its row, counted as
// failed upstream and not as a block, the status counts it and the feed
// says once that the name did not resolve.
func TestAHostWhoseNameDidNotResolveIsADestination(t *testing.T) {
	e := liveEnv(t, "dnsbox", nil)
	id, now := e.binding("dnsbox").ID, time.Now()
	for range 3 {
		e.m.egressEvent(t.Context(), egress.Event{Kind: egress.EventFailed, Time: now, BindingID: id, SandboxName: "dnsbox", Method: "CONNECT",
			Host: "does-not-exist.invalid", Port: 443, Status: http.StatusBadGateway, Error: "DNS resolution failed"}, 0)
	}
	if r := destinationKinds(t, e, "dnsbox")["does-not-exist.invalid"]; r.Failed != 3 || r.Kind != sandboxapi.DestinationOther {
		t.Fatalf("row = %+v, want other with 3 failed upstream", r)
	}
	if s := e.get("dnsbox").Egress; s.UpstreamFailed != 3 || s.Blocked != 0 {
		t.Fatalf("egress status = %+v, want 3 failed upstream and nothing blocked", s)
	}
	want := "⚠ does-not-exist.invalid: the connection failed upstream, not blocked by DefenseClaw (its name did not resolve); " +
		"`defenseclaw sandbox destinations dnsbox` counts the failures"
	if got := e.events("dnsbox", sandboxapi.ActivityFinding, sandboxapi.ReasonUpstreamFailed); len(got) != 1 || got[0].Message != want {
		t.Fatalf("feed = %+v, want one %q", got, want)
	}
}
