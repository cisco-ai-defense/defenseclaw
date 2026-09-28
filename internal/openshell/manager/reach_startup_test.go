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

package manager

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// A hooks-only harness sends no hook before its first prompt, and live its
// start-up and onboarding traffic (update checks, telemetry, a download,
// through the egress proxy and around it) raised a HIGH "hooks are not
// reaching the daemon; every tool call is being blocked" alarm 30 seconds
// into agy's first-run screens, and on a started sandbox with no harness at
// all. None of it is a model call of the harness, so none of it starts the
// window.
func TestHookReachIgnoresStartupTraffic(t *testing.T) {
	r := newReachEnv(t)
	ctx := context.Background()
	for _, host := range []string{"pypi.org", "antigravity-unleash.goog", "raw.githubusercontent.com"} {
		r.m.egressEvent(ctx, egress.Event{Kind: egress.EventAllowed, SandboxName: r.name, Host: host, Port: 443, Time: r.clock(), FirstSeen: true})
		r.m.egressEvent(ctx, egress.Event{Kind: egress.EventClosed, SandboxName: r.name, Host: host, Port: 443, Time: r.clock()})
	}
	// The harness's own requests around the proxy, refused or allowed by a
	// rule that is no provider's, and a tool's.
	r.ocsf("NET:OPEN [MED] DENIED " + testClaudeBin + "(9) -> play.googleapis.com:443 [reason:transparent_tcp_policy_denied]")
	r.ocsf("NET:OPEN [INFO] ALLOWED " + testClaudeBin + "(9) -> registry.example.org:443 [policy:allow_registry_example_org_443 engine:opa]")
	r.ocsf("NET:OPEN [INFO] ALLOWED /usr/bin/curl(3) -> api.anthropic.com:443 [policy:_provider_anthropic engine:opa]")
	for i := 0; i < 4; i++ {
		r.advance(DefaultHookReachWindow)
		r.m.checkHookReach(ctx)
	}
	if h := r.hooks(); h.Unreachable {
		t.Fatalf("start-up traffic raised the alarm: %+v", h)
	}
	if n := len(r.feed(sandboxapi.ReasonHooksUnreachable)); n != 0 || len(r.findings()) != 0 {
		t.Fatalf("warnings = %d, findings = %d", n, len(r.findings()))
	}
}

// The harness calling its model without a single hook request is still
// flagged, but DefenseClaw saw no hook fail: the warning says no hook has
// reached it yet, not that every tool call is being blocked.
func TestHookReachModelCallSaysNotYet(t *testing.T) {
	r := newReachEnv(t)
	ctx := context.Background()
	r.ocsf("NET:OPEN [INFO] ALLOWED " + testClaudeBin + "(9) -> api.anthropic.com:443 [policy:_provider_anthropic engine:opa]")
	r.advance(DefaultHookReachWindow + 2*time.Second)
	r.m.checkHookReach(ctx)
	h := r.hooks()
	if !h.Unreachable || !h.NoHookYet || !strings.Contains(h.UnreachableReason, "calling its model for 32s") {
		t.Fatalf("hooks = %+v", h)
	}
	warn := r.feed(sandboxapi.ReasonHooksUnreachable)
	if len(warn) != 1 || !strings.HasPrefix(warn[0].Message, "⚠ No hook has reached DefenseClaw yet (") ||
		strings.Contains(warn[0].Message, sandboxapi.HooksUnreachableWarning) || !strings.HasSuffix(warn[0].Message, sandboxapi.HooksDoctorHint) {
		t.Fatalf("feed = %+v", warn)
	}
	if f := r.findings(); len(f) != 1 || strings.Contains(f[0].Description, "every tool call of the session is blocked") {
		t.Fatalf("findings = %+v", f)
	}
	// A hook clears it, and NoHookYet with it.
	r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
	if h := r.hooks(); h.Unreachable || h.NoHookYet {
		t.Fatalf("after a hook = %+v", h)
	}
}

// OpenShell answers a connection to the ingress with a mapping denial while
// it republishes the host alias's mapping (live: Claude's OTLP export 4s
// after the session's last hook). The client's next request gets through,
// so the denial alone raises nothing; one no request follows is a refusal
// once the grace period ends.
func TestHookReachMappingDenialNeedsConfirmation(t *testing.T) {
	denied := "NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> host.openshell.internal:" + strconv.Itoa(testIngressPort) +
		" [reason:transparent_tcp_mapping_denied]"
	ctx := context.Background()

	r := newReachEnv(t)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteHook)
	r.advance(time.Second)
	r.ocsf(denied)
	if h := r.hooks(); h.Unreachable || h.IngressRefused != 0 {
		t.Fatalf("a mapping denial flagged the session at once: %+v", h)
	}
	r.advance(time.Second)
	r.m.ObserveIngress(r.binding, sandboxauth.RouteOTLP)
	r.advance(hookAttemptGrace + time.Second)
	r.m.checkHookReach(ctx)
	if h := r.hooks(); h.Unreachable || h.IngressRefused != 0 {
		t.Fatalf("a mapping denial the next request answered = %+v", h)
	}

	r = newReachEnv(t)
	r.ocsf(denied)
	r.advance(hookAttemptGrace - time.Second)
	r.m.checkHookReach(ctx)
	if h := r.hooks(); h.Unreachable {
		t.Fatalf("flagged within the grace period: %+v", h)
	}
	r.advance(2 * time.Second)
	r.m.checkHookReach(ctx)
	if h := r.hooks(); !h.Unreachable || h.NoHookYet || h.IngressRefused != 1 || !strings.Contains(h.UnreachableReason, "OpenShell refused") {
		t.Fatalf("an unanswered mapping denial = %+v", h)
	}
}
