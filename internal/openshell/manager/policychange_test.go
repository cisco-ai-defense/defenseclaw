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
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// feedWith returns the sandbox's feed events of kind with reason.
func feedWith(e *harnessEnv, sandbox, kind, reason string) []sandboxapi.ActivityEvent {
	var out []sandboxapi.ActivityEvent
	for _, ev := range e.m.ActivitySince(0, sandbox) {
		if ev.Kind == kind && ev.Reason == reason {
			out = append(out, ev)
		}
	}
	return out
}

// When the organization requires the strict pack, a running sandbox's web
// egress goes off: live, every request got the proxy's 407 "use the
// HTTPS_PROXY value the sandbox was started with", nothing reached the
// feed, and the agent went debugging its proxy credentials. The proxy now
// answers with a 403 that names the organization's required pack, the feed
// says so once, and it says what moved in the policy.
func TestRequiredStrictPackTurnsRunningEgressOff(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	proxy := startLiveProxy(t, e)
	sb := e.create(sandboxapi.CreateRequest{Name: "basebox"})
	e.watch.waitStarted(t, sb.Name)
	if status, _ := proxy.connect(t, e, sb.Name, "example.org:443"); status != http.StatusOK {
		t.Fatalf("CONNECT under the open pack = %d", status)
	}

	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "strict" })
	e.m.refreshEgress()
	status, body := proxy.connect(t, e, sb.Name, "example.org:443")
	if status != http.StatusForbidden || body.Category != egress.CategoryEgressOff ||
		!strings.Contains(body.Reason, "required sandbox pack (strict)") || !strings.Contains(body.Reason, "openshell.admin.required_pack") {
		t.Fatalf("CONNECT under the required strict pack = %d %+v", status, body)
	}
	off := feedWith(e, sb.Name, sandboxapi.ActivityEgressBlocked, sandboxapi.ReasonEgressOff)
	if len(off) != 1 || !strings.HasPrefix(off[0].Message, "✗ all web egress: your organization's required sandbox pack (strict)") {
		t.Fatalf("egress-off feed = %+v", off)
	}
	moved := feedWith(e, sb.Name, sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged)
	if len(moved) != 1 || !strings.HasPrefix(moved[0].Message, "your organization's sandbox policy changed: ") ||
		!strings.Contains(moved[0].Message, "pack open → strict") || !strings.Contains(moved[0].Message, "(web egress off)") {
		t.Fatalf("policy-change feed = %+v", moved)
	}
	got, _ := e.m.Get(context.Background(), sb.Name)
	if got.NetworkMode != "deny" || got.Pack != "strict" {
		t.Fatalf("status = pack %s, network %s", got.Pack, got.NetworkMode)
	}

	// The same configuration again moves nothing.
	e.m.refreshEgress()
	if n := len(feedWith(e, sb.Name, sandboxapi.ActivityEgressBlocked, sandboxapi.ReasonEgressOff)); n != 1 {
		t.Fatalf("egress-off lines = %d", n)
	}
	if n := len(feedWith(e, sb.Name, sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged)); n != 1 {
		t.Fatalf("policy-change lines = %d", n)
	}

	// Relaxed again, the egress comes back.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "" })
	e.m.refreshEgress()
	if status, _ := proxy.connect(t, e, sb.Name, "example.org:443"); status != http.StatusOK {
		t.Fatalf("CONNECT after the relax = %d", status)
	}
	moved = feedWith(e, sb.Name, sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged)
	if len(moved) != 2 || !strings.Contains(moved[1].Message, "pack strict → open") {
		t.Fatalf("policy-change feed after the relax = %+v", moved)
	}
}

// An administrator's change of the egress lists reaches every running
// sandbox's feed as one line, naming what changed; a stopped sandbox gets
// none.
func TestAdminEgressChangeIsAnnouncedPerSandbox(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	one := e.create(sandboxapi.CreateRequest{Name: "onebox"})
	two := e.create(sandboxapi.CreateRequest{Name: "twobox", Project: e.otherProject("two")})
	idle := e.create(sandboxapi.CreateRequest{Name: "idlebox", Project: e.otherProject("idle")})
	e.watch.waitStarted(t, one.Name)
	e.watch.waitStarted(t, two.Name)
	if _, err := e.m.Stop(context.Background(), idle.Name); err != nil {
		t.Fatal(err)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"example.com", "*.example.org"} })
	e.m.refreshEgress()
	for _, name := range []string{one.Name, two.Name} {
		moved := feedWith(e, name, sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged)
		if len(moved) != 1 || moved[0].Message != "your organization's sandbox policy changed: egress_block now includes example.com, *.example.org; applied to "+name {
			t.Fatalf("%s: policy-change feed = %+v", name, moved)
		}
	}
	if moved := feedWith(e, idle.Name, sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged); len(moved) != 0 {
		t.Fatalf("a stopped sandbox was told: %+v", moved)
	}
}

// Status reported the next launch's skip-permissions mode as the session's:
// "skip-permissions off" while the running Claude was still in bypass mode.
// The view keeps Launch.Yolo for the next launch, reports the session's in
// SessionYolo, and warns that the session runs out of policy.
func TestStatusReportsTheSessionsSkipPermissions(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "yolobox"})
	e.watch.waitStarted(t, sb.Name)
	ctx := context.Background()
	got, _ := e.m.Get(ctx, sb.Name)
	if !got.Launch.Yolo || !got.SessionYolo {
		t.Fatalf("before = launch %v, session %v", got.Launch.Yolo, got.SessionYolo)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowYolo = boolPtr(false) })
	e.m.refreshEgress()
	got, _ = e.m.Get(ctx, sb.Name)
	var warned bool
	for _, w := range got.Warnings {
		warned = warned || (strings.Contains(w, "skip-permissions stays on in the session running now") && strings.Contains(w, "openshell.admin.allow_yolo"))
	}
	if got.Launch.Yolo || got.Yolo || !got.SessionYolo || !warned {
		t.Fatalf("after allow_yolo false = launch %v, yolo %v, session %v, warnings %q", got.Launch.Yolo, got.Yolo, got.SessionYolo, got.Warnings)
	}
	// The next session follows the policy.
	if _, err := e.m.Stop(ctx, sb.Name); err != nil {
		t.Fatal(err)
	}
	if got, _ = e.m.Get(ctx, sb.Name); got.SessionYolo {
		t.Fatal("a stopped sandbox reports a session in skip-permissions mode")
	}
	if _, err := e.m.Start(ctx, sb.Name, sandboxapi.StartRequest{}); err != nil {
		t.Fatal(err)
	}
	got, _ = e.m.Get(ctx, sb.Name)
	for _, w := range got.Warnings {
		if strings.Contains(w, "skip-permissions stays on") {
			t.Fatalf("the new session is still warned: %q", got.Warnings)
		}
	}
	if got.SessionYolo || got.Launch.Yolo {
		t.Fatalf("new session = launch %v, session %v", got.Launch.Yolo, got.SessionYolo)
	}
}

// The create-time clamps of a sandbox stayed on status after the
// administrator dropped the constraint behind them ("blocked by your
// organization's DefenseClaw policy: pack … the run uses pack strict" with
// no required pack left). The view reports the clamps the configuration
// applies now.
func TestViolationsFollowThePolicy(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "strict" })
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "clampbox", Pack: "open"})
	e.watch.waitStarted(t, sb.Name)
	ctx := context.Background()
	got, _ := e.m.Get(ctx, sb.Name)
	var pack bool
	for _, v := range got.Violations {
		pack = pack || v.Key == "pack"
	}
	if !pack {
		t.Fatalf("violations under the required pack = %+v", got.Violations)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "" })
	e.m.refreshEgress()
	got, _ = e.m.Get(ctx, sb.Name)
	for _, v := range got.Violations {
		if v.Key == "pack" {
			t.Fatalf("stale violation after the constraint went: %+v", got.Violations)
		}
	}
	if got.Pack != "open" || got.Approvals == "manual" {
		t.Fatalf("status = pack %s, approvals %s", got.Pack, got.Approvals)
	}
}
