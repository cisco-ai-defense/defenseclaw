// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// gatewayViewFake is the managed gateway's policy view as the gateway gives
// it: a view names a connector, and one that names none is refused (403
// connector unknown, gateway/sandbox_authority_routes.go). asked records the
// connectors it was asked for.
type gatewayViewFake struct {
	mu    sync.Mutex
	asked []string
	view  *sandboxapi.ManagedExplain
}

func (g *gatewayViewFake) policy(_ context.Context, harness string) (*sandboxapi.ManagedExplain, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked = append(g.asked, harness)
	if harness == "" {
		return nil, errors.New("403 connector_unknown")
	}
	return g.view, nil
}

func (g *gatewayViewFake) connectors() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return strings.Join(g.asked, ",")
}

// profileRefusedFixture is a managed account whose profile refuses sandboxes
// while the daemon's own status (a daemon that just restarted) names the
// install reason: the fixture of viewDenied, with a gateway that needs a
// connector.
func profileRefusedFixture(t *testing.T, primary string) (*testApp, *gatewayViewFake) {
	t.Helper()
	ta, _ := launchAgentDoctorFixture(t, "", nil)
	ta.GOOS = "linux"
	ta.daemon.status.Enabled, ta.daemon.status.Available = true, false
	ta.daemon.status.Managed = managedFromJSON(t, prerequisiteJSON)
	if got := ta.daemon.status.ManagedOff(); got != sandboxapi.ManagedOffUnavailable {
		t.Fatalf("the raw status is kind %d, want the install reason", got)
	}
	ta.Cfg.Guardrail.Connector = primary
	g := &gatewayViewFake{view: managedExplainFixture()}
	g.view.Allowed = false
	ta.ManagedAccountPolicy = g.policy
	return ta, g
}

func statusReason(t *testing.T, ta *testApp) string {
	t.Helper()
	ta.out.Reset()
	if err := ta.Status(bg, "", OutputJSON); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(ta.out.Bytes(), &got); err != nil {
		t.Fatalf("status --json: %v\n%s", err, ta.out.String())
	}
	return got.Reason
}

// `sandbox status` and `sandbox activity -f` ask the gateway for the view of
// the configured primary connector: the gateway answers no view for an empty
// connector, so asking for none never merged the profile's refusal
// (GAP-2059). `sandbox run` asks for its own agent's.
func TestAccountViewIsAskedForAConnectorTheGatewayKnows(t *testing.T) {
	withManagedHost(t)
	ta, g := profileRefusedFixture(t, "codex")
	if reason := statusReason(t, ta); !strings.Contains(reason, profilePhrase) || strings.Contains(reason, installPhrase) {
		t.Errorf("status --json reason = %q, want the profile's refusal", reason)
	}
	if got := g.connectors(); got != "codex" {
		t.Errorf("status asked the gateway for %q, want its primary connector codex", got)
	}
	var off *DisabledError
	if err := ta.Activity(bg, ActivityOptions{Follow: true}); !errors.As(err, &off) || !strings.Contains(off.Message, profilePhrase) {
		t.Errorf("activity -f = %v, want a refusal that names the profile", err)
	}
	if err := ta.Run(bg, RunOptions{Harness: "claude"}); err == nil || !strings.Contains(err.Error(), profilePhrase) {
		t.Errorf("run = %v, want the profile's refusal", err)
	}
	if got := g.connectors(); !strings.HasSuffix(got, ",claudecode") {
		t.Errorf("run asked the gateway for %q, want its own agent (claudecode) last", got)
	}
}

// GAP-2068: `sandbox status --output json` named the account's reason at the
// top (reason) and kept the daemon's install text in managed.unavailable
// beside it, so a script reading that field got the wrong reason. The
// managed object agrees with the reason: it carries the organization's text
// for an organization-off account, and the profile's refusal (never "", which
// means sandboxes can run) with no install recovery step for a profile deny.
// It does so for a daemon that has not settled its view of the account and
// for one that has (it sets AccountDenied itself). The keys stay the same,
// so the schema holds.
func TestStatusJSONManagedUnavailableAgreesWithTheAccountReason(t *testing.T) {
	withManagedHost(t)
	read := func(t *testing.T, ta *testApp) (reason, unavailable, recovery string) {
		t.Helper()
		ta.out.Reset()
		if err := ta.Status(bg, "", OutputJSON); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Reason  string `json:"reason"`
			Managed struct {
				Unavailable string `json:"unavailable"`
				Recovery    string `json:"recovery"`
			} `json:"managed"`
		}
		if err := json.Unmarshal(ta.out.Bytes(), &got); err != nil {
			t.Fatalf("status --json: %v\n%s", err, ta.out.String())
		}
		return got.Reason, got.Managed.Unavailable, got.Managed.Recovery
	}
	t.Run("profile denies sandboxes", func(t *testing.T) {
		ta, _ := profileRefusedFixture(t, "claudecode")
		ta.daemon.status.Managed.Recovery = "stop the OpenShell gateway and run the migration"
		reason, unavailable, recovery := read(t, ta)
		if !strings.Contains(reason, profilePhrase) {
			t.Fatalf("reason = %q, want the profile's refusal", reason)
		}
		if unavailable != sandboxapi.AccountNotAllowedReason || recovery != "" {
			t.Errorf("managed.unavailable = %q, managed.recovery = %q; want the profile's refusal and no install recovery next to reason %q", unavailable, recovery, reason)
		}
	})
	// A daemon that has settled its view of the account sets AccountDenied
	// itself and still sends the install text (managedStatusFor), so
	// accountStatus returns early: the managed object still agrees (RV-111D).
	t.Run("settled daemon, profile denies sandboxes", func(t *testing.T) {
		ta, _ := profileRefusedFixture(t, "claudecode")
		ta.daemon.status.Managed.AccountDenied = true
		ta.daemon.status.Managed.Recovery = "stop the OpenShell gateway and run the migration"
		reason, unavailable, recovery := read(t, ta)
		if !strings.Contains(reason, profilePhrase) {
			t.Fatalf("reason = %q, want the profile's refusal", reason)
		}
		if unavailable != sandboxapi.AccountNotAllowedReason || recovery != "" {
			t.Errorf("managed.unavailable = %q, managed.recovery = %q; want the profile's refusal and no install recovery next to reason %q", unavailable, recovery, reason)
		}
	})
	t.Run("settled daemon, organization turned sandboxes off", func(t *testing.T) {
		ta, _ := profileRefusedFixture(t, "claudecode")
		ta.daemon.status.Managed.AccountDenied = true
		ta.daemon.status.Managed.Unavailable = sandboxapi.OrganizationOffReason
		ta.daemon.status.Managed.Recovery = "stop the OpenShell gateway and run the migration"
		reason, unavailable, recovery := read(t, ta)
		if !strings.Contains(reason, orgPhrase) || unavailable != sandboxapi.OrganizationOffReason || recovery != "" {
			t.Errorf("reason = %q, managed.unavailable = %q, managed.recovery = %q; want the organization's reason and no install recovery", reason, unavailable, recovery)
		}
	})
	t.Run("organization turned sandboxes off", func(t *testing.T) {
		ta, _ := profileRefusedFixture(t, "claudecode")
		ta.ManagedOrganizationOff = func(context.Context) bool { return true }
		reason, unavailable, _ := read(t, ta)
		if !strings.Contains(reason, orgPhrase) || !strings.Contains(unavailable, orgPhrase) || strings.Contains(unavailable, installPhrase) {
			t.Errorf("reason = %q, managed.unavailable = %q; want the organization's reason in both", reason, unavailable)
		}
	})
	t.Run("no verdict leaves the daemon status", func(t *testing.T) {
		ta, _ := profileRefusedFixture(t, "")
		_, unavailable, _ := read(t, ta)
		if !strings.Contains(unavailable, installPhrase) {
			t.Errorf("managed.unavailable = %q; want the daemon's install text while no account reason applies", unavailable)
		}
	})
}

// With no connector configured there is no view to ask for: the daemon's
// status stands, and the gateway is not asked for a view of no connector.
func TestAccountViewWithNoConnectorLeavesTheDaemonStatus(t *testing.T) {
	withManagedHost(t)
	ta, g := profileRefusedFixture(t, "")
	if reason := statusReason(t, ta); !strings.Contains(reason, installPhrase) || strings.Contains(reason, profilePhrase) {
		t.Errorf("status --json reason = %q, want the daemon's install reason", reason)
	}
	if got := g.connectors(); got != "" {
		t.Errorf("the gateway was asked for %q with no connector configured", got)
	}
}

// `sandbox activity -f` ends at once only for a reason that means no sandbox
// can run for the account. The install's reason does not: sandboxes that still
// run have a feed, which the follower shows (rv-111A).
func TestActivityFollowKeepsFollowingWhileOnlyTheInstallReasonShows(t *testing.T) {
	withManagedHost(t)
	ta, _ := launchAgentDoctorFixture(t, "", nil)
	ta.GOOS = "linux"
	ta.daemon.status.Enabled, ta.daemon.status.Available = true, false
	ta.daemon.status.Managed = managedFromJSON(t, prerequisiteJSON)
	if got := ta.daemon.status.ManagedOff(); got != sandboxapi.ManagedOffUnavailable {
		t.Fatalf("the status is kind %d, want the install reason", got)
	}
	ta.daemon.events = []sandboxapi.ActivityEvent{{Seq: 1, Epoch: "e1", Sandbox: "alpha", Kind: sandboxapi.ActivityEgressBlocked, Host: "evil.example"}}
	ta.daemon.hold = make(chan struct{})
	defer close(ta.daemon.hold)
	out := &lockedBuffer{}
	ta.IO.Out = out
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- ta.Activity(ctx, ActivityOptions{Follow: true, Output: OutputJSON}) }()
	deadline := time.After(2 * time.Second)
	for !strings.Contains(out.String(), "evil.example") {
		select {
		case err := <-done:
			t.Fatalf("activity -f ended with %v before following the feed of sandboxes that run", err)
		case <-deadline:
			t.Fatalf("activity -f showed no event of the running sandbox: %q", out.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done
}

// With the organization's switch off and the profile denying sandboxes, a
// daemon that has not settled names neither: `sandbox status` and `sandbox
// activity -f` say the organization's, as `sandbox run` does.
func TestAccountViewKeepsTheOrganizationsReasonFirst(t *testing.T) {
	withManagedHost(t)
	ta, _ := profileRefusedFixture(t, "claudecode")
	ta.ManagedOrganizationOff = func(context.Context) bool { return true }
	if reason := statusReason(t, ta); !strings.Contains(reason, orgPhrase) || strings.Contains(reason, profilePhrase) {
		t.Errorf("status --json reason = %q, want the organization's", reason)
	}
	var off *DisabledError
	if err := ta.Activity(bg, ActivityOptions{Follow: true}); !errors.As(err, &off) || !strings.Contains(off.Message, orgPhrase) {
		t.Errorf("activity -f = %v, want the organization's reason", err)
	}
	runErr := ta.Run(bg, RunOptions{Harness: "claude"})
	if !errors.As(runErr, &off) || !strings.Contains(off.Message, orgPhrase) {
		t.Errorf("run = %v, want the organization's reason", runErr)
	}
}

// The gateway call runs on the command's context: Ctrl-C ends it, where it
// ran detached with a 5 s limit.
func TestAccountViewIsAskedOnTheCommandsContext(t *testing.T) {
	withManagedHost(t)
	ta, _ := profileRefusedFixture(t, "claudecode")
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	var seen error
	ta.ManagedAccountPolicy = func(c context.Context, _ string) (*sandboxapi.ManagedExplain, error) {
		cancel() // Ctrl-C while the gateway call is out
		seen = c.Err()
		return nil, c.Err()
	}
	if err := ta.Status(ctx, "", OutputJSON); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(seen, context.Canceled) {
		t.Errorf("the gateway call's context after Ctrl-C: %v, want canceled", seen)
	}
}
