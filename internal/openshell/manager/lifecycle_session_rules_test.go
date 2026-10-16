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
	"errors"
	"strings"
	"testing"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// sessionRuleStart stops managed sandbox name holding a rule the person
// approved in its session, then starts it while the gateway refuses both
// tries to remove that rule; it returns the start's refusal and the rule.
func sessionRuleStart(t *testing.T, name string, stopFails bool) (*harnessEnv, *sandboxapi.Error, string) {
	t.Helper()
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	e.live(sandboxapi.CreateRequest{Name: name})
	e.register(name)
	host := "session.example.org"
	e.propose(name, host)
	e.draft(name)
	asks := e.waitAsks(name, 1)
	must(t, e.decide(asks[0].ID, sandboxapi.ApprovalDecision{Decision: "approve"}))
	rule := ruleFor(host)
	eventually(t, "the approved rule "+rule, func() bool {
		return e.approvedRules(name)[rule] == actorOperator && e.hasRule(name, rule)
	})
	e.waitAsks(name, 0)
	e.stopBox(name)

	busy := &types.StatusError{Code: types.ErrorUnavailable, Message: "policy store busy"}
	before := e.fake.Calls(openshelltest.MethodUpdateConfig)
	e.fake.FailNext(openshelltest.MethodUpdateConfig, busy)
	e.fake.FailNext(openshelltest.MethodUpdateConfig, busy)
	if stopFails {
		e.fake.FailNext(openshelltest.MethodStopSandbox, &types.StatusError{Code: types.ErrorInternal, Message: "driver busy"})
	}
	_, err := e.m.Start(t.Context(), name, sandboxapi.StartRequest{})
	if got := e.fake.Calls(openshelltest.MethodUpdateConfig) - before; got != 2 {
		t.Fatalf("policy updates during the start = %d, want the two removal tries", got)
	}
	var apiErr *sandboxapi.Error
	if !errors.As(err, &apiErr) {
		t.Fatalf("start with the last session's rule still in the policy = %v, want a refusal", err)
	}
	for _, raw := range []string{"policy store busy", "driver busy"} {
		if strings.Contains(err.Error(), raw) {
			t.Fatalf("refusal shows the gateway's raw error: %q", err.Error())
		}
	}
	if e.approvedRules(name)[rule] != actorOperator {
		t.Fatal("the record forgot the rule that is still in the policy")
	}
	return e, apiErr, rule
}

// A managed start whose two tries to remove the rule approved for the last
// session both fail (before the start and once the sandbox runs) does not
// leave the new session running with that rule: the start stops the
// sandbox again and names the rule; the next start removes it
// (rel-1-0-2:GAP-0014, LF-LEAD P2-2).
func TestManagedStartStopsWhenTheLastSessionRuleCannotBeRemoved(t *testing.T) {
	e, apiErr, rule := sessionRuleStart(t, "srfail", false)
	if !strings.Contains(apiErr.Message, rule) || !strings.Contains(apiErr.Message, "stopped it again") {
		t.Fatalf("refusal = %q, want it to name %s and say the sandbox was stopped", apiErr.Message, rule)
	}
	if phase := e.get("srfail").Phase; phase != "stopped" {
		t.Fatalf("sandbox phase after the refused start = %q, want stopped", phase)
	}

	e.startBox("srfail", sandboxapi.StartRequest{})
	if e.hasRule("srfail", rule) {
		t.Fatal("the next start kept the last session's rule")
	}
}

// When stopping it again fails too, the sandbox still runs with the last
// session's rule: the refusal says so, never that it was stopped, and names
// the stop that ends it; after that stop the next start removes the rule
// (rel-1-0-2:GAP-0014 fix-up).
func TestManagedStartSaysTheSandboxStillRunsWithTheRuleWhenItCannotBeStopped(t *testing.T) {
	e, apiErr, rule := sessionRuleStart(t, "srkeep", true)
	if phase := e.get("srkeep").Phase; phase == "stopped" {
		t.Fatal("the fake gateway stopped the sandbox although its stop failed")
	}
	if !e.hasRule("srkeep", rule) {
		t.Fatalf("the running sandbox lost %s: the stop failure was not reproduced", rule)
	}
	if strings.Contains(apiErr.Message, "stopped") || strings.Contains(apiErr.Message, "did not start") {
		t.Fatalf("refusal = %q, claims the sandbox was stopped", apiErr.Message)
	}
	if !strings.Contains(apiErr.Message, "still running with the network rule "+rule) {
		t.Fatalf("refusal = %q, want it to say the sandbox still runs with %s", apiErr.Message, rule)
	}
	if !strings.Contains(apiErr.Detail, "`defenseclaw sandbox stop srkeep`, then start it again") {
		t.Fatalf("refusal detail = %q, want the stop that ends it", apiErr.Detail)
	}

	e.stopBox("srkeep")
	e.startBox("srkeep", sandboxapi.StartRequest{})
	if e.hasRule("srkeep", rule) {
		t.Fatal("the start after the stop kept the last session's rule")
	}
}
