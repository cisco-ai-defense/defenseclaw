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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
)

// approvedRule creates a ready sandbox with one approved triaged rule to
// host and returns the sandbox name and the rule.
func approvedRule(t *testing.T, e *harnessEnv, name, host string) string {
	t.Helper()
	rule := "allow_" + ruleToken(host) + "_443"
	sb := e.create(sandboxapi.CreateRequest{Name: name})
	e.watch.waitStarted(t, sb.Name)
	id := addChunk(e, sb.Name, chunk(rule, host, 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "approval applied", func() bool { return chunkStatus(e, sb.Name, id) == "approved" })
	return rule
}

func ruleToken(host string) string {
	out := []byte(host)
	for i, c := range out {
		if c == '.' || c == '-' {
			out[i] = '_'
		}
	}
	return string(out)
}

func hasRule(e *harnessEnv, sandbox, rule string) bool {
	policy, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sandbox)
	_, ok := policy.NetworkPolicies[rule]
	return ok
}

// TestBlockListRemovesApprovedRules pins that a destination the user adds
// to the block list loses the approved direct rules it already has: they
// bypass the proxy that now blocks it. Rules to other destinations stay.
func TestBlockListRemovesApprovedRules(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	drop := approvedRule(t, e, "blkbox", "drop.example.org")
	id := addChunk(e, "blkbox", chunk("allow_keep_example_org_443", "keep.example.org", 443))
	e.watch.push(t, "blkbox", stream.Event{Kind: stream.KindDraft})
	eventually(t, "second approval applied", func() bool { return chunkStatus(e, "blkbox", id) == "approved" })

	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"drop.example.org"} })
	e.m.enforceAll(context.Background())
	if hasRule(e, "blkbox", drop) {
		t.Fatal("the rule to the blocked destination is still in the policy")
	}
	if !hasRule(e, "blkbox", "allow_keep_example_org_443") {
		t.Fatal("a rule to another destination was removed")
	}
	var recorded bool
	e.tel.mu.Lock()
	for _, p := range e.tel.policy {
		recorded = recorded || (p.Operation == audit.SandboxPolicyRuleRemove && p.Target == drop && p.Reason == policyReasonBlocklist)
	}
	e.tel.mu.Unlock()
	if !recorded {
		t.Fatal("no rule_remove record for the blocked destination")
	}
}

// TestConfigChangeIsEnforcedAfterAnEgressRefresh pins that an
// administrator's tightening reaches approved rules even when a create or
// delete rebuilt the egress deciders from the new configuration before
// the config loop saw it.
func TestConfigChangeIsEnforcedAfterAnEgressRefresh(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	rule := approvedRule(t, e, "cfgbox", "gone.example.org")
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"gone.example.org"} })
	// A create or delete finishing first refreshes the deciders.
	e.m.refreshEgress()
	deadline := time.Now().Add(6 * time.Second)
	for hasRule(e, "cfgbox", rule) {
		if time.Now().After(deadline) {
			t.Fatal("the admin-blocked rule survived the configuration change")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
