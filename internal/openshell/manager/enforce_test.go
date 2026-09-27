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
	"testing"
	"time"

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
