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

package connector

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Review round 2 of the uninstall step. A valid agent config the uninstall
// could not clean (larger than the 16 MiB check limit, or naming DefenseClaw
// in a form it does not remove) was skipped while the uninstall reported
// success, so an --all uninstall then removed the stub the config still ran.
// A lost OmniGent import-path record left the .pth unlisted, and an OpenHands
// matcher group emptied of DefenseClaw's hook lost the operator's own fields.

// removedLargeConfig is c's agent config with DefenseClaw's entry and an
// operator entry, padded by an operator value past size bytes.
func removedLargeConfig(t *testing.T, h *removedHost, c removedOnlyConnector, size int) string {
	t.Helper()
	pad := strings.Repeat("x", size)
	if c.name == removedOmnigentID {
		return "policy_modules:\n  - corp_policy\n  - " + removedOmnigentModuleName + "\npolicies:\n  corp:\n    handler: corp_policy.check\n    note: " + pad +
			"\n  " + removedOmnigentPolicyKey + ":\n    handler: " + removedOmnigentModuleName + ".defenseclaw_policy\n"
	}
	return `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook","note":"` + pad + `"}]},` +
		`{"matcher":"*","hooks":[{"type":"command","command":` + removedJSONString(t, h.script(c)) + `}]}]}`
}

func TestUninstallCleansAValidConfigLargerThanTheCheckLimit(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name, func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			writeRemovedFile(t, h.agentConfig, removedLargeConfig(t, h, c, 17<<20), 0o600)
			uninstallRemoved(t, c, h.opts)
			config := readRemovedTestFile(t, h.agentConfig)
			if strings.Contains(config, c.script) || strings.Contains(config, removedOmnigentModuleName) {
				t.Fatalf("%s still names DefenseClaw's %s after the uninstall", h.agentConfig, c.script)
			}
			operator := "/usr/local/bin/audit-hook"
			if c.name == removedOmnigentID {
				operator = "corp_policy.check"
			}
			if !strings.Contains(config, operator) || len(config) < 17<<20 {
				t.Fatalf("the uninstall lost the operator's entries (%d bytes left)", len(config))
			}
			requireRemovedGone(t, h.script(c))
			// What the uninstall runs next accepts it: the verification, the
			// leftovers and a retried uninstall, which writes no stub back.
			if err := c.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean after the uninstall: %v", err)
			}
			if removedListsPath(c.leftovers(h.opts), h.agentConfig) {
				t.Fatalf("the uninstall still lists the cleaned %s", h.agentConfig)
			}
			uninstallRemoved(t, c, h.opts)
			requireRemovedGone(t, h.script(c))
		})
	}
}

func TestUninstallFailsWhileAValidConfigStillNamesDefenseClaw(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name+" too large to check", func(t *testing.T) {
			saved := removedConfigReadLimit
			removedConfigReadLimit = 1 << 20
			t.Cleanup(func() { removedConfigReadLimit = saved })
			h := newRemovedHost(t)
			h.stage(t, c)
			large := removedLargeConfig(t, h, c, 2<<20)
			writeRemovedFile(t, h.agentConfig, large, 0o600)
			requireRemovedUninstallFails(t, h, c, large)
		})
		t.Run(c.name+" in a form the uninstall does not remove", func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			kept := "policy_modules:\n  primary: " + removedOmnigentModuleName + "\n"
			if c.name == removedOpenHandsID {
				kept = `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","run":` + removedJSONString(t, h.script(c)) + `}]}]}`
			}
			writeRemovedFile(t, h.agentConfig, kept, 0o600)
			requireRemovedUninstallFails(t, h, c, kept)
		})
	}
	t.Run("a comment that names the module is not a registration", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, removedOmnigent)
		writeRemovedFile(t, h.agentConfig, "# was "+removedOmnigentModuleName+"\npolicy_modules:\n  - corp_policy\n  - "+removedOmnigentModuleName+"\n", 0o600)
		uninstallRemoved(t, removedOmnigent, h.opts)
		if got := readRemovedTestFile(t, h.agentConfig); !strings.Contains(got, "corp_policy") || strings.Contains(got, "- "+removedOmnigentModuleName) {
			t.Fatalf("config after the uninstall:\n%s", got)
		}
	})
}

// requireRemovedUninstallFails runs the teardown and the uninstall step and
// wants the step to fail with the config unchanged and the stub kept, so an
// uninstall removes no data.
func requireRemovedUninstallFails(t *testing.T, h *removedHost, c removedOnlyConnector, config string) {
	t.Helper()
	if err := c.Teardown(context.Background(), h.opts); err != nil {
		t.Fatalf("%s teardown: %v", c.name, err)
	}
	ok, err := UninstallRemovedConnector(c.name, h.opts)
	if !ok || err == nil || !strings.Contains(err.Error(), filepath.Base(h.agentConfig)) {
		t.Fatalf("UninstallRemovedConnector(%s) = %v, %v; want an error naming %s", c.name, ok, err, h.agentConfig)
	}
	if got := readRemovedTestFile(t, h.agentConfig); got != config {
		t.Fatalf("the failed uninstall changed %s", h.agentConfig)
	}
	h.requireStub(t, c)
}

func TestUninstallListsTheImportPathWhenItsRecordIsLost(t *testing.T) {
	h := newRemovedHost(t)
	h.stage(t, removedOmnigent)
	if err := os.Remove(managedFileBackupPath(h.dataDir, removedOmnigentID, "pth")); err != nil {
		t.Fatal(err)
	}
	uninstallRemoved(t, removedOmnigent, h.opts)
	for _, item := range removedOmnigent.leftovers(h.opts) {
		if item.Path == removedOmnigentPthName && strings.Contains(item.Step, "purelib") {
			return
		}
	}
	t.Fatalf("the uninstall does not list %s once its record is lost: %+v", removedOmnigentPthName, removedOmnigent.leftovers(h.opts))
}

func TestUninstallKeepsTheOperatorsFieldsOfAnEmptiedMatcherGroup(t *testing.T) {
	h := newRemovedHost(t)
	h.stage(t, removedOpenHands)
	writeRemovedFile(t, h.agentConfig, `{"pre_tool_use":[{"matcher":"Bash","description":"corp review","hooks":[{"type":"command","command":`+
		removedJSONString(t, h.script(removedOpenHands))+`}]},{"matcher":"*","hooks":[{"type":"command","command":`+
		removedJSONString(t, h.script(removedOpenHands))+`}]}],"stop":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]}]}`, 0o600)
	uninstallRemoved(t, removedOpenHands, h.opts)
	config := readRemovedTestFile(t, h.agentConfig)
	if names, _ := removedOpenHands.configNames([]byte(config)); names ||
		!strings.Contains(config, `"corp review"`) || !strings.Contains(config, `"Bash"`) || !strings.Contains(config, "/usr/local/bin/audit-hook") ||
		strings.Count(config, `"matcher"`) != 2 {
		t.Fatalf("hooks.json after the uninstall:\n%s", config)
	}
	requireRemovedGone(t, h.script(removedOpenHands))
}
