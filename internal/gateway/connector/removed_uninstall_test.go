// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Review fixes (uninstall lifecycle round b): an uninstall ran only the
// teardown a gateway start runs, so a 1.0.2/1.0.3 OmniGent config.yaml still
// imported DefenseClaw's policy module (the stub that denies every request)
// and an OpenHands hooks.json still ran the stub that blocks every call: a
// removed DefenseClaw kept blocking the agent. The uninstall step now removes
// every entry an older setup wrote, the stub and OmniGent's import path, and
// keeps everything that is not DefenseClaw's.

func readRemovedTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// removedJSONString is s as a JSON string: a Windows path holds backslashes.
func removedJSONString(t *testing.T, s string) string {
	t.Helper()
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func requireRemovedGone(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s is still there after the uninstall: %v", path, err)
	}
}

// uninstallRemoved runs what an uninstall runs: the teardown, then the
// uninstall step.
func uninstallRemoved(t *testing.T, c removedOnlyConnector, opts SetupOpts) {
	t.Helper()
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("%s teardown: %v", c.name, err)
	}
	if ok, err := UninstallRemovedConnector(c.name, opts); !ok || err != nil {
		t.Fatalf("UninstallRemovedConnector(%s) = %v, %v", c.name, ok, err)
	}
}

func TestUninstallRemovesTheRemovedConnectorsPolicyFromTheAgent(t *testing.T) {
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name, func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			if c.name == removedOpenHandsID {
				// What setup wrote, as valid JSON on every OS.
				writeRemovedFile(t, h.agentConfig, `{"pre_tool_use":[{"matcher":"*","hooks":[{"type":"command","command":"/usr/local/bin/audit-hook"}]},`+
					`{"matcher":"*","hooks":[{"type":"command","command":`+removedJSONString(t, h.script(c))+`,"timeout":60}]}]}`, 0o600)
			}
			codexConfig := filepath.Join(h.home, ".codex", "config.toml")
			codexScript := filepath.Join(h.dataDir, "hooks", "codex-hook.sh")
			codexBefore := readRemovedTestFile(t, codexConfig) + readRemovedTestFile(t, codexScript)

			uninstallRemoved(t, c, h.opts)

			config := readRemovedTestFile(t, h.agentConfig)
			if names, err := c.configNames([]byte(config)); names || err != nil {
				t.Fatalf("%s still names DefenseClaw's %s after the uninstall (err=%v):\n%s", h.agentConfig, c.script, err, config)
			}
			operator := "/usr/local/bin/audit-hook"
			if c.name == removedOmnigentID {
				operator = "corp_policy"
			}
			if !strings.Contains(config, operator) {
				t.Fatalf("the uninstall removed the operator's %s from %s:\n%s", operator, h.agentConfig, config)
			}
			requireRemovedGone(t, h.script(c))
			if c.name == removedOmnigentID {
				requireRemovedGone(t, h.pth)
			}
			leftovers := c.leftovers(h.opts)
			for _, path := range []string{h.agentConfig, h.script(c), h.pth} {
				if path != "" && removedListsPath(leftovers, path) {
					t.Fatalf("the uninstall still lists %s: %+v", path, leftovers)
				}
			}
			if err := c.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean after the uninstall: %v", err)
			}
			if got := readRemovedTestFile(t, codexConfig) + readRemovedTestFile(t, codexScript); got != codexBefore {
				t.Fatalf("the uninstall changed the surviving connector's files")
			}
			// A later teardown (a retried uninstall, a start) writes no stub
			// back: nothing runs or imports it.
			uninstallRemoved(t, c, h.opts)
			requireRemovedGone(t, h.script(c))
			if err := c.VerifyClean(h.opts); err != nil {
				t.Fatalf("VerifyClean after a second uninstall: %v", err)
			}
		})
	}
}

func TestUninstallRemovesEveryShapeOfDefenseClawsEntries(t *testing.T) {
	t.Run("omnigent policy without a module entry, comments and other policies kept", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, removedOmnigent)
		writeRemovedFile(t, h.agentConfig, "# my settings\npolicy_modules: corp_policy\npolicies:\n  corp:\n    handler: corp_policy.check\n"+
			"  "+removedOmnigentPolicyKey+":\n    type: function\n    handler: "+removedOmnigentModuleName+".defenseclaw_policy\n", 0o600)
		uninstallRemoved(t, removedOmnigent, h.opts)
		config := readRemovedTestFile(t, h.agentConfig)
		if strings.Contains(config, removedOmnigentModuleName) || !strings.Contains(config, "corp_policy.check") || !strings.Contains(config, "# my settings") {
			t.Fatalf("config after the uninstall:\n%s", config)
		}
		requireRemovedGone(t, h.script(removedOmnigent))
	})
	t.Run("omnigent import path with other lines keeps them", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, removedOmnigent)
		other := filepath.Join(h.home, "corp-lib")
		writeRemovedFile(t, h.pth, other+"\n"+filepath.Join(h.dataDir, "hooks")+"\n", 0o600)
		uninstallRemoved(t, removedOmnigent, h.opts)
		if got := readRemovedTestFile(t, h.pth); strings.Contains(got, filepath.Join(h.dataDir, "hooks")) || !strings.Contains(got, other) {
			t.Fatalf("import path after the uninstall = %q", got)
		}
	})
	t.Run("openhands native launcher hook", func(t *testing.T) {
		h := newRemovedHost(t)
		h.stage(t, removedOpenHands)
		writeRemovedFile(t, h.agentConfig, `{"pre_tool_use":[{"matcher":"*","hooks":[`+
			`{"type":"command","command":"\"C:\\Program Files\\DefenseClaw\\defenseclaw-hook.exe\" --connector openhands"},`+
			`{"type":"command","command":"/usr/local/bin/audit-hook"}]}],`+
			`"stop":[{"matcher":"*","hooks":[{"type":"command","command":`+removedJSONString(t, h.script(removedOpenHands))+`}]}]}`, 0o600)
		uninstallRemoved(t, removedOpenHands, h.opts)
		config := readRemovedTestFile(t, h.agentConfig)
		if names, _ := removedOpenHands.configNames([]byte(config)); names || !strings.Contains(config, "/usr/local/bin/audit-hook") || strings.Contains(config, `"stop"`) {
			t.Fatalf("hooks.json after the uninstall:\n%s", config)
		}
		requireRemovedGone(t, h.script(removedOpenHands))
	})
	for _, c := range removedConnectorsUnderTest() {
		t.Run(c.name+" config that cannot be parsed keeps the stub and is listed", func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, c)
			broken := "policy_modules: [" + removedOmnigentModuleName + "\n"
			if c.name == removedOpenHandsID {
				broken = `{"pre_tool_use":[{"command":` + removedJSONString(t, h.script(c)) + `}`
			}
			writeRemovedFile(t, h.agentConfig, broken, 0o600)
			uninstallRemoved(t, c, h.opts)
			if got := readRemovedTestFile(t, h.agentConfig); got != broken {
				t.Fatalf("the uninstall changed a config it cannot parse: %q", got)
			}
			h.requireStub(t, c)
			if !removedListsPath(c.leftovers(h.opts), h.agentConfig) {
				t.Fatalf("the config that still names %s is not listed", c.script)
			}
		})
	}
	if ok, err := UninstallRemovedConnector("codex", SetupOpts{DataDir: t.TempDir()}); ok || err != nil {
		t.Fatalf("UninstallRemovedConnector(codex) = %v, %v; want not a removed connector", ok, err)
	}
}
