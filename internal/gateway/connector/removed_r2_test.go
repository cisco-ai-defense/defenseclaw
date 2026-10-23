// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

// until 1.1: review fixes (G-deadcode loop round 2) for the teardown-only
// OpenHands and OmniGent connectors (removed.go). Delete with that file.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An agent config is read for its decoded values, so a name written with
// JSON or YAML escapes, another spelling of the launcher's connector flag, or
// another case is listed; a file that cannot be checked is listed for a
// check by hand; a config that does not name the hook is not.
func TestRemovedConnectorLeftoversReadDecodedConfigs(t *testing.T) {
	cases := []struct {
		connector, name, body string
		listed, byHand        bool
	}{
		{removedOpenHandsID, "a JSON escape in the script name", `{"pre_tool_use":[{"hooks":[{"command":"/h/.defenseclaw/hooks/openhands\u002dhook.sh"}]}]}`, true, false},
		{removedOpenHandsID, "every letter escaped", `{"pre_tool_use":[{"hooks":[{"command":"\u006f\u0070\u0065\u006e\u0068\u0061\u006e\u0064\u0073-hook.sh"}]}]}`, true, false},
		{removedOpenHandsID, "the script name in another case", `{"pre_tool_use":[{"hooks":[{"command":"C:/dc/OpenHands-Hook.SH"}]}]}`, true, false},
		{removedOpenHandsID, "--connector=openhands", `{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook --connector=openhands"}]}]}`, true, false},
		{removedOpenHandsID, "a quoted connector", `{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook --connector \"openhands\""}]}]}`, true, false},
		{removedOpenHandsID, "an escaped flag", `{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook \u002d\u002dconnector open-hands"}]}]}`, true, false},
		{removedOpenHandsID, "a tab and upper case", `{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook --connector\tOpenHands"}]}]}`, true, false},
		{removedOpenHandsID, "a byte order mark", "\xef\xbb\xbf" + `{"pre_tool_use":[{"hooks":[{"command":"openhands\u002dhook.sh"}]}]}`, true, false},
		{removedOpenHandsID, "not JSON", `{"pre_tool_use": [`, false, true},
		{removedOpenHandsID, "another hook only", removedOpenHandsOperatorHooks, false, false},
		{removedOpenHandsID, "another connector of the launcher", `{"pre_tool_use":[{"hooks":[{"command":"defenseclaw-hook.exe hook --connector opencode"}]}]}`, false, false},
		{removedOpenHandsID, "an empty file", "  \n", false, false},
		{removedOmnigentID, "a YAML hex escape", "policy_modules: [\"defenseclaw_omnigent_polic\\x79\"]\n", true, false},
		{removedOmnigentID, "a YAML unicode escape", "policy_modules:\n  - \"\\u0064efenseclaw_omnigent_policy\"\n", true, false},
		{removedOmnigentID, "a handler through an alias", "x: &h \"defenseclaw_omnigent_polic\\x79.defenseclaw_policy\"\npolicies:\n  g:\n    handler: *h\n", true, false},
		{removedOmnigentID, "a folded key", "policies:\n  ? \"defenseclaw_omnigent_polic\\x79\"\n  : {}\n", true, false},
		{removedOmnigentID, "not YAML", "policy_modules: [\n", false, true},
		{removedOmnigentID, "another module only", removedOmnigentOperatorConfig, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.connector+"/"+tc.name, func(t *testing.T) {
			h := newRemovedHost(t)
			c, _ := removedConnectorFor(tc.connector)
			config := homePath(map[string]string{removedOpenHandsID: ".openhands", removedOmnigentID: ".omnigent"}[tc.connector],
				map[string]string{removedOpenHandsID: "hooks.json", removedOmnigentID: "config.yaml"}[tc.connector])
			writeRemovedFile(t, config, tc.body, 0o600)
			leftovers, _ := RemovedConnectorLeftovers(c.name, h.opts)
			var item *RemovedLeftover
			for i := range leftovers {
				if leftovers[i].Path == config {
					item = &leftovers[i]
				}
			}
			switch {
			case tc.listed && (item == nil || item.Step != c.configStep):
				t.Fatalf("leftovers %+v do not list %s with its step", leftovers, config)
			case tc.byHand && (item == nil || !strings.HasPrefix(item.Step, "check it by hand: ") || !strings.Contains(item.What, "could not be checked")):
				t.Fatalf("leftovers %+v do not list %s for a check by hand", leftovers, config)
			case !tc.listed && !tc.byHand && item != nil:
				t.Fatalf("leftovers list %+v for a config that does not name the hook", *item)
			}
		})
	}
}

// With an explicit config home, the agent's default config is read too.
func TestRemovedConnectorLeftoversReadTheDefaultConfigBesideTheConfigHome(t *testing.T) {
	h := newRemovedHost(t)
	defaultConfig := homePath(".omnigent", "config.yaml")
	writeRemovedFile(t, defaultConfig, "policy_modules: ["+removedOmnigentModuleName+"]\n", 0o600)
	explicit := filepath.Join(h.home, "elsewhere", ".omnigent")
	writeRemovedFile(t, filepath.Join(explicit, "config.yaml"), "policy_modules: ["+removedOmnigentModuleName+"]\n", 0o600)
	opts := h.opts
	opts.ConfigHome = explicit
	leftovers, _ := RemovedConnectorLeftovers(removedOmnigentID, opts)
	for _, path := range []string{defaultConfig, filepath.Join(explicit, "config.yaml")} {
		if !removedListsPath(leftovers, path) {
			t.Errorf("leftovers %+v do not name %s", leftovers, path)
		}
	}
	hooks := homePath(".openhands", "hooks.json")
	writeRemovedFile(t, hooks, `{"pre_tool_use":[{"hooks":[{"command":"`+filepath.ToSlash(removedOpenHands.scriptPath(h.dataDir))+`"}]}]}`, 0o600)
	opts.ConfigHome = filepath.Join(h.home, "ws", ".openhands")
	if leftovers, _ := RemovedConnectorLeftovers(removedOpenHandsID, opts); !removedListsPath(leftovers, hooks) {
		t.Errorf("leftovers %+v do not name the default %s", leftovers, hooks)
	}
}

// OmniGent's import-path file is listed with a step that removes only
// DefenseClaw's line when it holds other import paths, and is not listed when
// it no longer holds that line.
func TestRemovedOmnigentPthStepKeepsOtherImportPaths(t *testing.T) {
	cases := []struct {
		name, body string
		listed     bool
		onlyLine   bool
	}{
		{name: "only DefenseClaw's line", body: "{hooks}\n", listed: true},
		{name: "only DefenseClaw's line, CRLF and a byte order mark", body: "\xef\xbb\xbf{hooks}\r\n", listed: true},
		{name: "DefenseClaw's line and a user path", body: "/opt/corp/lib\n{hooks}\n", listed: true, onlyLine: true},
		{name: "a user import line after it", body: "{hooks}\nimport corp_site\n", listed: true, onlyLine: true},
		{name: "a user path only", body: "/opt/corp/lib\n", listed: false},
		{name: "an empty file", body: "", listed: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRemovedHost(t)
			h.stage(t, removedOmnigent)
			hooks := filepath.Join(h.dataDir, "hooks")
			writeRemovedFile(t, h.pth, strings.ReplaceAll(tc.body, "{hooks}", hooks), 0o600)
			leftovers, _ := RemovedConnectorLeftovers(removedOmnigentID, h.opts)
			var item *RemovedLeftover
			for i := range leftovers {
				if leftovers[i].Path == h.pth {
					item = &leftovers[i]
				}
			}
			switch {
			case !tc.listed:
				if item != nil {
					t.Fatalf("a .pth without DefenseClaw's line is listed: %+v", *item)
				}
			case item == nil:
				t.Fatalf("leftovers %+v do not list %s", leftovers, h.pth)
			case tc.onlyLine:
				if !strings.HasPrefix(item.Step, "remove only the line "+hooks+" ") || strings.Contains(item.Step, "delete this file") {
					t.Fatalf("step %q would delete the user's import paths", item.Step)
				}
			default:
				if !strings.HasPrefix(item.Step, "delete this file once no OmniGent config.yaml names") {
					t.Fatalf("step %q, want delete this file", item.Step)
				}
			}
			// The teardown never changes it.
			before, _ := os.ReadFile(h.pth)
			conn, _ := RetiredConnector(removedOmnigentID)
			if err := conn.Teardown(context.Background(), h.opts); err != nil {
				t.Fatal(err)
			}
			if after, _ := os.ReadFile(h.pth); string(after) != string(before) {
				t.Fatalf("teardown changed %s: %q -> %q", h.pth, before, after)
			}
		})
	}
}

// The retired gateway routes are the paths every older hook posts to, and
// block with the removal reason the stubs give.
func TestRemovedConnectorHookPathsAndReasons(t *testing.T) {
	for path, want := range map[string]string{
		"/api/v1/openhands/hook": removedOpenHandsID,
		"/api/v1/omnigent/hook":  removedOmnigentID,
	} {
		if got, ok := RemovedConnectorForHookPath(path); !ok || got != want {
			t.Errorf("RemovedConnectorForHookPath(%q) = %q, %v", path, got, ok)
		}
		reason, ok := RemovedConnectorDenyReason(want)
		if !ok || !strings.Contains(reason, "support was removed in DefenseClaw 1.0.4") {
			t.Errorf("RemovedConnectorDenyReason(%q) = %q, %v", want, reason, ok)
		}
	}
	for _, path := range []string{"/api/v1/codex/hook", "/api/v1/opencode/hook", "/api/v1/openhands/hook/x", ""} {
		if got, ok := RemovedConnectorForHookPath(path); ok {
			t.Errorf("RemovedConnectorForHookPath(%q) = %q", path, got)
		}
	}
	if _, ok := RemovedConnectorDenyReason("codex"); ok {
		t.Error("codex has a removal reason")
	}
}
