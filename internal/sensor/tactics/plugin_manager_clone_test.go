// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import "testing"

// GAP-1448: the first run of Claude Code clones the official plugin
// marketplace under ~/.claude/plugins (a .staging copy first) and the files in
// it include .mcp.json and .npmrc. The plugin manager's own clone is not the
// agent rewriting its standing configuration or writing a credential store.
func TestPluginManagerCloneIsNotAgentConfigOrCredentialWrite(t *testing.T) {
	t.Parallel()
	cases := map[string][]string{
		"linux":   {"/home/dev"},
		"darwin":  {"/Users/dev"},
		"windows": {`C:\Users\dev`, `c:\users\dev`},
	}
	for goos, homes := range cases {
		indicators := IndicatorsFor(goos)
		for _, home := range homes {
			sep := "/"
			if goos == "windows" {
				sep = `\`
			}
			join := func(parts ...string) string {
				out := home
				for _, p := range parts {
					out += sep + p
				}
				return out
			}
			for _, path := range []string{
				join(".claude", "plugins", "marketplaces", "claude-plugins-official.staging", "plugins", "x", ".mcp.json"),
				join(".claude", "plugins", "marketplaces", "claude-plugins-official.staging", ".npmrc"),
				join(".claude", "plugins", "marketplaces", "claude-plugins-official", "external_plugins", "y", ".mcp.json"),
				join(".claude", "plugins", "cache", "claude-plugins-official", "z", "1.0.0", ".mcp.json"),
			} {
				for _, kind := range []string{KindFileWrite, KindFileRead} {
					if match, ok := Classify(Observation{Kind: kind, Path: path}, indicators); ok {
						t.Errorf("%s: %v of %s classified as %s/%s; the plugin manager's own clone must stay quiet", goos, kind, path, match.Tactic, match.SignalID)
					}
				}
			}
		}
	}
}

// The exemption is the clone folders only: the agent's own settings, the
// plugin registry beside them, a real secret and a .mcp.json outside the
// clone still count.
func TestPluginManagerCloneExemptionStaysNarrow(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin", "windows"} {
		indicators := IndicatorsFor(goos)
		home := "/home/dev"
		if goos == "darwin" {
			home = "/Users/dev"
		}
		if goos == "windows" {
			home = `C:\Users\dev`
		}
		for _, test := range []struct {
			name string
			obs  Observation
			want string
		}{
			{"settings", Observation{Kind: KindFileWrite, Path: home + "/.claude/settings.json"}, "agent_config_persistence"},
			{"project mcp", Observation{Kind: KindFileWrite, Path: home + "/proj/.mcp.json"}, "agent_config_persistence"},
			{"npmrc outside", Observation{Kind: KindFileWrite, Path: home + "/.npmrc"}, "agent_credential_access"},
			{"secret in clone", Observation{Kind: KindFileRead, Path: home + "/.claude/plugins/marketplaces/m/.aws/credentials"}, "agent_credential_access"},
		} {
			match, ok := Classify(test.obs, indicators)
			if !ok || match.SignalID != test.want {
				t.Errorf("%s/%s: got %v %q, want %s", goos, test.name, ok, match.SignalID, test.want)
			}
		}
	}
}
