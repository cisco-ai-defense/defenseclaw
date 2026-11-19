// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"slices"
	"testing"
)

// rel-1-0-10:GAP-1179: every developer CLI and agent login file of the
// credentials-file table gets the hook verdict of its class, not only the
// shape match (TestMatchCredentialFileShapeDeveloperToolLogins). The reads
// are the cert110 L69 C25b table (TST-6064), run through the gateway's own
// Claude Code hook in action mode: the Claude Code login and podman's login
// in the home and in the runtime folder raised nothing at rel, because the
// table named them by a shorter Relative than the home-relative path.
func TestGAP1179DeveloperLoginFileReadsRaiseTheirFindingOnTheHookPath(t *testing.T) {
	installCorrelationHMACForTest(t)
	rows := []struct{ command, rule string }{
		{"cat ~/.config/git/credentials", "PATH-GIT-CREDS"},
		{"cat ~/.vault-token", "PATH-CRED-STORE-USER"},
		{"cat ~/.terraform.d/credentials.tfrc.json", "PATH-GIT-CREDS"},
		{"cat ~/.cargo/credentials.toml", "PATH-GIT-CREDS"},
		{"cat ~/.gem/credentials", "PATH-GIT-CREDS"},
		{"cat ~/.aws/sso/cache/x.json", "secrets.cloud_credential_read"},
		{"cat ~/.config/containers/auth.json", "PATH-DOCKER"},
		{"cat ~/.m2/settings-security.xml", "PATH-GIT-CREDS"},
		{"cat ~/.config/github-copilot/hosts.json", "secrets.cloud_credential_read"},
		{"head -c 0 ~/.claude/.credentials.json", "secrets.cloud_credential_read"},
		{"cat ~/.claude/.credentials.json", "secrets.cloud_credential_read"},
		{"head -c 0 ~/.codex/auth.json", "secrets.cloud_credential_read"},
		{"cat /run/user/1000/containers/auth.json", "PATH-DOCKER"},
		{"cat /home/bob/.config/containers/auth.json", "PATH-DOCKER"},
	}
	// Look-alikes that are no account's login file keep no finding of the
	// login rules.
	quiet := []string{
		"cat /run/user/x/containers/auth.json",
		"cat /run/user/1000/containers/policy.json",
		"cat /repo/testdata/.claude/.credentials.json",
		"cat ~/.config/containers/registries.conf",
	}
	for _, pack := range []string{"default", "strict"} {
		t.Run(pack, func(t *testing.T) {
			handler := hostClaudeHookHandlerForTest(t, pack)
			for i, row := range rows {
				ev := claudeToolEvent("PreToolUse", fmt.Sprintf("gap1179-%s-%d", pack, i), "read", row.command)
				ev["cwd"] = "/work"
				got := callAgentHookForTest(t, handler, ev)
				if !slices.Contains(got.RuleIDs, row.rule) || got.Action == "allow" {
					t.Errorf("%q: action %q rules %v, want %s to alert or block", row.command, got.Action, got.RuleIDs, row.rule)
				}
			}
			for i, command := range quiet {
				ev := claudeToolEvent("PreToolUse", fmt.Sprintf("gap1179q-%s-%d", pack, i), "read", command)
				ev["cwd"] = "/work"
				got := callAgentHookForTest(t, handler, ev)
				for _, rule := range []string{"PATH-DOCKER", "secrets.cloud_credential_read"} {
					if slices.Contains(got.RuleIDs, rule) {
						t.Errorf("%q: look-alike raised %s (action %q)", command, rule, got.Action)
					}
				}
			}
		})
	}
}

func TestMatchesRuntimeContainerAuthFile(t *testing.T) {
	for value, want := range map[string]bool{
		"/run/user/1000/containers/auth.json":               true,
		"/run/user/0/containers/auth.json":                  true,
		"/run/user/1000/containers/../containers/auth.json": true,
		"/run/user/x/containers/auth.json":                  false,
		"/run/user//containers/auth.json":                   false,
		"/run/user/1000/containers/policy.json":             false,
		"/run/user/1000/x/containers/auth.json":             false,
		"/var/run/user/1000/containers/auth.json":           false,
		"run/user/1000/containers/auth.json.example":        false,
	} {
		if got := matchesRuntimeContainerAuthFile(value); got != want {
			t.Errorf("matchesRuntimeContainerAuthFile(%q) = %t, want %t", value, got, want)
		}
	}
}
