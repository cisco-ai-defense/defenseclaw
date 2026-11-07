// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// systemAliasEvidence rewrites the hook client evidence the way a macOS
// client writes it: /etc, /var and /tmp are links into /private, so the
// client lists each file under them with its physical name.
func systemAliasEvidence(t *testing.T, evidence string) string {
	t.Helper()
	targets, ok := hookpaths.Decode(evidence)
	if !ok {
		t.Fatalf("hook evidence %q is not readable", evidence)
	}
	for operand, resolved := range targets {
		if operand != resolved {
			continue
		}
		for _, alias := range []string{"/etc/", "/var/", "/tmp/"} {
			if strings.HasPrefix(operand, alias) {
				targets[operand] = "/private" + resolved
			}
		}
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// TestFileToolOnASystemLinkKeepsItsContentRule pins GAP-0819: a whole-file
// write under a system path that is itself a link (/etc on macOS) keeps the
// verdict the same call gets where the path is its own file. The file the
// link reaches is one more spelling of the operand, so it does not break
// the exact proof of the content rule or read as an operand the client
// left out. Benign writes through the same links stay allowed.
func TestFileToolOnASystemLinkKeepsItsContentRule(t *testing.T) {
	home, project := hermesPatchHome(t)
	const preload = "# logger\nexport LD_PRELOAD=/usr/local/lib/liblogger.so\n"
	pad := strings.Repeat(" ", 70000)
	for _, c := range []struct {
		name, target, content, rule string
	}{
		{"docker insecure registry", "/etc/docker/daemon.json", overLimitDockerHTTPRegistry, dockerInsecureHTTPRegistryRuleID},
		{"docker insecure registry over the limit", "/etc/docker/daemon.json", overLimitDockerHTTPRegistry + pad, dockerInsecureHTTPRegistryRuleID},
		{"global preload", "/etc/profile.d/logger.sh", preload, "persistence.global_ld_preload_install"},
		{"benign daemon settings", "/etc/docker/daemon.json", `{"log-level":"warn"}`, ""},
		{"benign profile fragment", "/etc/profile.d/colors.sh", "export CLICOLOR=1\n", ""},
		{"project file", filepath.Join(project, "notes.txt"), preload, ""},
	} {
		for _, link := range []bool{false, true} {
			t.Run(c.name+"/link="+map[bool]string{false: "no", true: "yes"}[link], func(t *testing.T) {
				call := nativeWriteCall{"claudecode", "Write", func(path string) map[string]any {
					return map[string]any{"file_path": path, "content": c.content}
				}}
				body := call.body(t, project, c.target)
				evidence := hookpaths.ResolveConnector("claudecode", "", "preToolUse", []byte(body))
				if link {
					evidence = systemAliasEvidence(t, evidence)
				}
				got := overLimitHostHookWithEvidence(t, "claudecode", home, body, evidence)
				action := overLimitHookAction(t, got)
				if c.rule == "" {
					if action == "block" {
						t.Fatalf("benign write action = %q, want it not blocked: %.600s", action, got)
					}
					return
				}
				if action != "block" || !strings.Contains(got, c.rule) {
					t.Fatalf("action = %q, want block by %s: %.600s", action, c.rule, got)
				}
			})
		}
	}
}

// TestOverLimitPatchOnASystemLinkKeepsItsVerdict pins that a Codex patch
// padded past the argument limit keeps the verdict of the same patch at
// normal size when the client lists its file by the physical name of a
// system link (GAP-0819).
func TestOverLimitPatchOnASystemLinkKeepsItsVerdict(t *testing.T) {
	home, project := hermesPatchHome(t)
	verdict := func(body string) string {
		call := nativeWriteCall{"codex", "apply_patch", func(string) map[string]any {
			return map[string]any{"command": "*** Begin Patch\n*** Add File: /etc/docker/daemon.json\n+" + body + "\n*** End Patch\n"}
		}}
		hook := call.body(t, project, "/etc/docker/daemon.json")
		evidence := systemAliasEvidence(t, hookpaths.ResolveConnector("codex", "", "preToolUse", []byte(hook)))
		return overLimitHookAction(t, overLimitHostHookWithEvidence(t, "codex", home, hook, evidence))
	}
	small := verdict(overLimitDockerHTTPRegistry)
	if padded := verdict(overLimitDockerHTTPRegistry + strings.Repeat(" ", 70000)); padded != small {
		t.Fatalf("padded verdict %q, small %q", padded, small)
	}
}
