// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows name POSIX system paths (/etc).

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

// linkEvidence is the hook client evidence of body with the link the call
// names resolved to the physical file, as the client reports an existing link.
func linkEvidence(t *testing.T, body, link, physical string) string {
	t.Helper()
	targets, ok := hookpaths.Decode(hookpaths.Resolve([]byte(body)))
	if !ok {
		t.Fatalf("hook evidence of %.200s is not readable", body)
	}
	targets[link] = physical
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// TestContentRulesJudgeAWriteThroughALinkLikeTheProtectedName pins that the
// code-owned content rules (global loader injection, PAM bypass, Docker
// insecure registry) give a write through a link the client resolved to the
// protected file the verdict the write by the protected name gets, and that
// the ordinary text of the same files stays allowed.
func TestContentRulesJudgeAWriteThroughALinkLikeTheProtectedName(t *testing.T) {
	home, project := hermesPatchHome(t)
	const (
		preloadRule = "persistence.global_ld_preload_install"
		pamRule     = "tamper.pam_permit_authentication_bypass"
	)
	pamEdit := func(link, newText string) map[string]any {
		return map[string]any{"file_path": link, "old_string": "account    required     pam_nologin.so", "new_string": newText}
	}
	insecure := "{\"insecure-registries\":[\"http://registry.example.test:5000\"]}\n"
	for _, c := range []struct {
		name, connector, tool, physical, rule string
		args                                  func(link string) map[string]any
		blocked                               bool
	}{
		{"profile fragment write", "claudecode", "Write", "/etc/profile.d/gawk.sh", preloadRule, func(l string) map[string]any {
			return map[string]any{"file_path": l, "content": "export LD_PRELOAD=/usr/local/lib/libreview.so\n"}
		}, true},
		{"profile fragment benign", "claudecode", "Write", "/etc/profile.d/gawk.sh", preloadRule, func(l string) map[string]any {
			return map[string]any{"file_path": l, "content": "export CLICOLOR=1\n"}
		}, false},
		{"preload file write", "claudecode", "Write", "/etc/ld.so.preload", preloadRule, func(l string) map[string]any {
			return map[string]any{"file_path": l, "content": "/usr/local/lib/libreview.so\n"}
		}, true},
		{"preload file comment", "claudecode", "Write", "/etc/ld.so.preload", preloadRule, func(l string) map[string]any {
			return map[string]any{"file_path": l, "content": "# no libraries\n"}
		}, false},
		{"pam edit without replace_all", "claudecode", "Edit", "/etc/pam.d/sshd", pamRule, func(l string) map[string]any {
			return pamEdit(l, "auth sufficient pam_permit.so\naccount    required     pam_nologin.so")
		}, true},
		{"pam edit of a comment", "claudecode", "Edit", "/etc/pam.d/sshd", pamRule, func(l string) map[string]any {
			args := pamEdit(l, "# kept\n")
			args["old_string"] = "# old"
			return args
		}, false},
		{"docker write", "claudecode", "Write", "/etc/docker/daemon.json", dockerInsecureHTTPRegistryRuleID, func(l string) map[string]any {
			return map[string]any{"file_path": l, "content": insecure}
		}, true},
		{"docker benign document", "claudecode", "Write", "/etc/docker/daemon.json", dockerInsecureHTTPRegistryRuleID, func(l string) map[string]any {
			return map[string]any{"file_path": l, "content": "{\"log-level\":\"warn\"}\n"}
		}, false},
		{"docker write_file path", "hermes", "write_file", "/etc/docker/daemon.json", dockerInsecureHTTPRegistryRuleID, func(l string) map[string]any {
			return map[string]any{"path": l, "content": insecure}
		}, true},
		{"docker write_file file_path", "hermes", "write_file", "/etc/docker/daemon.json", dockerInsecureHTTPRegistryRuleID, func(l string) map[string]any {
			return map[string]any{"file_path": l, "content": insecure}
		}, true},
		{"docker write_file benign", "hermes", "write_file", "/etc/docker/daemon.json", dockerInsecureHTTPRegistryRuleID, func(l string) map[string]any {
			return map[string]any{"file_path": l, "content": "{\"log-level\":\"warn\"}\n"}
		}, false},
	} {
		for _, linked := range []bool{false, true} {
			t.Run(c.name+"/linked="+map[bool]string{false: "no", true: "yes"}[linked], func(t *testing.T) {
				target, link := c.physical, filepath.Join(project, "named-link")
				if linked {
					target = link
				}
				wrap := sudoersClaudeCall
				if c.connector == "hermes" {
					wrap = sudoersHermesCall
				}
				body := string(mustJSON(t, wrap(c.tool, sudoersFixed(c.args(target)))(project)))
				evidence := hookpaths.Resolve([]byte(body))
				if linked {
					evidence = linkEvidence(t, body, link, c.physical)
				}
				got := overLimitHostHookWithEvidence(t, c.connector, home, body, evidence)
				blocked := overLimitHookAction(t, got) == "block"
				if blocked != c.blocked || strings.Contains(got, c.rule) != c.blocked {
					t.Fatalf("blocked=%t, want %t by %s: %.600s", blocked, c.blocked, c.rule, got)
				}
			})
		}
	}
}
