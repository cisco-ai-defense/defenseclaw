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

// managedPlacedEvidence is the hook client evidence of body with the operand
// as the client keys it in project (hookpaths.OperandPath) answered with the
// physical file, as the client reports an existing link, or no extra answer
// when physical is empty.
func managedPlacedEvidence(t *testing.T, body, project, operand, physical string) string {
	t.Helper()
	targets, ok := hookpaths.Decode(hookpaths.Resolve([]byte(body)))
	if !ok {
		t.Fatalf("hook evidence of %.200s is not readable", body)
	}
	if physical != "" {
		targets[hookpaths.OperandPath(operand, project)] = physical
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// TestManagedContentRulesPlaceARelativeFilePathLikeTheAbsoluteName pins that a
// managed gateway, which has no working directory of its own for a call in the
// home of the user, gives a relative or link-named file path the verdict the
// absolute name of the protected file gets: a link name and a dot-dot path to
// the loader preload file, a profile.d fragment, a PAM service and the Docker
// daemon file. Ordinary text and ordinary files stay allowed.
func TestManagedContentRulesPlaceARelativeFilePathLikeTheAbsoluteName(t *testing.T) {
	home, project := hermesPatchHome(t)
	const (
		preloadRule = "persistence.global_ld_preload_install"
		pamRule     = "tamper.pam_permit_authentication_bypass"
		library     = "/usr/local/lib/libreview.so\n"
	)
	toEtc := func(file string) string {
		rel, err := filepath.Rel(project, file)
		if err != nil {
			t.Fatal(err)
		}
		return rel
	}
	insecure := "{\"insecure-registries\":[\"http://registry.example.test:5000\"]}\n"
	write := func(name, content string) map[string]any {
		return map[string]any{"file_path": name, "content": content}
	}
	pamEdit := func(name, added string) map[string]any {
		return map[string]any{"file_path": name, "old_string": "auth       substack     password-auth", "new_string": added + "auth       substack     password-auth"}
	}
	for _, c := range []struct {
		name, tool, operand, physical, rule string
		args                                map[string]any
		blocked                             bool
	}{
		{"loader link name", "Write", "named-link", "/etc/ld.so.preload", preloadRule, write("named-link", library), true},
		{"loader dot-slash link name", "Write", "./named-link", "/etc/ld.so.preload", preloadRule, write("./named-link", library), true},
		{"loader up-dots path, client answer", "Write", toEtc("/etc/ld.so.preload"), "/etc/ld.so.preload", preloadRule, write(toEtc("/etc/ld.so.preload"), library), true},
		{"loader up-dots path, no answer", "Write", toEtc("/etc/ld.so.preload"), "", preloadRule, write(toEtc("/etc/ld.so.preload"), library), true},
		{"loader link name, comment text", "Write", "named-link", "/etc/ld.so.preload", preloadRule, write("named-link", "# none\n"), false},
		{"loader link to an ordinary file", "Write", "named-link", filepath.Join(project, "notes.txt"), preloadRule, write("named-link", library), false},
		{"loader path that stays in the home", "Write", "../etc/ld.so.preload", "", preloadRule, write("../etc/ld.so.preload", library), false},
		{"profile fragment link name", "Write", "named-link", "/etc/profile.d/r109.sh", preloadRule, write("named-link", "export LD_PRELOAD=/usr/local/lib/libreview.so\n"), true},
		{"profile fragment link name, benign export", "Write", "named-link", "/etc/profile.d/r109.sh", preloadRule, write("named-link", "export CLICOLOR=1\n"), false},
		{"pam edit link name", "Edit", "named-link", "/etc/pam.d/sshd", pamRule, pamEdit("named-link", "auth       sufficient   pam_permit.so\n"), true},
		{"pam edit link name, inline comment", "Edit", "named-link", "/etc/pam.d/sshd", pamRule, pamEdit("named-link", "auth sufficient pam_permit.so # review\n"), true},
		{"pam edit up-dots path", "Edit", toEtc("/etc/pam.d/sshd"), "", pamRule, pamEdit(toEtc("/etc/pam.d/sshd"), "auth       sufficient   pam_permit.so\n"), true},
		{"pam edit link name, ordinary line", "Edit", "named-link", "/etc/pam.d/sshd", pamRule, pamEdit("named-link", "session    required     pam_limits.so\n"), false},
		{"pam edit link to an ordinary file", "Edit", "named-link", filepath.Join(project, "notes.txt"), pamRule, pamEdit("named-link", "auth       sufficient   pam_permit.so\n"), false},
		{"docker write link name", "Write", "named-link", "/etc/docker/daemon.json", dockerInsecureHTTPRegistryRuleID, write("named-link", insecure), true},
		{"docker write link name, benign", "Write", "named-link", "/etc/docker/daemon.json", dockerInsecureHTTPRegistryRuleID, write("named-link", "{\"log-level\":\"warn\"}\n"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := string(mustJSON(t, sudoersClaudeCall(c.tool, sudoersFixed(c.args))(project)))
			got := overLimitHostHookWithEvidence(t, "claudecode", home, body, managedPlacedEvidence(t, body, project, c.operand, c.physical))
			blocked := overLimitHookAction(t, got) == "block"
			if blocked != c.blocked || strings.Contains(got, c.rule) != c.blocked {
				t.Fatalf("blocked=%t, want %t by %s: %.600s", blocked, c.blocked, c.rule, got)
			}
		})
	}
}
