// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows name POSIX system paths (/etc).

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A relative name that steps up a directory after a link reaches the physical
// file the hook client answered with; its lexical clean is a different path that
// happens to be a protected file. The loader, profile.d and PAM content rules
// judge the file the write reaches, as the Docker rule does: an ordinary file is
// never judged as the protected file its lexical clean names, and a protected
// file reached the same way stays blocked. (A name the client gave no answer for
// stays on its lexical clean: TestManagedContentRulesPlaceARelativeFilePathLikeTheAbsoluteName.)
func TestContentRulesJudgeTheFileADotDotNameReachesNotItsLexicalClean(t *testing.T) {
	home, project := hermesPatchHome(t)
	const (
		preloadRule = "persistence.global_ld_preload_install"
		pamRule     = "tamper.pam_permit_authentication_bypass"
	)
	deep := filepath.Join(project, "deep", "a", "b", "c", "d", "e", "f", "g", "h")
	if err := os.MkdirAll(deep, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(deep, filepath.Join(project, "link")); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, tool, file, rule string
		args                   func(target string) map[string]any
		benign                 map[string]any
	}{
		{
			name: "loader preload file", tool: "Write", file: "/etc/ld.so.preload", rule: preloadRule,
			args: func(target string) map[string]any {
				return map[string]any{"file_path": target, "content": "/usr/local/lib/libreview.so\n"}
			},
			benign: map[string]any{"content": "# none\n"},
		},
		{
			name: "profile fragment", tool: "Write", file: "/etc/profile.d/review.sh", rule: preloadRule,
			args: func(target string) map[string]any {
				return map[string]any{"file_path": target, "content": "export LD_PRELOAD=/usr/local/lib/libreview.so\n"}
			},
			benign: map[string]any{"content": "export CLICOLOR=1\n"},
		},
		{
			name: "PAM service", tool: "Edit", file: "/etc/pam.d/sshd", rule: pamRule,
			args: func(target string) map[string]any {
				return map[string]any{
					"file_path": target, "old_string": "auth       substack     password-auth",
					"new_string": "auth       sufficient   pam_permit.so\nauth       substack     password-auth",
				}
			},
			benign: map[string]any{"new_string": "session    required     pam_limits.so\nauth       substack     password-auth"},
		},
	} {
		up, err := filepath.Rel(project, c.file)
		if err != nil {
			t.Fatal(err)
		}
		target := "link/../" + filepath.ToSlash(up)
		ordinary := filepath.Clean(filepath.Join(deep, "..", up))
		if err := os.MkdirAll(filepath.Dir(ordinary), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ordinary, []byte("# ordinary\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if lexical := filepath.Clean(project + "/" + target); lexical != c.file {
			t.Fatalf("%s: lexical target = %q", c.name, lexical)
		}
		if reached, err := filepath.EvalSymlinks(project + "/" + target); err != nil || reached != ordinary {
			t.Fatalf("%s: physical target = %q, err = %v, want %q", c.name, reached, err, ordinary)
		}
		for _, row := range []struct {
			name, physical string
			benign         bool
			block          bool
		}{
			{"to an ordinary file", ordinary, false, false},
			{"to the protected file", c.file, false, true},
			{"to the protected file, ordinary text", c.file, true, false},
		} {
			t.Run(c.name+"/"+row.name, func(t *testing.T) {
				args := c.args(target)
				if row.benign {
					for key, value := range c.benign {
						args[key] = value
					}
				}
				body := string(mustJSON(t, sudoersClaudeCall(c.tool, sudoersFixed(args))(project)))
				got := overLimitHostHookWithEvidence(t, "claudecode", home, body,
					managedPlacedEvidence(t, body, project, target, row.physical))
				blocked := overLimitHookAction(t, got) == "block"
				if blocked != row.block || strings.Contains(got, c.rule) != row.block {
					t.Fatalf("blocked=%t, want %t by %s: %.600s", blocked, row.block, c.rule, got)
				}
			})
		}
	}
}
