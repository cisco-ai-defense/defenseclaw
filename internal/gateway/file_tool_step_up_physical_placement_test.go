// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX links to the system folder /etc/pam.d.

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stepUpRow is one write whose file name steps up a directory (a dot-dot
// segment) after a link: the link is a segment of the name, or the working
// directory of the call. The operating system walks the links before the
// segment, so the file the write reaches is the physical one, not the lexical
// clean of the name.
type stepUpRow struct {
	name      string
	connector string
	rule      string // the rule the physical file brings; empty for an ordinary file
	call      func(t *testing.T, project string) map[string]any
}

// stepUpLink makes name in dir a link to target and returns its path.
func stepUpLink(t *testing.T, dir, name, target string) string {
	t.Helper()
	link := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link
}

// stepUpOrdinaryFolder makes a folder of the user, beside the project, that a
// link can lead to: the file after the step up is an ordinary file there.
func stepUpOrdinaryFolder(t *testing.T, project string) string {
	t.Helper()
	folder := filepath.Join(filepath.Dir(project), "other", "deep")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	return folder
}

func stepUpClaude(tool string, input map[string]any) func(t *testing.T, project string) map[string]any {
	return func(t *testing.T, project string) map[string]any {
		return sudoersClaudeCall(tool, sudoersFixed(input))(project)
	}
}

func stepUpRows() []stepUpRow {
	const loader = "persistence.global_ld_preload_install"
	const system = "/etc/pam.d"
	preload := map[string]any{"content": "/opt/lib/libreview.so\n"}
	withLink := func(name string, call func(t *testing.T, project string) map[string]any) func(t *testing.T, project string) map[string]any {
		return func(t *testing.T, project string) map[string]any {
			stepUpLink(t, project, name, system)
			return call(t, project)
		}
	}
	withCWDLink := func(call func(t *testing.T, project string) map[string]any) func(t *testing.T, project string) map[string]any {
		return func(t *testing.T, project string) map[string]any {
			cwd := stepUpLink(t, project, "lnk-cwd", system)
			made := call(t, project)
			made["cwd"] = cwd
			return made
		}
	}
	return []stepUpRow{
		{"loader file after a link", "claudecode", loader, withLink("lnk-sys", stepUpClaude("Write",
			map[string]any{"file_path": "lnk-sys/../ld.so.preload", "content": preload["content"]}))},
		{"loader file after a link, absolute project name", "claudecode", loader, func(t *testing.T, project string) map[string]any {
			stepUpLink(t, project, "lnk-sys", system)
			return stepUpClaude("Write", map[string]any{
				"file_path": project + "/lnk-sys/../ld.so.preload", "content": preload["content"]})(t, project)
		}},
		{"loader file from a working directory named through a link", "claudecode", loader, withCWDLink(stepUpClaude("Write",
			map[string]any{"file_path": "../ld.so.preload", "content": preload["content"]}))},
		{"loader file two steps up from a working directory link", "claudecode", loader, func(t *testing.T, project string) map[string]any {
			made := stepUpClaude("Write", map[string]any{"file_path": "../../etc/ld.so.preload", "content": preload["content"]})(t, project)
			made["cwd"] = stepUpLink(t, project, "lnk-cwd", system)
			return made
		}},
		{"profile fragment after a link", "claudecode", loader, withLink("lnk-sys", stepUpClaude("Write",
			map[string]any{"file_path": "lnk-sys/../profile.d/zz-review.sh", "content": "export LD_PRELOAD=/opt/lib/libreview.so\n"}))},
		{"pam entry added by an edit without replace_all, after a link", "claudecode", pamPermitAuthenticationBypassRuleID,
			withLink("lnk-sys", stepUpClaude("Edit", map[string]any{
				"file_path": "lnk-sys/sshd/../sshd", "old_string": "# review", "new_string": "# review\nauth sufficient pam_permit.so"}))},
		{"pam entry added by an edit from a working directory link", "claudecode", pamPermitAuthenticationBypassRuleID,
			withCWDLink(stepUpClaude("Edit", map[string]any{
				"file_path": "../pam.d/sshd", "old_string": "# review", "new_string": "# review\nauth sufficient pam_permit.so"}))},
		{"loader file by a patch header after a link", "codex", loader, withLink("lnk-sys", func(t *testing.T, project string) map[string]any {
			return codexBashCall(codexHeredocPatch("Add File", "lnk-sys/../ld.so.preload", "+/opt/lib/libreview.so\n"))(project)
		})},
		{"pam entry by a patch header after a link", "codex", pamPermitAuthenticationBypassRuleID, withLink("lnk-sys", func(t *testing.T, project string) map[string]any {
			return codexBashCall(codexHeredocPatch("Update File", "lnk-sys/../pam.d/sshd", "@@\n+auth sufficient pam_permit.so\n"))(project)
		})},
		// Ordinary twins: the same shapes with a file nobody protects.
		{"ordinary file after a link", "claudecode", "", func(t *testing.T, project string) map[string]any {
			stepUpLink(t, project, "lnk-other", stepUpOrdinaryFolder(t, project))
			return stepUpClaude("Write", map[string]any{"file_path": "lnk-other/../notes-review.txt", "content": "notes\n"})(t, project)
		}},
		{"ordinary file from a working directory named through a link", "claudecode", "", func(t *testing.T, project string) map[string]any {
			made := stepUpClaude("Write", map[string]any{"file_path": "../notes-review.txt", "content": "notes\n"})(t, project)
			made["cwd"] = stepUpLink(t, project, "lnk-cwd", stepUpOrdinaryFolder(t, project))
			return made
		}},
		{"project loader-named file after a plain folder", "claudecode", "", func(t *testing.T, project string) map[string]any {
			if err := os.Mkdir(filepath.Join(project, "sub"), 0o700); err != nil {
				t.Fatal(err)
			}
			return stepUpClaude("Write", map[string]any{"file_path": "sub/../ld.so.preload", "content": preload["content"]})(t, project)
		}},
		{"comment in the pam file after a link", "claudecode", "", withLink("lnk-sys", stepUpClaude("Edit", map[string]any{
			"file_path": "lnk-sys/../pam.d/sshd", "old_string": "# review", "new_string": "# review comment"}))},
		{"ordinary file by a patch header after a link", "codex", "", func(t *testing.T, project string) map[string]any {
			stepUpLink(t, project, "lnk-other", stepUpOrdinaryFolder(t, project))
			return codexBashCall(codexHeredocPatch("Add File", "lnk-other/../notes-review.txt", "+notes\n"))(project)
		}},
		{"comment in the pam file by a patch header after a link", "codex", "", withLink("lnk-sys", func(t *testing.T, project string) map[string]any {
			return codexBashCall(codexHeredocPatch("Update File", "lnk-sys/../pam.d/sshd", "@@\n+# review comment\n"))(project)
		})},
	}
}

// TestStepUpWriteNamesAreJudgedAsThePhysicalFile: a write whose name steps up a
// directory after a link, or from a working directory that is a link, is judged
// as the file the operating system opens, as the direct name of that file is,
// on the per-user gateway that walks the home itself and on the managed gateway
// that reads the answer of the hook client, for a file tool and for the
// apply_patch header of a shell here-document. The same shapes aimed at an
// ordinary file stay allowed.
func TestStepUpWriteNamesAreJudgedAsThePhysicalFile(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, profile := range []string{"default", "strict"} {
			for _, row := range stepUpRows() {
				name := map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + profile + "/" + row.name
				t.Run(name, func(t *testing.T) {
					blocked, body := postConnectorHookBehindProtectHome(t, row.connector, managed, profile,
						func(home, project string) map[string]any { return row.call(t, project) })
					if row.rule != "" {
						if !blocked || !strings.Contains(body, row.rule) {
							t.Fatalf("blocked = %t, want a block naming %s: %.500s", blocked, row.rule, body)
						}
						return
					}
					if blocked {
						t.Fatalf("an ordinary file is blocked: %.500s", body)
					}
				})
			}
		}
	}
}
