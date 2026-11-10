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

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
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

// stepUpDeepOrdinaryName returns the name of a link in the project to a folder
// of the user that lies deeper than the project does, climbed out of as many
// times as the lexical path of the project is deep: cleaned lexically the name
// reaches the root and spells the system loader file, while the operating
// system, which walks the link first, opens an ordinary file inside the user
// folders.
func stepUpDeepOrdinaryName(t *testing.T, project, leaf string) string {
	t.Helper()
	ups := strings.Count(filepath.ToSlash(filepath.Clean(project)), "/") + 1
	folder := filepath.Join(filepath.Dir(project), "other")
	for i := 0; i < ups+2; i++ {
		folder = filepath.Join(folder, "d")
	}
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	stepUpLink(t, project, "lnk-deep", folder)
	return "lnk-deep/" + strings.Repeat("../", ups) + leaf
}

func stepUpClaude(tool string, input map[string]any) func(t *testing.T, project string) map[string]any {
	return func(t *testing.T, project string) map[string]any {
		return sudoersClaudeCall(tool, sudoersFixed(input))(project)
	}
}

func stepUpRows() []stepUpRow {
	const loader = "persistence.global_ld_preload_install"
	const sudoersGrantRuleID = "privilege.sudoers_unrestricted_nopasswd"
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
		{"sudoers grant by a patch header after a link to the profile folder", "codex", sudoersGrantRuleID, func(t *testing.T, project string) map[string]any {
			stepUpLink(t, project, "lnk-profd", "/etc/profile.d")
			return codexBashCall(codexHeredocPatch("Update File", "lnk-profd/../sudoers", "@@\n+reviewer ALL=(ALL) NOPASSWD: ALL\n"))(project)
		}},
		{"sudoers drop-in by a patch header after a link to the profile folder", "codex", sudoersGrantRuleID, func(t *testing.T, project string) map[string]any {
			stepUpLink(t, project, "lnk-profd", "/etc/profile.d")
			return codexBashCall(codexHeredocPatch("Add File", "lnk-profd/../sudoers.d/review", "+reviewer ALL=(ALL) NOPASSWD: ALL\n"))(project)
		}},
		{"sudoers grant by a file tool after a link to the profile folder", "claudecode", sudoersGrantRuleID, func(t *testing.T, project string) map[string]any {
			stepUpLink(t, project, "lnk-profd", "/etc/profile.d")
			return stepUpClaude("Write", map[string]any{"file_path": "lnk-profd/../sudoers", "content": "reviewer ALL=(ALL) NOPASSWD: ALL\n"})(t, project)
		}},
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
		{"ordinary physical file whose lexical name is the loader file", "claudecode", "", func(t *testing.T, project string) map[string]any {
			return stepUpClaude("Write", map[string]any{"file_path": stepUpDeepOrdinaryName(t, project, "etc/ld.so.preload"), "content": preload["content"]})(t, project)
		}},
		{"ordinary physical file by a patch header whose lexical name is the loader file", "codex", "", func(t *testing.T, project string) map[string]any {
			return codexBashCall(codexHeredocPatch("Add File", stepUpDeepOrdinaryName(t, project, "etc/ld.so.preload"), "+/opt/lib/libreview.so\n"))(project)
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

// TestStepUpOrdinaryFileNamedAsASudoersDropInIsAllowedInBalanced: a file in the
// folders of the user whose lexical name cleans to a sudoers drop-in is the
// ordinary file it is, for a file tool and for the Add File and Update File
// header of a shell here-document, with the same grant text that a drop-in
// would be blocked for, on the per-user gateway and on the managed one (which
// reads the walk of the hook client, for a lexical name in a folder the user
// cannot open as well). The strict tier keeps its path rule on the lexical name
// of the file.
func TestStepUpOrdinaryFileNamedAsASudoersDropInIsAllowedInBalanced(t *testing.T) {
	const grant = "reviewer ALL=(ALL) NOPASSWD: ALL\n"
	type row struct {
		connector string
		call      func(t *testing.T, home, project string) map[string]any
	}
	physicalFile := func(t *testing.T, home, project, spelling string, content string) {
		t.Helper()
		physical, ok := hookpaths.ResolvePatchWriteTarget(project + "/" + spelling)
		if !ok || !strings.HasPrefix(physical, home+"/") {
			t.Fatalf("physical = %q, known = %t", physical, ok)
		}
		if err := os.MkdirAll(filepath.Dir(physical), 0o700); err != nil {
			t.Fatal(err)
		}
		if content != "" {
			if err := os.WriteFile(physical, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	patch := func(directive string) row {
		return row{"codex", func(t *testing.T, home, project string) map[string]any {
			spelling := stepUpDeepOrdinaryName(t, project, "etc/sudoers.d/review")
			body := "+" + grant
			if directive == "Update File" {
				physicalFile(t, home, project, spelling, "# old\n")
				body = "@@\n # old\n+" + grant
			} else {
				physicalFile(t, home, project, spelling, "")
			}
			return codexBashCall(codexHeredocPatch(directive, spelling, body))(project)
		}}
	}
	calls := map[string]row{
		"patch Add File":    patch("Add File"),
		"patch Update File": patch("Update File"),
		"file tool": {"claudecode", func(t *testing.T, home, project string) map[string]any {
			spelling := stepUpDeepOrdinaryName(t, project, "etc/sudoers.d/review")
			physicalFile(t, home, project, spelling, "")
			return stepUpClaude("Write", map[string]any{"file_path": spelling, "content": grant})(t, project)
		}},
	}
	for _, managed := range []bool{false, true} {
		for name, row := range calls {
			t.Run(map[bool]string{false: "per-user", true: "managed"}[managed]+"/"+name, func(t *testing.T) {
				blocked, body := postConnectorHookBehindProtectHome(t, row.connector, managed, "default",
					func(home, project string) map[string]any { return row.call(t, home, project) })
				if blocked {
					t.Fatalf("an ordinary file is blocked: %.500s", body)
				}
			})
		}
	}
}

// TestStepUpPatchHeaderIsJudgedAsTheKeyFileItReaches: the header of a shell
// here-document patch that steps up out of a link reaches a file the lexical
// clean does not name. A link into a folder of the SSH folder reaches the
// authorized-keys file and blocks, on the per-user and the managed gateway,
// whatever the clean spelling is; the same name through a link to an ordinary
// folder is an ordinary file and is allowed.
func TestStepUpPatchHeaderIsJudgedAsTheKeyFileItReaches(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, profile := range []string{"default", "strict"} {
			for _, keys := range []bool{true, false} {
				name := map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + profile + "/" +
					map[bool]string{true: "key file", false: "ordinary file"}[keys]
				t.Run(name, func(t *testing.T) {
					blocked, body := postConnectorHookBehindProtectHome(t, "codex", managed, profile, func(home, project string) map[string]any {
						folder := filepath.Join(home, "other", "keys")
						if keys {
							folder = filepath.Join(home, ".ssh", "keys")
						}
						if err := os.MkdirAll(folder, 0o700); err != nil {
							t.Fatal(err)
						}
						stepUpLink(t, project, "lnk-keys", folder)
						physical, ok := hookpaths.ResolvePatchWriteTarget(project + "/lnk-keys/../authorized_keys")
						if !ok || !strings.HasPrefix(physical, home+"/") {
							t.Fatalf("physical = %q, known = %t", physical, ok)
						}
						return codexBashCall(codexHeredocPatch("Add File", "lnk-keys/../authorized_keys", "+ssh-ed25519 AAAAC3review review\n"))(project)
					})
					if blocked != keys {
						t.Fatalf("blocked = %t, want %t: %.500s", blocked, keys, body)
					}
				})
			}
		}
	}
}
