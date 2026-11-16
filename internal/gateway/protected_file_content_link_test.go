// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX symlinks.

//go:build !windows

package gateway

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// protectedContentCase is one structured write of a protected file whose
// content a code-owned rule judges, named by a project link.
type protectedContentCase struct {
	name      string
	ruleID    string
	connector string
	tool      string
	pathKey   string
	target    string
	content   string
	benign    string
}

var protectedContentCases = []protectedContentCase{
	{
		name: "sudoers drop-in", ruleID: sudoersGrantRuleID,
		connector: "claudecode", tool: "Write", pathKey: "file_path", target: "/etc/sudoers.d/r109ops",
		content: "r109yem5 ALL=(ALL) NOPASSWD: ALL\n",
		// No ordinary content: any text written into the drop-in directory is
		// judged by the strict path rule, by design (GAP-0190).
	},
	{
		name: "PAM service entry", ruleID: pamPermitAuthenticationBypassRuleID,
		connector: "claudecode", tool: "Write", pathKey: "file_path", target: "/etc/pam.d/sshd",
		content: "auth sufficient pam_permit.so\n", benign: "auth required pam_unix.so\n",
	},
	{
		name: "Docker daemon configuration", ruleID: dockerInsecureHTTPRegistryRuleID,
		connector: "claudecode", tool: "Write", pathKey: "file_path", target: "/etc/docker/daemon.json",
		content: `{"insecure-registries":["http://mirror.local"]}`, benign: `{"log-level":"warn"}`,
	},
	{
		name: "global preload profile fragment", ruleID: "persistence.global_ld_preload_install",
		connector: "claudecode", tool: "Write", pathKey: "file_path", target: "/etc/profile.d/r109.sh",
		content: "export LD_PRELOAD=/opt/lib/r109.so\n", benign: "export EDITOR=vim\n",
	},
	{
		name: "account database", ruleID: "privilege.posix_non_root_uid_zero_account_write",
		connector: "hermes", tool: "write_file", pathKey: "path", target: "/etc/passwd",
		content: "root:x:0:0:root:/root:/bin/bash\nr109:x:0:0::/root:/bin/sh\n",
		benign:  "root:x:0:0:root:/root:/bin/bash\nr109:x:1001:1001::/home/r109:/bin/sh\n",
	},
}

// The answers the hook of a link to a protected file can give.
const (
	// linkResolved: the hook client resolved the link (managed hook).
	linkResolved = "resolved"
	// linkClosedDirectory: a directory on the way is closed to the user; the
	// client lists the file the link text leads to.
	linkClosedDirectory = "closed directory"
	// linkNoEvidence: the per-user hook sends no client evidence at all, and
	// the gateway walks the link itself.
	linkNoEvidence = "no client evidence"
)

var protectedLinkModes = []string{linkResolved, linkClosedDirectory, linkNoEvidence}

// protectedLinkEvidence rewrites the hook client evidence of the write
// through the project link grant-link to the answer of mode for a link to
// target.
func protectedLinkEvidence(t *testing.T, target, mode string) func(*testing.T, string) string {
	return func(t *testing.T, evidence string) string {
		t.Helper()
		if mode == linkNoEvidence {
			return ""
		}
		targets, ok := hookpaths.Decode(evidence)
		if !ok {
			t.Fatalf("hook evidence %q is not readable", evidence)
		}
		for key := range targets {
			if filepath.Base(key) != "grant-link" || !strings.HasPrefix(key, "/") {
				continue
			}
			if mode == linkClosedDirectory {
				targets[key] = ""
				targets[hookpaths.LinkTextFactPrefix+key] = target
			} else {
				targets[key] = target
			}
		}
		encoded, err := json.Marshal(targets)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
}

func protectedContentLinkRow(t *testing.T, test protectedContentCase, content string, relative bool) sudoersHookRow {
	return sudoersHookRow{test.connector, test.name, func(project string) map[string]any {
		link := filepath.Join(project, "grant-link")
		if err := os.Symlink(test.target, link); err != nil {
			t.Fatal(err)
		}
		operand := link
		if relative {
			operand = "./grant-link"
		}
		fields := sudoersFixed(map[string]any{test.pathKey: operand, "content": content})
		if test.connector == "claudecode" {
			return sudoersClaudeCall(test.tool, fields)(project)
		}
		return sudoersHermesCall(test.tool, fields)(project)
	}}
}

// TestStructuredWriteOfAProtectedFileThroughALinkIsJudgedLikeTheDirectName: a
// project link to a protected file whose content a code-owned rule judges (a
// PAM service entry, Docker's daemon configuration) takes the verdict of the
// direct name in default, strict and managed, whether the client resolved the
// link or could only read its text.
func TestStructuredWriteOfAProtectedFileThroughALinkIsJudgedLikeTheDirectName(t *testing.T) {
	for _, test := range protectedContentCases {
		for _, mode := range protectedLinkModes {
			for _, relative := range []bool{false, true} {
				for _, profile := range []string{"default", "strict"} {
					for _, managed := range []bool{false, true} {
						if managed && mode == linkNoEvidence {
							// The managed hook always sends its client evidence.
							continue
						}
						name := strings.Join([]string{test.name, mode,
							map[bool]string{false: "absolute", true: "relative"}[relative], profile,
							map[bool]string{false: "per-user", true: "managed"}[managed]}, "/")
						t.Run(name, func(t *testing.T) {
							direct := sudoersHookRow{test.connector, "direct", func(project string) map[string]any {
								fields := sudoersFixed(map[string]any{test.pathKey: test.target, "content": test.content})
								if test.connector == "claudecode" {
									return sudoersClaudeCall(test.tool, fields)(project)
								}
								return sudoersHermesCall(test.tool, fields)(project)
							}}
							blocked, _, body := postSudoersHook(t, direct, profile, managed)
							if !blocked || !strings.Contains(body, test.ruleID) {
								t.Fatalf("the direct name is not blocked by %s: %.600s", test.ruleID, body)
							}
							sudoersEvidenceRewrite = protectedLinkEvidence(t, test.target, mode)
							t.Cleanup(func() { sudoersEvidenceRewrite = nil })
							blocked, _, body = postSudoersHook(t, protectedContentLinkRow(t, test, test.content, relative), profile, managed)
							if !blocked || !strings.Contains(body, test.ruleID) {
								t.Fatalf("link blocked = %t, want a block naming %s like the direct name: %.600s", blocked, test.ruleID, body)
							}
						})
					}
				}
			}
		}
	}
}

// TestStructuredWriteOfOrdinaryContentThroughAProtectedFileLinkIsAllowed is
// the benign twin: content that is no bypass of the rule is allowed through
// the same link in default, and a link to an ordinary file takes no rule.
func TestStructuredWriteOfOrdinaryContentThroughAProtectedFileLinkIsAllowed(t *testing.T) {
	for _, test := range protectedContentCases {
		for _, mode := range protectedLinkModes {
			for _, elsewhere := range []bool{false, true} {
				if test.benign == "" && !elsewhere {
					continue
				}
				name := test.name + "/" + mode +
					"/" + map[bool]string{false: "ordinary content", true: "ordinary file"}[elsewhere]
				t.Run(name, func(t *testing.T) {
					target, content := test.target, test.benign
					if elsewhere {
						target, content = "/srv/closed/notes.txt", test.content
					}
					sudoersEvidenceRewrite = protectedLinkEvidence(t, target, mode)
					t.Cleanup(func() { sudoersEvidenceRewrite = nil })
					linked := test
					linked.target = target
					blocked, _, body := postSudoersHook(t, protectedContentLinkRow(t, linked, content, false), "default", false)
					if blocked || strings.Contains(body, test.ruleID) {
						t.Fatalf("blocked = %t, names %s = %t, want neither: %.600s", blocked, test.ruleID, strings.Contains(body, test.ruleID), body)
					}
				})
			}
		}
	}
}

// TestStrictWriteOfOrdinaryTextThroughALinkIntoTheSudoersDirectoryKeepsTheDirectNameVerdict:
// the strict profile refuses any text written into the drop-in directory by
// its name (PATH-ETC-SUDOERS); a project link to it takes the same verdict
// whatever the hook could tell of the link, and the balanced profiles do not
// gain a block from the link.
func TestStrictWriteOfOrdinaryTextThroughALinkIntoTheSudoersDirectoryKeepsTheDirectNameVerdict(t *testing.T) {
	test := protectedContentCase{
		name: "sudoers drop-in", connector: "claudecode", tool: "Write", pathKey: "file_path", target: "/etc/sudoers.d/r109ops",
	}
	direct := sudoersHookRow{test.connector, "direct", sudoersClaudeCall(test.tool, sudoersFixed(map[string]any{
		test.pathKey: test.target, "content": "# ordinary\n"}))}
	wantStrict, _, body := postSudoersHook(t, direct, "strict", false)
	if !wantStrict {
		t.Fatalf("the direct name is not blocked in strict: %.600s", body)
	}
	for _, mode := range protectedLinkModes {
		for _, relative := range []bool{false, true} {
			t.Run(mode+"/"+map[bool]string{false: "absolute", true: "relative"}[relative], func(t *testing.T) {
				sudoersEvidenceRewrite = protectedLinkEvidence(t, test.target, mode)
				t.Cleanup(func() { sudoersEvidenceRewrite = nil })
				blocked, _, body := postSudoersHook(t, protectedContentLinkRow(t, test, "# ordinary\n", relative), "strict", false)
				if !blocked {
					t.Fatalf("strict link to the drop-in directory is allowed like no direct name: %.600s", body)
				}
			})
		}
	}
}
