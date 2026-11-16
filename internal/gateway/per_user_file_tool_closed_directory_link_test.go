// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX symlinks and close a directory with chmod.

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// perUserNoClientEvidence makes the hook send no client path evidence, as the
// per-user hook does: the gateway walks the link itself.
func perUserNoClientEvidence(t *testing.T) {
	t.Helper()
	sudoersEvidenceRewrite = func(*testing.T, string) string { return "" }
	t.Cleanup(func() { sudoersEvidenceRewrite = nil })
}

func perUserLinkWriteRow(t *testing.T, target, tool, content string) sudoersHookRow {
	t.Helper()
	return sudoersHookRow{"claudecode", tool, func(project string) map[string]any {
		if err := os.Symlink(target, filepath.Join(project, "grant-link")); err != nil {
			t.Fatal(err)
		}
		return sudoersClaudeCall(tool, sudoersFixed(perUserFileToolArgs("./grant-link", tool, content)))(project)
	}}
}

func perUserFileToolArgs(path, tool, content string) map[string]any {
	args := map[string]any{"file_path": path}
	switch tool {
	case "Write":
		args["content"] = content
	case "Edit":
		args["old_string"] = "# old\n"
		args["new_string"] = content
	case "MultiEdit":
		args["edits"] = []any{map[string]any{"old_string": "# old\n", "new_string": content}}
	}
	return args
}

// A per-user gateway walks a project link into a directory the user cannot
// open and finds an ordinary file there: the write is no key write and is
// allowed in the balanced profiles, as the direct name of that file is.
func TestPerUserWriteThroughALinkIntoAnOrdinaryClosedDirectoryIsAllowed(t *testing.T) {
	for _, profile := range []string{"default", "permissive"} {
		t.Run(profile, func(t *testing.T) {
			perUserNoClientEvidence(t)
			row := sudoersHookRow{"claudecode", "ordinary closed directory link", func(project string) map[string]any {
				closed := filepath.Join(project, "closed")
				if err := os.Mkdir(closed, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(closed, "notes.txt"), filepath.Join(project, "grant-link")); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(closed, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
				return sudoersClaudeCall("Write", sudoersFixed(map[string]any{
					"file_path": "./grant-link", "content": "hello\n",
				}))(project)
			}}
			if blocked, _, body := postSudoersHook(t, row, profile, false); blocked {
				t.Fatalf("ordinary closed-directory link blocked in %s: %.600s", profile, body)
			}
		})
	}
}

// Ordinary text written through a project link to a sudoers drop-in gets the
// verdict of the direct name for every file tool, and a grant through the
// same link is still blocked.
func TestPerUserFileToolThroughASudoersDropInLinkKeepsTheDirectNameVerdict(t *testing.T) {
	grant := "r109x ALL=(ALL) NOPASSWD: ALL\n"
	for _, tool := range []string{"Write", "Edit", "MultiEdit"} {
		for _, profile := range []string{"default", "permissive"} {
			t.Run(tool+"/"+profile+"/ordinary text", func(t *testing.T) {
				perUserNoClientEvidence(t)
				linked, _, linkBody := postSudoersHook(t, perUserLinkWriteRow(t, "/etc/sudoers.d/r109ops", tool, "# ordinary\n"), profile, false)
				direct := sudoersHookRow{"claudecode", tool + " direct", sudoersClaudeCall(tool, sudoersFixed(perUserFileToolArgs("/etc/sudoers.d/r109ops", tool, "# ordinary\n")))}
				directBlocked, _, directBody := postSudoersHook(t, direct, profile, false)
				if linked != directBlocked || strings.Contains(linkBody, sudoersGrantRuleID) {
					t.Fatalf("link blocked=%t direct blocked=%t; direct %.350s; link %.350s", linked, directBlocked, directBody, linkBody)
				}
			})
			t.Run(tool+"/"+profile+"/grant", func(t *testing.T) {
				perUserNoClientEvidence(t)
				blocked, _, body := postSudoersHook(t, perUserLinkWriteRow(t, "/etc/sudoers.d/r109ops", tool, grant), profile, false)
				if !blocked || !strings.Contains(body, sudoersGrantRuleID) {
					t.Fatalf("grant through link blocked=%t grant rule=%t: %.600s", blocked, strings.Contains(body, sudoersGrantRuleID), body)
				}
			})
		}
	}
}

// The same link into a closed SSH directory of the user leads to the key
// file by its text, so it stays blocked in every profile.
func TestPerUserWriteThroughALinkIntoAClosedSSHDirectoryStaysBlocked(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			perUserNoClientEvidence(t)
			row := sudoersHookRow{"claudecode", "closed ssh directory link", func(project string) map[string]any {
				ssh := filepath.Join(filepath.Dir(project), ".ssh")
				if err := os.Mkdir(ssh, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(ssh, "authorized_keys"), filepath.Join(project, "grant-link")); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(ssh, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(ssh, 0o700) })
				return sudoersClaudeCall("Write", sudoersFixed(map[string]any{
					"file_path": "./grant-link", "content": "ssh-ed25519 AAAA test\n",
				}))(project)
			}}
			if blocked, _, body := postSudoersHook(t, row, profile, false); !blocked {
				t.Fatalf("key file link in a closed directory allowed in %s: %.600s", profile, body)
			}
		})
	}
}

// A shell command can open a closed directory before it writes, so a link
// into one is not judged by its link text: the append through a hidden inner
// link to the key file stays blocked in every profile, while the same link
// written by a file tool (which cannot open the directory) is judged by text.
func TestPerUserShellWriteThroughALinkIntoAClosedDirectoryStaysBlockedWhenTheCommandOpensIt(t *testing.T) {
	for _, command := range []string{
		"chmod u+x closed && printf marker >> ./alias",
		"chmod 700 closed; printf marker >> alias",
	} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			t.Run(profile+"/"+command, func(t *testing.T) {
				perUserNoClientEvidence(t)
				row := sudoersHookRow{"claudecode", "closed directory reopened by the command", func(project string) map[string]any {
					ssh := filepath.Join(filepath.Dir(project), ".ssh")
					if err := os.Mkdir(ssh, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(ssh, "authorized_keys"), []byte("# keys\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					closed := filepath.Join(project, "closed")
					if err := os.Mkdir(closed, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join(ssh, "authorized_keys"), filepath.Join(closed, "inner")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join(closed, "inner"), filepath.Join(project, "alias")); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(closed, 0); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
					return sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": command}))(project)
				}}
				if blocked, _, body := postSudoersHook(t, row, profile, false); !blocked {
					t.Fatalf("append through a link the command reopens allowed in %s: %.600s", profile, body)
				}
			})
		}
	}
}

// The benign twin: a file-tool Write through the same two links, with an
// ordinary file behind the inner link, is no key write and stays allowed in
// the balanced profiles (the tool cannot open the directory, so the link text
// decides). A shell command through an unresolvable link keeps the verdict it
// has on the base: the command may open the directory first.
func TestPerUserWriteThroughAChainOfLinksIntoAnOrdinaryClosedDirectoryIsAllowed(t *testing.T) {
	for _, profile := range []string{"default", "permissive"} {
		t.Run(profile, func(t *testing.T) {
			perUserNoClientEvidence(t)
			row := sudoersHookRow{"claudecode", "closed directory chain, ordinary file", func(project string) map[string]any {
				closed := filepath.Join(project, "closed")
				if err := os.Mkdir(closed, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(project, "notes.txt"), filepath.Join(closed, "inner")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(closed, "inner"), filepath.Join(project, "alias")); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(closed, 0); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
				return sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": "./alias", "content": "hello\n"}))(project)
			}}
			if blocked, _, body := postSudoersHook(t, row, profile, false); blocked {
				t.Fatalf("ordinary file behind a chain of links blocked in %s: %.600s", profile, body)
			}
		})
	}
}
