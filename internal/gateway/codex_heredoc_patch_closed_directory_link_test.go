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

// closedKeyFolderProject builds the key file in the SSH folder of the home, the
// project links to it (a file link, a link to that link) and closes the folder.
func closedKeyFolderProject(t *testing.T, home, project string) {
	t.Helper()
	keyDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"keys-link": filepath.Join(keyDir, "authorized_keys"),
		"hop-keys":  filepath.Join(project, "keys-link"),
		"keys-dir":  keyDir,
	} {
		if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(keyDir, 0); err != nil {
		t.Fatal(err)
	}
}

// A patch the Codex hook sees as a shell here-document that writes key text
// through a link into the SSH folder of the user, which the user has closed, is
// refused in every profile, as the typed file tool, the shell spellings and the
// patch through a link to the folder itself are, per-user and managed.
func TestCodexHeredocPatchThroughALinkIntoAClosedSSHFolderIsBlocked(t *testing.T) {
	const key = "+ssh-ed25519 AAAA test\n"
	for _, managed := range []bool{false, true} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			for _, shape := range []string{"top level", "called function", "condition"} {
				for _, name := range []string{"keys-link", "./keys-link", "hop-keys", "keys-dir/authorized_keys", "{project}/keys-link"} {
					for _, directive := range []string{"Add File", "Update File"} {
						t.Run(map[bool]string{false: "per-user", true: "managed"}[managed]+"/"+profile+"/"+shape+"/"+directive+"/"+name, func(t *testing.T) {
							blocked, body := postConnectorHookBehindProtectHome(t, "codex", managed, profile, func(home, project string) map[string]any {
								closedKeyFolderProject(t, home, project)
								target := strings.ReplaceAll(name, "{project}", project)
								patch := key
								if directive == "Update File" {
									patch = "@@\n" + key
								}
								return codexBashCall(inCodexShellShape(shape, codexHeredocPatch(directive, target, patch)))(project)
							})
							if !blocked || !strings.Contains(body, authorizedKeysRuleID) {
								t.Fatalf("key text through a link into a closed SSH folder was not refused: %.600s", body)
							}
						})
					}
				}
			}
		}
	}
}

// inCodexShellShape puts a here-document patch at the top level of the shell
// text, in the body of a function the text calls, or behind a condition.
func inCodexShellShape(shape, patch string) string {
	switch shape {
	case "called function":
		return "f() {\n" + patch + "}\nf\n"
	case "condition":
		return "if true; then\n" + patch + "fi\n"
	}
	return patch
}

// The benign twin: a patch through a link into a closed folder that holds an
// ordinary file, and a patch of an ordinary project file, stay allowed in the
// balanced profiles.
func TestCodexHeredocPatchThroughALinkIntoAnOrdinaryClosedFolderIsAllowed(t *testing.T) {
	for _, managed := range []bool{false, true} {
		for _, profile := range []string{"default", "permissive"} {
			for _, name := range []string{"notes-link", "notes.txt"} {
				t.Run(map[bool]string{false: "per-user", true: "managed"}[managed]+"/"+profile+"/"+name, func(t *testing.T) {
					blocked, body := postConnectorHookBehindProtectHome(t, "codex", managed, profile, func(home, project string) map[string]any {
						closed := filepath.Join(project, "closed")
						if err := os.Mkdir(closed, 0o700); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink(filepath.Join(closed, "notes.txt"), filepath.Join(project, "notes-link")); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(closed, 0); err != nil {
							t.Fatal(err)
						}
						return codexBashCall(codexHeredocPatch("Add File", name, "+hello\n"))(project)
					})
					if blocked {
						t.Fatalf("ordinary patch blocked: %.600s", body)
					}
				})
			}
		}
	}
}

// A grant written by a patch through a project link into the sudoers folder,
// which is closed to the user (mode 0750 root), is refused whether the patch is
// at the top level of the shell text or in the body of a function the text
// calls, in every profile, per-user and managed. The folder cannot be read, so
// the link text names the drop-in.
func TestCodexHeredocPatchOfAGrantThroughALinkIntoTheClosedSudoersFolderIsBlocked(t *testing.T) {
	hostLinksEtc(t, false)
	withClosedDirectoryEvidence(t, "/etc/sudoers.d/r109ops")
	patch := codexHeredocPatch("Add File", "grant-link", "+r109yem5 ALL=(ALL) NOPASSWD: ALL\n")
	shapes := map[string]string{
		"top level":               patch,
		"called function":         "f() {\n" + patch + "}\nf\n",
		"function then a command": "f() {\n" + patch + "}\nf && true\n",
	}
	for shape, command := range shapes {
		for _, profile := range []string{"default", "permissive", "strict"} {
			t.Run(shape+"/"+profile, func(t *testing.T) {
				blocked, body := postConnectorHookBehindProtectHome(t, "codex", true, profile, func(home, project string) map[string]any {
					if err := os.Symlink("/etc/sudoers.d/r109ops", filepath.Join(project, "grant-link")); err != nil {
						t.Fatal(err)
					}
					return codexBashCall(command)(project)
				})
				if !blocked || !strings.Contains(body, sudoersGrantRuleID) {
					t.Fatalf("grant through a link into the closed sudoers folder was not refused: %.600s", body)
				}
			})
		}
	}
}

// The benign twin: the same shapes with a link whose closed folder holds an
// ordinary file stay allowed in the balanced profiles.
func TestCodexHeredocPatchThroughALinkIntoAnotherClosedFolderIsAllowedInAFunction(t *testing.T) {
	hostLinksEtc(t, false)
	withClosedDirectoryEvidence(t, "/srv/closed/notes.txt")
	patch := codexHeredocPatch("Add File", "grant-link", "+r109yem5 ALL=(ALL) NOPASSWD: ALL\n")
	for shape, command := range map[string]string{"top level": patch, "called function": inCodexShellShape("called function", patch)} {
		for _, profile := range []string{"default", "permissive"} {
			t.Run(shape+"/"+profile, func(t *testing.T) {
				blocked, body := postConnectorHookBehindProtectHome(t, "codex", true, profile, func(home, project string) map[string]any {
					if err := os.Symlink("/srv/closed/notes.txt", filepath.Join(project, "grant-link")); err != nil {
						t.Fatal(err)
					}
					return codexBashCall(command)(project)
				})
				if blocked {
					t.Fatalf("ordinary closed-folder link blocked: %.600s", body)
				}
			})
		}
	}
}
