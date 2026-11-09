// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX symlinks and close a directory with chmod.

//go:build !windows

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const authorizedKeysRuleID = "persistence.ssh_authorized_keys_command"

// The managed hook runs the path resolver in the user process and sends its
// answers; the managed gateway cannot read the home of the user. A link into a
// directory the user cannot open must be judged exactly as the per-user hook
// judges it.

// postManagedHookBehindProtectHome posts a Claude Code call as a managed hook
// does: the hook client runs as the user on the real filesystem and its
// evidence is encoded first; the gateway then runs with the parent of the home
// closed, the same incomplete walk as ProtectHome gives a service account.
// setup builds the project (cwd) and returns the call. It returns whether the
// call was refused, and the response.
func postManagedHookBehindProtectHome(t *testing.T, profile string, setup func(home, project string) map[string]any) (bool, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "alice")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	packDir := filepath.Join(guardrailPoliciesRoot(t), profile)
	installToolCallCorpusPackDirConnector(t, "claudecode", packDir)
	raw := string(mustJSON(t, setup(home, project)))
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, _ error) error {
			if entry != nil && entry.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	evidence := hookpaths.Resolve([]byte(raw))
	if err := os.Chmod(homes, 0); err != nil {
		t.Fatal(err)
	}
	// The data directory lies outside the closed home: a lock that cannot be
	// read counts as an install window, which the strict tier answers first.
	dataDir := filepath.Join(root, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	cfg := &config.Config{DataDir: dataDir}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = packDir
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, evidence)
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %.400s", recorder.Code, body)
	}
	return strings.Contains(body, `"action":"block"`) || strings.Contains(body, `"permissionDecision":"deny"`), body
}

// closedSSHKeyLink builds the key file in the SSH folder of the home, a
// project link to it and, when closed, mode 000 on the folder; it returns a
// file-tool call through the link.
func closedSSHKeyLink(t *testing.T, tool, content string, closed bool) func(home, project string) map[string]any {
	return func(home, project string) map[string]any {
		keyDir := filepath.Join(home, ".ssh")
		if err := os.Mkdir(keyDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(keyDir, "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(keyDir, "authorized_keys"), filepath.Join(project, "keys-link")); err != nil {
			t.Fatal(err)
		}
		if closed {
			if err := os.Chmod(keyDir, 0); err != nil {
				t.Fatal(err)
			}
		}
		return sudoersClaudeCall(tool, sudoersFixed(perUserFileToolArgs("keys-link", tool, content)))(project)
	}
}

// A managed hook for a file-tool write of a key line through a project link
// into the closed SSH directory of the user stays blocked in every profile,
// as the direct name and the per-user hook are.
func TestManagedFileToolThroughALinkIntoAClosedSSHDirectoryStaysBlocked(t *testing.T) {
	for _, tool := range []string{"Write", "Edit", "MultiEdit"} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			t.Run(tool+"/"+profile, func(t *testing.T) {
				blocked, body := postManagedHookBehindProtectHome(t, profile, closedSSHKeyLink(t, tool, "ssh-ed25519 AAAA test\n", true))
				if !blocked || !strings.Contains(body, authorizedKeysRuleID) {
					t.Fatalf("key file link in a closed directory allowed by the managed hook in %s: %.600s", profile, body)
				}
			})
		}
	}
}

// The open-folder twin: the same link with the SSH folder open to the user is
// judged by the physical file and stays blocked.
func TestManagedFileToolThroughALinkIntoAnOpenSSHDirectoryStaysBlocked(t *testing.T) {
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			blocked, body := postManagedHookBehindProtectHome(t, profile, closedSSHKeyLink(t, "Write", "ssh-ed25519 AAAA test\n", false))
			if !blocked || !strings.Contains(body, authorizedKeysRuleID) {
				t.Fatalf("key file link in an open directory allowed by the managed hook in %s: %.600s", profile, body)
			}
		})
	}
}

// The benign twin: an ordinary file behind a link into a closed directory is
// no key write and stays allowed in the balanced profiles.
func TestManagedFileToolThroughALinkIntoAnOrdinaryClosedDirectoryIsAllowed(t *testing.T) {
	for _, profile := range []string{"default", "permissive"} {
		t.Run(profile, func(t *testing.T) {
			blocked, body := postManagedHookBehindProtectHome(t, profile, func(home, project string) map[string]any {
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
				return sudoersClaudeCall("Write", sudoersFixed(map[string]any{"file_path": "notes-link", "content": "hello\n"}))(project)
			})
			if blocked {
				t.Fatalf("ordinary closed-directory link blocked by the managed hook in %s: %.600s", profile, body)
			}
		})
	}
}

// A shell command can open a closed directory before it writes, so the managed
// hook leaves the hidden inner link unresolved and blocked, as the per-user
// hook does.
func TestManagedShellWriteThroughALinkIntoAClosedDirectoryStaysBlockedWhenTheCommandOpensIt(t *testing.T) {
	for _, command := range []string{
		"chmod u+x closed && printf marker >> ./alias",
		"chmod 700 closed; printf marker >> alias",
	} {
		for _, profile := range []string{"default", "permissive", "strict"} {
			t.Run(profile+"/"+command, func(t *testing.T) {
				blocked, body := postManagedHookBehindProtectHome(t, profile, func(home, project string) map[string]any {
					keyDir := filepath.Join(home, ".ssh")
					if err := os.Mkdir(keyDir, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(keyDir, "authorized_keys"), []byte("# keys\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					closed := filepath.Join(project, "closed")
					if err := os.Mkdir(closed, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join(keyDir, "authorized_keys"), filepath.Join(closed, "inner")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join(closed, "inner"), filepath.Join(project, "alias")); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(closed, 0); err != nil {
						t.Fatal(err)
					}
					return sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": command}))(project)
				})
				if !blocked {
					t.Fatalf("append through a link the command reopens allowed by the managed hook in %s: %.600s", profile, body)
				}
			})
		}
	}
}
