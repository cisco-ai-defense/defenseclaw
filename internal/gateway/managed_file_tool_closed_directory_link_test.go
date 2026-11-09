// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows create POSIX symlinks and close a directory with chmod.

//go:build !windows

package gateway

import (
	"fmt"
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

// The redirect paths are kept below this many bytes, the longest path every
// supported system opens (macOS stops at 1024), so the client resolves every
// one of them and the map grows with the names.
const (
	boundedOperandPathBytes = 900
	boundedPadPerName       = 40
)

// boundedClosedLinkCall builds a project with a shell command of count
// ordinary redirects, then a command that reopens a closed folder and appends
// through a project link into the key file. pad lengthens the redirect names,
// boundedPadPerName bytes at a time from the first, so the client map grows
// byte by byte towards its bound: the operand answer and its link text are the
// last entries, which makes the bound fall between them for some pad. The
// folder names are sized from the project path, so the redirect paths have the
// same length on every system whatever the length of its temporary folder.
func boundedClosedLinkCall(t *testing.T, count, pad int) func(home, project string) map[string]any {
	return func(home, project string) map[string]any {
		keyDir := filepath.Join(home, ".ssh")
		closed := filepath.Join(project, "closed")
		for _, dir := range []string{keyDir, closed} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		key := filepath.Join(keyDir, "authorized_keys")
		if err := os.WriteFile(key, []byte("# keys\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for link, target := range map[string]string{
			filepath.Join(closed, "inner"):  key,
			filepath.Join(project, "alias"): filepath.Join(closed, "inner"),
		} {
			if _, err := os.Lstat(link); err == nil {
				continue
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
		}
		// Four folders, then "/f000" and the longest pad of one name.
		width := (boundedOperandPathBytes - len(project) - 4*3 - len("/f000") - boundedPadPerName) / 4
		if width < 1 || width > 200 {
			t.Fatalf("the project path %q leaves no usable folder name size (%d)", project, width)
		}
		filler := project
		for part := 0; part < 4; part++ {
			filler = filepath.Join(filler, fmt.Sprintf("d%d", part)+strings.Repeat("q", width))
		}
		if err := os.MkdirAll(filler, 0o700); err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel(project, filler)
		if err != nil {
			t.Fatal(err)
		}
		var statements []string
		remaining := pad
		for i := 0; i < count; i++ {
			name := fmt.Sprintf("f%03d", i)
			extra := min(remaining, boundedPadPerName)
			name += strings.Repeat("r", extra)
			remaining -= extra
			statements = append(statements, fmt.Sprintf("printf x > %s/%s", relative, name))
		}
		if remaining > 0 {
			t.Fatalf("pad %d does not fit in %d redirect names", pad, count)
		}
		statements = append(statements, "chmod u+x closed", "printf marker >> ./alias")
		return sudoersClaudeCall("Bash", sudoersFixed(map[string]any{"command": strings.Join(statements, "; ")}))(project)
	}
}

// The client map is bounded. The answer for an operand behind a closed folder
// and the link text that says so are one entry: for no map size does the
// client send the empty answer without its link text and without saying the
// map is incomplete, and the managed hook blocks the key append at the sizes
// where the bound falls on that entry. The sweep finds the bound on the system
// it runs on (the most redirects the map holds whole, then the pads that move
// the last whole entry across it) and must cross it, or it would not hold the
// case it names.
func TestManagedShellWriteThroughAClosedFolderLinkStaysBlockedWhenTheClientMapIsAtItsBound(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX link walk")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	closed := filepath.Join(project, "closed")
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	alias := filepath.Join(project, "alias")
	resolve := func(count, pad int) map[string]string {
		raw := mustJSON(t, boundedClosedLinkCall(t, count, pad)(home, project))
		if err := os.Chmod(closed, 0); err != nil {
			t.Fatal(err)
		}
		targets, ok := hookpaths.Decode(hookpaths.Resolve(raw))
		if err := os.Chmod(closed, 0o700); err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("%d redirects, pad %d: the client map could not be read back", count, pad)
		}
		return targets
	}
	// The most redirects the map holds whole. The hard cap is far above the
	// count the 64 KiB bound allows for paths of this size.
	const redirectCap = 400
	count := 0
	for next := 1; next <= redirectCap; next++ {
		if resolve(next, 0)[hookpaths.TruncatedKey] != "" {
			break
		}
		count = next
	}
	if count == 0 || count == redirectCap {
		t.Fatalf("the map bound was not found: %d redirects held whole (cap %d)", count, redirectCap)
	}
	var incomplete []int
	withText := 0
	// With the pad on the first names, the room left after the last whole
	// entry shrinks two bytes a step: it passes the size of the operand answer
	// and its link text once, then the last redirect no longer fits and the
	// answer is whole again. The sweep ends there.
	for pad, last := 0, count*boundedPadPerName; pad <= last; pad++ {
		targets := resolve(count, pad)
		resolved, present := targets[alias]
		_, text := targets[hookpaths.LinkTextFactPrefix+alias]
		switch {
		case present && resolved == "" && text:
			withText++
			if len(incomplete) > 0 {
				pad = last
			}
		case present && resolved == "":
			t.Fatalf("%d redirects, pad %d: an empty answer for the linked operand without its link text and without a bound marker", count, pad)
		case !present && targets[hookpaths.TruncatedKey] != "":
			incomplete = append(incomplete, pad)
		}
	}
	t.Logf("the map holds %d redirects; %d maps with the link text, %d incomplete maps (pads %v)", count, withText, len(incomplete), incomplete)
	if withText == 0 || len(incomplete) < 2 {
		t.Fatalf("the sweep did not cross the bound: %d maps with the link text, %d incomplete maps", withText, len(incomplete))
	}
	for _, pad := range []int{incomplete[0], incomplete[len(incomplete)-1]} {
		t.Run(fmt.Sprintf("pad%d", pad), func(t *testing.T) {
			blocked, body := postManagedHookBehindProtectHome(t, "default", func(home, project string) map[string]any {
				call := boundedClosedLinkCall(t, count, pad)(home, project)
				if err := os.Chmod(filepath.Join(project, "closed"), 0); err != nil {
					t.Fatal(err)
				}
				return call
			})
			if !blocked {
				t.Fatalf("key append through a closed-folder link allowed with a map at its bound: %.600s", body)
			}
		})
	}
}
