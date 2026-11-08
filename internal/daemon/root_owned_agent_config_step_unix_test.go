//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// runAgentConfigReturn runs the chain step the way the printed command does
// (sh -c script sh paths...) with a stand-in sudo that records what it was asked
// to run. It returns what sudo was asked to run, the step output and the status.
func runAgentConfigReturn(t *testing.T, sudoStatus string, paths ...string) (calls []string, output string, status int) {
	t.Helper()
	bin := t.TempDir()
	log := filepath.Join(t.TempDir(), "sudo.log")
	stand := "#!/bin/sh\necho \"$*\" >> " + log + "\nexit " + sudoStatus + "\n"
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(stand), 0o755); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-c", rootOwnedAgentConfigReturnScript, "sh"}, paths...)
	cmd := exec.Command("sh", args...)
	cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + t.TempDir()}
	out, err := cmd.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); ok {
		status = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(log); err == nil {
		calls = strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
	return calls, string(out), status
}

func TestRootOwnedAgentConfigReturnStepChecksEachPathWhenItRuns(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.Join(root, ".claude")
	file := filepath.Join(folder, "settings.json")
	if err := os.MkdirAll(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("a path in a plain folder is handed to sudo find with the guards", func(t *testing.T) {
		calls, _, status := runAgentConfigReturn(t, "0", file)
		if status != 0 || len(calls) != 1 {
			t.Fatalf("status %d, sudo calls %v", status, calls)
		}
		for _, want := range []string{"find -P ./settings.json", "-user root", "-links 1", "-execdir chown -h"} {
			if !strings.Contains(calls[0], want) {
				t.Fatalf("sudo call lacks %q: %q", want, calls[0])
			}
		}
	})

	t.Run("a folder swapped for a link after the scan is skipped", func(t *testing.T) {
		outside, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		swapped := filepath.Join(root, ".swapped")
		if err := os.Symlink(outside, swapped); err != nil {
			t.Fatal(err)
		}
		calls, output, status := runAgentConfigReturn(t, "0", filepath.Join(swapped, "settings.json"))
		if status != 0 || len(calls) != 0 || !strings.Contains(output, "skipped") {
			t.Fatalf("a path through a link reached sudo: status %d, calls %v, output %q", status, calls, output)
		}
	})

	t.Run("a path that is gone is skipped without a call", func(t *testing.T) {
		calls, _, status := runAgentConfigReturn(t, "0", filepath.Join(folder, "gone.json"))
		if status != 0 || len(calls) != 0 {
			t.Fatalf("status %d, sudo calls %v", status, calls)
		}
	})

	t.Run("a failed sudo ends the step before the next path", func(t *testing.T) {
		calls, _, status := runAgentConfigReturn(t, "1", file, folder)
		if status == 0 || len(calls) != 1 {
			t.Fatalf("status %d, sudo calls %v", status, calls)
		}
	})
}

// TestRootOwnedAgentConfigReturnStepWalksTheFolderItChecked swaps the folder
// that holds the path, and the folder one level above it, for a link at the
// moment sudo is called: the step must still walk the folder it checked (now
// under another name), never the folder the link points to. The sudo stand-in
// does the swap and then runs the find it was given as the account, with the
// owner test pointed at that account; the chown stand-in records the physical
// folder find ran it in.
func TestRootOwnedAgentConfigReturnStepWalksTheFolderItChecked(t *testing.T) {
	if _, err := exec.LookPath("find"); err != nil {
		t.Skip("find is not available")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		parent string // the folder swapped for a link
		path   string // the path handed to the step, relative to the home
		folder bool   // the path is a folder, not a file
	}{
		{"file in a vendor folder", ".claude", ".claude/settings.json", false},
		{"vendor folder below its parent", ".copilot", ".copilot/hooks", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(base, "home")
			outside := filepath.Join(base, "outside")
			target := filepath.Join(home, filepath.FromSlash(tc.path))
			for _, item := range []string{target, filepath.Join(outside, filepath.Base(tc.path))} {
				if tc.folder {
					if err := os.MkdirAll(item, 0o700); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if err := os.MkdirAll(filepath.Dir(item), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(item, []byte("{}\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			bin := t.TempDir()
			log := filepath.Join(t.TempDir(), "chown.log")
			link := filepath.Join(home, tc.parent)
			sudo := "#!/bin/sh\n" +
				"mv '" + link + "' '" + link + "-moved'\n" +
				"ln -s '" + outside + "' '" + link + "'\n" +
				"n=$#; while [ $n -gt 0 ]; do a=$1; shift; [ \"$a\" = root ] && a=" + me.Username + "; set -- \"$@\" \"$a\"; n=$((n-1)); done\n" +
				"exec \"$@\"\n"
			chown := "#!/bin/sh\necho \"$(/bin/pwd -P)\" >> " + log + "\n"
			for name, body := range map[string]string{"sudo": sudo, "chown": chown, "chmod": "#!/bin/sh\n"} {
				if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh", "-c", rootOwnedAgentConfigReturnScript, "sh", target)
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "HOME=" + home}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("step failed: %v\n%s", err, out)
			}
			raw, err := os.ReadFile(log)
			if err != nil {
				t.Fatalf("the owner change never ran: %v", err)
			}
			for _, folder := range strings.Fields(string(raw)) {
				if !strings.HasPrefix(folder, link+"-moved") {
					t.Fatalf("the owner change ran in %q, outside the folder the step checked (%s-moved)", folder, link)
				}
			}
		})
	}
}
