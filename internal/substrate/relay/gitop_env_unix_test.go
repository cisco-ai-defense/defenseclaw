// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0795 H1, H2, H3: the environment of the relay's own git runs is an
// allow-list. PATH keeps only folders only root can write (a folder anyone
// can write, a sticky one and a relative name go), never a folder of the
// relay's own PATH (/etc is root-only but no system folder: the image PATH
// is not read), and no HOME, XDG_* or GIT_* of the relay's environment is
// passed on.
func TestGAP0795RelayEnvIsAnAllowList(t *testing.T) {
	if _, ok := rootOnlyDir("/usr/bin"); !ok {
		t.Skip("/usr/bin is not root-only here")
	}
	open := filepath.Join(t.TempDir(), "bin")
	if err := os.Mkdir(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", strings.Join([]string{open, "/tmp", "bin", "/etc", "/usr/bin", "/bin"}, ":"))
	t.Setenv("HOME", open)
	t.Setenv("XDG_CONFIG_HOME", open)
	t.Setenv("GIT_ATTR_SOURCE", "HEAD")
	env, err := gitRelayEnv(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		switch {
		case k == "PATH":
			path = v
		case k == "HOME" || strings.HasPrefix(k, "XDG_") || strings.HasPrefix(k, "GIT_") && k != "GIT_TERMINAL_PROMPT":
			t.Errorf("the relay passes %s on to its root runs", k)
		}
	}
	for _, d := range filepath.SplitList(path) {
		if d == "/etc" {
			t.Errorf("PATH %q names %q of the relay's PATH: the root runs read the image PATH", path, d)
		}
		if d == open || d == "/tmp" || !filepath.IsAbs(d) {
			t.Errorf("PATH %q names %q, a folder root does not own alone", path, d)
		}
		if _, ok := rootOnlyDir(d); !ok {
			t.Errorf("PATH %q names %q, not root-only", path, d)
		}
	}
	if path == "" {
		t.Fatalf("no PATH in %v", env)
	}
}

// gap0795Tree is a root-owned 0755 folder for the root tests below, with
// "agent", a folder the agent's user (65534) owns.
func gap0795Tree(t *testing.T) (base, agent string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("GAP-0795: needs root to make root's and another user's files; run as root on a build box")
	}
	base, err := os.MkdirTemp("/tmp", "gap0795n-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	agent = filepath.Join(base, "agent")
	if err := os.Mkdir(agent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(agent, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	return base, agent
}

// gap0795Link makes link at p pointing to target, owned by uid.
func gap0795Link(t *testing.T, target, p string, uid int) {
	t.Helper()
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(p, uid, uid); err != nil {
		t.Fatal(err)
	}
}

// GAP-0795 N1 (CHK-T6-0795B): a root-only file or folder reached through a
// link was checked only at the end of the chain. A hop in a folder the
// agent can write could be swapped after the check. Every hop is checked
// now: a link is followed only when the folder that holds it is root's
// alone; links in root's folders still resolve.
func TestGAP0795LinkHopsAreRootOnly(t *testing.T) {
	base, agent := gap0795Tree(t)
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	if git, err = filepath.EvalSymlinks(git); err != nil || !rootOnlyFile(git) {
		t.Skip("git is not a root-only file here")
	}
	sys, dir := filepath.Join(base, "sys"), filepath.Join(base, "rootdir")
	for _, d := range []string{sys, dir} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Files: sys/ok is a link of root's in a root-only folder; sys/hop leads
	// through a link in the agent's folder.
	gap0795Link(t, git, filepath.Join(sys, "ok"), 0)
	gap0795Link(t, git, filepath.Join(agent, "git"), 65534)
	gap0795Link(t, filepath.Join(agent, "git"), filepath.Join(sys, "hop"), 0)
	if !rootOnlyFile(filepath.Join(sys, "ok")) {
		t.Error("a link of root's in a root-only folder to a root-only file is refused")
	}
	if rootOnlyFile(filepath.Join(sys, "hop")) {
		t.Error("a file reached through a link in the agent's folder reads as root-only")
	}
	// Folders: base/ok leads to rootdir directly; base/hop through the
	// agent's link agent/d.
	gap0795Link(t, dir, filepath.Join(base, "ok"), 0)
	gap0795Link(t, dir, filepath.Join(agent, "d"), 65534)
	gap0795Link(t, filepath.Join(agent, "d"), filepath.Join(base, "hop"), 0)
	if r, ok := rootOnlyDir(filepath.Join(base, "ok")); !ok || r != dir {
		t.Errorf("rootOnlyDir(link to %s) = %q, %v; want the folder", dir, r, ok)
	}
	if r, ok := rootOnlyDir(filepath.Join(base, "hop")); ok {
		t.Errorf("a folder reached through a link in the agent's folder reads as root-only (%s)", r)
	}
}

// GAP-0795 N2 (CHK-T6-0795B): git runs its helpers (git-remote-https) as
// root from its exec-path folder, which was checked as a folder only. Each
// of its files is checked now: one the agent's user owns ("agent-file"), or
// a link leading through the agent's folder ("agent-link"), refuses the
// root runs (errNoRootGit); root's files ("control") pass.
func TestGAP0795ExecPathFilesAreRootOnly(t *testing.T) {
	for _, name := range []string{"control", "agent-file", "agent-link"} {
		t.Run(name, func(t *testing.T) {
			base, agent := gap0795Tree(t)
			git, err := exec.LookPath("git")
			if err != nil {
				t.Skip("git not installed")
			}
			xbin, xp := filepath.Join(base, "xbin"), filepath.Join(base, "xp")
			for _, d := range []string{xbin, xp} {
				if err := os.Mkdir(d, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// A git of root's that names xp as its exec-path folder.
			body := fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = --exec-path ]; then echo %s; exit 0; fi\nexec %s \"$@\"\n", xp, git)
			if err := os.WriteFile(filepath.Join(xbin, "git"), []byte(body), 0o755); err != nil {
				t.Fatal(err)
			}
			helper := filepath.Join(xp, "git-remote-https")
			switch name {
			case "control", "agent-file":
				if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				if name == "agent-file" {
					if err := os.Lchown(helper, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
			case "agent-link":
				if err := os.WriteFile(filepath.Join(agent, "h"), []byte("#!/bin/sh\n"), 0o755); err != nil {
					t.Fatal(err)
				}
				gap0795Link(t, filepath.Join(agent, "h"), helper, 0)
			}
			old := gitSystemPath
			gitSystemPath = append([]string{xbin}, old...)
			t.Cleanup(func() { gitSystemPath = old })
			t.Setenv("PATH", xbin+":"+os.Getenv("PATH"))
			_, err = gitRelayEnv(context.Background())
			switch {
			case name == "control" && err != nil:
				t.Fatalf("an exec-path folder of root's files is refused: %v", err)
			case name != "control" && !errors.Is(err, errNoRootGit):
				t.Fatalf("gitRelayEnv = %v; want errNoRootGit for an exec-path file the agent can change", err)
			}
		})
	}
}
