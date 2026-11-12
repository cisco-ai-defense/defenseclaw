// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A local path that reaches a network share through a link on its way (a
// project folder that is a junction to \\server\share) is read only once the
// share answered, as the path that names the share is: the operating system
// opens the link, and the share, in the read (rel-1-0-9:GAP-0621).
type linkedShareFixture struct {
	home, project, share string
	// viaLink is a path below the link; link is the link itself.
	viaLink, link string
}

func newLinkedShareFixture(t *testing.T) linkedShareFixture {
	t.Helper()
	home := t.TempDir()
	project := filepath.Join(home, "project")
	share := t.TempDir()
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(share, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, ".claude")
	if err := os.Symlink(share, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	return linkedShareFixture{home: home, project: project, share: share, link: link, viaLink: filepath.Join(link, "skills")}
}

var linkedShareReads = []struct {
	name string
	read func(string) error
}{
	{"lstat", func(p string) error { _, err := pathLstat(p); return err }},
	{"stat", func(p string) error { _, err := pathStat(p); return err }},
	{"stat pinned", func(p string) error { _, err := pathStatPinned(p); return err }},
	{"open", func(p string) error {
		f, err := pathOpen(p)
		if f != nil {
			f.Close()
		}
		return err
	}},
	{"readdir", func(p string) error { _, err := pathReadDir(p); return err }},
	{"readlink", func(p string) error { _, err := pathReadlink(p); return err }},
	{"evalsymlinks", func(p string) error { _, err := pathEvalSymlinks(p); return err }},
	{"walkdir", func(p string) error {
		var seen error
		_ = pathWalkDir(p, func(_ string, _ os.DirEntry, err error) error { seen = err; return err })
		return seen
	}},
}

func TestAncestorLinkToAShareThatDoesNotAnswerIsAskedBeforeEveryRead(t *testing.T) {
	fx := newLinkedShareFixture(t)
	for _, tc := range linkedShareReads {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			probes := fakeNetworkShare(t, fx.share, 20*time.Millisecond, time.Second, func(string) { <-release })
			start := time.Now()
			err := tc.read(fx.viaLink)
			if took := time.Since(start); took > time.Second {
				t.Fatalf("read through the link held the call %v", took)
			}
			if !errors.Is(err, errNetworkShareUnanswered) {
				t.Fatalf("read through the link = %v, want the share error", err)
			}
			if probes.Load() != 1 {
				t.Fatalf("%d probes, want one", probes.Load())
			}
		})
	}
}

// The link as the last component is opened by stat and read, not by lstat,
// readlink and a directory walk.
func TestFinalLinkToAShareThatDoesNotAnswerIsOpenedOnlyByTheReadsThatFollowIt(t *testing.T) {
	fx := newLinkedShareFixture(t)
	for _, tc := range linkedShareReads {
		t.Run(tc.name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			probes := fakeNetworkShare(t, fx.share, 20*time.Millisecond, time.Second, func(string) { <-release })
			err := tc.read(fx.link)
			follows := tc.name != "lstat" && tc.name != "readlink" && tc.name != "walkdir"
			if follows != errors.Is(err, errNetworkShareUnanswered) || follows != (probes.Load() == 1) {
				t.Fatalf("final link read = %v with %d probes; follows the link: %v", err, probes.Load(), follows)
			}
		})
	}
}

// Every shape of link on the way is asked: a relative target, a chain of
// links, and a path that goes on with ".." after the link.
func TestLinkChainsToAShareThatDoesNotAnswerAreAsked(t *testing.T) {
	fx := newLinkedShareFixture(t)
	hop := filepath.Join(fx.home, "hop")
	if err := os.Symlink(fx.link, hop); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	relative := filepath.Join(fx.home, "relative")
	if err := os.MkdirAll(relative, 0o700); err != nil {
		t.Fatal(err)
	}
	relativeLink := filepath.Join(relative, "up")
	if rel, err := filepath.Rel(relative, fx.link); err != nil {
		t.Skip("no relative target")
	} else if err := os.Symlink(rel, relativeLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	for name, path := range map[string]string{
		"chain":    filepath.Join(hop, "skills"),
		"relative": filepath.Join(relativeLink, "skills"),
		"dotdot":   filepath.Join(fx.link, "skills", "..", "skills"),
	} {
		t.Run(name, func(t *testing.T) {
			release := make(chan struct{})
			defer close(release)
			probes := fakeNetworkShare(t, fx.share, 20*time.Millisecond, time.Second, func(string) { <-release })
			if _, err := pathStat(path); !errors.Is(err, errNetworkShareUnanswered) || probes.Load() != 1 {
				t.Fatalf("stat %s = %v with %d probes, want the share error after one probe", name, err, probes.Load())
			}
		})
	}
}

// Benign twins: a link to a local folder, and a link to a share that
// answers, read as before.
func TestLinkToALocalFolderOrAShareThatAnswersIsRead(t *testing.T) {
	fx := newLinkedShareFixture(t)
	local := t.TempDir()
	if err := os.MkdirAll(filepath.Join(local, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	localLink := filepath.Join(fx.project, "local")
	if err := os.Symlink(local, localLink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	probes := fakeNetworkShare(t, fx.share, 200*time.Millisecond, time.Second, func(string) {})
	for _, tc := range linkedShareReads {
		if tc.name == "readlink" {
			continue
		}
		if err := tc.read(filepath.Join(localLink, "skills")); err != nil {
			t.Fatalf("%s through a link to a local folder = %v", tc.name, err)
		}
	}
	if probes.Load() != 0 {
		t.Fatalf("a link to a local folder cost %d probes", probes.Load())
	}
	for _, tc := range linkedShareReads {
		if tc.name == "readlink" {
			continue
		}
		if err := tc.read(fx.viaLink); err != nil {
			t.Fatalf("%s through a link to a share that answers = %v", tc.name, err)
		}
	}
	if probes.Load() != 1 {
		t.Fatalf("a share that answers was asked %d times, want once", probes.Load())
	}
}

// The project skill root behind such a link reads as unreadable, the
// classification of a root that cannot be read, within the answer wait; an
// ordinary root beside it is untouched.
func TestProjectSkillRootBehindALinkToAShareThatDoesNotAnswerIsUnreadable(t *testing.T) {
	fx := newLinkedShareFixture(t)
	ordinary := filepath.Join(fx.home, "plain", ".claude", "skills")
	if err := os.MkdirAll(ordinary, 0o700); err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	probes := fakeNetworkShare(t, fx.share, 20*time.Millisecond, time.Second, func(string) { <-release })
	for _, root := range []string{fx.viaLink, fx.link} {
		start := time.Now()
		if got := inspectProjectSkillRoot(fx.home, root); got != ProjectSkillRootUnreadable {
			t.Fatalf("root %s = %q, want %q", root, got, ProjectSkillRootUnreadable)
		}
		if took := time.Since(start); took > time.Second {
			t.Fatalf("root %s held the call %v", root, took)
		}
	}
	if probes.Load() != 1 {
		t.Fatalf("%d probes, want one for the share", probes.Load())
	}
	if got := inspectProjectSkillRoot(fx.home, ordinary); got != "" {
		t.Fatalf("ordinary root = %q, want no finding", got)
	}
}
