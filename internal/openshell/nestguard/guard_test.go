// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package nestguard

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type collector struct {
	mu  sync.Mutex
	got []Detection
}

func (c *collector) add(d Detection) {
	c.mu.Lock()
	c.got = append(c.got, d)
	c.mu.Unlock()
}

func (c *collector) list() []Detection {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Detection(nil), c.got...)
}

func (c *collector) wait(t *testing.T, n int) []Detection {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := c.list(); len(got) >= n {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d detections, have %+v", n, c.list())
	return nil
}

func realTemp(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, p, content string) {
	t.Helper()
	mkdir(t, filepath.Dir(p))
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

var fixedNow = func() time.Time { return time.Date(2026, 9, 27, 10, 0, 0, 0, time.UTC) }

func noLinks(context.Context, string) ([]string, error) { return nil, nil }

func TestTakeBaseline(t *testing.T) {
	root := realTemp(t)
	mkdir(t, filepath.Join(root, ".git", "objects"))
	mkdir(t, filepath.Join(root, "vendor", "lib", ".git"))
	write(t, filepath.Join(root, "worktree", ".git"), "gitdir: /elsewhere\n")
	mkdir(t, filepath.Join(root, "node_modules", "dep", ".git"))
	mkdir(t, filepath.Join(root, "src", QuarantinePrefix+"20260101T000000Z"))
	outside := realTemp(t)
	mkdir(t, filepath.Join(outside, "evil", ".git"))
	if err := os.Symlink(filepath.Join(outside, "evil"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	b, err := TakeBaseline(context.Background(), root, 0, func(context.Context, string) ([]string, error) {
		return []string{"third_party/sub"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{".", "node_modules/dep", "vendor/lib", "worktree"}
	if !slices.Equal(b.Repos, want) {
		t.Fatalf("baseline repos = %v, want %v (symlinks not followed)", b.Repos, want)
	}
	if !slices.Equal(b.Gitlinks, []string{"third_party/sub"}) {
		t.Fatalf("baseline gitlinks = %v", b.Gitlinks)
	}
	nonGit := realTemp(t)
	b, err = TakeBaseline(context.Background(), nonGit, 0, func(context.Context, string) ([]string, error) {
		t.Fatal("gitlinks read for a non-git folder")
		return nil, nil
	})
	if err != nil || len(b.Repos) != 0 {
		t.Fatalf("non-git baseline = %+v, %v", b, err)
	}
}

func TestSweepQuarantinesNewRepositories(t *testing.T) {
	root := realTemp(t)
	mkdir(t, filepath.Join(root, ".git"))
	mkdir(t, filepath.Join(root, "old", ".git"))
	baseline, err := TakeBaseline(context.Background(), root, 0, noLinks)
	if err != nil {
		t.Fatal(err)
	}
	mkdir(t, filepath.Join(root, "a", "b", ".git", "hooks"))
	write(t, filepath.Join(root, "a", "b", ".git", "config"), "[core]\n")
	write(t, filepath.Join(root, "file-repo", ".git"), "gitdir: ../x\n")
	var c, merged collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, OnMerge: merged.add, Now: fixedNow, Gitlinks: noLinks})
	if err != nil {
		t.Fatal(err)
	}
	g.sweep(".")
	got := c.list()
	if len(got) != 2 {
		t.Fatalf("detections = %+v", got)
	}
	for _, d := range got {
		if d.Error != "" || d.Kind != KindRepository || !strings.HasPrefix(filepath.Base(d.Quarantined), QuarantinePrefix+"20260927T100000Z") {
			t.Fatalf("detection = %+v", d)
		}
		if _, err := os.Lstat(filepath.Join(root, d.Dir, GitEntry)); !os.IsNotExist(err) {
			t.Fatalf("%s/.git still exists", d.Dir)
		}
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(d.Quarantined))); err != nil {
			t.Fatalf("quarantined entry %s missing: %v", d.Quarantined, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "a", "b", filepath.Base(got[0].Quarantined), "config")); err != nil && got[0].Dir == "a/b" {
		t.Fatalf("quarantine lost the repository's content: %v", err)
	}
	for _, keep := range []string{".git", "old/.git"} {
		if _, err := os.Lstat(filepath.Join(root, keep)); err != nil {
			t.Fatalf("baseline %s was touched: %v", keep, err)
		}
	}
	// A second sweep finds nothing new; a .git created again in a folder
	// whose first one was quarantined is quarantined too, under a fresh
	// name, and so is a third. Within MergeWindow (the fixed clock) they
	// belong to the first detection.
	g.sweep(".")
	if n := len(c.list()); n != 2 {
		t.Fatalf("second sweep detections = %d", n)
	}
	for i, suffix := range []string{"-1", "-2"} {
		mkdir(t, filepath.Join(root, "a", "b", ".git"))
		g.sweep(".")
		m := merged.list()
		if len(c.list()) != 2 || len(m) != 1+i || m[i].Dir != "a/b" || len(m[i].Also) != 1+i || !strings.HasSuffix(m[i].Also[i], suffix) {
			t.Fatalf("repeat quarantine %d = %+v, merged %+v", i+1, c.list(), m)
		}
		if _, err := os.Lstat(filepath.Join(root, "a", "b", ".git")); !os.IsNotExist(err) {
			t.Fatalf("repeat %d: a/b/.git still exists", i+1)
		}
	}
}

// TestRepeatRepositoryInEventsMode: the events path reaches the same
// folder again after its first .git was quarantined.
func TestRepeatRepositoryInEventsMode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inotify only")
	}
	root := realTemp(t)
	mkdir(t, filepath.Join(root, "src"))
	baseline, _ := TakeBaseline(context.Background(), root, 0, noLinks)
	var c collector
	// A clock the loop moves past MergeWindow: each .git is a repository
	// of its own.
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Mode: ModeEvents, Gitlinks: noLinks, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	waitMode(t, g, ModeEvents)
	for i := 1; i <= 2; i++ {
		mkdir(t, filepath.Join(root, "src", ".git"))
		got := c.wait(t, i)
		if got[i-1].Dir != "src" || got[i-1].Quarantined == "" {
			t.Fatalf("detection %d = %+v", i, got[i-1])
		}
		mu.Lock()
		now = now.Add(MergeWindow + time.Second)
		mu.Unlock()
	}
}

// TestQuarantineRestoresWritePermission: the agent runs as the operator's
// uid and can take write permission off the folder that holds its .git;
// the guard gets it back for the rename and restores the folder's mode.
func TestQuarantineRestoresWritePermission(t *testing.T) {
	root := realTemp(t)
	baseline, _ := TakeBaseline(context.Background(), root, 0, noLinks)
	sub := filepath.Join(root, "sub")
	write(t, filepath.Join(sub, ".git", "config"), "[core]\n")
	if err := os.Chmod(sub, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o755) })
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Now: fixedNow, Gitlinks: noLinks})
	if err != nil {
		t.Fatal(err)
	}
	g.sweep(".")
	got := c.list()
	if len(got) != 1 || got[0].Error != "" || got[0].Quarantined == "" {
		t.Fatalf("detections = %+v", got)
	}
	if _, err := os.Lstat(filepath.Join(sub, ".git")); !os.IsNotExist(err) {
		t.Fatal("sub/.git was not quarantined")
	}
	info, err := os.Stat(sub)
	if err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("sub mode = %v, %v; want the agent's 0555 back", info, err)
	}
}

// TestFailedQuarantineReportedOnce: a quarantine that keeps failing the
// same way is retried on every sweep but reported once, and again when it
// fails differently or the repository comes back after going away.
func TestFailedQuarantineReportedOnce(t *testing.T) {
	root := realTemp(t)
	baseline, _ := TakeBaseline(context.Background(), root, 0, noLinks)
	sub := filepath.Join(root, "sub")
	mkdir(t, filepath.Join(sub, ".git"))
	// Every name the quarantine could use is taken.
	name := QuarantinePrefix + fixedNow().UTC().Format("20060102T150405Z")
	mkdir(t, filepath.Join(sub, name))
	for i := 1; i < 100; i++ {
		mkdir(t, filepath.Join(sub, name+"-"+strconv.Itoa(i)))
	}
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Now: fixedNow, Gitlinks: noLinks})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		g.sweep(".")
	}
	got := c.list()
	if len(got) != 1 || got[0].Error == "" {
		t.Fatalf("detections after three failing sweeps = %+v; want one failure", got)
	}
	if err := os.RemoveAll(filepath.Join(sub, ".git")); err != nil {
		t.Fatal(err)
	}
	g.sweep(".")
	mkdir(t, filepath.Join(sub, ".git"))
	g.sweep(".")
	if got := c.list(); len(got) != 2 || got[1].Error == "" {
		t.Fatalf("detections after the repository came back = %+v", got)
	}
	// Once a name frees up the quarantine succeeds.
	if err := os.Remove(filepath.Join(sub, name+"-99")); err != nil {
		t.Fatal(err)
	}
	g.sweep(".")
	if got := c.list(); len(got) != 3 || got[2].Error != "" || !strings.HasSuffix(got[2].Quarantined, "-99") {
		t.Fatalf("detections after a name freed up = %+v", got)
	}
}

// TestCaseVariantOfGitEntry: on a case-insensitive filesystem git finds
// sub/.GIT as sub/.git, so the guard quarantines it; on a case-sensitive
// one it is an ordinary folder, which the guard leaves alone and looks
// inside.
func TestCaseVariantOfGitEntry(t *testing.T) {
	root := realTemp(t)
	baseline, _ := TakeBaseline(context.Background(), root, 0, noLinks)
	write(t, filepath.Join(root, "sub", ".GIT", "config"), "[core]\n")
	_, err := os.Lstat(filepath.Join(root, "sub", ".git"))
	insensitive := err == nil
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Now: fixedNow, Gitlinks: noLinks})
	if err != nil {
		t.Fatal(err)
	}
	g.sweep(".")
	got := c.list()
	if !insensitive {
		if len(got) != 0 {
			t.Fatalf("case-sensitive filesystem: detections = %+v", got)
		}
		mkdir(t, filepath.Join(root, "sub", ".GIT", "inner", ".git"))
		g.sweep(".")
		if got := c.list(); len(got) != 1 || got[0].Dir != "sub/.GIT/inner" {
			t.Fatalf("a repository inside sub/.GIT = %+v", got)
		}
		return
	}
	if len(got) != 1 || got[0].Dir != "sub" || got[0].Quarantined == "" {
		t.Fatalf("case-insensitive filesystem: detections = %+v", got)
	}
	if _, err := os.Lstat(filepath.Join(root, "sub", ".GIT")); !os.IsNotExist(err) {
		t.Fatal("sub/.GIT was not quarantined")
	}
	// The baseline recognizes the spelling too.
	write(t, filepath.Join(root, "old", ".Git", "config"), "[core]\n")
	if b, err := TakeBaseline(context.Background(), root, 0, noLinks); err != nil || !slices.Contains(b.Repos, "old") {
		t.Fatalf("baseline = %+v, %v", b, err)
	}
}

// TestTruncatedBaselineLeavesOlderRepositories: a project too large for
// the baseline scan has repositories the baseline does not list. One the
// guard reaches later is left alone when its .git is older than the
// session, and quarantined when it is newer.
func TestTruncatedBaselineLeavesOlderRepositories(t *testing.T) {
	root := realTemp(t)
	for i := 0; i < 20; i++ {
		write(t, filepath.Join(root, "a", "f"+strconv.Itoa(i)), "x")
	}
	mkdir(t, filepath.Join(root, "z", ".git"))
	baseline, err := TakeBaseline(context.Background(), root, 10, noLinks)
	if err != nil || !baseline.Truncated || slices.Contains(baseline.Repos, "z") || baseline.At.IsZero() {
		t.Fatalf("baseline = %+v, %v; want a truncated one without z", baseline, err)
	}
	run := func(at time.Time) []Detection {
		b := baseline
		b.At = at
		var c collector
		g, err := New(Options{Root: root, Baseline: b, OnDetect: c.add, Now: fixedNow, Gitlinks: noLinks})
		if err != nil {
			t.Fatal(err)
		}
		g.sweep(".")
		g.sweep(".")
		return c.list()
	}
	// The session started after z/.git was made.
	if got := run(time.Now().Add(time.Minute)); len(got) != 0 {
		t.Fatalf("an older repository was quarantined: %+v", got)
	}
	if _, err := os.Lstat(filepath.Join(root, "z", ".git")); err != nil {
		t.Fatal("z/.git was moved")
	}
	// The session started before it.
	if got := run(time.Now().Add(-time.Minute)); len(got) != 1 || got[0].Dir != "z" || got[0].Quarantined == "" {
		t.Fatalf("a newer repository = %+v", got)
	}
	// A complete baseline never exempts anything.
	baseline.Truncated = false
	mkdir(t, filepath.Join(root, "z", ".git"))
	if got := run(time.Now().Add(time.Minute)); len(got) != 1 || got[0].Dir != "z" {
		t.Fatalf("complete baseline = %+v", got)
	}
}

func TestTopLevelRepositoryInNonGitFolder(t *testing.T) {
	root := realTemp(t)
	baseline, _ := TakeBaseline(context.Background(), root, 0, noLinks)
	mkdir(t, filepath.Join(root, ".git"))
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Now: fixedNow, Gitlinks: noLinks})
	if err != nil {
		t.Fatal(err)
	}
	g.sweep(".")
	got := c.list()
	if len(got) != 1 || got[0].Dir != "." || got[0].Label() != ".git" || got[0].Quarantined == "" {
		t.Fatalf("detections = %+v", got)
	}
	if _, err := os.Lstat(filepath.Join(root, ".git")); !os.IsNotExist(err) {
		t.Fatal("top-level .git not quarantined")
	}
}

// TestQuarantineRefusesSymlinkedParents: an agent that swaps a directory on
// the path for a symlink after the scan must not get the guard to rename a
// .git entry elsewhere (here the project's own repository).
func TestQuarantineRefusesSymlinkedParents(t *testing.T) {
	root := realTemp(t)
	mkdir(t, filepath.Join(root, ".git"))
	if err := os.Symlink(".", filepath.Join(root, "loop")); err != nil {
		t.Fatal(err)
	}
	if _, err := quarantine(root, "loop", QuarantinePrefix+"x", time.Time{}); err == nil {
		t.Fatal("quarantine followed a symlinked directory")
	}
	if _, err := os.Lstat(filepath.Join(root, ".git")); err != nil {
		t.Fatal("the project repository was renamed through a symlink")
	}
	// A .git symlink itself is renamed, not followed.
	target := filepath.Join(realTemp(t), "gitdir")
	mkdir(t, target)
	mkdir(t, filepath.Join(root, "sub"))
	if err := os.Symlink(target, filepath.Join(root, "sub", ".git")); err != nil {
		t.Fatal(err)
	}
	name, err := quarantine(root, "sub", QuarantinePrefix+"y", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(root, "sub", name)); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("renamed entry = %v, %v; want the symlink itself", info, err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("the symlink target was touched")
	}
	if _, err := quarantine(root, "../x", "n", time.Time{}); err == nil {
		t.Fatal("a path outside the root was accepted")
	}
}

func TestRunEventsDetectsNewRepositories(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inotify only")
	}
	testRun(t, ModeEvents)
}

func TestRunPollDetectsNewRepositories(t *testing.T) {
	testRun(t, ModePoll)
}

func testRun(t *testing.T, mode Mode) {
	root := realTemp(t)
	mkdir(t, filepath.Join(root, ".git"))
	mkdir(t, filepath.Join(root, "src"))
	baseline, _ := TakeBaseline(context.Background(), root, 0, noLinks)
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Mode: mode, PollInterval: 50 * time.Millisecond, Gitlinks: noLinks})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()
	waitMode(t, g, mode)

	mkdir(t, filepath.Join(root, "src", "deep", "er", ".git"))
	got := c.wait(t, 1)
	if got[0].Dir != "src/deep/er" || got[0].Quarantined == "" {
		t.Fatalf("detection = %+v", got[0])
	}
	// A tree moved in whole: the event is for its top directory only.
	staged := filepath.Join(realTemp(t), "pkg")
	mkdir(t, filepath.Join(staged, "inner", ".git"))
	if err := os.Rename(staged, filepath.Join(root, "src", "pkg")); err != nil {
		t.Skipf("cross-device rename: %v", err)
	}
	got = c.wait(t, 2)
	if got[1].Dir != "src/pkg/inner" {
		t.Fatalf("moved-in detection = %+v", got[1])
	}
	if _, err := os.Lstat(filepath.Join(root, ".git")); err != nil {
		t.Fatal("the project repository was quarantined")
	}
}

func waitMode(t *testing.T, g *Guard, want Mode) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for g.Mode() != want {
		if time.Now().After(deadline) {
			t.Fatalf("mode = %q, want %q", g.Mode(), want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Let the initial watch setup and sweep finish.
	time.Sleep(100 * time.Millisecond)
}

// runGuard starts g and stops it when the test ends.
func runGuard(t *testing.T, g *Guard, mode Mode) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	})
	waitMode(t, g, mode)
}

// mkdirMode creates dir with exactly mode and gives it 0755 back at
// cleanup so the test directory can be removed.
func mkdirMode(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
}

func skipRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads and watches every folder")
	}
}

// TestEventsWatchFolderCreatedUnreadable: the agent runs as the operator's
// uid and can create a folder without the read permission a watch needs.
// When it makes the folder readable later, the guard watches it then and
// quarantines a .git created inside, although no event came from it
// before. The poll interval is far away, so the mode change does it.
func TestEventsWatchFolderCreatedUnreadable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inotify only")
	}
	skipRoot(t)
	root := realTemp(t)
	baseline, _ := TakeBaseline(context.Background(), root, 0, noLinks)
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Mode: ModeEvents, PollInterval: time.Hour, Gitlinks: noLinks})
	if err != nil {
		t.Fatal(err)
	}
	runGuard(t, g, ModeEvents)

	dir := filepath.Join(root, "late")
	mkdirMode(t, dir, 0)
	time.Sleep(200 * time.Millisecond)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	mkdir(t, filepath.Join(dir, ".git"))
	got := c.wait(t, 1)
	if got[0].Dir != "late" || got[0].Quarantined == "" {
		t.Fatalf("detection = %+v", got[0])
	}
}

// TestRepositoryInUnlistableFolder: a folder with search and write but no
// read permission can be neither listed nor watched, yet host git finds a
// .git in it by path. The guard looks it up by name, in both modes, and
// on Linux renames it through the folder as host git would reach it. One
// that existed before the session is left alone.
func TestRepositoryInUnlistableFolder(t *testing.T) {
	skipRoot(t)
	modes := []Mode{ModePoll}
	if runtime.GOOS == "linux" {
		modes = append(modes, ModeEvents)
	}
	for _, mode := range modes {
		t.Run(string(mode), func(t *testing.T) {
			root := realTemp(t)
			old := filepath.Join(root, "old")
			mkdir(t, filepath.Join(old, ".git"))
			if err := os.Chmod(old, 0o311); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(old, 0o755) })
			baseline, err := TakeBaseline(context.Background(), root, 0, noLinks)
			if err != nil || !slices.Equal(baseline.Repos, []string{"old"}) {
				t.Fatalf("baseline = %+v, %v; want the repository in the unlistable folder", baseline, err)
			}
			var c collector
			g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Mode: mode, PollInterval: 50 * time.Millisecond, Gitlinks: noLinks})
			if err != nil {
				t.Fatal(err)
			}
			runGuard(t, g, mode)

			dir := filepath.Join(root, "hidden")
			mkdirMode(t, dir, 0o300)
			time.Sleep(100 * time.Millisecond)
			if err := os.Mkdir(filepath.Join(dir, ".git"), 0o755); err != nil {
				t.Fatal(err)
			}
			got := c.wait(t, 1)
			if got[0].Dir != "hidden" {
				t.Fatalf("detection = %+v", got[0])
			}
			if runtime.GOOS == "linux" {
				if got[0].Quarantined == "" {
					t.Fatalf("not quarantined: %+v", got[0])
				}
				if _, err := os.Lstat(filepath.Join(dir, ".git")); !os.IsNotExist(err) {
					t.Fatal("hidden/.git is still in place")
				}
				if info, err := os.Lstat(dir); err != nil || info.Mode().Perm() != 0o300 {
					t.Fatalf("hidden mode = %v, %v; want the agent's 0300 kept", info, err)
				}
			}
			if _, err := os.Lstat(filepath.Join(old, ".git")); err != nil {
				t.Fatal("the pre-session repository was quarantined")
			}
			if n := len(c.list()); n != 1 {
				t.Fatalf("detections = %+v", c.list())
			}
		})
	}
}

// TestManyUnwatchableFoldersFallBackToPolling: events mode rechecks every
// folder it could not watch on each interval; past maxUnwatched that is a
// sweep, so the guard polls instead.
func TestManyUnwatchableFoldersFallBackToPolling(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inotify only")
	}
	skipRoot(t)
	root := realTemp(t)
	for i := 0; i <= maxUnwatched; i++ {
		mkdirMode(t, filepath.Join(root, "d"+strconv.Itoa(i)), 0)
	}
	var c collector
	g, err := New(Options{Root: root, OnDetect: c.add, Mode: ModeEvents, PollInterval: 50 * time.Millisecond, Gitlinks: noLinks})
	if err != nil {
		t.Fatal(err)
	}
	runGuard(t, g, ModePoll)
}

func TestWatchLimitFallsBackToPolling(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("inotify only")
	}
	root := realTemp(t)
	for _, d := range []string{"a", "b", "c", "d"} {
		mkdir(t, filepath.Join(root, d))
	}
	var logs []string
	var mu sync.Mutex
	var c collector
	g, err := New(Options{Root: root, OnDetect: c.add, Mode: ModeEvents, MaxWatches: 2, PollInterval: 50 * time.Millisecond,
		Gitlinks: noLinks, Logf: func(f string, a ...any) { mu.Lock(); logs = append(logs, f); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = g.Run(ctx) }()
	waitMode(t, g, ModePoll)
	mkdir(t, filepath.Join(root, "c", ".git"))
	if got := c.wait(t, 1); got[0].Dir != "c" {
		t.Fatalf("detection = %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(logs) == 0 || !strings.Contains(strings.Join(logs, " "), "polling") {
		t.Fatalf("no fallback notice: %v", logs)
	}
}

func TestGitlinks(t *testing.T) {
	root := realTemp(t)
	mkdir(t, filepath.Join(root, ".git"))
	links := []string{"old"}
	var mu sync.Mutex
	read := func(context.Context, string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), links...), nil
	}
	baseline, _ := TakeBaseline(context.Background(), root, 0, read)
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Gitlinks: read, Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	g.checkGitlinks(context.Background())
	if n := len(c.list()); n != 0 {
		t.Fatalf("baseline gitlink reported: %+v", c.list())
	}
	mu.Lock()
	links = append(links, "evil/sub")
	mu.Unlock()
	g.checkGitlinks(context.Background())
	g.checkGitlinks(context.Background())
	got := c.list()
	if len(got) != 1 || got[0].Kind != KindGitlink || got[0].Dir != "evil/sub" || got[0].Label() != "evil/sub (gitlink)" {
		t.Fatalf("gitlink detections = %+v", got)
	}
}

// TestRunOnceSweepsAndReturns pins the final pass: Run with Once
// quarantines what appeared since the baseline, reports new gitlinks and
// returns without watching.
func TestRunOnceSweepsAndReturns(t *testing.T) {
	root := realTemp(t)
	mkdir(t, filepath.Join(root, ".git"))
	baseline, err := TakeBaseline(context.Background(), root, 0, noLinks)
	if err != nil {
		t.Fatal(err)
	}
	mkdir(t, filepath.Join(root, "late", ".git"))
	links := func(context.Context, string) ([]string, error) { return []string{"late/sub"}, nil }
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Now: fixedNow, Gitlinks: links, Once: true})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- g.Run(context.Background()) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run with Once kept watching")
	}
	got := c.list()
	if len(got) != 2 || got[0].Kind != KindRepository || got[0].Dir != "late" || got[1].Kind != KindGitlink {
		t.Fatalf("detections = %+v", got)
	}
	if _, err := os.Lstat(filepath.Join(root, "late", ".git")); !os.IsNotExist(err) {
		t.Fatal("the late repository was not quarantined")
	}
}

func TestParseGitlinks(t *testing.T) {
	out := "100644 0123456789012345678901234567890123456789 0\tREADME.md\x00" +
		"160000 abcdefabcdefabcdefabcdefabcdefabcdefabcd 0\tvendor/sub\x00" +
		"160000 abcdefabcdefabcdefabcdefabcdefabcdefabcd 0\tpath with\ttab\x00"
	got := parseGitlinks([]byte(out))
	if !slices.Equal(got, []string{"vendor/sub", "path with\ttab"}) {
		t.Fatalf("gitlinks = %q", got)
	}
}

func TestGitGitlinksAgainstRealGit(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	root := realTemp(t)
	run := func(args ...string) {
		cmd := exec.Command(gitBin, append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid"}, args...)...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	write(t, filepath.Join(root, "a.txt"), "a\n")
	run("add", "a.txt")
	run("update-index", "--add", "--cacheinfo", "160000,1234567890123456789012345678901234567890,mod/sub")
	got, err := GitGitlinks(context.Background(), root)
	if err != nil || !slices.Equal(got, []string{"mod/sub"}) {
		t.Fatalf("GitGitlinks = %v, %v", got, err)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Options{Root: "relative", OnDetect: func(Detection) {}}); err == nil {
		t.Error("relative root accepted")
	}
	if _, err := New(Options{Root: "/tmp"}); err == nil {
		t.Error("missing OnDetect accepted")
	}
}
