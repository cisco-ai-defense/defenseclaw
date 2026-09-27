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
	var c collector
	g, err := New(Options{Root: root, Baseline: baseline, OnDetect: c.add, Now: fixedNow, Gitlinks: noLinks})
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
	// A second sweep finds nothing new; a repeat .git in the same folder
	// gets a fresh name.
	g.sweep(".")
	if n := len(c.list()); n != 2 {
		t.Fatalf("second sweep detections = %d", n)
	}
	mkdir(t, filepath.Join(root, "a", "b", ".git"))
	g.mu.Lock()
	delete(g.known, "a/b")
	g.mu.Unlock()
	g.sweep(".")
	got = c.list()
	if len(got) != 3 || got[2].Quarantined == got[0].Quarantined && got[0].Dir == "a/b" || !strings.HasSuffix(got[2].Quarantined, "-1") {
		t.Fatalf("repeat quarantine = %+v", got)
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
	if _, err := quarantine(root, "loop", QuarantinePrefix+"x"); err == nil {
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
	name, err := quarantine(root, "sub", QuarantinePrefix+"y")
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(root, "sub", name)); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("renamed entry = %v, %v; want the symlink itself", info, err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatal("the symlink target was touched")
	}
	if _, err := quarantine(root, "../x", "n"); err == nil {
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
