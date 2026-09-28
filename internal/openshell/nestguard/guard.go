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

// Package nestguard is the live nested-repository guard of a live-mounted
// sandbox project. A sandboxed agent can write anywhere in the mounted
// folder, including a new `.git` directory (or `.git` file) whose config
// runs code the next time the operator's git, or a git-aware shell prompt,
// touches that directory on the host (core.fsmonitor, hooks, filters). The
// guard watches the project while the sandbox runs and, the moment a new
// `.git` entry appears at any depth (the top level of a non-git folder
// included), renames it to `.git.defenseclaw-quarantine-<timestamp>` with
// no-follow operations inside the project root, so no host git ever reads
// it. It also reports new gitlink (mode 160000) entries in the project's
// index. Detection uses inotify where available and falls back to a
// bounded periodic scan when the watch limit is reached (and on platforms
// whose file-event API needs a descriptor per file). Symlinks are never
// followed.
package nestguard

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// GitEntry is the name the guard watches for.
const GitEntry = ".git"

// QuarantinePrefix starts the name a quarantined .git entry is renamed to.
const QuarantinePrefix = ".git.defenseclaw-quarantine-"

// Defaults.
const (
	DefaultPollInterval = 5 * time.Second
	DefaultMaxWatches   = 32768
	DefaultMaxEntries   = 500000
	// indexSettle debounces index rewrites before gitlinks are checked.
	indexSettle = 500 * time.Millisecond
)

// Kind classifies a detection.
type Kind string

const (
	// KindRepository is a new .git directory, file or symlink.
	KindRepository Kind = "repository"
	// KindGitlink is a new gitlink (submodule, mode 160000) in the
	// project's index.
	KindGitlink Kind = "gitlink"
)

// Mode is how the guard observes the project.
type Mode string

const (
	ModeEvents Mode = "events"
	ModePoll   Mode = "poll"
)

// Detection is one nested repository the guard found.
type Detection struct {
	Kind Kind `json:"kind"`
	// Dir is the project-relative directory holding the .git entry ("."
	// for the project folder itself); for a gitlink, the entry's path.
	Dir string `json:"dir"`
	// Quarantined is the project-relative path the .git entry was renamed
	// to; empty for gitlinks and failed quarantines.
	Quarantined string `json:"quarantined,omitempty"`
	// Error is set when the quarantine failed.
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

// Label is the operator-facing name of what was found.
func (d Detection) Label() string {
	if d.Kind == KindGitlink {
		return d.Dir + " (gitlink)"
	}
	if d.Dir == "." {
		return GitEntry
	}
	return d.Dir + "/" + GitEntry
}

// Baseline is what already existed when the session started; the guard
// never touches it.
type Baseline struct {
	// Repos are project-relative directories that held a .git entry ("."
	// for the project's own repository).
	Repos []string `json:"repos,omitempty"`
	// Gitlinks are the gitlink paths in the project's index.
	Gitlinks []string `json:"gitlinks,omitempty"`
	// Truncated reports that the baseline scan stopped at the entry limit.
	Truncated bool `json:"truncated,omitempty"`
	// At is when the baseline scan started. With a truncated baseline, a
	// .git entry the scan did not reach whose status last changed before
	// then existed before the session and is left alone.
	At time.Time `json:"at,omitempty"`
}

// ctimeSlack allows for filesystems that keep change times at a coarser
// grain than the clock the baseline time comes from.
const ctimeSlack = 2 * time.Second

// Options configure a guard.
type Options struct {
	// Root is the absolute, symlink-free project folder. Required.
	Root string
	// Baseline is the session's starting point (see TakeBaseline).
	Baseline Baseline
	// OnDetect receives every detection. Required.
	OnDetect func(Detection)
	// Mode forces events or polling; empty picks events where the
	// platform supports them cheaply (Linux inotify).
	Mode         Mode
	PollInterval time.Duration
	MaxWatches   int
	MaxEntries   int
	// Gitlinks lists the gitlinks of the project's index; nil uses the
	// host git through gitsafe.
	Gitlinks func(ctx context.Context, root string) ([]string, error)
	Now      func() time.Time
	// Logf receives operational messages (fallback to polling, scan
	// errors); nil discards them.
	Logf func(format string, args ...any)
}

// Guard watches one project.
type Guard struct {
	opts Options

	mu sync.Mutex
	// known are the dirs whose .git existed before the session.
	known map[string]bool
	// failed holds, per dir, the error of its last failed quarantine: a
	// quarantine is retried on every sweep or event, and reported again
	// only when it fails differently.
	failed   map[string]string
	gitlinks map[string]bool
	handled  []Detection
	mode     Mode
}

// New validates opts.
func New(opts Options) (*Guard, error) {
	if opts.Root == "" || !filepath.IsAbs(opts.Root) {
		return nil, errors.New("nestguard: an absolute project root is required")
	}
	if opts.OnDetect == nil {
		return nil, errors.New("nestguard: OnDetect is required")
	}
	if !supported() {
		return nil, ErrUnsupported
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.MaxWatches <= 0 {
		opts.MaxWatches = DefaultMaxWatches
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxEntries
	}
	if opts.Gitlinks == nil {
		opts.Gitlinks = GitGitlinks
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	g := &Guard{opts: opts, known: map[string]bool{}, failed: map[string]string{}, gitlinks: map[string]bool{}}
	for _, r := range opts.Baseline.Repos {
		g.known[cleanRel(r)] = true
	}
	for _, l := range opts.Baseline.Gitlinks {
		g.gitlinks[cleanRel(l)] = true
	}
	return g, nil
}

// ErrUnsupported reports a platform without the no-follow primitives the
// quarantine needs.
var ErrUnsupported = errors.New("nestguard: the nested-repository guard is not supported on this platform")

// Mode reports how the guard currently observes the project.
func (g *Guard) Mode() Mode {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.mode
}

// Detections returns everything the guard found so far.
func (g *Guard) Detections() []Detection {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Detection(nil), g.handled...)
}

// Run watches until ctx ends. It first sweeps the project for .git entries
// that appeared since the baseline.
func (g *Guard) Run(ctx context.Context) error {
	info, err := os.Lstat(g.opts.Root)
	if err != nil {
		return fmt.Errorf("nestguard: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("nestguard: %s is not a directory", g.opts.Root)
	}
	mode := g.opts.Mode
	if mode == "" {
		mode = defaultMode()
	}
	if mode == ModeEvents {
		err := g.runEvents(ctx)
		if !errors.Is(err, errFallback) {
			return err
		}
	}
	return g.runPoll(ctx)
}

var errFallback = errors.New("nestguard: fall back to polling")

func (g *Guard) setMode(m Mode) {
	g.mu.Lock()
	g.mode = m
	g.mu.Unlock()
}

// runPoll sweeps the project every interval, stretching the interval when
// a sweep is slow so polling never takes more than about a tenth of the
// time.
func (g *Guard) runPoll(ctx context.Context) error {
	g.setMode(ModePoll)
	interval := g.opts.PollInterval
	var lastIndex time.Time
	for {
		started := time.Now()
		g.sweep(".")
		if mt := g.indexModTime(); !mt.Equal(lastIndex) {
			lastIndex = mt
			g.checkGitlinks(ctx)
		}
		if took := time.Since(started); took*10 > interval {
			interval = took * 10
		}
		t := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
	}
}

// sweep walks rel (no-follow, bounded) and quarantines every .git entry
// that is not known.
func (g *Guard) sweep(rel string) {
	found, truncated, err := scan(g.opts.Root, rel, g.opts.MaxEntries, g.skipDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		g.opts.Logf("nested-repository guard: scan %s: %v", rel, err)
	}
	if truncated {
		g.opts.Logf("nested-repository guard: %s has more than %d entries; only part of it is checked each pass", rel, g.opts.MaxEntries)
	}
	if err == nil && !truncated {
		// A .git whose quarantine failed and that is gone now is a new
		// repository if it comes back.
		seen := make(map[string]bool, len(found))
		for _, dir := range found {
			seen[dir] = true
		}
		g.mu.Lock()
		for dir := range g.failed {
			if within(dir, cleanRel(rel)) && !seen[dir] {
				delete(g.failed, dir)
			}
		}
		g.mu.Unlock()
	}
	for _, dir := range found {
		g.handle(dir)
	}
}

// forgetFailure drops the failed quarantine of dir, whose .git went away.
func (g *Guard) forgetFailure(dir string) {
	g.mu.Lock()
	delete(g.failed, cleanRel(dir))
	g.mu.Unlock()
}

// within reports whether the project-relative dir is rel or below it.
func within(dir, rel string) bool {
	return rel == "." || dir == rel || strings.HasPrefix(dir, rel+"/")
}

// skipDir reports directories the walk must not descend into: .git
// directories themselves (their contents are the repository) and
// quarantined entries.
func (g *Guard) skipDir(name string) bool {
	return name == GitEntry || strings.HasPrefix(name, QuarantinePrefix)
}

// handle quarantines the .git entry in dir unless it existed before the
// session. A dir whose .git was quarantined is watched like any other: a
// .git created there again is quarantined again.
func (g *Guard) handle(dir string) {
	dir = cleanRel(dir)
	g.mu.Lock()
	known := g.known[dir]
	g.mu.Unlock()
	if known {
		return
	}
	// A baseline cut short at the entry limit does not list every
	// repository that existed: one the guard reaches later is left alone
	// when its entry is older than the session.
	var keepBefore time.Time
	if b := g.opts.Baseline; b.Truncated && !b.At.IsZero() {
		keepBefore = b.At.Add(-ctimeSlack)
	}
	now := g.opts.Now()
	d := Detection{Kind: KindRepository, Dir: dir, At: now}
	newName, err := quarantine(g.opts.Root, dir, QuarantinePrefix+now.UTC().Format("20060102T150405Z"), keepBefore)
	g.mu.Lock()
	lastErr, failedBefore := g.failed[dir]
	delete(g.failed, dir)
	switch {
	case errors.Is(err, errPreexisting):
		g.known[dir] = true
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		g.failed[dir] = err.Error()
	}
	g.mu.Unlock()
	switch {
	case errors.Is(err, errPreexisting):
		g.opts.Logf("nested-repository guard: %s is older than the session; left in place (the baseline did not list every repository)", d.Label())
		return
	case errors.Is(err, fs.ErrNotExist):
		// Gone before the guard got to it (git init rolled back, the dir
		// was removed): nothing is left to quarantine.
		return
	case err != nil:
		if failedBefore && lastErr == err.Error() {
			// Retried and failed the same way: already reported.
			return
		}
		d.Error = err.Error()
	default:
		d.Quarantined = path.Join(dir, newName)
	}
	g.record(d)
}

// errPreexisting is quarantine's answer for an entry older than the
// session.
var errPreexisting = errors.New("nestguard: the entry existed before the session")

func (g *Guard) record(d Detection) {
	g.mu.Lock()
	g.handled = append(g.handled, d)
	g.mu.Unlock()
	g.opts.OnDetect(d)
}

// checkGitlinks reports gitlinks added to the project's index.
func (g *Guard) checkGitlinks(ctx context.Context) {
	if !containsString(g.opts.Baseline.Repos, ".") {
		return
	}
	links, err := g.opts.Gitlinks(ctx, g.opts.Root)
	if err != nil {
		g.opts.Logf("nested-repository guard: read the index: %v", err)
		return
	}
	sort.Strings(links)
	for _, l := range links {
		l = cleanRel(l)
		g.mu.Lock()
		seen := g.gitlinks[l]
		g.gitlinks[l] = true
		g.mu.Unlock()
		if !seen {
			g.record(Detection{Kind: KindGitlink, Dir: l, At: g.opts.Now()})
		}
	}
}

func (g *Guard) indexModTime() time.Time {
	info, err := os.Lstat(filepath.Join(g.opts.Root, GitEntry, "index"))
	if err != nil {
		return time.Time{}
	}
	return info.ModTime()
}

// TakeBaseline records the .git entries and gitlinks a project has now.
func TakeBaseline(ctx context.Context, root string, maxEntries int, gitlinks func(context.Context, string) ([]string, error)) (Baseline, error) {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxEntries
	}
	at := time.Now().UTC()
	skip := func(name string) bool { return name == GitEntry || strings.HasPrefix(name, QuarantinePrefix) }
	repos, truncated, err := scan(root, ".", maxEntries, skip)
	if err != nil {
		return Baseline{}, err
	}
	b := Baseline{Repos: repos, Truncated: truncated, At: at}
	if containsString(repos, ".") {
		if gitlinks == nil {
			gitlinks = GitGitlinks
		}
		links, err := gitlinks(ctx, root)
		if err != nil {
			return Baseline{}, err
		}
		b.Gitlinks = links
	}
	return b, nil
}

// scan walks root/rel without following symlinks and returns the
// directories that hold a .git entry (of any type, in any spelling git
// finds it by: see isGitEntry).
func scan(root, rel string, maxEntries int, skip func(string) bool) ([]string, bool, error) {
	start := filepath.Join(root, filepath.FromSlash(rel))
	info, err := os.Lstat(start)
	if err != nil {
		return nil, false, err
	}
	if !info.IsDir() {
		return nil, false, nil
	}
	var found []string
	count := 0
	truncated := false
	err = filepath.WalkDir(start, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			if p == start {
				return walkErr
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		count++
		if count > maxEntries {
			truncated = true
			return fs.SkipAll
		}
		if p == start {
			return nil
		}
		name := d.Name()
		if isGitEntry(p, name) {
			r, err := filepath.Rel(root, filepath.Dir(p))
			if err == nil {
				found = append(found, cleanRel(filepath.ToSlash(r)))
			}
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// WalkDir never follows symlinks; skip what must not be entered.
		if d.IsDir() && skip(name) {
			return fs.SkipDir
		}
		return nil
	})
	sort.Strings(found)
	return found, truncated, err
}

// isGitEntry reports whether the entry at p, named name, is what git finds
// as its directory's .git: that name, or on a case-insensitive filesystem
// (macOS's default) any other spelling of it (.GIT, .Git), which git's
// lookup of .git resolves to.
func isGitEntry(p, name string) bool {
	if name == GitEntry {
		return true
	}
	if !strings.EqualFold(name, GitEntry) {
		return false
	}
	entry, err := os.Lstat(p)
	if err != nil {
		return false
	}
	lookup, err := os.Lstat(filepath.Join(filepath.Dir(p), GitEntry))
	return err == nil && os.SameFile(entry, lookup)
}

func cleanRel(rel string) string {
	rel = path.Clean(filepath.ToSlash(strings.TrimSpace(rel)))
	if rel == "" || rel == "/" {
		return "."
	}
	return strings.TrimPrefix(rel, "./")
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if cleanRel(v) == s {
			return true
		}
	}
	return false
}
