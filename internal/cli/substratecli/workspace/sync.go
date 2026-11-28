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

package workspace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// Sync defaults (design B2 2.2, D2-3).
const (
	SyncDebounce        = time.Second
	SyncMaxWait         = 5 * time.Second
	SyncCheckpointEvery = 10 * time.Minute
	SyncStateEvery      = 30 * time.Second
)

// Actor states Sync acts on.
const (
	SyncActorRunning   = "running"
	SyncActorSuspended = "suspended"
	SyncActorGone      = "gone"
)

// SyncOptions configures Sync.
type SyncOptions struct {
	// Push is the push each batch runs (Mode and Op are set by Sync).
	Push PushOptions
	// Events are changed paths; nil watches the copy's folder.
	Events <-chan string
	// State reports the actor's state; nil means always running.
	State func(context.Context) (string, error)
	Out   io.Writer
	// Label is the agent's name in the hints.
	Label string
	// HourBytes caps what is sent in any hour (0: no cap).
	HourBytes int64

	Debounce, MaxWait, CheckpointEvery, StateEvery time.Duration
}

// ErrSyncActorGone ends a sync whose actor was deleted.
var ErrSyncActorGone = errors.New("the agent is gone; sync stopped")

// Sync is a one-way live sync from the laptop folder into the actor. It
// runs until ctx ends or the actor is deleted. Each batch is a push with
// PushTheirs: a conflict is skipped and named once. It takes a restore
// point at the start and then one in each CheckpointEvery window in which
// something was sent. A suspended actor is not woken: changes wait and
// the state is checked every StateEvery while they do. Nothing keeps
// running after it returns.
func Sync(ctx context.Context, opts SyncOptions) error {
	d := func(v, def time.Duration) time.Duration {
		if v > 0 {
			return v
		}
		return def
	}
	debounce, maxWait := d(opts.Debounce, SyncDebounce), d(opts.MaxWait, SyncMaxWait)
	cpEvery, stateEvery := d(opts.CheckpointEvery, SyncCheckpointEvery), d(opts.StateEvery, SyncStateEvery)
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	rec, err := osw.LoadCopy(opts.Push.Start.DataDir, opts.Push.Name)
	if err != nil {
		return err
	}
	ign := newIgnoreCache(ctx, rec.Project, rec.Kind == osw.CopyGit)
	events := opts.Events
	var full <-chan struct{}
	if events == nil {
		w, err := newTreeWatcher(rec.Project, ign)
		if err != nil {
			return fmt.Errorf("watch %s: %w", rec.Project, err)
		}
		defer w.close()
		events, full = w.events, w.full
	}
	s := &syncer{opts: opts, out: out, rec: rec, named: map[string]bool{}, ign: ign}
	if err := s.checkpoint(ctx); err != nil {
		return err
	}
	cpAt := time.Now()
	var (
		pending  bool
		first    time.Time
		timer    = time.NewTimer(time.Hour)
		waitTick *time.Ticker
		waitC    <-chan time.Time
	)
	timer.Stop()
	defer timer.Stop()
	stopWait := func() {
		if waitTick != nil {
			waitTick.Stop()
			waitTick, waitC = nil, nil
		}
	}
	defer stopWait()
	flush := func() error {
		if s.sentSinceCP && time.Since(cpAt) >= cpEvery {
			if err := s.checkpoint(ctx); err != nil {
				fmt.Fprintf(out, "Could not save a restore point: %v\n", err)
			} else {
				cpAt = time.Now()
			}
		}
		waiting, err := s.batch(ctx)
		if err != nil {
			return err
		}
		pending = waiting
		if waiting && waitTick == nil {
			waitTick = time.NewTicker(stateEvery)
			waitC = waitTick.C
		} else if !waiting {
			stopWait()
		}
		return nil
	}
	// Changes made while sync was not running go first.
	if err := flush(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case p, ok := <-events:
			if !ok {
				return nil
			}
			if s.note(p) {
				continue
			}
			now := time.Now()
			if !pending {
				pending, first = true, now
			}
			wait := debounce
			if left := first.Add(maxWait).Sub(now); left < wait {
				wait = max(left, 0)
			}
			if waitTick == nil {
				timer.Reset(wait)
			}
		case <-full:
			full = nil
			fmt.Fprintf(out, "Sync no longer sees new folders: %v. Restart sync to watch them again.\n", errKqueueBound)
		case <-timer.C:
			if err := flush(); err != nil {
				return err
			}
		case <-waitC:
			if err := flush(); err != nil {
				return err
			}
		}
	}
}

type syncer struct {
	opts        SyncOptions
	out         io.Writer
	rec         *osw.CopyRecord
	named       map[string]bool
	cp          string
	sentSinceCP bool
	sent        []sentBytes
	waitShown   bool
	ign         *ignoreCache
}

type sentBytes struct {
	at time.Time
	n  int64
}

func (s *syncer) once(key, line string) {
	if !s.named[key] {
		s.named[key] = true
		fmt.Fprintln(s.out, line)
	}
}

// note names a changed path sync never sends (git internals, package
// caches) once, and reports true for it: it starts no batch.
func (s *syncer) note(p string) bool {
	rel, err := filepath.Rel(s.rec.Project, p)
	if err != nil {
		return false
	}
	if why := syncSkip(filepath.ToSlash(rel)); why != "" {
		s.once("skip:"+why, "Not synced: "+why+".")
		return true
	}
	// What git ignores never goes (a build writing target/): no batch.
	return s.ign.ignored(filepath.ToSlash(rel))
}

// ignoreCache answers whether git ignores a project path: the folders git
// ignores come from one call at the start, other paths from check-ignore,
// remembered (RV1 P3-4). A plain folder ignores nothing.
type ignoreCache struct {
	ctx  context.Context
	root string
	git  bool
	dirs map[string]bool
	seen map[string]bool
}

// ignoreCacheMax bounds the remembered answers (then they start again).
const ignoreCacheMax = 20000

func newIgnoreCache(ctx context.Context, root string, git bool) *ignoreCache {
	c := &ignoreCache{ctx: ctx, root: root, git: git, dirs: map[string]bool{}, seen: map[string]bool{}}
	if !git {
		return c
	}
	out, err := hostGit(ctx, root, nil, nil, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory")
	if err != nil {
		return c
	}
	for _, e := range strings.Split(string(out), "\x00") {
		if strings.HasSuffix(e, "/") {
			c.dirs[strings.TrimSuffix(e, "/")] = true
		}
	}
	return c
}

func (c *ignoreCache) ignored(rel string) bool {
	if c == nil || !c.git || rel == "" || rel == "." {
		return false
	}
	for d := rel; ; {
		if c.dirs[d] {
			return true
		}
		i := strings.LastIndexByte(d, '/')
		if i < 0 {
			break
		}
		d = d[:i]
	}
	if v, ok := c.seen[rel]; ok {
		return v
	}
	_, err := hostGit(c.ctx, c.root, nil, nil, "check-ignore", "-q", "--", rel)
	v := err == nil
	if len(c.seen) >= ignoreCacheMax {
		c.seen = map[string]bool{}
	}
	c.seen[rel] = v
	return v
}

func (s *syncer) label() string {
	if s.opts.Label != "" {
		return s.opts.Label
	}
	return "NAME"
}

// syncSkip says why sync leaves rel out ("" when it does not).
func syncSkip(rel string) string {
	for _, part := range strings.Split(rel, "/") {
		if part == ".git" {
			return ".git (git internals)"
		}
	}
	if dir := osw.HeavyDirOf(rel + "/x"); dir != "" {
		return strings.TrimSuffix(dir, "/") + " (package cache)"
	}
	return ""
}

func (s *syncer) checkpoint(ctx context.Context) error {
	cp, err := Checkpoint(ctx, CheckpointOptions{Exec: s.opts.Push.Transport, Dir: s.rec.RemoteDir, DataDir: s.opts.Push.Start.DataDir, Name: s.opts.Push.Name, Label: "sync"})
	if err != nil {
		return fmt.Errorf("save a restore point before the sync: %w", err)
	}
	s.cp, s.sentSinceCP = cp.ID, false
	fmt.Fprintf(s.out, "Saved restore point %s (sync).\n", cp.ID)
	return nil
}

// batch runs one push. It reports true when changes wait (the actor is
// suspended or the hourly cap is reached).
func (s *syncer) batch(ctx context.Context) (bool, error) {
	if s.opts.State != nil {
		st, err := s.opts.State(ctx)
		switch {
		case err != nil:
			fmt.Fprintf(s.out, "Could not read the agent's state: %v\n", err)
			return true, nil
		case st == SyncActorGone:
			return false, ErrSyncActorGone
		case st == SyncActorSuspended:
			if !s.waitShown {
				s.waitShown = true
				fmt.Fprintln(s.out, "The agent is suspended; changes wait and go when it wakes.")
			}
			return true, nil
		}
	}
	if s.waitShown {
		s.waitShown = false
		fmt.Fprintln(s.out, "The agent is back; sending the changes that waited.")
	}
	if s.opts.HourBytes > 0 {
		cut := time.Now().Add(-time.Hour)
		var n int64
		kept := s.sent[:0]
		for _, b := range s.sent {
			if b.at.After(cut) {
				kept = append(kept, b)
				n += b.n
			}
		}
		s.sent = kept
		if n >= s.opts.HourBytes {
			s.once("cap", fmt.Sprintf("Sync paused: %s sent in the last hour (the limit is %s). Changes wait.", uploadSize(n), uploadSize(s.opts.HourBytes)))
			return true, nil
		}
		delete(s.named, "cap")
	}
	po := s.opts.Push
	po.Mode, po.Op = osw.PushTheirs, relay.OpSync
	po.NoCheckpoint, po.Checkpoint, po.PatchOut, po.DryRun = true, s.cp, "", false
	res, err := Push(ctx, po)
	if ctx.Err() != nil {
		return false, nil
	}
	if err != nil {
		var refused *HTTPError
		if errors.As(err, &refused) && refused.Reason == "sync_disabled" {
			return false, errors.New("your administrator turned off syncing into a running agent (substrate.files.sync); sync stopped")
		}
		if errors.As(err, &refused) && refused.Reason == "push_disabled" {
			return false, errors.New("your administrator turned off sending changes into a running agent (substrate.files.push), which sync uses; sync stopped")
		}
		var moved *osw.BaselineMovedError
		if errors.As(err, &moved) || errors.Is(err, ErrPushHostCopy) {
			return false, err
		}
		fmt.Fprintf(s.out, "Could not sync: %v\n", err)
		return true, nil
	}
	for _, h := range res.Plan.HeldBack {
		s.once("held:"+h, "Held back: "+h+" (looks like a secret). Share it with: push "+s.label()+" --unmask "+h)
	}
	if res.Result == nil {
		return false, nil
	}
	for _, k := range res.Result.Kept {
		line := fmt.Sprintf("The agent also changed %s; not synced (send it with: push %s --mine %s).", k, s.label(), k)
		for _, c := range res.Plan.Changes {
			if c.Path == k && c.Replaces != "" {
				line = fmt.Sprintf("The agent also changed %s (%s); not synced (send it with: push %s --mine --replace %s).", k, c.ReplaceNote(), s.label(), k)
				break
			}
		}
		s.once("conflict:"+k, line)
	}
	if line := res.SendLine("Synced"); line != "" {
		fmt.Fprintln(s.out, line)
		s.sentSinceCP = true
		s.sent = append(s.sent, sentBytes{at: time.Now(), n: res.Plan.Bytes()})
	}
	return false, nil
}

// treeWatcher reports changed paths under a folder, recursively, leaving
// out .git and package caches.
type treeWatcher struct {
	w      *fsnotify.Watcher
	ign    *ignoreCache
	files  int
	root   string
	events chan string
	// full is closed the first time a folder made during the sync is not
	// watched because of the macOS bound (RV2 N5).
	full     chan struct{}
	saidFull bool
	done     chan struct{}
	exited   chan struct{}
}

// maxKqueueEntries bounds what sync watches on macOS, where the watcher
// (kqueue) holds one open file for every file and folder it watches: past
// it, sync stops with advice instead of "too many open files" (RV1 P3-4).
const maxKqueueEntries = 10000

var errKqueueBound = fmt.Errorf("this folder has more than %d files outside the folders git ignores, and watching them on macOS holds one open file each; send changes with push instead, or ignore build output in .gitignore", maxKqueueEntries)

func newTreeWatcher(root string, ign *ignoreCache) (*treeWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	t := &treeWatcher{w: w, ign: ign, root: root, events: make(chan string, 64), full: make(chan struct{}), done: make(chan struct{}), exited: make(chan struct{})}
	if err := t.addTree(root); err != nil {
		w.Close()
		return nil, err
	}
	go t.run()
	return t, nil
}

func (t *treeWatcher) addTree(dir string) error {
	return filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if p == dir {
				return err
			}
			return nil
		}
		rel, _ := filepath.Rel(t.root, p)
		rel = filepath.ToSlash(rel)
		if !e.IsDir() {
			if runtime.GOOS == "darwin" {
				if t.files++; t.files > maxKqueueEntries {
					return errKqueueBound
				}
			}
			return nil
		}
		if rel != "." && (syncSkip(rel) != "" || t.ign.ignored(rel)) {
			return filepath.SkipDir
		}
		if runtime.GOOS == "darwin" {
			t.files++
		}
		return t.w.Add(p)
	})
}

func (t *treeWatcher) run() {
	defer close(t.exited)
	for {
		select {
		case <-t.done:
			return
		case ev, ok := <-t.w.Events:
			if !ok {
				return
			}
			if ev.Has(fsnotify.Create) {
				if fi, err := os.Lstat(ev.Name); err == nil && fi.IsDir() {
					if err := t.addTree(ev.Name); errors.Is(err, errKqueueBound) && !t.saidFull {
						t.saidFull = true
						close(t.full)
					}
				}
			}
			select {
			case t.events <- ev.Name:
			case <-t.done:
				return
			default: // a batch is due anyway; drop the duplicate
			}
		case _, ok := <-t.w.Errors:
			if !ok {
				return
			}
		}
	}
}

func (t *treeWatcher) close() {
	close(t.done)
	_ = t.w.Close()
	<-t.exited
}
