// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package protectedfiles is the gateway's protected-file watch (#1172).
//
// The hook decides from a tool call's text, and a program that runs other
// programs (a script, xargs, find -exec, make, a git option) can write a
// file the text never names. The watch is the layer after the hook: it
// polls a short list of files that grant persistence (SSH authorized keys,
// shell startup files, user autostart entries) in each watched home, and
// when one changes while an agent tool call runs for that user it reports
// the change with the agent session it can name. A change with no agent
// tool call running is the user's own and is only recorded. In restore
// mode (opt-in) the watch also puts back the last content it accepted.
//
// A file is watched by its path, so a write through another hard link of
// it, and a rename over it, are both seen.
package protectedfiles

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// Path classes, for the audit row.
const (
	ClassAuthorizedKeys = "authorized_keys"
	ClassShellRC        = "shell_rc"
	ClassAutostart      = "autostart"
	ClassOther          = "other"
)

// Digest values that are not content.
const (
	digestAbsent = "absent"
)

const (
	// DefaultInterval is the poll period.
	DefaultInterval = 2 * time.Second
	// maxFileBytes bounds what one poll reads of a file.
	maxFileBytes = 1 << 20
	// maxDirEntries bounds the entries of one watched directory.
	maxDirEntries = 64
	// maxHomes bounds the homes one gateway watches.
	maxHomes     = 256
	stateVersion = 1
	stateName    = "protected-files.json"
	copiesName   = "protected-files"
)

// DefaultPaths are the home-relative names watched on goos when
// guardrail.protected_files.paths is unset. A trailing "/" watches the
// entries of a directory (one level).
func DefaultPaths(goos string) []string {
	keys := []string{".ssh/authorized_keys", ".ssh/authorized_keys2"}
	shell := []string{".bashrc", ".bash_profile", ".profile", ".zshrc"}
	switch goos {
	case "windows":
		return keys
	case "darwin":
		return append(append(keys, shell...), "Library/LaunchAgents/")
	default:
		return append(append(keys, shell...), ".config/systemd/user/", ".config/autostart/")
	}
}

// ClassOf names the class of a home-relative watched name.
func ClassOf(rel string) string {
	rel = filepath.ToSlash(rel)
	switch {
	case strings.HasPrefix(rel, ".ssh/authorized_keys") || strings.HasSuffix(rel, "administrators_authorized_keys"):
		return ClassAuthorizedKeys
	case strings.HasPrefix(rel, ".config/systemd/user/") || strings.HasPrefix(rel, ".config/autostart/") ||
		strings.HasPrefix(rel, "Library/LaunchAgents/"):
		return ClassAutostart
	case strings.HasPrefix(rel, ".") && !strings.Contains(rel, "/"):
		return ClassShellRC
	}
	return ClassOther
}

// Change is one change the watch saw.
type Change struct {
	At    time.Time
	Path  string
	Home  string
	Class string
	// Before and After are "sha256:" and 12 hex of the content, or
	// "absent"; never the content.
	Before, After string
	// Attributed is true when an agent tool call ran for the home.
	Attributed bool
	Session    Session
	// Restored is true when restore mode put the accepted content back.
	Restored     bool
	RestoreError string
}

// Options configure a Watcher.
type Options struct {
	// Restore puts back the accepted content of an attributed change.
	Restore bool
	// Paths are home-relative names (DefaultPaths when empty).
	Paths []string
	// System are absolute paths watched once, attributed to any home's
	// agent (Windows administrators_authorized_keys on a managed host).
	System []string
	// StateDir keeps the accepted digests (and, with Restore, copies).
	// Empty keeps them in memory only.
	StateDir string
	Interval time.Duration
	Activity *Activity
	Emit     func(Change)
	Now      func() time.Time
	// Restorable reports whether the watch may write path back. Nil allows
	// a path whose directory this process owns (restorableDefault).
	Restorable func(path string) bool
}

type entry struct {
	home, class string
	digest      string // accepted digest
}

// Watcher polls the protected files of the homes added to it.
type Watcher struct {
	opts     Options
	mu       sync.Mutex
	homes    map[string]bool
	files    map[string]*entry // path -> accepted state
	dirs     map[string]entry  // watched directory path -> home/class
	stored   map[string]string // digests read from the state file
	lastScan time.Time
	dirty    bool
}

// New returns a Watcher. It reads the state file once.
func New(opts Options) *Watcher {
	if len(opts.Paths) == 0 {
		opts.Paths = DefaultPaths(runtime.GOOS)
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Restorable == nil {
		opts.Restorable = restorableDefault
	}
	w := &Watcher{opts: opts, homes: map[string]bool{}, files: map[string]*entry{}, dirs: map[string]entry{}, stored: map[string]string{}}
	w.readState()
	for _, p := range opts.System {
		if filepath.IsAbs(p) {
			w.track(filepath.Clean(p), "", ClassAuthorizedKeys)
		}
	}
	return w
}

// AddHome starts watching home. The first time a path is seen its current
// content is accepted, unless the state file holds an earlier digest of it
// (a change while the gateway was stopped is then reported, unattributed).
func (w *Watcher) AddHome(home string) {
	if w == nil || home == "" || !filepath.IsAbs(home) {
		return
	}
	home = filepath.Clean(home)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.homes[home] || len(w.homes) >= maxHomes {
		return
	}
	w.homes[home] = true
	for _, rel := range w.opts.Paths {
		rel = filepath.FromSlash(rel)
		class := ClassOf(filepath.ToSlash(rel))
		full := filepath.Join(home, strings.TrimSuffix(rel, string(filepath.Separator)))
		if strings.HasSuffix(filepath.ToSlash(rel), "/") {
			w.dirs[full] = entry{home: home, class: class}
			for _, child := range listDir(full) {
				w.track(child, home, class)
			}
			continue
		}
		w.track(full, home, class)
	}
}

// Homes returns the watched homes.
func (w *Watcher) Homes() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.homes))
	for home := range w.homes {
		out = append(out, home)
	}
	sort.Strings(out)
	return out
}

// track accepts path's current state unless it is tracked already. Called
// with mu held.
func (w *Watcher) track(path, home, class string) {
	if _, ok := w.files[path]; ok {
		return
	}
	digest, ok := w.stored[path]
	if !ok {
		digest = digestOf(path)
		w.dirty = true
	}
	w.files[path] = &entry{home: home, class: class, digest: digest}
	if w.opts.Restore && digest == digestOf(path) {
		w.saveCopy(path, digest)
	}
}

// Run polls until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	ticker := time.NewTicker(w.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.Scan()
		}
	}
}

// Scan polls every watched path once and reports each change.
func (w *Watcher) Scan() {
	w.mu.Lock()
	now := w.opts.Now()
	from := w.lastScan
	if from.IsZero() {
		from = now.Add(-w.opts.Interval)
	}
	w.lastScan = now
	for dir, e := range w.dirs {
		for _, child := range listDir(dir) {
			if _, ok := w.files[child]; !ok {
				// A new entry: it was absent until now.
				w.files[child] = &entry{home: e.home, class: e.class, digest: digestAbsent}
				w.dirty = true
			}
		}
	}
	type pending struct {
		path   string
		e      *entry
		before string
		after  string
	}
	var changes []pending
	for path, e := range w.files {
		if after := digestOf(path); after != e.digest {
			changes = append(changes, pending{path, e, e.digest, after})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].path < changes[j].path })
	var out []Change
	for _, c := range changes {
		change := Change{At: now, Path: c.path, Home: c.e.home, Class: c.e.class, Before: short(c.before), After: short(c.after)}
		change.Session, change.Attributed = w.opts.Activity.Attribute(c.e.home, from, now)
		accepted := c.after
		if change.Attributed && w.opts.Restore {
			if err := w.restore(c.path, c.before); err != nil {
				change.RestoreError = err.Error()
			} else if digestOf(c.path) == c.before {
				change.Restored, accepted = true, c.before
			} else {
				change.RestoreError = "the file changed again while it was restored"
			}
		}
		c.e.digest = accepted
		w.dirty = true
		if w.opts.Restore && !change.Restored && !change.Attributed {
			// The user's own change becomes the content to restore.
			w.saveCopy(c.path, accepted)
		}
		out = append(out, change)
	}
	if w.dirty {
		w.writeState()
	}
	emit := w.opts.Emit
	w.mu.Unlock()
	if emit != nil {
		for _, change := range out {
			emit(change)
		}
	}
}

func short(digest string) string {
	if strings.HasPrefix(digest, "sha256:") && len(digest) > len("sha256:")+12 {
		return digest[:len("sha256:")+12]
	}
	return digest
}

// digestOf is the state of path without following a final symlink: its
// content's sha256, a symlink's target, or absent. A FIFO or device is
// never opened.
func digestOf(path string) string {
	info, err := os.Lstat(path)
	if err != nil {
		return digestAbsent
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		target, err := os.Readlink(path)
		if err != nil {
			return "link:unreadable"
		}
		sum := sha256.Sum256([]byte(target))
		return "link:sha256:" + hex.EncodeToString(sum[:])
	case info.IsDir():
		return "dir"
	case !info.Mode().IsRegular():
		return "special"
	}
	file, err := openNoFollow(path)
	if err != nil {
		return "unreadable"
	}
	defer file.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return "unreadable"
	}
	if n > maxFileBytes {
		return fmt.Sprintf("large:%d:%d", info.Size(), info.ModTime().UnixNano())
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// listDir lists a watched directory's entries, one level, bounded.
func listDir(dir string) []string {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if len(out) >= maxDirEntries {
			break
		}
		if e.IsDir() {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	return out
}

type stateFile struct {
	Version int               `json:"version"`
	Files   map[string]string `json:"files"`
}

func (w *Watcher) readState() {
	if w.opts.StateDir == "" {
		return
	}
	data, err := os.ReadFile(filepath.Join(w.opts.StateDir, stateName))
	if err != nil {
		return
	}
	var st stateFile
	if json.Unmarshal(data, &st) != nil || st.Version != stateVersion {
		return
	}
	for path, digest := range st.Files {
		if filepath.IsAbs(path) && digest != "" {
			w.stored[path] = digest
		}
	}
}

// writeState saves the accepted digests (mu held).
func (w *Watcher) writeState() {
	w.dirty = false
	if w.opts.StateDir == "" {
		return
	}
	st := stateFile{Version: stateVersion, Files: map[string]string{}}
	// Digests of homes not added yet in this run (a managed gateway adds a
	// home at its first hook call) are kept as they were read.
	for path, digest := range w.stored {
		st.Files[path] = digest
	}
	for path, e := range w.files {
		st.Files[path] = e.digest
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = writeAtomic(filepath.Join(w.opts.StateDir, stateName), data, 0o600)
}

func (w *Watcher) copyPath(path string) string {
	sum := sha256.Sum256([]byte(path))
	return filepath.Join(w.opts.StateDir, copiesName, hex.EncodeToString(sum[:16]))
}

// saveCopy keeps the content of path whose digest is digest, for restore
// (mu held). An absent file keeps no copy: restoring it removes the file.
func (w *Watcher) saveCopy(path, digest string) {
	if w.opts.StateDir == "" || !strings.HasPrefix(digest, "sha256:") {
		if w.opts.StateDir != "" {
			_ = os.Remove(w.copyPath(path))
		}
		return
	}
	file, err := openNoFollow(path)
	if err != nil {
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil || len(data) > maxFileBytes {
		return
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return
	}
	dir := filepath.Join(w.opts.StateDir, copiesName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	_ = writeAtomic(w.copyPath(path), data, 0o600)
}

// restore puts back the accepted state of path (mu held).
func (w *Watcher) restore(path, accepted string) error {
	if !w.opts.Restorable(path) {
		return errors.New("restore is not allowed for this path")
	}
	if accepted == digestAbsent {
		info, err := os.Lstat(path)
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return errors.New("a directory now has the name")
		}
		return os.Remove(path)
	}
	if !strings.HasPrefix(accepted, "sha256:") || w.opts.StateDir == "" {
		return errors.New("no saved copy")
	}
	data, err := os.ReadFile(w.copyPath(path))
	if err != nil {
		return errors.New("no saved copy")
	}
	sum := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(sum[:]) != accepted {
		return errors.New("the saved copy does not match")
	}
	mode := os.FileMode(0o600)
	if info, err := os.Lstat(path); err == nil {
		if info.IsDir() {
			return errors.New("a directory now has the name")
		}
		if info.Mode().IsRegular() {
			mode = info.Mode().Perm()
		}
	}
	return writeAtomic(path, data, mode)
}

// writeAtomic writes data to a temporary file next to path and renames it
// over path, so a reader never sees a partial file and a symlink at path is
// replaced, not followed.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".dc-protected-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	if werr == nil {
		werr = tmp.Sync()
	}
	cerr := tmp.Close()
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Chmod(name, mode)
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		_ = os.Remove(name)
	}
	return werr
}
