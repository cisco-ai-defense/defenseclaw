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

package nestguard

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/defenseclaw/defenseclaw/internal/gitsafe"
)

// defaultMode picks inotify on Linux. fsnotify's kqueue backend (macOS,
// BSD) holds a descriptor for every watched file, so polling is cheaper
// there.
func defaultMode() Mode {
	if runtime.GOOS == "linux" {
		return ModeEvents
	}
	return ModePoll
}

// runEvents watches every directory of the project. It returns errFallback
// when the watch limit is reached, so Run continues by polling.
func (g *Guard) runEvents(ctx context.Context) error {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		g.opts.Logf("nested-repository guard: file events unavailable (%v); polling instead", err)
		return errFallback
	}
	defer w.Close()
	g.setMode(ModeEvents)
	watches := 0
	add := func(dir string) error {
		if watches >= g.opts.MaxWatches {
			return errWatchLimit
		}
		if err := w.Add(dir); err != nil {
			if errors.Is(err, syscall.ENOSPC) || errors.Is(err, syscall.EMFILE) {
				return errWatchLimit
			}
			return err
		}
		watches++
		return nil
	}
	// watchTree adds every directory under dir; it returns errWatchLimit
	// when the limit is hit.
	watchTree := func(dir string) error {
		count := 0
		return filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if d != nil && d.IsDir() && p != dir {
					return fs.SkipDir
				}
				if p == dir {
					return walkErr
				}
				return nil
			}
			if !d.IsDir() {
				return nil
			}
			count++
			if count > g.opts.MaxEntries {
				return errWatchLimit
			}
			if p != dir && g.skipDir(d.Name()) {
				return fs.SkipDir
			}
			if err := add(p); err != nil {
				if errors.Is(err, errWatchLimit) {
					return err
				}
				// A directory that vanished or cannot be read: skip it.
				return fs.SkipDir
			}
			return nil
		})
	}
	if err := watchTree(g.opts.Root); err != nil {
		if errors.Is(err, errWatchLimit) {
			g.opts.Logf("nested-repository guard: the project has more directories than the file-watch limit; polling instead")
			return errFallback
		}
		return err
	}
	// The project's own .git directory is watched (not recursively) for
	// index rewrites, which may add gitlinks.
	gitDir := filepath.Join(g.opts.Root, GitEntry)
	if info, err := os.Lstat(gitDir); err == nil && info.IsDir() && containsString(g.opts.Baseline.Repos, ".") {
		if err := add(gitDir); errors.Is(err, errWatchLimit) {
			return errFallback
		}
	}
	// Anything created between the baseline and the first watch.
	g.sweep(".")
	g.checkGitlinks(ctx)

	var indexTimer *time.Timer
	indexDue := make(chan struct{}, 1)
	defer func() {
		if indexTimer != nil {
			indexTimer.Stop()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-indexDue:
			g.checkGitlinks(ctx)
		case err, ok := <-w.Errors:
			if !ok {
				return errFallback
			}
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				// Events were lost: sweep everything.
				g.sweep(".")
				continue
			}
			g.opts.Logf("nested-repository guard: %v", err)
		case ev, ok := <-w.Events:
			if !ok {
				return errFallback
			}
			if !ev.Has(fsnotify.Create) && !ev.Has(fsnotify.Rename) && !ev.Has(fsnotify.Write) {
				continue
			}
			rel, err := filepath.Rel(g.opts.Root, ev.Name)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, GitEntry+"/") {
				// The project's own .git directory: only the index matters.
				if rel == GitEntry+"/index" && (ev.Has(fsnotify.Create) || ev.Has(fsnotify.Write)) {
					if indexTimer == nil {
						indexTimer = time.AfterFunc(indexSettle, func() {
							select {
							case indexDue <- struct{}{}:
							default:
							}
						})
					} else {
						indexTimer.Reset(indexSettle)
					}
				}
				continue
			}
			if !ev.Has(fsnotify.Create) {
				continue
			}
			base := filepath.Base(ev.Name)
			if base == GitEntry {
				g.handle(filepath.ToSlash(filepath.Dir(rel)))
				continue
			}
			info, err := os.Lstat(ev.Name)
			if err != nil || !info.IsDir() || g.skipDir(base) {
				continue
			}
			// A new or moved-in directory: watch it and check whatever
			// arrived with it.
			if err := watchTree(ev.Name); errors.Is(err, errWatchLimit) {
				g.opts.Logf("nested-repository guard: the file-watch limit was reached; polling instead")
				return errFallback
			}
			g.sweep(rel)
		}
	}
}

var errWatchLimit = errors.New("nestguard: file-watch limit reached")

// GitGitlinks lists the gitlinks (mode 160000) of the index of the git
// repository at root, through gitsafe so no repository configuration can
// run code.
func GitGitlinks(ctx context.Context, root string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd, err := gitsafe.Command(ctx, root, "ls-files", "--stage", "-z")
	if err != nil {
		return nil, err
	}
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		return nil, errors.New("git ls-files: " + strings.TrimSpace(stderr.String()))
	}
	return parseGitlinks(out.Bytes()), nil
}

// parseGitlinks reads `git ls-files --stage -z` output.
func parseGitlinks(out []byte) []string {
	var links []string
	for _, rec := range bytes.Split(out, []byte{0}) {
		meta, name, ok := bytes.Cut(rec, []byte{'\t'})
		if !ok || !bytes.HasPrefix(meta, []byte("160000 ")) {
			continue
		}
		links = append(links, string(name))
	}
	return links
}
