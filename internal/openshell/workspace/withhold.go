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
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// A git copy ships part of the project's history, and with it every
// committed version of a file that copy mode holds back from the working
// tree: an agent could read a tracked secret with `git show HEAD:<path>`
// or `git log -p`. withholdHistory therefore rebuilds the staged
// repository's object store without those blobs. The commits and trees
// are untouched (same object names, so pushes, fetches and the host's
// merge keep working), and the one pack left is marked as a partial
// clone's promisor pack, which is how git itself represents a repository
// with blobs it was never sent. Its promisor remote has no URL, so a
// command that needs one of the blobs in the sandbox fails with "could not
// fetch ... from promisor remote" instead of reading it. The full object
// store stays on the host and becomes base.git's after the upload.
const (
	// withheldRemote is the partial-clone promisor of such a copy.
	withheldRemote = "defenseclaw-withheld"
	// withheldObjectsDir, under the stage root (never uploaded), keeps
	// the complete object store until uploadStaged moves it into base.git.
	withheldObjectsDir = ".dc-objects"
	withheldPackDir    = ".dc-pack"
)

// withholdHistory drops from the staged repository sg (at stage, inside
// stageRoot) every blob that sits, somewhere in the staged history, at a
// path withheld reports true for. A blob that a shipped path still needs
// (at HEAD or in the baseline, under a name that is not withheld) is kept:
// the agent can read that file anyway, and git needs its object. It
// returns how many blobs were left out. It must run after every object of
// the copy has been written.
func withholdHistory(ctx context.Context, sg gitCmd, stage, stageRoot string, withheld func(rel string) bool) (int, error) {
	raw, err := sg.output(ctx, "log", "--all", "--format=", "--raw", "-z", "--no-abbrev", "--no-renames", "-m", "--root")
	if err != nil {
		return 0, err
	}
	// Each change is ":<old mode> <new mode> <old oid> <new oid> <status>"
	// and then its path; commits are separated by empty records. The first
	// commit of the shallow history is diffed against nothing (--root), so
	// every blob the copy holds appears as some change's new side.
	drop := map[string]struct{}{}
	parts := splitNUL(raw)
	for i := 0; i+1 < len(parts); i++ {
		head, ok := strings.CutPrefix(strings.TrimLeft(parts[i], "\n"), ":")
		meta := strings.Fields(head)
		if !ok || len(meta) < 5 {
			continue
		}
		rel := parts[i+1]
		i++
		if mode, oid := meta[1], meta[3]; mode != modeGitlink && strings.Trim(oid, "0") != "" && withheld(rel) {
			drop[oid] = struct{}{}
		}
	}
	if len(drop) == 0 {
		return 0, nil
	}
	for _, rev := range []string{"HEAD", baselineRef} {
		if _, code, err := sg.outputCode(ctx, "rev-parse", "-q", "--verify", rev+"^{tree}"); err != nil || code != 0 {
			continue
		}
		listing, err := sg.output(ctx, "ls-tree", "-r", "-z", "--full-tree", rev)
		if err != nil {
			return 0, err
		}
		for _, entry := range splitNUL(listing) {
			meta, rel, ok := strings.Cut(entry, "\t")
			if f := strings.Fields(meta); ok && len(f) == 3 && !withheld(rel) {
				delete(drop, f[2])
			}
		}
	}
	if len(drop) == 0 {
		return 0, nil
	}

	objects, err := sg.output(ctx, "rev-list", "--objects", "--all")
	if err != nil {
		return 0, err
	}
	// Lines are "<oid>[ <path>]"; the path only guides delta search. A
	// path with a line break splits its line, and the fragment, which does
	// not start with an object name, is skipped.
	var keep bytes.Buffer
	for _, line := range strings.Split(string(objects), "\n") {
		oid, _, _ := strings.Cut(line, " ")
		if !isOID(oid) {
			continue
		}
		if _, dropped := drop[oid]; !dropped {
			keep.WriteString(line)
			keep.WriteByte('\n')
		}
	}
	packDir := filepath.Join(stageRoot, withheldPackDir)
	if err := os.Mkdir(packDir, 0o700); err != nil {
		return 0, err
	}
	defer os.RemoveAll(packDir)
	g := sg
	g.stdin = &keep
	hash, err := g.line(ctx, "pack-objects", "-q", filepath.Join(packDir, "pack"))
	if err != nil {
		return 0, fmt.Errorf("workspace: repack the copy without held-back history: %w", err)
	}
	if !isOID(hash) {
		return 0, fmt.Errorf("workspace: pack-objects printed %q", hash)
	}
	packed, err := filepath.Glob(filepath.Join(packDir, "pack-"+hash+".*"))
	if err != nil || len(packed) == 0 {
		return 0, fmt.Errorf("workspace: the repacked copy is missing")
	}

	store := filepath.Join(stage, ".git", "objects")
	if err := os.Rename(store, filepath.Join(stageRoot, withheldObjectsDir)); err != nil {
		return 0, err
	}
	for _, d := range []string{store, filepath.Join(store, "pack"), filepath.Join(store, "info")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return 0, err
		}
	}
	for _, p := range packed {
		if err := os.Rename(p, filepath.Join(store, "pack", filepath.Base(p))); err != nil {
			return 0, err
		}
	}
	if err := os.WriteFile(filepath.Join(store, "pack", "pack-"+hash+".promisor"), nil, 0o644); err != nil {
		return 0, err
	}
	// pack.window=0: a thin pack (a push, or the pull's bundle) tries the
	// prerequisite's blob at a changed path as a delta base, and dies when
	// that blob was withheld. Without a delta search it never reads it.
	for _, kv := range [][2]string{{"core.repositoryformatversion", "1"}, {"extensions.partialClone", withheldRemote}, {"pack.window", "0"}} {
		if err := sg.run(ctx, "config", kv[0], kv[1]); err != nil {
			return 0, err
		}
	}
	return len(drop), nil
}

// restoreWithheldObjects gives base.git, the staged repository after its
// upload, the complete object store withholdHistory set aside, and makes
// it an ordinary repository again. It does nothing for a copy that
// withheld nothing.
func restoreWithheldObjects(ctx context.Context, stageRoot, base string) error {
	full := filepath.Join(stageRoot, withheldObjectsDir)
	if !pathExists(full) {
		return nil
	}
	store := filepath.Join(base, "objects")
	partial := store + ".partial"
	if err := os.Rename(store, partial); err != nil {
		return err
	}
	if err := os.Rename(full, store); err != nil {
		_ = os.Rename(partial, store)
		return err
	}
	if err := os.RemoveAll(partial); err != nil {
		return err
	}
	g := gitCmd{dir: filepath.Dir(base), gitDir: base}
	for _, key := range []string{"extensions.partialClone", "pack.window"} {
		// Exit status 5: the key was not set.
		var ge *GitError
		if err := g.run(ctx, "config", "--unset", key); err != nil && !(errors.As(err, &ge) && ge.ExitCode == 5) {
			return err
		}
	}
	return nil
}

// secretByName reports whether the hold-back name rules (secret
// directories, operator masks, built-in secret names) cover rel.
func secretByName(patterns []string, rel string) bool {
	for _, part := range strings.Split(path.Dir(rel), "/") {
		if isSecretDirName(part) {
			return true
		}
	}
	if _, ok := matchAny(patterns, rel); ok {
		return true
	}
	_, ok := isSecretName(rel)
	return ok
}

// unmaskedBy reports whether an operator exception (a path, a directory
// or a glob) keeps rel visible.
func unmaskedBy(unmask []string, rel string) bool {
	for _, u := range unmask {
		dir := strings.ToLower(strings.Trim(u, "/"))
		if matchGlob(u, rel) || strings.EqualFold(dir, rel) || strings.HasPrefix(strings.ToLower(rel), dir+"/") {
			return true
		}
	}
	return false
}
