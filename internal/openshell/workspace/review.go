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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

// ReviewOptions configures Review.
type ReviewOptions struct {
	DataDir string
	Name    string
	// Scanners run on added and modified files. nil means DefaultScanners;
	// a non-nil empty slice runs none.
	Scanners []ContentScanner
	// SensitiveGlobs are extra paths whose change is always flagged (the
	// sandbox pack's workspace.sensitive_changes).
	SensitiveGlobs []string
	// MaxScanBytes skips larger files in scanners (default 1 MiB).
	MaxScanBytes int64
}

// ReviewReport is the end-of-session view of a live-mounted folder.
type ReviewReport struct {
	Name    string       `json:"name"`
	Project string       `json:"project"`
	Kind    SnapshotKind `json:"kind"`
	Changes []TreeChange `json:"changes,omitempty"`
	// FilesChanged, Insertions and Deletions are the diffstat totals.
	FilesChanged int `json:"files_changed"`
	Insertions   int `json:"insertions"`
	Deletions    int `json:"deletions"`
	// Flags are changes that can run code on this machine, most severe
	// first.
	Flags    []Flag        `json:"flags,omitempty"`
	Findings []ScanFinding `json:"findings,omitempty"`

	HeadBefore   string      `json:"head_before,omitempty"`
	HeadAfter    string      `json:"head_after,omitempty"`
	BranchBefore string      `json:"branch_before,omitempty"`
	BranchAfter  string      `json:"branch_after,omitempty"`
	RefChanges   []RefChange `json:"ref_changes,omitempty"`
	// NewIgnored lists paths that became ignored (or new ignored paths)
	// when the session changed ignore rules; they are not in Changes.
	NewIgnored []string `json:"new_ignored,omitempty"`
	Warnings   []string `json:"warnings,omitempty"`
}

// Sensitive reports whether the session changed anything that can run
// code on this machine (high or critical flags) or wrote a critical
// secret.
func (r *ReviewReport) Sensitive() bool {
	for _, f := range r.Flags {
		if f.Severity.rank() >= SeverityHigh.rank() {
			return true
		}
	}
	for _, f := range r.Findings {
		if f.Scanner == "clawshield-secrets" && f.Severity == string(scanner.SeverityCritical) {
			return true
		}
	}
	return false
}

// HostExecLabels lists the labels of medium-or-worse flags, for the
// "Changed files that can run code on your machine" line.
func (r *ReviewReport) HostExecLabels() []string {
	var out []string
	for _, f := range r.Flags {
		if f.Severity.rank() >= SeverityMedium.rank() {
			out = append(out, f.Label)
		}
	}
	return dedupe(out)
}

// SummaryLine is "8 files changed (+212 −37)".
func (r *ReviewReport) SummaryLine() string {
	noun := "files"
	if r.FilesChanged == 1 {
		noun = "file"
	}
	return fmt.Sprintf("%d %s changed (+%d −%d)", r.FilesChanged, noun, r.Insertions, r.Deletions)
}

// RiskLine is the warning line for the end-of-session banner, or "".
func (r *ReviewReport) RiskLine() string {
	labels := r.HostExecLabels()
	if len(labels) == 0 {
		return ""
	}
	return "⚠ Changed files that can run code on your machine: " + strings.Join(firstN(labels, 6), ", ") + "  → review before running"
}

// Review compares the folder with its pre-session snapshot and flags what
// can execute on the host. It does not change the folder.
func Review(ctx context.Context, opts ReviewOptions) (*ReviewReport, error) {
	if !platformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	rec, err := LoadSnapshot(opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	if err := checkProjectPath(rec.Project); err != nil {
		return nil, err
	}
	if opts.Scanners == nil {
		opts.Scanners = DefaultScanners()
	}
	if opts.MaxScanBytes <= 0 {
		opts.MaxScanBytes = defaultMaxScanBytes
	}
	rep := &ReviewReport{Name: rec.Name, Project: rec.Project, Kind: rec.Kind}
	man, err := loadIgnored(opts.DataDir, opts.Name)
	if err != nil {
		rep.Warnings = append(rep.Warnings, "the record of the files the snapshot does not copy is unreadable ("+err.Error()+"); changes there are not reported")
	}
	now, err := scanSentinels(rec.Project, skipList(rec))
	if err != nil {
		return nil, err
	}
	switch rec.Kind {
	case SnapshotGit:
		err = reviewGit(ctx, rec, man, now, opts, rep)
	case SnapshotCopy:
		err = reviewCopy(rec, man, now, opts, rep)
	default:
		err = fmt.Errorf("workspace: snapshot %s has unknown kind %q", rec.Name, rec.Kind)
	}
	if err != nil {
		return nil, err
	}
	reviewSentinels(rec, man, now, opts, rep)
	rep.Flags = sortFlags(rep.Flags)
	for _, c := range rep.Changes {
		if c.NewMode == "040000" || (c.OldMode == "040000" && c.NewMode == "") {
			continue
		}
		rep.FilesChanged++
		rep.Insertions += c.Added
		rep.Deletions += c.Deleted
	}
	return rep, nil
}

func reviewGit(ctx context.Context, rec *SnapshotRecord, man *ignoredManifest, now *sentinelScan, opts ReviewOptions, rep *ReviewReport) error {
	gs := rec.Git
	st, err := openSession(ctx, rec, "defenseclaw: working tree at review of sandbox session "+rec.Name, false)
	if err != nil {
		return err
	}
	defer st.unlock()
	rep.Warnings = append(rep.Warnings, st.warnings...)
	if rep.Changes, err = diffTrees(ctx, st.sh.bare(), gs.Tree, st.postTree); err != nil {
		return err
	}
	if man != nil {
		nowRoots, _ := st.sh.ignoredEntries(ctx, maxIgnoredFiles+1)
		reviewIgnored(rec, man, nowRoots, now, rep)
	}
	blobs := blobReader{g: st.sh.bare()}
	var oids []string
	for _, c := range rep.Changes {
		if c.OldOID != "" {
			oids = append(oids, c.OldOID)
		}
		if c.NewOID != "" {
			oids = append(oids, c.NewOID)
		}
	}
	data, err := blobs.read(ctx, oids, opts.MaxScanBytes)
	if err != nil {
		return err
	}
	content := func(c TreeChange, after bool) ([]byte, bool) {
		oid := c.OldOID
		if after {
			oid = c.NewOID
		}
		b, ok := data[oid]
		return b, ok
	}
	rep.Flags = append(rep.Flags, classifyChanges(rep.Changes, content, opts.SensitiveGlobs)...)
	rep.Findings = scanChanges(rep.Changes, opts.Scanners, content)

	if !st.gitDirOK {
		rep.Flags = append(rep.Flags, Flag{Path: ".git", Label: ".git", Kind: RiskGitControl, Severity: SeverityCritical,
			Detail: "the git directory was replaced during the session; a planted .git can run code the next time git (or a git-aware shell prompt) runs here — undo is refused until it is inspected"})
		return nil
	}
	rep.HeadBefore, rep.BranchBefore = gs.Head, gs.Branch
	rep.HeadAfter, rep.BranchAfter = st.head, st.branch
	rep.RefChanges = refChanges(gs.Refs, st.refs)
	control, err := controlChanges(gs)
	if err != nil {
		return err
	}
	for _, rel := range control {
		rep.Flags = append(rep.Flags, Flag{Path: ".git/" + rel, Label: ".git/" + rel, Kind: RiskGitControl, Severity: SeverityCritical,
			Detail: "git control file changed; it changes what git on this machine reads or runs (undo restores it)"})
	}
	for _, rel := range pinnedChanges(rec) {
		rep.Flags = append(rep.Flags, Flag{Path: rel, Label: rel, Kind: RiskGitControl, Severity: SeverityMedium,
			Detail: "changed during the session although it is read-only inside the sandbox, so the change was made on this machine"})
	}
	if touchesIgnoreRules(rep.Changes) {
		now, err := st.sh.ignoredEntries(ctx, maxIgnoredEntries)
		if err == nil {
			before := toSet(gs.Ignored)
			for _, e := range now {
				if _, ok := before[strings.TrimSuffix(e, "/")]; ok {
					continue
				}
				if _, ok := before[e]; ok {
					continue
				}
				rep.NewIgnored = append(rep.NewIgnored, e)
			}
		}
		if len(rep.NewIgnored) > 0 {
			rep.Flags = append(rep.Flags, Flag{Path: ".gitignore", Label: ".gitignore", Kind: RiskIgnoreRules, Severity: SeverityMedium,
				Detail: fmt.Sprintf("ignore rules changed; %d newly ignored path(s) are not in this diff: %s", len(rep.NewIgnored), strings.Join(firstN(rep.NewIgnored, 5), ", "))})
		}
	}
	return nil
}

func touchesIgnoreRules(changes []TreeChange) bool {
	for _, c := range changes {
		if path.Base(c.Path) == ".gitignore" {
			return true
		}
	}
	return false
}

func scanChanges(changes []TreeChange, scanners []ContentScanner, content contentFunc) []ScanFinding {
	if len(scanners) == 0 {
		return nil
	}
	var out []ScanFinding
	scanned := 0
	for _, c := range changes {
		if c.Status == "D" || c.Binary || c.NewMode == modeGitlink || c.NewMode == modeSymlink || c.NewMode == "040000" {
			continue
		}
		b, ok := content(c, true)
		if !ok || looksBinary(b) {
			continue
		}
		if scanned++; scanned > maxScannedFiles {
			break
		}
		out = append(out, runScanners(scanners, c.Path, b)...)
	}
	return out
}

func reviewCopy(rec *SnapshotRecord, man *ignoredManifest, now *sentinelScan, opts ReviewOptions, rep *ReviewReport) error {
	changes, _, _, err := compareTrees(rec.Copy, rec.Project)
	if err != nil {
		return err
	}
	rep.Changes = changes
	if man != nil {
		reviewIgnored(rec, man, now.heavy, now, rep)
	}
	content := func(c TreeChange, after bool) ([]byte, bool) {
		root := rec.Copy.Dir
		if after {
			root = rec.Project
		}
		p := filepath.Join(root, filepath.FromSlash(c.Path))
		if (after && c.NewMode == modeSymlink) || (!after && c.OldMode == modeSymlink) {
			t, err := os.Readlink(p)
			return []byte(t), err == nil
		}
		b, err := readSmallRegular(p, opts.MaxScanBytes+1)
		if err != nil || int64(len(b)) > opts.MaxScanBytes {
			return nil, false
		}
		return b, true
	}
	rep.Flags = append(rep.Flags, classifyChanges(changes, content, opts.SensitiveGlobs)...)
	rep.Findings = scanChanges(changes, opts.Scanners, content)
	return nil
}

// reviewIgnored flags what the session changed where the snapshot holds no
// copy (see ignoredManifest); nowRoots are those places now. Sentinel
// files are left to reviewSentinels.
func reviewIgnored(rec *SnapshotRecord, man *ignoredManifest, nowRoots []string, now *sentinelScan, rep *ReviewReport) {
	exclude := changedPaths(rep.Changes)
	for rel := range now.files {
		exclude[rel] = struct{}{}
	}
	for rel := range rec.Sentinels {
		exclude[rel] = struct{}{}
	}
	irep, err := diffIgnored(rec.Project, man, nowRoots, nil, exclude)
	if err != nil {
		rep.Warnings = append(rep.Warnings, "could not check the files the snapshot does not copy: "+err.Error())
		return
	}
	git := rec.Kind == SnapshotGit
	flags, quiet := ignoredFlags(irep.Changes, git)
	rep.Flags = append(rep.Flags, flags...)
	if len(quiet) > 0 {
		what := "Files git ignores"
		if !git {
			what = "Files in directories the undo snapshot does not copy"
		}
		rep.Warnings = append(rep.Warnings, what+" changed during the session in "+strings.Join(firstN(quiet, 5), ", ")+"; they are not in the diff and undo leaves them")
	}
	if w := ignoredWarning(irep, git); w != "" {
		rep.Warnings = append(rep.Warnings, w)
	}
}

func changedPaths(changes []TreeChange) map[string]struct{} {
	out := make(map[string]struct{}, len(changes))
	for _, c := range changes {
		out[c.Path] = struct{}{}
	}
	return out
}

// reviewSentinels uses the re-walk of the folder (now) for host-executable
// files that the tree diff cannot see (ignored by git), new nested
// repositories and changed dependency directories.
func reviewSentinels(rec *SnapshotRecord, man *ignoredManifest, now *sentinelScan, opts ReviewOptions, rep *ReviewReport) {
	inDiff := map[string]struct{}{}
	for _, c := range rep.Changes {
		inDiff[c.Path] = struct{}{}
	}
	var extra []TreeChange
	states := map[string][2]FileState{}
	for rel, after := range now.files {
		before := rec.Sentinels[rel]
		if before.equal(after) {
			continue
		}
		if _, ok := inDiff[rel]; ok {
			continue
		}
		c := TreeChange{Path: rel, Status: "M", OldMode: stateMode(before), NewMode: stateMode(after)}
		if !before.Exists {
			c.Status, c.OldMode = "A", ""
		}
		extra = append(extra, c)
		states[rel] = [2]FileState{before, after}
	}
	for rel, before := range rec.Sentinels {
		if _, ok := now.files[rel]; ok || !before.Exists {
			continue
		}
		if _, ok := inDiff[rel]; ok {
			continue
		}
		extra = append(extra, TreeChange{Path: rel, Status: "D", OldMode: stateMode(before)})
	}
	sort.Slice(extra, func(i, j int) bool { return extra[i].Path < extra[j].Path })
	if len(extra) > 0 {
		content := func(c TreeChange, after bool) ([]byte, bool) {
			s := states[c.Path]
			st := s[0]
			if after {
				st = s[1]
			}
			if st.Symlink != "" {
				return []byte(st.Symlink), true
			}
			return st.Content, st.Content != nil
		}
		for _, f := range classifyChanges(extra, content, opts.SensitiveGlobs) {
			f.Detail += " (git ignores this file, so it is not in the diff)"
			rep.Flags = append(rep.Flags, f)
		}
	}
	before := toSet(rec.NestedRepos)
	for _, n := range now.nested {
		if _, ok := before[n]; ok {
			continue
		}
		label := n + "/.git"
		detail := "a git repository was created inside the folder; its config can run code whenever git runs there, including from a git-aware shell prompt (undo removes it)"
		if n == "." && rec.Kind == SnapshotCopy {
			label = ".git"
			detail = "a .git directory was created in this non-git folder; its config can run code the next time git (or a git-aware shell prompt) runs here (undo removes it)"
		}
		rep.Flags = append(rep.Flags, Flag{Path: n, Label: label, Kind: RiskNestedRepo, Severity: SeverityCritical, Detail: detail})
	}
	for dir, fp := range now.deps {
		if old, ok := rec.DependencyDirs[dir]; (ok && old == fp) || man.covers(dir) {
			// Unchanged, or the ignored manifest compares it file by file.
			continue
		}
		rep.Flags = append(rep.Flags, Flag{Path: dir, Label: dir + "/", Kind: RiskDependencies, Severity: SeverityMedium,
			Detail: "packages were installed or changed inside the sandbox; they run on this machine when you use them"})
	}
	if rec.SentinelsCapped || now.capped {
		rep.Warnings = append(rep.Warnings, "the folder is too large to check every file for host-executable changes")
	}
}

func stateMode(s FileState) string {
	switch {
	case !s.Exists:
		return ""
	case s.Symlink != "":
		return modeSymlink
	case s.Dir:
		return "040000"
	case s.Mode&0o111 != 0:
		return modeExec
	default:
		return "100644"
	}
}

// ReviewDiff returns the unified diff of the session's changes (pre-session
// snapshot to the folder now) for the "[d] show diff" prompt.
func ReviewDiff(ctx context.Context, dataDir, name string) ([]byte, error) {
	rec, err := LoadSnapshot(dataDir, name)
	if err != nil {
		return nil, err
	}
	if err := checkProjectPath(rec.Project); err != nil {
		return nil, err
	}
	switch rec.Kind {
	case SnapshotGit:
		st, err := openSession(ctx, rec, "defenseclaw: working tree at review of sandbox session "+rec.Name, false)
		if err != nil {
			return nil, err
		}
		defer st.unlock()
		return st.sh.bare().output(ctx, "diff-tree", "-p", "-r", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color", rec.Git.Tree, st.postTree)
	case SnapshotCopy:
		changes, _, _, err := compareTrees(rec.Copy, rec.Project)
		if err != nil {
			return nil, err
		}
		var out bytes.Buffer
		for i, c := range changes {
			if i >= 500 {
				fmt.Fprintf(&out, "… %d more changed paths\n", len(changes)-i)
				break
			}
			if c.NewMode == "040000" || c.OldMode == "040000" {
				fmt.Fprintf(&out, "%s directory %s\n", map[string]string{"A": "new", "D": "deleted", "T": "replaced"}[c.Status], c.Path)
				continue
			}
			a, b := filepath.Join(rec.Copy.Dir, filepath.FromSlash(c.Path)), filepath.Join(rec.Project, filepath.FromSlash(c.Path))
			if c.Status == "A" {
				a = os.DevNull
			}
			if c.Status == "D" {
				b = os.DevNull
			}
			d, err := noIndexDiff(ctx, filepath.Dir(rec.Copy.Dir), a, b)
			if err != nil {
				return nil, err
			}
			out.Write(d)
		}
		return out.Bytes(), nil
	}
	return nil, fmt.Errorf("workspace: snapshot %s has unknown kind %q", rec.Name, rec.Kind)
}

// noIndexDiff diffs two files outside any repository; exit 1 means they
// differ and is not an error.
func noIndexDiff(ctx context.Context, dir, a, b string) ([]byte, error) {
	out, _, err := gitCmd{dir: dir}.outputCode(ctx, "diff", "--no-index", "--no-ext-diff", "--no-textconv", "--no-color", "--", a, b)
	return out, err
}
