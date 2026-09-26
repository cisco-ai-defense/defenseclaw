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
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CopyKind says how a copy was staged.
type CopyKind string

const (
	// CopyGit is a shallow clone of the project's history plus its working
	// tree; the agent sees a normal repository.
	CopyGit CopyKind = "git"
	// CopyPlain is a non-git folder; DefenseClaw keeps a hidden git dir
	// outside it (/sandbox/.dc/git) for the baseline and the result.
	CopyPlain CopyKind = "plain"
)

const (
	// DefaultRemoteRoot is where copies live inside the sandbox; the
	// project lands at <root>/<repo>. It is under the sandbox HOME, which
	// the sandbox user can write and Landlock allows.
	DefaultRemoteRoot = "/sandbox/work"
	// remoteStateDir holds the hidden git dir and bundles in the sandbox.
	remoteStateDir = "/sandbox/.dc"

	DefaultCopyMaxBytes int64 = 500 << 20
	DefaultGitDepth           = 200

	baselineRef = "refs/defenseclaw/baseline"
	resultRef   = "refs/defenseclaw/result"
	effectRef   = "refs/defenseclaw/effective"
)

// StageOptions configures Stage. Mask and size settings normally come from
// openshell.workdir (masks, unmask, max_upload_mb, git_depth).
type StageOptions struct {
	Project   string
	Name      string
	DataDir   string
	Home      string
	Protected []string
	// RemoteRoot is the sandbox parent directory (DefaultRemoteRoot).
	RemoteRoot string
	// GitDepth is the history depth of the shallow clone (200).
	GitDepth int
	// MaxBytes caps the staged copy, history included (500 MiB).
	MaxBytes int64
	// Masks, Unmask, Detector and DisableContentScan select the secrets
	// that are held back, with the same rules as a live mount's masks
	// (tracked files included: nothing secret leaves the host).
	Masks              []string
	Unmask             []string
	Detector           SecretDetector
	DisableContentScan bool
	// Replace discards an existing copy record of the same name.
	Replace bool
	Now     func() time.Time
}

// CopyRecord is the persisted state of one copy-mode sandbox.
type CopyRecord struct {
	Version  int      `json:"version"`
	Name     string   `json:"name"`
	Project  string   `json:"project"`
	RepoName string   `json:"repo_name"`
	Kind     CopyKind `json:"kind"`
	// RemoteDir is the project inside the sandbox; RemoteGitDir its git
	// dir (RemoteDir/.git, or the hidden /sandbox/.dc/git for plain
	// folders).
	RemoteDir    string `json:"remote_dir"`
	RemoteGitDir string `json:"remote_git_dir"`
	// Stage is the local staged tree until Upload succeeds; BaseGit keeps
	// the uploaded history and baseline for verifying pulls.
	Stage   string `json:"stage,omitempty"`
	BaseGit string `json:"base_git"`
	// Baseline is the commit of the uploaded working tree; Head the commit
	// it was staged from ("" for plain folders and unborn branches).
	Baseline string `json:"baseline"`
	Head     string `json:"head,omitempty"`
	Branch   string `json:"branch,omitempty"`
	// Remotes are the (credential-free) remotes configured in the copy.
	Remotes    map[string]string `json:"remotes,omitempty"`
	HeldBack   []string          `json:"held_back,omitempty"`
	Files      int               `json:"files"`
	Bytes      int64             `json:"bytes"`
	StagedAt   time.Time         `json:"staged_at"`
	UploadedAt *time.Time        `json:"uploaded_at,omitempty"`
	VerifiedAt *time.Time        `json:"verified_at,omitempty"`
	Warnings   []string          `json:"warnings,omitempty"`
}

// Labels are the sandbox labels for a copy-mode sandbox.
func (r *CopyRecord) Labels() map[string]string {
	key, value := ProjectLabel(r.Project)
	return map[string]string{key: value, ModeLabelKey: "copy"}
}

func (l layout) copyDir(name string) string { return filepath.Join(l.sandboxDir(name), "copy") }
func (l layout) copyRecord(name string) string {
	return filepath.Join(l.copyDir(name), "copy.json")
}

// LoadCopy reads the copy-mode record for name.
func LoadCopy(dataDir, name string) (*CopyRecord, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	lay, err := newLayout(dataDir)
	if err != nil {
		return nil, err
	}
	var rec CopyRecord
	if err := readJSON(lay.copyRecord(name), &rec); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrCopyNotFound, name)
		}
		return nil, err
	}
	return &rec, nil
}

func saveCopy(dataDir string, rec *CopyRecord) error {
	lay, err := newLayout(dataDir)
	if err != nil {
		return err
	}
	return writeJSON(lay.copyRecord(rec.Name), rec)
}

// DeleteCopy removes everything copy mode stored for name.
func DeleteCopy(dataDir, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	lay, err := newLayout(dataDir)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(lay.copyDir(name)); err != nil {
		_ = chmodTree(lay.copyDir(name))
		return os.RemoveAll(lay.copyDir(name))
	}
	return nil
}

// Stage prepares a copy of the project for upload: for git projects a
// sanitized shallow clone (no hooks, DefenseClaw-written config, remotes
// without credentials) with the current working tree on top; for other
// folders the files plus a hidden git dir. Secrets are held back and the
// size is checked before anything is copied.
func Stage(ctx context.Context, opts StageOptions) (*CopyRecord, error) {
	if !platformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	if err := ValidateName(opts.Name); err != nil {
		return nil, err
	}
	lay, err := newLayout(opts.DataDir)
	if err != nil {
		return nil, err
	}
	if _, err := requireGit(ctx, lay.dataDir); err != nil {
		return nil, err
	}
	if !opts.Replace && pathExists(lay.copyRecord(opts.Name)) {
		return nil, fmt.Errorf("workspace: copy %s already exists", opts.Name)
	}
	real, warnings, err := validateShareable(opts.Project, SourceOptions{Home: opts.Home, DataDir: lay.dataDir, Protected: opts.Protected})
	if err != nil {
		return nil, err
	}
	root := opts.RemoteRoot
	if root == "" {
		root = DefaultRemoteRoot
	}
	if !path.IsAbs(root) || path.Clean(root) == "/" {
		return nil, fmt.Errorf("workspace: remote root %q must be an absolute directory below /", root)
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultCopyMaxBytes
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	repo := RepoName(real)
	rec := &CopyRecord{
		Version: 1, Name: opts.Name, Project: real, RepoName: repo,
		RemoteDir: path.Join(path.Clean(root), repo), StagedAt: now().UTC(),
		Warnings: warnings,
	}
	copyDir := lay.copyDir(opts.Name)
	if err := os.RemoveAll(copyDir); err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(copyDir); err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(copyDir)
		}
	}()
	stageRoot := filepath.Join(copyDir, "stage")
	if err := os.Mkdir(stageRoot, 0o700); err != nil {
		return nil, err
	}
	rec.Stage = filepath.Join(stageRoot, repo)

	scanOpts := secretScanOptions{
		patterns: opts.Masks, unmask: normalizeUnmask(opts.Unmask, real), maskTracked: true,
		detector: opts.Detector, contentScan: !opts.DisableContentScan,
	}
	if scanOpts.detector == nil {
		scanOpts.detector = DefaultSecretDetector()
	}
	top, _, _ := (gitCmd{dir: real}).outputCode(ctx, "rev-parse", "--show-toplevel")
	if samePath(strings.TrimSpace(string(top)), real) {
		rec.Kind = CopyGit
		rec.RemoteGitDir = path.Join(rec.RemoteDir, ".git")
		err = stageGit(ctx, rec, opts, scanOpts, maxBytes)
	} else {
		rec.Kind = CopyPlain
		rec.RemoteGitDir = path.Join(remoteStateDir, "git")
		if parent := enclosingRepo(real); parent != "" {
			rec.Warnings = append(rec.Warnings, fmt.Sprintf("%s is inside the git repository at %s; it is copied as a plain folder", real, parent))
		}
		err = stagePlain(ctx, rec, stageRoot, scanOpts, maxBytes)
	}
	if err != nil {
		return nil, err
	}
	if err := saveCopy(lay.dataDir, rec); err != nil {
		return nil, err
	}
	ok = true
	return rec, nil
}

// stagedFile is one working-tree path to copy.
type stagedFile struct {
	rel  string
	info fs.FileInfo
}

func stageGit(ctx context.Context, rec *CopyRecord, opts StageOptions, scanOpts secretScanOptions, maxBytes int64) error {
	proj := gitCmd{dir: rec.Project}
	head, branch, err := resolveHead(ctx, proj)
	if err != nil {
		return err
	}
	rec.Head, rec.Branch = head, branch

	// The working tree to ship: tracked files still present plus untracked
	// files git does not ignore.
	tracked, err := proj.output(ctx, "ls-files", "-z", "--cached", "--stage")
	if err != nil {
		return err
	}
	trackedSet := map[string]string{}
	for _, e := range splitNUL(tracked) {
		meta, p, ok := strings.Cut(e, "\t")
		if !ok {
			continue
		}
		trackedSet[p] = strings.Fields(meta)[0]
	}
	others, err := proj.output(ctx, "ls-files", "-z", "--others", "--exclude-standard")
	if err != nil {
		return err
	}
	candidates := make([]string, 0, len(trackedSet))
	for p, mode := range trackedSet {
		if mode != modeGitlink {
			candidates = append(candidates, p)
		}
	}
	for _, p := range splitNUL(others) {
		if strings.HasSuffix(p, "/") {
			rec.Warnings = append(rec.Warnings, "nested repository "+strings.TrimSuffix(p, "/")+" is not copied")
			continue
		}
		if underHeavyDir(p) {
			continue
		}
		candidates = append(candidates, p)
	}
	scanOpts.tracked = map[string]struct{}{}
	for p := range trackedSet {
		scanOpts.tracked[p] = struct{}{}
	}
	files, heldBack, warnings, err := selectFiles(rec.Project, candidates, scanOpts, maxBytes, rec)
	if err != nil {
		return err
	}
	rec.Warnings = append(rec.Warnings, warnings...)
	rec.HeldBack = heldBack

	stage := rec.Stage
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	sg := gitCmd{dir: stage}
	if err := sg.run(ctx, "init", "--quiet", "--template=", "."); err != nil {
		return err
	}
	if f := gitConfigValue(ctx, proj, gitConfigPath(ctx, proj), "extensions.objectFormat"); f != "" && f != "sha1" {
		return &NeedsCopyError{Path: rec.Project, Reason: "sha256 repositories are not supported by copy mode yet"}
	}
	depth := opts.GitDepth
	if depth <= 0 {
		depth = DefaultGitDepth
	}
	if head != "" {
		source := "file://" + rec.Project
		if err := sg.run(ctx, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-gc", "--no-auto-maintenance",
			"--no-recurse-submodules", fmt.Sprintf("--depth=%d", depth), source, "+HEAD:refs/defenseclaw/head"); err != nil {
			return fmt.Errorf("workspace: copy history: %w", err)
		}
		fetched, err := sg.line(ctx, "rev-parse", "refs/defenseclaw/head")
		if err != nil || fetched != head {
			return fmt.Errorf("workspace: copy history: fetched %s, expected HEAD %s", fetched, head)
		}
		if err := sg.run(ctx, "update-ref", "-d", "refs/defenseclaw/head"); err != nil {
			return err
		}
	}
	switch {
	case branch != "" && head != "":
		if err := sg.run(ctx, "update-ref", branch, head); err != nil {
			return err
		}
		fallthrough
	case branch != "":
		if err := sg.run(ctx, "symbolic-ref", "HEAD", branch); err != nil {
			return err
		}
	default:
		if err := sg.run(ctx, "update-ref", "--no-deref", "HEAD", head); err != nil {
			return err
		}
	}
	remotes, dropped, err := copyRemotes(ctx, proj, sg, branch)
	if err != nil {
		return err
	}
	rec.Remotes = remotes
	for _, d := range dropped {
		rec.Warnings = append(rec.Warnings, "remote "+d+" is a local path and is not configured in the copy")
	}

	if err := copyFiles(rec.Project, stage, files); err != nil {
		return err
	}
	if head != "" {
		if err := sg.run(ctx, "read-tree", "HEAD"); err != nil {
			return err
		}
	}
	// Tracked secrets are held back: mark them skip-worktree so neither
	// the agent's git nor the pull capture treats them as deleted.
	var heldTracked []string
	for _, p := range heldBack {
		if _, ok := trackedSet[p]; ok {
			heldTracked = append(heldTracked, p)
		}
	}
	if len(heldTracked) > 0 {
		g := sg
		g.stdin = strings.NewReader(strings.Join(heldTracked, "\x00") + "\x00")
		if err := g.run(ctx, "update-index", "--skip-worktree", "-z", "--stdin"); err != nil {
			return err
		}
	}
	baseline, err := captureBaseline(ctx, sg, filepath.Join(stage, ".git", "index"), head, false)
	if err != nil {
		return err
	}
	rec.Baseline = baseline
	rec.Files = len(files)
	size, err := treeSize(stage)
	if err != nil {
		return err
	}
	rec.Bytes = size
	if size > maxBytes {
		return &TooLargeError{What: "the copy (files and history)", Size: size, Limit: maxBytes}
	}
	return nil
}

func gitConfigPath(ctx context.Context, g gitCmd) string {
	p, err := g.line(ctx, "rev-parse", "--git-common-dir")
	if err != nil {
		return ""
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(g.dir, p)
	}
	return filepath.Join(p, "config")
}

func stagePlain(ctx context.Context, rec *CopyRecord, stageRoot string, scanOpts secretScanOptions, maxBytes int64) error {
	var candidates []string
	var opaque []string
	_, err := walkProject(rec.Project, 0, func(rel string, d fs.DirEntry) error {
		if isOpaqueDir(d) || d.Name() == ".git" {
			opaque = append(opaque, rel)
			return nil
		}
		if !d.IsDir() {
			candidates = append(candidates, rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(opaque) > 0 {
		sort.Strings(opaque)
		rec.Warnings = append(rec.Warnings, "not copied: "+strings.Join(firstN(opaque, 5), ", "))
	}
	files, heldBack, warnings, err := selectFiles(rec.Project, candidates, scanOpts, maxBytes, rec)
	if err != nil {
		return err
	}
	rec.Warnings = append(rec.Warnings, warnings...)
	rec.HeldBack = heldBack
	if err := os.Mkdir(rec.Stage, 0o700); err != nil {
		return err
	}
	if err := copyFiles(rec.Project, rec.Stage, files); err != nil {
		return err
	}
	// Repo names never start with a dot, so this cannot collide.
	gitParent := filepath.Join(stageRoot, ".dc")
	if err := os.Mkdir(gitParent, 0o700); err != nil {
		return err
	}
	gitDir := filepath.Join(gitParent, "git")
	if err := (gitCmd{dir: gitParent}).run(ctx, "init", "--quiet", "--bare", "--template=", gitDir); err != nil {
		return err
	}
	g := gitCmd{dir: rec.Stage, gitDir: gitDir, workTree: rec.Stage}
	if err := g.run(ctx, "config", "core.bare", "false"); err != nil {
		return err
	}
	baseline, err := captureBaseline(ctx, g, "", "", true)
	if err != nil {
		return err
	}
	if err := g.run(ctx, "update-ref", "refs/heads/main", baseline); err != nil {
		return err
	}
	if err := g.run(ctx, "symbolic-ref", "HEAD", "refs/heads/main"); err != nil {
		return err
	}
	rec.Baseline = baseline
	rec.Files = len(files)
	size, err := treeSize(stageRoot)
	if err != nil {
		return err
	}
	rec.Bytes = size
	if size > maxBytes {
		return &TooLargeError{What: "the copy", Size: size, Limit: maxBytes}
	}
	return nil
}

// selectFiles applies the hold-back rules and the size preflight to the
// candidate paths.
func selectFiles(root string, candidates []string, scanOpts secretScanOptions, maxBytes int64, rec *CopyRecord) ([]stagedFile, []string, []string, error) {
	sort.Strings(candidates)
	held, err := detectSecretsIn(root, candidates, scanOpts)
	if err != nil {
		return nil, nil, nil, err
	}
	heldSet := toSet(held.paths)
	var files []stagedFile
	var total int64
	for _, rel := range candidates {
		if skipped(heldSet, rel) {
			continue
		}
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue // deleted from the working tree
		}
		if !info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
			rec.Warnings = append(rec.Warnings, rel+" is a special file and is not copied")
			continue
		}
		total += info.Size()
		if total > maxBytes {
			return nil, nil, nil, &TooLargeError{What: "the working tree", Size: total, Limit: maxBytes}
		}
		files = append(files, stagedFile{rel: rel, info: info})
	}
	return files, held.paths, held.warnings, nil
}

type heldBack struct {
	paths    []string
	warnings []string
}

// detectSecretsIn applies the mask rules to a fixed list of files (copy
// mode ships exactly git's view of the working tree, not a directory walk).
func detectSecretsIn(root string, rels []string, opts secretScanOptions) (*heldBack, error) {
	res := &heldBack{}
	budget := defaultMaxContentScanFiles
	unmasked := func(rel string) bool {
		for _, u := range opts.unmask {
			if matchGlob(u, rel) || strings.EqualFold(strings.Trim(u, "/"), rel) ||
				strings.HasPrefix(strings.ToLower(rel), strings.ToLower(strings.Trim(u, "/"))+"/") {
				return true
			}
		}
		return false
	}
	for _, rel := range rels {
		if unmasked(rel) {
			continue
		}
		inSecretDir := false
		for _, part := range strings.Split(path.Dir(rel), "/") {
			if isSecretDirName(part) {
				inSecretDir = true
			}
		}
		_, byPattern := matchAny(opts.patterns, rel)
		_, byName := isSecretName(rel)
		if inSecretDir || byPattern || byName {
			res.paths = append(res.paths, rel)
			continue
		}
		if !opts.contentScan || opts.detector == nil || budget <= 0 {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(p)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > maxContentScanBytes {
			continue
		}
		budget--
		content, err := readSmallRegular(p, maxContentScanBytes)
		if err != nil || looksBinary(content) {
			continue
		}
		if _, ok := opts.detector.DetectSecret(rel, content); ok {
			res.paths = append(res.paths, rel)
		}
	}
	if len(res.paths) > 0 {
		res.warnings = append(res.warnings, fmt.Sprintf("%d secret file(s) held back from the copy: %s", len(res.paths), strings.Join(firstN(res.paths, 5), ", ")))
	}
	return res, nil
}

func copyFiles(src, dst string, files []stagedFile) error {
	for _, f := range files {
		from := filepath.Join(src, filepath.FromSlash(f.rel))
		to := filepath.Join(dst, filepath.FromSlash(f.rel))
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			return err
		}
		if f.info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(from)
			if err != nil {
				return err
			}
			if err := os.Symlink(target, to); err != nil {
				return err
			}
			continue
		}
		if err := copyRegular(from, to, f.info.Mode(), f.info.ModTime()); err != nil {
			return fmt.Errorf("workspace: copy %s: %w", f.rel, err)
		}
	}
	return nil
}

// captureBaseline commits the staged working tree through a temporary
// index (seeded from seedIndex so skip-worktree bits survive) and points
// refs/defenseclaw/baseline at it.
func captureBaseline(ctx context.Context, g gitCmd, seedIndex, parent string, force bool) (string, error) {
	tmp, err := os.CreateTemp("", "dc-baseline-index-")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	_ = os.Remove(tmpPath)
	defer os.Remove(tmpPath)
	if seedIndex != "" && pathExists(seedIndex) {
		if err := copyRegular(seedIndex, tmpPath, 0o600, time.Time{}); err != nil {
			return "", err
		}
	}
	gi := g
	gi.index = tmpPath
	args := []string{"add", "--all"}
	if force {
		args = append(args, "--force")
	}
	args = append(args, "--", ".")
	args = append(args, heavyExcludePathspecs()...)
	if err := gi.run(ctx, args...); err != nil {
		return "", err
	}
	tree, err := gi.line(ctx, "write-tree")
	if err != nil {
		return "", err
	}
	commitArgs := []string{"commit-tree", tree, "-m", "defenseclaw: baseline (working tree uploaded to the sandbox)"}
	if parent != "" {
		commitArgs = append(commitArgs, "-p", parent)
	}
	commit, err := g.line(ctx, commitArgs...)
	if err != nil {
		return "", err
	}
	if err := g.run(ctx, "update-ref", baselineRef, commit); err != nil {
		return "", err
	}
	return commit, nil
}

func underHeavyDir(rel string) bool {
	for _, part := range strings.Split(path.Dir(rel), "/") {
		if isHeavyDir(part) {
			return true
		}
	}
	return false
}

// heavyExcludePathspecs keeps package caches out of forced captures of
// plain folders (they are not staged, so they must not look "added").
func heavyExcludePathspecs() []string {
	names := make([]string, 0, len(heavyDirNames))
	for n := range heavyDirNames {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, ":(exclude,glob)**/"+n+"/**")
	}
	return out
}

// copyRemotes configures the copy with the project's network remotes,
// credentials stripped. Local-path remotes are dropped.
func copyRemotes(ctx context.Context, proj, stage gitCmd, branch string) (map[string]string, []string, error) {
	out, code, err := proj.outputCode(ctx, "config", "--null", "--get-regexp", `^remote\..*\.url$`)
	if err != nil {
		return nil, nil, err
	}
	remotes := map[string]string{}
	var dropped []string
	if code != 0 {
		return remotes, nil, nil
	}
	for _, entry := range splitNUL(out) {
		key, value, ok := strings.Cut(entry, "\n")
		if !ok {
			continue
		}
		name := strings.TrimSuffix(strings.TrimPrefix(key, "remote."), ".url")
		clean, ok := sanitizeRemoteURL(value)
		if !ok {
			dropped = append(dropped, name)
			continue
		}
		remotes[name] = clean
		if err := stage.run(ctx, "config", "remote."+name+".url", clean); err != nil {
			return nil, nil, err
		}
		if err := stage.run(ctx, "config", "remote."+name+".fetch", "+refs/heads/*:refs/remotes/"+name+"/*"); err != nil {
			return nil, nil, err
		}
	}
	if b := strings.TrimPrefix(branch, "refs/heads/"); b != "" && b != branch {
		if r := gitConfigLocal(ctx, proj, "branch."+b+".remote"); r != "" {
			if _, kept := remotes[r]; kept {
				_ = stage.run(ctx, "config", "branch."+b+".remote", r)
				if m := gitConfigLocal(ctx, proj, "branch."+b+".merge"); m != "" {
					_ = stage.run(ctx, "config", "branch."+b+".merge", m)
				}
			}
		}
	}
	return remotes, dropped, nil
}

func gitConfigLocal(ctx context.Context, g gitCmd, key string) string {
	out, code, err := g.outputCode(ctx, "config", "--get", key)
	if err != nil || code != 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// sanitizeRemoteURL strips userinfo from URL-style remotes and rejects
// local paths (meaningless, and a host path leak, inside the sandbox).
func sanitizeRemoteURL(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	// "<helper>::<address>" runs git-remote-<helper> (ext:: runs a shell).
	if raw == "" || strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, ".") ||
		strings.HasPrefix(strings.ToLower(raw), "file:") || strings.HasPrefix(raw, "~") ||
		strings.Contains(raw, "::") || strings.ContainsAny(raw, " \t") {
		return "", false
	}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "", false
		}
		if strings.HasPrefix(u.Scheme, "ext") {
			return "", false
		}
		if u.User != nil {
			// Keep an ssh login name (git@host); drop anything with a
			// password or token.
			if _, hasPassword := u.User.Password(); hasPassword || !strings.HasPrefix(u.Scheme, "ssh") {
				u.User = nil
			}
		}
		return u.String(), true
	}
	// scp-like syntax: [user@]host:path
	if i := strings.Index(raw, ":"); i > 0 && !strings.Contains(raw[:i], "/") {
		return raw, true
	}
	return "", false
}

func treeSize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			if info, err := d.Info(); err == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total, err
}

// Upload sends the staged copy into the sandbox, then keeps the staged git
// history (base.git) for verifying pulls and discards the staged files.
func Upload(ctx context.Context, dataDir, name string, up Uploader) (*CopyRecord, error) {
	rec, err := LoadCopy(dataDir, name)
	if err != nil {
		return nil, err
	}
	if rec.Stage == "" || !pathExists(rec.Stage) {
		return nil, fmt.Errorf("workspace: copy %s has nothing staged to upload", name)
	}
	lay, _ := newLayout(dataDir)
	remoteRoot := path.Dir(rec.RemoteDir)
	if err := up.Upload(ctx, name, rec.Stage, remoteRoot); err != nil {
		return nil, err
	}
	stageRoot := filepath.Dir(rec.Stage)
	var localGit string
	if rec.Kind == CopyPlain {
		localGit = filepath.Join(stageRoot, ".dc", "git")
		if err := up.Upload(ctx, name, localGit, remoteStateDir); err != nil {
			return nil, err
		}
	} else {
		localGit = filepath.Join(rec.Stage, ".git")
	}
	base := filepath.Join(lay.copyDir(name), "base.git")
	_ = os.RemoveAll(base)
	if err := os.Rename(localGit, base); err != nil {
		return nil, err
	}
	if err := (gitCmd{dir: filepath.Dir(base), gitDir: base}).run(ctx, "config", "core.bare", "true"); err != nil {
		return nil, err
	}
	if err := os.RemoveAll(stageRoot); err != nil {
		return nil, err
	}
	rec.BaseGit = base
	rec.Stage = ""
	t := time.Now().UTC()
	rec.UploadedAt = &t
	if err := saveCopy(dataDir, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// remoteGitPrelude is the shell prologue every in-sandbox git script uses:
// no system or global config, no hooks, no fsmonitor, a fixed identity.
func remoteGitPrelude(rec *CopyRecord) string {
	return strings.Join([]string{
		"set -eu",
		"export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 LC_ALL=C",
		"G=" + shellQuote(rec.RemoteGitDir),
		"W=" + shellQuote(rec.RemoteDir),
		"D=" + shellQuote(remoteStateDir),
		`g() { git --git-dir="$G" --work-tree="$W" -c core.hooksPath=/dev/null -c core.fsmonitor=false ` +
			`-c commit.gpgSign=false -c user.name=DefenseClaw -c user.email=defenseclaw@localhost "$@"; }`,
	}, "\n")
}

// EstablishBaseline points refs/defenseclaw/baseline in the sandbox copy at
// the uploaded baseline and verifies the copy is where DefenseClaw expects
// it. Pull diffs everything against this commit.
func EstablishBaseline(ctx context.Context, dataDir, name string, ex Execer) (*CopyRecord, error) {
	rec, err := LoadCopy(dataDir, name)
	if err != nil {
		return nil, err
	}
	if rec.UploadedAt == nil {
		return nil, fmt.Errorf("workspace: copy %s was not uploaded", name)
	}
	script := remoteGitPrelude(rec) + "\n" + strings.Join([]string{
		`test -d "$W"`,
		`mkdir -p "$D"`,
		`g update-ref ` + baselineRef + ` ` + rec.Baseline,
		`b=$(g rev-parse -q --verify '` + baselineRef + `^{commit}')`,
		`h=$(g rev-parse -q --verify 'HEAD^{commit}' || true)`,
		`printf 'baseline=%s\nhead=%s\n' "$b" "$h"`,
	}, "\n")
	res, err := ex.Exec(ctx, name, ExecRequest{Argv: []string{"sh", "-c", script}, Timeout: 2 * time.Minute})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("workspace: set the baseline in the sandbox (exit %d): %s", res.ExitCode, lastLines(res.Stderr, 5))
	}
	kv := parseKV(res.Stdout)
	if kv["baseline"] != rec.Baseline {
		return nil, fmt.Errorf("workspace: sandbox baseline is %q, expected %s", kv["baseline"], rec.Baseline)
	}
	wantHead := rec.Head
	if rec.Kind == CopyPlain {
		wantHead = rec.Baseline
	}
	if kv["head"] != wantHead {
		return nil, fmt.Errorf("workspace: sandbox HEAD is %q, expected %q", kv["head"], wantHead)
	}
	t := time.Now().UTC()
	rec.VerifiedAt = &t
	if err := saveCopy(dataDir, rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// parseKV reads key=value lines; repeated "remote" lines are joined.
func parseKV(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range bytes.Split(b, []byte("\n")) {
		k, v, ok := strings.Cut(strings.TrimRight(string(line), "\r"), "=")
		if !ok {
			continue
		}
		if prev, dup := out[k]; dup {
			out[k] = prev + "\n" + v
		} else {
			out[k] = v
		}
	}
	return out
}
