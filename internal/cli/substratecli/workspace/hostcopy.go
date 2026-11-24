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

// The host copy (GAP-0173): how the launcher copies a project and brings
// the agent's work back on an operating system the OpenShell copy pipeline
// does not run on (Windows). The agent runs in the cluster; only the copy
// happens here, so nothing of a sandbox is needed on this computer.
//
//   - Start lists the folder as git does (tracked and untracked files, the
//     ignore rules applied) or, outside a repository, walks it; holds back
//     secrets with the pipeline's own rules (osw.HeldBack); records the
//     exact bytes it sends as a baseline commit in a private git directory
//     under the launcher's data directory (no filters: CRLF and every other
//     byte stay as they are); and streams them to the relay as a tar
//     (PUT files). Names with spaces and any Unicode are kept.
//   - Pull reads the copy back as a tar (GET files), keeps regular files
//     only (links, invalid names, .git and package caches are named, not
//     brought back), commits that tree on top of the baseline in the same
//     private directory, and reviews the difference with the pipeline's
//     rules (osw.ReviewFlags, the secret detector).
//   - Apply writes the difference into the folder with git apply (all or
//     nothing), onto a new branch through a temporary worktree, or into a
//     patch file.
//
// It needs git on this computer, as copy mode does everywhere, and nothing
// in the actor but the relay's file routes.

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// hostCopy says whether Start, Pull and Apply use the host copy: on an
// operating system the OpenShell copy pipeline does not support. Tests set
// it on any OS.
var hostCopy = runtime.GOOS == "windows"

// UsesHostCopy reports whether copies on this system are host copies (no
// git history in the actor).
func UsesHostCopy() bool { return hostCopy }

const hostRecordVersion = 1

// hostRecord is the launcher's record of one host copy (mode 0600, under
// the data directory; no secret, no token).
type hostRecord struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	Project   string `json:"project"`
	Folder    string `json:"folder"`
	RemoteDir string `json:"remote_dir"`
	StateDir  string `json:"remote_state_dir,omitempty"`
	// Baseline is the commit of what was sent; Since what an apply has
	// brought back already (a later pull starts there).
	Baseline string   `json:"baseline"`
	Since    string   `json:"since,omitempty"`
	HeldBack []string `json:"held_back,omitempty"`
	Unmasked []string `json:"unmasked,omitempty"`
	Files    int      `json:"files"`
	Bytes    int64    `json:"bytes"`
	// Result is the last pull's commit; Pulled its review (for Apply).
	Result     string          `json:"result,omitempty"`
	Pulled     *osw.PullResult `json:"pulled,omitempty"`
	UploadedAt time.Time       `json:"uploaded_at"`
	// CloneURL and CloneRef are set for a run --clone: the baseline is the
	// fresh clone read back from the actor, and pull and apply use the
	// folder pull runs in as the project, on any OS.
	CloneURL string `json:"clone_url,omitempty"`
	CloneRef string `json:"clone_ref,omitempty"`
	// LocalHead is set on a computer that did not run run (GAP-0489): the
	// baseline is this commit of Project, and the record serves pull and
	// apply only (push, sync, checkpoint and undo still refuse here).
	LocalHead string `json:"local_head,omitempty"`
	// Masks are the --exclude globs the person repeated for such a record,
	// held back on both sides as run held them; ExcludesStated says they
	// said what run left out (--exclude or --no-exclude). Without it, apply
	// and branch refuse (ExcludesUnknownError).
	Masks          []string `json:"masks,omitempty"`
	ExcludesStated bool     `json:"excludes_stated,omitempty"`
}

func hostDir(dataDir string) string { return filepath.Join(dataDir, "substrate", "hostcopies") }

func hostRecordPath(dataDir, name string) string {
	return filepath.Join(hostDir(dataDir), name+".json")
}

func hostGitDir(dataDir, name string) string { return filepath.Join(hostDir(dataDir), name+".git") }

func loadHostRecord(dataDir, name string) (*hostRecord, error) {
	b, err := os.ReadFile(hostRecordPath(dataDir, name))
	if err != nil {
		return nil, err
	}
	var r hostRecord
	if err := json.Unmarshal(b, &r); err != nil || r.Version != hostRecordVersion || r.Name != name {
		return nil, fmt.Errorf("workspace: the record of the copy %s is not readable", name)
	}
	return &r, nil
}

func (r *hostRecord) save(dataDir string) error {
	if err := os.MkdirAll(hostDir(dataDir), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	p := hostRecordPath(dataDir, r.Name)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// RemoteDirOf is where a copy this computer made lives in the actor, from
// whichever record it has (the copy pipeline's, the host copy's, which a
// clone also writes); "" when it has none.
func RemoteDirOf(dataDir, name string) string {
	if rec, err := osw.LoadCopy(dataDir, name); err == nil && rec != nil && rec.RemoteDir != "" {
		return rec.RemoteDir
	}
	if rec, err := loadHostRecord(dataDir, name); err == nil && rec.RemoteDir != "" && rec.LocalHead == "" {
		return rec.RemoteDir
	}
	return ""
}

// usesHostCopy says whether pull and apply of name go through the host
// copy: on Windows, and for a clone everywhere.
func usesHostCopy(dataDir, name string) bool {
	rec, err := loadHostRecord(dataDir, name)
	return err == nil && (hostCopy || rec.CloneURL != "" || rec.LocalHead != "")
}

// HasCopy reports whether this computer has the record of a copy it sent
// (run or run --clone) for name. A baseline pull took from a checkout on
// another computer (GAP-0489) is not one.
func HasCopy(dataDir, name string) bool {
	if _, err := osw.LoadCopy(dataDir, name); err == nil {
		return true
	}
	rec, err := loadHostRecord(dataDir, name)
	return err == nil && rec.LocalHead == ""
}

// --- git on this computer ---------------------------------------------------

// hostGit runs git with a private configuration: no system config, no hooks,
// no line-ending conversion, no prompts.
func hostGit(ctx context.Context, dir string, env []string, stdin []byte, args ...string) ([]byte, error) {
	return runHostGit(ctx, dir, true, env, stdin, args...)
}

// hostCheckoutGit runs git with this computer's own configuration (system,
// user and repository: core.autocrlf, core.eol, filter drivers), still with
// no hooks and no prompts, to write files as a checkout here writes them
// (GAP-0489).
func hostCheckoutGit(ctx context.Context, dir string, env []string, stdin []byte, args ...string) ([]byte, error) {
	return runHostGit(ctx, dir, false, env, stdin, args...)
}

func runHostGit(ctx context.Context, dir string, private bool, env []string, stdin []byte, args ...string) ([]byte, error) {
	base := []string{"-c", "core.hooksPath=" + os.DevNull,
		"-c", "core.fsmonitor=false", "-c", "core.quotePath=false", "-c", "commit.gpgSign=false", "-c", "core.longpaths=true"}
	if private {
		base = append([]string{"-c", "core.autocrlf=false", "-c", "core.safecrlf=false"}, base...)
	}
	cmd := exec.CommandContext(ctx, "git", append(base, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0",
		"GIT_AUTHOR_NAME=defenseclaw", "GIT_AUTHOR_EMAIL=defenseclaw@localhost",
		"GIT_COMMITTER_NAME=defenseclaw", "GIT_COMMITTER_EMAIL=defenseclaw@localhost")
	if private {
		cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1")
	}
	cmd.Env = append(cmd.Env, env...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, errors.New("git is not installed on this computer; install it (Git for Windows on Windows) and run again")
		}
		msg := strings.TrimSpace(errb.String())
		if i := strings.LastIndexByte(msg, '\n'); i >= 0 {
			msg = msg[i+1:]
		}
		return out.Bytes(), fmt.Errorf("git %s: %s", args[0], firstNonEmpty(msg, err.Error()))
	}
	return out.Bytes(), nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func splitNUL(b []byte) []string {
	var out []string
	for _, p := range bytes.Split(b, []byte{0}) {
		if len(p) > 0 {
			out = append(out, string(p))
		}
	}
	return out
}

// --- start ------------------------------------------------------------------

type hostFile struct {
	rel  string
	mode string // 100644 or 100755
	size int64
	mt   time.Time
}

// listHostProject lists what a copy sends: git's view of the folder when it
// is in a work tree (tracked plus untracked, ignore rules applied, paths
// relative to the folder), else every regular file outside .git and
// package caches.
func listHostProject(ctx context.Context, project string) ([]hostFile, []string, error) {
	var warnings []string
	modes := map[string]string{}
	var rels []string
	if out, err := hostGit(ctx, project, nil, nil, "rev-parse", "--is-inside-work-tree"); err == nil && strings.TrimSpace(string(out)) == "true" {
		staged, err := hostGit(ctx, project, nil, nil, "ls-files", "-z", "-s", "--", ".")
		if err != nil {
			return nil, nil, err
		}
		for _, line := range splitNUL(staged) {
			meta, p, ok := strings.Cut(line, "\t")
			if !ok {
				continue
			}
			if f := strings.Fields(meta); len(f) > 0 {
				modes[p] = f[0]
			}
		}
		listed, err := hostGit(ctx, project, nil, nil, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ".")
		if err != nil {
			return nil, nil, err
		}
		seen := map[string]bool{}
		for _, p := range splitNUL(listed) {
			if !seen[p] {
				seen[p] = true
				rels = append(rels, p)
			}
		}
	} else {
		err := filepath.WalkDir(project, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(project, p)
			rel = filepath.ToSlash(rel)
			if d.IsDir() {
				if rel != "." && (d.Name() == ".git" || osw.UnderHeavyDir(rel+"/x")) {
					return filepath.SkipDir
				}
				return nil
			}
			rels = append(rels, rel)
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	}
	var files []hostFile
	links := 0
	for _, rel := range rels {
		fi, err := os.Lstat(filepath.Join(project, filepath.FromSlash(rel)))
		if err != nil {
			continue // listed but gone (a deleted tracked file)
		}
		if !fi.Mode().IsRegular() {
			if fi.Mode()&fs.ModeSymlink != 0 {
				links++
			}
			continue
		}
		mode := modes[rel]
		if mode != "100755" {
			mode = "100644"
			if runtime.GOOS != "windows" && fi.Mode().Perm()&0o111 != 0 {
				mode = "100755"
			}
		}
		files = append(files, hostFile{rel: rel, mode: mode, size: fi.Size(), mt: fi.ModTime()})
	}
	if links > 0 {
		warnings = append(warnings, fmt.Sprintf("%d link(s) in the folder are not copied (links are not supported by this copy)", links))
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	return files, warnings, nil
}

// hostFolderName is the copy's folder name in the actor: the project
// folder's own name (spaces and Unicode kept).
func hostFolderName(project string) string {
	n := filepath.Base(filepath.Clean(project))
	if n == "" || n == "." || n == ".." || n == string(filepath.Separator) || strings.ContainsAny(n, "/\\:\x00") || len(n) > 255 {
		return "project"
	}
	for _, r := range n {
		if r < 0x20 || r == 0x7f {
			return "project"
		}
	}
	return n
}

type hostUpload struct {
	dir, project, folder, baseline string
	held, unmasked, warnings       []string
	files                          int
	bytes                          int64
}

func prepareHostUpload(ctx context.Context, opts StartOptions, summary *osw.CopySummary) (_ *hostUpload, err error) {
	project, err := filepath.Abs(opts.Project)
	if err != nil {
		return nil, err
	}
	listed, warnings, err := listHostProject(ctx, project)
	if err != nil {
		return nil, cleanErr("copy the project", err)
	}
	det := opts.Detector
	if det == nil && !opts.DisableContentScan {
		det = osw.DefaultSecretDetector()
	}
	var files []hostFile
	var held, unmasked []string
	for _, f := range listed {
		abs := filepath.Join(project, filepath.FromSlash(f.rel))
		content := func() ([]byte, bool) {
			if f.size > 256<<10 {
				return nil, false
			}
			b, err := os.ReadFile(abs)
			return b, err == nil
		}
		if _, h := osw.HeldBack(f.rel, opts.Masks, opts.Unmask, content, det); h {
			held = append(held, f.rel)
			continue
		}
		if _, h := osw.HeldBack(f.rel, opts.Masks, nil, nil, nil); h {
			unmasked = append(unmasked, f.rel)
		}
		summary.Add(f.rel, f.size)
		files = append(files, f)
	}
	if summary.Bytes > opts.MaxBytes {
		return nil, &osw.TooLargeError{What: "the working tree", Size: summary.Bytes, Limit: opts.MaxBytes}
	}
	if err := safefile.ProtectDirectory(hostDir(opts.DataDir)); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(hostDir(opts.DataDir), ".preflight-")
	if err != nil {
		return nil, err
	}
	p := &hostUpload{dir: dir, project: project, folder: hostFolderName(project),
		held: held, unmasked: unmasked, warnings: warnings, files: summary.Files, bytes: summary.Bytes}
	defer func() {
		if err != nil {
			p.close()
		}
	}()
	gitDir := filepath.Join(dir, "baseline.git")
	if _, err = hostGit(ctx, project, nil, nil, "init", "-q", "--bare", gitDir); err != nil {
		return nil, err
	}
	p.baseline, err = hostCommit(ctx, gitDir, project, files, "")
	if err != nil {
		return nil, err
	}
	tarFile, err := os.OpenFile(filepath.Join(dir, "upload.tar"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	err = errors.Join(writeHostTar(tarFile, project, p.folder, files), tarFile.Close())
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *hostUpload) close() { _ = os.RemoveAll(p.dir) }

func (p *hostUpload) send(ctx context.Context, c *Client, dataDir, name, root, stateDir string) (*StartResult, error) {
	if err := osw.ValidateName(name); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(p.dir, "upload.tar"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	resp, err := c.request(ctx, "the upload", http.MethodPut, relay.RouteFiles, url.Values{"dir": {root}}, f, "application/x-tar", http.StatusNoContent)
	if err != nil {
		return nil, cleanErr("upload the project to the actor", err)
	}
	resp.Body.Close()
	gitDir := hostGitDir(dataDir, name)
	if err := os.RemoveAll(gitDir); err != nil {
		return nil, err
	}
	if err := os.Rename(filepath.Join(p.dir, "baseline.git"), gitDir); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	remoteDir := path.Join(root, p.folder)
	rec := &hostRecord{Version: hostRecordVersion, Name: name, Project: p.project, Folder: p.folder,
		RemoteDir: remoteDir, StateDir: stateDir, Baseline: p.baseline, HeldBack: p.held, Unmasked: p.unmasked,
		Files: p.files, Bytes: p.bytes, UploadedAt: now}
	if err := rec.save(dataDir); err != nil {
		return nil, err
	}
	cr := &osw.CopyRecord{Version: 1, Name: name, Project: p.project, RepoName: p.folder, RemoteDir: remoteDir,
		StateDir: stateDir, Baseline: p.baseline, HeldBack: p.held, Unmasked: p.unmasked, Files: p.files, Bytes: p.bytes,
		StagedAt: now, UploadedAt: &now, VerifiedAt: &now}
	return &StartResult{CopyRecord: cr, KeptBack: p.held, Unmasked: p.unmasked, Warnings: p.warnings}, nil
}

// hostCommit records files of dir (their bytes as they are now) as a
// commit on parent ("" for none) in gitDir and returns it.
func hostCommit(ctx context.Context, gitDir, dir string, files []hostFile, parent string) (string, error) {
	index := filepath.Join(gitDir, "dc-index-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	defer os.Remove(index)
	env := []string{"GIT_DIR=" + gitDir, "GIT_INDEX_FILE=" + index}
	var info bytes.Buffer
	if len(files) > 0 {
		var paths bytes.Buffer
		for _, f := range files {
			paths.WriteString(filepath.Join(dir, filepath.FromSlash(f.rel)))
			paths.WriteByte('\n')
		}
		out, err := hostGit(ctx, dir, env, paths.Bytes(), "hash-object", "-w", "--no-filters", "--stdin-paths")
		if err != nil {
			return "", err
		}
		oids := strings.Fields(string(out))
		if len(oids) != len(files) {
			return "", errors.New("git hash-object did not hash every file")
		}
		for i, f := range files {
			fmt.Fprintf(&info, "%s %s\t%s\x00", f.mode, oids[i], f.rel)
		}
	}
	if _, err := hostGit(ctx, dir, env, info.Bytes(), "update-index", "-z", "--add", "--index-info"); err != nil {
		return "", err
	}
	tree, err := hostGit(ctx, dir, env, nil, "write-tree")
	if err != nil {
		return "", err
	}
	args := []string{"commit-tree", strings.TrimSpace(string(tree)), "-m", "defenseclaw copy"}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	commit, err := hostGit(ctx, dir, env, nil, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(commit)), nil
}

func writeHostTar(w io.Writer, project, folder string, files []hostFile) error {
	tw := tar.NewWriter(w)
	now := time.Now()
	dirs := map[string]bool{}
	addDir := func(d string) error {
		var chain []string
		for d != "." && d != "" && !dirs[d] {
			chain = append(chain, d)
			d = path.Dir(d)
		}
		for i := len(chain) - 1; i >= 0; i-- {
			dirs[chain[i]] = true
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: chain[i] + "/", Mode: 0o755, ModTime: now, Format: tar.FormatPAX}); err != nil {
				return err
			}
		}
		return nil
	}
	if err := addDir(folder); err != nil {
		return err
	}
	for _, f := range files {
		name := folder + "/" + f.rel
		if err := addDir(path.Dir(name)); err != nil {
			return err
		}
		p := filepath.Join(project, filepath.FromSlash(f.rel))
		fh, err := os.Open(p)
		if err != nil {
			return err
		}
		fi, err := fh.Stat()
		if err != nil || !fi.Mode().IsRegular() || fi.Size() != f.size || !fi.ModTime().Equal(f.mt) {
			fh.Close()
			return fmt.Errorf("%s changed while it was being copied; run again", f.rel)
		}
		mode := int64(0o644)
		if f.mode == "100755" {
			mode = 0o755
		}
		hdr := &tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: mode, Size: f.size, ModTime: f.mt, Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			fh.Close()
			return err
		}
		n, err := io.Copy(tw, fh)
		fh.Close()
		if err != nil {
			return err
		}
		if n != f.size {
			return fmt.Errorf("%s changed while it was being copied; run again", f.rel)
		}
	}
	return tw.Close()
}

// --- pull -------------------------------------------------------------------

// windowsName reports a name Windows cannot hold (reserved device names,
// characters it refuses, a trailing dot or space).
func windowsName(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if part == "" || strings.ContainsAny(part, `<>:"\|?*`) || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return false
		}
		for _, r := range part {
			if r < 0x20 {
				return false
			}
		}
		base := strings.ToUpper(strings.SplitN(part, ".", 2)[0])
		switch base {
		case "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
			"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9":
			return false
		}
	}
	return true
}

// hasGitComponent reports a path with a folder named .git in any case, or
// in a form NTFS reads as .git (git~1, .git followed by dots or spaces;
// git's is_ntfs_dotgit, GAP-0575): git metadata (a nested repository's,
// or one the agent made), which the folder never takes (GAP-0530).
func hasGitComponent(rel string) bool {
	for _, p := range strings.Split(rel, "/") {
		if isDotGitName(p) {
			return true
		}
	}
	return false
}

// isDotGitName is git's is_ntfs_dotgit with its case fold: .git, then
// only dots or spaces, or the short name git~1.
func isDotGitName(name string) bool {
	n := strings.ToLower(name)
	return n == "git~1" || (strings.HasPrefix(n, ".git") && strings.Trim(n[4:], ". ") == "")
}

// stageHostTree reads the actor's copy (a tar of <folder>) into dir:
// regular files only. It returns the files kept and notes on what was not.
func stageHostTree(r io.Reader, folder, dir string, limit int64, held func(string) bool) ([]hostFile, []string, []string, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	defer root.Close()
	var files []hostFile
	var notes, dropped []string
	links, invalid, caches, gitMeta := 0, 0, 0, 0
	var total int64
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("the actor's copy is not readable: %w", err)
		}
		name := strings.TrimPrefix(path.Clean("/"+hdr.Name), "/")
		rel, ok := strings.CutPrefix(name, folder+"/")
		if !ok || rel == "" {
			continue
		}
		switch {
		case rel == ".git" || strings.HasPrefix(rel, ".git/"):
			continue
		case hasGitComponent(rel):
			// A .git folder below the top, or one in another case (.GIT):
			// git metadata, never the project's (GAP-0530).
			if hdr.Typeflag == tar.TypeReg {
				gitMeta++
			}
			continue
		case osw.UnderHeavyDir(rel):
			if hdr.Typeflag == tar.TypeReg {
				caches++
			}
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
		case tar.TypeSymlink, tar.TypeLink:
			links++
			continue
		default:
			continue
		}
		if !windowsName(rel) {
			invalid++
			continue
		}
		if held(rel) {
			dropped = append(dropped, rel)
			continue
		}
		total += hdr.Size
		if total > limit {
			return nil, nil, nil, fmt.Errorf("the agent's work is larger than %d MB; bring it back from inside the agent with git", limit>>20)
		}
		if d := path.Dir(rel); d != "." {
			if err := root.MkdirAll(d, 0o700); err != nil {
				return nil, nil, nil, err
			}
		}
		f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, nil, nil, err
		}
		n, err := io.Copy(f, io.LimitReader(tr, hdr.Size))
		f.Close()
		if err != nil || n != hdr.Size {
			return nil, nil, nil, fmt.Errorf("the actor's copy of %s is incomplete", rel)
		}
		mode := "100644"
		if hdr.Mode&0o111 != 0 {
			mode = "100755"
		}
		files = append(files, hostFile{rel: rel, mode: mode, size: hdr.Size})
	}
	if links > 0 {
		notes = append(notes, fmt.Sprintf("%d link(s) the agent made are not brought back", links))
	}
	if invalid > 0 {
		notes = append(notes, fmt.Sprintf("%d file(s) have names this computer cannot hold and are not brought back", invalid))
	}
	if caches > 0 {
		notes = append(notes, fmt.Sprintf("%d file(s) in package caches (node_modules and the like) are not brought back", caches))
	}
	if gitMeta > 0 {
		notes = append(notes, fmt.Sprintf("%d file(s) in git metadata folders the agent made (.git in any case) are not brought back", gitMeta))
	}
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
	return files, notes, dropped, nil
}

func (c *Client) downloadHostTree(ctx context.Context, rec *hostRecord, dir string) ([]hostFile, []string, []string, error) {
	resp, err := c.request(ctx, "the download", http.MethodGet, relay.RouteFiles, url.Values{"path": {rec.RemoteDir}}, nil, "", http.StatusOK)
	if err != nil {
		return nil, nil, nil, err
	}
	defer resp.Body.Close()
	limit := c.MaxDownloadBytes
	if limit <= 0 {
		limit = DefaultMaxDownloadBytes
	}
	heldSet := map[string]bool{}
	for _, h := range rec.HeldBack {
		heldSet[h] = true
	}
	return stageHostTree(resp.Body, rec.Folder, dir, limit, func(rel string) bool {
		if heldSet[rel] {
			return true
		}
		// The shared files are exact paths, not patterns (RV1 P1-1).
		if slices.Contains(rec.Unmasked, rel) {
			return false
		}
		_, h := osw.HeldBack(rel, rec.Masks, nil, nil, nil)
		return h
	})
}

// gitIgnoredLocally drops what the project's own ignore rules exclude
// (build output the agent made), when the project is a git work tree.
func gitIgnoredLocally(ctx context.Context, project string, files []hostFile) []hostFile {
	if out, err := hostGit(ctx, project, nil, nil, "rev-parse", "--is-inside-work-tree"); err != nil || strings.TrimSpace(string(out)) != "true" {
		return files
	}
	var in bytes.Buffer
	for _, f := range files {
		in.WriteString(f.rel)
		in.WriteByte(0)
	}
	out, _ := hostGit(ctx, project, nil, in.Bytes(), "check-ignore", "-z", "--stdin", "--no-index")
	ignored := map[string]bool{}
	for _, p := range splitNUL(out) {
		ignored[p] = true
	}
	kept := files[:0]
	for _, f := range files {
		if !ignored[f.rel] {
			kept = append(kept, f)
		}
	}
	return kept
}

func hostPull(ctx context.Context, opts PullOptions, label string) (*Review, error) {
	c, ok := opts.Exec.(*Client)
	if !ok {
		return nil, errors.New("workspace: the host copy needs the relay client")
	}
	rec, err := loadHostRecord(opts.DataDir, opts.Name)
	if err != nil {
		return nil, cleanErr("read "+label, err)
	}
	if rec.CloneURL != "" {
		if rec.Baseline == "" {
			return nil, fmt.Errorf("this computer kept no copy of the clone of %s, so pull cannot tell what the agent changed; push from inside the agent (connect, then git push)", rec.CloneURL)
		}
		// A clone has no folder of its own here: the changes go into the
		// folder pull runs in (a checkout of the repository).
		project := opts.Project
		if project == "" {
			if project, err = os.Getwd(); err != nil {
				return nil, err
			}
		}
		if rec.Project, err = filepath.Abs(project); err != nil {
			return nil, err
		}
	}
	stage := filepath.Join(hostDir(opts.DataDir), opts.Name+".pull")
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(stage)
	files, notes, dropped, err := c.downloadHostTree(ctx, rec, stage)
	if err != nil {
		return nil, cleanErr("read "+label, err)
	}
	gitDir := hostGitDir(opts.DataDir, opts.Name)
	from := firstNonEmpty(rec.Since, rec.Baseline)
	if rec.CloneURL != "" {
		files = cloneIgnored(ctx, gitDir, stage, from, files)
	} else {
		files = gitIgnoredLocally(ctx, rec.Project, files)
	}
	result, err := hostCommit(ctx, gitDir, stage, files, from)
	if err != nil {
		return nil, cleanErr("read "+label, err)
	}
	changes, err := hostChanges(ctx, gitDir, from, result)
	if err != nil {
		return nil, cleanErr("read "+label, err)
	}
	content := func(ch osw.TreeChange, after bool) ([]byte, bool) {
		oid := ch.OldOID
		if after {
			oid = ch.NewOID
		}
		if oid == "" || strings.Trim(oid, "0") == "" {
			return nil, false
		}
		b, err := hostGit(ctx, gitDir, []string{"GIT_DIR=" + gitDir}, nil, "cat-file", "blob", oid)
		return b, err == nil
	}
	if rec.LocalHead != "" {
		head := []string{elsewhereNote(rec.LocalHead)}
		if n := elsewhereExcludesNote(rec); n != "" {
			head = append(head, n)
		}
		notes = append(head, notes...)
	}
	rep := osw.ReviewReport{Name: opts.Name, Project: rec.Project, Changes: changes, Warnings: notes}
	rep.Flags = osw.ReviewFlags(changes, content, nil)
	det := osw.DefaultSecretDetector()
	for _, ch := range changes {
		rep.FilesChanged++
		rep.Insertions += ch.Added
		rep.Deletions += ch.Deleted
		if ch.Status == "D" {
			continue
		}
		if b, ok := content(ch, true); ok && len(b) <= 256<<10 {
			if rule, hit := det.DetectSecret(ch.Path, b); hit {
				rep.Findings = append(rep.Findings, osw.SecretFinding(ch.Path, rule))
			}
		}
	}
	pr := &osw.PullResult{Name: opts.Name, Project: rec.Project, Baseline: rec.Baseline, Result: result, Effective: result,
		Since: rec.Since, Changes: changes, Review: rep, Dropped: dropped, PulledAt: time.Now().UTC()}
	rec.Result, rec.Pulled = result, pr
	if err := rec.save(opts.DataDir); err != nil {
		return nil, err
	}
	rv := buildReview(pr)
	if !pr.Empty() {
		if d, err := hostGit(ctx, gitDir, []string{"GIT_DIR=" + gitDir}, nil, "diff", "--binary", "--no-renames", from, result); err == nil {
			rv.Diff = d
		}
	}
	rv.Text = rv.render(label)
	return rv, nil
}

// hostChanges is the change list between two commits of gitDir.
func hostChanges(ctx context.Context, gitDir, from, to string) ([]osw.TreeChange, error) {
	env := []string{"GIT_DIR=" + gitDir}
	raw, err := hostGit(ctx, gitDir, env, nil, "diff-tree", "-r", "-z", "--no-renames", "--raw", from, to)
	if err != nil {
		return nil, err
	}
	num, err := hostGit(ctx, gitDir, env, nil, "diff-tree", "-r", "-z", "--no-renames", "--numstat", from, to)
	if err != nil {
		return nil, err
	}
	stats := map[string][3]int{} // added, deleted, binary
	for _, rec := range splitNUL(num) {
		f := strings.SplitN(rec, "\t", 3)
		if len(f) != 3 {
			continue
		}
		a, errA := strconv.Atoi(f[0])
		d, errD := strconv.Atoi(f[1])
		bin := 0
		if errA != nil || errD != nil {
			bin = 1
		}
		stats[f[2]] = [3]int{a, d, bin}
	}
	parts := splitNUL(raw)
	var out []osw.TreeChange
	for i := 0; i+1 < len(parts); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(parts[i], ":"))
		if len(meta) < 5 {
			continue
		}
		p := parts[i+1]
		st := stats[p]
		out = append(out, osw.TreeChange{Path: p, Status: meta[4][:1], OldMode: meta[0], NewMode: meta[1],
			OldOID: meta[2], NewOID: meta[3], Added: st[0], Deleted: st[1], Binary: st[2] == 1})
	}
	return out, nil
}

// --- apply ------------------------------------------------------------------

func hostApply(ctx context.Context, opts ApplyOptions) (*ApplyResult, error) {
	rec, err := loadHostRecord(opts.DataDir, opts.Name)
	if err != nil || rec.Pulled == nil || rec.Result == "" {
		return nil, errors.New("pull first: there is nothing reviewed to bring back")
	}
	pr := rec.Pulled
	if rec.LocalHead != "" && !rec.ExcludesStated && opts.Mode != ModePatch {
		return nil, &ExcludesUnknownError{Name: opts.Name}
	}
	if needsDecision(pr) && !opts.AcceptSensitive && opts.Mode != ModePatch {
		if opts.Mode != ModeBranch || len(pr.Review.SecretPaths()) != 0 {
			return nil, &SensitiveError{Files: flaggedPaths(pr)}
		}
	}
	gitDir := hostGitDir(opts.DataDir, opts.Name)
	env := []string{"GIT_DIR=" + gitDir}
	from := firstNonEmpty(rec.Since, rec.Baseline)
	patch, err := hostGit(ctx, gitDir, env, nil, "diff", "--binary", "--no-renames", "--full-index", from, rec.Result)
	if err != nil {
		return nil, err
	}
	out := &ApplyResult{Mode: opts.Mode}
	if out.Mode == "" {
		out.Mode = ModeApply
	}
	if len(bytes.TrimSpace(patch)) == 0 {
		out.UpToDate = true
		if out.Mode == ModeBranch {
			out.Branch = opts.Branch
		}
		out.Text = applyText(out, rec.Project, 0)
		return out, nil
	}
	switch out.Mode {
	case ModePatch:
		if opts.PatchPath == "" {
			return nil, errors.New("workspace: a patch file is required for patch mode")
		}
		flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
		if opts.Force {
			flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
		}
		f, err := os.OpenFile(opts.PatchPath, flags, 0o600)
		if err != nil {
			return nil, fmt.Errorf("cannot write the patch: %w", err)
		}
		if _, err := f.Write(patch); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Close(); err != nil {
			return nil, err
		}
		out.PatchPath = opts.PatchPath
	case ModeBranch:
		if err := hostApplyBranch(ctx, rec, opts, patch); err != nil {
			return nil, err
		}
		out.Branch = opts.Branch
	default:
		// The working tree is the copy's own: paths in the patch are
		// relative to the project folder; git apply changes all files or
		// none.
		wt := []string{"GIT_DIR=" + gitDir, "GIT_WORK_TREE=" + rec.Project}
		if _, err := hostGit(ctx, rec.Project, wt, patch, "apply", "--whitespace=nowarn", "-"); err != nil {
			save := filepath.Join(hostDir(opts.DataDir), opts.Name+".patch")
			_ = os.WriteFile(save, patch, 0o600)
			out.FellBack, out.PatchPath = true, save
			out.Conflicts = []string{"files you changed since the copy"}
			if rec.CloneURL != "" {
				out.Conflicts = []string{"files in this folder that differ from the clone"}
			}
			out.Text = applyText(out, rec.Project, len(pr.Changes))
			return out, nil
		}
		for _, ch := range pr.Changes {
			out.Written = append(out.Written, ch.Path)
		}
		rec.Since = rec.Result
	}
	t := time.Now().UTC()
	pr.AppliedAt = &t
	if err := rec.save(opts.DataDir); err != nil {
		return nil, err
	}
	out.Text = applyText(out, rec.Project, len(pr.Changes))
	return out, nil
}

// hostApplyBranch commits the patch on a new branch of the project's
// repository through a temporary worktree; the checkout is not touched.
func hostApplyBranch(ctx context.Context, rec *hostRecord, opts ApplyOptions, patch []byte) error {
	top, err := hostGit(ctx, rec.Project, nil, nil, "rev-parse", "--show-toplevel")
	if err != nil {
		return errors.New("--branch needs the folder to be in a git repository; use --apply or --patch-out FILE")
	}
	prefix, _ := hostGit(ctx, rec.Project, nil, nil, "rev-parse", "--show-prefix")
	toplevel := strings.TrimSpace(string(top))
	if opts.Branch == "" {
		return errors.New("name the branch: --branch NAME")
	}
	if _, err := hostGit(ctx, toplevel, nil, nil, "check-ref-format", "--branch", opts.Branch); err != nil {
		return fmt.Errorf("%q is not a valid branch name", opts.Branch)
	}
	if _, err := hostGit(ctx, toplevel, nil, nil, "rev-parse", "--verify", "--quiet", "refs/heads/"+opts.Branch); err == nil && !opts.Force {
		return fmt.Errorf("branch %s exists already; choose another name or add --force", opts.Branch)
	}
	tmp, err := os.MkdirTemp(hostDir(opts.DataDir), opts.Name+".wt-")
	if err != nil {
		return err
	}
	_ = os.Remove(tmp)
	defer func() {
		_, _ = hostGit(context.WithoutCancel(ctx), toplevel, nil, nil, "worktree", "remove", "--force", tmp)
		_ = os.RemoveAll(tmp)
	}()
	bflag := "-b"
	if opts.Force {
		bflag = "-B"
	}
	// GAP-0393: a repository with no commit has no HEAD to branch from, and
	// git said only "invalid reference: HEAD".
	if _, err := hostGit(ctx, toplevel, nil, nil, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"); err != nil {
		return errors.New("--branch needs a first commit in this repository to branch from; commit once (git commit --allow-empty -m init), or use --apply or --patch-out FILE")
	}
	if _, err := hostGit(ctx, toplevel, nil, nil, "worktree", "add", "--quiet", bflag, opts.Branch, tmp, "HEAD"); err != nil {
		return err
	}
	dir := "--directory=" + strings.TrimSuffix(strings.TrimSpace(string(prefix)), "/")
	args := []string{"apply", "--whitespace=nowarn", "--index"}
	if dir != "--directory=" {
		args = append(args, dir)
	}
	if _, err := hostGit(ctx, tmp, nil, patch, append(args, "-")...); err != nil {
		return fmt.Errorf("the changes do not apply to %s's last commit: %w", opts.Branch, err)
	}
	user := hostUser(ctx, toplevel)
	if _, err := hostGit(ctx, tmp, user, nil, "commit", "-q", "-m", "Changes from the agent "+opts.Name); err != nil {
		return err
	}
	return nil
}

// hostUser is the person's git identity for a branch commit (their config),
// else the DefenseClaw one.
func hostUser(ctx context.Context, repo string) []string {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "config", "--get", "user.name")
	n, _ := cmd.Output()
	cmd = exec.CommandContext(ctx, "git", "-C", repo, "config", "--get", "user.email")
	e, _ := cmd.Output()
	name, email := strings.TrimSpace(string(n)), strings.TrimSpace(string(e))
	if name == "" || email == "" {
		return nil
	}
	return []string{"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + email, "GIT_COMMITTER_NAME=" + name, "GIT_COMMITTER_EMAIL=" + email}
}
