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
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// shadow is a DefenseClaw-owned git directory whose work tree is the
// project. Snapshots, post-session captures, diffs and restores all run
// through it, so nothing the agent wrote into the project's .git (config,
// attributes, commondir, hooks, index) is ever read by those commands:
//
//   - its config is written by DefenseClaw: no filters, no hooks, no
//     fsmonitor, raw line endings;
//   - info/attributes unsets text/eol/ident/filter/encoding for every path,
//     so captures and restores round-trip bytes exactly;
//   - it borrows the project's objects through alternates and, where the
//     filesystem allows, hard-links them (packs and loose objects are
//     immutable), so deleting the project's .git/objects does not destroy
//     the snapshot.
type shadow struct {
	dir     string
	project string
	gitDir  string
	home    string
	xdg     string
}

type shadowMarker struct {
	Project string `json:"project"`
	GitDir  string `json:"git_dir"`
	Format  string `json:"object_format"`
}

const shadowAttributes = "* -text -eol -crlf -ident -filter -working-tree-encoding\n"

func (s *shadow) git() gitCmd {
	return gitCmd{dir: s.project, gitDir: s.dir, workTree: s.project}
}

// bare runs git in the shadow without a work tree (object and ref work).
func (s *shadow) bare() gitCmd {
	return gitCmd{dir: filepath.Dir(s.dir), gitDir: s.dir}
}

// openShadow creates or refreshes the shadow for a project and takes its
// lock. The caller must call the returned unlock.
func openShadow(ctx context.Context, lay layout, project, gitDir, homeOverride string) (*shadow, func(), error) {
	if _, err := requireGit(ctx, project); err != nil {
		return nil, nil, err
	}
	home, xdg := operatorConfigDirs(homeOverride)
	s := &shadow{dir: lay.shadowDir(ProjectKey(project)), project: project, gitDir: gitDir, home: home, xdg: xdg}
	parent := filepath.Dir(s.dir)
	if err := ensurePrivateDir(parent); err != nil {
		return nil, nil, err
	}
	unlock, err := lockPath(ctx, s.dir+".lock")
	if err != nil {
		return nil, nil, err
	}
	if err := s.prepare(ctx); err != nil {
		unlock()
		return nil, nil, err
	}
	return s, unlock, nil
}

// reopenShadow locks an existing shadow recorded in a snapshot.
func reopenShadow(ctx context.Context, dir, project, gitDir string) (*shadow, func(), error) {
	if _, err := requireGit(ctx, project); err != nil {
		return nil, nil, err
	}
	s := &shadow{dir: dir, project: project, gitDir: gitDir}
	if !pathExists(filepath.Join(dir, "HEAD")) {
		return nil, nil, fmt.Errorf("workspace: snapshot storage %s is missing", dir)
	}
	unlock, err := lockPath(ctx, dir+".lock")
	if err != nil {
		return nil, nil, err
	}
	if err := s.writeConfig(ctx); err != nil {
		unlock()
		return nil, nil, err
	}
	return s, unlock, nil
}

func (s *shadow) prepare(ctx context.Context) error {
	format := "sha1"
	if f := gitConfigValue(ctx, gitCmd{dir: s.project}, filepath.Join(s.gitDir, "config"), "extensions.objectFormat"); f != "" {
		format = strings.ToLower(f)
	}
	markerPath := filepath.Join(s.dir, "defenseclaw-project.json")
	if pathExists(s.dir) {
		var m shadowMarker
		if err := readJSON(markerPath, &m); err != nil {
			return fmt.Errorf("workspace: snapshot storage %s is not DefenseClaw's: %w", s.dir, err)
		}
		if m.Project != s.project || m.Format != format {
			return fmt.Errorf("workspace: snapshot storage %s belongs to %s (%s objects)", s.dir, m.Project, m.Format)
		}
		if m.GitDir != s.gitDir {
			m.GitDir = s.gitDir
			if err := writeJSON(markerPath, m); err != nil {
				return err
			}
		}
	} else {
		args := []string{"init", "--quiet", "--bare", "--template=", "--object-format=" + format, s.dir}
		if err := (gitCmd{dir: filepath.Dir(s.dir)}).run(ctx, args...); err != nil {
			return err
		}
		if err := os.Chmod(s.dir, 0o700); err != nil {
			return err
		}
		if err := writeJSON(markerPath, shadowMarker{Project: s.project, GitDir: s.gitDir, Format: format}); err != nil {
			return err
		}
	}
	if err := s.writeConfig(ctx); err != nil {
		return err
	}
	if err := s.writeExcludes(); err != nil {
		return err
	}
	return s.writeAlternates()
}

func (s *shadow) writeConfig(ctx context.Context) error {
	projectCfg := filepath.Join(s.gitDir, "config")
	g := gitCmd{dir: s.project}
	var b strings.Builder
	format := "sha1"
	var m shadowMarker
	if err := readJSON(filepath.Join(s.dir, "defenseclaw-project.json"), &m); err == nil && m.Format != "" {
		format = m.Format
	}
	version := "0"
	if format != "sha1" {
		version = "1"
	}
	fmt.Fprintf(&b, "[core]\n\trepositoryformatversion = %s\n\tbare = false\n", version)
	b.WriteString("\tfilemode = true\n\tsymlinks = true\n\tautocrlf = false\n\tsafecrlf = false\n")
	b.WriteString("\tfsmonitor = false\n\tuntrackedCache = false\n\thooksPath = /dev/null\n")
	b.WriteString("\tlogAllRefUpdates = true\n\tquotePath = false\n")
	for _, key := range []string{"core.ignorecase", "core.precomposeunicode"} {
		if v := gitConfigValue(ctx, g, projectCfg, key); v == "true" || v == "false" {
			fmt.Fprintf(&b, "\t%s = %s\n", strings.TrimPrefix(key, "core."), v)
		}
	}
	if format != "sha1" {
		fmt.Fprintf(&b, "[extensions]\n\tobjectformat = %s\n", format)
	}
	b.WriteString("[gc]\n\tauto = 0\n\tpruneExpire = never\n\treflogExpire = never\n\treflogExpireUnreachable = never\n")
	b.WriteString("[maintenance]\n\tauto = false\n")
	b.WriteString("[uploadpack]\n\tallowAnySHA1InWant = true\n")
	if err := os.WriteFile(filepath.Join(s.dir, "config"), []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("workspace: write snapshot config: %w", err)
	}
	info := filepath.Join(s.dir, "info")
	if err := os.MkdirAll(info, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(info, "attributes"), []byte(shadowAttributes), 0o600)
}

// writeExcludes copies the ignore rules git would apply for the operator
// (the project's info/exclude plus the global excludes file) into the
// shadow, so captures skip the same files the operator's git skips.
func (s *shadow) writeExcludes() error {
	var b bytes.Buffer
	appendFile := func(p string) {
		data, err := readSmallRegular(p, 1<<20)
		if err != nil || len(data) == 0 {
			return
		}
		b.Write(data)
		if data[len(data)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	appendFile(filepath.Join(s.gitDir, "info", "exclude"))
	for _, p := range globalExcludesFiles(s.home, s.xdg) {
		appendFile(p)
	}
	return os.WriteFile(filepath.Join(s.dir, "info", "exclude"), b.Bytes(), 0o600)
}

// operatorConfigDirs returns the home and XDG config directories whose git
// ignore settings apply to the operator. An explicit home override also
// pins XDG to <home>/.config.
func operatorConfigDirs(homeOverride string) (home, xdg string) {
	home, _ = resolveHome(homeOverride)
	if homeOverride == "" {
		xdg = os.Getenv("XDG_CONFIG_HOME")
	}
	if xdg == "" && home != "" {
		xdg = filepath.Join(home, ".config")
	}
	return home, xdg
}

func globalExcludesFiles(home, xdg string) []string {
	var cfgs []string
	if home != "" {
		cfgs = append(cfgs, filepath.Join(home, ".gitconfig"))
	}
	if xdg != "" {
		cfgs = append(cfgs, filepath.Join(xdg, "git", "config"))
	}
	var out []string
	for _, cfg := range cfgs {
		if !pathExists(cfg) {
			continue
		}
		if v := gitConfigValue(context.Background(), gitCmd{dir: filepath.Dir(cfg)}, cfg, "core.excludesFile"); v != "" {
			out = append(out, expandGitPath(v, filepath.Dir(cfg), home))
		}
	}
	if len(out) == 0 && xdg != "" {
		out = append(out, filepath.Join(xdg, "git", "ignore"))
	}
	return out
}

func (s *shadow) writeAlternates() error {
	objects := filepath.Join(s.gitDir, "objects")
	dir := filepath.Join(s.dir, "objects", "info")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "alternates"), []byte(objects+"\n"), 0o600)
}

var (
	loosePrefixRE = regexp.MustCompile(`^[0-9a-f]{2}$`)
	looseObjectRE = regexp.MustCompile(`^[0-9a-f]{38}([0-9a-f]{24})?$`)
	packFileRE    = regexp.MustCompile(`^pack-[0-9a-f]+\.(pack|rev|bitmap|mtimes|promisor|idx)$`)
)

// linkObjects hard-links the project's immutable object files into the
// shadow. It reports false (with a reason) when the data dir is on another
// filesystem or the filesystem refuses links; the snapshot then relies on
// alternates alone.
func (s *shadow) linkObjects() (bool, string) {
	src := filepath.Join(s.gitDir, "objects")
	dst := filepath.Join(s.dir, "objects")
	link := func(from, to string) error {
		if pathExists(to) {
			return nil
		}
		if err := os.Link(from, to); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return nil
			}
			return err
		}
		return nil
	}
	fail := func(err error) (bool, string) {
		if errors.Is(err, syscall.EXDEV) {
			return false, "the DefenseClaw data dir is on a different filesystem than the project, so the snapshot shares the project's git objects instead of keeping its own copy"
		}
		return false, "could not keep a private copy of the project's git objects (" + err.Error() + "); the snapshot shares them with the project"
	}

	packs, _ := os.ReadDir(filepath.Join(src, "pack"))
	var names []string
	for _, e := range packs {
		if e.Type().IsRegular() && packFileRE.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	// Link each pack before its index so a reader never sees an index
	// whose pack is missing.
	sort.Slice(names, func(i, j int) bool {
		ii, ji := strings.HasSuffix(names[i], ".idx"), strings.HasSuffix(names[j], ".idx")
		if ii != ji {
			return !ii
		}
		return names[i] < names[j]
	})
	if len(names) > 0 {
		if err := os.MkdirAll(filepath.Join(dst, "pack"), 0o700); err != nil {
			return fail(err)
		}
	}
	for _, n := range names {
		if err := link(filepath.Join(src, "pack", n), filepath.Join(dst, "pack", n)); err != nil {
			return fail(err)
		}
	}
	prefixes, _ := os.ReadDir(src)
	for _, p := range prefixes {
		if !p.IsDir() || !loosePrefixRE.MatchString(p.Name()) {
			continue
		}
		objs, err := os.ReadDir(filepath.Join(src, p.Name()))
		if err != nil {
			continue
		}
		made := false
		for _, o := range objs {
			if !o.Type().IsRegular() || !looseObjectRE.MatchString(o.Name()) {
				continue
			}
			if !made {
				if err := os.MkdirAll(filepath.Join(dst, p.Name()), 0o700); err != nil {
					return fail(err)
				}
				made = true
			}
			if err := link(filepath.Join(src, p.Name(), o.Name()), filepath.Join(dst, p.Name(), o.Name())); err != nil {
				return fail(err)
			}
		}
	}
	return true, ""
}

// capture stages the whole work tree (tracked and untracked, minus
// ignored files) into the shadow index and commits it. The shadow index
// persists between captures, so unchanged files are not re-hashed.
func (s *shadow) capture(ctx context.Context, message, parent string) (commit, tree string, warnings []string, err error) {
	g := s.git()
	_, addErr := g.strict(ctx, "add", "--all", "--ignore-errors", "--", ".")
	if addErr != nil {
		var ge *GitError
		if errors.As(addErr, &ge) {
			for _, line := range strings.Split(ge.Stderr, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "error:") {
					warnings = append(warnings, "not captured: "+strings.TrimSpace(strings.TrimPrefix(line, "error:")))
				}
			}
		}
	}
	tree, err = g.line(ctx, "write-tree")
	if err != nil {
		if addErr != nil {
			return "", "", nil, addErr
		}
		return "", "", nil, err
	}
	args := []string{"commit-tree", tree, "-m", message}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	commit, err = g.line(ctx, args...)
	if err != nil {
		return "", "", nil, err
	}
	if len(warnings) > 20 {
		n := len(warnings)
		warnings = append(warnings[:20], fmt.Sprintf("… and %d more files that could not be read", n-20))
	}
	return commit, tree, warnings, nil
}

func (s *shadow) updateRef(ctx context.Context, ref, oid string) error {
	return s.bare().run(ctx, "update-ref", "-m", "defenseclaw", ref, oid)
}

// ignoredEntries lists ignored paths, collapsing fully ignored directories
// ("node_modules/"), bounded by limit.
func (s *shadow) ignoredEntries(ctx context.Context, limit int) ([]string, error) {
	out, err := s.git().output(ctx, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--directory", "--no-empty-directory")
	if err != nil {
		return nil, err
	}
	entries := splitNUL(out)
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

// TreeChange is one path that differs between two trees.
type TreeChange struct {
	Path string `json:"path"`
	// Status is A (added), M (modified), D (deleted) or T (type changed),
	// from the first tree to the second.
	Status  string `json:"status"`
	OldMode string `json:"old_mode,omitempty"`
	NewMode string `json:"new_mode,omitempty"`
	OldOID  string `json:"old_oid,omitempty"`
	NewOID  string `json:"new_oid,omitempty"`
	Added   int    `json:"added,omitempty"`
	Deleted int    `json:"deleted,omitempty"`
	Binary  bool   `json:"binary,omitempty"`
}

const (
	modeGitlink = "160000"
	modeSymlink = "120000"
	modeExec    = "100755"
)

// diffTrees lists changes from a to b (either may be "" for the empty tree).
func diffTrees(ctx context.Context, g gitCmd, a, b string) ([]TreeChange, error) {
	if a == "" {
		a = emptyTree(ctx, g)
	}
	if b == "" {
		b = emptyTree(ctx, g)
	}
	raw, err := g.output(ctx, "diff-tree", "-r", "-z", "--no-renames", "--raw", "--no-ext-diff", "--no-textconv", a, b)
	if err != nil {
		return nil, err
	}
	var changes []TreeChange
	index := map[string]int{}
	parts := splitNUL(raw)
	for i := 0; i+1 < len(parts); i += 2 {
		meta := strings.Fields(strings.TrimPrefix(parts[i], ":"))
		if len(meta) < 5 {
			return nil, fmt.Errorf("workspace: unexpected diff-tree output %q", parts[i])
		}
		c := TreeChange{Path: parts[i+1], OldMode: meta[0], NewMode: meta[1], OldOID: meta[2], NewOID: meta[3], Status: meta[4][:1]}
		if strings.Trim(c.OldMode, "0") == "" {
			c.OldMode, c.OldOID = "", ""
		}
		if strings.Trim(c.NewMode, "0") == "" {
			c.NewMode, c.NewOID = "", ""
		}
		index[c.Path] = len(changes)
		changes = append(changes, c)
	}
	num, err := g.output(ctx, "diff-tree", "-r", "-z", "--no-renames", "--numstat", "--no-ext-diff", "--no-textconv", a, b)
	if err != nil {
		return nil, err
	}
	for _, entry := range splitNUL(num) {
		fields := strings.SplitN(entry, "\t", 3)
		if len(fields) != 3 {
			continue
		}
		i, ok := index[fields[2]]
		if !ok {
			continue
		}
		if fields[0] == "-" {
			changes[i].Binary = true
			continue
		}
		changes[i].Added, _ = strconv.Atoi(fields[0])
		changes[i].Deleted, _ = strconv.Atoi(fields[1])
	}
	return changes, nil
}

func emptyTree(ctx context.Context, g gitCmd) string {
	oid, err := g.line(ctx, "hash-object", "-t", "tree", "--stdin")
	if err == nil {
		return oid
	}
	return "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
}

// blobReader reads blob contents through one `git cat-file --batch`.
type blobReader struct {
	g gitCmd
}

// read returns the contents of the given blobs that are at most max bytes.
// Sizes are checked first so a huge blob is never buffered.
func (r blobReader) read(ctx context.Context, oids []string, max int64) (map[string][]byte, error) {
	out := make(map[string][]byte, len(oids))
	if len(oids) == 0 {
		return out, nil
	}
	var check bytes.Buffer
	for _, o := range oids {
		check.WriteString(o)
		check.WriteByte('\n')
	}
	g := r.g
	g.stdin = &check
	sizes, err := g.output(ctx, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	if err != nil {
		return nil, err
	}
	var in bytes.Buffer
	for _, line := range strings.Split(string(sizes), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[1] != "blob" {
			continue
		}
		if n, err := strconv.ParseInt(fields[2], 10, 64); err == nil && n <= max {
			in.WriteString(fields[0])
			in.WriteByte('\n')
		}
	}
	if in.Len() == 0 {
		return out, nil
	}
	g.stdin = &in
	data, err := g.output(ctx, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}
	br := bufio.NewReader(bytes.NewReader(data))
	for {
		header, err := br.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		fields := strings.Fields(header)
		if len(fields) == 2 && fields[1] == "missing" {
			continue
		}
		if len(fields) != 3 {
			return nil, fmt.Errorf("workspace: unexpected cat-file output %q", header)
		}
		size, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		if _, err := br.ReadByte(); err != nil && err != io.EOF {
			return nil, err
		}
		if fields[1] == "blob" && size <= max {
			out[fields[0]] = buf
		}
	}
	return out, nil
}
