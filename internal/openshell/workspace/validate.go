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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// SourceOptions configures ValidateSource.
type SourceOptions struct {
	// Home is the operator's home directory; "" uses os.UserHomeDir.
	Home string
	// DataDir is the DefenseClaw data directory. It is never shared.
	DataDir string
	// Protected lists further host paths that must never be shared, be
	// shared from inside, or be contained in a shared folder.
	Protected []string
}

// Source is a folder that may be shared with a sandbox.
type Source struct {
	// Path is absolute, cleaned and free of symlinked components.
	Path string
	// Git describes the repository when Path is the root of a git work
	// tree; nil for plain folders.
	Git *GitLayout
	// Warnings are shown to the operator but do not block the launch.
	Warnings []string
}

// GitLayout is the git state a live mount has to protect.
type GitLayout struct {
	// GitDir is the absolute git directory; always inside the project.
	GitDir string
	// DotGitFile is set when <project>/.git is a "gitdir:" pointer file.
	DotGitFile bool
	// StaleCommondirPin is set when a previous session's commondir pin
	// (a file containing ".") was never released.
	StaleCommondirPin bool
	// HooksPath is core.hooksPath when it resolves inside the project.
	HooksPath string
	// IncludeFiles are config include targets inside the project.
	IncludeFiles []string
	// Submodules are absolute git directories under GitDir/modules.
	Submodules []string
	// HasWorktrees is set when GitDir/worktrees exists (the project has
	// linked worktrees elsewhere on the host).
	HasWorktrees bool
}

// maxProtectedSubmodules bounds how many submodule git dirs a mount pins;
// beyond it the mount list gets unwieldy and copy mode is the safer answer.
const maxProtectedSubmodules = 32

// Top-level host directories that are never shared, nor anything under
// them. Paths are compared after symlink resolution and by file identity,
// so /etc on macOS (a symlink to /private/etc) is covered by /private/etc.
var refusedTrees = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
	"/proc", "/root", "/run", "/sbin", "/snap", "/sys", "/usr", "/nix",
	"/var/run", "/var/lib", "/var/log", "/var/cache", "/var/spool", "/var/db",
	"/System", "/Library", "/Applications", "/opt/homebrew",
	"/private/etc", "/private/var/db", "/private/var/root", "/private/var/run",
	"/private/var/log",
}

// Directories that are refused themselves (they hold many unrelated
// projects or other users' data) but whose subdirectories may be shared.
var refusedExact = []string{
	"/private", "/private/tmp", "/private/var", "/private/var/tmp",
	"/private/var/folders", "/var", "/var/tmp", "/var/folders", "/tmp",
	"/opt", "/srv", "/mnt", "/media", "/home", "/Users", "/Volumes", "/data",
}

// Home-relative locations that hold credentials or DefenseClaw/OpenShell
// state. Sharing one of them, a folder inside one, or a folder that
// contains one (after symlink resolution) is refused; credentialTrees
// adds their XDG variants.
var refusedHomeTrees = []string{
	".ssh", ".aws", ".config", ".gnupg", ".kube", ".docker", ".azure",
	".password-store", ".local/share/keyrings", ".local/share/openshell",
	".local/state/openshell", ".defenseclaw", ".openshell", ".terraform.d",
	".oci", ".m2", ".gradle", "Library",
}

// ValidateSource checks that path may be bind-mounted into a sandbox and
// describes its git layout. A *SourceError means never; a *NeedsCopyError
// means only with --copy.
func ValidateSource(ctx context.Context, path string, opts SourceOptions) (*Source, error) {
	if !platformSupported() {
		return nil, ErrUnsupportedPlatform
	}
	real, warnings, err := validateShareable(path, opts)
	if err != nil {
		return nil, err
	}
	src := &Source{Path: real, Warnings: warnings}
	layout, gitWarnings, err := detectGit(ctx, real, opts)
	if err != nil {
		return nil, err
	}
	src.Git = layout
	src.Warnings = append(src.Warnings, gitWarnings...)
	return src, nil
}

// validateShareable applies the path refusal matrix and returns the
// symlink-free absolute path.
func validateShareable(path string, opts SourceOptions) (string, []string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil, &SourceError{Path: path, Reason: "no folder given"}
	}
	for _, r := range path {
		if unicode.IsControl(r) {
			return "", nil, &SourceError{Path: fmt.Sprintf("%q", path), Reason: "the path contains control characters"}
		}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", nil, &SourceError{Path: path, Reason: err.Error()}
	}
	abs = filepath.Clean(abs)
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", nil, &SourceError{Path: abs, Reason: "it does not exist"}
		}
		return "", nil, &SourceError{Path: abs, Reason: err.Error()}
	}
	if real != abs {
		return "", nil, &SourceError{
			Path:   abs,
			Reason: "the path goes through a symbolic link",
			Hint:   "launch from " + real + " instead",
		}
	}
	info, err := os.Stat(real)
	if err != nil {
		return "", nil, &SourceError{Path: real, Reason: err.Error()}
	}
	if !info.IsDir() {
		return "", nil, &SourceError{Path: real, Reason: "it is not a directory"}
	}
	if real == "/" || strings.Count(real, "/") < 2 {
		return "", nil, &SourceError{Path: real, Reason: "it is a top-level system directory"}
	}
	for _, p := range refusedExact {
		if samePath(real, p) {
			return "", nil, &SourceError{Path: real, Reason: "it holds data for many projects or users", Hint: "launch from the project folder itself"}
		}
	}
	for _, p := range refusedTrees {
		if within(real, p) {
			return "", nil, &SourceError{Path: real, Reason: "it is part of the operating system (" + p + ")"}
		}
	}

	home, err := resolveHome(opts.Home)
	if err != nil {
		return "", nil, err
	}
	if home != "" {
		if samePath(real, home) {
			return "", nil, &SourceError{Path: real, Reason: "it is your home directory", Hint: "launch from a project folder inside it"}
		}
		if within(home, real) {
			return "", nil, &SourceError{Path: real, Reason: "it contains your home directory"}
		}
	}
	for _, t := range credentialTrees(home) {
		switch {
		case within(real, t.path):
			return "", nil, &SourceError{Path: real, Reason: "it is inside " + abbreviateHome(t.name, home) + ", which holds credentials or sandbox state"}
		case within(t.path, real):
			return "", nil, &SourceError{Path: real, Reason: "it contains " + abbreviateHome(t.name, home) + ", which holds credentials or sandbox state"}
		}
	}
	protected := append([]string(nil), opts.Protected...)
	if opts.DataDir != "" {
		protected = append(protected, opts.DataDir)
	}
	for _, p := range protected {
		if p == "" {
			continue
		}
		rp := resolveExisting(p)
		switch {
		case within(real, rp):
			return "", nil, &SourceError{Path: real, Reason: "it is inside " + rp + ", which must not be shared"}
		case within(rp, real):
			return "", nil, &SourceError{Path: real, Reason: "it contains " + rp + ", which must not be shared"}
		}
	}

	var warnings []string
	if uid, ok := ownerUID(info); ok && uid != os.Getuid() {
		warnings = append(warnings, fmt.Sprintf("%s is owned by uid %d but the agent runs as uid %d; it may not be able to write there", real, uid, os.Getuid()))
	}
	return real, warnings, nil
}

// credentialTree is a refused credential or state directory: path is
// compared, name is what the refusal shows.
type credentialTree struct{ path, name string }

// credentialTrees lists the directories no share may be inside of or
// contain: refusedHomeTrees below home, their XDG base-directory homes
// ($XDG_CONFIG_HOME stands for ~/.config, $XDG_DATA_HOME/{keyrings,
// openshell} and $XDG_STATE_HOME/openshell for their ~/.local variants),
// and the OpenShell config directory as openshell.UserConfigDir resolves
// it. Each is listed as named and, when that differs, with its symbolic
// links resolved: a dotfile manager may link ~/.config elsewhere, and the
// share itself is always a resolved path.
func credentialTrees(home string) []credentialTree {
	var out []credentialTree
	add := func(p string) {
		if p == "" || !filepath.IsAbs(p) {
			return
		}
		p = filepath.Clean(p)
		out = append(out, credentialTree{path: p, name: p})
		if r := resolveExisting(p); r != p {
			out = append(out, credentialTree{path: r, name: p})
		}
	}
	if home != "" {
		for _, rel := range refusedHomeTrees {
			add(filepath.Join(home, rel))
		}
	}
	// The XDG spec ignores relative values; so does this.
	add(os.Getenv("XDG_CONFIG_HOME"))
	if data := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(data) {
		add(filepath.Join(data, "keyrings"))
		add(filepath.Join(data, "openshell"))
	}
	if state := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(state) {
		add(filepath.Join(state, "openshell"))
	}
	if dir, err := openshell.UserConfigDir(); err == nil {
		add(dir)
	}
	return out
}

func resolveHome(home string) (string, error) {
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil || h == "" {
			return "", nil
		}
		home = h
	}
	abs, err := filepath.Abs(home)
	if err != nil {
		return "", fmt.Errorf("workspace: home directory: %w", err)
	}
	return resolveExisting(abs), nil
}

// Overlaps reports whether a shared folder and a protected path overlap:
// the path is the folder, lies inside it or holds it. Symbolic links are
// resolved and, where both exist, file identity is compared (so a
// case-insensitive filesystem or a bind mount cannot hide the overlap).
// This is the relation ValidateSource refuses for SourceOptions.Protected;
// a caller that must keep re-checking a share it already validated (the
// sandbox manager, for the policy files a sandbox could rewrite) uses it
// directly.
func Overlaps(share, protected string) bool {
	if share == "" || protected == "" {
		return false
	}
	rs, rp := resolveExisting(share), resolveExisting(protected)
	return within(rs, rp) || within(rp, rs)
}

// resolveExisting resolves symlinks in the longest existing prefix of p so
// a not-yet-created protected path still compares correctly.
func resolveExisting(p string) string {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	dir, base := filepath.Split(p)
	if dir == "" || dir == p {
		return p
	}
	return filepath.Join(resolveExisting(strings.TrimSuffix(dir, string(filepath.Separator))), base)
}

// samePath reports whether a and b name the same directory entry, by
// string or, when both exist, by file identity (so case-insensitive
// filesystems and bind mounts cannot sneak past a string compare).
func samePath(a, b string) bool {
	// A relative path (the empty one included) would resolve against the
	// process's working directory, which says nothing about either path.
	if !filepath.IsAbs(a) || !filepath.IsAbs(b) {
		return false
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == b {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// within reports whether child is parent or lies below it.
func within(child, parent string) bool {
	child, parent = filepath.Clean(child), filepath.Clean(parent)
	if child == parent || strings.HasPrefix(child, strings.TrimSuffix(parent, "/")+"/") {
		return true
	}
	pi, err := os.Stat(parent)
	if err != nil {
		return false
	}
	for p := child; ; {
		if ci, err := os.Stat(p); err == nil && os.SameFile(ci, pi) {
			return true
		}
		next := filepath.Dir(p)
		if next == p {
			return false
		}
		p = next
	}
}

// strictlyWithin reports whether child lies below parent (not equal).
func strictlyWithin(child, parent string) bool {
	return within(child, parent) && !samePath(child, parent)
}

func abbreviateHome(p, home string) string {
	if home != "" && (p == home || strings.HasPrefix(p, home+"/")) {
		return "~" + strings.TrimPrefix(p, home)
	}
	return p
}

// detectGit inspects <project>/.git. It returns nil for plain folders.
func detectGit(ctx context.Context, project string, opts SourceOptions) (*GitLayout, []string, error) {
	dotGit := filepath.Join(project, ".git")
	info, err := os.Lstat(dotGit)
	if errors.Is(err, fs.ErrNotExist) {
		var warnings []string
		if parent := enclosingRepo(project); parent != "" {
			warnings = append(warnings, fmt.Sprintf(
				"%s is inside the git repository at %s; the sandbox sees it as a plain folder (launch from %s to give the agent git)",
				project, parent, parent))
		}
		return nil, warnings, nil
	}
	if err != nil {
		return nil, nil, &SourceError{Path: dotGit, Reason: err.Error()}
	}
	layout := &GitLayout{}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		return nil, nil, &NeedsCopyError{Path: project, Reason: ".git is a symbolic link"}
	case info.Mode().IsRegular():
		gitDir, err := readGitFile(project, dotGit)
		if err != nil {
			return nil, nil, err
		}
		layout.GitDir = gitDir
		layout.DotGitFile = true
	case info.IsDir():
		layout.GitDir = dotGit
	default:
		return nil, nil, &SourceError{Path: dotGit, Reason: "it is not a file or directory"}
	}

	for _, need := range []string{"HEAD", "objects", "refs"} {
		if !pathExists(filepath.Join(layout.GitDir, need)) {
			return nil, nil, &NeedsCopyError{Path: project, Reason: "its git directory is incomplete (missing " + need + ")"}
		}
	}
	if err := checkCommondir(project, layout); err != nil {
		return nil, nil, err
	}

	cfg := filepath.Join(layout.GitDir, "config")
	g := gitCmd{dir: project}
	if wt := gitConfigValue(ctx, g, cfg, "core.worktree"); wt != "" {
		return nil, nil, &NeedsCopyError{Path: project, Reason: "its git config sets core.worktree=" + wt}
	}
	home, _ := resolveHome(opts.Home)
	if hp := gitConfigValue(ctx, g, cfg, "core.hooksPath"); hp != "" {
		resolved := expandGitPath(hp, project, home)
		if within(resolved, project) {
			layout.HooksPath = resolveExisting(resolved)
			if !within(layout.HooksPath, project) {
				return nil, nil, &NeedsCopyError{Path: project, Reason: "core.hooksPath resolves outside the folder through a symbolic link"}
			}
		}
	}
	includes, err := includeFiles(ctx, g, cfg, project, home, 0)
	if err != nil {
		return nil, nil, err
	}
	layout.IncludeFiles = includes

	var warnings []string
	subs, err := submoduleGitDirs(filepath.Join(layout.GitDir, "modules"))
	if err != nil {
		return nil, nil, err
	}
	if len(subs) > maxProtectedSubmodules {
		return nil, nil, &NeedsCopyError{Path: project, Reason: fmt.Sprintf("it has %d submodule git directories (at most %d can be protected in a live mount)", len(subs), maxProtectedSubmodules)}
	}
	layout.Submodules = subs
	layout.HasWorktrees = pathExists(filepath.Join(layout.GitDir, "worktrees"))
	warnings = append(warnings, alternatesWarnings(layout.GitDir, project)...)
	return layout, warnings, nil
}

// readGitFile resolves a "gitdir: <path>" pointer file. The target must be
// a directory inside the project; worktrees and submodule checkouts whose
// git data lives elsewhere need copy mode.
func readGitFile(project, dotGit string) (string, error) {
	data, err := os.ReadFile(dotGit)
	if err != nil {
		return "", &SourceError{Path: dotGit, Reason: err.Error()}
	}
	if len(data) > 4096 {
		return "", &NeedsCopyError{Path: project, Reason: ".git is an unexpectedly large file"}
	}
	line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	target, ok := strings.CutPrefix(line, "gitdir:")
	if !ok {
		return "", &NeedsCopyError{Path: project, Reason: ".git is a file without a gitdir: line"}
	}
	target = strings.TrimSpace(target)
	if !filepath.IsAbs(target) {
		target = filepath.Join(project, target)
	}
	real, err := filepath.EvalSymlinks(filepath.Clean(target))
	if err != nil {
		return "", &NeedsCopyError{Path: project, Reason: "its .git file points at " + target + ", which cannot be resolved"}
	}
	if !strictlyWithin(real, project) {
		return "", &NeedsCopyError{Path: project, Reason: "its git directory lives at " + real + ", outside the folder (a git worktree or submodule checkout)"}
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		return "", &NeedsCopyError{Path: project, Reason: "its .git file points at " + real + ", which is not a directory"}
	}
	return real, nil
}

// commondirPin is the content of the file a live mount places at
// <gitdir>/commondir: "." makes git's common dir the git dir itself, so the
// pin is a no-op for git while its read-only bind stops the agent from
// redirecting config and hooks to a directory it controls.
const commondirPin = ".\n"

func checkCommondir(project string, layout *GitLayout) error {
	path := filepath.Join(layout.GitDir, "commondir")
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return &SourceError{Path: path, Reason: err.Error()}
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return &NeedsCopyError{Path: project, Reason: "its git directory has an unusual commondir entry"}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return &SourceError{Path: path, Reason: err.Error()}
	}
	value := strings.TrimRight(string(data), "\r\n")
	target := value
	if !filepath.IsAbs(target) {
		target = filepath.Join(layout.GitDir, target)
	}
	if samePath(target, layout.GitDir) {
		layout.StaleCommondirPin = string(data) == commondirPin
		return nil
	}
	return &NeedsCopyError{Path: project, Reason: "it is a linked worktree; its shared git data lives at " + filepath.Clean(target)}
}

// enclosingRepo returns the nearest ancestor of dir that has a .git entry.
func enclosingRepo(dir string) string {
	for p := filepath.Dir(dir); ; {
		if pathExists(filepath.Join(p, ".git")) {
			return p
		}
		next := filepath.Dir(p)
		if next == p {
			return ""
		}
		p = next
	}
}

// gitConfigValue reads one key from a single config file (plus its
// includes). "git config --file" never consults the repository, so this is
// safe on hostile content; errors read as "unset".
func gitConfigValue(ctx context.Context, g gitCmd, file, key string) string {
	out, code, err := g.outputCode(ctx, "config", "--file", file, "--includes", "--get", key)
	if err != nil || code != 0 {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// expandGitPath applies git's path rules: "~/" is the home directory and a
// relative path is relative to base.
func expandGitPath(p, base, home string) string {
	switch {
	case p == "~" && home != "":
		p = home
	case strings.HasPrefix(p, "~/") && home != "":
		p = filepath.Join(home, p[2:])
	case !filepath.IsAbs(p):
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}

// includeFiles lists config include targets inside the project, following
// includes that are themselves inside the project. Targets outside it are
// not agent-writable and need no protection.
func includeFiles(ctx context.Context, g gitCmd, file, project, home string, depth int) ([]string, error) {
	if depth > 5 {
		return nil, &NeedsCopyError{Path: project, Reason: "its git config includes are nested too deeply"}
	}
	out, code, err := g.outputCode(ctx, "config", "--file", file, "--null", "--get-regexp", `^include(if\..*)?\.path$`)
	if err != nil || code != 0 {
		return nil, nil
	}
	var result []string
	for _, entry := range splitNUL(out) {
		_, value, ok := strings.Cut(entry, "\n")
		if !ok || value == "" {
			continue
		}
		target := expandGitPath(value, filepath.Dir(file), home)
		if !within(target, project) {
			continue
		}
		real := resolveExisting(target)
		if !within(real, project) {
			return nil, &NeedsCopyError{Path: project, Reason: "a git config include resolves outside the folder through a symbolic link"}
		}
		result = append(result, real)
		if pathExists(real) {
			nested, err := includeFiles(ctx, g, real, project, home, depth+1)
			if err != nil {
				return nil, err
			}
			result = append(result, nested...)
		}
	}
	return dedupe(result), nil
}

// submoduleGitDirs finds git directories under <gitdir>/modules (they may
// nest: modules/a/modules/b).
func submoduleGitDirs(modules string) ([]string, error) {
	info, err := os.Lstat(modules)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, nil
	}
	var dirs []string
	err = filepath.WalkDir(modules, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !d.IsDir() || p == modules {
			return nil
		}
		switch d.Name() {
		case "objects", "refs", "logs", "hooks", "info", "lfs", "worktrees":
			return fs.SkipDir
		}
		if pathExists(filepath.Join(p, "HEAD")) && pathExists(filepath.Join(p, "objects")) {
			dirs = append(dirs, p)
			if len(dirs) > maxProtectedSubmodules {
				return fs.SkipAll
			}
		}
		return nil
	})
	return dirs, err
}

func alternatesWarnings(gitDir, project string) []string {
	data, err := os.ReadFile(filepath.Join(gitDir, "objects", "info", "alternates"))
	if err != nil {
		return nil
	}
	var warnings []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := line
		if !filepath.IsAbs(p) {
			p = filepath.Join(gitDir, "objects", p)
		}
		if !within(p, project) {
			warnings = append(warnings, "git objects borrowed from "+filepath.Clean(p)+" are not visible inside the sandbox; some history may be missing there")
		}
	}
	return warnings
}

func dedupe(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
