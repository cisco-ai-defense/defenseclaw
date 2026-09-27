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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// MountKind says why a bind mount exists.
type MountKind string

const (
	// MountProject is the project folder itself, read-write.
	MountProject MountKind = "project"
	// MountPin re-binds a git directory onto itself (read-write) so the
	// agent cannot rename it away and plant a replacement.
	MountPin MountKind = "pin"
	// MountProtect is read-only git state that would run code on the host
	// (hooks, config, include files, commondir, worktree admin dirs).
	MountProtect MountKind = "protect"
	// MountMask hides a secret behind an empty read-only file or directory.
	MountMask MountKind = "mask"
	// MountContext is an extra reference folder, read-only.
	MountContext MountKind = "context"
)

// Mount is one docker-driver bind mount.
type Mount struct {
	Kind     MountKind `json:"kind"`
	Source   string    `json:"source"`
	Target   string    `json:"target"`
	ReadOnly bool      `json:"read_only"`
}

// MountOptions configures PlanMount. Values normally come from the
// openshell.workdir config block and `sandbox run` flags.
type MountOptions struct {
	// Project is the launch folder.
	Project string
	// Name is the sandbox name; it scopes mask files and mount state.
	Name string
	// DataDir is the DefenseClaw data directory.
	DataDir string
	// Home overrides the home directory used by the refusal matrix.
	Home string
	// TargetRoot is the container directory mounts live under ("/work").
	TargetRoot string
	// Masks are extra secret globs (openshell.workdir.masks). Unlike the
	// built-in names they also hide tracked files.
	Masks []string
	// Unmask lists paths or globs (relative to the project, or absolute
	// inside it) to keep visible even though they look like secrets.
	Unmask []string
	// MaskTracked masks tracked secret-named files even when they hold
	// exactly their committed contents. (A tracked file whose working copy
	// differs, or is marked skip-worktree or assume-unchanged, is always
	// masked by name and scanned like an untracked one.)
	MaskTracked bool
	// Context lists extra folders to mount read-only next to the project.
	Context []string
	// Protected lists further host paths that must never be shared.
	Protected []string
	// DisableContentScan turns off the content-based secret detector.
	DisableContentScan bool
	// Detector overrides DefaultSecretDetector.
	Detector SecretDetector
	// MaxWalkEntries bounds the secret scan walk (default 250k entries).
	// A folder with more is refused (*ScanIncompleteError): past the
	// limit nothing would be masked.
	MaxWalkEntries int
	// MaxContentScanFiles bounds content scanning (default 2k files).
	MaxContentScanFiles int
}

// ContextMount is a read-only reference folder.
type ContextMount struct {
	Source string       `json:"source"`
	Target string       `json:"target"`
	Masked []MaskedPath `json:"masked,omitempty"`
}

// MountPlan is everything a sandbox create call needs for a live mount.
type MountPlan struct {
	Name     string `json:"name"`
	Project  string `json:"project"`
	RepoName string `json:"repo_name"`
	// Target is the project's path inside the sandbox (/work/<repo>).
	Target string     `json:"target"`
	Git    *GitLayout `json:"git,omitempty"`
	Mounts []Mount    `json:"mounts"`
	// Masked lists hidden secrets in the project; context masks are on
	// each ContextMount.
	Masked   []MaskedPath `json:"masked,omitempty"`
	Unmasked []string     `json:"unmasked,omitempty"`
	// TrackedSecrets are secret-named files left visible because they hold
	// exactly their committed contents.
	TrackedSecrets []string       `json:"tracked_secrets,omitempty"`
	Protected      []string       `json:"protected,omitempty"`
	Contexts       []ContextMount `json:"contexts,omitempty"`
	// ReadWrite and ReadOnly are the Landlock paths the sandbox policy must
	// add (filesystem_policy.read_write / read_only).
	ReadWrite []string `json:"read_write"`
	ReadOnly  []string `json:"read_only,omitempty"`
	// RunAsUser/RunAsGroup are the host uid/gid for process.run_as_*, so
	// files the agent writes keep the operator's ownership.
	RunAsUser  string `json:"run_as_user"`
	RunAsGroup string `json:"run_as_group"`
	// Labels go on the sandbox (project identity for resume, mode).
	Labels   map[string]string `json:"labels"`
	Warnings []string          `json:"warnings,omitempty"`

	home string
}

// pinRecord is a host file or directory PlanMount created so it could be
// bind-mounted read-only; ReleaseMount removes it again.
type pinRecord struct {
	Path string `json:"path"`
	Dir  bool   `json:"dir,omitempty"`
	// Content is what a created file holds (commondir pin or empty
	// include); release only removes it if it still does.
	Content string `json:"content"`
	ID      FileID `json:"id"`
}

type mountState struct {
	Version int         `json:"version"`
	Name    string      `json:"name"`
	Project string      `json:"project"`
	Pins    []pinRecord `json:"pins,omitempty"`
	// Sources are every host path the sandbox binds; a pin another
	// sandbox still binds is not released (a stopped sandbox needs its
	// bind sources to start again).
	Sources []string `json:"sources,omitempty"`
}

// PlanMount validates opts.Project and prepares a live mount. Besides
// computing the mount list it creates, on the host: the empty mask files
// under the data dir, and any protection pin that must exist to be bound
// read-only (an empty .git/hooks, the commondir pin, a missing
// core.hooksPath directory or include file). Those pins are recorded so
// ReleaseMount can remove them when the sandbox is deleted.
func PlanMount(ctx context.Context, opts MountOptions) (*MountPlan, error) {
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
	srcOpts := SourceOptions{Home: opts.Home, DataDir: lay.dataDir, Protected: opts.Protected}
	src, err := ValidateSource(ctx, opts.Project, srcOpts)
	if err != nil {
		return nil, err
	}
	root := opts.TargetRoot
	if root == "" {
		root = DefaultTargetRoot
	}
	if !path.IsAbs(root) || path.Clean(root) == "/" {
		return nil, fmt.Errorf("workspace: target root %q must be an absolute directory below /", root)
	}
	root = path.Clean(root)
	home, _ := resolveHome(opts.Home)
	repo := RepoName(src.Path)
	plan := &MountPlan{
		Name:       opts.Name,
		Project:    src.Path,
		RepoName:   repo,
		Target:     path.Join(root, repo),
		Git:        src.Git,
		RunAsUser:  strconv.Itoa(os.Getuid()),
		RunAsGroup: strconv.Itoa(os.Getgid()),
		Warnings:   append([]string(nil), src.Warnings...),
		home:       home,
	}
	key, value := ProjectLabel(src.Path)
	plan.Labels = map[string]string{key: value, ModeLabelKey: "mount"}
	plan.Mounts = append(plan.Mounts, Mount{Kind: MountProject, Source: src.Path, Target: plan.Target})
	plan.ReadWrite = []string{plan.Target}

	state := &mountState{Version: 1, Name: opts.Name, Project: src.Path}
	ok := false
	defer func() {
		if !ok {
			releasePins(state.Pins)
		}
	}()

	if src.Git != nil {
		if err := planGitProtection(plan, state); err != nil {
			return nil, err
		}
	}

	scanOpts := secretScanOptions{
		patterns:     opts.Masks,
		unmask:       normalizeUnmask(opts.Unmask, src.Path),
		maskTracked:  opts.MaskTracked,
		detector:     opts.Detector,
		contentScan:  !opts.DisableContentScan,
		maxEntries:   opts.MaxWalkEntries,
		maxScanFiles: opts.MaxContentScanFiles,
	}
	if scanOpts.detector == nil {
		scanOpts.detector = DefaultSecretDetector()
	}
	if src.Git != nil {
		tracked, err := trackedFiles(ctx, src.Path, src.Git.GitDir)
		if err != nil {
			return nil, err
		}
		scanOpts.tracked = tracked
	}
	scan, err := detectSecrets(src.Path, scanOpts)
	if err != nil {
		return nil, err
	}
	plan.Masked = scan.masks
	plan.Unmasked = scan.unmasked
	plan.TrackedSecrets = scan.trackedSecrets
	plan.Warnings = append(plan.Warnings, scan.warnings...)

	usedTargets := map[string]string{plan.Target: src.Path}
	for _, c := range opts.Context {
		cm, warnings, err := planContext(c, src.Path, root, srcOpts, scanOpts, usedTargets)
		if err != nil {
			return nil, err
		}
		plan.Contexts = append(plan.Contexts, *cm)
		plan.Warnings = append(plan.Warnings, warnings...)
		plan.ReadOnly = append(plan.ReadOnly, cm.Target)
	}

	if len(plan.Masked) > 0 || contextMasks(plan.Contexts) > 0 {
		emptyFile, emptyDir, err := prepareMaskSources(lay.maskDir(opts.Name))
		if err != nil {
			return nil, err
		}
		for _, m := range plan.Masked {
			plan.Mounts = append(plan.Mounts, maskMount(m, plan.Target, emptyFile, emptyDir))
		}
		for _, c := range plan.Contexts {
			for _, m := range c.Masked {
				plan.Mounts = append(plan.Mounts, maskMount(m, c.Target, emptyFile, emptyDir))
			}
		}
	}
	for _, c := range plan.Contexts {
		plan.Mounts = append(plan.Mounts, Mount{Kind: MountContext, Source: c.Source, Target: c.Target, ReadOnly: true})
	}
	sortMounts(plan.Mounts)
	for _, m := range plan.Mounts {
		state.Sources = append(state.Sources, m.Source)
	}

	if err := writeJSON(lay.mountState(opts.Name), state); err != nil {
		return nil, err
	}
	ok = true
	return plan, nil
}

// planGitProtection adds the git pins and read-only binds.
func planGitProtection(plan *MountPlan, state *mountState) error {
	g := plan.Git
	gitRel, err := relSlash(plan.Project, g.GitDir)
	if err != nil {
		return err
	}
	target := func(hostPath string) string {
		rel, _ := relSlash(plan.Project, hostPath)
		return path.Join(plan.Target, rel)
	}
	protect := func(hostPath string) {
		plan.Mounts = append(plan.Mounts, Mount{Kind: MountProtect, Source: hostPath, Target: target(hostPath), ReadOnly: true})
	}

	pinGitDir := func(gitDir string, top bool) error {
		plan.Mounts = append(plan.Mounts, Mount{Kind: MountPin, Source: gitDir, Target: target(gitDir)})
		cfg := filepath.Join(gitDir, "config")
		if err := ensurePinFile(state, cfg, "", 0o644); err != nil {
			return err
		}
		protect(cfg)
		// Pin config.worktree read-only, even if it doesn't exist. An empty
		// file is harmless because git reads it only when the read-only main
		// config enables extensions.worktreeConfig.
		cfgWorktree := filepath.Join(gitDir, "config.worktree")
		if err := ensurePinFile(state, cfgWorktree, "", 0o644); err != nil {
			return err
		}
		protect(cfgWorktree)
		hooks := filepath.Join(gitDir, "hooks")
		if err := ensurePinDir(state, hooks); err != nil {
			return err
		}
		protect(hooks)
		commondir := filepath.Join(gitDir, "commondir")
		if !pathExists(commondir) || (top && g.StaleCommondirPin) {
			if err := ensurePinFile(state, commondir, commondirPin, 0o444); err != nil {
				return err
			}
		} else if err := checkCommondir(plan.Project, &GitLayout{GitDir: gitDir}); err != nil {
			return err
		}
		protect(commondir)
		return nil
	}
	if err := pinGitDir(g.GitDir, true); err != nil {
		return err
	}
	if g.DotGitFile {
		protect(filepath.Join(plan.Project, ".git"))
	}
	if g.HasWorktrees {
		protect(filepath.Join(g.GitDir, "worktrees"))
	}
	for _, sub := range g.Submodules {
		if err := pinGitDir(sub, false); err != nil {
			return err
		}
	}
	if g.HooksPath != "" && !samePath(g.HooksPath, plan.Project) {
		if err := ensurePinDir(state, g.HooksPath); err != nil {
			return err
		}
		protect(g.HooksPath)
	} else if g.HooksPath != "" {
		return &NeedsCopyError{Path: plan.Project, Reason: "core.hooksPath is the project folder itself, so hooks cannot be protected"}
	}
	for _, inc := range g.IncludeFiles {
		if err := ensurePinFile(state, inc, "", 0o644); err != nil {
			return err
		}
		protect(inc)
	}

	plan.Protected = []string{gitRel + "/hooks", gitRel + "/config", gitRel + "/config.worktree"}
	if g.DotGitFile {
		plan.Protected = append(plan.Protected, ".git")
	}
	if g.HooksPath != "" {
		rel, _ := relSlash(plan.Project, g.HooksPath)
		plan.Protected = append(plan.Protected, rel)
	}
	for _, inc := range g.IncludeFiles {
		rel, _ := relSlash(plan.Project, inc)
		plan.Protected = append(plan.Protected, rel)
	}
	if len(g.Submodules) > 0 {
		plan.Protected = append(plan.Protected, fmt.Sprintf("%d submodule git dirs", len(g.Submodules)))
	}
	return nil
}

func ensurePinFile(state *mountState, p, content string, mode fs.FileMode) error {
	info, err := os.Lstat(p)
	if err == nil {
		if !info.Mode().IsRegular() {
			return &NeedsCopyError{Path: state.Project, Reason: p + " is not a regular file"}
		}
		if content == commondirPin {
			// A stale pin from an earlier session: take it over so the
			// release of this session removes it.
			if id, ok := identityOf(info); ok {
				state.Pins = append(state.Pins, pinRecord{Path: p, Content: content, ID: id})
			}
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		return fmt.Errorf("workspace: create protection pin %s: %w", p, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		return err
	}
	info, err = os.Lstat(p)
	if err != nil {
		return err
	}
	id, _ := identityOf(info)
	state.Pins = append(state.Pins, pinRecord{Path: p, Content: content, ID: id})
	return nil
}

func ensurePinDir(state *mountState, p string) error {
	info, err := os.Lstat(p)
	if err == nil {
		if !info.IsDir() {
			return &NeedsCopyError{Path: state.Project, Reason: p + " is not a directory"}
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(p, 0o755); err != nil {
		return fmt.Errorf("workspace: create protection pin %s: %w", p, err)
	}
	info, err = os.Lstat(p)
	if err != nil {
		return err
	}
	id, _ := identityOf(info)
	state.Pins = append(state.Pins, pinRecord{Path: p, Dir: true, ID: id})
	return nil
}

func planContext(dir, project, root string, srcOpts SourceOptions, scanOpts secretScanOptions, used map[string]string) (*ContextMount, []string, error) {
	real, warnings, err := validateShareable(dir, srcOpts)
	if err != nil {
		return nil, nil, err
	}
	if within(real, project) || within(project, real) {
		return nil, nil, &SourceError{Path: real, Reason: "a context folder must not overlap the project"}
	}
	for _, other := range used {
		if within(real, other) || within(other, real) {
			return nil, nil, &SourceError{Path: real, Reason: "context folders must not overlap each other"}
		}
	}
	base := RepoName(real)
	target := path.Join(root, base)
	for i := 2; ; i++ {
		if _, taken := used[target]; !taken {
			break
		}
		target = path.Join(root, fmt.Sprintf("%s-%d", base, i))
	}
	used[target] = real
	ctxScan := scanOpts
	ctxScan.tracked = nil
	ctxScan.unmask = normalizeUnmask(scanOpts.unmask, real)
	scan, err := detectSecrets(real, ctxScan)
	if err != nil {
		return nil, nil, err
	}
	return &ContextMount{Source: real, Target: target, Masked: scan.masks}, append(warnings, scan.warnings...), nil
}

func contextMasks(cs []ContextMount) int {
	n := 0
	for _, c := range cs {
		n += len(c.Masked)
	}
	return n
}

// normalizeUnmask turns absolute --unmask paths inside root into relative
// ones; everything else is kept as a relative path or glob.
func normalizeUnmask(in []string, root string) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		if filepath.IsAbs(u) {
			rel, err := filepath.Rel(root, filepath.Clean(u))
			if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
				continue
			}
			u = filepath.ToSlash(rel)
		}
		out = append(out, strings.TrimPrefix(filepath.ToSlash(u), "./"))
	}
	return out
}

// prepareMaskSources creates the shared empty file and empty directory the
// masks bind from. Both are read-only and owned by the operator.
func prepareMaskSources(dir string) (string, string, error) {
	if err := ensurePrivateDir(dir); err != nil {
		return "", "", err
	}
	emptyFile := filepath.Join(dir, "empty")
	emptyDir := filepath.Join(dir, "emptydir")
	if info, err := os.Lstat(emptyFile); err == nil {
		if !info.Mode().IsRegular() || info.Size() != 0 {
			if err := os.Remove(emptyFile); err != nil {
				return "", "", err
			}
		}
	}
	if !pathExists(emptyFile) {
		if err := os.WriteFile(emptyFile, nil, 0o444); err != nil {
			return "", "", fmt.Errorf("workspace: create mask file: %w", err)
		}
	}
	if err := os.Chmod(emptyFile, 0o444); err != nil {
		return "", "", err
	}
	if info, err := os.Lstat(emptyDir); err == nil && !info.IsDir() {
		if err := os.Remove(emptyDir); err != nil {
			return "", "", err
		}
	}
	if !pathExists(emptyDir) {
		if err := os.Mkdir(emptyDir, 0o555); err != nil {
			return "", "", fmt.Errorf("workspace: create mask directory: %w", err)
		}
	}
	if err := os.Chmod(emptyDir, 0o555); err != nil {
		return "", "", err
	}
	entries, err := os.ReadDir(emptyDir)
	if err != nil {
		return "", "", err
	}
	if len(entries) != 0 {
		return "", "", fmt.Errorf("workspace: mask directory %s is not empty", emptyDir)
	}
	return emptyFile, emptyDir, nil
}

func maskMount(m MaskedPath, root, emptyFile, emptyDir string) Mount {
	src := emptyFile
	if m.Dir {
		src = emptyDir
	}
	return Mount{Kind: MountMask, Source: src, Target: path.Join(root, m.Rel), ReadOnly: true}
}

// sortMounts orders parents before children so every over-mount lands on
// top of the mount it shadows.
func sortMounts(ms []Mount) {
	sort.SliceStable(ms, func(i, j int) bool {
		di, dj := strings.Count(ms[i].Target, "/"), strings.Count(ms[j].Target, "/")
		if di != dj {
			return di < dj
		}
		return ms[i].Target < ms[j].Target
	})
}

func relSlash(root, p string) (string, error) {
	rel, err := filepath.Rel(root, p)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("workspace: %s is not inside %s", p, root)
	}
	return filepath.ToSlash(rel), nil
}

// DriverConfig returns the SandboxTemplate.DriverConfig value for the
// OpenShell docker driver: {"docker": {"mounts": [...]}}. The shape uses
// only structpb-compatible types.
func (p *MountPlan) DriverConfig() map[string]any {
	mounts := make([]any, 0, len(p.Mounts))
	for _, m := range p.Mounts {
		mounts = append(mounts, map[string]any{
			"type":      "bind",
			"source":    m.Source,
			"target":    m.Target,
			"read_only": m.ReadOnly,
		})
	}
	return map[string]any{"docker": map[string]any{"mounts": mounts}}
}

// DriverConfigJSON is DriverConfig for `openshell sandbox create
// --driver-config-json`.
func (p *MountPlan) DriverConfigJSON() (string, error) {
	b, err := json.Marshal(p.DriverConfig())
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// MaskedRels returns the masked project paths; non-git snapshots skip them
// because the sandbox cannot change them.
func (p *MountPlan) MaskedRels() []string {
	out := make([]string, 0, len(p.Masked))
	for _, m := range p.Masked {
		out = append(out, m.Rel)
	}
	return out
}

// Summary is the launch-banner view of a plan.
type Summary struct {
	Project   string   `json:"project"`
	Hidden    []string `json:"hidden,omitempty"`
	Protected []string `json:"protected,omitempty"`
	Context   []string `json:"context,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Summary describes the plan for the launch banner.
func (p *MountPlan) Summary() Summary {
	s := Summary{
		Project:   fmt.Sprintf("%s → %s (live)", abbreviateHome(p.Project, p.home), p.Target),
		Protected: append([]string(nil), p.Protected...),
		Warnings:  append([]string(nil), p.Warnings...),
	}
	for _, m := range p.Masked {
		s.Hidden = append(s.Hidden, displayMask(m))
	}
	for _, c := range p.Contexts {
		s.Context = append(s.Context, fmt.Sprintf("%s → %s (read-only)", abbreviateHome(c.Source, p.home), c.Target))
		for _, m := range c.Masked {
			s.Hidden = append(s.Hidden, path.Join(path.Base(c.Target), displayMask(m)))
		}
	}
	return s
}

func displayMask(m MaskedPath) string {
	if m.Dir {
		return m.Rel + "/"
	}
	return m.Rel
}

// Lines renders the summary as aligned banner lines.
func (s Summary) Lines() []string {
	row := func(label, text string) string { return fmt.Sprintf("%-10s%s", label, text) }
	lines := []string{row("Project", s.Project)}
	if len(s.Hidden) > 0 {
		lines = append(lines, row("Hidden", strings.Join(firstN(s.Hidden, 8), "  ")+"  (secret files appear empty inside; --unmask PATH to share)"))
	}
	if len(s.Protected) > 0 {
		lines = append(lines, row("Protected", strings.Join(s.Protected, " ")+" (read-only)"))
	}
	for _, c := range s.Context {
		lines = append(lines, row("Context", c))
	}
	lines = append(lines, row("", "Not visible: everything else on this machine"))
	for _, w := range s.Warnings {
		lines = append(lines, "⚠ "+w)
	}
	return lines
}

// ReleaseMount removes the protection pins PlanMount created for name and
// its mask files. Call it when the sandbox is deleted (not when it is only
// stopped: a restart reuses the same mounts). Pins that changed since they
// were created are left in place.
func ReleaseMount(dataDir, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	lay, err := newLayout(dataDir)
	if err != nil {
		return err
	}
	var state mountState
	if err := readJSON(lay.mountState(name), &state); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	inUse := sourcesInUse(lay, name)
	var mine []pinRecord
	if _, unknown := inUse["*"]; !unknown {
		for _, p := range state.Pins {
			if _, shared := inUse[p.Path]; !shared {
				mine = append(mine, p)
			}
		}
	}
	releasePins(mine)
	if err := os.RemoveAll(lay.maskDir(name)); err != nil {
		if chmodTree(lay.maskDir(name)) == nil {
			err = os.RemoveAll(lay.maskDir(name))
		}
		if err != nil {
			return fmt.Errorf("workspace: remove mask files: %w", err)
		}
	}
	return os.Remove(lay.mountState(name))
}

// sourcesInUse collects the bind sources of every other sandbox's mount
// state. When the state of another sandbox cannot be read its sources
// are unknown, so nothing it might share is released.
func sourcesInUse(lay layout, except string) map[string]struct{} {
	out := map[string]struct{}{}
	entries, err := os.ReadDir(filepath.Join(lay.dataDir, "sandboxes"))
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == except || ValidateName(e.Name()) != nil {
			continue
		}
		var st mountState
		if err := readJSON(lay.mountState(e.Name()), &st); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				out["*"] = struct{}{}
			}
			continue
		}
		for _, s := range st.Sources {
			out[s] = struct{}{}
		}
		for _, p := range st.Pins {
			out[p.Path] = struct{}{}
		}
	}
	if _, unknown := out["*"]; unknown {
		// Treat every pin as shared rather than guess.
		return map[string]struct{}{"*": {}}
	}
	return out
}

// releasePins removes created pins in reverse order, but only while each
// is still the object DefenseClaw created with the content it wrote.
func releasePins(pins []pinRecord) {
	for i := len(pins) - 1; i >= 0; i-- {
		pin := pins[i]
		info, err := os.Lstat(pin.Path)
		if err != nil {
			continue
		}
		if id, ok := identityOf(info); ok && id != pin.ID {
			continue
		}
		if pin.Dir {
			if info.IsDir() {
				_ = os.Remove(pin.Path) // only succeeds while empty
			}
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(pin.Path)
		if err != nil || string(data) != pin.Content {
			continue
		}
		_ = os.Remove(pin.Path)
	}
}

func chmodTree(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return os.Chmod(p, 0o700)
		}
		return nil
	})
}
