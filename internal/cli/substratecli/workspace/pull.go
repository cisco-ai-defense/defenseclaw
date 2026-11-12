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
	"path"
	"sort"
	"strings"
	"time"

	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// largeChangeLines is the size of a change, in added plus deleted lines,
// that the review calls out.
const largeChangeLines = 1000

// PullOptions configures Pull.
type PullOptions struct {
	// Exec runs the capture in the actor and streams the result bundle
	// back: the *Client that Start used.
	Exec osw.Execer
	// DataDir and Name identify the copy Start made.
	DataDir string
	Name    string
	// MaxBundleBytes caps the result bundle (1 GiB by default); Timeout the
	// in-actor capture (10 minutes).
	MaxBundleBytes int64
	Timeout        time.Duration
	// Scanners and SensitiveGlobs feed the review (the defaults when nil
	// and empty).
	Scanners       []osw.ContentScanner
	SensitiveGlobs []string
}

// File is one changed file of a review.
type File struct {
	Path string
	// Status is "added", "modified", "deleted" or "type changed".
	Status string
	// Flags say in plain words why the file needs a look before it is
	// brought back; empty for an ordinary change.
	Flags []string
}

// Review is the agent's work, verified and reviewed. Nothing is in the
// project yet.
type Review struct {
	// Changed lists the files the actor changed. Flagged files come first
	// (most serious first), then the others by path.
	Changed []File
	// Flagged counts the files with at least one flag.
	Flagged int
	// Summary is "8 files changed (+212 -37)".
	Summary string
	// Text is the review as the CLI prints it.
	Text string
	// Diff is what a patch would hold, without binary data (cut at 4 MiB).
	Diff []byte
	// Sensitive is set when some change can run code on this machine or
	// holds a secret: bringing it into the working tree needs a yes.
	Sensitive bool
	// Dropped are held-back (secret) paths the actor changed; those
	// changes are not brought back.
	Dropped []string
	// Blocking are reasons the apply and branch modes are refused.
	Blocking []string
	Warnings []string
	// Empty is true when the actor changed nothing that would be applied.
	Empty bool
	// Result is the underlying pull, for callers that need more.
	Result *osw.PullResult
}

// Pull reads the agent's work out of the actor, verifies it against the
// history that was uploaded, drops changes to held-back secrets and reviews
// what is left. The review is the same one `sandbox pull` shows (flags for
// hooks, CI, scripts, executables, symlinks, ignore rules and secrets in the
// content), with the reasons in plain words.
func Pull(ctx context.Context, opts PullOptions) (*Review, error) {
	if opts.Exec == nil {
		return nil, errors.New("workspace: pull needs a transport to the actor")
	}
	res, err := osw.Pull(ctx, osw.PullOptions{
		DataDir: opts.DataDir, Name: opts.Name, Exec: opts.Exec,
		MaxBundleBytes: opts.MaxBundleBytes, Timeout: opts.Timeout,
		Scanners: opts.Scanners, SensitiveGlobs: opts.SensitiveGlobs,
	})
	if err != nil {
		return nil, cleanErr("pull "+opts.Name, err)
	}
	rv := buildReview(res)
	if !res.Empty() {
		if diff, err := osw.PullDiff(ctx, opts.DataDir, opts.Name); err != nil {
			rv.Warnings = append(rv.Warnings, "the diff could not be read: "+strings.ReplaceAll(err.Error(), "workspace: ", ""))
		} else {
			rv.Diff = []byte(diff)
		}
	}
	rv.Text = rv.render(opts.Name)
	return rv, nil
}

var statusWords = map[string]string{"A": "added", "M": "modified", "D": "deleted", "T": "type changed"}

// kindWords say what each review flag means.
var kindWords = map[osw.RiskKind]string{
	osw.RiskGitControl:     "changes git settings or hooks, which run code when git is used",
	osw.RiskNestedRepo:     "adds a nested git repository",
	osw.RiskSubmodule:      "changes a submodule",
	osw.RiskGitAttributes:  "changes git attributes, which can run filters",
	osw.RiskPackageScripts: "changes install or build scripts that run code",
	osw.RiskAutoExec:       "runs by itself when the folder is opened or built",
	osw.RiskBuild:          "changes how the project is built",
	osw.RiskCI:             "changes a CI workflow, which runs on your CI",
	osw.RiskExecutable:     "is an executable script",
	osw.RiskSymlink:        "is a symlink that may point outside the project",
	osw.RiskSecretFile:     "looks like a secret file",
	osw.RiskDependencies:   "changes dependencies",
	osw.RiskPolicy:         "is listed as sensitive by policy",
	osw.RiskIgnoreRules:    "changes what git ignores",
	osw.RiskUnreadable:     "could not be read",
	osw.RiskZeroFilled:     "came back empty (a write the actor lost)",
}

var severityRank = map[osw.Severity]int{
	osw.SeverityInfo: 0, osw.SeverityMedium: 1, osw.SeverityHigh: 2, osw.SeverityCritical: 3,
}

type fileInfo struct {
	File
	rank int
}

func buildReview(res *osw.PullResult) *Review {
	rv := &Review{
		Summary:   res.Review.SummaryLine(),
		Sensitive: res.Review.Sensitive(),
		Dropped:   res.Dropped,
		Blocking:  res.Blocking,
		Warnings:  res.Review.Warnings,
		Empty:     res.Empty(),
		Result:    res,
	}
	files := map[string]*fileInfo{}
	var order []string
	get := func(p string) *fileInfo {
		f := files[p]
		if f == nil {
			f = &fileInfo{File: File{Path: p}}
			files[p] = f
			order = append(order, p)
		}
		return f
	}
	flag := func(p, reason string, rank int) {
		f := get(p)
		for _, have := range f.Flags {
			if have == reason {
				return
			}
		}
		f.Flags = append(f.Flags, reason)
		if rank > f.rank {
			f.rank = rank
		}
	}
	for _, c := range res.Changes {
		f := get(c.Path)
		f.Status = statusWords[c.Status]
		if f.Status == "" {
			f.Status = "changed"
		}
		switch {
		case c.Binary:
			flag(c.Path, "binary file", 0)
		case c.Added+c.Deleted >= largeChangeLines:
			flag(c.Path, fmt.Sprintf("large change (%d lines)", c.Added+c.Deleted), 0)
		}
		if c.NewMode == "120000" {
			flag(c.Path, "is a symlink that may point outside the project", 1)
		}
		if strings.HasPrefix(path.Base(c.Path), ".") && c.Status != "D" {
			flag(c.Path, "hidden file (dotfile)", 0)
		}
	}
	for _, fl := range res.Review.Flags {
		reason := kindWords[fl.Kind]
		if reason == "" {
			reason = fl.Label
		}
		if fl.Detail != "" {
			reason += " (" + fl.Detail + ")"
		}
		flag(fl.Path, "can run code: "+reason, 1+severityRank[fl.Severity])
	}
	for _, fd := range res.Review.Findings {
		switch fd.Scanner {
		case "clawshield-secrets":
			flag(fd.Path, "contains what looks like a secret", 4)
		default:
			flag(fd.Path, fd.Title, 1)
		}
	}
	for _, p := range order {
		if len(files[p].Flags) > 0 {
			rv.Flagged++
		}
	}
	list := make([]*fileInfo, 0, len(order))
	for _, p := range order {
		list = append(list, files[p])
	}
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		af, bf := len(a.Flags) > 0, len(b.Flags) > 0
		switch {
		case af != bf:
			return af
		case af && a.rank != b.rank:
			return a.rank > b.rank
		}
		return a.Path < b.Path
	})
	for _, f := range list {
		if f.Status == "" {
			continue // flagged by a finding, but not a change of this pull
		}
		rv.Changed = append(rv.Changed, f.File)
	}
	return rv
}

// render writes the review as plain lines.
func (r *Review) render(name string) string {
	var b strings.Builder
	if r.Empty {
		fmt.Fprintf(&b, "%s: nothing to bring back\n", name)
	} else {
		fmt.Fprintf(&b, "%s: %s\n", name, r.Summary)
	}
	if r.Flagged > 0 {
		noun := "files need"
		if r.Flagged == 1 {
			noun = "file needs"
		}
		fmt.Fprintf(&b, "%d %s a look before you bring them back:\n", r.Flagged, noun)
	}
	flagged := true
	for _, f := range r.Changed {
		if len(f.Flags) == 0 && flagged {
			flagged = false
			if r.Flagged > 0 {
				b.WriteString("Other changes:\n")
			}
		}
		if len(f.Flags) > 0 {
			fmt.Fprintf(&b, "  %s (%s): %s\n", f.Path, f.Status, strings.Join(f.Flags, "; "))
		} else {
			fmt.Fprintf(&b, "  %s (%s)\n", f.Path, f.Status)
		}
	}
	for _, d := range r.Dropped {
		fmt.Fprintf(&b, "%s was held back from the actor; its change is not brought back\n", d)
	}
	for _, x := range r.Blocking {
		fmt.Fprintf(&b, "refused: %s\n", x)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "note: %s\n", w)
	}
	return b.String()
}

// ApplyMode says how a pull lands.
type ApplyMode string

const (
	// ModeApply merges the changes into the working tree (a 3-way merge; on
	// a conflict nothing is touched and they go to a branch and a patch).
	ModeApply ApplyMode = "apply"
	// ModeBranch puts them on a branch (dc/<name> unless Branch is set)
	// and leaves the checkout alone.
	ModeBranch ApplyMode = "branch"
	// ModePatch writes a patch file.
	ModePatch ApplyMode = "patch"
)

// ApplyOptions configures Apply.
type ApplyOptions struct {
	DataDir string
	Name    string
	Mode    ApplyMode
	// Branch names the branch for ModeBranch; PatchPath is the file for
	// ModePatch.
	Branch    string
	PatchPath string
	// AcceptSensitive confirms changes that can run code on this machine
	// when they would land in the working tree.
	AcceptSensitive bool
	// Force replaces an existing branch or patch file and overrides the
	// review's blocking reasons.
	Force bool
}

// ApplyResult says what was written.
type ApplyResult struct {
	Mode ApplyMode
	// Written are the paths changed in the working tree (ModeApply).
	Written []string
	// Branch and PatchPath are where the changes went.
	Branch    string
	PatchPath string
	// UpToDate is set when the project had these changes already.
	UpToDate bool
	// FellBack is set when ModeApply did not touch the working tree (a
	// conflict) and the changes are on Branch and in PatchPath instead.
	FellBack  bool
	Conflicts []string
	// PreApplyRef keeps the working tree as it was before the merge.
	PreApplyRef string
	Warnings    []string
	// Text is the outcome as the CLI prints it.
	Text string
}

// SensitiveError is Apply's refusal to put changes that can run code on this
// machine into the working tree without a yes.
type SensitiveError struct {
	// Files are the flagged files; Review is the full list.
	Files []string
}

func (e *SensitiveError) Error() string {
	return "some changes can run code on this machine (" + strings.Join(firstN(e.Files, 6), ", ") +
		"); review them and pass --accept-sensitive, or bring them back with --branch or --patch-out FILE"
}

func (e *SensitiveError) Unwrap() error { return osw.ErrSensitiveChanges }

func firstN(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (m ApplyMode) toOSW() (osw.ApplyMode, error) {
	switch m {
	case ModeApply, "":
		return osw.ApplyMerge, nil
	case ModeBranch:
		return osw.ApplyBranch, nil
	case ModePatch:
		return osw.ApplyPatch, nil
	}
	return "", fmt.Errorf("workspace: unknown apply mode %q (apply, branch or patch)", m)
}

// Apply lands the last Pull of the copy: a 3-way merge into the working
// tree, a branch, or a patch file. It makes the checks `sandbox pull` makes
// first (an existing branch, a patch file that is there, a project that is
// not a git repository for a branch) so nothing is half done, and refuses
// changes that can run code on this machine unless AcceptSensitive says yes.
// A branch or a patch file runs nothing, so they need no yes unless a secret
// would go into the branch's history.
func Apply(ctx context.Context, opts ApplyOptions) (*ApplyResult, error) {
	mode, err := opts.Mode.toOSW()
	if err != nil {
		return nil, err
	}
	if mode == osw.ApplyPatch && opts.PatchPath == "" {
		return nil, errors.New("workspace: a patch file is required for patch mode")
	}
	oo := osw.ApplyOptions{DataDir: opts.DataDir, Name: opts.Name, Mode: mode, Branch: opts.Branch,
		PatchPath: opts.PatchPath, AcceptSensitive: opts.AcceptSensitive, Force: opts.Force}
	if _, err := osw.CheckApply(ctx, oo); err != nil {
		return nil, cleanErr("bring back "+opts.Name+"'s changes", err)
	}
	pr, err := osw.LoadPull(opts.DataDir, opts.Name)
	if err != nil {
		return nil, cleanErr("bring back "+opts.Name+"'s changes", err)
	}
	if pr.Review.Sensitive() && !oo.AcceptSensitive {
		if mode == osw.ApplyPatch || mode == osw.ApplyBranch && len(pr.Review.SecretPaths()) == 0 {
			oo.AcceptSensitive = true
		} else {
			return nil, &SensitiveError{Files: flaggedPaths(pr)}
		}
	}
	res, err := osw.Apply(ctx, oo)
	if err != nil {
		var gate *osw.GateError
		if errors.As(err, &gate) && errors.Is(err, osw.ErrSensitiveChanges) {
			return nil, &SensitiveError{Files: flaggedPaths(pr)}
		}
		return nil, cleanErr("bring back "+opts.Name+"'s changes", err)
	}
	out := &ApplyResult{
		Mode: opts.Mode, Branch: res.Branch, PatchPath: res.PatchPath, UpToDate: res.UpToDate,
		Conflicts: res.Conflicts, PreApplyRef: res.PreApplyRef, Warnings: res.Warnings,
	}
	if out.Mode == "" {
		out.Mode = ModeApply
	}
	if mode == osw.ApplyMerge && res.Applied {
		for _, c := range res.Changes {
			out.Written = append(out.Written, c.Path)
		}
	}
	out.FellBack = mode == osw.ApplyMerge && !res.Applied && (len(res.Conflicts) > 0 || res.Branch != "" || res.PatchPath != "")
	out.Text = applyText(out, pr.Project, len(res.Changes))
	return out, nil
}

func flaggedPaths(pr *osw.PullResult) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range pr.Review.Flags {
		if !seen[f.Path] {
			seen[f.Path] = true
			out = append(out, f.Path)
		}
	}
	for _, p := range pr.Review.SecretPaths() {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func applyText(r *ApplyResult, project string, changes int) string {
	var b strings.Builder
	switch {
	case r.FellBack:
		if len(r.Conflicts) > 0 {
			fmt.Fprintf(&b, "the 3-way apply conflicted in %s; your working tree is unchanged\n", strings.Join(firstN(r.Conflicts, 6), ", "))
		} else {
			b.WriteString("the changes could not be applied to your working tree, which is unchanged\n")
		}
		if r.Branch != "" {
			fmt.Fprintf(&b, "the changes are on branch %s instead (merge them when you are ready: git merge %s)\n", r.Branch, r.Branch)
		}
		if r.PatchPath != "" {
			fmt.Fprintf(&b, "and in %s (git apply --3way %s)\n", r.PatchPath, r.PatchPath)
		}
	case r.Mode == ModeApply && r.UpToDate:
		fmt.Fprintf(&b, "nothing to apply: %s already has these changes\n", project)
	case r.Mode == ModeApply:
		fmt.Fprintf(&b, "applied %d changes to %s\n", changes, project)
		if r.PreApplyRef != "" {
			fmt.Fprintf(&b, "your previous working tree is kept at %s\n", r.PreApplyRef)
		}
	case r.Mode == ModeBranch && r.UpToDate:
		fmt.Fprintf(&b, "nothing to do: branch %s already has these changes (your checkout is unchanged)\n", r.Branch)
	case r.Mode == ModeBranch:
		fmt.Fprintf(&b, "the changes are on branch %s (your checkout is unchanged)\n", r.Branch)
	default:
		fmt.Fprintf(&b, "wrote %s\n", r.PatchPath)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "note: %s\n", w)
	}
	return b.String()
}
