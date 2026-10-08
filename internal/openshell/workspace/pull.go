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
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultMaxBundleBytes caps the result bundle a pull downloads.
const DefaultMaxBundleBytes int64 = 1 << 30

// PullOptions configures Pull.
type PullOptions struct {
	DataDir string
	Name    string
	// Exec runs the capture and streams the result bundle back.
	Exec Execer
	// MaxBundleBytes caps the result bundle (DefaultMaxBundleBytes). The
	// cap applies to the bytes the host actually receives, whatever size
	// the sandbox reports.
	MaxBundleBytes int64
	// Timeout bounds the in-sandbox capture (default 10 min).
	Timeout time.Duration
	// Scanners and SensitiveGlobs feed the review of the result, as in
	// ReviewOptions.
	Scanners       []ContentScanner
	SensitiveGlobs []string
	// Reuse makes the pull again from the last one, whose Result it names,
	// without reading the sandbox: the caller knows the sandbox has not run
	// since that pull read its copy. The review, the changes and where they
	// start (Since) are made anew, so an apply or an undo since counts. Pull
	// returns ErrNoReusablePull when the last pull is another one, or of
	// another copy.
	Reuse string
}

// PullResult is the agent's work, verified and reviewed, ready for Apply.
type PullResult struct {
	Name     string   `json:"name"`
	Project  string   `json:"project"`
	Kind     CopyKind `json:"kind"`
	Baseline string   `json:"baseline"`
	Head     string   `json:"head,omitempty"`
	// SandboxHead is the sandbox repository's HEAD at pull time.
	SandboxHead string `json:"sandbox_head,omitempty"`
	// Result is the sandbox's final state (its HEAD plus uncommitted work);
	// Effective is Result with held-back paths reset, which Apply uses.
	Result    string `json:"result"`
	Effective string `json:"effective"`
	// Since is where Changes (and the review, the apply's merge base and a
	// patch) start: the effective result an earlier 3-way apply put in the
	// folder, so what was brought back already is not brought back again;
	// "" measures from the baseline.
	Since string `json:"since,omitempty"`
	// ResultTree is Result's tree: a refresh treats a sandbox whose HEAD
	// and working tree still match SandboxHead and ResultTree as pulled.
	ResultTree string       `json:"result_tree,omitempty"`
	Changes    []TreeChange `json:"changes,omitempty"`
	Review     ReviewReport `json:"review"`
	// Blocking are reasons Apply refuses the branch and 3-way modes
	// without Force.
	Blocking []string `json:"blocking,omitempty"`
	// Dropped are held-back (secret) paths the sandbox created, changed or
	// deleted without ever seeing them; those changes are not applied.
	Dropped []string          `json:"dropped,omitempty"`
	Remotes map[string]string `json:"remotes,omitempty"`
	// PulledAt is when the sandbox's copy was read: for a Reused pull, when
	// the pull it was made from read it.
	PulledAt time.Time `json:"pulled_at"`
	// Reused is set on a pull made from the last one (PullOptions.Reuse)
	// without reading the sandbox.
	Reused bool `json:"reused,omitempty"`
	// AppliedAt is when Apply last put the result somewhere that outlives
	// the copy: the working tree, a branch, or a patch file of the
	// operator's choosing.
	AppliedAt *time.Time `json:"applied_at,omitempty"`
}

// Empty reports whether the agent changed nothing that would be applied.
func (p *PullResult) Empty() bool { return len(p.Changes) == 0 }

// HandedOver reports whether nothing of the pull is lost when the copy is
// replaced: it was applied (or a pull of the same state from the same
// point was), or it holds no change Apply could land.
func (p *PullResult) HandedOver() bool {
	return p.AppliedAt != nil || (p.Empty() && p.Effective != "" && len(p.Blocking) == 0)
}

func (l layout) pullRecord(name string) string { return filepath.Join(l.copyDir(name), "pull.json") }

// LoadPull reads the last pull of name.
func LoadPull(dataDir, name string) (*PullResult, error) {
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	lay, err := newLayout(dataDir)
	if err != nil {
		return nil, err
	}
	var pr PullResult
	if err := readJSON(lay.pullRecord(name), &pr); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("workspace: sandbox %s has not been pulled yet", name)
		}
		return nil, err
	}
	return &pr, nil
}

// captureScript commits the sandbox copy's working tree on top of its HEAD
// (through a scratch index seeded from the real one, so skip-worktree bits
// hold) and bundles every object the host does not already have. It
// prints key=value lines.
func captureScript(rec *CopyRecord, bundle bool) string {
	head := rec.Head
	if rec.Kind == CopyPlain {
		head = rec.Baseline
	}
	addArgs := "--all"
	if rec.Kind == CopyPlain {
		addArgs += " --force"
	}
	var excludes []string
	for _, p := range heavyExcludePathspecs() {
		excludes = append(excludes, shellQuote(p))
	}
	lines := []string{
		remoteGitPrelude(rec),
		"B=" + shellQuote(rec.Baseline),
		"H=" + shellQuote(head),
		`mkdir -p "$D"`,
		`idx="$D/capture.index"; out="$D/result.bundle"`,
		`rm -f "$idx" "$out"`,
		`if [ -f "$G/index" ]; then cp "$G/index" "$idx"; fi`,
		`head=$(g rev-parse -q --verify 'HEAD^{commit}' || true)`,
		`if [ ! -s "$idx" ] && [ -n "$head" ]; then GIT_INDEX_FILE="$idx" g read-tree "$head"; fi`,
		// An uninitialized submodule whose empty folder is gone is not
		// a removed submodule: its files never came into the copy
		// (GAP-0250).
		`GIT_INDEX_FILE="$idx" g ls-files -s | while read -r m o s p; do if [ "$m" = 160000 ] && [ ! -e "$W/$p" ]; then mkdir -p -- "$W/$p"; fi; done || true`,
		`GIT_INDEX_FILE="$idx" g add ` + addArgs + ` -- . ` + strings.Join(excludes, " "),
		`tree=$(GIT_INDEX_FILE="$idx" g write-tree)`,
		`rm -f "$idx"`,
		`if [ -n "$head" ] && [ "$tree" = "$(g rev-parse "$head^{tree}")" ]; then result=$head`,
		`elif [ -n "$head" ]; then result=$(g commit-tree "$tree" -p "$head" -m ` + shellQuote("defenseclaw: uncommitted changes in sandbox "+rec.Name) + `)`,
		`else result=$(g commit-tree "$tree" -m ` + shellQuote("defenseclaw: uncommitted changes in sandbox "+rec.Name) + `); fi`,
		`printf 'head=%s\nresult=%s\ntree=%s\n' "$head" "$result" "$tree"`,
	}
	if bundle {
		lines = append(lines,
			`g update-ref `+resultRef+` "$result"`,
			`set -- `+resultRef,
			`for x in "$H" "$B"; do if [ -n "$x" ] && g cat-file -e "$x^{commit}" 2>/dev/null; then set -- "$@" "^$x"; fi; done`,
			`if [ "$(g rev-list --count "$@")" -gt 0 ]; then g bundle create "$out" "$@" >/dev/null; printf 'bundle=%s\n' "$(wc -c < "$out" | tr -d ' ')"; else echo bundle=none; fi`,
			`g config --get-regexp '^remote\..*\.url$' | sed 's/^/remote=/' || true`,
		)
	}
	return strings.Join(lines, "\n")
}

// Pull captures the sandbox copy, brings it back as a git bundle, verifies
// it against the staged history, drops changes to held-back secrets and
// reviews the result. Nothing in the project changes until Apply.
func Pull(ctx context.Context, opts PullOptions) (*PullResult, error) {
	rec, err := LoadCopy(opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	if rec.UploadedAt == nil || rec.BaseGit == "" {
		return nil, fmt.Errorf("workspace: copy %s was never uploaded", opts.Name)
	}
	lay, _ := newLayout(opts.DataDir)
	maxBundle := opts.MaxBundleBytes
	if maxBundle <= 0 {
		maxBundle = DefaultMaxBundleBytes
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	var kv, remotes map[string]string
	pulledAt := time.Now().UTC()
	last := lastPullOf(opts.DataDir, rec)
	if opts.Reuse != "" {
		// What the last pull read, whose objects base.git holds, taken as a
		// capture with nothing to download.
		if !reusable(last, opts.Reuse) {
			return nil, ErrNoReusablePull
		}
		kv = map[string]string{"head": last.SandboxHead, "result": last.Result, "tree": last.ResultTree, "bundle": "none"}
		remotes, pulledAt = last.Remotes, last.PulledAt
	} else {
		// Not Idempotent: two captures must never run at once (they share
		// the scratch index, the result ref and the bundle).
		res, err := opts.Exec.Exec(ctx, opts.Name, ExecRequest{Argv: []string{"sh", "-c", captureScript(rec, true)}, Timeout: timeout})
		if err != nil {
			return nil, err
		}
		if res.ExitCode != 0 {
			return nil, fmt.Errorf("workspace: capture the sandbox copy (exit %d): %s", res.ExitCode, lastLines(res.Stderr, 5))
		}
		kv = parseKV(res.Stdout)
		remotes = parseRemotes(kv["remote"])
	}
	result := kv["result"]
	if !isOID(result) {
		return nil, fmt.Errorf("workspace: sandbox reported result %q", result)
	}
	pr := &PullResult{
		Name: rec.Name, Project: rec.Project, Kind: rec.Kind, Baseline: rec.Baseline, Head: rec.Head,
		SandboxHead: kv["head"], Result: result, ResultTree: kv["tree"], PulledAt: pulledAt, Reused: opts.Reuse != "",
	}
	base := gitCmd{dir: lay.copyDir(rec.Name), gitDir: rec.BaseGit, config: []string{"transfer.fsckObjects=true", "fetch.fsckObjects=true"}}
	if kv["bundle"] == "none" {
		if _, code, err := base.outputCode(ctx, "cat-file", "-e", result+"^{commit}"); err != nil || code != 0 {
			pr.Blocking = append(pr.Blocking, "history rewrite: the sandbox moved back to a commit that is not in the uploaded history")
			return savePull(lay, pr)
		}
		if err := base.run(ctx, "update-ref", resultRef, result); err != nil {
			return nil, err
		}
	} else {
		if err := fetchBundle(ctx, rec, opts, base, kv["bundle"], result, maxBundle, timeout); err != nil {
			return nil, err
		}
	}

	if rec.Kind == CopyGit && rec.Head != "" {
		_, code, err := base.outputCode(ctx, "merge-base", "--is-ancestor", rec.Head, result)
		if err != nil || code != 0 {
			pr.Blocking = append(pr.Blocking, fmt.Sprintf("history rewrite: the result does not build on the commit the copy started from (%s)", shortOID(rec.Head)))
		}
	}
	pr.Remotes = remotes
	for _, name := range sortedKeys(pr.Remotes) {
		url := pr.Remotes[name]
		switch before, ok := rec.Remotes[name]; {
		case !ok:
			pr.Blocking = append(pr.Blocking, fmt.Sprintf("new remote %q (%s) was added in the sandbox", name, url))
		case before != url:
			pr.Blocking = append(pr.Blocking, fmt.Sprintf("remote %q now points to %s", name, url))
		}
	}

	effective, dropped, err := dropHeldBack(ctx, base, rec, result)
	if err != nil {
		return nil, err
	}
	pr.Effective, pr.Dropped = effective, dropped
	if err := base.run(ctx, "update-ref", effectRef, effective); err != nil {
		return nil, err
	}
	// After an apply, the work it brought is in the folder: the pull says
	// what changed since, and the next apply merges only that.
	if pr.Since, err = markSince(ctx, base); err != nil {
		return nil, err
	}
	if pr.Changes, err = diffTrees(ctx, base, pr.from(), effective); err != nil {
		return nil, err
	}
	scanners := opts.Scanners
	if scanners == nil {
		scanners = DefaultScanners()
	}
	rep, err := reviewTreeChanges(ctx, base, pr.Changes, scanners, opts.SensitiveGlobs)
	if err != nil {
		return nil, err
	}
	rep.Name, rep.Project = rec.Name, rec.Project
	pr.Review = *rep
	for _, f := range rep.Flags {
		if f.Kind == RiskSubmodule {
			pr.Blocking = append(pr.Blocking, "submodule change: "+f.Detail)
		}
	}
	if last != nil && last.AppliedAt != nil && last.ResultTree != "" && last.SandboxHead == pr.SandboxHead &&
		last.ResultTree == pr.ResultTree && last.Since == pr.Since {
		// The sandbox's state and the point its changes start from are the
		// last pull's, which went to a branch or a patch file: this one is
		// there too (a capture of uncommitted work is another commit of the
		// same tree each time).
		pr.AppliedAt = last.AppliedAt
	}
	return savePull(lay, pr)
}

// from is the commit the pull's changes start from.
func (p *PullResult) from() string {
	if p.Since != "" {
		return p.Since
	}
	return p.Baseline
}

// markSince points sinceRef at the result the last 3-way apply put in the
// folder (appliedRef) and returns it; with none it removes sinceRef and
// returns "".
func markSince(ctx context.Context, base gitCmd) (string, error) {
	applied := refCommit(ctx, base, appliedRef)
	if applied == "" {
		return "", deleteRef(ctx, base, sinceRef)
	}
	if err := base.run(ctx, "update-ref", sinceRef, applied); err != nil {
		return "", err
	}
	return applied, nil
}

// refCommit is the commit ref names in g, "" when there is none.
func refCommit(ctx context.Context, g gitCmd, ref string) string {
	out, code, err := g.outputCode(ctx, "rev-parse", "-q", "--verify", ref+"^{commit}")
	if oid := strings.TrimSpace(string(out)); err == nil && code == 0 && isOID(oid) {
		return oid
	}
	return ""
}

// deleteRef removes ref from g when it exists.
func deleteRef(ctx context.Context, g gitCmd, ref string) error {
	if _, code, err := g.outputCode(ctx, "rev-parse", "-q", "--verify", ref); err != nil || code != 0 {
		return err
	}
	return g.run(ctx, "update-ref", "-d", ref)
}

func savePull(lay layout, pr *PullResult) (*PullResult, error) {
	if err := writeJSON(lay.pullRecord(pr.Name), pr); err != nil {
		return nil, err
	}
	return pr, nil
}

func fetchBundle(ctx context.Context, rec *CopyRecord, opts PullOptions, base gitCmd, reported, result string, maxBundle int64, timeout time.Duration) error {
	size, err := strconv.ParseInt(reported, 10, 64)
	if err != nil || size <= 0 {
		return fmt.Errorf("workspace: sandbox reported bundle size %q", reported)
	}
	if size > maxBundle {
		return &TooLargeError{What: "the sandbox result", Size: size, Limit: maxBundle}
	}
	lay, _ := newLayout(opts.DataDir)
	dir := filepath.Join(lay.copyDir(rec.Name), "pull")
	_ = os.RemoveAll(dir)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	local := filepath.Join(dir, "result.bundle")
	got, err := receiveBundle(ctx, opts.Exec, rec.Name, local, maxBundle, timeout)
	if err != nil {
		return err
	}
	if got != size {
		return fmt.Errorf("workspace: received a %d-byte bundle, the sandbox reported %d", got, size)
	}
	if err := base.run(ctx, "bundle", "verify", local); err != nil {
		return fmt.Errorf("workspace: the result bundle does not apply to the uploaded history: %w", err)
	}
	heads, err := base.output(ctx, "bundle", "list-heads", local)
	if err != nil {
		return err
	}
	want := result + " " + resultRef
	found := false
	for _, line := range strings.Split(string(heads), "\n") {
		if strings.TrimSpace(line) == want {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("workspace: the result bundle does not contain %s at %s", resultRef, shortOID(result))
	}
	return base.run(ctx, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-gc", "--no-auto-maintenance",
		"--no-recurse-submodules", local, "+"+resultRef+":"+resultRef)
}

// receiveBundle streams the sandbox's result bundle into the new private
// file local and returns its size. The bundle travels base64-encoded on
// the stdout of an exec rather than through `openshell sandbox download`:
// the agent controls that file and can swap it for a huge or sparse file,
// a directory or a link after any check, so the host counts the bytes it
// actually receives and stops the transfer past limit, and it never
// unpacks an archive the agent made. The in-sandbox check only makes the
// common refusals quick and clear.
func receiveBundle(ctx context.Context, ex Execer, name, local string, limit int64, timeout time.Duration) (int64, error) {
	f, err := os.OpenFile(local, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sink := &base64Sink{w: f, limit: limit}
	script := strings.Join([]string{
		"set -eu",
		"f=" + shellQuote(remoteStateDir+"/result.bundle"),
		`if [ -h "$f" ] || [ ! -f "$f" ]; then echo "the result bundle is not a regular file" >&2; exit 3; fi`,
		`n=$(wc -c < "$f" | tr -d ' ')`,
		`if [ "$n" -gt ` + strconv.FormatInt(limit, 10) + ` ]; then echo "the result bundle has $n bytes" >&2; exit 4; fi`,
		`base64 < "$f"`,
	}, "\n")
	res, err := ex.Exec(ctx, name, ExecRequest{Argv: []string{"sh", "-c", script}, Timeout: timeout, Stdout: sink})
	if errors.Is(err, errBundleLimit) || errors.Is(sink.err, errBundleLimit) {
		return 0, &TooLargeError{What: "the sandbox result", Size: limit + 1, Limit: limit}
	}
	if err != nil {
		return 0, fmt.Errorf("workspace: receive the result bundle: %w", err)
	}
	if res.ExitCode != 0 {
		return 0, fmt.Errorf("workspace: receive the result bundle (exit %d): %s", res.ExitCode, lastLines(res.Stderr, 5))
	}
	if err := sink.Close(); err != nil {
		return 0, err
	}
	if err := f.Close(); err != nil {
		return 0, err
	}
	return sink.n, nil
}

// errBundleLimit stops a bundle stream that grew past its limit.
var errBundleLimit = errors.New("workspace: the result bundle exceeds its size limit")

// base64Sink decodes a streamed base64 text (line breaks allowed) into w
// and fails, without writing them, once decoded bytes would exceed limit.
type base64Sink struct {
	w     io.Writer
	limit int64
	n     int64
	// pending holds encoded bytes not decoded yet; out is decode scratch.
	pending, out []byte
	ended        bool // a padded quantum was decoded: nothing may follow
	err          error
}

func (s *base64Sink) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	for _, b := range p {
		if b != '\n' && b != '\r' {
			s.pending = append(s.pending, b)
		}
	}
	if err := s.flush(); err != nil {
		return 0, err
	}
	return len(p), nil
}

// flush decodes the whole quanta in pending.
func (s *base64Sink) flush() error {
	whole := len(s.pending) / 4 * 4
	if whole == 0 {
		return nil
	}
	if s.ended {
		s.err = errors.New("workspace: the result bundle stream continues after its end")
		return s.err
	}
	if need := base64.StdEncoding.DecodedLen(whole); cap(s.out) < need {
		s.out = make([]byte, need)
	}
	n, err := base64.StdEncoding.Decode(s.out[:cap(s.out)], s.pending[:whole])
	if err != nil {
		s.err = fmt.Errorf("workspace: the result bundle stream is not base64: %w", err)
		return s.err
	}
	if s.n+int64(n) > s.limit {
		s.err = errBundleLimit
		return s.err
	}
	if _, err := s.w.Write(s.out[:n]); err != nil {
		s.err = err
		return err
	}
	s.n += int64(n)
	s.ended = s.pending[whole-1] == '='
	s.pending = append(s.pending[:0], s.pending[whole:]...)
	return nil
}

// Close reports a stream that stopped inside a quantum.
func (s *base64Sink) Close() error {
	if s.err == nil && len(s.pending) > 0 {
		s.err = errors.New("workspace: the result bundle stream is truncated")
	}
	return s.err
}

// dropHeldBack resets every held-back path in result to its baseline
// state: the sandbox never saw those files, so any change to them is a
// blind overwrite or deletion of an operator secret.
func dropHeldBack(ctx context.Context, base gitCmd, rec *CopyRecord, result string) (string, []string, error) {
	if len(rec.HeldBack) == 0 {
		return result, nil, nil
	}
	changes, err := diffTrees(ctx, base, rec.Baseline, result)
	if err != nil {
		return "", nil, err
	}
	held := toSet(rec.HeldBack)
	var dropped []string
	for _, c := range changes {
		if skipped(held, c.Path) {
			dropped = append(dropped, c.Path)
		}
	}
	if len(dropped) == 0 {
		return result, nil, nil
	}
	tmp := filepath.Join(filepath.Dir(rec.BaseGit), "effective-"+randomSuffix()+".index")
	defer os.Remove(tmp)
	g := base
	g.index = tmp
	if err := g.run(ctx, "read-tree", result); err != nil {
		return "", nil, err
	}
	var info bytes.Buffer
	for _, c := range changes {
		if !skipped(held, c.Path) {
			continue
		}
		if c.OldMode == "" {
			fmt.Fprintf(&info, "0 %s\t%s\n", strings.Repeat("0", len(c.NewOID)), c.Path)
		} else {
			fmt.Fprintf(&info, "%s %s\t%s\n", c.OldMode, c.OldOID, c.Path)
		}
	}
	g.stdin = &info
	if err := g.run(ctx, "update-index", "--index-info"); err != nil {
		return "", nil, err
	}
	g.stdin = nil
	tree, err := g.line(ctx, "write-tree")
	if err != nil {
		return "", nil, err
	}
	commit, err := g.line(ctx, "commit-tree", tree, "-p", result, "-m", "defenseclaw: sandbox result without changes to held-back files")
	if err != nil {
		return "", nil, err
	}
	sort.Strings(dropped)
	return commit, dropped, nil
}

// reviewTreeChanges classifies and scans a tree diff held in g's object
// store.
func reviewTreeChanges(ctx context.Context, g gitCmd, changes []TreeChange, scanners []ContentScanner, sensitive []string) (*ReviewReport, error) {
	var oids []string
	for _, c := range changes {
		if c.OldOID != "" {
			oids = append(oids, c.OldOID)
		}
		if c.NewOID != "" {
			oids = append(oids, c.NewOID)
		}
	}
	data, err := blobReader{g: g}.read(ctx, oids, defaultMaxScanBytes)
	if err != nil {
		return nil, err
	}
	content := func(c TreeChange, after bool) ([]byte, bool) {
		oid := c.OldOID
		if after {
			oid = c.NewOID
		}
		b, ok := data[oid]
		return b, ok
	}
	rep := &ReviewReport{Changes: changes}
	rep.Flags = classifyChanges(changes, content, sensitive)
	rep.Findings = scanChanges(changes, scanners, content)
	for _, c := range changes {
		rep.FilesChanged++
		rep.Insertions += c.Added
		rep.Deletions += c.Deleted
	}
	return rep, nil
}

func parseRemotes(lines string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(lines, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || !strings.HasPrefix(key, "remote.") || !strings.HasSuffix(key, ".url") {
			continue
		}
		out[strings.TrimSuffix(strings.TrimPrefix(key, "remote."), ".url")] = strings.TrimSpace(value)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func shortOID(oid string) string {
	if len(oid) > 12 {
		return oid[:12]
	}
	return oid
}

// ApplyMode selects how a pull lands in the project.
type ApplyMode string

const (
	// ApplyMerge 3-way merges the agent's changes into the working tree
	// (the operator may have kept working); on conflicts nothing is
	// touched and the result falls back to a branch and a patch.
	ApplyMerge ApplyMode = "apply"
	// ApplyBranch creates dc/<name> at the result.
	ApplyBranch ApplyMode = "branch"
	// ApplyPatch writes a binary-safe patch file.
	ApplyPatch ApplyMode = "patch"
)

// ApplyOptions configures Apply.
type ApplyOptions struct {
	DataDir string
	Name    string
	Mode    ApplyMode
	// Branch overrides dc/<name>.
	Branch string
	// PatchPath is where ApplyPatch writes (required for that mode).
	PatchPath string
	// AcceptSensitive confirms changes that can run code on this machine.
	AcceptSensitive bool
	// Force overrides blocking gates, an existing branch, or an existing
	// patch file.
	Force bool
	// Starts tells CheckApply that the pull it is made before starts a
	// stopped sandbox to read its work, unless that pull can be made from
	// the last one: Reuse names the pull it would reuse (PullOptions.Reuse;
	// "" when the sandbox has run since, so none can be). Apply ignores
	// both.
	Starts bool
	Reuse  string
}

// ApplyResult reports what Apply did.
type ApplyResult struct {
	Mode    ApplyMode    `json:"mode"`
	Applied bool         `json:"applied"`
	Changes []TreeChange `json:"changes,omitempty"`
	// Conflicts lists paths where the 3-way merge conflicted; Branch and
	// PatchPath then hold the fallback.
	Conflicts []string `json:"conflicts,omitempty"`
	Branch    string   `json:"branch,omitempty"`
	PatchPath string   `json:"patch_path,omitempty"`
	// UpToDate reports that the result was there already, so nothing
	// changed: the working tree holds it (an earlier apply brought it), or
	// the branch does (an earlier pull put the same work on it).
	UpToDate bool `json:"up_to_date,omitempty"`
	// PreApplyRef keeps the working tree as it was before the merge; its
	// reflog keeps the state before each earlier apply.
	PreApplyRef string   `json:"pre_apply_ref,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// Apply lands the last pull of a copy-mode sandbox in the project. When
// the result reached the working tree (now or by an earlier apply), a
// branch or the requested patch file, the pull is marked applied, which
// lets Refresh replace the copy without Force.
func Apply(ctx context.Context, opts ApplyOptions) (*ApplyResult, error) {
	rec, err := LoadCopy(opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	pr, err := LoadPull(opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	res, err := applyPull(ctx, rec, pr, opts)
	if err != nil {
		return nil, err
	}
	if res.Mode == ApplyMerge && (res.Applied || res.UpToDate) {
		// The folder has this result now: the next pull starts from it.
		lay, _ := newLayout(opts.DataDir)
		base := gitCmd{dir: lay.copyDir(rec.Name), gitDir: rec.BaseGit}
		if err := base.run(ctx, "update-ref", appliedRef, pr.Effective); err != nil {
			res.Warnings = append(res.Warnings, "the next pull will show these changes again: recording the apply failed ("+err.Error()+")")
		}
	}
	if res.Applied || res.UpToDate || res.Branch != "" || res.Mode == ApplyPatch {
		t := time.Now().UTC()
		pr.AppliedAt = &t
		lay, _ := newLayout(opts.DataDir)
		if _, err := savePull(lay, pr); err != nil {
			return res, fmt.Errorf("workspace: the result was applied, but recording that failed: %w", err)
		}
	}
	return res, nil
}

func applyPull(ctx context.Context, rec *CopyRecord, pr *PullResult, opts ApplyOptions) (*ApplyResult, error) {
	if pr.Result == "" || pr.Effective == "" {
		return nil, fmt.Errorf("%w: the pull was refused (%s)", ErrBlocked, strings.Join(pr.Blocking, "; "))
	}
	if pr.Empty() {
		return nil, ErrNoChanges
	}
	if err := checkProjectPath(rec.Project); err != nil {
		return nil, err
	}
	mode := opts.Mode
	if mode == "" {
		mode = ApplyMerge
	}
	if mode == ApplyBranch && rec.Kind == CopyGit {
		// A branch that holds the result already (an earlier pull put it
		// there) lands nothing new: no gate applies, and it stays.
		if branch := branchName(rec, opts.Branch); branchHolds(ctx, rec, branch, pr.Effective) {
			return &ApplyResult{Mode: mode, UpToDate: true, Branch: branch}, nil
		}
	}
	if mode != ApplyPatch {
		if len(pr.Blocking) > 0 && !opts.Force {
			return nil, &GateError{Sentinel: ErrBlocked, Reasons: pr.Blocking}
		}
		if pr.Review.Sensitive() && !opts.AcceptSensitive {
			return nil, &GateError{Sentinel: ErrSensitiveChanges, Reasons: pr.Review.HostExecLabels()}
		}
	}
	lay, _ := newLayout(opts.DataDir)
	base := gitCmd{dir: lay.copyDir(rec.Name), gitDir: rec.BaseGit}
	if pr.Since != "" && refCommit(ctx, base, sinceRef) != pr.Since {
		return nil, fmt.Errorf("workspace: the last pull of %s started from an apply that is no longer recorded (it was undone); pull again", rec.Name)
	}
	switch mode {
	case ApplyPatch:
		if opts.PatchPath == "" {
			return nil, errors.New("workspace: a patch path is required")
		}
		if err := writePatch(ctx, base, pr.from(), pr.Effective, opts.PatchPath, opts.Force); err != nil {
			return nil, err
		}
		return &ApplyResult{Mode: mode, Applied: true, Changes: pr.Changes, PatchPath: opts.PatchPath}, nil
	case ApplyBranch:
		if rec.Kind != CopyGit {
			return nil, ErrNotGitProject
		}
		branch, note, err := createBranch(ctx, rec, pr, opts, false)
		if err != nil {
			return nil, err
		}
		out := &ApplyResult{Mode: mode, Applied: true, Changes: pr.Changes, Branch: branch}
		if note != "" {
			out.Warnings = append(out.Warnings, note)
		}
		return out, nil
	case ApplyMerge:
		return applyMerge(ctx, lay, rec, pr, opts)
	}
	return nil, fmt.Errorf("workspace: unknown apply mode %q", mode)
}

// maxPullDiffBytes caps the diff PullDiff shows; a larger one is cut, and
// says how to get all of it (a patch file).
const maxPullDiffBytes = 4 << 20

// PullDiff is the last pull of a copy-mode sandbox as a diff to read: what
// `pull --patch-out` would write, without binary data, so a copy's work
// can be read before it is applied (GAP-0207).
func PullDiff(ctx context.Context, dataDir, name string) (string, error) {
	rec, err := LoadCopy(dataDir, name)
	if err != nil {
		return "", err
	}
	pr, err := LoadPull(dataDir, name)
	if err != nil {
		return "", err
	}
	if pr.Effective == "" || pr.Empty() {
		return "", nil
	}
	lay, _ := newLayout(dataDir)
	base := gitCmd{dir: lay.copyDir(rec.Name), gitDir: rec.BaseGit}
	diff, err := base.output(ctx, "diff", "--no-ext-diff", "--no-textconv", "--no-color", pr.from(), pr.Effective)
	if err != nil {
		return "", err
	}
	if len(diff) > maxPullDiffBytes {
		return string(diff[:maxPullDiffBytes]) + "\n… the diff goes on; `pull --patch-out FILE` writes all of it\n", nil
	}
	return string(diff), nil
}

func writePatch(ctx context.Context, base gitCmd, from, to, dest string, force bool) error {
	diff, err := base.output(ctx, "diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "--no-color", from, to)
	if err != nil {
		return err
	}
	exists, err := checkPatchPath(dest, force)
	if err != nil {
		return err
	}
	if exists {
		if err := os.Remove(dest); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(diff); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// importResult fetches the effective result and the commit its changes
// start from (baseRef: the baseline, or sinceRef) from base.git into the
// project under refs/defenseclaw/copy/<name>/.
func importResult(ctx context.Context, rec *CopyRecord, proj gitCmd, baseRef string) (result, baseline string, err error) {
	prefix := "refs/defenseclaw/copy/" + rec.Name
	g := proj
	g.config = append(g.config, "transfer.fsckObjects=true", "fetch.writeCommitGraph=false")
	if err := g.run(ctx, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-gc", "--no-auto-maintenance",
		"--no-recurse-submodules", rec.BaseGit, "+"+effectRef+":"+prefix+"/result", "+"+baseRef+":"+prefix+"/base"); err != nil {
		return "", "", fmt.Errorf("workspace: import the sandbox result: %w", err)
	}
	return prefix + "/result", prefix + "/base", nil
}

// checkPatchPath reports whether the patch file dest exists, which only
// force lets a patch replace, and refuses one that is not a regular file.
func checkPatchPath(dest string, force bool) (bool, error) {
	info, err := os.Lstat(dest)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("workspace: %w", err)
	case info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular():
		return true, fmt.Errorf("workspace: refusing to write the patch over %s", dest)
	case !force:
		return true, fmt.Errorf("workspace: %s already exists", dest)
	}
	return true, nil
}

// branchName is the branch ApplyBranch puts rec's work on: name, or
// dc/<sandbox>.
func branchName(rec *CopyRecord, name string) string {
	if name == "" {
		return "dc/" + rec.Name
	}
	return name
}

// branchHolds reports whether branch in rec's project holds the tree of
// effective, a result in the copy's base.git: an earlier pull put the same
// work there (a result made again has another commit, the same tree).
func branchHolds(ctx context.Context, rec *CopyRecord, branch, effective string) bool {
	if effective == "" {
		return false
	}
	tip, err := gitCmd{dir: rec.Project}.line(ctx, "rev-parse", "-q", "--verify", "refs/heads/"+branch+"^{tree}")
	if err != nil || tip == "" {
		return false
	}
	base := gitCmd{gitDir: rec.BaseGit}
	if whole, err := base.line(ctx, "rev-parse", "-q", "--verify", effective+"^{tree}"); err == nil && whole == tip {
		// The whole result: a branch an earlier build made, or one that
		// keeps the folder's edits.
		return true
	}
	want, _, _, err := branchTree(ctx, base, rec, effective, rec.Baseline)
	return err == nil && want == tip
}

// branchTree is the tree a branch of rec's work holds, in g (the project,
// or the copy's base.git) where result is the sandbox's result and base the
// copy's baseline. It is result's tree, unless the copy was made from a
// folder with uncommitted edits: those are in the baseline, and so in the
// result, but they are the folder's and stay in it, not the sandbox's
// (GAP-0282). The tree is then the copy's HEAD with what the sandbox
// changed since the copy was made, and edits names the folder's edits.
// kept says why they stay in the tree all the same (the sandbox changed
// them further, or git is older than 2.38), "" when they are left out.
func branchTree(ctx context.Context, g gitCmd, rec *CopyRecord, result, base string) (tree string, edits []string, kept string, err error) {
	if tree, err = g.line(ctx, "rev-parse", "--verify", result+"^{tree}"); err != nil || rec.Head == "" {
		return tree, nil, "", err
	}
	headTree, err := g.line(ctx, "rev-parse", "--verify", rec.Head+"^{tree}")
	if err != nil {
		return "", nil, "", err
	}
	baseTree, err := g.line(ctx, "rev-parse", "--verify", base+"^{tree}")
	if err != nil || baseTree == headTree {
		return tree, nil, "", err
	}
	changes, err := diffTrees(ctx, g, headTree, baseTree)
	if err != nil {
		return "", nil, "", err
	}
	for _, c := range changes {
		edits = append(edits, c.Path)
	}
	v, err := hostGitVersion(ctx, rec.Project)
	if err != nil {
		return "", nil, "", err
	}
	if !v.atLeast(2, 38) {
		return tree, edits, "git " + v.String() + " cannot leave them out (git 2.38+ can)", nil
	}
	ours, theirs, err := onMergeBase(ctx, g, base, rec.Head, result, rec.Name)
	if err != nil {
		return "", nil, "", err
	}
	merged, conflicts, err := mergeTrees(ctx, g, nil, ours, theirs)
	switch {
	case err != nil:
		return "", nil, "", fmt.Errorf("workspace: leave the folder's uncommitted edits out of the branch: %w", err)
	case len(conflicts) > 0:
		return tree, edits, "the sandbox changed " + strings.Join(firstN(conflicts, 5), ", ") + " further", nil
	}
	return merged, edits, "", nil
}

// branchCommit is the commit a branch of rec's work points at, in the
// project where result and base are imported (branchTree): the result
// itself, or one commit on the copy's HEAD with what the sandbox changed,
// which names the sandbox's own commits it takes in. note says what the
// branch holds of the folder's uncommitted edits, when it had any.
func branchCommit(ctx context.Context, rec *CopyRecord, proj gitCmd, result, base, branch string) (commit, note string, err error) {
	tree, edits, kept, err := branchTree(ctx, proj, rec, result, base)
	if err != nil {
		return "", "", err
	}
	if commit, err = proj.line(ctx, "rev-parse", "--verify", result+"^{commit}"); err != nil || len(edits) == 0 {
		return commit, "", err
	}
	what := "your folder's uncommitted edits from when the copy was made (" + strings.Join(firstN(edits, 5), ", ") + ")"
	if kept != "" {
		return commit, "branch " + branch + " also holds " + what + ": " + kept, nil
	}
	msg := "defenseclaw: changes made in sandbox " + rec.Name + "\n\nThe folder's uncommitted edits from when the copy was made are left out."
	if raw, err := proj.output(ctx, "log", "--reverse", "--format=%s", rec.Head+".."+result); err == nil {
		var own []string
		for _, s := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if s != "" && !strings.HasPrefix(s, "defenseclaw: ") {
				own = append(own, "- "+s)
			}
		}
		if len(own) > 0 {
			msg += "\n\nThe sandbox's commits it takes in:\n" + strings.Join(firstN(own, 20), "\n")
		}
	}
	if commit, err = proj.line(ctx, "commit-tree", tree, "-p", rec.Head, "-m", msg); err != nil {
		return "", "", err
	}
	return commit, "branch " + branch + " starts at " + shortOID(rec.Head) + " with only the sandbox's changes: " + what +
		" are not on it, and stay in your working tree", nil
}

// reusable reports whether a pull can be made from last, the copy's last
// pull, as PullOptions.Reuse names it.
func reusable(last *PullResult, reuse string) bool {
	return last != nil && reuse != "" && last.Result == reuse && isOID(last.Result)
}

// CheckApply looks, before a pull, at what would stop Apply with opts from
// landing the pull's result and can be told without the sandbox: the
// project folder, a branch for a folder that is not a git repository
// (ErrNotGitProject), an invalid branch name, a branch that exists and does
// not hold the last pull's result (unless Force), and a patch file that
// exists (unless Force) or whose folder does not. It reports whether the
// branch already holds that result, which Apply of a pull that took the same
// state finds up to date.
//
// A branch that holds the last pull's result is refused too (unless Force:
// an *EarlierPullError) before a pull that Starts a stopped sandbox that
// has run since that pull: what it holds now takes a boot to read, the new
// pull lands on that branch only if the sandbox changed nothing, and the
// refusal would otherwise come after the boot. A pull made from the last
// one (Reuse) takes that result again, and is done.
func CheckApply(ctx context.Context, opts ApplyOptions) (bool, error) {
	rec, err := LoadCopy(opts.DataDir, opts.Name)
	if err != nil {
		return false, err
	}
	if err := checkProjectPath(rec.Project); err != nil {
		return false, err
	}
	switch opts.Mode {
	case ApplyBranch:
		if rec.Kind != CopyGit {
			return false, ErrNotGitProject
		}
		proj := gitCmd{dir: rec.Project}
		branch := branchName(rec, opts.Branch)
		if err := proj.run(ctx, "check-ref-format", "--branch", branch); err != nil {
			return false, fmt.Errorf("workspace: invalid branch name %q", branch)
		}
		if _, code, err := proj.outputCode(ctx, "rev-parse", "-q", "--verify", "refs/heads/"+branch); err != nil || code != 0 {
			return false, err
		}
		if last := lastPullOf(opts.DataDir, rec); last != nil && branchHolds(ctx, rec, branch, last.Effective) {
			if opts.Starts && !opts.Force && !reusable(last, opts.Reuse) {
				return false, &EarlierPullError{Branch: branch, PulledAt: last.PulledAt}
			}
			return true, nil
		}
		if !opts.Force {
			return false, fmt.Errorf("workspace: branch %s already exists", branch)
		}
	case ApplyPatch:
		if opts.PatchPath == "" {
			return false, errors.New("workspace: a patch path is required")
		}
		if _, err := checkPatchPath(opts.PatchPath, opts.Force); err != nil {
			return false, err
		}
		if info, err := os.Stat(filepath.Dir(opts.PatchPath)); err != nil || !info.IsDir() {
			return false, fmt.Errorf("workspace: cannot write the patch to %s: its folder does not exist", opts.PatchPath)
		}
	}
	return false, nil
}

// createBranch puts the pull's work on a branch (branchCommit) and returns
// its name and what the branch holds of the folder's uncommitted edits.
func createBranch(ctx context.Context, rec *CopyRecord, pr *PullResult, opts ApplyOptions, pickFree bool) (string, string, error) {
	proj := gitCmd{dir: rec.Project}
	branch := branchName(rec, opts.Branch)
	if err := proj.run(ctx, "check-ref-format", "--branch", branch); err != nil {
		return "", "", fmt.Errorf("workspace: invalid branch name %q", branch)
	}
	ref := "refs/heads/" + branch
	exists := func(r string) bool {
		_, code, err := proj.outputCode(ctx, "rev-parse", "-q", "--verify", r)
		return err == nil && code == 0
	}
	if exists(ref) {
		switch {
		case pickFree:
			for i := 2; exists(ref); i++ {
				branch = fmt.Sprintf("%s-%d", strings.TrimSuffix(opts.Branch, "/"), i)
				if opts.Branch == "" {
					branch = fmt.Sprintf("dc/%s-%d", rec.Name, i)
				}
				ref = "refs/heads/" + branch
			}
		case !opts.Force:
			return "", "", fmt.Errorf("workspace: branch %s already exists", branch)
		}
	}
	imported, importedBase, err := importResult(ctx, rec, proj, baselineRef)
	if err != nil {
		return "", "", err
	}
	defer func() {
		_ = proj.run(ctx, "update-ref", "-d", imported)
		_ = proj.run(ctx, "update-ref", "-d", importedBase)
	}()
	tip, note, err := branchCommit(ctx, rec, proj, imported, importedBase, branch)
	if err != nil {
		return "", "", err
	}
	if err := proj.run(ctx, "update-ref", "-m", "defenseclaw: sandbox "+rec.Name, ref, tip); err != nil {
		return "", "", err
	}
	return branch, note, nil
}

// applyGit runs git against the working tree Apply and UndoApply change:
// the project's own repository, or for a plain folder the copy's base.git
// with the folder as its work tree.
func applyGit(rec *CopyRecord) gitCmd {
	if rec.Kind == CopyGit {
		return gitCmd{dir: rec.Project, config: lineEndingArgs(rec.LineEndings)}
	}
	return gitCmd{dir: rec.Project, gitDir: rec.BaseGit, workTree: rec.Project}
}

// applyRef names a ref Apply keeps for a sandbox, in the project (git) or
// in base.git (plain folders): pre-apply is the working tree before the
// last apply (its reflog holds the earlier ones), post-apply the tree that
// apply left, on top of pre-apply, which UndoApply reverts.
func applyRef(name, which string) string { return "refs/defenseclaw/copy/" + name + "/" + which }

// captureWorkTree records the operator's working tree (they may have kept
// working) as a tree, through a scratch index seeded from the real one so
// the real index is never touched. It returns g on the scratch index, the
// tree, and the scratch index's cleanup.
func captureWorkTree(ctx context.Context, lay layout, rec *CopyRecord, g gitCmd) (gitCmd, string, func(), error) {
	idx := filepath.Join(lay.copyDir(rec.Name), "apply-"+randomSuffix()+".index")
	cleanup := func() { _ = os.Remove(idx) }
	if rec.Kind == CopyGit {
		if real, err := g.line(ctx, "rev-parse", "--git-path", "index"); err == nil {
			if !filepath.IsAbs(real) {
				real = filepath.Join(rec.Project, real)
			}
			if pathExists(real) {
				if err := copyRegular(real, idx, 0o600, time.Time{}); err != nil {
					return gitCmd{}, "", nil, err
				}
			}
		}
	}
	gi := g
	gi.index = idx
	addArgs := []string{"add", "--all"}
	if rec.Kind == CopyPlain {
		addArgs = append(addArgs, "--force")
	}
	addArgs = append(append(addArgs, "--", "."), heavyExcludePathspecs()...)
	if err := gi.run(ctx, addArgs...); err != nil {
		cleanup()
		return gitCmd{}, "", nil, err
	}
	tree, err := gi.line(ctx, "write-tree")
	if err != nil {
		cleanup()
		return gitCmd{}, "", nil, err
	}
	return gi, tree, cleanup, nil
}

// mergeTrees runs a merge-tree of ours and theirs (commits) and returns the
// merged tree, or the conflicting paths.
func mergeTrees(ctx context.Context, g gitCmd, args []string, ours, theirs string) (string, []string, error) {
	mergeArgs := append([]string{"merge-tree", "--write-tree", "-z", "--name-only", "--no-messages"}, args...)
	raw, code, err := g.outputCode(ctx, append(mergeArgs, ours, theirs)...)
	if err != nil {
		return "", nil, err
	}
	parts := splitNUL(raw)
	if len(parts) == 0 || !isOID(parts[0]) {
		return "", nil, fmt.Errorf("workspace: unexpected merge-tree output")
	}
	if code != 1 {
		return parts[0], nil, nil
	}
	var conflicts []string
	for _, p := range parts[1:] {
		if p != "" {
			conflicts = append(conflicts, p)
		}
	}
	return "", dedupe(conflicts), nil
}

// onMergeBase commits the trees of ours and theirs on a parentless commit
// of base's tree, so a merge-tree of the two uses base as its merge base.
func onMergeBase(ctx context.Context, g gitCmd, base, ours, theirs, name string) (string, string, error) {
	b, err := g.line(ctx, "commit-tree", base+"^{tree}", "-m", "defenseclaw: merge base for sandbox "+name)
	if err != nil {
		return "", "", err
	}
	o, err := g.line(ctx, "commit-tree", ours+"^{tree}", "-p", b, "-m", "defenseclaw: folder for sandbox "+name)
	if err != nil {
		return "", "", err
	}
	t, err := g.line(ctx, "commit-tree", theirs+"^{tree}", "-p", b, "-m", "defenseclaw: result of sandbox "+name)
	if err != nil {
		return "", "", err
	}
	return o, t, nil
}

func applyMerge(ctx context.Context, lay layout, rec *CopyRecord, pr *PullResult, opts ApplyOptions) (*ApplyResult, error) {
	v, err := hostGitVersion(ctx, rec.Project)
	if err != nil {
		return nil, err
	}
	out := &ApplyResult{Mode: ApplyMerge}
	g := applyGit(rec)
	// The merge base is where the pull's changes start: the baseline, or
	// the result an earlier apply brought (what the operator changed of
	// that since stays theirs).
	var result, baseline, parent string
	if rec.Kind == CopyGit {
		baseRef := baselineRef
		if pr.Since != "" {
			baseRef = sinceRef
		}
		if result, baseline, err = importResult(ctx, rec, g, baseRef); err != nil {
			return nil, err
		}
		defer func() {
			_ = g.run(ctx, "update-ref", "-d", result)
			_ = g.run(ctx, "update-ref", "-d", baseline)
		}()
		head, _, err := resolveHead(ctx, g)
		if err != nil {
			return nil, err
		}
		parent = head
	} else {
		result, baseline, parent = pr.Effective, pr.from(), rec.Baseline
	}
	if !v.atLeast(2, 38) {
		out.Warnings = append(out.Warnings, "git "+v.String()+" cannot merge without touching the working tree (git 2.38+ can)")
		return fallback(ctx, lay, rec, pr, opts, out, nil)
	}

	gi, curTree, cleanup, err := captureWorkTree(ctx, lay, rec, g)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	commitArgs := []string{"commit-tree", curTree, "-m", "defenseclaw: working tree before applying sandbox " + rec.Name}
	if parent != "" {
		commitArgs = append(commitArgs, "-p", parent)
	}
	cur, err := g.line(ctx, commitArgs...)
	if err != nil {
		return nil, err
	}

	// Both sides go on one parentless commit of the base, which makes it
	// the merge base on every git: 2.38 and 2.39 have no --merge-base and
	// take the base from ancestry, which would be the baseline and bring
	// back what the operator took back of an earlier apply, unreviewed.
	ours, theirs, err := onMergeBase(ctx, g, baseline, cur, result, rec.Name)
	if err != nil {
		return nil, err
	}
	merged, conflicts, err := mergeTrees(ctx, g, nil, ours, theirs)
	if err != nil {
		return nil, fmt.Errorf("workspace: merge the sandbox result: %w", err)
	}
	if len(conflicts) > 0 {
		return fallback(ctx, lay, rec, pr, opts, out, conflicts)
	}
	preRef := applyRef(rec.Name, "pre-apply")
	if merged == curTree {
		// An earlier apply already brought the result: nothing changes,
		// and that apply's undo point stays where it is.
		out.UpToDate = true
		return out, nil
	}
	if out.Changes, err = diffTrees(ctx, g, curTree, merged); err != nil {
		return nil, err
	}
	// The undo point goes first, so the working tree never changes without
	// one; the reflog keeps the state before each earlier apply.
	prevPre, _ := g.line(ctx, "rev-parse", "-q", "--verify", preRef)
	if err := g.run(ctx, "update-ref", "--create-reflog", "-m", "defenseclaw: before applying sandbox "+rec.Name, preRef, cur); err != nil {
		return nil, err
	}
	if rec.Kind == CopyGit {
		out.PreApplyRef = preRef
	}
	// Two-way switch from the captured tree to the merge: files the
	// operator changed since the capture make this fail instead of being
	// overwritten; the real index is never touched.
	if err := gi.run(ctx, "read-tree", "-m", "-u", curTree, merged); err != nil {
		if prevPre != "" {
			_ = g.run(ctx, "update-ref", "-m", "defenseclaw: the apply of sandbox "+rec.Name+" failed", preRef, prevPre, cur)
		} else {
			_ = g.run(ctx, "update-ref", "-d", preRef, cur)
		}
		return nil, fmt.Errorf("workspace: update the working tree: %w", err)
	}
	out.Applied = true
	post, err := g.line(ctx, "commit-tree", merged, "-p", cur, "-m", "defenseclaw: working tree after applying sandbox "+rec.Name)
	if err == nil {
		err = g.run(ctx, "update-ref", "-m", "defenseclaw: applied sandbox "+rec.Name, applyRef(rec.Name, "post-apply"), post)
	}
	if err != nil {
		out.Warnings = append(out.Warnings, "the apply was not recorded for undo ("+err.Error()+"); the folder before it is kept at "+preRef)
	}
	return out, nil
}

// fallback leaves the tracked files alone and hands the result over as a
// branch (git projects) and a patch file in the project folder, where the
// interactive patch choice writes it too, so deleting the sandbox never
// takes it along.
func fallback(ctx context.Context, lay layout, rec *CopyRecord, pr *PullResult, opts ApplyOptions, out *ApplyResult, conflicts []string) (*ApplyResult, error) {
	out.Applied = false
	out.Conflicts = conflicts
	if rec.Kind == CopyGit {
		branch, note, err := createBranch(ctx, rec, pr, ApplyOptions{Name: opts.Name, Branch: opts.Branch}, true)
		if err != nil {
			return nil, err
		}
		out.Branch = branch
		if note != "" {
			out.Warnings = append(out.Warnings, note)
		}
	}
	base := gitCmd{dir: lay.copyDir(rec.Name), gitDir: rec.BaseGit}
	patch, err := writeFreePatch(ctx, base, pr.from(), pr.Effective, rec.Project, rec.Name)
	if err != nil {
		return nil, err
	}
	out.PatchPath = patch
	return out, nil
}

// writeFreePatch writes the from..to patch to <dir>/<name>.patch, or the
// first of <name>-2.patch, <name>-3.patch, ... that does not exist yet.
func writeFreePatch(ctx context.Context, base gitCmd, from, to, dir, name string) (string, error) {
	for i := 1; i <= 100; i++ {
		file := name + ".patch"
		if i > 1 {
			file = fmt.Sprintf("%s-%d.patch", name, i)
		}
		p := filepath.Join(dir, file)
		if pathExists(p) {
			continue
		}
		err := writePatch(ctx, base, from, to, p, false)
		if err == nil {
			return p, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("workspace: no free patch file name for %s in %s", name, dir)
}
