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
	Dropped  []string          `json:"dropped,omitempty"`
	Remotes  map[string]string `json:"remotes,omitempty"`
	PulledAt time.Time         `json:"pulled_at"`
	// AppliedAt is when Apply last put the result somewhere that outlives
	// the copy: the working tree, a branch, or a patch file of the
	// operator's choosing.
	AppliedAt *time.Time `json:"applied_at,omitempty"`
}

// Empty reports whether the agent changed nothing that would be applied.
func (p *PullResult) Empty() bool { return len(p.Changes) == 0 }

// handedOver reports whether nothing of the pull is lost when the copy is
// replaced: it was applied, or it holds no change Apply could land.
func (p *PullResult) handedOver() bool {
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
	// Not Idempotent: two captures must never run at once (they share the
	// scratch index, the result ref and the bundle).
	res, err := opts.Exec.Exec(ctx, opts.Name, ExecRequest{Argv: []string{"sh", "-c", captureScript(rec, true)}, Timeout: timeout})
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("workspace: capture the sandbox copy (exit %d): %s", res.ExitCode, lastLines(res.Stderr, 5))
	}
	kv := parseKV(res.Stdout)
	result := kv["result"]
	if !isOID(result) {
		return nil, fmt.Errorf("workspace: sandbox reported result %q", result)
	}
	pr := &PullResult{
		Name: rec.Name, Project: rec.Project, Kind: rec.Kind, Baseline: rec.Baseline, Head: rec.Head,
		SandboxHead: kv["head"], Result: result, ResultTree: kv["tree"], PulledAt: time.Now().UTC(),
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
	pr.Remotes = parseRemotes(kv["remote"])
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
	if pr.Changes, err = diffTrees(ctx, base, rec.Baseline, effective); err != nil {
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
	return savePull(lay, pr)
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
	// PreApplyRef keeps the working tree as it was before the merge.
	PreApplyRef string   `json:"pre_apply_ref,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
}

// Apply lands the last pull of a copy-mode sandbox in the project. When
// the result reached the working tree, a branch or the requested patch
// file, the pull is marked applied, which lets Refresh replace the copy
// without Force.
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
	if res.Applied || res.Branch != "" || res.Mode == ApplyPatch {
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
	switch mode {
	case ApplyPatch:
		if opts.PatchPath == "" {
			return nil, errors.New("workspace: a patch path is required")
		}
		if err := writePatch(ctx, base, rec.Baseline, pr.Effective, opts.PatchPath, opts.Force); err != nil {
			return nil, err
		}
		return &ApplyResult{Mode: mode, Applied: true, Changes: pr.Changes, PatchPath: opts.PatchPath}, nil
	case ApplyBranch:
		if rec.Kind != CopyGit {
			return nil, ErrNotGitProject
		}
		branch, err := createBranch(ctx, rec, pr, opts, false)
		if err != nil {
			return nil, err
		}
		return &ApplyResult{Mode: mode, Applied: true, Changes: pr.Changes, Branch: branch}, nil
	case ApplyMerge:
		return applyMerge(ctx, lay, rec, pr, opts)
	}
	return nil, fmt.Errorf("workspace: unknown apply mode %q", mode)
}

func writePatch(ctx context.Context, base gitCmd, from, to, dest string, force bool) error {
	diff, err := base.output(ctx, "diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv", "--no-color", from, to)
	if err != nil {
		return err
	}
	if info, err := os.Lstat(dest); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("workspace: refusing to write the patch over %s", dest)
		}
		if !force {
			return fmt.Errorf("workspace: %s already exists", dest)
		}
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

// importResult fetches the effective result and the baseline from base.git
// into the project under refs/defenseclaw/copy/<name>/.
func importResult(ctx context.Context, rec *CopyRecord, proj gitCmd) (result, baseline string, err error) {
	prefix := "refs/defenseclaw/copy/" + rec.Name
	g := proj
	g.config = append(g.config, "transfer.fsckObjects=true", "fetch.writeCommitGraph=false")
	if err := g.run(ctx, "fetch", "--quiet", "--no-tags", "--no-write-fetch-head", "--no-auto-gc", "--no-auto-maintenance",
		"--no-recurse-submodules", rec.BaseGit, "+"+effectRef+":"+prefix+"/result", "+"+baselineRef+":"+prefix+"/base"); err != nil {
		return "", "", fmt.Errorf("workspace: import the sandbox result: %w", err)
	}
	return prefix + "/result", prefix + "/base", nil
}

func createBranch(ctx context.Context, rec *CopyRecord, pr *PullResult, opts ApplyOptions, pickFree bool) (string, error) {
	proj := gitCmd{dir: rec.Project}
	branch := opts.Branch
	if branch == "" {
		branch = "dc/" + rec.Name
	}
	if err := proj.run(ctx, "check-ref-format", "--branch", branch); err != nil {
		return "", fmt.Errorf("workspace: invalid branch name %q", branch)
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
			return "", fmt.Errorf("workspace: branch %s already exists", branch)
		}
	}
	imported, importedBase, err := importResult(ctx, rec, proj)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = proj.run(ctx, "update-ref", "-d", imported)
		_ = proj.run(ctx, "update-ref", "-d", importedBase)
	}()
	if err := proj.run(ctx, "update-ref", "-m", "defenseclaw: sandbox "+rec.Name, ref, pr.Effective); err != nil {
		return "", err
	}
	return branch, nil
}

func applyMerge(ctx context.Context, lay layout, rec *CopyRecord, pr *PullResult, opts ApplyOptions) (*ApplyResult, error) {
	v, err := hostGitVersion(ctx, rec.Project)
	if err != nil {
		return nil, err
	}
	out := &ApplyResult{Mode: ApplyMerge}
	var g gitCmd
	var result, baseline, parent string
	if rec.Kind == CopyGit {
		g = gitCmd{dir: rec.Project, config: lineEndingArgs(rec.LineEndings)}
		if result, baseline, err = importResult(ctx, rec, g); err != nil {
			return nil, err
		}
		head, _, err := resolveHead(ctx, g)
		if err != nil {
			return nil, err
		}
		parent = head
	} else {
		g = gitCmd{dir: rec.Project, gitDir: rec.BaseGit, workTree: rec.Project}
		result, baseline, parent = pr.Effective, rec.Baseline, rec.Baseline
	}
	if !v.atLeast(2, 38) {
		out.Warnings = append(out.Warnings, "git "+v.String()+" cannot merge without touching the working tree (git 2.38+ can)")
		return fallback(ctx, lay, rec, pr, opts, out, nil)
	}

	// Capture the operator's current working tree (they may have kept
	// working) through a scratch index.
	idx := filepath.Join(lay.copyDir(rec.Name), "apply-"+randomSuffix()+".index")
	defer os.Remove(idx)
	if rec.Kind == CopyGit {
		if real, err := g.line(ctx, "rev-parse", "--git-path", "index"); err == nil {
			if !filepath.IsAbs(real) {
				real = filepath.Join(rec.Project, real)
			}
			if pathExists(real) {
				if err := copyRegular(real, idx, 0o600, time.Time{}); err != nil {
					return nil, err
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
		return nil, err
	}
	curTree, err := gi.line(ctx, "write-tree")
	if err != nil {
		return nil, err
	}
	commitArgs := []string{"commit-tree", curTree, "-m", "defenseclaw: working tree before applying sandbox " + rec.Name}
	if parent != "" {
		commitArgs = append(commitArgs, "-p", parent)
	}
	cur, err := g.line(ctx, commitArgs...)
	if err != nil {
		return nil, err
	}
	preRef := "refs/defenseclaw/copy/" + rec.Name + "/pre-apply"
	if err := g.run(ctx, "update-ref", preRef, cur); err != nil {
		return nil, err
	}
	if rec.Kind == CopyGit {
		out.PreApplyRef = preRef
	}

	mergeArgs := []string{"merge-tree", "--write-tree", "-z", "--name-only", "--no-messages"}
	if v.atLeast(2, 40) {
		mergeArgs = append(mergeArgs, "--merge-base="+baseline)
	} else {
		mergeArgs = append(mergeArgs, "--allow-unrelated-histories")
	}
	mergeArgs = append(mergeArgs, cur, result)
	raw, code, err := g.outputCode(ctx, mergeArgs...)
	if err != nil {
		return nil, fmt.Errorf("workspace: merge the sandbox result: %w", err)
	}
	parts := splitNUL(raw)
	if len(parts) == 0 || !isOID(parts[0]) {
		return nil, fmt.Errorf("workspace: unexpected merge-tree output")
	}
	merged := parts[0]
	if code == 1 {
		var conflicts []string
		for _, p := range parts[1:] {
			if p != "" {
				conflicts = append(conflicts, p)
			}
		}
		return fallback(ctx, lay, rec, pr, opts, out, dedupe(conflicts))
	}
	if out.Changes, err = diffTrees(ctx, g, curTree, merged); err != nil {
		return nil, err
	}
	// Two-way switch from the captured tree to the merge: files the
	// operator changed since the capture make this fail instead of being
	// overwritten; the real index is never touched.
	if err := gi.run(ctx, "read-tree", "-m", "-u", curTree, merged); err != nil {
		return nil, fmt.Errorf("workspace: update the working tree: %w", err)
	}
	out.Applied = true
	if rec.Kind == CopyGit {
		_ = g.run(ctx, "update-ref", "-d", result)
		_ = g.run(ctx, "update-ref", "-d", baseline)
	}
	return out, nil
}

// fallback leaves the working tree alone and hands the result over as a
// branch (git projects) and a patch file.
func fallback(ctx context.Context, lay layout, rec *CopyRecord, pr *PullResult, opts ApplyOptions, out *ApplyResult, conflicts []string) (*ApplyResult, error) {
	out.Applied = false
	out.Conflicts = conflicts
	if rec.Kind == CopyGit {
		branch, err := createBranch(ctx, rec, pr, ApplyOptions{Name: opts.Name, Branch: opts.Branch}, true)
		if err != nil {
			return nil, err
		}
		out.Branch = branch
	}
	patch := filepath.Join(lay.copyDir(rec.Name), rec.Name+".patch")
	base := gitCmd{dir: lay.copyDir(rec.Name), gitDir: rec.BaseGit}
	if err := writePatch(ctx, base, rec.Baseline, pr.Effective, patch, true); err != nil {
		return nil, err
	}
	out.PatchPath = patch
	return out, nil
}
