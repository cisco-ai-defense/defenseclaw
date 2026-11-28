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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Push sends the local changes made since the last send (the run or an
// earlier push) into a copy that is already in the sandbox. It stages the
// folder with the same rules as the first copy (PrepareCopy: masking, the
// secret scan, the size cap, ignored and heavy folders), compares the stage
// with the recorded baseline, and refuses a path the agent also changed
// unless the caller picks a side. What is sent becomes part of the
// baseline, so a later pull shows only the agent's own work.

// PushMode says what a push does with a conflict: a path both sides
// changed since the last send, to different content.
type PushMode string

const (
	// PushRefuse sends nothing when there is a conflict.
	PushRefuse PushMode = ""
	// PushMine sends the laptop version of a conflicting path.
	PushMine PushMode = "mine"
	// PushMineReplace is PushMine that also removes an agent file, link
	// or folder in the way of the laptop version (Replacing). PushMine
	// refuses those with *PushReplaceError (RV2 N2).
	PushMineReplace PushMode = "mine-replace"
	// PushTheirs keeps the agent's version and sends the rest.
	PushTheirs PushMode = "theirs"
)

// PushChange is one path the laptop changed since the last send.
type PushChange struct {
	Path   string `json:"path"`
	Status string `json:"status"` // added, modified, deleted
	Bytes  int64  `json:"bytes"`
	// Conflict: the agent changed it too, to other content.
	Conflict bool `json:"conflict,omitempty"`
	// Same: the agent made the same change; nothing to write.
	Same bool `json:"same,omitempty"`

	oldOID, newOID, newMode string
	// seen is the agent's state of the path at the check, as agentProbe
	// prints it; the write re-checks it and stops when it moved (RV1 P3-3).
	seen string
	// badParent: a leading directory of the path is, in the agent, a
	// symlink or not a directory. The path is never deleted (a delete
	// would follow the link out of the project) and conflicts unless
	// the push itself deletes that parent (RV1 P2-1, P3-2).
	badParent bool
	// Replaces is the agent's file, link or folder that sending the
	// laptop version would remove: a file or link where the path needs a
	// folder, or a folder where the laptop has a file (RV2 N2).
	Replaces string `json:"replaces,omitempty"`
}

// ReplaceNote says in plain words what sending this path removes in the
// agent, or "" when it removes nothing of the agent's.
func (c PushChange) ReplaceNote() string {
	switch c.Replaces {
	case "":
		return ""
	case c.Path:
		return "the agent has a folder here; sending yours removes that folder"
	default:
		return "the agent has a file or link at " + c.Replaces + "; sending yours removes it"
	}
}

// agentProbe is the shell function both the check and the write use to
// read one path in the agent: "parent:Q" when a leading directory Q is a
// symlink or not a directory (checked before the path, so nothing is read
// through it), else the blob id of the file or link, "dir" for a folder,
// "other" for anything else, "-" for nothing there.
const agentProbe = `probe() {
  q=$1
  while :; do
    case $q in */*) q=${q%/*} ;; *) break ;; esac
    if [ -L "$W/$q" ] || { [ -e "$W/$q" ] && ! [ -d "$W/$q" ]; }; then printf 'parent:%s' "$q"; return; fi
  done
  f="$W/$1"
  if [ -L "$f" ]; then printf '%s' "$(readlink -- "$f")" | g hash-object --stdin
  elif [ -f "$f" ]; then g hash-object --path="$1" -- "$f"
  elif [ -d "$f" ]; then printf dir
  elif [ -e "$f" ]; then printf other
  else printf -; fi
}`

// PushPlanOptions configures PlanPush.
type PushPlanOptions struct {
	DataDir string
	Name    string
	// Stage is the folder staged now with the copy rules (PrepareCopy).
	Stage *PreparedCopy
	Exec  Execer
	// Paths limits the push to these project-relative files or folders.
	Paths   []string
	Timeout time.Duration
}

// PushPlan is what a push would send. Nothing has been written yet.
type PushPlan struct {
	Changes  []PushChange
	HeldBack []string
	Warnings []string

	opts  PushPlanOptions
	rec   *CopyRecord
	stage gitCmd
}

// Conflicts lists the paths both sides changed to different content.
func (p *PushPlan) Conflicts() []string {
	var out []string
	for _, c := range p.Changes {
		if c.Conflict {
			out = append(out, c.Path)
		}
	}
	return out
}

// Replacing lists the conflicts whose laptop version removes an agent
// file, link or folder in its way (PushChange.Replaces): PushMine refuses
// them, PushMineReplace sends them (RV2 N2).
func (p *PushPlan) Replacing() []PushChange {
	var out []PushChange
	for _, c := range p.Changes {
		if c.Conflict && c.Replaces != "" {
			out = append(out, c)
		}
	}
	return out
}

// Bytes is the size of what the push writes.
func (p *PushPlan) Bytes() int64 {
	var n int64
	for _, c := range p.Changes {
		n += c.Bytes
	}
	return n
}

// ErrNothingStaged is returned for a copy that was never uploaded.
var ErrNothingStaged = errors.New("workspace: this copy was never sent to the agent")

// PlanPush stages nothing new: it compares opts.Stage with the copy's
// baseline and asks the sandbox which of those paths the agent changed.
func PlanPush(ctx context.Context, opts PushPlanOptions) (*PushPlan, error) {
	rec, err := LoadCopy(opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	if rec.UploadedAt == nil || rec.BaseGit == "" || rec.Baseline == "" {
		return nil, ErrNothingStaged
	}
	if opts.Stage == nil || opts.Stage.dir == "" {
		return nil, errors.New("workspace: push needs a staged folder")
	}
	srec := opts.Stage.rec
	if filepath.Clean(srec.Project) != filepath.Clean(rec.Project) {
		return nil, fmt.Errorf("workspace: this agent has %s, not %s", rec.Project, srec.Project)
	}
	sg := gitCmd{gitDir: stageGitDir(srec)}
	// The stage borrows the baseline's objects, read-only, so both trees
	// are in one repository.
	alt := filepath.Join(sg.gitDir, "objects", "info", "alternates")
	if err := os.MkdirAll(filepath.Dir(alt), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(alt, []byte(filepath.Join(rec.BaseGit, "objects")+"\n"), 0o600); err != nil {
		return nil, err
	}
	diff, err := diffTrees(ctx, sg, rec.Baseline, srec.Baseline)
	if err != nil {
		return nil, err
	}
	only, err := pushPathFilter(rec.Project, opts.Paths)
	if err != nil {
		return nil, err
	}
	held := map[string]bool{}
	for _, h := range srec.HeldBack {
		held[filepath.ToSlash(h)] = true
	}
	p := &PushPlan{opts: opts, rec: rec, stage: sg, Warnings: srec.Warnings}
	for _, h := range srec.HeldBack {
		if only(filepath.ToSlash(h)) {
			p.HeldBack = append(p.HeldBack, h)
		}
	}
	for _, c := range diff {
		if !only(c.Path) {
			continue
		}
		if strings.ContainsAny(c.Path, "\n\r") {
			return nil, fmt.Errorf("workspace: cannot push %q: the name has a line break", c.Path)
		}
		pc := PushChange{Path: c.Path, oldOID: c.OldOID, newOID: c.NewOID, newMode: c.NewMode}
		switch {
		case c.NewOID == "" || c.Status == "D":
			if held[c.Path] {
				// Held back now (a secret was added): not a delete.
				continue
			}
			pc.Status, pc.newOID = "deleted", ""
		case c.OldOID == "" || c.Status == "A":
			pc.Status = "added"
		default:
			pc.Status = "modified"
		}
		if pc.Status != "deleted" {
			if fi, err := os.Lstat(filepath.Join(srec.Stage, filepath.FromSlash(c.Path))); err == nil {
				pc.Bytes = fi.Size()
			}
		}
		p.Changes = append(p.Changes, pc)
	}
	sort.Slice(p.Changes, func(i, j int) bool { return p.Changes[i].Path < p.Changes[j].Path })
	if len(p.Changes) == 0 {
		return p, nil
	}
	if err := p.checkAgent(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// HeavyDirOf is the package-cache folder above rel ("web/node_modules/"),
// or "": the folders a copy leaves out.
func HeavyDirOf(rel string) string { return heavyDirOf(rel) }

// stageGitDir is the git directory of a staged copy.
func stageGitDir(rec *CopyRecord) string {
	if rec.Kind == CopyPlain {
		return filepath.Join(filepath.Dir(rec.Stage), ".dc", "git")
	}
	return filepath.Join(rec.Stage, ".git")
}

// pushPathFilter turns PATH arguments (relative to the working directory
// or absolute) into a project-relative prefix match.
func pushPathFilter(project string, paths []string) (func(string) bool, error) {
	if len(paths) == 0 {
		return func(string) bool { return true }, nil
	}
	cwd, _ := os.Getwd()
	var rels []string
	for _, p := range paths {
		abs := p
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(cwd, p)
		}
		if r, err := winpath.EvalLinks(abs); err == nil {
			abs = r
		} else if r, err := winpath.EvalLinks(filepath.Dir(abs)); err == nil {
			abs = filepath.Join(r, filepath.Base(abs))
		}
		rel, err := filepath.Rel(project, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("workspace: %s is not inside %s", p, project)
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return func(string) bool { return true }, nil
		}
		rels = append(rels, strings.TrimSuffix(rel, "/"))
	}
	return func(p string) bool {
		for _, r := range rels {
			if p == r || strings.HasPrefix(p, r+"/") {
				return true
			}
		}
		return false
	}, nil
}

// pushCheckChunk bounds the paths of one sandbox check.
const pushCheckChunk = 1000

// checkAgent hashes the changed paths in the sandbox and marks conflicts.
func (p *PushPlan) checkAgent(ctx context.Context) error {
	script := remoteGitPrelude(p.rec) + "\n" + strings.Join([]string{
		`b=$(g rev-parse -q --verify '` + baselineRef + `^{commit}' || true)`,
		`printf 'baseline=%s\n' "$b"`,
		agentProbe,
		`for p do printf 'o=%s\n' "$(probe "$p")"; done`,
	}, "\n")
	timeout := p.opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	for start := 0; start < len(p.Changes); start += pushCheckChunk {
		end := min(start+pushCheckChunk, len(p.Changes))
		argv := []string{"sh", "-c", script, "sh"}
		for _, c := range p.Changes[start:end] {
			argv = append(argv, c.Path)
		}
		res, err := p.opts.Exec.Exec(ctx, p.rec.Name, ExecRequest{Argv: argv, Timeout: timeout, Idempotent: true})
		if err != nil {
			return err
		}
		if res.ExitCode != 0 {
			return fmt.Errorf("workspace: read the agent's files (exit %d): %s", res.ExitCode, stderrReason(res.Stderr))
		}
		kv := parseKV(res.Stdout)
		if kv["baseline"] != p.rec.Baseline {
			return &BaselineMovedError{Want: p.rec.Baseline, Got: kv["baseline"]}
		}
		oids := strings.Split(kv["o"], "\n")
		if len(oids) != end-start {
			return fmt.Errorf("workspace: read the agent's files: %d answers for %d paths", len(oids), end-start)
		}
		for i, o := range oids {
			c := &p.Changes[start+i]
			c.seen = o
			if strings.HasPrefix(o, "parent:") {
				c.badParent = true
				continue // decided below, once every path is read
			}
			now := o
			if o == "-" {
				now = ""
			}
			if now == c.oldOID {
				continue // the agent did not touch it
			}
			if now == c.newOID {
				c.Same = true
				continue
			}
			c.Conflict = true
			if o == "dir" && c.Status != "deleted" {
				c.Replaces = c.Path // the laptop file would replace the agent's folder
			}
		}
	}
	// A path under an agent file or symlink conflicts, unless the push
	// deletes that parent and the agent left it alone (a laptop file that
	// became a folder): then the path is new under a parent the push
	// removes first. Writing it would unlink the agent's file (RV1 P2-1).
	deleted := map[string]bool{}
	for _, c := range p.Changes {
		if c.Status == "deleted" && !c.Conflict && !c.badParent {
			deleted[c.Path] = true
		}
	}
	for i := range p.Changes {
		c := &p.Changes[i]
		if !c.badParent {
			continue
		}
		q := strings.TrimPrefix(c.seen, "parent:")
		if deleted[q] && c.oldOID == "" {
			c.badParent = false
			continue
		}
		c.Conflict = true
		if c.Status != "deleted" {
			c.Replaces = q // the write would unlink the agent's file to make the folder
		}
	}
	return nil
}

// BaselineMovedError: the sandbox copy is not at the recorded baseline
// (another computer pushed, or the copy was replaced).
type BaselineMovedError struct{ Want, Got string }

func (e *BaselineMovedError) Error() string {
	if e.Got == "" {
		return "workspace: the copy in the agent has no DefenseClaw baseline; run it again from this folder"
	}
	return "workspace: the copy in the agent moved since this computer last sent to it; pull first, or run it again from this folder"
}

// PushResult says what a push did.
type PushResult struct {
	Sent     []PushChange
	Kept     []string // conflicts left at the agent's version
	Baseline string
	Number   int
}

// PushEntry is one push in the copy's push log. Undo to a restore point
// taken at or before Checkpoint puts the baseline back to Old.
type PushEntry struct {
	Number     int       `json:"number"`
	Checkpoint string    `json:"checkpoint,omitempty"`
	Old        string    `json:"old"`
	New        string    `json:"new"`
	Files      int       `json:"files"`
	At         time.Time `json:"at"`
	// SecretLines are the record's replaced credentials before the push:
	// undo past it puts them back with the baseline.
	SecretLines []SecretLine `json:"secret_lines,omitempty"`
}

// mergeSecretLines is the record's replaced credentials after a push: the
// pushed paths take the stage's entries (none for a deleted path), the
// others keep theirs. Send kept only the baseline, so a credential a push
// replaced was not a replaced file on pull: its placeholder went into the
// branch and the patch, and apply could put it over the person's value
// (RV6-1).
func mergeSecretLines(rec, stage []SecretLine, pushed []PushChange) []SecretLine {
	touched := map[string]bool{}
	for _, c := range pushed {
		touched[c.Path] = true
	}
	var out []SecretLine
	for _, l := range rec {
		if !touched[l.Rel] {
			out = append(out, l)
		}
	}
	for _, l := range stage {
		if touched[l.Rel] {
			out = append(out, l)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Rel < out[j].Rel })
	return out
}

func (l layout) pushLog(name string) string { return filepath.Join(l.copyDir(name), "pushes.json") }

// LoadPushLog reads the copy's push log (empty before the first push).
func LoadPushLog(dataDir, name string) ([]PushEntry, error) {
	lay, err := newLayout(dataDir)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(lay.pushLog(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []PushEntry
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("workspace: push log of %s: %w", name, err)
	}
	return out, nil
}

func savePushLog(dataDir, name string, log []PushEntry) error {
	lay, err := newLayout(dataDir)
	if err != nil {
		return err
	}
	return writeJSON(lay.pushLog(name), log)
}

// NextPushNumber is the number the next push gets.
func NextPushNumber(dataDir, name string) int {
	log, _ := LoadPushLog(dataDir, name)
	if len(log) == 0 {
		return 1
	}
	return log[len(log)-1].Number + 1
}

// PatchOut writes the laptop's change to the conflicting paths as a git
// patch (binary-safe), for a hand merge.
func (p *PushPlan) PatchOut(ctx context.Context, file string) error {
	conf := p.Conflicts()
	if len(conf) == 0 {
		return errors.New("workspace: no conflicts to write")
	}
	args := []string{"diff", "--binary", "--no-color", "--no-ext-diff", "--no-textconv", p.rec.Baseline, p.opts.Stage.rec.Baseline, "--"}
	for _, c := range conf {
		args = append(args, ":(literal)"+c)
	}
	out, err := p.stage.output(ctx, args...)
	if err != nil {
		return err
	}
	return os.WriteFile(file, out, 0o600)
}

// Send writes the plan into the sandbox. With conflicts, PushRefuse sends
// nothing; PushTheirs leaves them at the agent's version; PushMine sends
// the laptop's. checkpoint is the restore point taken before this push.
func (p *PushPlan) Send(ctx context.Context, up Uploader, mode PushMode, checkpoint string) (*PushResult, error) {
	conf := p.Conflicts()
	if len(conf) > 0 && mode == PushRefuse {
		return nil, &PushConflictError{Paths: conf}
	}
	if r := p.Replacing(); len(r) > 0 && mode == PushMine {
		return nil, &PushReplaceError{Changes: r}
	}
	var base, write []PushChange
	res := &PushResult{}
	for _, c := range p.Changes {
		if c.Conflict && mode == PushTheirs {
			res.Kept = append(res.Kept, c.Path)
			continue
		}
		base = append(base, c)
		if !c.Same {
			write = append(write, c)
		}
	}
	res.Sent = write
	res.Baseline = p.rec.Baseline
	if len(base) == 0 {
		return res, nil
	}
	newBase, bundleDir, err := p.commit(ctx, base)
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(bundleDir)
	var writes, deletes, expect bytes.Buffer
	var touched []string
	for _, c := range write {
		if c.Status == "deleted" {
			if c.badParent {
				continue // nothing of ours is there; a delete would follow the link (RV1 P3-2)
			}
			deletes.WriteString(c.Path + "\x00")
		} else {
			writes.WriteString(c.Path + "\x00")
		}
		touched = append(touched, c.Path)
		expect.WriteString(octalEscape(c.seen) + " " + octalEscape(c.Path) + "\n")
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "writes"), writes.Bytes(), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "deletes"), deletes.Bytes(), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(bundleDir, "expect"), expect.Bytes(), 0o600); err != nil {
		return nil, err
	}
	// The laptop's record learns the commit first, so a pull can verify
	// against it whatever happens next.
	bundle := filepath.Join(bundleDir, "push.bundle")
	base0 := gitCmd{gitDir: p.rec.BaseGit}
	if err := base0.run(ctx, "fetch", "-q", "--no-tags", bundle, "+"+pushRef+":"+pushRef); err != nil {
		return nil, err
	}
	stateDir := p.rec.stateDir()
	if err := uploadChecked(ctx, up, p.opts.Exec, p.rec.Name, bundleDir, stateDir, stateDir); err != nil {
		return nil, err
	}
	rd := path.Join(stateDir, filepath.Base(bundleDir))
	script := remoteGitPrelude(p.rec) + "\n" + strings.Join([]string{
		"export GIT_LITERAL_PATHSPECS=1",
		"old=" + shellQuote(p.rec.Baseline) + " new=" + shellQuote(newBase) + " bd=" + shellQuote(rd),
		agentProbe,
		// One writer at a time (a push while sync runs, two computers):
		// the lock covers check, write and the baseline move. A lock left
		// by a killed write is older than any write may run (RV1 P3-3); it
		// is taken over under a short guard, so two writers that both find
		// it stale cannot both get in. A guard left by a killed takeover
		// is older than a minute (RV2 N4).
		`L="$D/push.lock" T="$D/push.lock.take"`,
		`stale() { [ -n "$(find "$D" -maxdepth 1 -name push.lock -mmin +` + strconv.Itoa(pushLockStaleMinutes) + ` 2>/dev/null)" ]; }`,
		`find "$D" -maxdepth 1 -name push.lock.take -mmin +1 -exec rm -rf -- {} + 2>/dev/null || true`,
		`if stale && mkdir -- "$T" 2>/dev/null; then if stale; then rm -rf -- "$L"; fi; rmdir -- "$T" 2>/dev/null || true; fi`,
		// dash and busybox sh skip the EXIT trap when a signal ends them;
		// the relay ends a write on timeout or Ctrl-C with TERM (RV2 N3).
		`trap 'exit 143' TERM; trap 'exit 130' INT; trap 'exit 129' HUP`,
		`mkdir -- "$L" 2>/dev/null || { rm -rf -- "$bd"; echo "another push or sync is writing into this agent" >&2; exit 98; }`,
		`cleanup() { rm -rf -- "$bd" "$D/push.idx" "$L"; g update-ref -d ` + pushRef + ` 2>/dev/null || true; }`,
		`trap cleanup EXIT`,
		`cur=$(g rev-parse -q --verify '` + baselineRef + `^{commit}' || true)`,
		`[ "$cur" = "$old" ] || { echo "the copy in the agent moved (baseline $cur)" >&2; exit 95; }`,
		// Every path the push touches must still be as the check saw it.
		`n=0`,
		// Both fields are octal-escaped: a "parent:Q" with a space in Q
		// would split into the wrong fields (RV2 N1).
		`while IFS=' ' read -r ee enc; do n=$((n+1)); e=$(printf "%bx" "$ee"); e=${e%x}; p=$(printf "%bx" "$enc"); p=${p%x}; [ "$(probe "$p")" = "$e" ] || { printf 'changed=%s\n' "$n"; exit 97; }; done < "$bd/expect"`,
		`g fetch -q --no-tags "$bd/push.bundle" "+` + pushRef + `:` + pushRef + `"`,
		`[ "$(g rev-parse -q --verify '` + pushRef + `^{commit}')" = "$new" ] || { echo "the push did not arrive whole" >&2; exit 96; }`,
		`if [ -s "$bd/deletes" ]; then GIT_INDEX_FILE="$D/push.idx" g read-tree "$old" && GIT_INDEX_FILE="$D/push.idx" g rm -q -f --ignore-unmatch --pathspec-from-file="$bd/deletes" --pathspec-file-nul; rm -f -- "$D/push.idx"; fi`,
		`if [ -s "$bd/writes" ]; then GIT_INDEX_FILE="$D/push.idx" g read-tree "$new" && GIT_INDEX_FILE="$D/push.idx" g checkout-index -f -q -z --stdin < "$bd/writes"; fi`,
		`g update-ref ` + baselineRef + ` "$new" "$old"`,
		`printf 'baseline=%s\n' "$(g rev-parse -q --verify '` + baselineRef + `^{commit}')"`,
	}, "\n")
	timeout := p.opts.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	r, err := p.opts.Exec.Exec(ctx, p.rec.Name, ExecRequest{Argv: []string{"sh", "-c", script}, Timeout: timeout})
	if err != nil {
		return nil, err
	}
	if r.ExitCode == 97 {
		what := "a file"
		if n, err := strconv.Atoi(parseKV(r.Stdout)["changed"]); err == nil && n >= 1 && n <= len(touched) {
			what = touched[n-1]
		}
		return nil, &AgentChangedError{Path: what}
	}
	if r.ExitCode == 98 {
		return nil, ErrPushBusy
	}
	if r.ExitCode != 0 {
		return nil, fmt.Errorf("workspace: write the push in the agent (exit %d): %s", r.ExitCode, stderrReason(r.Stderr))
	}
	if got := parseKV(r.Stdout)["baseline"]; got != newBase {
		return nil, fmt.Errorf("workspace: the agent's baseline is %q after the push, expected %s", got, newBase)
	}
	log, _ := LoadPushLog(p.opts.DataDir, p.opts.Name)
	n := 1
	if len(log) > 0 {
		n = log[len(log)-1].Number + 1
	}
	_ = base0.run(ctx, "update-ref", "refs/defenseclaw/push-"+strconv.Itoa(n), newBase)
	log = append(log, PushEntry{Number: n, Checkpoint: checkpoint, Old: p.rec.Baseline, New: newBase, Files: len(write), At: time.Now().UTC(),
		SecretLines: p.rec.SecretLines})
	p.rec.Baseline = newBase
	p.rec.SecretLines = mergeSecretLines(p.rec.SecretLines, p.opts.Stage.rec.SecretLines, base)
	if err := saveCopy(p.opts.DataDir, p.rec); err != nil {
		return nil, err
	}
	if err := savePushLog(p.opts.DataDir, p.opts.Name, log); err != nil {
		return nil, err
	}
	res.Baseline, res.Number = newBase, n
	return res, nil
}

const pushRef = "refs/defenseclaw/push"

// pushLockStaleMinutes: a write lock older than this was left by a killed
// write (a write runs at most 5 minutes) and is taken over.
const pushLockStaleMinutes = 15

// ErrPushBusy: another push or sync was writing into the agent; nothing
// was written.
var ErrPushBusy = errors.New("workspace: another push or sync is writing into this agent; nothing was sent, try again (a lock left by an interrupted push clears after 15 minutes)")

// AgentChangedError: the agent changed a path between the check and the
// write; nothing was written.
type AgentChangedError struct{ Path string }

func (e *AgentChangedError) Error() string {
	return "workspace: the agent changed " + e.Path + " while the push was being prepared; nothing was sent, push again"
}

// octalEscape spells every byte of s as \0ooo for the shell's printf %b,
// so any path (spaces, newlines) travels on one line.
func octalEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "\\0%03o", s[i])
	}
	return b.String()
}

// commit builds the new baseline in the stage repository: the old
// baseline with the pushed paths at their staged content, and bundles it.
func (p *PushPlan) commit(ctx context.Context, base []PushChange) (string, string, error) {
	dir, err := os.MkdirTemp(p.opts.Stage.dir, "dc-push-")
	if err != nil {
		return "", "", err
	}
	fail := func(err error) (string, string, error) {
		_ = os.RemoveAll(dir)
		return "", "", err
	}
	idx := gitCmd{gitDir: p.stage.gitDir, index: filepath.Join(dir, "index")}
	if err := idx.run(ctx, "read-tree", p.rec.Baseline); err != nil {
		return fail(err)
	}
	var info bytes.Buffer
	for _, c := range base {
		if c.Status == "deleted" {
			fmt.Fprintf(&info, "0 %s\t%s\x00", strings.Repeat("0", len(p.rec.Baseline)), c.Path)
		} else {
			fmt.Fprintf(&info, "%s %s\t%s\x00", c.newMode, c.newOID, c.Path)
		}
	}
	idx.stdin = &info
	if err := idx.run(ctx, "update-index", "-z", "--index-info"); err != nil {
		return fail(err)
	}
	idx.stdin = nil
	tree, err := idx.output(ctx, "write-tree")
	if err != nil {
		return fail(err)
	}
	c, err := p.stage.output(ctx, "commit-tree", strings.TrimSpace(string(tree)), "-p", p.rec.Baseline, "-m", "defenseclaw push")
	if err != nil {
		return fail(err)
	}
	commit := strings.TrimSpace(string(c))
	_ = os.Remove(filepath.Join(dir, "index"))
	if err := p.stage.run(ctx, "update-ref", pushRef, commit); err != nil {
		return fail(err)
	}
	if err := p.stage.run(ctx, "bundle", "create", filepath.Join(dir, "push.bundle"), pushRef, "^"+p.rec.Baseline); err != nil {
		return fail(err)
	}
	return commit, dir, nil
}

// PushReplaceError: with PushMine, sending these conflicts would remove an
// agent file, link or folder in their way that the person did not name;
// nothing was sent. PushMineReplace sends them anyway (RV2 N2).
type PushReplaceError struct{ Changes []PushChange }

func (e *PushReplaceError) Error() string {
	lines := make([]string, 0, len(e.Changes))
	for _, c := range e.Changes {
		lines = append(lines, c.Path+" ("+c.ReplaceNote()+")")
	}
	return "workspace: sending your version removes the agent's files in the way: " + strings.Join(lines, ", ")
}

// PushConflictError lists the paths both sides changed.
type PushConflictError struct{ Paths []string }

func (e *PushConflictError) Error() string {
	return fmt.Sprintf("workspace: the agent also changed %d of these files: %s", len(e.Paths), strings.Join(e.Paths, ", "))
}

// RewindPushes puts the baseline back to where it was at restore point
// checkpoint: undo restores the agent's files to that point, so a push
// made after it is no longer in the folder and must not stay in the
// baseline (pull would then hide the undone files). It returns how many
// pushes were rewound.
func RewindPushes(ctx context.Context, dataDir, name string, ex Execer, checkpoint string) (int, error) {
	id, err := strconv.Atoi(strings.TrimPrefix(checkpoint, "dc-checkpoint-"))
	if err != nil {
		return 0, nil
	}
	log, err := LoadPushLog(dataDir, name)
	if err != nil || len(log) == 0 {
		return 0, err
	}
	cut := len(log)
	for i, e := range log {
		if n, err := strconv.Atoi(e.Checkpoint); err == nil && n >= id {
			cut = i
			break
		}
	}
	if cut == len(log) {
		return 0, nil
	}
	rec, err := LoadCopy(dataDir, name)
	if err != nil {
		return 0, err
	}
	old := log[cut].Old
	script := remoteGitPrelude(rec) + "\n" + `g update-ref ` + baselineRef + ` ` + shellQuote(old) + "\n" +
		`printf 'baseline=%s\n' "$(g rev-parse -q --verify '` + baselineRef + `^{commit}')"`
	r, err := ex.Exec(ctx, name, ExecRequest{Argv: []string{"sh", "-c", script}, Timeout: 2 * time.Minute, Idempotent: true})
	if err != nil {
		return 0, err
	}
	if r.ExitCode != 0 || parseKV(r.Stdout)["baseline"] != old {
		return 0, fmt.Errorf("workspace: put the agent's baseline back (exit %d): %s", r.ExitCode, stderrReason(r.Stderr))
	}
	rec.Baseline = old
	rec.SecretLines = log[cut].SecretLines
	if err := saveCopy(dataDir, rec); err != nil {
		return 0, err
	}
	n := len(log) - cut
	return n, savePushLog(dataDir, name, log[:cut])
}
