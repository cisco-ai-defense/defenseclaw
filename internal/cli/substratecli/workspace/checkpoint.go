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
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	osw "github.com/defenseclaw/defenseclaw/internal/openshell/workspace"
)

// Checkpoints are snapshots of the project folder taken inside the actor
// with git, in a repository of their own (outside the project, so the
// project's history, index and hooks are never touched and the next Pull
// does not see them). They are the person's convenience, not a security
// boundary: the agent can reach them like any other file in the actor.

var (
	// ErrNoGit: the actor image has no git.
	ErrNoGit = errors.New("this actor has no git, so it cannot take or restore checkpoints; use an image that includes git")
	// ErrNoCheckpoint: there is nothing to restore.
	ErrNoCheckpoint = errors.New("there is no checkpoint to go back to")
	// ErrNoFolder: the project folder is not in the actor (an actor that
	// came back from a crash at its template's start; GAP-0410).
	ErrNoFolder = errors.New("the project folder is not in the actor")
)

const (
	exitNoGit        = 90
	exitNoDir        = 91
	exitNoCheckpoint = 92
	exitUnknownID    = 93

	checkpointTimeout = 5 * time.Minute
	tagPrefix         = "dc-checkpoint-"
)

// CheckpointOptions configures Checkpoint.
type CheckpointOptions struct {
	// Exec runs git in the actor: the *Client.
	Exec osw.Execer
	// Dir is the project folder in the actor (the copy's RemoteDir).
	Dir string
	// StateDir holds the checkpoint repository. When empty and the copy
	// Name has a private state directory (Start made one), it is that
	// directory's checkpoint folder; otherwise .dc-checkpoint next to Dir
	// (in /tmp when Dir is directly below /). It must not be inside Dir.
	StateDir string
	// DataDir and Name find the copy Start made, whose recorded state
	// directory holds the checkpoints. Both empty is fine (no copy).
	DataDir string
	Name    string
	// Label is a short note kept in the checkpoint's commit message.
	Label   string
	Timeout time.Duration
}

// CheckpointInfo is a checkpoint that was taken.
type CheckpointInfo struct {
	// ID is the number to give Undo; Tag is the git tag that holds it.
	ID     string
	Tag    string
	Commit string
	// Files is how many files the checkpoint holds.
	Files int
}

// UndoOptions configures Undo.
type UndoOptions struct {
	Exec     osw.Execer
	Dir      string
	StateDir string
	// DataDir and Name: see CheckpointOptions.
	DataDir string
	Name    string
	// ID is a checkpoint number (or its tag); empty means the last one.
	ID      string
	Timeout time.Duration
}

// UndoInfo is the checkpoint the folder went back to.
type UndoInfo struct {
	// Pushes counts the pushes the undo took back.
	Pushes int
	ID     string
	Commit string
	// Removed and Restored are the files (paths in the actor, below the
	// folder) the undo removed (added since the checkpoint and gone after
	// it) and put back (changed or deleted since), at most 512 KiB of names
	// each; an actor that does not list them (an older script) leaves both
	// empty. The launcher reports them
	// to the cluster's chain state (substrate-1:GAP-0476).
	Removed  []string
	Restored []string
}

const gitPrelude = `set -eu
dir=$1; state=$2
command -v git >/dev/null 2>&1 || { echo "no git in this image" >&2; exit 90; }
[ -d "$dir" ] || { echo "$dir does not exist in the actor" >&2; exit 91; }
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 LC_ALL=C
G="$state/${dir##*/}.git"
g() { git --git-dir="$G" --work-tree="$dir" -c core.hooksPath=/dev/null -c core.fsmonitor=false -c core.autocrlf=false -c commit.gpgSign=false -c user.name=defenseclaw-checkpoint -c user.email=defenseclaw-checkpoint@localhost "$@"; }
last() { g tag -l 'dc-checkpoint-*' | sed 's/^dc-checkpoint-//' | sort -n | tail -n 1; }
`

const checkpointScript = gitPrelude + `( umask 077; mkdir -p "$state"; chmod 700 "$state" )
[ -d "$G" ] || git --git-dir="$G" init -q
cd "$dir"
n=$(( $(last | grep . || echo 0) + 1 ))
g add -A -- .
g commit -q --allow-empty --no-verify -m "checkpoint $n${3:+: $3}"
g tag "dc-checkpoint-$n"
printf 'checkpoint=%s\ncommit=%s\nfiles=%s\n' "$n" "$(g rev-parse HEAD)" "$(g ls-files | wc -l | tr -d ' ')"
`

const undoScript = gitPrelude + `[ -d "$G" ] || { echo "no checkpoint" >&2; exit 92; }
cd "$dir"
if [ -z "$3" ]; then
  id=$(last); [ -n "$id" ] || { echo "no checkpoint" >&2; exit 92; }
else
  id=${3#dc-checkpoint-}
  g rev-parse -q --verify "refs/tags/dc-checkpoint-$id^{commit}" >/dev/null || { echo "known=$(g tag -l 'dc-checkpoint-*' | sed 's/^dc-checkpoint-//' | sort -n | tr '\n' ' ')"; exit 93; }
fi
L="$state/undo.$$"
g diff --name-status --no-renames -z "dc-checkpoint-$id" -- >"$L.d" 2>/dev/null || : >"$L.d"
g diff --name-only --no-renames --diff-filter=A -z "dc-checkpoint-$id" -- >"$L.a" 2>/dev/null || : >"$L.a"
g reset -q --hard "dc-checkpoint-$id"
g ls-files --others --exclude-standard -z >>"$L.a" 2>/dev/null || :
g clean -q -fd
xargs -0 sh -c 'for f; do [ -e "$f" ] || [ -L "$f" ] || printf "%s\0" "$f"; done' dc-gone <"$L.a" >"$L.u" 2>/dev/null || : >"$L.u"
printf 'restored=%s\ncommit=%s\n' "$id" "$(g rev-parse HEAD)"
printf 'changes=%s,%s\n' "$(head -c 524288 "$L.d" | wc -c | tr -d ' ')" "$(head -c 524288 "$L.u" | wc -c | tr -d ' ')"
head -c 524288 "$L.d"; head -c 524288 "$L.u"
rm -f "$L.d" "$L.a" "$L.u"
`

var idRE = regexp.MustCompile(`^(dc-checkpoint-)?[0-9]+$`)

// checkpointFolder is where the checkpoint repository lives inside a
// copy's private state directory.
const checkpointFolder = "checkpoint"

// recordedState is the checkpoint folder inside the private state directory
// of the copy name, "" when there is no copy or it has no private one (a
// copy made before they existed).
func recordedState(dataDir, name string) (string, error) {
	if dataDir == "" || name == "" {
		return "", nil
	}
	if hr, err := loadHostRecord(dataDir, name); err == nil {
		return hr.StateDir, nil
	}
	rec, err := osw.LoadCopy(dataDir, name)
	if err != nil {
		if errors.Is(err, osw.ErrCopyNotFound) {
			return "", nil
		}
		return "", fmt.Errorf("workspace: read the copy %s: %w", name, err)
	}
	if rec.StateDir == "" {
		return "", nil
	}
	return path.Join(rec.StateDir, checkpointFolder), nil
}

func checkpointPaths(dir, state, dataDir, name string) (string, string, error) {
	if state == "" {
		var err error
		if state, err = recordedState(dataDir, name); err != nil {
			return "", "", err
		}
	}
	if !path.IsAbs(dir) || path.Clean(dir) == "/" {
		return "", "", fmt.Errorf("workspace: the project folder %q must be an absolute path below /", dir)
	}
	dir = path.Clean(dir)
	if state == "" {
		parent := path.Dir(dir)
		if parent == "/" {
			parent = "/tmp"
		}
		state = path.Join(parent, ".dc-checkpoint")
	}
	state = path.Clean(state)
	if !path.IsAbs(state) {
		return "", "", fmt.Errorf("workspace: the checkpoint folder %q must be an absolute path", state)
	}
	if state == dir || strings.HasPrefix(state, dir+"/") {
		return "", "", fmt.Errorf("workspace: the checkpoint folder %s must be outside the project folder %s", state, dir)
	}
	return dir, state, nil
}

// kv parses "key=value" lines.
func kv(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func runScript(ctx context.Context, ex osw.Execer, script string, timeout time.Duration, args ...string) (*osw.ExecResult, error) {
	if timeout <= 0 {
		timeout = checkpointTimeout
	}
	argv := append([]string{"sh", "-c", script, "dc-checkpoint"}, args...)
	return ex.Exec(ctx, "", osw.ExecRequest{Argv: argv, Timeout: timeout})
}

func failure(what string, res *osw.ExecResult) error {
	reason := strings.TrimSpace(string(res.Stderr))
	if reason == "" {
		reason = strings.TrimSpace(string(res.Stdout))
	}
	if reason == "" {
		reason = "it printed no error"
	}
	if i := strings.LastIndex(strings.TrimSpace(reason), "\n"); i >= 0 {
		reason = strings.TrimSpace(reason)[i+1:]
	}
	return fmt.Errorf("%s failed in the actor (exit %d): %s", what, res.ExitCode, safetext.Line(reason))
}

// Checkpoint snapshots the project folder in the actor (every file that
// git would not ignore) and returns the checkpoint's number. It fails with
// ErrNoGit when the actor image has no git.
func Checkpoint(ctx context.Context, opts CheckpointOptions) (*CheckpointInfo, error) {
	if opts.Exec == nil {
		return nil, errors.New("workspace: checkpoint needs a transport to the actor")
	}
	dir, state, err := checkpointPaths(opts.Dir, opts.StateDir, opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	label := strings.Join(strings.Fields(opts.Label), " ")
	res, err := runScript(ctx, opts.Exec, checkpointScript, opts.Timeout, dir, state, label)
	if err != nil {
		return nil, cleanErr("checkpoint", err)
	}
	switch res.ExitCode {
	case 0:
	case exitNoGit:
		return nil, ErrNoGit
	default:
		return nil, failure("the checkpoint", res)
	}
	m := kv(res.Stdout)
	n, err := strconv.Atoi(m["checkpoint"])
	if err != nil || m["commit"] == "" {
		return nil, fmt.Errorf("workspace: the actor answered the checkpoint with %q", strings.TrimSpace(string(res.Stdout)))
	}
	files, _ := strconv.Atoi(m["files"])
	return &CheckpointInfo{ID: strconv.Itoa(n), Tag: tagPrefix + strconv.Itoa(n), Commit: m["commit"], Files: files}, nil
}

// Undo puts the project folder back to the checkpoint ID (the last one when
// empty): files changed since are restored, files added since are removed
// (what git ignores is left alone). It fails with ErrNoGit when the actor has
// no git and ErrNoCheckpoint when there is none to go back to.
func Undo(ctx context.Context, opts UndoOptions) (*UndoInfo, error) {
	if opts.Exec == nil {
		return nil, errors.New("workspace: undo needs a transport to the actor")
	}
	if opts.ID != "" && !idRE.MatchString(opts.ID) {
		return nil, fmt.Errorf("workspace: %q is not a checkpoint number", opts.ID)
	}
	dir, state, err := checkpointPaths(opts.Dir, opts.StateDir, opts.DataDir, opts.Name)
	if err != nil {
		return nil, err
	}
	res, err := runScript(ctx, opts.Exec, undoScript, opts.Timeout, dir, state, opts.ID)
	if err != nil {
		return nil, cleanErr("undo", err)
	}
	switch res.ExitCode {
	case 0:
	case exitNoGit:
		return nil, ErrNoGit
	case exitNoCheckpoint:
		return nil, ErrNoCheckpoint
	case exitNoDir:
		return nil, fmt.Errorf("%w: %s", ErrNoFolder, dir)
	case exitUnknownID:
		known := strings.Fields(kv(res.Stdout)["known"])
		msg := fmt.Sprintf("there is no checkpoint %s", strings.TrimPrefix(opts.ID, tagPrefix))
		if len(known) > 0 {
			msg += "; the checkpoints are " + strings.Join(known, ", ")
		}
		return nil, errors.New(msg)
	default:
		return nil, failure("the undo", res)
	}
	head, changes := undoAnswer(res.Stdout)
	m := kv(head)
	if m["restored"] == "" {
		return nil, fmt.Errorf("workspace: the actor answered the undo with %q", strings.TrimSpace(string(head)))
	}
	info := &UndoInfo{ID: safetext.Line(m["restored"]), Commit: safetext.Line(m["commit"])}
	info.Removed, info.Restored = undoChanges(dir, m["changes"], changes)
	if opts.DataDir != "" && opts.Name != "" && !usesHostCopy(opts.DataDir, opts.Name) {
		// A push after this restore point is undone with the files, so
		// the baseline goes back too; pull then shows the right work.
		n, err := osw.RewindPushes(ctx, opts.DataDir, opts.Name, opts.Exec, info.ID)
		if err != nil {
			return info, cleanErr("put the copy's baseline back", err)
		}
		info.Pushes = n
	}
	return info, nil
}

// undoAnswer splits the undo script's answer into its key=value lines and
// the file lists after the changes line. File names come only after it, so
// none can stand for a key.
func undoAnswer(out []byte) (head, changes []byte) {
	i := bytes.Index(out, []byte("\nchanges="))
	if i < 0 {
		return out, nil
	}
	j := bytes.IndexByte(out[i+1:], '\n')
	if j < 0 {
		return out, nil
	}
	return out[:i+1+j+1], out[i+1+j+1:]
}

// undoChanges reads the two NUL-separated lists the undo script printed,
// sizes from the changes line: git diff --name-status against the
// checkpoint (M, T, D: put back) then the files the undo removed. A name
// counts as removed only when nothing is left at its path after the reset
// and the clean (added since the checkpoint, or untracked and not ignored
// under the rules the reset put back), so a file clean kept (ignored again
// by a .gitignore the reset restored) is not listed (substrate-1:GAP-0476).
// A name cut off at the size bound is dropped, and so is one that is
// absolute, has a ".." element or does not name a path below dir: the
// answer comes from the actor, and the chain state must never forget a
// file outside the folder.
func undoChanges(dir, sizes string, b []byte) (removed, restored []string) {
	ds, us, ok := strings.Cut(sizes, ",")
	nd, err1 := strconv.Atoi(ds)
	nu, err2 := strconv.Atoi(us)
	if !ok || err1 != nil || err2 != nil || nd < 0 || nu < 0 || nd+nu > len(b) {
		return nil, nil
	}
	below := func(rel string) (string, bool) {
		if rel == "" || path.IsAbs(rel) || slices.Contains(strings.Split(rel, "/"), "..") {
			return "", false
		}
		p := path.Join(dir, rel)
		return p, strings.HasPrefix(p, dir+"/")
	}
	// The last piece of each list follows its last NUL: empty, or a name
	// cut off at the bound.
	diff := strings.Split(string(b[:nd]), "\x00")
	diff = diff[:len(diff)-1]
	for i := 0; i+1 < len(diff); i += 2 {
		switch diff[i] {
		case "M", "T", "D":
			if p, ok := below(diff[i+1]); ok {
				restored = append(restored, p)
			}
		}
	}
	gone := strings.Split(string(b[nd:nd+nu]), "\x00")
	for _, name := range gone[:len(gone)-1] {
		if p, ok := below(name); ok {
			removed = append(removed, p)
		}
	}
	return removed, restored
}
