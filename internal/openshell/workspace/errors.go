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
	"errors"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Sentinel errors. Typed errors below unwrap to these so callers can branch
// with errors.Is and still print the detailed message.
var (
	// ErrUnsafeSource: the folder must never be mounted into a sandbox.
	ErrUnsafeSource = errors.New("workspace: unsafe mount source")
	// ErrNeedsCopy: the folder is safe to share but its git layout cannot be
	// protected by a live mount (worktree, external git dir); use --copy.
	ErrNeedsCopy = errors.New("workspace: project needs copy mode")
	// ErrUnsupportedPlatform: live mounts, snapshots and copy staging are
	// implemented for Linux and macOS hosts only, like OpenShell sandboxes.
	// It is the openshell package's sentinel, so errors.Is matches either.
	ErrUnsupportedPlatform = openshell.ErrUnsupportedPlatform
	// ErrTooLarge: a size preflight failed.
	ErrTooLarge = errors.New("workspace: too large")
	// ErrSnapshotExists: a snapshot with this name is already recorded.
	ErrSnapshotExists = errors.New("workspace: snapshot already exists")
	// ErrSnapshotNotFound: no snapshot is recorded under this name.
	ErrSnapshotNotFound = errors.New("workspace: snapshot not found")
	// ErrGitDirReplaced: the project's git directory is no longer the one
	// recorded at snapshot time.
	ErrGitDirReplaced = errors.New("workspace: the project's git directory was replaced during the session")
	// ErrCopyNotFound: no copy-mode staging record exists under this name.
	ErrCopyNotFound = errors.New("workspace: copy-mode record not found")
	// ErrBlocked: a pull contains changes DefenseClaw refuses to apply
	// (history rewrites below the baseline, new remotes, submodule URL
	// changes) unless the caller forces it.
	ErrBlocked = errors.New("workspace: pull blocked by review gates")
	// ErrSensitiveChanges: a pull contains changes that can run code on the
	// host; the caller must confirm them first.
	ErrSensitiveChanges = errors.New("workspace: pull contains changes that can run code on this machine")
	// ErrUnpulledChanges: a refresh would discard work the agent has not
	// handed back yet.
	ErrUnpulledChanges = errors.New("workspace: the sandbox has changes that were not pulled")
	// ErrUnappliedPull: a refresh would discard a pulled result that was
	// never applied.
	ErrUnappliedPull = errors.New("workspace: the last pull was not applied")
	// ErrNotGitProject: the operation needs a git repository on the host.
	ErrNotGitProject = errors.New("workspace: the project is not a git repository")
	// ErrNoChanges: the sandbox result equals the baseline.
	ErrNoChanges = errors.New("workspace: no changes to bring back")
	// ErrNothingApplied: no 3-way apply of a copy-mode sandbox's work is
	// recorded that UndoApply could revert.
	ErrNothingApplied = errors.New("workspace: no apply to undo")
	// ErrNoReusablePull: the pull PullOptions.Reuse names is not the last
	// pull of the copy (another pull replaced it, or an undo dropped it),
	// so the sandbox has to be read again.
	ErrNoReusablePull = errors.New("workspace: the last pull cannot be reused")
	// ErrScanIncomplete: the secret scan could not look at the whole
	// folder, so a live mount is refused rather than showing files nobody
	// checked.
	ErrScanIncomplete = errors.New("workspace: the secret scan could not check the whole folder")
	// ErrUnreadableFolders: the session left folders DefenseClaw cannot
	// list, so undo cannot tell what they hold.
	ErrUnreadableFolders = errors.New("workspace: the session left folders that cannot be read")
	// ErrUploadNotArrived: openshell reported an upload done, but the
	// sandbox it named does not have it.
	ErrUploadNotArrived = errors.New("workspace: an upload did not arrive in the sandbox")
)

// UploadNotArrivedError is an upload openshell reported done that the
// sandbox, asked over the exec API, does not have (ErrUploadNotArrived).
type UploadNotArrivedError struct {
	Sandbox string
	// Dir is where the upload should have landed; Missing is set when Dir
	// is not there at all, else Marker, the file the upload carried, is
	// not in it.
	Dir, Marker string
	Missing     bool
}

func (e *UploadNotArrivedError) Error() string {
	what := e.Dir + " has no " + e.Marker
	if e.Missing {
		what = e.Dir + " is not there"
	}
	return fmt.Sprintf("workspace: the upload to %s did not arrive: openshell reported it done, but in %s %s; "+
		"the files went elsewhere, for example into another sandbox through an ssh connection shared between sandboxes", e.Sandbox, e.Sandbox, what)
}

func (e *UploadNotArrivedError) Unwrap() error { return ErrUploadNotArrived }

// UnreadableError lists the folders a session made unreadable (see
// ErrUnreadableFolders). Undo refuses until they can be read again: what
// is inside, a planted git repository included, is unknown to it.
type UnreadableError struct {
	Project string
	Dirs    []string
}

func (e *UnreadableError) Error() string {
	return fmt.Sprintf("workspace: undo cannot look inside %s in %s: the session took read permission away, so what it put there is unknown; "+
		"make them readable again (chmod u+rwx) and run undo again", strings.Join(firstN(e.Dirs, 5), ", "), e.Project)
}

func (e *UnreadableError) Unwrap() error { return ErrUnreadableFolders }

// ScanIncompleteError reports a secret scan that stopped at its entry
// limit before it had seen the whole folder.
type ScanIncompleteError struct {
	Path  string
	Limit int
	// Git is set for a git project, which copy mode can still share: it
	// copies what git lists instead of walking the folder.
	Git bool
}

func (e *ScanIncompleteError) Error() string {
	hint := "raise the scan's entry limit or launch from a smaller folder"
	if e.Git {
		hint += ", or run with --copy"
	}
	return fmt.Sprintf("workspace: refusing to mount %s: it has more than %d files and directories, so the secret scan could not check all of it "+
		"and the rest would be visible unmasked (%s)", e.Path, e.Limit, hint)
}

func (e *ScanIncompleteError) Unwrap() error { return ErrScanIncomplete }

// SourceError explains why a folder cannot be mounted.
type SourceError struct {
	Path   string
	Reason string
	// Hint is an optional next step for the operator.
	Hint string
}

func (e *SourceError) Error() string {
	msg := fmt.Sprintf("workspace: refusing to share %s with a sandbox: %s", e.Path, e.Reason)
	if e.Hint != "" {
		msg += " (" + e.Hint + ")"
	}
	return msg
}

func (e *SourceError) Unwrap() error { return ErrUnsafeSource }

// NeedsCopyError explains why a folder must use copy mode.
type NeedsCopyError struct {
	Path   string
	Reason string
}

func (e *NeedsCopyError) Error() string {
	return fmt.Sprintf("workspace: %s cannot be mounted live: %s; run with --copy to work on a copy", e.Path, e.Reason)
}

func (e *NeedsCopyError) Unwrap() error { return ErrNeedsCopy }

// TooLargeError reports a failed size preflight.
type TooLargeError struct {
	What  string
	Size  int64
	Limit int64
	// Entries says Size and Limit count files and directories, not bytes.
	// The walk stops at the limit, so Size is then only a lower bound.
	Entries bool
}

func (e *TooLargeError) Error() string {
	if e.Entries {
		return fmt.Sprintf("workspace: %s has more than the limit of %d files and directories", e.What, e.Limit)
	}
	return fmt.Sprintf("workspace: %s is %s, above the %s limit", e.What, humanBytes(e.Size), humanBytes(e.Limit))
}

// tooManyEntries is the error for a folder walk that hit its entry limit.
func tooManyEntries(what string, limit int) *TooLargeError {
	limit = walkLimit(limit)
	return &TooLargeError{What: what, Size: int64(limit) + 1, Limit: int64(limit), Entries: true}
}

func (e *TooLargeError) Unwrap() error { return ErrTooLarge }

// GateError lists the review gates that stopped an apply.
type GateError struct {
	Sentinel error
	Reasons  []string
}

func (e *GateError) Error() string {
	msg := e.Sentinel.Error()
	for i, r := range e.Reasons {
		if i == 0 {
			msg += ": "
		} else {
			msg += "; "
		}
		msg += r
	}
	return msg
}

func (e *GateError) Unwrap() error { return e.Sentinel }

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
