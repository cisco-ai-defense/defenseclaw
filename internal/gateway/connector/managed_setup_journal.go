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

package connector

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// A setup read-back (updateManagedFileBackupPostHash) used to record the hash
// of whatever the target held as DefenseClaw output. An edit that landed
// between the capture and the patch (which merges it) or between the patch and
// the read-back was therefore recorded as ours, and the exact restore replaced
// it with the pre-setup copy.
//
// While a first setup is open on a path, the shared writers report each write
// here. The span follows the bytes DefenseClaw committed: a write must find the
// file as the setup left it (the pre-setup bytes, or the previous write), and
// the read-back must find the last bytes written. Anything else is an edit by
// someone else, so the record is retired to owned-entry cleanup. A setup whose
// writers never report is held to the pre-setup bytes, so an unreported writer
// ends in owned-entry cleanup, never in a restore over bytes nobody vouched
// for.
type managedSetupSpan struct {
	expected string
	// prior is what the target held before the last reported write: a writer
	// that reruns its transformation over the same base (a compare-and-swap
	// retry) finds that, not the bytes it staged.
	prior   string
	tainted bool
	// later marks a span opened over an existing record. It holds the target
	// to base, the bytes the record vouches for when the setup began, whatever
	// the writers report: the setup must leave them unchanged to keep the
	// exact restore.
	later bool
	base  string
	// conversion marks a span a rollback conversion opened. Its writes refuse
	// to replace a file that is not the one the conversion read, so a save
	// by someone else is never overwritten; found is what the last write
	// found, checked again just before the file is replaced.
	conversion bool
	found      string
}

// errManagedTargetMoved is a write refused because the file is not the one the
// writer read: someone saved it in between. The file is left as it is.
var errManagedTargetMoved = errors.New("the file changed while DefenseClaw was rewriting it; it was left as it is")

var managedSetupSpans = struct {
	sync.Mutex
	byPath map[string]*managedSetupSpan
}{byPath: map[string]*managedSetupSpan{}}

func managedSetupSpanKey(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = path
	}
	abs = filepath.Clean(abs)
	if runtime.GOOS == "windows" {
		abs = strings.ToLower(abs)
	}
	return abs
}

// beginManagedSetupSpan opens a span on a captured target. expected is the
// hash of the state the setup begins on (managedFileSnapshotHash); later is set
// when it is the state an existing record vouches for.
func beginManagedSetupSpan(path, expected string, later bool) {
	managedSetupSpans.Lock()
	defer managedSetupSpans.Unlock()
	managedSetupSpans.byPath[managedSetupSpanKey(path)] = &managedSetupSpan{expected: expected, base: expected, later: later}
}

// beginManagedConversionSpan opens a span for a rollback conversion that
// starts on the bytes with hash expected. It reports false, and opens nothing,
// when a setup holds a span on the path.
func beginManagedConversionSpan(path, expected string) bool {
	managedSetupSpans.Lock()
	defer managedSetupSpans.Unlock()
	key := managedSetupSpanKey(path)
	if _, open := managedSetupSpans.byPath[key]; open {
		return false
	}
	managedSetupSpans.byPath[key] = &managedSetupSpan{expected: expected, base: expected, conversion: true}
	return true
}

// endManagedSetupSpan closes the span and returns it (ok is false when none
// was open).
func endManagedSetupSpan(path string) (managedSetupSpan, bool) {
	managedSetupSpans.Lock()
	defer managedSetupSpans.Unlock()
	key := managedSetupSpanKey(path)
	span, ok := managedSetupSpans.byPath[key]
	if !ok {
		return managedSetupSpan{}, false
	}
	delete(managedSetupSpans.byPath, key)
	return *span, true
}

// noteManagedSetupWrite is called by a writer before it replaces path with
// data. The target is read here, not taken from the caller. A conversion span
// refuses (errManagedTargetMoved) a target that is not the bytes the rollback
// left.
func noteManagedSetupWrite(path string, data []byte) error {
	managedSetupSpans.Lock()
	defer managedSetupSpans.Unlock()
	if len(managedSetupSpans.byPath) == 0 {
		return nil
	}
	span, ok := managedSetupSpans.byPath[managedSetupSpanKey(path)]
	if !ok {
		return nil
	}
	current, info, err := readManagedTarget(path)
	if err != nil {
		if span.conversion {
			return errManagedTargetMoved
		}
		span.tainted = true
		span.expected = managedFileSnapshotHash(data, true)
		return nil
	}
	return span.note(managedFileSnapshotHash(current, info != nil), data)
}

// confirmManagedSetupPublish is called by a writer right before it replaces
// path: the target must still be what noteManagedSetupWrite found. A save that
// landed in between taints a setup span, and a conversion span refuses the
// write. The replacement itself cannot compare the file, so a save in the
// instant between this check and the replacement is the one case left.
func confirmManagedSetupPublish(path string) error {
	managedSetupSpans.Lock()
	defer managedSetupSpans.Unlock()
	if len(managedSetupSpans.byPath) == 0 {
		return nil
	}
	span, ok := managedSetupSpans.byPath[managedSetupSpanKey(path)]
	if !ok {
		return nil
	}
	current, info, err := readManagedTarget(path)
	if err == nil && managedFileSnapshotHash(current, info != nil) == span.found {
		return nil
	}
	if span.conversion {
		return errManagedTargetMoved
	}
	span.tainted = true
	return nil
}

// noteManagedSetupTransform is noteManagedSetupWrite for a writer that already
// holds the bytes it read (current, exists) and the bytes it will publish.
func noteManagedSetupTransform(path string, current []byte, exists bool, data []byte) {
	managedSetupSpans.Lock()
	defer managedSetupSpans.Unlock()
	if len(managedSetupSpans.byPath) == 0 {
		return
	}
	span, ok := managedSetupSpans.byPath[managedSetupSpanKey(path)]
	if !ok {
		return
	}
	_ = span.note(managedFileSnapshotHash(current, exists), data)
}

// note records a write of data over a target that held the hash found. A
// conversion span records nothing and refuses a target it did not leave.
func (s *managedSetupSpan) note(found string, data []byte) error {
	matched := found == s.expected || found == s.prior
	if !matched {
		if s.conversion {
			return errManagedTargetMoved
		}
		s.tainted = true
	}
	s.found = found
	s.prior = s.expected
	s.expected = managedFileSnapshotHash(data, true)
	return nil
}
