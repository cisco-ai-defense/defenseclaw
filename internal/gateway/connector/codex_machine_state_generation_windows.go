// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// The Codex managed runtime state is written so that no write needs exclusive
// access to a file a standard user can open (GAP-0650, g582 review 7 M2).
// Every standard user must read the state, because the hook reads it with the
// token of the user, and any reader may refuse delete sharing: a fixed name
// that is replaced in place could then not be written for as long as that
// reader kept it open. Two kinds of file hold it instead, in the Codex
// machine policy folder:
//
//   - The writer copy, .defenseclaw-managed-hooks.state.committed, which only
//     Administrators and SYSTEM can open. Every transaction starts from it, so
//     no standard user can hold it or refuse its read. An empty writer copy
//     means there is no state; it is kept only while a copy of the fixed name
//     of 1.0.8 is still held open, so that the next transaction does not take
//     that copy for the state.
//   - The hook copy, .defenseclaw-managed-hooks.state.<n>, where n is the even
//     value that ends the transaction that wrote it (the writer lock counter).
//     State is present after a transaction exactly when the hook copy named by
//     its end value exists. The transaction creates that copy new
//     (CREATE_NEW, DefenseClaw protection set at creation, no sharing while it
//     writes) and closes it before the counter becomes even, so the hook never
//     sees it half-written. The hook reads the copy named by the even counter
//     it observed, between its two counter reads.
//
// The other copies are deleted while the counter is still odd. A copy another
// process holds open stays where it is, harmlessly: no reader uses a name
// other than the one the counter gives, and later transactions delete it.
// The logical path every caller passes (opts.ManagedStatePath, the fixed name)
// stays the identity the layout checks validate.

// windowsCodexManagedStateCommittedFile is the writer copy.
const windowsCodexManagedStateCommittedFile = windowsCodexManagedStateFile + ".committed"

const windowsCodexManagedStateLabel = "Codex managed runtime state"

// windowsCodexManagedStateGenerationPath is the hook copy for counter.
func windowsCodexManagedStateGenerationPath(dir string, counter uint64) string {
	return filepath.Join(dir, windowsCodexManagedStateFile+"."+strconv.FormatUint(counter, 10))
}

// windowsCodexManagedStateGenerationOf returns the counter a hook copy is
// named for, and whether name is one.
func windowsCodexManagedStateGenerationOf(name string) (uint64, bool) {
	prefix := windowsCodexManagedStateFile + "."
	if len(name) <= len(prefix) || !strings.EqualFold(name[:len(prefix)], prefix) {
		return 0, false
	}
	digits := name[len(prefix):]
	if len(digits) > 8 || (len(digits) > 1 && digits[0] == 48) {
		return 0, false
	}
	for _, r := range digits {
		if r < 48 || r > 57 {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(digits, 10, 64)
	return value, err == nil
}

// windowsCodexManagedStateCopyName reports whether name is the writer copy or
// a hook copy of the state (not the legacy fixed name).
func windowsCodexManagedStateCopyName(name string) bool {
	if strings.EqualFold(name, windowsCodexManagedStateCommittedFile) {
		return true
	}
	_, ok := windowsCodexManagedStateGenerationOf(name)
	return ok
}

// windowsCodexManagedStateGenerations lists the hook copies in dir.
func windowsCodexManagedStateGenerations(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list the %s copies in %s: %w", windowsCodexManagedStateLabel, dir, err)
	}
	var paths []string
	for _, entry := range entries {
		if _, ok := windowsCodexManagedStateGenerationOf(entry.Name()); ok {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths, nil
}

// windowsCodexManagedStateTx is the state as one writer transaction sees and
// changes it. It is set only while windowsCodexMachineProcessMu and the
// writer lock are held.
type windowsCodexManagedStateTx struct {
	dir     string
	end     uint64
	data    []byte
	exists  bool
	changed bool
	// committedExisted: the writer copy existed when the transaction began.
	committedExisted bool
	// requirementsTouched: the transaction tried to change requirements.toml,
	// so the hook's pair changes even when the state bytes do not.
	requirementsTouched bool
	// direct: Secure Client. The state is the fixed-name file of 1.0.8 and
	// earlier, read and written in place under that release's lock, as
	// before GAP-0650.
	direct bool
}

var windowsCodexActiveManagedState *windowsCodexManagedStateTx

// beginWindowsCodexManagedState reads the committed state for a transaction
// that ends at end. Without a writer copy no writer of this release has
// committed yet, and the state is the fixed-name file of 1.0.8 (or of a test
// build of this round): it is read once, and the transaction writes it into
// the new files. Keep reading the fixed name while upgrades from 1.0.8 are
// supported.
func beginWindowsCodexManagedState(dir string, end uint64) (*windowsCodexManagedStateTx, error) {
	tx := &windowsCodexManagedStateTx{dir: dir, end: end}
	committed, err := readWindowsCodexMachineFile(
		filepath.Join(dir, windowsCodexManagedStateCommittedFile),
		windowsCodexManagedStateLimit,
		true,
		windowsCodexManagedStateLabel+" (writer copy)",
	)
	if err != nil {
		return nil, err
	}
	if committed.existed {
		tx.committedExisted = true
		tx.exists = len(committed.data) != 0
		if tx.exists {
			tx.data = committed.data
		}
		return tx, nil
	}
	legacyPath := filepath.Join(dir, windowsCodexManagedStateFile)
	legacy, err := readWindowsCodexMachineFile(
		legacyPath,
		windowsCodexManagedStateLimit,
		true,
		windowsCodexManagedStateLabel,
	)
	if err != nil {
		// A user can open the fixed name of 1.0.8 (it was user-readable) and
		// refuse every sharing mode. The holder is named, and the caller
		// waits for the release a bounded time like it does for
		// requirements.toml (g582 round 9 S1).
		return nil, windowsCodexFileHeldFailure(legacyPath, err, true)
	}
	tx.exists = legacy.existed
	tx.data = legacy.data
	return tx, nil
}

// windowsCodexManagedStateFor returns the running transaction state for path,
// which must be the logical state path of its folder.
func windowsCodexManagedStateFor(path string) (*windowsCodexManagedStateTx, error) {
	tx := windowsCodexActiveManagedState
	if tx == nil {
		return nil, fmt.Errorf("the %s is read or written only inside a Codex machine policy transaction", windowsCodexManagedStateLabel)
	}
	if !strings.EqualFold(filepath.Base(path), windowsCodexManagedStateFile) ||
		!sameWindowsCodexMachinePath(filepath.Dir(path), tx.dir) {
		return nil, fmt.Errorf("refusing noncanonical Codex managed runtime state path %s", path)
	}
	return tx, nil
}

// readWindowsCodexManagedState is readWindowsCodexMachineFile for the state:
// the view of the running transaction.
func readWindowsCodexManagedState(path string, allowMissing bool) (windowsCodexStableFile, error) {
	tx, err := windowsCodexManagedStateFor(path)
	if err != nil {
		return windowsCodexStableFile{}, err
	}
	if tx.direct {
		return readWindowsCodexMachineFile(path, windowsCodexManagedStateLimit, allowMissing, windowsCodexManagedStateLabel)
	}
	if !tx.exists {
		if !allowMissing {
			return windowsCodexStableFile{}, fmt.Errorf("inspect %s: %w", windowsCodexManagedStateLabel, os.ErrNotExist)
		}
		return windowsCodexStableFile{}, nil
	}
	return windowsCodexStableFile{data: append([]byte(nil), tx.data...), existed: true}, nil
}

// writeWindowsCodexManagedState sets the state the transaction commits.
func writeWindowsCodexManagedState(path string, data []byte) error {
	tx, err := windowsCodexManagedStateFor(path)
	if err != nil {
		return err
	}
	if tx.direct {
		return writeWindowsCodexMachineFile(path, data, windowsCodexManagedStateLimit, windowsCodexManagedStateLabel)
	}
	if len(data) == 0 || len(data) > windowsCodexManagedStateLimit {
		return fmt.Errorf("%s must hold 1 to %d bytes", windowsCodexManagedStateLabel, windowsCodexManagedStateLimit)
	}
	if tx.exists && bytes.Equal(tx.data, data) {
		// The same bytes the transaction already holds change nothing: the
		// hook copy and the counter stay, whoever asked (g582 round 11,
		// GAP-0764).
		return nil
	}
	tx.data = append([]byte(nil), data...)
	tx.exists = true
	tx.changed = true
	return nil
}

// deleteWindowsCodexManagedState removes the state in the transaction.
func deleteWindowsCodexManagedState(path string) error {
	tx, err := windowsCodexManagedStateFor(path)
	if err != nil {
		return err
	}
	if tx.direct {
		return deleteWindowsCodexMachineFile(path, windowsCodexManagedStateLabel)
	}
	if tx.exists {
		tx.changed = true
	}
	tx.data = nil
	tx.exists = false
	return nil
}

// unchanged reports a transaction that changed neither the state nor
// requirements.toml and that began at the even counter previous, whose hook
// copy is still in place. Verify, status and a guardian pass that finds
// nothing to do are such transactions: they leave the hook copy alone and the
// counter goes back to previous (g582 round 9 L1). A pass that finds no hook
// copy for the state it holds writes one.
func (tx *windowsCodexManagedStateTx) unchanged(previous uint64) bool {
	// Counter 0 is a writer lock no transaction has used: the first one moves
	// it, so the hook stops reading the fixed name of 1.0.8.
	if tx.changed || tx.requirementsTouched || previous%2 != 0 || previous == 0 {
		return false
	}
	if !tx.exists {
		return !tx.committedExisted && !windowsCodexLegacyStatePresent(filepath.Join(tx.dir, windowsCodexManagedStateFile))
	}
	return tx.committedExisted &&
		tx.hookCopyIntact(windowsCodexManagedStateGenerationPath(tx.dir, previous))
}

// hookCopyIntact reports that the hook copy at path is present, holds the
// state the transaction holds, and carries DefenseClaw's protection. The hook
// reads that copy and nothing else, so a copy that was truncated, changed or
// given another access list since it was written is not the state the pass
// would have written: it is published again under a new name (g582 round 11c,
// S1). The access list is read first, with an open that asks for no data
// access, so a copy a user holds open does not hide a drifted list. A copy
// that cannot be read because a user holds it open without read sharing
// (GAP-0650 allows that) is not intact either: the hook and the guardian read
// that copy and nothing else, so while the hold lasts every hook call and the
// guardian fail on it. The pass publishes the state under a new name, which
// frees them within one pass; the held copy stays until it is released. Once
// the new copy is the current one nothing is written again, so the rewrite of
// GAP-0764 does not return. (A first version counted a sharing violation as
// intact; the native run with a held current copy showed the guardian never
// recovering and Setup stopping on its coverage.)
func (tx *windowsCodexManagedStateTx) hookCopyIntact(path string) bool {
	if !windowsCodexPathPresent(path) {
		return false
	}
	drift, err := windowsCodexMachineFileDrift(path)
	if err != nil || !drift.Canonical {
		return false
	}
	file, err := readWindowsCodexMachineFile(path, windowsCodexManagedStateLimit, false, windowsCodexManagedStateLabel)
	if err != nil {
		return false
	}
	return bytes.Equal(file.data, tx.data)
}

// keepsPrevious reports that the hook copy of the counter the transaction
// began at is still a complete pair with requirements.toml, so a commit that
// failed before it replaced the copy leaves the hook on it.
func (tx *windowsCodexManagedStateTx) keepsPrevious(previous uint64) bool {
	return !tx.requirementsTouched && tx.exists && previous%2 == 0 && previous > 0 &&
		windowsCodexPathPresent(windowsCodexManagedStateGenerationPath(tx.dir, previous))
}

// settle ends the state part of a transaction while the counter is still odd
// and returns the value the counter takes: previous when nothing changed or
// the commit failed before it replaced the hook copy, the end value
// otherwise.
func (tx *windowsCodexManagedStateTx) settle(previous uint64) (uint64, error) {
	if tx.unchanged(previous) {
		keep := ""
		if tx.exists {
			keep = windowsCodexManagedStateGenerationPath(tx.dir, previous)
		}
		tx.dropOtherCopies(keep)
		return previous, nil
	}
	if err := tx.commit(); err != nil {
		if tx.keepsPrevious(previous) {
			return previous, err
		}
		return tx.end, err
	}
	return tx.end, nil
}

// dropOtherCopies deletes, best effort, every hook copy but keep and the
// fixed name of 1.0.8; one that is held open stays for a later transaction.
func (tx *windowsCodexManagedStateTx) dropOtherCopies(keep string) {
	generations, err := windowsCodexManagedStateGenerations(tx.dir)
	if err == nil {
		for _, path := range generations {
			if keep == "" || !sameWindowsCodexMachinePath(path, keep) {
				_ = deleteWindowsCodexManagedStateCopy(path)
			}
		}
	}
	legacyPath := filepath.Join(tx.dir, windowsCodexManagedStateFile)
	if windowsCodexLegacyStatePresent(legacyPath) {
		_ = deleteWindowsCodexManagedStateCopy(legacyPath)
	}
}

// commit writes the state of the transaction while the counter is still odd.
// With state, the writer copy is written first, then the hook copy for the
// end value. Without, the writer copy is emptied before any hook copy goes,
// so a writer that stops part way never leaves an older state for the next
// transaction to carry forward. Then every other copy and the legacy fixed
// name are deleted; one that is held open stays for a later transaction.
func (tx *windowsCodexManagedStateTx) commit() error {
	committedPath := filepath.Join(tx.dir, windowsCodexManagedStateCommittedFile)
	legacyPath := filepath.Join(tx.dir, windowsCodexManagedStateFile)
	label := windowsCodexManagedStateLabel + " (writer copy)"
	current := ""
	if tx.exists {
		if tx.changed || !tx.committedExisted {
			if err := writeWindowsCodexMachineFile(committedPath, tx.data, windowsCodexManagedStateLimit, label); err != nil {
				return err
			}
		}
		current = windowsCodexManagedStateGenerationPath(tx.dir, tx.end)
		if err := createWindowsCodexManagedStateGeneration(current, tx.data); err != nil {
			return err
		}
	} else if tx.committedExisted || windowsCodexLegacyStatePresent(legacyPath) {
		if err := writeWindowsCodexMachineFile(committedPath, []byte{}, windowsCodexManagedStateLimit, label); err != nil {
			return err
		}
	}
	generations, err := windowsCodexManagedStateGenerations(tx.dir)
	if err != nil {
		return err
	}
	for _, path := range generations {
		if current == "" || !sameWindowsCodexMachinePath(path, current) {
			_ = deleteWindowsCodexManagedStateCopy(path)
		}
	}
	_ = deleteWindowsCodexManagedStateCopy(legacyPath)
	if !tx.exists && !windowsCodexLegacyStatePresent(legacyPath) {
		// Nothing a later transaction could take for state is left, so the
		// empty writer copy goes too.
		if err := deleteWindowsCodexMachineFile(committedPath, label); err != nil {
			return err
		}
	}
	return nil
}

// windowsCodexPathPresent reports that path can be inspected: a hook copy
// that cannot be inspected counts as missing, so the pass writes one.
func windowsCodexPathPresent(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// windowsCodexLegacyStatePresent reports the fixed-name state file of 1.0.8
// as present unless it is known to be missing. A file that cannot be
// inspected (a sharing violation, an access error) is never taken for an
// absent one: the empty writer copy stays that keeps a later transaction from
// taking it for the state, and nothing is concluded from the error (GAP-0765).
func windowsCodexLegacyStatePresent(path string) bool {
	_, err := os.Lstat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}

// windowsCodexStateGenerationTaken reports a hook copy already named for
// counter in dir: one held open from before the counter wrapped. The
// transaction counter skips such a value, so a commit always creates its copy
// new.
func windowsCodexStateGenerationTaken(dir string, counter uint64) bool {
	_, err := os.Lstat(windowsCodexManagedStateGenerationPath(dir, counter))
	return !errors.Is(err, os.ErrNotExist)
}

// createWindowsCodexManagedStateGeneration creates path new with data and
// the user-readable DefenseClaw protection, set when the file is created. Its
// handle shares nothing while it writes, and it is closed before the
// transaction ends. A file that cannot be completed is deleted through that
// handle.
func createWindowsCodexManagedStateGeneration(path string, data []byte) (err error) {
	descriptor, err := windows.SecurityDescriptorFromString(windowsCodexMachineCanonicalDescriptorSDDL(true))
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		name,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
		0,
		&attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("create %s %s: %w", windowsCodexManagedStateLabel, path, err)
	}
	defer func() {
		if err != nil {
			deleteFile := byte(1)
			_ = windows.SetFileInformationByHandle(handle, windows.FileDispositionInfo, &deleteFile, 1)
		}
		if closeErr := windows.CloseHandle(handle); closeErr != nil && err == nil {
			err = fmt.Errorf("close %s %s: %w", windowsCodexManagedStateLabel, path, closeErr)
		}
	}()
	for written := 0; written < len(data); {
		var done uint32
		if err := windows.WriteFile(handle, data[written:], &done, nil); err != nil {
			return fmt.Errorf("write %s %s: %w", windowsCodexManagedStateLabel, path, err)
		}
		if done == 0 {
			return fmt.Errorf("write %s %s: no progress", windowsCodexManagedStateLabel, path)
		}
		written += int(done)
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("flush %s %s: %w", windowsCodexManagedStateLabel, path, err)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect %s %s: %w", windowsCodexManagedStateLabel, path, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		info.NumberOfLinks != 1 ||
		uint64(info.FileSizeHigh)<<32|uint64(info.FileSizeLow) != uint64(len(data)) {
		return fmt.Errorf("%s %s is not the single-link regular file just written", windowsCodexManagedStateLabel, path)
	}
	return nil
}
