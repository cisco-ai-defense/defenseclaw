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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// atomicWriteFile writes data to a temp file in the same directory and then
// performs a replacement-style rename. This prevents partial writes from
// corrupting the target file if the process crashes mid-write.
//
// If path is a symlink, write through to the linked target instead of renaming
// over the symlink itself. Many operators keep agent dotfiles in a managed
// repo and symlink ~/.codex/config.toml or ~/.claude/settings.json; preserving
// that filesystem shape is part of the teardown contract.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	return atomicWriteFileWithPublisher(path, data, perm, atomicFilePublish)
}

type atomicFilePublisher func(string, string, os.FileInfo, os.FileMode) error

func atomicWriteFileWithPublisher(
	path string,
	data []byte,
	perm os.FileMode,
	publish atomicFilePublisher,
) error {
	writePath, err := resolveAtomicWritePath(path)
	if err != nil {
		return err
	}
	return atomicWriteFileAt(path, writePath, data, perm, publish, false)
}

// atomicWriteFileNoFollow is atomicWriteFile for a path that must be a regular
// file or absent: it never writes through a link. A link or other non-regular
// file there is an error, and the rename replaces the directory entry itself,
// so a link put there after the check is replaced, not followed. The Hermes
// home record (recordHermesHomeSetUp) uses it.
func atomicWriteFileNoFollow(path string, data []byte, perm os.FileMode) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil && !info.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("lstat %s: %w", path, err)
	}
	return atomicWriteFileAt(path, path, data, perm, atomicFilePublish, false)
}

// atomicWriteFileAt writes data to writePath, path or the file a link at path
// leads to. A writePath that already holds data and perm is left as it is,
// unless always is set.
func atomicWriteFileAt(path, writePath string, data []byte, perm os.FileMode, publish atomicFilePublisher, always bool) error {
	// In an account home bound for the enterprise per-user code, a path
	// that leads out of the home is never changed, nor a folder created
	// there; a write that would change nothing is still fine (rel-1-0-3
	// GAP-0206).
	if err := confineAtomicWritePath(path); err != nil {
		if atomicFileAlreadyMatches(writePath, data, perm) {
			return nil
		}
		return err
	}

	if err := noteManagedSetupWrite(path, data); err != nil {
		return err
	}

	dir := filepath.Dir(writePath)
	if err := atomicMkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create dir for %s: %w", writePath, err)
	}
	// Avoid replacing an already-correct config. This is especially important
	// on Windows, where a replacement is a file-identity transition and must not
	// churn NTFS metadata. The platform helper validates the effective owner-only
	// DACL instead of comparing Go's synthetic 0666 FileMode to 0600.
	if !always && atomicFileAlreadyMatches(writePath, data, perm) {
		return nil
	}

	tmp, tmpPath, err := atomicFileCreateTemp(dir, perm)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	if err := atomicStageKeepOwner(tmpPath, writePath); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("keep owner of temp file: %w", err)
	}
	if runtime.GOOS == "windows" && perm.Perm()&0o077 == 0 {
		// atomicFileCreateTemp creates private Windows files with their final
		// owner and protected DACL in the handle-bound NtCreateFile operation.
		// Validate that same handle before writing sensitive bytes. Do not reopen
		// the pathname here: the staging handle deliberately denies write sharing,
		// so a path-based protection pass would conflict with our own handle.
		if err := atomicFileValidateStagedProtection(tmp, perm); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return fmt.Errorf("validate private temp file: %w", err)
		}
	}

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("sync temp file: %w", err)
	}
	stagedInfo, err := tmp.Stat()
	if err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("stat temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("close temp file: %w", err)
	}
	if atomicFileBeforePublish != nil {
		atomicFileBeforePublish(path)
	}
	if err := confirmManagedSetupPublish(path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if atomicFileAfterConfirm != nil {
		atomicFileAfterConfirm(path)
	}
	switch done, err := publishKeepingConversionSaves(path, tmpPath, writePath, data); {
	case done && err != nil:
		return err
	case !done:
		if err := publish(tmpPath, writePath, stagedInfo, perm); err != nil {
			os.Remove(tmpPath)
			return &atomicPublishError{Path: writePath, Err: publishCause(err)}
		}
	}
	// The staged file was synced before publication. POSIX rename additionally
	// needs an explicit parent-directory fsync.
	if runtime.GOOS != "windows" {
		return atomicFileSyncParent(dir)
	}
	return nil
}

// atomicFileBeforePublish runs just before the managed-setup check that
// precedes a replacement, and atomicFileAfterConfirm just after it; tests save
// a file at each to prove the replacement keeps it.
var (
	atomicFileBeforePublish func(path string)
	atomicFileAfterConfirm  func(path string)
)

// confirmingRename is a rename attempt of a publisher that retries a busy
// rename (the Windows private publisher, up to 100 attempts 5 ms apart). Each
// attempt checks the managed-setup span again, so a save that lands while the
// publisher waits is found, not replaced.
func confirmingRename(
	path string,
	rename func(parent, source *os.File, target string, replace bool) error,
) func(parent, source *os.File, target string, replace bool) error {
	return func(parent, source *os.File, target string, replace bool) error {
		if err := confirmManagedSetupPublish(path); err != nil {
			return err
		}
		return rename(parent, source, target, replace)
	}
}

// publishKeepingConversionSaves replaces writePath with the staged tmpPath for
// a rollback conversion by exchanging the two names, so the file displaced is
// the one in tmpPath afterwards and can be compared with the bytes the
// conversion consumed. A file that is not those bytes is a save made after the
// last check: the exchange is undone, the save is back under its name and the
// write is refused (errManagedTargetMoved), so a replacement never drops a save,
// whatever the timing. done is false when no conversion holds the path or the
// platform cannot exchange; the caller then replaces as before, with the one
// remaining instant between its check and the rename (Windows, and a file
// system without exchange).
func publishKeepingConversionSaves(path, tmpPath, writePath string, data []byte) (done bool, err error) {
	found, held := managedConversionFound(path)
	if !held {
		return false, nil
	}
	err = exchangeAtomicFiles(tmpPath, writePath)
	switch {
	case err == nil:
	case atomicExchangeUnsupported(err):
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		// The target is gone, or never was: only a conversion that found it
		// missing may create it, and never over a file made since.
		if found != managedFileSnapshotHash(nil, false) {
			os.Remove(tmpPath)
			return true, errManagedTargetMoved
		}
		if moveErr := moveAtomicFileNoReplace(tmpPath, writePath); moveErr != nil {
			os.Remove(tmpPath)
			if errors.Is(moveErr, errAtomicTransformConflict) {
				return true, errManagedTargetMoved
			}
			return true, &atomicPublishError{Path: writePath, Err: publishCause(moveErr)}
		}
		return true, nil
	default:
		os.Remove(tmpPath)
		return true, &atomicPublishError{Path: writePath, Err: publishCause(err)}
	}
	if displacedMatches(tmpPath, found) {
		os.Remove(tmpPath)
		return true, nil
	}
	// Someone saved the file after the check. Put the save back.
	if err := exchangeAtomicFiles(tmpPath, writePath); err != nil {
		return true, fmt.Errorf("%s was saved while DefenseClaw replaced it and could not be put back; the saved file is %s: %w", writePath, tmpPath, err)
	}
	if displacedMatches(tmpPath, managedFileSnapshotHash(data, true)) {
		os.Remove(tmpPath)
		return true, errManagedTargetMoved
	}
	// A second save landed in the instant of the undo. Keep the newest one in
	// place and the earlier one next to it, and say so.
	if err := exchangeAtomicFiles(tmpPath, writePath); err != nil {
		return true, fmt.Errorf("%s was saved twice while DefenseClaw replaced it; the earlier save is %s and the file may be that one: %w", writePath, tmpPath, err)
	}
	return true, fmt.Errorf("%s was saved twice while DefenseClaw replaced it; the earlier save is kept in %s", writePath, tmpPath)
}

// displacedMatches reports whether the file at path is a regular file whose
// bytes have the managed snapshot hash want.
func displacedMatches(path, want string) bool {
	current, info, err := readManagedTarget(path)
	return err == nil && info != nil && managedFileSnapshotHash(current, true) == want
}

// atomicFileSyncParent syncs dir after a rename into it. A failure leaves the
// new file in place; tests replace it to prove callers handle that.
var atomicFileSyncParent = func(dir string) error {
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open parent directory for sync: %w", err)
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil {
		return fmt.Errorf("sync parent directory: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close parent directory after sync: %w", closeErr)
	}
	return nil
}

// atomicPublishError is a failed replacement of Path. It names the target and
// the cause once: the os rename error repeats both paths, and the staged temp
// file it names is already gone when anyone reads the message.
type atomicPublishError struct {
	Path string
	Err  error
}

func (e *atomicPublishError) Error() string { return fmt.Sprintf("replace %s: %v", e.Path, e.Err) }
func (e *atomicPublishError) Unwrap() error { return e.Err }

func publishCause(err error) error {
	var link *os.LinkError
	if errors.As(err, &link) && link.Err != nil {
		return link.Err
	}
	return err
}

func atomicFileAlreadyMatches(path string, data []byte, perm os.FileMode) bool {
	var matched bool
	_ = safefile.RetryTransientRead(func() error {
		file, err := winpath.OpenReadShared(path)
		if err != nil {
			return err
		}
		defer file.Close()
		matched, err = atomicFileMatchesOpened(file, path, data, perm)
		return err
	})
	return matched
}

func atomicFileMatchesOpened(file *os.File, path string, data []byte, perm os.FileMode) (bool, error) {
	openedInfo, err := file.Stat()
	if err != nil {
		return false, err
	}
	if !openedInfo.Mode().IsRegular() || !atomicFileProtectionMatches(file, openedInfo, perm) {
		return false, nil
	}
	// The destination is commonly user-owned runtime state. Never size an
	// allocation from attacker-controlled metadata: a sparse file can advertise
	// terabytes while consuming almost no disk. A byte-for-byte match must have
	// the exact expected length, and the bounded read below closes a grow-after-
	// stat race without changing the comparison result.
	if openedInfo.Size() != int64(len(data)) {
		return false, nil
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		return false, nil
	}
	current, err := io.ReadAll(io.LimitReader(file, int64(len(data))+1))
	if err != nil {
		return false, err
	}
	if !bytes.Equal(current, data) {
		return false, nil
	}
	pathInfo, err = os.Lstat(path)
	if err != nil {
		return false, err
	}
	return pathInfo.Mode()&os.ModeSymlink == 0 && os.SameFile(openedInfo, pathInfo), nil
}

func resolveAtomicWritePath(path string) (string, error) {
	cur := path
	for i := 0; i < 16; i++ {
		var info os.FileInfo
		err := safefile.RetryTransientRead(func() error {
			var lookupErr error
			info, lookupErr = os.Lstat(cur)
			return lookupErr
		})
		if err != nil {
			if os.IsNotExist(err) {
				return cur, nil
			}
			return "", fmt.Errorf("lstat %s: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			return cur, nil
		}
		target, err := os.Readlink(cur)
		if err != nil {
			return "", fmt.Errorf("readlink %s: %w", cur, err)
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(cur), target)
		}
		cur = filepath.Clean(target)
	}
	return "", fmt.Errorf("resolve symlink %s: too many symlinks", path)
}
