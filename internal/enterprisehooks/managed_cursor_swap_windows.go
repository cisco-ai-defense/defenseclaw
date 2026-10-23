// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

// windowsCursorManagedSwap is one compare-and-swap write of a Cursor
// enterprise artifact.
type windowsCursorManagedSwap struct {
	path string
	// expect is the file the write may replace. The swap publishes data only
	// while path still holds exactly that file; any other file is newer and
	// is kept (errWindowsCursorManagedConcurrentChange).
	expect windowsManagedFileSnapshot
	data   []byte
	limit  int
	// metadata, when set, is the security descriptor and attributes the
	// file ends with.
	metadata *windowsCursorManagedFileMetadata
	// keepReplacedMetadata keeps the replaced file's metadata. Otherwise, and
	// for a new file, the file gets DefenseClaw's protection, as
	// windowsManagedPolicyWriter writes it.
	keepReplacedMetadata bool
}

type windowsCursorManagedSwapResult struct {
	// swapped reports that data was published at path.
	swapped bool
	// replacedMetadata is the metadata of the file the swap replaced, read
	// under the swap's lock; zero when there was none.
	replacedMetadata windowsCursorManagedFileMetadata
}

// windowsCursorManagedFileSwap is swapWindowsCursorManagedFile; tests replace
// it to fail or interleave a write.
var windowsCursorManagedFileSwap = swapWindowsCursorManagedFile

var errWindowsCursorManagedConcurrentChange = errors.New(
	"enterprise hooks: a Cursor guard file changed concurrently")

func windowsCursorManagedConcurrentChange(path string) error {
	return fmt.Errorf("%w: %s", errWindowsCursorManagedConcurrentChange, path)
}

// swapWindowsCursorManagedFile publishes data at path only while path holds
// request.expect (safefile.CompareAndSwapFile). The administrator and Cursor
// do not take the DefenseClaw lock, so a read before a write cannot see a
// save made in between; the swap compares and replaces under one handle no
// other process can write through instead.
func swapWindowsCursorManagedFile(request windowsCursorManagedSwap) (windowsCursorManagedSwapResult, error) {
	path := request.path
	var result windowsCursorManagedSwapResult
	if err := rejectWindowsReparseChain(path); err != nil {
		return result, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return result, fmt.Errorf("enterprise hooks: refusing non-regular managed policy file: %s", path)
		}
		if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
			return result, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".defenseclaw-policy-*.tmp")
	if err != nil {
		return result, err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	_, err = temp.Write(request.data)
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return result, err
	}
	userReadable := !strings.EqualFold(filepath.Base(path), windowsCursorManagedReceiptFile)
	if err := setWindowsManagedPolicyProtection(tempPath, false, userReadable); err != nil {
		return result, err
	}
	swap, err := safefile.CompareAndSwapFile(
		tempPath, path,
		safefile.SwapExpectation{Exists: request.expect.existed, Data: request.expect.data},
		request.limit,
		func(file *os.File) error {
			var metadataErr error
			result.replacedMetadata, metadataErr = windowsCursorManagedLockedFileMetadata(file)
			return metadataErr
		},
	)
	if err != nil {
		if errors.Is(err, safefile.ErrSwapRaced) {
			return windowsCursorManagedSwapResult{}, windowsCursorManagedConcurrentChange(path)
		}
		return windowsCursorManagedSwapResult{}, fmt.Errorf("enterprise hooks: publish managed policy %s: %w", path, err)
	}
	result.swapped = true
	switch {
	case request.metadata != nil:
		err = restoreWindowsCursorManagedFileMetadata(path, *request.metadata)
	case request.keepReplacedMetadata && swap.Replaced:
		err = restoreWindowsCursorManagedFileMetadata(path, result.replacedMetadata)
	default:
		err = setWindowsManagedPolicyProtection(path, false, userReadable)
		if err == nil {
			err = windowsManagedPolicyFileTrustCheck(path)
		}
	}
	return result, err
}

// removeWindowsCursorManagedFileIfUnchanged deletes path only while it holds
// data, and returns the removed file's metadata. A different file is kept,
// and a different or missing file is reported as a concurrent change.
func removeWindowsCursorManagedFileIfUnchanged(
	path string,
	data []byte,
	limit int,
) (windowsCursorManagedFileMetadata, error) {
	var metadata windowsCursorManagedFileMetadata
	_, err := safefile.RemoveFileIfUnchanged(path, data, limit, func(file *os.File) error {
		var metadataErr error
		metadata, metadataErr = windowsCursorManagedLockedFileMetadata(file)
		return metadataErr
	})
	if errors.Is(err, safefile.ErrSwapRaced) {
		return windowsCursorManagedFileMetadata{}, windowsCursorManagedConcurrentChange(path)
	}
	if err != nil {
		return windowsCursorManagedFileMetadata{}, fmt.Errorf("enterprise hooks: remove %s: %w", path, err)
	}
	return metadata, nil
}

// windowsCursorManagedLockedFileMetadata reads the security descriptor and
// attributes of a file through its handle.
func windowsCursorManagedLockedFileMetadata(file *os.File) (windowsCursorManagedFileMetadata, error) {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return windowsCursorManagedFileMetadata{}, err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil || descriptor == nil || descriptor.String() == "" {
		if err == nil {
			err = errors.New("empty security descriptor")
		}
		return windowsCursorManagedFileMetadata{}, fmt.Errorf(
			"enterprise hooks: snapshot Cursor security descriptor for %s: %w", file.Name(), err)
	}
	return windowsCursorManagedFileMetadata{
		securityDescriptor: descriptor.String(),
		attributes:         info.FileAttributes,
	}, nil
}

// windowsCursorManagedHooksEdit is one edit of the shared hooks.json: new
// bytes, or removing the file. metadata, when set, is what the file ends
// with; otherwise it keeps the replaced file's, and a new file gets
// DefenseClaw's protection.
type windowsCursorManagedHooksEdit struct {
	data     []byte
	remove   bool
	metadata *windowsCursorManagedFileMetadata
}

// windowsCursorManagedHooksWrite is a hooks.json edit that
// publishWindowsCursorManagedHooks published, kept so that it can be undone.
type windowsCursorManagedHooksWrite struct {
	written          bool
	edit             windowsCursorManagedHooksEdit
	replaced         windowsManagedFileSnapshot
	replacedMetadata windowsCursorManagedFileMetadata
}

// publishWindowsCursorManagedHooks publishes the edit render makes of the
// shared hooks.json, read as base. Administrators and Cursor do not take the
// DefenseClaw lock, so the write is a compare-and-swap against the file
// render read. When another writer saved in between, the newer file is kept
// and render runs again on it, up to windowsCursorManagedGuardRebuildAttempts
// times. An error from render, a save in progress that is not JSON for
// example, stops with that file in place. An edit that changes nothing is not
// written.
func publishWindowsCursorManagedHooks(
	base windowsManagedFileSnapshot,
	render func(windowsManagedFileSnapshot) (windowsCursorManagedHooksEdit, error),
) (windowsCursorManagedHooksWrite, error) {
	for attempt := 1; ; attempt++ {
		edit, err := render(base)
		if err != nil {
			return windowsCursorManagedHooksWrite{}, err
		}
		if (edit.remove && !base.existed) ||
			(!edit.remove && edit.metadata == nil && base.existed && bytes.Equal(edit.data, base.data)) {
			return windowsCursorManagedHooksWrite{replaced: base}, nil
		}
		write := windowsCursorManagedHooksWrite{written: true, edit: edit, replaced: base}
		if edit.remove {
			write.replacedMetadata, err = removeWindowsCursorManagedFileIfUnchanged(
				base.path, base.data, windowsCursorManagedHooksLimit)
		} else {
			var result windowsCursorManagedSwapResult
			result, err = windowsCursorManagedFileSwap(windowsCursorManagedSwap{
				path: base.path, expect: base, data: edit.data, limit: windowsCursorManagedHooksLimit,
				metadata: edit.metadata, keepReplacedMetadata: edit.metadata == nil,
			})
			write.replacedMetadata = result.replacedMetadata
			if result.swapped && err != nil {
				// Published, but its metadata failed: the caller undoes it.
				return write, err
			}
		}
		if err == nil {
			return write, nil
		}
		if !errors.Is(err, errWindowsCursorManagedConcurrentChange) || attempt == windowsCursorManagedGuardRebuildAttempts {
			return windowsCursorManagedHooksWrite{}, err
		}
		if base, err = snapshotWindowsManagedFileWithLimit(base.path, windowsCursorManagedHooksLimit); err != nil {
			return windowsCursorManagedHooksWrite{}, err
		}
	}
}

// undo puts back the file the write replaced, but only while hooks.json still
// holds what the write published: the put-back is itself a compare-and-swap.
// A file another writer saved since is newer and is kept; the error then wraps
// errWindowsCursorManagedConcurrentChange.
func (write windowsCursorManagedHooksWrite) undo() error {
	if !write.written {
		return nil
	}
	path := write.replaced.path
	if !write.replaced.existed {
		_, err := removeWindowsCursorManagedFileIfUnchanged(path, write.edit.data, windowsCursorManagedHooksLimit)
		return err
	}
	expect := windowsManagedFileSnapshot{path: path, existed: !write.edit.remove}
	if expect.existed {
		expect.data = write.edit.data
	}
	_, err := windowsCursorManagedFileSwap(windowsCursorManagedSwap{
		path: path, expect: expect, data: write.replaced.data, limit: windowsCursorManagedHooksLimit,
		metadata: &write.replacedMetadata,
	})
	return err
}
