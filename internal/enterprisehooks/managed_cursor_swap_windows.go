// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// windowsCursorManagedSwap is one compare-and-swap write of a Cursor
// enterprise artifact.
type windowsCursorManagedSwap struct {
	path string
	// expect is the file the write may replace. The swap publishes data only
	// while path still holds exactly that file; any other file is newer and
	// is kept (errWindowsCursorManagedConcurrentChange).
	expect windowsManagedFileSnapshot
	// expectMetadata, when set, is compared too: a file whose owner, access
	// list or attributes changed is newer as well. The shared hooks.json
	// writer sets it.
	expectMetadata *windowsCursorManagedFileMetadata
	data           []byte
	limit          int
	// metadata, when set, is the security descriptor and attributes the
	// file is published with. Otherwise it gets DefenseClaw's protection, as
	// windowsManagedPolicyWriter writes it.
	metadata *windowsCursorManagedFileMetadata
}

type windowsCursorManagedSwapResult struct {
	// swapped reports that data was published at path.
	swapped bool
	// replacedMetadata is the metadata of the file the swap replaced, read
	// under the swap's lock; zero when there was none.
	replacedMetadata windowsCursorManagedFileMetadata
	// publishedMetadata is the metadata of the published file.
	publishedMetadata windowsCursorManagedFileMetadata
}

// windowsCursorManagedFileSwap is swapWindowsCursorManagedFile; tests replace
// it to fail or interleave a write.
var windowsCursorManagedFileSwap = swapWindowsCursorManagedFile

var errWindowsCursorManagedConcurrentChange = errors.New(
	"enterprise hooks: a Cursor guard file changed concurrently")

// windowsCursorManagedConcurrentChange reports a file another writer changed.
// It wraps safefile.ErrSwapRaced too, so the shared writer renders again on
// the newer file.
func windowsCursorManagedConcurrentChange(path string) error {
	return fmt.Errorf("%w: %s (%w)", errWindowsCursorManagedConcurrentChange, path, safefile.ErrSwapRaced)
}

// swapWindowsCursorManagedFile publishes data at path only while path holds
// request.expect (safefile.PublishSharedFile). The administrator and Cursor
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
	userReadable := !strings.EqualFold(filepath.Base(path), windowsCursorManagedReceiptFile)
	publish := safefile.SharedPublish{
		Base:        safefile.SharedFile{Path: path, Exists: request.expect.existed, Data: request.expect.data},
		Data:        request.data,
		Limit:       request.limit,
		TempPattern: ".defenseclaw-policy-*.tmp",
		Protect: func(temp string) error {
			return setWindowsManagedPolicyProtection(temp, false, userReadable)
		},
	}
	if request.expectMetadata != nil {
		publish.CompareMetadata = true
		publish.Base.Metadata = request.expectMetadata.shared()
		result.replacedMetadata = *request.expectMetadata
	} else {
		publish.Inspect = func(file *os.File) error {
			metadata, err := safefile.ReadFileMetadata(file)
			result.replacedMetadata = windowsCursorManagedFileMetadataOf(metadata)
			return err
		}
	}
	if request.metadata != nil {
		metadata := request.metadata.shared()
		publish.Metadata = &metadata
	}
	published, swapped, err := safefile.PublishSharedFile(publish)
	if !swapped {
		if errors.Is(err, safefile.ErrSwapRaced) {
			return windowsCursorManagedSwapResult{}, windowsCursorManagedConcurrentChange(path)
		}
		return windowsCursorManagedSwapResult{}, fmt.Errorf("enterprise hooks: publish managed policy %s: %w", path, err)
	}
	result.swapped = true
	result.publishedMetadata = windowsCursorManagedFileMetadataOf(published)
	if err == nil {
		err = windowsManagedPolicyFileTrustCheck(path)
	}
	return result, err
}

// removeWindowsCursorManagedFileIfUnchanged deletes path only while it holds
// data and, when metadata is set, that metadata. A different file is kept,
// and a different or missing file is reported as a concurrent change.
func removeWindowsCursorManagedFileIfUnchanged(
	path string,
	data []byte,
	metadata *windowsCursorManagedFileMetadata,
	limit int,
) error {
	base := safefile.SharedFile{Path: path, Exists: true, Data: data}
	if metadata != nil {
		base.Metadata = metadata.shared()
	}
	err := safefile.RemoveSharedFile(base, metadata != nil, limit, nil)
	if errors.Is(err, safefile.ErrSwapRaced) {
		return windowsCursorManagedConcurrentChange(path)
	}
	if err != nil {
		return fmt.Errorf("enterprise hooks: remove %s: %w", path, err)
	}
	return nil
}

func (metadata windowsCursorManagedFileMetadata) shared() safefile.FileMetadata {
	return safefile.FileMetadata{SecurityDescriptor: metadata.securityDescriptor, Attributes: metadata.attributes}
}

func windowsCursorManagedFileMetadataOf(metadata safefile.FileMetadata) windowsCursorManagedFileMetadata {
	return windowsCursorManagedFileMetadata{securityDescriptor: metadata.SecurityDescriptor, attributes: metadata.Attributes}
}

// windowsCursorSharedHooks is hooks.json as the shared writer sees it.
func windowsCursorSharedHooks(
	snapshot windowsManagedFileSnapshot,
	metadata windowsCursorManagedFileMetadata,
) safefile.SharedFile {
	file := safefile.SharedFile{Path: snapshot.path, Exists: snapshot.existed}
	if snapshot.existed {
		file.Data, file.Metadata = snapshot.data, metadata.shared()
	}
	return file
}

// windowsCursorHooksWriter is the shared writer (safefile.SharedFileWriter)
// for C:\ProgramData\Cursor\hooks.json. Every DefenseClaw write, rollback and
// restore of that file goes through it, under the Cursor transaction lock:
// each edit changes only DefenseClaw's own entries, is published only over
// the file it was made from (content, owner, access list and attributes), and
// keeps that file's metadata unless it restores metadata DefenseClaw
// recorded. A newer save is kept and the edit is made again on it, up to
// windowsCursorManagedGuardRebuildAttempts times.
func windowsCursorHooksWriter() safefile.SharedFileWriter {
	return safefile.SharedFileWriter{
		Attempts: windowsCursorManagedGuardRebuildAttempts,
		Read:     readWindowsCursorSharedHooks,
		Write:    writeWindowsCursorSharedHooks,
	}
}

func readWindowsCursorSharedHooks(path string) (safefile.SharedFile, error) {
	snapshot, err := snapshotWindowsManagedFileWithLimit(path, windowsCursorManagedHooksLimit)
	if err != nil {
		return safefile.SharedFile{}, err
	}
	metadata, err := snapshotWindowsCursorManagedFileMetadata(snapshot)
	if err != nil {
		return safefile.SharedFile{}, err
	}
	return windowsCursorSharedHooks(snapshot, metadata), nil
}

func writeWindowsCursorSharedHooks(base safefile.SharedFile, edit safefile.SharedEdit) (safefile.SharedWriteResult, error) {
	metadata := windowsCursorManagedFileMetadataOf(base.Metadata)
	if edit.Remove {
		err := removeWindowsCursorManagedFileIfUnchanged(base.Path, base.Data, &metadata, windowsCursorManagedHooksLimit)
		return safefile.SharedWriteResult{Published: err == nil, Left: safefile.SharedFile{Path: base.Path}}, err
	}
	request := windowsCursorManagedSwap{
		path:   base.Path,
		expect: windowsManagedFileSnapshot{path: base.Path, existed: base.Exists, data: base.Data},
		data:   edit.Data,
		limit:  windowsCursorManagedHooksLimit,
	}
	if base.Exists {
		request.expectMetadata = &metadata
		request.metadata = &metadata
	}
	if edit.Metadata != nil {
		final := windowsCursorManagedFileMetadataOf(*edit.Metadata)
		request.metadata = &final
	}
	result, err := windowsCursorManagedFileSwap(request)
	return safefile.SharedWriteResult{
		Published: result.swapped,
		Left: safefile.SharedFile{
			Path: base.Path, Exists: true, Data: edit.Data, Metadata: result.publishedMetadata.shared(),
		},
	}, err
}

// publishWindowsCursorManagedHooks publishes render's edit of hooks.json, read
// as base, with the shared writer.
func publishWindowsCursorManagedHooks(base safefile.SharedFile, render safefile.SharedRender) (safefile.SharedFileWrite, error) {
	return windowsCursorHooksWriter().Update(base, render)
}

// undoWindowsCursorManagedHooks undoes a hooks.json write. Over a save another
// writer made since, rebase makes the rollback's own change on that save:
// DefenseClaw's entries as they were before the write, and nothing else.
func undoWindowsCursorManagedHooks(write safefile.SharedFileWrite, rebase safefile.SharedRender) error {
	return windowsCursorHooksWriter().Undo(write, rebase)
}

// windowsCursorHooksRegistrationRender merges the guard's registration at
// failMode into hooks.json: only DefenseClaw's entries change. A file that
// already carries it is left as it is; a file that is not JSON, another
// writer's save in progress, is never discarded.
func windowsCursorHooksRegistrationRender(adapterPath, failMode string) safefile.SharedRender {
	return func(base safefile.SharedFile) (safefile.SharedEdit, error) {
		hooks, err := mergeWindowsCursorManagedRebuildHooks(windowsCursorManagedSnapshotOf(base), adapterPath, failMode, false)
		return safefile.SharedEdit{Data: hooks}, err
	}
}

// windowsCursorHooksRemovalRender takes DefenseClaw's entries out of
// hooks.json, keeping every other byte. A file DefenseClaw created
// (preexisting false) that holds nothing else is removed.
func windowsCursorHooksRemovalRender(adapterPath string, preexisting bool) safefile.SharedRender {
	return func(base safefile.SharedFile) (safefile.SharedEdit, error) {
		if !base.Exists {
			return safefile.SharedEdit{Remove: true}, nil
		}
		cleaned, err := connector.SpliceRemoveWindowsCursorEnterpriseHooks(base.Data, adapterPath)
		if err != nil {
			return safefile.SharedEdit{}, err
		}
		if !preexisting && connector.WindowsCursorEnterpriseHooksEmpty(cleaned) {
			return safefile.SharedEdit{Remove: true}, nil
		}
		return safefile.SharedEdit{Data: cleaned}, nil
	}
}

func windowsCursorManagedSnapshotOf(file safefile.SharedFile) windowsManagedFileSnapshot {
	return windowsManagedFileSnapshot{path: file.Path, existed: file.Exists, data: file.Data}
}
