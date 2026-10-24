// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// FileMetadata is a file's owner, group and access list, as an SDDL string,
// and its attributes.
type FileMetadata struct {
	SecurityDescriptor string
	Attributes         uint32
}

// SharedFile is one read of a file DefenseClaw shares with writers that do
// not take its lock: an administrator's editor, management tools and the
// agent itself. Cursor's C:\ProgramData\Cursor\hooks.json and Codex's
// requirements.toml are such files. Exists false means the file was absent.
type SharedFile struct {
	Path     string
	Exists   bool
	Data     []byte
	Metadata FileMetadata
}

// Same reports whether other is the same file: present or absent alike, the
// same bytes and the same metadata.
func (f SharedFile) Same(other SharedFile) bool {
	if f.Exists != other.Exists {
		return false
	}
	return !f.Exists || (bytes.Equal(f.Data, other.Data) && f.Metadata == other.Metadata)
}

// SharedEdit is what a render makes of a SharedFile: new bytes, or removing
// the file.
type SharedEdit struct {
	Data   []byte
	Remove bool
	// Metadata, when set, is the metadata the file ends with. Otherwise the
	// file keeps the metadata of the file it replaces, byte for byte, and a
	// new file gets DefenseClaw's protection.
	Metadata *FileMetadata
	// Rewrite publishes the edit even when it changes nothing.
	Rewrite bool
}

// SharedRender makes DefenseClaw's edit of a shared file from the file as it
// is now. It changes only DefenseClaw's own content: a render must keep every
// other byte of the file, and leave Metadata unset unless the file must end
// with metadata DefenseClaw recorded.
type SharedRender func(SharedFile) (SharedEdit, error)

// SharedWriteResult is what one SharedFileWriter.Write call did.
type SharedWriteResult struct {
	// Published reports that the edit was published. A write can publish and
	// still fail afterwards (a trust check of the published file, say); the
	// caller then undoes it.
	Published bool
	// Left is the file the write left at the path.
	Left SharedFile
}

// SharedFileWrite is an edit a SharedFileWriter published, kept so that it
// can be undone.
type SharedFileWrite struct {
	// Written reports that an edit was published.
	Written bool
	// Replaced is the file the edit was made from and replaced.
	Replaced SharedFile
	// Published is what the edit left at the path; Replaced when nothing was
	// written.
	Published SharedFile
}

// SharedFileWriter is the one read-modify-write of a shared file. Every
// DefenseClaw write, rollback and restore of such a file goes through it,
// under the caller's DefenseClaw lock for that file:
//
//   - A render makes DefenseClaw's edit from the file as it is now, and
//     changes only DefenseClaw's own content.
//   - Write publishes the edit only while the file still is the one the render
//     read, content and metadata alike (CompareAndSwapFile). The file keeps
//     its own owner, access list and attributes unless the edit names
//     metadata, and the name holds the old file or the new one at every
//     instant.
//   - When another writer changed the file in between, its file is newer and
//     is kept: the render runs again on it, up to Attempts times.
//   - Undo puts back what a write replaced only while the file still holds
//     exactly what the write published. Over a newer file it makes
//     DefenseClaw's own change of the rollback on that file instead
//     (rebase), so a rollback restores only DefenseClaw's own entries.
type SharedFileWriter struct {
	// Attempts bounds how often Update renders and writes again after a
	// concurrent change. Zero is one attempt.
	Attempts int
	// Read reads the file at path as it is now.
	Read func(path string) (SharedFile, error)
	// Write publishes edit over base with a compare-and-swap on content and
	// metadata. It reports ErrSwapRaced (wrapped) when the path no longer
	// holds base; the newer file is then left in place.
	Write func(base SharedFile, edit SharedEdit) (SharedWriteResult, error)
}

// Unchanged reports whether edit leaves base as it is.
func (edit SharedEdit) Unchanged(base SharedFile) bool {
	if edit.Rewrite {
		return false
	}
	if edit.Remove {
		return !base.Exists
	}
	return base.Exists && bytes.Equal(edit.Data, base.Data) &&
		(edit.Metadata == nil || *edit.Metadata == base.Metadata)
}

// Update publishes render's edit of base, and of a newer file another writer
// saves meanwhile. An error from render, a save in progress that is not a
// valid document for example, stops with that file in place. An edit that
// changes nothing is not written.
func (w SharedFileWriter) Update(base SharedFile, render SharedRender) (SharedFileWrite, error) {
	attempts := w.Attempts
	if attempts < 1 {
		attempts = 1
	}
	for attempt := 1; ; attempt++ {
		unwritten := SharedFileWrite{Replaced: base, Published: base}
		edit, err := render(base)
		if err != nil {
			return unwritten, err
		}
		if edit.Unchanged(base) {
			return unwritten, nil
		}
		result, err := w.Write(base, edit)
		if err == nil || result.Published {
			return SharedFileWrite{Written: true, Replaced: base, Published: result.Left}, err
		}
		if !errors.Is(err, ErrSwapRaced) || attempt >= attempts {
			return unwritten, err
		}
		if base, err = w.Read(base.Path); err != nil {
			return SharedFileWrite{}, err
		}
	}
}

// Undo puts back the file write replaced, its content and metadata, but only
// while the path holds exactly what write published. A file another writer
// saved since is newer and is kept. rebase, when set, then makes DefenseClaw's
// own change of the rollback on that newer file with Update: DefenseClaw's
// entries as they were before the write. Without rebase the error wraps
// ErrSwapRaced.
func (w SharedFileWriter) Undo(write SharedFileWrite, rebase SharedRender) error {
	if !write.Written {
		return nil
	}
	back := SharedEdit{Remove: !write.Replaced.Exists}
	if write.Replaced.Exists {
		metadata := write.Replaced.Metadata
		back.Data, back.Metadata = write.Replaced.Data, &metadata
	}
	result, err := w.Write(write.Published, back)
	if err == nil || result.Published || !errors.Is(err, ErrSwapRaced) || rebase == nil {
		return err
	}
	current, readErr := w.Read(write.Published.Path)
	if readErr != nil {
		return errors.Join(err, readErr)
	}
	_, err = w.Update(current, rebase)
	return err
}

// SharedPublish is one compare-and-swap publication of a shared file.
type SharedPublish struct {
	// Base is the file the publication may replace: absent, or present with
	// Base.Data (and Base.Metadata when CompareMetadata is set).
	Base            SharedFile
	CompareMetadata bool
	Data            []byte
	// Metadata is what the published file gets, applied before the swap so
	// that it is published with it. Nil applies Protect.
	Metadata *FileMetadata
	Protect  func(path string) error
	Limit    int
	// Inspect runs on the locked current file before the comparison.
	Inspect     func(*os.File) error
	TempPattern string
	// BeforeSwap, when set, runs just before the compare-and-swap.
	BeforeSwap func(path string)
}

// PublishSharedFile writes Data to a new file beside Base.Path, gives it its
// metadata and moves it over Base.Path with CompareAndSwapFile. It returns the
// metadata of the published file and whether it was published; a publish
// that fails after the swap reports published with its error. An owner,
// access list or attribute change another writer makes in the instant between
// the comparison and the replacement is newer than what the publication
// read: it is put on the published file.
func PublishSharedFile(request SharedPublish) (FileMetadata, bool, error) {
	path := request.Base.Path
	temp, err := os.CreateTemp(filepath.Dir(path), request.TempPattern)
	if err != nil {
		return FileMetadata{}, false, err
	}
	tempPath := temp.Name()
	defer removeSharedTemp(tempPath)
	_, err = temp.Write(request.Data)
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return FileMetadata{}, false, err
	}
	switch {
	case request.Metadata != nil:
		err = ApplyFileMetadata(tempPath, *request.Metadata)
	case request.Protect != nil:
		err = request.Protect(tempPath)
	default:
		err = errors.New("safefile: a new shared file needs metadata or a protection")
	}
	if err != nil {
		return FileMetadata{}, false, err
	}
	published, err := ReadPathMetadata(tempPath)
	if err != nil {
		return FileMetadata{}, false, err
	}
	expected := SwapExpectation{Exists: request.Base.Exists, Data: request.Base.Data}
	if request.CompareMetadata && request.Base.Exists {
		metadata := request.Base.Metadata
		expected.Metadata = &metadata
	}
	if request.BeforeSwap != nil {
		request.BeforeSwap(path)
	}
	result, err := CompareAndSwapFile(tempPath, path, expected, request.Limit, request.Inspect)
	if err != nil {
		return FileMetadata{}, false, err
	}
	if expected.Metadata != nil && result.ReplacedMetadata != nil && *result.ReplacedMetadata != *expected.Metadata {
		if err := ApplyFileMetadata(path, *result.ReplacedMetadata); err != nil {
			return published, true, fmt.Errorf("safefile: keep the newer metadata of %s: %w", path, err)
		}
		if published, err = ReadPathMetadata(path); err != nil {
			return published, true, err
		}
	}
	return published, true, nil
}

// RemoveSharedFile deletes base.Path only while it holds base, its content
// and, when compareMetadata is set, its metadata (RemoveFileIfUnchanged).
func RemoveSharedFile(base SharedFile, compareMetadata bool, limit int, inspect func(*os.File) error) error {
	if !base.Exists {
		return swapRaced(base.Path)
	}
	expected := SwapExpectation{Exists: true, Data: base.Data}
	if compareMetadata {
		metadata := base.Metadata
		expected.Metadata = &metadata
	}
	_, err := RemoveFileIfUnchanged(base.Path, expected, limit, inspect)
	return err
}

// removeSharedTemp removes a temporary file a publication left, also when it
// got the read-only attribute.
func removeSharedTemp(path string) {
	if err := os.Remove(path); err == nil || errors.Is(err, os.ErrNotExist) {
		return
	}
	if name, err := winpath.UTF16Ptr(path); err == nil {
		_ = windows.SetFileAttributes(name, windows.FILE_ATTRIBUTE_NORMAL)
	}
	_ = os.Remove(path)
}

// ReadFileMetadata reads the owner, group, access list and attributes of the
// file behind file.
func ReadFileMetadata(file *os.File) (FileMetadata, error) {
	handle := windows.Handle(file.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return FileMetadata{}, err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err == nil && (descriptor == nil || descriptor.String() == "") {
		err = errors.New("empty security descriptor")
	}
	if err != nil {
		return FileMetadata{}, fmt.Errorf("safefile: read the security descriptor of %s: %w", file.Name(), err)
	}
	return FileMetadata{SecurityDescriptor: descriptor.String(), Attributes: info.FileAttributes}, nil
}

// ReadPathMetadata is ReadFileMetadata for the regular file at path. It does
// not follow a reparse point and refuses anything but a regular file.
func ReadPathMetadata(path string) (FileMetadata, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return FileMetadata{}, err
	}
	handle, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return FileMetadata{}, fmt.Errorf("safefile: open %s: %w", path, err)
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	metadata, err := ReadFileMetadata(file)
	if err != nil {
		return FileMetadata{}, err
	}
	if metadata.Attributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return FileMetadata{}, fmt.Errorf("safefile: refusing a file that is not regular: %s", path)
	}
	return metadata, nil
}

// ApplyFileMetadata gives the file at path the owner, group, access list and
// attributes in metadata, so that the file reads back with the same
// metadata. An access list that is marked auto-inherited is set as Windows
// sets one for any file there (SetNamedSecurityInfo), which recomputes its
// inherited entries from the parent and keeps the mark. Any other access list
// is set exactly as it is (SetKernelObjectSecurity): SetNamedSecurityInfo
// would add the mark.
func ApplyFileMetadata(path string, metadata FileMetadata) error {
	if metadata.SecurityDescriptor == "" {
		return errors.New("safefile: the metadata has no security descriptor")
	}
	descriptor, err := windows.SecurityDescriptorFromString(metadata.SecurityDescriptor)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("safefile: the metadata has an invalid security descriptor")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return errors.New("safefile: the metadata has no valid owner")
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return fmt.Errorf("safefile: inspect the metadata's group: %w", err)
	}
	// DACL's boolean result reports whether the ACL was defaulted; a missing
	// DACL is reported through err.
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return errors.New("safefile: the metadata has no access list")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("safefile: inspect the metadata's access list control: %w", err)
	}
	information := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION |
		windows.GROUP_SECURITY_INFORMATION |
		windows.DACL_SECURITY_INFORMATION)
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_AUTO_INHERITED != 0 {
		if control&windows.SE_DACL_PROTECTED != 0 {
			information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
		} else {
			information |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
		}
		extended, err := winpath.Extended(path)
		if err != nil {
			return err
		}
		if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, information, owner, group, dacl, nil); err != nil {
			return fmt.Errorf("safefile: set the security descriptor of %s: %w", path, err)
		}
	} else {
		handle, err := windows.CreateFile(
			name,
			windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
		if err != nil {
			return fmt.Errorf("safefile: open %s for its metadata: %w", path, err)
		}
		err = windows.SetKernelObjectSecurity(handle, information, descriptor)
		_ = windows.CloseHandle(handle)
		if err != nil {
			return fmt.Errorf("safefile: set the security descriptor of %s: %w", path, err)
		}
	}
	attributes := metadata.Attributes
	if attributes == 0 {
		attributes = windows.FILE_ATTRIBUTE_NORMAL
	}
	if err := windows.SetFileAttributes(name, attributes); err != nil {
		return fmt.Errorf("safefile: set the attributes of %s: %w", path, err)
	}
	return nil
}
