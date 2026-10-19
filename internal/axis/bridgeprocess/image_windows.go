// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

const windowsImageBound int64 = 512 << 20
const windowsImageLeaf = "image.exe"
const windowsImageNoExecute = 0x11000000 // SEC_IMAGE_NO_EXECUTE

var (
	windowsImageKernel     = windows.NewLazySystemDLL("kernel32.dll")
	windowsImageReopen     = windowsImageKernel.NewProc("ReOpenFile")
	windowsImageVolume     = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryVolumeInformationFile")
	errWindowsImageCleanup = errors.New("private AXIS Windows image cleanup remains incomplete")
)

type windowsImageID struct {
	Volume uint64
	File   [16]byte
}

// windowsImageState owns only new objects beneath one caller-held private
// root. No pathname selects the source, image, or cleanup target. A failed
// cleanup remains reachable through Image.Close, including partial admission.
type windowsImageState struct {
	root, directory, writer, weak, strict *os.File
	name                                  string
	id                                    windowsImageID
	fileCreated                           bool
	section                               windows.Handle
	view                                  uintptr
	uncertain                             bool
	// Per-owner hooks permit deterministic cleanup-failure tests without any
	// native call or global replacement. Production installs fixed APIs only.
	unmap        func(uintptr) error
	closeSection func(windows.Handle) error
}

// SealImageIn copies an already admitted artifact into a fresh NTFS object
// beneath privateRoot. It never discovers TEMP, source names or executables.
// The caller retains source/root ownership. This function does not execute a
// PE, load a DLL from the image, or activate Windows process transport.
//
// The copy is private before its first byte. Only the constructor ever has a
// writable handle/view. A retained read-only SEC_IMAGE_NO_EXECUTE view spans
// closure of that writer and acquisition of a strict read/execute file pin.
// Both the view and pin remain owned until Image.Close. Source mappings cannot
// mutate this independent copy. Unsupported filesystems or mapping APIs refuse.
//
// A nonnil image returned with an error is NOT admitted; retain it and call
// Close again after retryable cleanup failures. Native close/unmap uncertainty
// is sticky and never blindly retried. The context bounds copy iteration, not
// arbitrary filesystem calls; a separately bounded caller must own that limit.
func SealImageIn(ctx context.Context, source *os.File, expected string, privateRoot *os.File) (result *Image, resultErr error) {
	if ctx == nil || ctx.Err() != nil || source == nil || privateRoot == nil ||
		len(expected) != 71 || !strings.HasPrefix(expected, "sha256:") || strings.ToLower(expected) != expected {
		return nil, ErrAdmission
	}
	if raw, err := hex.DecodeString(expected[7:]); err != nil || len(raw) != sha256.Size {
		return nil, ErrAdmission
	}
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 64 || info.Size() > windowsImageBound {
		return nil, ErrAdmission
	}
	// Keep effective-token ownership stable across the security descriptor and
	// safe-file validation calls; no impersonation or privilege is installed.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	state := &windowsImageState{unmap: windows.UnmapViewOfFile, closeSection: windows.CloseHandle}
	accepted := false
	image := &Image{cleanup: state.close}
	defer func() {
		if !accepted {
			if cleanupErr := state.close(); cleanupErr != nil {
				// This nonlaunchable value retains cleanup; no file/digest authority.
				result = image
				resultErr = errors.Join(resultErr, cleanupErr)
			} else {
				result = nil
			}
		}
	}()
	// Only these source-fixed labels leave the constructor. Never attach a
	// native error's string, caller filename, handle value or descriptor.
	stage := "root_open"
	fail := func(reason error) (*Image, error) {
		return nil, fmt.Errorf("%w: stage=%s", reason, stage)
	}
	state.root, err = windowsImageOpen(privateRoot, ".", true, windows.FILE_OPEN, nil,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		return fail(err)
	}
	stage = "root_metadata"
	if _, err := windowsImageMetadata(state.root, true); err != nil {
		return fail(ErrAdmission)
	}
	stage = "root_private"
	if windowsImagePrivate(state.root) != nil {
		return fail(ErrAdmission)
	}
	stage = "root_local_ntfs"
	if windowsImageLocalNTFS(state.root) != nil {
		return fail(ErrAdmission)
	}
	stage = "private_directory_setup"
	user, err := windows.GetCurrentThreadEffectiveToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fail(ErrAdmission)
	}
	grants := fmt.Sprintf("(A;;FA;;;%s)", user.User.Sid)
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		grants += "(A;;FA;;;SY)"
	}
	descriptor, err := windows.SecurityDescriptorFromString(fmt.Sprintf("O:%sD:P%s", user.User.Sid, grants))
	if err != nil {
		return fail(ErrAdmission)
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return fail(ErrUnavailable)
	}
	state.name = "axis-image-" + hex.EncodeToString(random[:])
	state.directory, err = windowsImageOpen(state.root, state.name, true, windows.FILE_CREATE, descriptor,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.DELETE|windows.READ_CONTROL|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil {
		return fail(err)
	}
	if _, err := windowsImageMetadata(state.directory, true); err != nil || windowsImagePrivate(state.directory) != nil {
		return fail(ErrAdmission)
	}
	stage = "private_writer_setup"
	state.writer, err = windowsImageOpen(state.directory, windowsImageLeaf, false, windows.FILE_CREATE, descriptor,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.FILE_EXECUTE|windows.READ_CONTROL|windows.SYNCHRONIZE, windows.FILE_SHARE_READ)
	if err != nil {
		return fail(err)
	}
	state.fileCreated = true
	state.id, err = windowsImageMetadata(state.writer, false)
	if err != nil || windowsImagePrivate(state.writer) != nil {
		// Without a full identity cleanup must retain, rather than remove by name.
		return fail(ErrAdmission)
	}
	stage = "copy"
	if err := windowsImageCopy(ctx, source, state.writer, info.Size(), expected); err != nil {
		return fail(err)
	}
	stage = "pe64_and_flush"
	if !windowsImagePE64(state.writer, info.Size()) || state.writer.Sync() != nil {
		return fail(ErrAdmission)
	}
	stage = "image_section"
	state.section, err = windows.CreateFileMapping(windows.Handle(state.writer.Fd()), nil,
		windows.PAGE_READONLY|windowsImageNoExecute, 0, 0, nil)
	if err != nil {
		return fail(ErrUnavailable)
	}
	stage = "image_view"
	state.view, err = windows.MapViewOfFile(state.section, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return fail(ErrUnavailable)
	}
	stage = "weak_read_execute_pin"
	state.weak, err = windowsImageReopenFile(state.writer, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	if err != nil || !windowsImageSame(state.weak, state.id) {
		return fail(ErrAdmission)
	}
	stage = "writer_close"
	if state.closeFile(&state.writer) != nil {
		return fail(errWindowsImageCleanup)
	}
	// No external writer was ever supplied. The held image view covers the
	// share transition; the strict pin adds deny-write and deny-delete sharing.
	stage = "strict_read_execute_pin"
	state.strict, err = windowsImageReopenFile(state.weak, windows.FILE_SHARE_READ)
	if err != nil || !windowsImageSame(state.strict, state.id) {
		return fail(ErrAdmission)
	}
	stage = "weak_pin_close"
	if state.closeFile(&state.weak) != nil {
		return fail(errWindowsImageCleanup)
	}
	stage = "frozen_digest_and_identity"
	if err := windowsImageDigest(ctx, state.strict, info.Size(), expected); err != nil || !windowsImageSame(state.strict, state.id) {
		return fail(ErrAdmission)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	image.file, image.digest = state.strict, expected
	accepted = true
	return image, nil
}

func windowsImageCopy(ctx context.Context, source io.ReaderAt, destination io.Writer, size int64, expected string) error {
	hash := sha256.New()
	reader := io.NewSectionReader(source, 0, size)
	buffer := make([]byte, 64<<10)
	for remaining := size; remaining > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := reader.Read(buffer[:min(int64(len(buffer)), remaining)])
		if n == 0 || readErr != nil && readErr != io.EOF {
			return ErrAdmission
		}
		if written, err := destination.Write(buffer[:n]); err != nil || written != n {
			return ErrAdmission
		}
		_, _ = hash.Write(buffer[:n])
		remaining -= int64(n)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected[7:] {
		return ErrAdmission
	}
	return ctx.Err()
}

func windowsImageDigest(ctx context.Context, file *os.File, size int64, expected string) error {
	info, err := file.Stat()
	if err != nil || info.Size() != size {
		return ErrAdmission
	}
	hash := sha256.New()
	reader := io.NewSectionReader(file, 0, size)
	buffer := make([]byte, 64<<10)
	for remaining := size; remaining > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, readErr := reader.Read(buffer[:min(int64(len(buffer)), remaining)])
		if n == 0 || readErr != nil && readErr != io.EOF {
			return ErrAdmission
		}
		_, _ = hash.Write(buffer[:n])
		remaining -= int64(n)
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected[7:] {
		return ErrAdmission
	}
	return ctx.Err()
}

func windowsImagePE64(file *os.File, size int64) bool {
	var dos [64]byte
	if n, err := file.ReadAt(dos[:], 0); err != nil || n != len(dos) || dos[0] != 'M' || dos[1] != 'Z' {
		return false
	}
	offset := int64(uint32(dos[60]) | uint32(dos[61])<<8 | uint32(dos[62])<<16 | uint32(dos[63])<<24)
	var pe [26]byte
	if offset < 64 || offset > size-int64(len(pe)) || offset > 1<<20 {
		return false
	}
	if n, err := file.ReadAt(pe[:], offset); err != nil || n != len(pe) {
		return false
	}
	return string(pe[:4]) == "PE\x00\x00" && pe[4] == 0x64 && pe[5] == 0x86 && pe[24] == 0x0b && pe[25] == 0x02
}

func windowsImageOpen(parent *os.File, name string, directory bool, disposition uint32,
	descriptor *windows.SECURITY_DESCRIPTOR, access, share uint32) (*os.File, error) {
	connection, err := parent.SyscallConn()
	if err != nil {
		return nil, ErrAdmission
	}
	if name == "." && directory && disposition == windows.FILE_OPEN {
		// Go1.26 internal/syscall/windows OBJECT_ATTRIBUTES.init encodes a
		// self-root reopen with an empty NT ObjectName, not a literal dot.
		// RootDirectory stays the same held capability; no path is resolved.
		name = ""
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, ErrAdmission
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	var nativeErr error
	err = connection.Control(func(raw uintptr) {
		attributes := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
			RootDirectory: windows.Handle(raw), ObjectName: objectName,
			Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE, SecurityDescriptor: descriptor}
		options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_NON_DIRECTORY_FILE)
		attributesOnDisk := uint32(windows.FILE_ATTRIBUTE_NORMAL)
		if directory {
			options = windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_DIRECTORY_FILE
			attributesOnDisk = windows.FILE_ATTRIBUTE_DIRECTORY
		}
		nativeErr = windows.NtCreateFile(&handle, access, &attributes, &status, nil,
			attributesOnDisk, share, disposition, options, 0, 0)
	})
	if err != nil || nativeErr != nil {
		// NtCreateFile's typed status is numeric metadata. Do not format its
		// native Error() text or the caller's os.File/SyscallConn error.
		var status windows.NTStatus
		if errors.As(nativeErr, &status) {
			return nil, fmt.Errorf("%w: ntstatus=0x%08x", ErrAdmission, uint32(status))
		}
		return nil, ErrAdmission
	}
	return os.NewFile(uintptr(handle), "private-axis-image-object"), nil
}

func windowsImageReopenFile(file *os.File, share uint32) (*os.File, error) {
	connection, err := file.SyscallConn()
	if err != nil || windowsImageReopen.Find() != nil {
		return nil, ErrUnavailable
	}
	var handle windows.Handle
	err = connection.Control(func(raw uintptr) {
		value, _, _ := windowsImageReopen.Call(raw, windows.GENERIC_READ|windows.FILE_EXECUTE|windows.READ_CONTROL|windows.SYNCHRONIZE, uintptr(share), 0)
		handle = windows.Handle(value)
	})
	if err != nil || handle == 0 || handle == windows.InvalidHandle {
		return nil, ErrAdmission
	}
	return os.NewFile(uintptr(handle), "private-axis-image-pin"), nil
}

func windowsImageMetadata(file *os.File, directory bool) (windowsImageID, error) {
	var id windowsImageID
	var info windows.ByHandleFileInformation
	if file == nil || windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info) != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 ||
		windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))) != nil || id == (windowsImageID{}) {
		return windowsImageID{}, ErrAdmission
	}
	return id, nil
}

func windowsImageSame(file *os.File, expected windowsImageID) bool {
	actual, err := windowsImageMetadata(file, false)
	return err == nil && actual == expected
}

func windowsImagePrivate(file *os.File) error {
	handle := windows.Handle(file.Fd())
	if safefile.ValidatePrivateHandle(handle) != nil {
		return ErrAdmission
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrAdmission
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrAdmission
	}
	return nil
}

func windowsImageLocalNTFS(file *os.File) error {
	var filesystem [32]uint16
	if windows.GetVolumeInformationByHandle(windows.Handle(file.Fd()), nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))) != nil ||
		windows.UTF16ToString(filesystem[:]) != "NTFS" || windowsImageVolume.Find() != nil {
		return ErrUnavailable
	}
	// FILE_FS_DEVICE_INFORMATION: two ULONGs. FILE_DEVICE_DISK=7 and
	// FILE_REMOTE_DEVICE=0x10; the query is bound to the held object, not a drive.
	var device struct{ Type, Characteristics uint32 }
	var status windows.IO_STATUS_BLOCK
	result, _, _ := windowsImageVolume.Call(file.Fd(), uintptr(unsafe.Pointer(&status)),
		uintptr(unsafe.Pointer(&device)), unsafe.Sizeof(device), 4)
	if uint32(result) != 0 || status.Information != unsafe.Sizeof(device) || device.Type != 7 || device.Characteristics&0x10 != 0 {
		return ErrUnavailable
	}
	return nil
}

func (state *windowsImageState) closeFile(file **os.File) error {
	if *file == nil {
		return nil
	}
	owned := *file
	*file = nil // one close attempt; never reuse a possibly recycled handle
	if owned.Close() != nil {
		state.uncertain = true
		return errWindowsImageCleanup
	}
	return nil
}

func (state *windowsImageState) empty() bool {
	return state.root == nil && state.directory == nil && state.writer == nil && state.weak == nil && state.strict == nil && state.section == 0 && state.view == 0 && !state.uncertain
}

func (state *windowsImageState) close() error {
	// An initial identity-query failure retains the exact creation handle.
	// Read-only identity queries may be retried; no name is reopened until a
	// complete identity is known, and no uncertain close is ever retried.
	if state.fileCreated && state.id == (windowsImageID{}) {
		if state.writer == nil {
			return errWindowsImageCleanup
		}
		identity, err := windowsImageMetadata(state.writer, false)
		if err != nil {
			return errWindowsImageCleanup
		}
		state.id = identity
	}
	// Release the execution pins before deleting. Already handed-out strict
	// duplicates still deny write/delete opens and cause a retryable refusal.
	for _, file := range []**os.File{&state.writer, &state.strict, &state.weak} {
		_ = state.closeFile(file)
	}
	if state.view != 0 {
		view := state.view
		state.view = 0
		if state.unmap(view) != nil {
			state.uncertain = true
		}
	}
	if state.section != 0 {
		handle := state.section
		state.section = 0
		if state.closeSection(handle) != nil {
			state.uncertain = true
		}
	}
	if state.uncertain {
		return errWindowsImageCleanup
	}
	if state.fileCreated {
		if state.id == (windowsImageID{}) {
			return errWindowsImageCleanup // retain unknown-identity residue
		}
		file, err := windowsImageOpen(state.directory, windowsImageLeaf, false, windows.FILE_OPEN, nil,
			windows.DELETE|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
		if err != nil {
			return errWindowsImageCleanup
		}
		if !windowsImageSame(file, state.id) || windowsImagePrivate(file) != nil {
			_ = state.closeFile(&file)
			return errWindowsImageCleanup
		}
		flags := uint32(windows.FILE_DISPOSITION_DELETE)
		err = windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileDispositionInfoEx, (*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)))
		closeErr := state.closeFile(&file)
		if err != nil || closeErr != nil {
			return errWindowsImageCleanup
		}
		state.fileCreated = false
	}
	if state.directory != nil {
		// This exact held directory was created here. Disposition refuses a
		// nonempty replacement/addition; no enumeration or recursive delete.
		flags := uint32(windows.FILE_DISPOSITION_DELETE)
		if windows.SetFileInformationByHandle(windows.Handle(state.directory.Fd()), windows.FileDispositionInfoEx,
			(*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags))) != nil {
			return errWindowsImageCleanup
		}
		if err := state.closeFile(&state.directory); err != nil {
			return err
		}
	}
	if err := state.closeFile(&state.root); err != nil {
		return err
	}
	return nil
}

func (image *Image) duplicate() (*os.File, error) {
	if image == nil {
		return nil, ErrAdmission
	}
	image.mu.Lock()
	defer image.mu.Unlock()
	if image.file == nil || image.digest == "" {
		return nil, ErrAdmission
	}
	return windowsImageReopenFile(image.file, windows.FILE_SHARE_READ)
}
