// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Read-only native ABI qualification of exactly PROCESSINFOCLASS 44. No child,
// PSEC/SDK, process enumeration, PID reopen, token change or setter is used.
// NtDoc original research specifies an INPUT HANDLE buffer and no output:
// https://github.com/m417z/ntdoc/blob/main/descriptions/processinfoclass.md#processimagefilemapping-44
// phnt independently labels the enum as q: HANDLE (input):
// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h
func TestNativeReadOnlyProcessImageFileMappingHeldCurrentImageAndWrongFile(t *testing.T) {
	query := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryInformationProcess")
	if err := query.Find(); err != nil {
		t.Fatal("read-only process-image query export unavailable")
	}
	open := func(path string) *os.File {
		t.Helper()
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal("fixed image path encoding refused")
		}
		// FILE_GENERIC_READ includes SYNCHRONIZE. FILE_EXECUTE is additionally
		// required by class 44. No write access or write/delete sharing is added.
		handle, err := windows.CreateFile(name, windows.FILE_GENERIC_READ|windows.FILE_EXECUTE,
			windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			t.Fatal("read/execute image-handle open refused")
		}
		file := os.NewFile(uintptr(handle), "held-readonly-image-query-object")
		t.Cleanup(func() {
			if file.Close() != nil {
				t.Error("held read-only image-query object close failed")
			}
		})
		var information windows.ByHandleFileInformation
		if windows.GetFileInformationByHandle(handle, &information) != nil ||
			information.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
			t.Fatal("image-query object type refused")
		}
		return file
	}
	statusFor := func(file *os.File) uint32 {
		// This is intentionally NOT NtSetInformationProcess. The buffer contains
		// one borrowed file HANDLE; class 44 compares kernel section identity.
		handle := windows.Handle(file.Fd())
		status, _, _ := query.Call(uintptr(windows.CurrentProcess()), 44,
			uintptr(unsafe.Pointer(&handle)), unsafe.Sizeof(handle), 0)
		runtime.KeepAlive(file)
		return uint32(status)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal("current test image lookup refused")
	}
	current := open(self)
	if status := statusFor(current); status != 0 {
		t.Fatalf("current image direct-kernel match refused: NTSTATUS=0x%08x", status)
	}
	private := t.TempDir()
	copyPath := filepath.Join(private, "fixed-public-unexecuted-identical-image.exe")
	info, err := current.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 64<<20 {
		t.Fatal("current test image copy bound refused")
	}
	copyFile, err := os.OpenFile(copyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("fresh identical-image copy creation refused")
	}
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(copyFile, hash), io.LimitReader(current, info.Size()+1))
	closeErr := copyFile.Close()
	if copyErr != nil || closeErr != nil || n != info.Size() {
		t.Fatal("bounded held-image copy failed")
	}
	copied := open(copyPath)
	if readFixed(copied, info.Size(), hex.EncodeToString(hash.Sum(nil))) != nil {
		t.Fatal("copied image bytes differ")
	}
	currentID, currentErr := identity(current)
	copyID, copyErr := identity(copied)
	if currentErr != nil || copyErr != nil || currentID == copyID {
		t.Fatal("copied image must have a distinct full file identity")
	}
	if status := statusFor(copied); status == 0 {
		t.Fatal("direct-kernel image query accepted identical bytes in a distinct file")
	}
	wrong := filepath.Join(private, "fixed-public-wrong-image.bin")
	if os.WriteFile(wrong, []byte("fixed-public-synthetic-wrong-image\n"), 0600) != nil {
		t.Fatal("fresh public synthetic wrong-file fixture creation failed")
	}
	if status := statusFor(open(wrong)); status == 0 {
		t.Fatal("direct-kernel image query accepted an unrelated held file")
	}
}
