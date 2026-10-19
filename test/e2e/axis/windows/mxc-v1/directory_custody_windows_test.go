// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These inert native filesystem controls exercise the exact API/access modes
// used by the Rust identity helper and SDK overlay; no executable is run.
func TestNtOpenDirectoryRenameCustodyAccessControl(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "fixed-parent")
	moved := parent + "-renamed"
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	drive, err := windows.UTF16PtrFromString(filepath.VolumeName(parent))
	if err != nil {
		t.Fatal(err)
	}
	var target [1024]uint16
	if _, err := windows.QueryDosDevice(drive, &target[0], uint32(len(target))); err != nil {
		t.Fatal(err)
	}
	device := windows.UTF16ToString(target[:])
	if !strings.HasPrefix(device, `\Device\HarddiskVolume`) {
		t.Fatal("synthetic fixture is not on a fixed native volume")
	}
	name, err := windows.NewNTUnicodeString(device + parent[2:])
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: name,
		Attributes: 0x40 | 0x1000, // CASE_INSENSITIVE | DONT_REPARSE
	}
	open := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtOpenFile")
	for _, test := range []struct {
		name   string
		access uint32
		share  uint32
		blocks bool
	}{{"former_attributes_only", 0x00100080, 1, false}, {"list_access_no_delete_share", 0x00100081, 3, true}} {
		t.Run(test.name, func(t *testing.T) {
			var handle windows.Handle
			var status windows.IO_STATUS_BLOCK
			result, _, _ := open.Call(uintptr(unsafe.Pointer(&handle)), uintptr(test.access),
				uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&status)), uintptr(test.share), 0x00200021)
			runtime.KeepAlive(name)
			runtime.KeepAlive(attributes)
			if int32(result) < 0 {
				t.Fatalf("fixed directory open: %v", windows.NTStatus(uint32(result)))
			}
			pin := os.NewFile(uintptr(handle), "held-synthetic-directory")
			defer pin.Close()
			err := os.Rename(parent, moved)
			if test.blocks {
				if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
					t.Fatalf("held directory rename: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(moved, parent); err != nil {
					t.Fatal(err)
				}
			}
			content := filepath.Join(parent, "fixed-public.txt")
			if err := os.WriteFile(content, []byte("fixed public data"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(content); err != nil {
				t.Fatal(err)
			}
			if err := pin.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(parent, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, parent); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSdkStyleAncestorRenameControlAfterImageRelease(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "fixed-parent")
	moved := parent + "-renamed"
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(parent, "fixed-not-executed.exe")
	if err := os.WriteFile(image, []byte("fixed public bytes; never executed"), 0600); err != nil {
		t.Fatal(err)
	}
	open := func(path string, access, share uint32) *os.File {
		t.Helper()
		encoded, err := windows.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := windows.CreateFile(encoded, access, share, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			t.Fatal(err)
		}
		return os.NewFile(uintptr(handle), "held-synthetic-object")
	}
	for _, test := range []struct {
		name   string
		access uint32
		share  uint32
		blocks bool
	}{{"former_attributes_only", windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, false},
		{"list_access_no_delete_share", windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE, true}} {
		t.Run(test.name, func(t *testing.T) {
			pin := open(parent, test.access, test.share)
			defer pin.Close()
			// Exercise the image separately, then release it so it cannot mask
			// the ancestor's actual no-delete-sharing behavior.
			leaf := open(image, windows.GENERIC_READ, windows.FILE_SHARE_READ)
			if err := leaf.Close(); err != nil {
				t.Fatal(err)
			}
			err := os.Rename(parent, moved)
			if test.blocks {
				if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
					t.Fatalf("held ancestor rename: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(moved, parent); err != nil {
					t.Fatal(err)
				}
			}
			if err := pin.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(parent, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, parent); err != nil {
				t.Fatal(err)
			}
		})
	}
}
