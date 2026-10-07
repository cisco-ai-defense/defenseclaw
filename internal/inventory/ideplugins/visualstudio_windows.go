// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ideplugins

import (
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var procRegLoadAppKeyW = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegLoadAppKeyW")

func init() {
	visualStudioEnabledLookup = readVisualStudioEnabled
}

// readVisualStudioEnabled loads a private copy of an instance's hive. The
// registry API can create a missing hive and needs write access even when
// reading, so it must never receive the path in the user's profile. It reads
// the value names of
// ExtensionManager\EnabledExtensions, which are "<id>,<version>".
func readVisualStudioEnabled(instanceDir, instanceName string) (map[string]bool, bool) {
	hive := filepath.Join(instanceDir, "privateregistry.bin")
	const maxHiveBytes = 64 << 20
	info, err := os.Lstat(hive)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxHiveBytes {
		return nil, false
	}
	source, err := os.Open(hive)
	if err != nil {
		return nil, false
	}
	defer source.Close()
	privateDir, err := os.MkdirTemp("", "defenseclaw-vs-hive-")
	if err != nil {
		return nil, false
	}
	defer os.RemoveAll(privateDir)
	copyPath := filepath.Join(privateDir, "privateregistry.bin")
	copyFile, err := os.Create(copyPath)
	if err != nil {
		return nil, false
	}
	copied, copyErr := io.Copy(copyFile, io.LimitReader(source, maxHiveBytes+1))
	closeErr := copyFile.Close()
	if copyErr != nil || closeErr != nil || copied <= 0 || copied > maxHiveBytes {
		return nil, false
	}
	path, err := windows.UTF16PtrFromString(copyPath)
	if err != nil {
		return nil, false
	}
	if err := procRegLoadAppKeyW.Find(); err != nil {
		return nil, false
	}
	var root windows.Handle
	r, _, _ := procRegLoadAppKeyW.Call(
		uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(&root)),
		uintptr(registry.READ),
		0, 0,
	)
	if r != 0 {
		return nil, false
	}
	key := registry.Key(root)
	defer key.Close()
	for _, sub := range []string{instanceName, instanceName + "_Config"} {
		k, err := registry.OpenKey(key, `Software\Microsoft\VisualStudio\`+sub+`\ExtensionManager\EnabledExtensions`, registry.READ)
		if err != nil {
			continue
		}
		out, ok := visualStudioEnabledNames(k.ReadValueNames)
		k.Close()
		return out, ok
	}
	return nil, false
}
