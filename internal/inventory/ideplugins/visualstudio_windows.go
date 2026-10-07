// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ideplugins

import (
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var procRegLoadAppKeyW = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegLoadAppKeyW")

func init() {
	visualStudioEnabledLookup = readVisualStudioEnabled
}

// readVisualStudioEnabled loads an instance's privateregistry.bin with
// RegLoadAppKey (no options, so a hive Visual Studio already loaded is
// shared rather than locked against it) and reads the value names of
// ExtensionManager\EnabledExtensions, which are "<id>,<version>".
func readVisualStudioEnabled(instanceDir, instanceName string) (map[string]bool, bool) {
	hive := filepath.Join(instanceDir, "privateregistry.bin")
	path, err := windows.UTF16PtrFromString(hive)
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
