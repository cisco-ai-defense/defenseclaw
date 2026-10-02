//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	wslTrustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	wslProfileListKey      = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	wslKeyWriteAccess      = windows.KEY_SET_VALUE | windows.KEY_CREATE_SUB_KEY | windows.WRITE_DAC |
		windows.WRITE_OWNER | windows.DELETE | windows.GENERIC_WRITE | windows.GENERIC_ALL
)

type windowsWSLRegistry struct{}

func platformWSLRegistry() WSLRegistry { return windowsWSLRegistry{} }

func readRegistryValues(root registry.Key, path string) ([]RegValue, bool, error) {
	key, err := registry.OpenKey(root, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer key.Close()
	names, err := key.ReadValueNames(0)
	if err != nil {
		return nil, true, err
	}
	values := make([]RegValue, 0, len(names))
	for _, name := range names {
		size, kind, err := key.GetValue(name, nil)
		if err != nil {
			return nil, true, fmt.Errorf("%s: %w", name, err)
		}
		value := RegValue{Name: name, Type: kind}
		switch kind {
		case registry.SZ, registry.EXPAND_SZ:
			if size > policyFileLimit {
				return nil, true, fmt.Errorf("%s exceeds %d bytes", name, policyFileLimit)
			}
			if value.String, _, err = key.GetStringValue(name); err != nil {
				return nil, true, fmt.Errorf("%s: %w", name, err)
			}
		case registry.DWORD, registry.QWORD:
			if value.Number, _, err = key.GetIntegerValue(name); err != nil {
				return nil, true, fmt.Errorf("%s: %w", name, err)
			}
		}
		values = append(values, value)
	}
	return values, true, nil
}

func (windowsWSLRegistry) MachineValues(path string) ([]RegValue, bool, error) {
	return readRegistryValues(registry.LOCAL_MACHINE, path)
}

// UserValues reads path in every loaded local account hive (signed-in
// users); hives of signed-out users are not loaded and not read.
func (windowsWSLRegistry) UserValues(path string) (map[string][]RegValue, error) {
	users, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil, err
	}
	defer users.Close()
	sids, err := users.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}
	out := map[string][]RegValue{}
	for _, sid := range sids {
		if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") || strings.HasSuffix(strings.ToLower(sid), "_classes") {
			continue
		}
		values, _, err := readRegistryValues(registry.USERS, sid+`\`+path)
		if err != nil {
			return nil, fmt.Errorf("HKU\\%s\\%s: %w", sid, path, err)
		}
		if len(values) > 0 {
			out[sid] = values
		}
	}
	return out, nil
}

func wslTrustedSID(sid *windows.SID) bool {
	return sid != nil && (sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
		sid.IsWellKnown(windows.WinLocalSystemSid) || sid.String() == wslTrustedInstallerSID)
}

func (windowsWSLRegistry) MachineKeyWritableByUsers(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(`MACHINE\`+path, windows.SE_REGISTRY_WOW64_64KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if !wslTrustedSID(owner) {
		return true, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		// A missing DACL grants everyone full control.
		return true, nil
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE, 0x6, 0xA, 0xC:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			// Object and callback grants are not parsed: treat as open.
			return true, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !wslTrustedSID(sid) && uint32(ace.Mask)&wslKeyWriteAccess != 0 {
			return true, nil
		}
	}
	return false, nil
}

func (windowsWSLRegistry) SetMachineValue(path string, value RegValue) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer key.Close()
	switch value.Type {
	case RegSZ:
		return key.SetStringValue(value.Name, value.String)
	case RegDWORD:
		return key.SetDWordValue(value.Name, uint32(value.Number))
	}
	return fmt.Errorf("unsupported registry type %d", value.Type)
}

func (windowsWSLRegistry) DeleteMachineValue(path, name string) error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer key.Close()
	if err := key.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

func (windowsWSLRegistry) ProfileHomes() ([]string, error) {
	list, err := registry.OpenKey(registry.LOCAL_MACHINE, wslProfileListKey, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer list.Close()
	sids, err := list.ReadSubKeyNames(0)
	if err != nil {
		return nil, err
	}
	var homes []string
	for _, sid := range sids {
		if !strings.HasPrefix(strings.ToUpper(sid), "S-1-5-21-") {
			continue
		}
		key, err := registry.OpenKey(list, sid, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		path, _, err := key.GetStringValue("ProfileImagePath")
		key.Close()
		if err != nil || strings.TrimSpace(path) == "" {
			continue
		}
		if expanded, err := registry.ExpandString(path); err == nil {
			path = expanded
		}
		homes = append(homes, path)
	}
	return homes, nil
}
