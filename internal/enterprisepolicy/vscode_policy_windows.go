// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// vscodePolicyKey is VS Code's machine policy key.
const vscodePolicyKey = `Software\Policies\Microsoft\VSCode`

// windowsVSCodePolicyStore returns the HKLM policy key.
func windowsVSCodePolicyStore() (vscodePolicyStore, error) { return vscodePolicyRegistry{}, nil }

type vscodePolicyRegistry struct{}

func (vscodePolicyRegistry) where() string { return `HKLM\` + vscodePolicyKey }

func (vscodePolicyRegistry) load() (map[string]bool, error) {
	values := map[string]bool{}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, vscodePolicyKey, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if errors.Is(err, registry.ErrNotExist) {
		return values, nil
	}
	if err != nil {
		return nil, err
	}
	defer key.Close()
	for _, name := range vscodeDevicePolicyNames {
		value, valueType, err := key.GetIntegerValue(name)
		switch {
		case errors.Is(err, registry.ErrNotExist):
			continue
		case err != nil && !errors.Is(err, registry.ErrUnexpectedType):
			return nil, err
		}
		values[name] = err == nil && valueType == registry.DWORD && value == 1
	}
	return values, nil
}

func (vscodePolicyRegistry) apply(add, remove []string) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, vscodePolicyKey, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer key.Close()
	for _, name := range add {
		if err := key.SetDWordValue(name, 1); err != nil {
			return err
		}
	}
	for _, name := range remove {
		if err := key.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
	}
	return nil
}
