//go:build !windows

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

import "errors"

var errNoWindowsRegistry = errors.New("the Windows registry is not available on this platform")

type noWSLRegistry struct{}

func platformWSLRegistry() WSLRegistry { return noWSLRegistry{} }

func (noWSLRegistry) MachineValues(string) ([]RegValue, bool, error) {
	return nil, false, errNoWindowsRegistry
}
func (noWSLRegistry) UserValues(string) (map[string][]RegValue, error) {
	return nil, errNoWindowsRegistry
}
func (noWSLRegistry) MachineKeyWritableByUsers(string) (bool, error) {
	return false, errNoWindowsRegistry
}
func (noWSLRegistry) SetMachineValue(string, RegValue) error  { return errNoWindowsRegistry }
func (noWSLRegistry) DeleteMachineValue(string, string) error { return errNoWindowsRegistry }
func (noWSLRegistry) ProfileHomes() ([]string, error)         { return nil, errNoWindowsRegistry }
