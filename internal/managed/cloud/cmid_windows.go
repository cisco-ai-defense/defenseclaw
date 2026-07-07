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

package cloud

import "fmt"

// defaultLibPath is a placeholder for the Windows install location of
// cmidapi.dll shipped by Cisco Cloud Management. The real path is subject
// to confirmation from Cisco packaging; the Windows binding lands in a
// follow-up branch.
//
// TODO(cmid-windows): confirm the shipped path and wire a purego binding
// analogous to cmid_darwin.go.
const defaultLibPath = `C:\Program Files\Cisco\Cisco Secure Client\CloudManagement\cmidapi.dll`

func newLibCaller(path string) (caller, error) {
	return nil, fmt.Errorf("windows binding not implemented: %w", ErrUnsupportedPlatform)
}
