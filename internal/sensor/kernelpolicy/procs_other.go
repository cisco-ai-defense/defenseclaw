//go:build !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package kernelpolicy

import "errors"

// ScanProcs is Linux only: Tetragon has no agent for other systems.
func ScanProcs(string, func(int) bool) ([]Proc, error) {
	return nil, errors.New("kernelpolicy: process scan is only available on Linux")
}
