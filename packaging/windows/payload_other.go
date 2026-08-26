// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package windowspayload

// Non-Windows builds have no use for the lifecycle scripts and do not carry
// their bytes.
var (
	installer []byte
	module    []byte
)
